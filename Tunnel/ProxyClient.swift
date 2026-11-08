import Foundation
import Network

/// SOCKS5 / HTTP-CONNECT клиент для прокси-доменов.
/// Протокол ходит по TCP (TLS не обязателен: контент и так сквозной
/// TLS клиента; прокси видит только домен в CONNECT).
/// Endpoint (парсинг URL) — общий тип Shared/ProxyEndpoint.swift.
///
/// Дисциплина: методы вызываются с любых очередей; колбэки приходят
/// на queue коннекта.
enum ProxyClient {
    private static let timeout: TimeInterval = 5

    /// Коннект к домену через прокси. SOCKS5: greeting (опционально с
    /// user/pass), CONNECT по ИМЕНИ домена (ATYP=0x03 — резолв на
    /// стороне прокси). HTTP: CONNECT host:port.
    static func connect(endpoint: ProxyEndpoint, domain: String, port: UInt16,
                        ready: @escaping (ProxyStream?) -> Void) {
        let conn = NWConnection(host: NWEndpoint.Host(endpoint.host),
                                port: NWEndpoint.Port(rawValue: endpoint.port)!,
                                using: .tcp)
        var finished = false
        let lock = NSLock()
        func finishOnce(_ stream: ProxyStream?) {
            lock.lock(); defer { lock.unlock() }
            guard !finished else { return }
            finished = true
            if stream == nil { conn.cancel() }
            ready(stream)
        }
        conn.stateUpdateHandler = { state in
            switch state {
            case .ready:
                switch endpoint.kind {
                case .socks5:
                    socks5Handshake(conn: conn, endpoint: endpoint,
                                    domain: domain, port: port, done: finishOnce)
                case .http:
                    httpConnect(conn: conn, endpoint: endpoint,
                                domain: domain, port: port, done: finishOnce)
                }
            case .failed, .cancelled:
                finishOnce(nil)
            default:
                break
            }
        }
        conn.start(queue: .global(qos: .userInitiated))
        // Таймаут хендшейка.
        DispatchQueue.global().asyncAfter(deadline: .now() + timeout) { finishOnce(nil) }
    }

    /// Тест прокси: коннект к example.com:80 через прокси. Возвращает
    /// задержку хендшейка в мс или nil.
    static func probe(_ endpoint: ProxyEndpoint) async -> Int? {
        let start = DispatchTime.now()
        let ok: Bool = await withCheckedContinuation { (cont: CheckedContinuation<Bool, Never>) in
            connect(endpoint: endpoint, domain: "example.com", port: 80) { stream in
                stream?.close()
                cont.resume(returning: stream != nil)
            }
        }
        guard ok else { return nil }
        return Int((DispatchTime.now().uptimeNanoseconds - start.uptimeNanoseconds) / 1_000_000)
    }

    // MARK: - SOCKS5

    /// Двухфазный хендшейк: метод-согласование → CONNECT.
    private static func socks5Handshake(conn: NWConnection, endpoint: ProxyEndpoint,
                                         domain: String, port: UInt16,
                                         done: @escaping (ProxyStream?) -> Void) {
        let hasAuth = endpoint.user != nil
        // 1. VER METHODS NMETHODS METHODS
        var greeting = Data([0x05])
        if hasAuth {
            greeting.append(contentsOf: [2, 0x01, 0x02])  // 2 метода: no-auth, user/pass
        } else {
            greeting.append(contentsOf: [1, 0x00])        // только no-auth
        }
        conn.send(content: greeting, completion: .contentProcessed { err in
            guard err == nil else { done(nil); return }
            conn.receive(minimumIncompleteLength: 2, maximumLength: 2) { data, _, _, err in
                guard err == nil, let data, data.count == 2, data[0] == 0x05 else {
                    done(nil); return
                }
                if data[1] == 0x00 {
                    // no-auth выбран — сразу CONNECT.
                    socks5Connect(conn: conn, endpoint: endpoint,
                                  domain: domain, port: port, done: done)
                } else if data[1] == 0x02, let user = endpoint.user {
                    // user/pass: VER ULEN USER PLEN PASS
                    var auth = Data([0x01, UInt8(user.utf8.count)])
                    auth.append(Data(user.utf8))
                    let pass = endpoint.password ?? ""
                    auth.append(contentsOf: [UInt8(pass.utf8.count)])
                    auth.append(Data(pass.utf8))
                    conn.send(content: auth, completion: .contentProcessed { err2 in
                        guard err2 == nil else { done(nil); return }
                        conn.receive(minimumIncompleteLength: 2, maximumLength: 2) { resp, _, _, err3 in
                            guard err3 == nil, let resp, resp.count == 2,
                                  resp[1] == 0x00 else { done(nil); return }
                            socks5Connect(conn: conn, endpoint: endpoint,
                                          domain: domain, port: port, done: done)
                        }
                    })
                } else {
                    done(nil)
                }
            }
        })
    }

    /// CONNECT по имени (ATYP 0x03): VER CMD RSV ATYP LEN NAME PORT.
    private static func socks5Connect(conn: NWConnection, endpoint: ProxyEndpoint,
                                      domain: String, port: UInt16,
                                      done: @escaping (ProxyStream?) -> Void) {
        let name = Data(domain.utf8)
        var req = Data([0x05, 0x01, 0x00, 0x03, UInt8(name.count)])
        req.append(name)
        req.append(contentsOf: [UInt8((port >> 8) & 0xFF), UInt8(port & 0xFF)])
        conn.send(content: req, completion: .contentProcessed { err in
            guard err == nil else { done(nil); return }
            // Ответ: VER REP RSV ATYP + (адрес переменной длины) + PORT.
            // Читаем минимум 4 байта, затем добираем по ATYP.
            conn.receive(minimumIncompleteLength: 4, maximumLength: 4) { head, _, _, err in
                guard err == nil, let head, head.count == 4, head[1] == 0x00 else {
                    done(nil); return
                }
                let restLen: Int
                switch head[3] {
                case 0x01: restLen = 4 + 2   // IPv4 + port
                case 0x03:
                    // сначала длину имени
                    conn.receive(minimumIncompleteLength: 1, maximumLength: 1) { lenByte, _, _, e2 in
                        guard e2 == nil, let lenByte else { done(nil); return }
                        let n = Int(lenByte[0])
                        readTail(conn: conn, len: n + 2, done: done)
                    }
                    return
                case 0x04: restLen = 16 + 2  // IPv6 + port
                default: restLen = 2
                }
                readTail(conn: conn, len: restLen, done: done)
            }
        })
    }

    private static func readTail(conn: NWConnection, len: Int,
                                 done: @escaping (ProxyStream?) -> Void) {
        conn.receive(minimumIncompleteLength: len, maximumLength: len) { data, _, _, err in
            guard err == nil, data != nil else { done(nil); return }
            done(ProxyStream(conn: conn))
        }
    }

    // MARK: - HTTP CONNECT

    /// CONNECT domain:port HTTP/1.1 + базовая авторизация (если задана).
    private static func httpConnect(conn: NWConnection, endpoint: ProxyEndpoint,
                                    domain: String, port: UInt16,
                                    done: @escaping (ProxyStream?) -> Void) {
        var req = "CONNECT \(domain):\(port) HTTP/1.1\r\nHost: \(domain):\(port)\r\n"
        if let user = endpoint.user {
            let pass = endpoint.password ?? ""
            let token = Data("\(user):\(pass)".utf8).base64EncodedString()
            req += "Proxy-Authorization: Basic \(token)\r\n"
        }
        req += "\r\n"
        conn.send(content: Data(req.utf8), completion: .contentProcessed { err in
            guard err == nil else { done(nil); return }
            // Читаем до конца заголовков ответа (\r\n\r\n).
            readHttpResponse(conn: conn, acc: Data(), done: done)
        })
    }

    private static func readHttpResponse(conn: NWConnection, acc: Data,
                                         done: @escaping (ProxyStream?) -> Void) {
        conn.receive(minimumIncompleteLength: 1, maximumLength: 4096) { data, _, isComplete, err in
            guard err == nil, let data else { done(nil); return }
            var buf = acc
            buf.append(data)
            if let range = buf.range(of: Data("\r\n\r\n".utf8)) {
                // Статус-строка: HTTP/1.1 200 ...
                let statusLine = String(data: buf[buf.startIndex..<range.lowerBound],
                                        encoding: .utf8) ?? ""
                if statusLine.contains(" 200 ") {
                    done(ProxyStream(conn: conn))
                } else {
                    done(nil)
                }
                return
            }
            if isComplete { done(nil); return }
            if buf.count > 65536 { done(nil); return }
            readHttpResponse(conn: conn, acc: buf, done: done)
        }
    }
}

/// Живой прокси-поток: обёртка NWConnection c send/receive/close.
final class ProxyStream {
    private let conn: NWConnection
    private var closed = false

    init(conn: NWConnection) { self.conn = conn }

    func send(_ data: Data, completion: @escaping (Error?) -> Void) {
        guard !closed else { completion(nil); return }
        conn.send(content: data, completion: .contentProcessed { err in
            completion(err)
        })
    }

    func receive(min: Int, max: Int, completion: @escaping (Data?, Error?) -> Void) {
        guard !closed else { completion(nil, nil); return }
        conn.receive(minimumIncompleteLength: min, maximumLength: max) { data, _, _, err in
            completion(data, err)
        }
    }

    func close() {
        closed = true
        conn.cancel()
    }
}
