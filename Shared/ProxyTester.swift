import Foundation
import Network

/// Тест прокси из app-слоя: полный SOCKS5/HTTP-хендшейк до этапа
/// CONNECT (без реального коннекта к цели — достаточно убедиться,
/// что прокси жив, авторизация проходит и CONNECT принимает).
enum ProxyTester {
    /// Возвращает задержку хендшейка в мс или nil (мертв/бит формат).
    static func probe(_ endpoint: ProxyEndpoint) async -> Int? {
        let start = DispatchTime.now()
        let ok: Bool = await withCheckedContinuation { (cont: CheckedContinuation<Bool, Never>) in
            handshake(endpoint: endpoint) { success in
                cont.resume(returning: success)
            }
        }
        guard ok else { return nil }
        return Int((DispatchTime.now().uptimeNanoseconds - start.uptimeNanoseconds) / 1_000_000)
    }

    /// Хендшейк SOCKS5: greeting → (auth) → CONNECT example.com:80.
    /// HTTP: CONNECT example.com:80 → ждём "200".
    private static func handshake(endpoint: ProxyEndpoint,
                                   done: @escaping (Bool) -> Void) {
        let conn = NWConnection(host: NWEndpoint.Host(endpoint.host),
                                port: NWEndpoint.Port(rawValue: endpoint.port)!,
                                using: .tcp)
        var finished = false
        let lock = NSLock()
        func finishOnce(_ v: Bool) {
            lock.lock(); defer { lock.unlock() }
            guard !finished else { return }
            finished = true
            conn.cancel()
            done(v)
        }
        conn.stateUpdateHandler = { state in
            switch state {
            case .ready:
                switch endpoint.kind {
                case .socks5:
                    socks5(conn: conn, endpoint: endpoint, done: finishOnce)
                case .http:
                    http(conn: conn, endpoint: endpoint, done: finishOnce)
                }
            case .failed, .cancelled:
                finishOnce(false)
            default:
                break
            }
        }
        conn.start(queue: .global(qos: .userInitiated))
        DispatchQueue.global().asyncAfter(deadline: .now() + 5) { finishOnce(false) }
    }

    private static func socks5(conn: NWConnection, endpoint: ProxyEndpoint,
                               done: @escaping (Bool) -> Void) {
        let hasAuth = endpoint.user != nil
        var greeting = Data([0x05])
        if hasAuth {
            greeting.append(contentsOf: [2, 0x01, 0x02])
        } else {
            greeting.append(contentsOf: [1, 0x00])
        }
        conn.send(content: greeting, completion: .contentProcessed { err in
            guard err == nil else { done(false); return }
            conn.receive(minimumIncompleteLength: 2, maximumLength: 2) { data, _, _, err in
                guard err == nil, let data, data.count == 2, data[0] == 0x05 else { done(false); return }
                if data[1] == 0x00 {
                    connectCmd(conn: conn, endpoint: endpoint, done: done)
                } else if data[1] == 0x02, let user = endpoint.user {
                    var auth = Data([0x01, UInt8(user.utf8.count)])
                    auth.append(Data(user.utf8))
                    let pass = endpoint.password ?? ""
                    auth.append(contentsOf: [UInt8(pass.utf8.count)])
                    auth.append(Data(pass.utf8))
                    conn.send(content: auth, completion: .contentProcessed { err2 in
                        guard err2 == nil else { done(false); return }
                        conn.receive(minimumIncompleteLength: 2, maximumLength: 2) { resp, _, _, err3 in
                            guard err3 == nil, let resp, resp.count == 2, resp[1] == 0x00 else {
                                done(false); return
                            }
                            connectCmd(conn: conn, endpoint: endpoint, done: done)
                        }
                    })
                } else {
                    done(false)
                }
            }
        })
    }

    /// CONNECT example.com:80 (ATYP имя) — достаточно REP=0.
    private static func connectCmd(conn: NWConnection, endpoint: ProxyEndpoint,
                                   done: @escaping (Bool) -> Void) {
        let name = Data("example.com".utf8)
        var req = Data([0x05, 0x01, 0x00, 0x03, UInt8(name.count)])
        req.append(name)
        req.append(contentsOf: [0x00, 0x50])  // порт 80
        conn.send(content: req, completion: .contentProcessed { err in
            guard err == nil else { done(false); return }
            conn.receive(minimumIncompleteLength: 4, maximumLength: 4) { head, _, _, err2 in
                guard err2 == nil, let head, head.count == 4, head[1] == 0x00 else {
                    done(false); return
                }
                done(true)
            }
        })
    }

    private static func http(conn: NWConnection, endpoint: ProxyEndpoint,
                             done: @escaping (Bool) -> Void) {
        var req = "CONNECT example.com:80 HTTP/1.1\r\nHost: example.com\r\n"
        if let user = endpoint.user {
            let pass = endpoint.password ?? ""
            let token = Data("\(user):\(pass)".utf8).base64EncodedString()
            req += "Proxy-Authorization: Basic \(token)\r\n"
        }
        req += "\r\n"
        conn.send(content: Data(req.utf8), completion: .contentProcessed { err in
            guard err == nil else { done(false); return }
            conn.receive(minimumIncompleteLength: 12, maximumLength: 4096) { data, _, _, err2 in
                guard err2 == nil, let data else { done(false); return }
                let head = String(data: data.prefix(min(data.count, 64)), encoding: .utf8) ?? ""
                done(head.contains(" 200 "))
            }
        })
    }
}
