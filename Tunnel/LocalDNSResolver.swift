import Foundation
import Darwin
import Network

/// Локальный DNS-резолвер туннеля: перехватывает UDP:53 запросы из
/// packetFlow, применяет hosts-rewrite правила, непокрытые имена
/// гонит на upstream (выбранный DNS из настроек или системный).
///
/// Схема: dnsSettings туннеля указывает на адрес TUN-интерфейса
/// (198.18.0.2) — система направляет DNS-запросы в туннель, они
/// прилетают в readLoop как UDP-пакеты. Здесь парсим вопрос, матЧИМ
/// по таблице rewrites, отвечаем сами или форвардим на upstream.
///
/// Дисциплина потоков: tryHandle вызывается на lwipQueue; upstream-
/// сокеты работают на global-очереди, ответы доставляются через
/// writePacket (packetFlow.writePackets потокобезопасен).
final class LocalDNSResolver {
    /// Таблица rewrites: имя (lowercase) → IPv4 (big-endian u32).
    private var rewrites: [String: UInt32] = [:]
    /// Upstream-серверы (IP). Пусто = системный DNS.
    private var upstreams: [String] = []
    private static let upstreamTimeout: TimeInterval = 3
    private let writePacket: (Data) -> Void
    private(set) var statRewritten: UInt64 = 0
    private(set) var statForwarded: UInt64 = 0
    private(set) var statFailed: UInt64 = 0
    /// DoT-upstream: SNI-хост (nil = UDP:53). TLS-коннект к IP:853.
    private var upstreamDoTHost: String?
    /// DoH-upstream: URL (nil = не DoH). Запросы POST/GET-типа wireformat.
    private var upstreamDoHURL: URL?
    /// Страховочный UDP-листенер на 198.18.0.2:53: если ядро доставляет
    /// пакеты на TUN-адрес локально (а не через packetFlow), их ловит он.
    /// Оба пути валидны; ядро iOS выбирает один — сработает занятый.
    private var listenSock: Int32 = -1
    /// Очередь листенера.
    private let listenQueue = DispatchQueue(label: "com.l1ratch.WSBridge.localdns")

    init(writePacket: @escaping (Data) -> Void) {
        self.writePacket = writePacket
    }

    /// Поднимает страховочный UDP-сокет на 198.18.0.2:53. Вызывается из
    /// startTunnel. Пакеты, пришедшие в сокет, — это чистый DNS (без
    /// IP/UDP-обвязки): обрабатываем и отвечаем напрямую в сокет.
    func startListener() {
        let sock = socket(AF_INET, SOCK_DGRAM, 0)
        guard sock >= 0 else {
            EventLog.append("localdns:listen:socket=-1")
            return
        }
        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = in_port_t(53).bigEndian
        addr.sin_addr = in_addr(s_addr: 0xC6120002)  // 198.18.0.2 big-endian
        let bindResult = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                bind(sock, sa, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard bindResult == 0 else {
            EventLog.append("localdns:listen:bind=\(bindResult)")
            close(sock)
            return
        }
        listenSock = sock
        EventLog.append("localdns:listen=ok")
        receiveLoop()
    }

    /// Останавливает листенер (stopTunnel).
    func stopListener() {
        if listenSock >= 0 {
            close(listenSock)
            listenSock = -1
        }
    }

    /// Приём из страховочного сокета: чистый DNS-запрос (без IP/UDP).
    private func receiveLoop() {
        let sock = listenSock
        guard sock >= 0 else { return }
        listenQueue.async { [weak self] in
            guard let self else { return }
            var buf = [UInt8](repeating: 0, count: 4096)
            var srcAddr = sockaddr_in()
            var addrLen = socklen_t(MemoryLayout<sockaddr_in>.size)
            let n = withUnsafeMutablePointer(to: &srcAddr) { ptr in
                ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                    recvfrom(sock, &buf, buf.count, 0, sa, &addrLen)
                }
            }
            guard n > 12 else { return }
            let query = Data(buf[0..<n])
            self.handleSocketQuery(query, from: srcAddr)
            // Следующий приём только если сокет ещё жив.
            if self.listenSock == sock {
                self.receiveLoop()
            }
        }
    }

    /// Обработка запроса из сокета: тот же путь rewrites → upstream,
    /// ответ уходит напрямую в сокет (не в packetFlow).
    private func handleSocketQuery(_ question: Data, from src: sockaddr_in) {
        guard let qname = Self.parseQName(question) else { return }
        let name = qname.lowercased()
        let qtype = (Int(question[question.count - 4]) << 8)
                  | Int(question[question.count - 3])
        if qtype == 28 {
            replyToSocket(Self.buildReply(question: question, answer: Data(), rcode: 0), to: src)
            statRewritten += 1
            return
        }
        if qtype == 1, let ip = rewrites[name] {
            var answer = Data()
            answer.append(contentsOf: [0xC0, 0x0C])
            answer.append(contentsOf: [0, 1])
            answer.append(contentsOf: [0, 1])
            answer.append(contentsOf: [0, 0, 0, 60])
            answer.append(contentsOf: [0, 4])
            answer.append(contentsOf: IPv4Addr.bytes(ip))
            replyToSocket(Self.buildReply(question: question, answer: answer, rcode: 0), to: src)
            statRewritten += 1
            return
        }
        // Форвард: ответ придёт по адресу источника.
        statForwarded += 1
        if upstreams.isEmpty {
            DispatchQueue.global(qos: .userInitiated).async { [weak self] in
                guard let self else { return }
                if let answer = Self.systemQuery(question) {
                    self.replyToSocket(answer, to: src)
                } else {
                    self.statFailed += 1
                }
            }
        } else {
            let servers = upstreams
            DispatchQueue.global(qos: .userInitiated).async { [weak self] in
                guard let self else { return }
                for server in servers {
                    if let answer = Self.udpQuery(question, server: server) {
                        self.replyToSocket(answer, to: src)
                        return
                    }
                }
                self.statFailed += 1
            }
        }
    }

    /// Ответ в сокет по адресу источника.
    private func replyToSocket(_ dns: Data, to src: sockaddr_in) {
        guard listenSock >= 0 else { return }
        var addr = src
        let sent = dns.withUnsafeBytes { ptr in
            withUnsafePointer(to: &addr) { aPtr in
                aPtr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                    sendto(listenSock, ptr.baseAddress, dns.count, 0, sa,
                           socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
        }
        if sent != dns.count {
            statFailed += 1
        }
    }

    /// Сборка DNS-ответа из вопроса (заголовок + вопрос + answer).
    /// Выделен в статический: используется обоими путями (packetFlow и
    /// сокет).
    static func buildReply(question: Data, answer: Data, rcode: UInt8) -> Data {
        var dns = Data(question.prefix(12))
        dns[2] = (question[2] & 0x01) | 0x80 | (rcode << 4)
        dns[3] = 0
        let ancount: UInt16 = UInt16(answer.isEmpty ? 0 : 1)
        dns[6] = UInt8((ancount >> 8) & 0xFF)
        dns[7] = UInt8(ancount & 0xFF)
        dns[8] = 0; dns[9] = 0
        dns[10] = 0; dns[11] = 0
        dns.append(question.suffix(from: 12))
        dns.append(answer)
        return dns
    }

    /// Конфигурация на старте туннеля (один раз, до первого пакета).
    /// - Parameters:
    ///   - hostsText: текст hosts-файла (таблица rewrites).
    ///   - upstreams: IP-адреса upstream DNS (UDP:53 или DoT-IP:853).
    ///   - doT: SNI-хост для TLS-upstream (nil = UDP:53).
    ///   - doHURL: URL DoH-upstream (альтернатива DoT; nil = не DoH).
    func configure(hostsText: String?, upstreams: [String],
                   doT: String? = nil, doHURL: String? = nil) {
        self.upstreams = upstreams
        self.upstreamDoTHost = doT
        self.upstreamDoHURL = doHURL.map { URL(string: $0) ?? nil }
        var table: [String: UInt32] = [:]
        if let text = hostsText {
            for rawLine in text.split(separator: "\n") {
                let line = rawLine.trimmingCharacters(in: .whitespaces)
                if line.isEmpty || line.hasPrefix("#") { continue }
                // Формат hosts: «IP name [aliases…]», разделители
                // пробел/таб (в полях могут быть оба).
                let parts = line.split(whereSeparator: { $0 == " " || $0 == "\t" })
                guard parts.count >= 2 else { continue }
                // Только IPv4: наш стек v4-only.
                guard let ip = IPv4Addr.parse(String(parts[0])) else { continue }
                for namePart in parts.dropFirst() {
                    let name = namePart.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "."))
                    guard !name.isEmpty, name.count <= 253 else { continue }
                    table[name] = ip
                }
            }
        }
        self.rewrites = table
    }

    var rewriteCount: Int { rewrites.count }

    // MARK: - Перехват из packetFlow

    /// Проверяет, является ли пакет DNS-запросом к нашему локальному
    /// серверу (UDP, dst = TUN-адрес 198.18.0.2, порт 53). Возвращает
    /// true, если пакет потреблён резолвером. Вызывается на lwipQueue.
    func tryHandle(_ packet: Data) -> Bool {
        // Минимум: IP(20) + UDP(8) + DNS-заголовок(12)
        guard packet.count >= 40 else { return false }
        guard packet[9] == 17 else { return false }   // proto = UDP
        let ihl = Int(packet[0] & 0x0F) * 4
        guard ihl >= 20, ihl == 20, packet.count > ihl + 8 else { return false }
        // dst IP = 198.18.0.2 (наш TUN-адрес)
        guard packet[16] == 198, packet[17] == 18,
              packet[18] == 0, packet[19] == 2 else { return false }
        let dstPort = (Int(packet[ihl + 2]) << 8) | Int(packet[ihl + 3])
        guard dstPort == 53 else { return false }

        let dnsStart = ihl + 8
        let question = packet.subdata(in: dnsStart..<packet.count)
        guard question.count >= 17 else { return false }  // 12 + q + type/class
        let qdcount = (Int(question[4]) << 8) | Int(question[5])
        guard qdcount == 1 else { return false }

        guard let qname = Self.parseQName(question) else { return false }
        let name = qname.lowercased()
        // qtype/qclass — последние 4 байта вопроса.
        let qtype = (Int(question[question.count - 4]) << 8)
                  | Int(question[question.count - 3])
        let qclass = (Int(question[question.count - 2]) << 8)
                   | Int(question[question.count - 1])

        // AAAA (28): стек v4-only, отвечаем NOERROR без записей —
        // клиент не должен ретраить IPv6 вечно.
        if qtype == 28 {
            reply(packet: packet, question: question, answer: Data(), rcode: 0)
            statRewritten += 1
            return true
        }

        // A (1): ищем в rewrites.
        if qtype == 1, qclass == 1, let ip = rewrites[name] {
            var answer = Data()
            answer.append(contentsOf: [0xC0, 0x0C])   // name: ptr на вопрос
            answer.append(contentsOf: [0, 1])          // type A
            answer.append(contentsOf: [0, 1])          // class IN
            answer.append(contentsOf: [0, 0, 0, 60])   // TTL 60
            answer.append(contentsOf: [0, 4])          // rdlength
            answer.append(contentsOf: IPv4Addr.bytes(ip))
            reply(packet: packet, question: question, answer: answer, rcode: 0)
            statRewritten += 1
            return true
        }

        // Нет правила (или не-A запрос): форвард на upstream.
        statForwarded += 1
        forward(question: question, originalPacket: packet, name: name)
        return true
    }

    // MARK: - Сборка ответа (packetFlow-путь)

    /// Собирает DNS-ответ и пишет IP/UDP-пакет обратно в туннель с
    /// swap src/dst. packetFlow.writePackets потокобезопасен.
    private func reply(packet: Data, question: Data, answer: Data, rcode: UInt8) {
        let dns = Self.buildReply(question: question, answer: answer, rcode: rcode)
        sendToTunnel(dns: dns, original: packet)
    }

    /// Ответ upstream целиком: подменяем ID на клиентский, QR=1,
    /// переупаковываем в IP/UDP в туннель.
    private func replyFromUpstream(_ upstreamAnswer: Data,
                                   question: Data, original packet: Data) {
        guard upstreamAnswer.count >= 12 else { return }
        var fixed = upstreamAnswer
        fixed[0] = question[0]   // ID клиента
        fixed[1] = question[1]
        fixed[2] = fixed[2] | 0x80
        sendToTunnel(dns: fixed, original: packet)
    }

    /// Оборачивает DNS-сообщение в IP/UDP с swap src/dst и пишет в
    /// packetFlow. Общая для локальных и upstream-ответов.
    private func sendToTunnel(dns: Data, original packet: Data) {
        let ihl = Int(packet[0] & 0x0F) * 4
        var ip = Data(count: 20)
        ip[0] = 0x45
        let totalLen = 20 + 8 + dns.count
        ip[2] = UInt8((totalLen >> 8) & 0xFF)
        ip[3] = UInt8(totalLen & 0xFF)
        ip[4] = packet[4]; ip[5] = packet[5]       // IP ID из запроса
        ip[6] = 0x40; ip[7] = 0                    // DF
        ip[8] = 64                                  // TTL
        ip[9] = 17                                  // UDP
        ip.replaceSubrange(12..<16, with: packet.subdata(in: 16..<20))  // src = клиент dst
        ip.replaceSubrange(16..<20, with: packet.subdata(in: 12..<16))  // dst = клиент src
        var sum: UInt32 = 0
        for i in stride(from: 0, to: 20, by: 2) {
            sum += (UInt32(ip[i]) << 8) | UInt32(ip[i + 1])
        }
        while sum >> 16 != 0 { sum = (sum & 0xFFFF) + (sum >> 16) }
        let csum = ~sum & 0xFFFF
        ip[10] = UInt8((csum >> 8) & 0xFF)
        ip[11] = UInt8(csum & 0xFF)

        var udp = Data(count: 8)
        // sport = 53 (порт запроса), dport = порт клиента
        udp.replaceSubrange(0..<2, with: packet.subdata(in: (ihl + 2)..<(ihl + 4)))
        udp.replaceSubrange(2..<4, with: packet.subdata(in: ihl..<(ihl + 2)))
        let udpLen = 8 + dns.count
        udp[4] = UInt8((udpLen >> 8) & 0xFF)
        udp[5] = UInt8(udpLen & 0xFF)
        udp[6] = 0; udp[7] = 0   // UDP checksum = 0 (допустимо для IPv4)

        var out = ip
        out.append(udp)
        out.append(dns)
        writePacket(out)
    }

    // MARK: - Форвард

    /// Пересылает вопрос на upstream (UDP:53) или системный резолвер.
    private func forward(question: Data, originalPacket: Data, name: String) {
        if upstreams.isEmpty {
            // Системный upstream: пересылаем на res_query — система
            // использует свой DNS-путь, туннель его не маршрутизирует.
            DispatchQueue.global(qos: .userInitiated).async { [weak self] in
                guard let self else { return }
                guard let answer = Self.systemQuery(question) else {
                    self.reply(packet: originalPacket, question: question,
                               answer: Data(), rcode: 2)  // SERVFAIL
                    self.statFailed += 1
                    return
                }
                self.replyFromUpstream(answer, question: question,
                                       original: originalPacket)
            }
            return
        }
        // Конкретный upstream: транспорт по конфигурации (DoT/DoH/UDP).
        let servers = upstreams
        let doT = upstreamDoTHost
        let doH = upstreamDoHURL
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self else { return }
            // DoH: POST к URL, тело — wireformat-запрос.
            if let doH {
                if let answer = Self.doHQuery(question, url: doH) {
                    self.replyFromUpstream(answer, question: question,
                                           original: originalPacket)
                    return
                }
            } else if let doT {
                // DoT: TLS к IP:853 с SNI; фрейминг — 2-байтовый length
                // prefix (RFC 7858). Failover по IP.
                for server in servers {
                    if let answer = Self.doTQuery(question, server: server, sni: doT) {
                        self.replyFromUpstream(answer, question: question,
                                               original: originalPacket)
                        return
                    }
                }
            } else {
                // UDP: сырой :53. Failover по списку.
                for server in servers {
                    if let answer = Self.udpQuery(question, server: server) {
                        self.replyFromUpstream(answer, question: question,
                                               original: originalPacket)
                        return
                    }
                }
            }
            self.reply(packet: originalPacket, question: question,
                       answer: Data(), rcode: 2)  // SERVFAIL
            self.statFailed += 1
        }
    }

    /// DoT-запрос: TLS-коннект к server:853 с SNI, RFC 7858 фрейминг
    /// (2-байтовый big-endian length перед каждым сообщением).
    /// Синхронный, на global-очереди.
    private static func doTQuery(_ question: Data, server: String, sni: String) -> Data? {
        // Семафор: таймаут общий (upstreamTimeout + коннект).
        let sem = DispatchSemaphore(value: 0)
        var answer: Data?
        let tlsOpts = NWProtocolTLS.Options()
        let sec = tlsOpts.securityProtocolOptions
        _ = sni.withCString { sniC in
            sec_protocol_options_set_tls_server_name(sec, sniC)
        }
        let params = NWParameters(tls: tlsOpts)
        let conn = NWConnection(
            host: NWEndpoint.Host(server),
            port: NWEndpoint.Port(rawValue: 853)!,
            using: params)
        conn.stateUpdateHandler = { state in
            switch state {
            case .ready:
                // Отправляем: length-prefix + запрос.
                var frame = Data()
                frame.append(contentsOf: [UInt8((question.count >> 8) & 0xFF),
                                          UInt8(question.count & 0xFF)])
                frame.append(question)
                conn.send(content: frame, completion: .contentProcessed { err in
                    if err != nil { sem.signal(); return }
                    Self.receiveDoTFrame(conn) { data in
                        answer = data
                        sem.signal()
                    }
                })
            case .failed, .cancelled:
                sem.signal()
            default:
                break
            }
        }
        conn.start(queue: .global(qos: .userInitiated))
        // Таймаут: освобождаем ожидание, коннект отменяем после.
        _ = sem.wait(timeout: .now() + upstreamTimeout + 1)
        conn.cancel()
        return answer
    }

    /// Приём одного DoT-фрейма: 2-байтовый length + сообщение.
    private static func receiveDoTFrame(_ conn: NWConnection, done: @escaping (Data?) -> Void) {
        conn.receive(minimumIncompleteLength: 2, maximumLength: 2) { data, _, _, err in
            guard let lenBytes = data, lenBytes.count == 2, err == nil else {
                done(nil); return
            }
            let len = (Int(lenBytes[0]) << 8) | Int(lenBytes[1])
            guard len > 12, len < 65536 else { done(nil); return }
            conn.receive(minimumIncompleteLength: len, maximumLength: len) { msg, _, _, err2 in
                guard let msg = msg, msg.count == len, err2 == nil else {
                    done(nil); return
                }
                done(msg)
            }
        }
    }

    /// DoH-запрос: POST wireformat-тела к URL (RFC 8484). Синхронная
    /// обёртка над URLSession.
    private static func doHQuery(_ question: Data, url: URL) -> Data? {
        let sem = DispatchSemaphore(value: 0)
        var answer: Data?
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/dns-message", forHTTPHeaderField: "Content-Type")
        request.timeoutInterval = upstreamTimeout
        request.httpBody = question
        let task = URLSession.shared.dataTask(with: request) { data, response, _ in
            if let http = response as? HTTPURLResponse,
               http.statusCode == 200,
               let data, data.count > 12,
               let mime = (http.value(forHTTPHeaderField: "Content-Type")),
               mime.contains("application/dns-message") {
                answer = data
            }
            sem.signal()
        }
        task.resume()
        _ = sem.wait(timeout: .now() + upstreamTimeout + 1)
        return answer
    }

    /// UDP-запрос к одному серверу с таймаутом. Синхронный вызов на
    /// global-очереди.
    private static func udpQuery(_ question: Data, server: String) -> Data? {
        let sock = socket(AF_INET, SOCK_DGRAM, 0)
        guard sock >= 0 else { return nil }
        defer { close(sock) }
        var tv = timeval(tv_sec: Int(upstreamTimeout), tv_usec: 0)
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = in_port_t(53).bigEndian
        guard inet_pton(AF_INET, server, &addr.sin_addr) == 1 else { return nil }
        let sent = question.withUnsafeBytes { ptr in
            withUnsafePointer(to: &addr) { aPtr in
                aPtr.withMemoryRebound(to: sockaddr.self, capacity: 1) { saPtr in
                    sendto(sock, ptr.baseAddress, question.count, 0, saPtr,
                           socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
        }
        guard sent == question.count else { return nil }
        var buf = [UInt8](repeating: 0, count: 4096)
        let received = recvfrom(sock, &buf, buf.count, 0, nil, nil)
        guard received > 12 else { return nil }
        return Data(buf[0..<received])
    }

    /// Системный DNS через getaddrinfo: система шлёт запрос своим
    /// резолвером (вне маршрутов туннеля), мы получаем готовые адреса
    /// и сами собираем DNS-ответ. Только A-запросы (getaddrinfo IPv4);
    /// прочие типы — пустой NOERROR.
    private static func systemQuery(_ question: Data) -> Data? {
        guard let name = parseQName(question) else { return nil }
        var hints = addrinfo()
        hints.ai_family = AF_INET
        var res: UnsafeMutablePointer<addrinfo>?
        let rc = name.withCString { cName in
            getaddrinfo(cName, nil, &hints, &res)
        }
        guard rc == 0, res != nil else { return nil }
        defer { freeaddrinfo(res) }
        // Собираем A-записи из всех адресов (IPv4).
        var ips: [[UInt8]] = []
        var cur = res
        while let ai = cur {
            if ai.pointee.ai_family == AF_INET,
               let sa = ai.pointee.ai_addr {
                sa.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { sin in
                    let addr = sin.pointee.sin_addr.s_addr
                    // s_addr в памяти little-endian на байтовом порядке:
                    // байты уже в сетевом порядке — берём как лежат.
                    withUnsafeBytes(of: addr) { raw in
                        var ip = [UInt8](repeating: 0, count: 4)
                        for i in 0..<4 where i < raw.count { ip[i] = raw[i] }
                        ips.append(ip)
                    }
                }
            }
            cur = ai.pointee.ai_next
        }
        guard !ips.isEmpty else { return nil }
        // Ответ: заголовок + вопрос + N A-записей.
        var dns = Data(question.prefix(12))
        dns[2] = (question[2] & 0x01) | 0x80   // QR=1, rcode 0
        dns[3] = 0
        let ancount = UInt16(min(ips.count, 255))
        dns[6] = UInt8((ancount >> 8) & 0xFF)
        dns[7] = UInt8(ancount & 0xFF)
        dns[8] = 0; dns[9] = 0
        dns[10] = 0; dns[11] = 0
        dns.append(question.suffix(from: 12))
        for ip in ips.prefix(255) {
            dns.append(contentsOf: [0xC0, 0x0C])   // name: ptr на вопрос
            dns.append(contentsOf: [0, 1])          // type A
            dns.append(contentsOf: [0, 1])          // class IN
            dns.append(contentsOf: [0, 0, 0, 60])   // TTL 60
            dns.append(contentsOf: [0, 4])          // rdlength
            dns.append(contentsOf: ip)
        }
        return dns
    }

    // MARK: - Парсинг DNS

    /// Имя из question section. В запросах клиента сжатия не бывает
    /// (это привилегия серверов), но на всякий случай ограничиваем
    /// проход байтами вопроса.
    static func parseQName(_ dns: Data) -> String? {
        guard dns.count > 12 else { return nil }
        var labels: [String] = []
        var i = 12
        // Вопрос кончается за 4 байта до конца (type + class).
        while i < dns.count - 4 {
            let len = Int(dns[i])
            guard len > 0, len <= 63 else { break }
            guard i + 1 + len <= dns.count - 4 else { return nil }
            guard let label = String(data: dns.subdata(in: (i+1)..<(i+1+len)),
                                     encoding: .utf8) else { return nil }
            labels.append(label)
            i += 1 + len
        }
        guard !labels.isEmpty else { return nil }
        return labels.joined(separator: ".")
    }
}

/// IPv4-утилиты для hosts-таблицы.
enum IPv4Addr {
    static func parse(_ str: String) -> UInt32? {
        let parts = str.split(separator: ".")
        guard parts.count == 4 else { return nil }
        var v: UInt32 = 0
        for p in parts {
            guard let octet = UInt32(p), octet <= 255 else { return nil }
            v = (v << 8) | octet
        }
        return v
    }

    static func bytes(_ v: UInt32) -> [UInt8] {
        [UInt8((v >> 24) & 0xFF), UInt8((v >> 16) & 0xFF),
         UInt8((v >> 8) & 0xFF), UInt8(v & 0xFF)]
    }
}
