import Foundation

/// Перехватывает DNS-запросы (UDP:53) из туннеля и форвардит их напрямую
/// на указанный DNS-сервер через BSD UDP socket (работает из расширения
/// без entitlements; трафик расширения не проходит через свой же туннель).
/// Ответы возвращаются обратно в туннель.
final class DNSForwarder {
    private let dnsServers: [String]
    private let writePacket: (Data) -> Void
    private let queue = DispatchQueue(label: "dns-forwarder", qos: .userInitiated)

    init(dnsServers: [String], writePacket: @escaping (Data) -> Void) {
        self.dnsServers = dnsServers
        self.writePacket = writePacket
    }

    /// Проверяет, является ли пакет DNS-запросом (UDP:53).
    /// Возвращает true если пакет перехвачен и обработан.
    func tryHandle(_ packet: Data) -> Bool {
        guard packet.count > 28 else { return false }
        let ihl = Int(packet[0] & 0x0F) * 4
        guard packet[9] == 17 else { return false } // UDP

        let udpStart = ihl
        guard packet.count > udpStart + 8 else { return false }
        let dstPort = Int(packet[udpStart + 2]) << 8 | Int(packet[udpStart + 3])
        guard dstPort == 53 else { return false }

        let dnsPayload = packet.subdata(in: (udpStart + 8)..<packet.count)
        guard !dnsPayload.isEmpty else { return false }
        guard let server = dnsServers.first else { return false }

        NSLog("[WSBridge] DNS: intercepting query (%d bytes) -> %@", dnsPayload.count, server)

        queue.async {
            self.forward(dnsPayload: dnsPayload, originalPacket: packet, server: server)
        }
        return true
    }

    private func forward(dnsPayload: Data, originalPacket: Data, server: String) {
        let sock = socket(AF_INET, SOCK_DGRAM, 0)
        guard sock >= 0 else {
            NSLog("[WSBridge] DNS: socket() failed")
            return
        }
        defer { close(sock) }

        // Таймаут 3 секунды
        var tv = timeval(tv_sec: 3, tv_usec: 0)
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))

        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = in_port_t(53).bigEndian
        guard inet_pton(AF_INET, server, &addr.sin_addr) == 1 else {
            NSLog("[WSBridge] DNS: inet_pton failed for %@", server)
            return
        }

        let sent = dnsPayload.withUnsafeBytes { ptr -> Int in
            withUnsafePointer(to: &addr) { addrPtr in
                addrPtr.withMemoryRebound(to: sockaddr.self, capacity: 1) { saPtr in
                    sendto(sock, ptr.baseAddress, dnsPayload.count, 0, saPtr, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
        }
        guard sent == dnsPayload.count else {
            NSLog("[WSBridge] DNS: sendto failed (%d)", sent)
            return
        }
        NSLog("[WSBridge] DNS: sent %d bytes to %@", sent, server)

        // Ждём ответ
        var buf = [UInt8](repeating: 0, count: 4096)
        let received = recvfrom(sock, &buf, buf.count, 0, nil, nil)
        guard received > 0 else {
            NSLog("[WSBridge] DNS: recvfrom failed/timeout (%d)", received)
            return
        }
        NSLog("[WSBridge] DNS: received %d bytes from %@", received, server)

        let response = Data(buf[0..<received])
        wrapAndSend(dnsResponse: response, originalPacket: originalPacket)
    }

    /// Оборачивает DNS-ответ обратно в IP/UDP пакет (swap src/dst) и отправляет в туннель.
    private func wrapAndSend(dnsResponse: Data, originalPacket: Data) {
        let ihl = Int(originalPacket[0] & 0x0F) * 4
        let udpStart = ihl

        let srcIP = originalPacket.subdata(in: 12..<16)
        let dstIP = originalPacket.subdata(in: 16..<20)
        let srcPort = originalPacket.subdata(in: udpStart..<udpStart + 2)
        let dstPort = originalPacket.subdata(in: udpStart + 2..<udpStart + 4)

        var ipHeader = Data(count: 20)
        ipHeader[0] = 0x45
        let totalLen = 20 + 8 + dnsResponse.count
        ipHeader[2] = UInt8(totalLen >> 8)
        ipHeader[3] = UInt8(totalLen & 0xFF)
        ipHeader[8] = 64 // TTL
        ipHeader[9] = 17 // UDP
        ipHeader.replaceSubrange(12..<16, with: dstIP)
        ipHeader.replaceSubrange(16..<20, with: srcIP)

        let ipChecksum = computeChecksum(ipHeader)
        ipHeader[10] = UInt8(ipChecksum >> 8)
        ipHeader[11] = UInt8(ipChecksum & 0xFF)

        var udpHeader = Data(count: 8)
        udpHeader.replaceSubrange(0..<2, with: dstPort)
        udpHeader.replaceSubrange(2..<4, with: srcPort)
        let udpLen = 8 + dnsResponse.count
        udpHeader[4] = UInt8(udpLen >> 8)
        udpHeader[5] = UInt8(udpLen & 0xFF)

        var packet = ipHeader
        packet.append(udpHeader)
        packet.append(dnsResponse)

        writePacket(packet)
        NSLog("[WSBridge] DNS: response wrapped and sent to tunnel (%d bytes)", packet.count)
    }

    private func computeChecksum(_ data: Data) -> UInt16 {
        var sum: UInt32 = 0
        let bytes = [UInt8](data)
        var i = 0
        while i < bytes.count - 1 {
            sum += UInt32(bytes[i]) << 8 | UInt32(bytes[i + 1])
            i += 2
        }
        if bytes.count % 2 == 1 {
            sum += UInt32(bytes[bytes.count - 1]) << 8
        }
        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16)
        }
        return UInt16(~sum & 0xFFFF)
    }

    func stop() {}
}
