import Foundation

/// Минимальный парсер TLS ClientHello: достаёт SNI (extension 0x0000).
/// Никаких зависимостей, только чтение байтов — важно для лимита 50 МБ
/// NEPacketTunnelProvider: весь Go/sing-box-стек ради одного домена не нужен.
///
/// Зачем: нативные приложения (ChatGPT, Claude, Gemini) часто резолвят
/// домены через собственный DoH/DoT, минуя системный DNS. FakeIP тогда не
/// выдаётся, пакет уходит на РЕАЛЬНЫЙ IP. Если этот IP попал в туннель
/// (через includedRoutes по CIDR), мы всё равно видим первый TCP-пакет —
/// незашифрованный ClientHello — и можем передумать: увести поток в прокси
/// по извлечённому имени. Это и есть «routeOnly» из Happ/Xray.
enum TLSSNI {
    /// Первые байты TCP-потока от клиента. Возвращает домен в lowercase.
    /// nil = это не ClientHello, он обрезан, или SNI отсутствует.
    static func extract(from data: Data) -> String? {
        let bytes = [UInt8](data)
        guard bytes.count > 43,
              bytes[0] == 0x16,          // TLS Handshake
              bytes[5] == 0x01 else { return nil }  // ClientHello

        // Record Header (5) + Handshake Header (4) + Version (2) + Random (32)
        var offset = 43

        // Session ID
        guard offset < bytes.count else { return nil }
        let sessionIDLength = Int(bytes[offset])
        offset += 1 + sessionIDLength
        guard offset + 2 <= bytes.count else { return nil }

        // Cipher Suites
        let cipherSuitesLength = (Int(bytes[offset]) << 8) | Int(bytes[offset + 1])
        offset += 2 + cipherSuitesLength
        guard offset + 1 <= bytes.count else { return nil }

        // Compression Methods
        let compressionMethodsLength = Int(bytes[offset])
        offset += 1 + compressionMethodsLength
        guard offset + 2 <= bytes.count else { return nil }

        // Extensions block
        let extensionsLength = (Int(bytes[offset]) << 8) | Int(bytes[offset + 1])
        offset += 2
        let extensionsEnd = min(offset + extensionsLength, bytes.count)

        while offset + 4 <= extensionsEnd {
            let extType = (Int(bytes[offset]) << 8) | Int(bytes[offset + 1])
            let extLen = (Int(bytes[offset + 2]) << 8) | Int(bytes[offset + 3])
            offset += 4
            guard offset + extLen <= extensionsEnd else { break }

            if extType == 0x0000, extLen >= 5 {
                // Server Name List: 2 байта длина списка, затем
                // [1 байт type=0x00][2 байта длина][имя]
                let nameType = bytes[offset + 2]
                let nameLen = (Int(bytes[offset + 3]) << 8) | Int(bytes[offset + 4])
                if nameType == 0x00, offset + 5 + nameLen <= extensionsEnd, nameLen > 0 {
                    let domainBytes = bytes[(offset + 5)..<(offset + 5 + nameLen)]
                    return String(bytes: domainBytes, encoding: .utf8)?.lowercased()
                }
            }
            offset += extLen
        }
        return nil
    }
}
