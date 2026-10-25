import Foundation

/// Парсинг 64-байтного obfuscated init пакета MTProto.
/// Ключи: key = init[8:40], iv = init[40:56] (standard obfuscation, без secret).
/// После расшифровки: proto_tag at [56:60], dc_idx at [60:62].
enum InitParser {
    static let handshakeLen = 64
    static let skipLen = 8
    static let prekeyLen = 32
    static let ivLen = 16
    static let protoTagPos = 56
    static let dcIdxPos = 60

    struct ParsedInit {
        let dcId: Int
        let isMedia: Bool
        let isTestDC: Bool
        let protoTag: UInt32
        let key: Data   // init[8:40] — для MsgSplitter
        let iv: Data    // init[40:56] — для MsgSplitter
    }

    /// Парсит init пакет. Возвращает nil если это не валидный MTProto init.
    static func parse(_ data: Data) -> ParsedInit? {
        guard data.count >= handshakeLen else { return nil }
        let bytes = [UInt8](data.prefix(handshakeLen))

        let key = Data(bytes[skipLen..<skipLen + prekeyLen])
        let iv = Data(bytes[skipLen + prekeyLen..<skipLen + prekeyLen + ivLen])

        guard let cipher = AESCTR(key: key, iv: iv) else { return nil }
        guard let decrypted = cipher.update(data.prefix(handshakeLen)) else { return nil }
        let dec = [UInt8](decrypted)

        // proto_tag at offset 56 (4 bytes, little-endian)
        let protoTag = UInt32(dec[protoTagPos]) |
                       (UInt32(dec[protoTagPos + 1]) << 8) |
                       (UInt32(dec[protoTagPos + 2]) << 16) |
                       (UInt32(dec[protoTagPos + 3]) << 24)

        let abridged: UInt32 = 0xEFEFEFEF
        let intermediate: UInt32 = 0xEEEEEEEE
        let paddedIntermediate: UInt32 = 0xDDDDDDDD
        guard protoTag == abridged || protoTag == intermediate || protoTag == paddedIntermediate else {
            return nil
        }

        // dc_idx at offset 60 (2 bytes, signed little-endian)
        let dcIdxRaw = Int16(bitPattern: UInt16(dec[dcIdxPos]) | (UInt16(dec[dcIdxPos + 1]) << 8))
        let dcId = abs(Int(dcIdxRaw))
        let isMedia = dcIdxRaw < 0
        let isTestDC = dcId >= 10000

        return ParsedInit(dcId: dcId, isMedia: isMedia, isTestDC: isTestDC, protoTag: protoTag, key: key, iv: iv)
    }
}
