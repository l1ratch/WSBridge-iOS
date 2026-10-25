import Foundation

/// Разбивает TCP-поток на отдельные MTProto-пакеты для WS-фреймов.
/// Ключи из init клиента (без secret — стандартная обфускация).
/// Fast-forward на 64 байта (init уже отправлен как первый фрейм).
///
/// ponytail: [UInt8] вместо Data — у Data.subdata(in:) startIndex сдвигается
/// после removeFirst, что вызывало EXC_BREAKPOINT.
final class MsgSplitter {
    private let cipher: AESCTR
    private let protoTag: UInt32
    private var cipherBuf: [UInt8] = []
    private var plainBuf: [UInt8] = []
    private var disabled = false

    private static let abridged: UInt32 = 0xEFEFEFEF
    private static let intermediate: UInt32 = 0xEEEEEEEE
    private static let paddedIntermediate: UInt32 = 0xDDDDDDDD

    init?(key: Data, iv: Data, protoTag: UInt32) {
        guard let cipher = AESCTR(key: key, iv: iv) else { return nil }
        cipher.fastForward(64) // skip init
        self.cipher = cipher
        self.protoTag = protoTag
    }

    /// Принимает шифртекст, возвращает массив шифртекст-пакетов для WS-фреймов.
    func split(_ chunk: Data) -> [Data] {
        guard !chunk.isEmpty else { return [] }
        if disabled { return [chunk] }

        cipherBuf.append(contentsOf: [UInt8](chunk))
        if let plain = cipher.update(chunk) {
            plainBuf.append(contentsOf: [UInt8](plain))
        }

        var parts: [Data] = []
        var offset = 0
        let bufLen = cipherBuf.count

        while offset < bufLen {
            guard let packetLen = nextPacketLen(offset: offset, avail: bufLen - offset) else { break }
            if packetLen <= 0 {
                parts.append(Data(cipherBuf[offset...]))
                offset = bufLen
                disabled = true
                break
            }
            parts.append(Data(cipherBuf[offset..<offset + packetLen]))
            offset += packetLen
        }

        if offset > 0 {
            cipherBuf.removeFirst(offset)
            plainBuf.removeFirst(offset)
        }
        return parts
    }

    /// Возвращает остаток буфера при закрытии соединения.
    func flush() -> [Data] {
        guard !cipherBuf.isEmpty else { return [] }
        let tail = Data(cipherBuf)
        cipherBuf.removeAll()
        plainBuf.removeAll()
        return [tail]
    }

    private func nextPacketLen(offset: Int, avail: Int) -> Int? {
        guard avail > 0 else { return nil }
        if protoTag == Self.abridged {
            return nextAbridgedLen(offset: offset, avail: avail)
        }
        if protoTag == Self.intermediate || protoTag == Self.paddedIntermediate {
            return nextIntermediateLen(offset: offset, avail: avail)
        }
        return 0
    }

    private func nextAbridgedLen(offset: Int, avail: Int) -> Int? {
        let first = plainBuf[offset]
        var payloadLen: Int
        var headerLen: Int
        if first == 0x7F || first == 0xFF {
            if avail < 4 { return nil }
            payloadLen = (Int(plainBuf[offset + 1]) |
                         (Int(plainBuf[offset + 2]) << 8) |
                         (Int(plainBuf[offset + 3]) << 16)) * 4
            headerLen = 4
        } else {
            payloadLen = Int(first & 0x7F) * 4
            headerLen = 1
        }
        if payloadLen <= 0 { return 0 }
        let packetLen = headerLen + payloadLen
        if avail < packetLen { return nil }
        return packetLen
    }

    private func nextIntermediateLen(offset: Int, avail: Int) -> Int? {
        if avail < 4 { return nil }
        let payloadLen = (Int(plainBuf[offset]) |
                         (Int(plainBuf[offset + 1]) << 8) |
                         (Int(plainBuf[offset + 2]) << 16) |
                         (Int(plainBuf[offset + 3]) << 24)) & 0x7FFFFFFF
        if payloadLen <= 0 { return 0 }
        let packetLen = 4 + payloadLen
        if avail < packetLen { return nil }
        return packetLen
    }
}
