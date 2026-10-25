import Foundation
import CommonCrypto

/// AES-256-CTR шифр через CommonCrypto. CTR симметричен: encrypt == decrypt.
/// Используется для парсинга init и MsgSplitter.
final class AESCTR {
    private var cryptor: CCCryptorRef?

    init?(key: Data, iv: Data) {
        var ref: CCCryptorRef?
        let keyBytes = [UInt8](key)
        let ivBytes = [UInt8](iv)
        let status = CCCryptorCreateWithMode(
            CCOperation(kCCEncrypt),
            CCMode(kCCModeCTR),
            CCAlgorithm(kCCAlgorithmAES),
            CCPadding(ccNoPadding),
            ivBytes,
            keyBytes, keyBytes.count,
            nil, 0, 0,
            CCModeOptions(kCCModeOptionCTR_BE),  // big-endian counter (MTProto standard)
            &ref
        )
        guard status == kCCSuccess, let ref else { return nil }
        self.cryptor = ref
    }

    deinit {
        if let cryptor { CCCryptorRelease(cryptor) }
    }

    /// Обновляет шифр порцией данных. Возвращает зашифрованные/расшифрованные байты.
    func update(_ data: Data) -> Data? {
        guard let cryptor else { return nil }
        let input = [UInt8](data)
        var output = [UInt8](repeating: 0, count: input.count + kCCBlockSizeAES128)
        var outLen = 0
        let status = CCCryptorUpdate(
            cryptor,
            input, input.count,
            &output, output.count,
            &outLen
        )
        guard status == kCCSuccess else { return nil }
        return Data(output.prefix(outLen))
    }

    /// Прогоняет N нулевых байт через шифр (fast-forward keystream).
    func fastForward(_ count: Int) {
        let zeros = Data(repeating: 0, count: count)
        _ = update(zeros)
    }
}
