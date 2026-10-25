import Foundation

/// Ротационные CF-домены из апстрима tg-ws-proxy (.github/cfproxy-domains.txt).
/// Декодированы функцией _dd() из config.py (shift cipher).
/// kws{dc}.{base_domain} фронтирует WS-гейтвей Telegram через Cloudflare.
///
/// Список обновляемый: приложение при включении туннеля передаёт свежий
/// список (providerConfiguration["fronts"]) — фронты апстрима умирают
/// волнами, пересобирать приложение ради каждого обновления нельзя.
/// Пустой/битый обновлённый список = откат к встроенному.
enum CFDomains {
    // Полный встроенный список десктопа (_CFPROXY_ENC из config.py, decode _dd).
    static let builtinBases = [
        "pclead.co.uk",
        "offshor.co.uk",
        "cakeisalie.co.uk",
        "noskomnadzor.co.uk",
        "lovetrue.co.uk",
        "sorokdva.co.uk",
        "pyatdesyatdva.co.uk",
        "kartoshka.co.uk",
        "sorokodin.co.uk",
        "pyatdesyatodin.co.uk",
        "notelega.co.uk",
        "ebally.co.uk",
        "nebally.co.uk",
        "havegreatday.co.uk",
        "pomogite.co.uk",
        "fixtelega.co.uk",
        "sadnews.co.uk",
        "onedaychamp.co.uk",
        "stopblocking.co.uk",
        "nothingthere.co.uk",
    ]

    /// Активные базовые домены. Устанавливаются на старте туннеля из
    /// providerConfiguration["fronts"]; по умолчанию — встроенный список.
    private static var _bases: [String]?
    private static let lock = NSLock()

    static var bases: [String] {
        lock.lock(); defer { lock.unlock() }
        return _bases ?? builtinBases
    }

    /// Заменяет список фронтов (вызывается из PacketTunnelProvider.startTunnel).
    /// НЕ заменяет, а ОБЪЕДИНЯЕТ со встроенным: новые домены апстрима часто
    /// не резолвятся в DNS сразу после публикации (A-записей нет) — полная
    /// замена убивала живые встроенные фронты. Встроенные идут ПЕРВЫМИ
    /// (каскад берёт prefix — живые должны быть в начале), новые — после.
    /// Битовый/короткий список игнорируется.
    static func update(_ newBases: [String]) {
        lock.lock(); defer { lock.unlock() }
        guard newBases.count >= 3 else { return }
        var merged = builtinBases
        for d in newBases where !merged.contains(d) {
            merged.append(d)
        }
        _bases = merged
    }

    /// Возвращает список доменов для WS-подключения: kws{dc}.{base}
    static func domains(dc: Int) -> [String] {
        bases.map { "kws\(dc).\($0)" }
    }
}
