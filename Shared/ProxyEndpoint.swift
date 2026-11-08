import Foundation

/// Описание прокси: общий тип для app (настройки, парсинг, тест)
/// и extension (коннект). socks5://[user:pass@]host:port или
/// http://[user:pass@]host:port.
struct ProxyEndpoint: Equatable, Codable {
    enum Kind: String, Equatable, Codable { case socks5, http }
    var kind: Kind
    var host: String
    var port: UInt16
    var user: String?
    var password: String?

    /// Парсинг строки. nil = битый формат.
    static func parse(_ raw: String) -> ProxyEndpoint? {
        let s = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        let kind: Kind
        var rest = s
        if s.lowercased().hasPrefix("socks5://") {
            kind = .socks5; rest = String(s.dropFirst(9))
        } else if s.lowercased().hasPrefix("http://") {
            kind = .http; rest = String(s.dropFirst(7))
        } else {
            return nil
        }
        // [user:pass@]host:port
        var hostPort = rest
        var creds: String?
        if let at = rest.lastIndex(of: "@") {
            creds = String(rest[rest.startIndex..<at])
            hostPort = String(rest[rest.index(after: at)...])
        }
        var user: String? = nil
        var password: String? = nil
        if let creds {
            let parts = creds.split(separator: ":", maxSplits: 1)
            if parts.count == 2 {
                user = String(parts[0]); password = String(parts[1])
            } else {
                user = creds
            }
        }
        let hp = hostPort.split(separator: ":")
        guard hp.count == 2, let port = UInt16(hp[1]), !hp[0].isEmpty else { return nil }
        return ProxyEndpoint(kind: kind, host: String(hp[0]), port: port,
                             user: user, password: password)
    }

    /// Короткая подпись для UI (пароль маскируется).
    var display: String {
        let auth = user != nil ? "***@" : ""
        return "\(kind == .socks5 ? "socks5" : "http")://\(auth)\(host):\(port)"
    }
}
