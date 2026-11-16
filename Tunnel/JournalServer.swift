import Foundation
import Network

/// Журнал событий расширения отдаётся приложению через loopback TCP
/// (127.0.0.1:51001): оба процесса на одном устройстве, никаких entitlements.
///
/// Минимальный текстовый протокол: приложение присылает одну строку
///   "journal"        → текущий прогон целиком
///   "list"           → JSON-массив [{name,size,date}] всех прогонов
///   "file:<имя>"     → содержимое одного файла прогона
/// Без команды (старые клиенты) — "journal" для совместимости.
final class JournalServer {
    static let port = NWEndpoint.Port(rawValue: 51001)!
    private var listener: NWListener?

    func start() {
        let params = NWParameters.tcp
        params.requiredLocalEndpoint = NWEndpoint.hostPort(host: "127.0.0.1", port: Self.port)
        guard let l = try? NWListener(using: params) else { return }
        listener = l
        l.newConnectionHandler = { conn in
            conn.stateUpdateHandler = { state in
                guard state == .ready else { return }
                // Читаем команду (до \n или первые 256 байт).
                conn.receive(minimumIncompleteLength: 1, maximumLength: 256) { data, _, _, _ in
                    let cmd = data.flatMap { String(data: $0, encoding: .utf8) }?
                        .trimmingCharacters(in: .whitespacesAndNewlines) ?? "journal"
                    let reply = Self.handle(cmd)
                    conn.send(content: Data(reply.utf8), completion: .contentProcessed { _ in
                        conn.cancel()
                    })
                }
            }
            conn.start(queue: .global(qos: .utility))
        }
        l.start(queue: .global(qos: .utility))
    }

    private static func handle(_ cmd: String) -> String {
        if cmd == "list" {
            let items = EventLog.logFileEntries().map { e -> [String: Any] in
                ["name": e.name, "size": e.size,
                 "date": ISO8601DateFormatter().string(from: e.date)]
            }
            guard let d = try? JSONSerialization.data(withJSONObject: items),
                  let s = String(data: d, encoding: .utf8) else { return "[]" }
            return s
        }
        if cmd.hasPrefix("file:") {
            return EventLog.contents(of: String(cmd.dropFirst(5)))
        }
        return EventLog.journal()
    }

    func stop() {
        listener?.cancel()
        listener = nil
    }
}
