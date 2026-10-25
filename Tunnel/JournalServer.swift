import Foundation
import Network

/// Журнал событий расширения отдаётся приложению через loopback TCP
/// (127.0.0.1:51001): оба процесса на одном устройстве, никаких entitlements,
/// песочницы не мешают. Трафик на loopback в туннель не попадает.
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
                let data = Data(EventLog.journal().utf8)
                conn.send(content: data, completion: .contentProcessed { _ in
                    conn.cancel()
                })
            }
            conn.start(queue: .global(qos: .utility))
        }
        l.start(queue: .global(qos: .utility))
    }

    func stop() {
        listener?.cancel()
        listener = nil
    }
}
