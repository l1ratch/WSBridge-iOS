import Foundation

/// Обёртка над lwIP: инициализация, подача пакетов, таймеры.
/// Все колбэки приходят на том же потоке, откуда вызван input/poll.
final class LWIPBridge {
    typealias OutputHandler = (Data) -> Void
    typealias AcceptHandler = (UInt32, UInt32) -> Void  // connId, dcIP
    typealias RecvHandler = (UInt32, Data) -> Void
    typealias CloseHandler = (UInt32, Int32) -> Void  // connId, reason
    typealias SentHandler = (UInt32) -> Void

    private var outputHandler: OutputHandler?
    private var acceptHandler: AcceptHandler?
    private var recvHandler: RecvHandler?
    private var closeHandler: CloseHandler?
    private var sentHandler: SentHandler?

    init() {}

    func start(
        output: @escaping OutputHandler,
        accept: @escaping AcceptHandler,
        recv: @escaping RecvHandler,
        close: @escaping CloseHandler,
        sent: @escaping SentHandler
    ) {
        outputHandler = output
        acceptHandler = accept
        recvHandler = recv
        closeHandler = close
        sentHandler = sent

        lwip_bridge_init(
            Unmanaged.passUnretained(self).toOpaque(),
            { data, len, ctx in
                guard let ctx, let data else { return }
                let bridge = Unmanaged<LWIPBridge>.fromOpaque(ctx).takeUnretainedValue()
                let bytes = Data(bytes: data, count: Int(len))
                bridge.outputHandler?(bytes)
            },
            { connId, ctx in
                guard let ctx else { return }
                let bridge = Unmanaged<LWIPBridge>.fromOpaque(ctx).takeUnretainedValue()
                let dcIP = lwip_bridge_get_dst_ip(connId)
                if dcIP == 0 {
                    var ki: UInt32 = 0, kp: UInt16 = 0, dc: UInt32 = 0
                    var ni: UInt32 = 0, np: UInt16 = 0, nd: UInt32 = 0
                    lwip_bridge_dbg_nat(&ki, &kp, &dc, &ni, &np, &nd)
                    EventLog.append(String(format: "natmiss:key=%08x:%u dc=%08x nat0=%08x:%u->%08x",
                                           ki, kp, dc, ni, np, nd))
                }
                bridge.acceptHandler?(connId, dcIP)
            },
            { connId, data, len, ctx in
                guard let ctx, let data else { return }
                let bridge = Unmanaged<LWIPBridge>.fromOpaque(ctx).takeUnretainedValue()
                let bytes = Data(bytes: data, count: Int(len))
                bridge.recvHandler?(connId, bytes)
            },
            { connId, reason, ctx in
                guard let ctx else { return }
                let bridge = Unmanaged<LWIPBridge>.fromOpaque(ctx).takeUnretainedValue()
                bridge.closeHandler?(connId, reason)
            },
            { connId, ctx in
                guard let ctx else { return }
                let bridge = Unmanaged<LWIPBridge>.fromOpaque(ctx).takeUnretainedValue()
                bridge.sentHandler?(connId)
            }
        )
    }

    func input(_ packet: Data) {
        packet.withUnsafeBytes { raw in
            guard let base = raw.baseAddress else { return }
            lwip_bridge_input(base.assumingMemoryBound(to: UInt8.self), UInt16(raw.count))
        }
    }

    func poll() {
        lwip_bridge_poll()
    }

    func write(connId: UInt32, data: Data) -> Bool {
        data.withUnsafeBytes { raw -> Bool in
            guard let base = raw.baseAddress else { return false }
            return lwip_bridge_write(connId, base.assumingMemoryBound(to: UInt8.self), UInt16(raw.count)) == 0
        }
    }

    func close(connId: UInt32) {
        lwip_bridge_close(connId)
    }
}
