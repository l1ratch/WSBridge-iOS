import NetworkExtension
import Foundation
import Network
import UserNotifications

/// Фаза 2: lwIP + WS-сплайсинг.
/// Перехватывает TCP к DC Telegram, восстанавливает поток через lwIP,
/// парсит init, коннектится к kws-гейтвею и мостит байты.
///
/// ponytail: lwIP с NO_SYS=1 однопоточный. ВСЕ операции (input, poll, write, close)
/// идут через одну serial-очередь. readPackets и WS-колбэки приходят с разных потоков.
final class PacketTunnelProvider: NEPacketTunnelProvider {
    private let lwip = LWIPBridge()
    private var sessions: [UInt32: TunnelSession] = [:]
    private var packetCount: UInt64 = 0
    private var byteCount: UInt64 = 0
    private let startedAt = Date()
    private let lwipQueue = DispatchQueue(label: "com.l1ratch.WSBridge.lwip")
    private let journalServer = JournalServer()
    private var pollTimer: DispatchSourceTimer?
    private var ioTimer: DispatchSourceTimer?
    private var workerDomain: String?
    // Смена сети: расширение — единственный живой процесс, пока туннель
    // включен (приложение в фоне усыплено и NWPathMonitor там молчит).
    private var pathMonitor: NWPathMonitor?
    private var lastPathSig: String?
    private var lastNetNotifAt = Date.distantPast

    override func startTunnel(
        options: [String: NSObject]?,
        completionHandler: @escaping (Error?) -> Void
    ) {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "198.18.0.1")
        let ipv4 = NEIPv4Settings(addresses: ["198.18.0.2"], subnetMasks: ["255.255.255.255"])
        ipv4.includedRoutes = TelegramDCs.includedRoutes
        settings.ipv4Settings = ipv4
        // IPv6 НЕ анонсируем: lwIP у нас v4-only, анонсированный v6-маршрут
        // был чёрной дырой — Telegram ломился в v6 DC и висел до таймаута.
        settings.mtu = 1500

        let proto = protocolConfiguration as? NETunnelProviderProtocol
        let dnsList = proto?.providerConfiguration?["dns"] as? [String]
        let dohURL = proto?.providerConfiguration?["doh"] as? String
        let dotHost = proto?.providerConfiguration?["dot"] as? String
        if let dnsList, !dnsList.isEmpty {
            if let dotHost, !dotHost.isEmpty {
                // Приоритет 1: DNS-over-TLS. Коннект напрямую к IP:853 с SNI —
                // резолв имени сервера НЕ нужен. Под VPN бутстрап-резолв
                // DoH-хоста системой ломал malw (всё кроме туннеля умирало),
                // у DoT этой ступени нет вовсе.
                let dot = NEDNSOverTLSSettings(servers: dnsList)
                dot.serverName = dotHost
                settings.dnsSettings = dot
                NSLog("[WSBridge] DNS: DoT via %@", dotHost)
            } else if let dohURL, !dohURL.isEmpty {
                // Приоритет 2: DNS-over-HTTPS (порт 443, зашифровано)
                let doh = NEDNSOverHTTPSSettings(servers: dnsList)
                doh.serverURL = URL(string: dohURL)
                settings.dnsSettings = doh
                NSLog("[WSBridge] DNS: DoH via %@", dohURL)
            } else {
                // Приоритет 3: plain :53 (только свои конфиги без URL)
                settings.dnsSettings = NEDNSSettings(servers: dnsList)
                NSLog("[WSBridge] DNS: plain %@", dnsList.joined(separator: ", "))
            }
        }

        setTunnelNetworkSettings(settings) { [weak self] error in
            if let error {
                NSLog("[WSBridge] setTunnelNetworkSettings failed: %@", error.localizedDescription)
                completionHandler(error)
                return
            }
            NSLog("[WSBridge] tunnel started")
            EventLog.loadPrevious()
            let proto = self?.protocolConfiguration as? NETunnelProviderProtocol
            let wd = (proto?.providerConfiguration?["worker"] as? String)?
                .trimmingCharacters(in: .whitespacesAndNewlines)
            self?.workerDomain = (wd?.isEmpty == false) ? wd : nil
            EventLog.append("cfg:worker=\(self?.workerDomain ?? "-")")
            // Hot-обновление фронтов: свежий список от приложения (или встроенный).
            let fronts = proto?.providerConfiguration?["fronts"] as? [String]
            CFDomains.update(fronts ?? [])
            EventLog.append("cfg:fronts=\(CFDomains.bases.count)")
            // Android-порт: эвикция протухших из реестра (мёртвые >7 дней,
            // пропавшие из апстрима) + запись состояния реестра в журнал.
            FrontHealthRegistry.evict(absentFrom: Set(CFDomains.bases))
            EventLog.append("fronts_health:\(FrontHealthRegistry.summary())")
            let ver = Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "?"
            EventLog.append("tunnel_start v\(ver)")
            self?.journalServer.start()
            self?.setupLWIP()
            self?.startTimers()
            self?.readLoop()
            self?.startPathMonitor()
            completionHandler(nil)
        }
    }

    private func setupLWIP() {
        lwip.start(
            output: { [weak self] data in
                self?.writePacket(data)
            },
            accept: { [weak self] connId, dcIP in
                self?.handleAccept(connId: connId, dcIP: dcIP)
            },
            recv: { [weak self] connId, data in
                self?.handleRecv(connId: connId, data: data)
            },
            close: { [weak self] connId, reason in
                self?.handleClose(connId: connId, reason: reason)
            },
            sent: { [weak self] connId in
                self?.sessions[connId]?.handleSent()
            }
        )
    }

    private func writePacket(_ data: Data) {
        EventLog.outPkts += 1
        packetFlow.writePackets([data], withProtocols: [NSNumber(value: AF_INET)])
    }

    /// ponytail: lwIP NO_SYS=1 требует периодического sys_check_timeouts.
    /// Раньше poll() крутился только на входящих пакетах — когда клиент затихал
    /// в ожидании ответа, ретрансмиты зависших сегментов не происходили никогда
    /// и сессия висела вечно (ровно картина «ws_recv есть, а ТГ стоит»).
    private func startTimers() {
        let poll = DispatchSource.makeTimerSource(queue: lwipQueue)
        poll.schedule(deadline: .now() + .milliseconds(250), repeating: .milliseconds(250))
        poll.setEventHandler { [weak self] in self?.lwip.poll() }
        poll.resume()
        pollTimer = poll

        let io = DispatchSource.makeTimerSource(queue: lwipQueue)
        io.schedule(deadline: .now() + 15, repeating: 15)
        io.setEventHandler { [weak self] in
            guard let self else { return }
            EventLog.append("io:in=\(self.packetCount) out=\(EventLog.outPkts) v6=\(EventLog.inV6) oth=\(EventLog.inOther) wd=\(EventLog.wsDown) wf=\(EventLog.writeFails) up=\(EventLog.upBytes) rx=\(EventLog.rxBytes) pend=\(EventLog.pendCur) sent=\(EventLog.sentCb) inmem=\(lwip_bridge_inmem_drops()) mem=\(String(format: "%.1f", self.memFootprintMB()))MB conns=\(self.sessions.count)")
            for (id, _) in self.sessions.sorted(by: { $0.key < $1.key }).prefix(2) {
                var st: UInt32 = 0, un: UInt32 = 0
                lwip_bridge_conn_stats(id, &st, &un)
                EventLog.append("c\(id):st=\(st) un=\(un)")
            }
            EventLog.flush() // свежий файл даже при краше между append-порогами
        }
        io.resume()
        ioTimer = io
    }

    private func handleAccept(connId: UInt32, dcIP: UInt32) {
        NSLog("[WSBridge] accept conn \(connId) dc=\(dcIP)")
        postDarwinEvent("accept")
        let session = TunnelSession(connId: connId, dcIP: dcIP, workerDomain: workerDomain, bridge: lwip, queue: lwipQueue)
        sessions[connId] = session
    }

    private func handleRecv(connId: UInt32, data: Data) {
        sessions[connId]?.handleData(data)
    }

    private func handleClose(connId: UInt32, reason: Int32) {
        sessions[connId]?.handleClose(reason: reason)
        sessions.removeValue(forKey: connId)
    }

    private func readLoop() {
        packetFlow.readPackets { [weak self] packets, protocols in
            guard let self else { return }
            // Android-порт: TUN fd может умирать молча — колбэк приходит
            // с пустым результатом и всё. Диагностируем, не висим «включено».
            if packets.isEmpty {
                EventLog.append("tun_dead:read:packets=0")
                EventLog.flush()
            }
            self.lwipQueue.async {
                for (packet, family) in zip(packets, protocols) {
                    if family.intValue != AF_INET {
                        EventLog.inV6 += 1
                        continue
                    }
                    // Только TCP в lwIP; UDP (DNS, QUIC) роняем.
                    guard packet.count > 9, packet[9] == 6 else {
                        EventLog.inOther += 1
                        continue
                    }
                    self.packetCount += 1
                    self.byteCount += UInt64(packet.count)
                    self.lwip.input(packet)
                }
                self.lwip.poll()
                if self.packetCount % 50 == 0 {
                    self.postDarwinNotification()
                }
            }
            self.readLoop()
        }
    }

    private func postDarwinNotification() {
        postDarwinEvent("pkts")
    }

    private func postDarwinEvent(_ name: String) {
        let cfName = "com.l1ratch.WSBridge.\(name)" as CFString
        CFNotificationCenterPostNotification(
            CFNotificationCenterGetDarwinNotifyCenter(),
            CFNotificationName(cfName),
            nil, nil, true
        )
    }

    /// phys_footprint — то, по чему jetsam судит расширение (~50MB лимит).
    private func memFootprintMB() -> Double {
        var info = task_vm_info_data_t()
        var count = mach_msg_type_number_t(MemoryLayout<task_vm_info_data_t>.stride / MemoryLayout<integer_t>.stride)
        let kr = withUnsafeMutablePointer(to: &info) {
            $0.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                task_info(mach_task_self_, task_flavor_t(TASK_VM_INFO), $0, &count)
            }
        }
        return kr == KERN_SUCCESS ? Double(info.phys_footprint) / 1_048_576.0 : -1
    }

    override func stopTunnel(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        NSLog("[WSBridge] tunnel stopped (reason=%ld, pkts=%llu, bytes=%llu)",
              reason.rawValue, packetCount, byteCount)
        // reason: 0=none 1=user 2=providerFailed 3=sleep 4=appUpdate
        // 5=providerDisabled 6=badConfiguration 7=systemPolicy 8=evalFailed
        // 9=configurationDisabled 10=configurationInvalid ...
        EventLog.append("tunnel_stop:reason=\(reason.rawValue):pkts=\(packetCount)")
        // Android-порт: реестр здоровья на диск — процесс могут убить сразу
        // после completionHandler.
        FrontHealthRegistry.flush(immediate: true)
        EventLog.append("fronts_health:\(FrontHealthRegistry.summary())")
        EventLog.flush()
        journalServer.stop()
        pathMonitor?.cancel(); pathMonitor = nil
        pollTimer?.cancel(); pollTimer = nil
        ioTimer?.cancel(); ioTimer = nil
        lwipQueue.sync {
            for (_, session) in sessions { session.handleClose(reason: 1) }
            sessions.removeAll()
        }
        completionHandler()
    }

    /// ponytail: Wi-Fi↔соты и подобные переключения рвут WS-сессии и lwIP-
    /// состояние молча — трафик «протухает» до ручного перезапуска. Мониторим
    /// путь здесь (процесс жив, пока туннель включен) и nudg'им пользователя
    /// локальным уведомлением. Троттлинг 5 мин: флэпы Wi-Fi не спамлят.
    private func startPathMonitor() {
        let m = NWPathMonitor()
        m.pathUpdateHandler = { [weak self] path in
            guard let self else { return }
            let ifaces = path.availableInterfaces
                .map { Self.ifaceName($0.type) }
                .sorted()
                .joined(separator: "+")
            let sig = "\(path.status):\(ifaces)"
            defer { self.lastPathSig = sig }
            guard let prev = self.lastPathSig, prev != sig else { return }
            EventLog.append("net_change:\(prev)->\(sig)")
            guard path.status == .satisfied else { return }
            guard Date().timeIntervalSince(self.lastNetNotifAt) > 300 else { return }
            self.lastNetNotifAt = Date()
            let c = UNMutableNotificationContent()
            c.title = "Сеть сменилась"
            let prevIfaces = prev.split(separator: ":", maxSplits: 1)
                .last.map(String.init) ?? prev
            c.body = "Телефон переподключился: \(prevIfaces) → \(ifaces). Если интернет тормозит — перезапусти туннель в WSBridge."
            let req = UNNotificationRequest(
                identifier: "wsbridge.netChange", content: c,
                trigger: UNTimeIntervalNotificationTrigger(timeInterval: 1, repeats: false))
            UNUserNotificationCenter.current().add(req) { err in
                EventLog.append("notif_net:\(err?.localizedDescription ?? "ok")")
            }
        }
        m.start(queue: DispatchQueue(label: "com.l1ratch.WSBridge.pathmon"))
        pathMonitor = m
    }

    private static func ifaceName(_ t: NWInterface.InterfaceType) -> String {
        switch t {
        case .wifi: return "Wi-Fi"
        case .cellular: return "сот."
        case .wiredEthernet: return "Ethernet"
        case .loopback: return "loopback"
        case .other: return "др."
        @unknown default: return "?"
        }
    }

    override func handleAppMessage(
        _ messageData: Data,
        completionHandler: ((Data?) -> Void)?
    ) {
        let text = "pkts=\(packetCount) bytes=\(byteCount) uptime=\(Int(Date().timeIntervalSince(startedAt)))s conns=\(sessions.count)"
        completionHandler?(text.data(using: .utf8))
    }
}
