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
    /// Локальный DNS-резолвер: rewrites + upstream. Пишет ответы напрямую
    /// в packetFlow (обходя lwIP — UDP в стеке выключен). Создаётся в
    /// startTunnel: колбэк writePacket требует self.
    private var localDNS: LocalDNSResolver?
    /// Режим остался только для диагностики в журнале ("split"/"matchall").
    /// "default" (0.0.0.0/0) ОТКЛЮЧЁН: он забирал весь трафик, а readLoop
    /// его ронял — сайты умирали, loopback-журнал пропадал, NWPathMonitor
    /// слал ложные «смена сети». Рабочая конфигурация всегда узкая.
    private var dnsProbeMode: String = "split"
    /// Счётчики диагностики перехвата. Пишутся только на lwipQueue.
    private var statUDP53: UInt64 = 0
    private var statUDPOther: UInt64 = 0
    private var statDNSHandled: UInt64 = 0
    /// Первые N адресов назначения UDP:53 — куда система шлёт DNS.
    private var dnsDstSample: [String] = []
    private var pollTimer: DispatchSourceTimer?
    private var ioTimer: DispatchSourceTimer?
    private var workerDomain: String?
    /// Работники из «домены через запятую» + счётчик round-robin.
    private var workerDomains: [String] = []
    private var workerRRIndex = 0
    /// «DC → IP» маппинг из настроек.
    private var dcOverride: [String: String] = [:]
    /// Прокси для прокси-доменов (fake-IP 198.18.1.x): nil = нет прокси.
    private var proxyEndpoint: ProxyEndpoint?
    /// При включённом DoH-воркере 198.18.1.x — не мапа, а метка: домен
    /// достаём из TLS SNI, а не из localDNS.proxyDomain(forFakeIP:).
    private var dohWorkerActive = false
    /// Матчер доменов для SNI-фолбэка (замыкание на LocalDNSResolver).
    private var proxyDomainMatcher: ((String) -> Bool)?
    /// CIDR, добавленные в includedRoutes для real-IP перехвата. По ним
    /// же в handleAccept решаем, что трафик НЕ Telegram и его можно
    /// проверять на SNI. Пусто = SNI-фолбэк выключен.
    private var sniCIDRs: [(UInt32, UInt32)] = []
    /// ID нуджа «долго включен». Владелец — расширение (см. scheduleLongSessionNudge).
    private static let longSessionID = "wsbridge.longSession"
    // Смена сети: расширение — единственный живой процесс, пока туннель
    // включен (приложение в фоне усыплено и NWPathMonitor там молчит).
    private var pathMonitor: NWPathMonitor?
    private var lastPathSig: String?

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
        // НЕ экспериментируем с ipv6Settings: в v13 без него сайты работали,
        // а любое изменение здесь рискует снова уронить весь интернет.
        settings.mtu = 1500

        let proto = protocolConfiguration as? NETunnelProviderProtocol
        let dnsList = proto?.providerConfiguration?["dns"] as? [String]
        let dohURL = proto?.providerConfiguration?["doh"] as? String
        let dotHost = proto?.providerConfiguration?["dot"] as? String
        // Локальный DNS: резолвер в туннеле с hosts-rewrite списком.
        // dnsSettings указывает на наш TUN-адрес — запросы прилетают в
        // packetFlow, перехватываются readLoop'ом и обрабатываются
        // LocalDNSResolver'ом (rewrites → upstream → системный).
        let localDNSEnabled = (proto?.providerConfiguration?["localDNS"] as? Bool) == true
        // Прокси-домены: LRDNS отвечает им fake-IP 198.18.1.x; маршрут
        // 198.18.1.0/24 забирает их пакеты в туннель, соединения
        // терминируются lwIP и уходят через SOCKS5/HTTP-прокси.
        // DNS-адрес 198.18.0.3 — соседний с интерфейсным (0.2): маршрут
        // /32 уводит DNS-пакеты в packetFlow (см. LocalDNSResolver док).
        let proxyDomains = (proto?.providerConfiguration?["proxyDomains"] as? [String]) ?? []
        let proxyURLs = (proto?.providerConfiguration?["proxies"] as? [String]) ?? []
        // ── Этап 2: DoH-воркер (Вариант Б) ──────────────────────────
        // Приложение передаёт готовый serverURL, точные matchDomains и
        // заранее резолвленные IP воркера. Включается ТОЛЬКО при наличии
        // ключа — иначе всё работает как раньше.
        let dohWorkerURL = (proto?.providerConfiguration?["dohWorkerURL"] as? String)
            .flatMap { URL(string: $0) }
        let dohMatchDomains = (proto?.providerConfiguration?["dohMatchDomains"] as? [String]) ?? []
        let dohWorkerIPs = (proto?.providerConfiguration?["dohWorkerIPs"] as? [String]) ?? []
        // Диагностика (страница «Тест DNS»): какой из трёх вариантов
        // объявления резолвера проверяем в этом запуске.
        let probeMode = (proto?.providerConfiguration?["dnsProbe"] as? String) ?? "split"
        // "default" больше не поддерживается: принудительно сужаем до split,
        // даже если в UserDefaults телефона осталось старое значение.
        self.dnsProbeMode = probeMode == "default" ? "split" : probeMode
        var routes = TelegramDCs.includedRoutes
        // Маршрут /32 на 198.18.0.3 больше НЕ нужен: dnsSettings снят,
        // локальный резолвер не перехватывает системный DNS.
        // При включённом DoH-воркере 198.18.1.0/24 нужен ВСЕГДА: воркер
        // возвращает 198.18.1.1 как метку, и пакет обязан попасть в utun.
        // Раньше маршрут зависел от proxyDomains/proxyURLs — если они не
        // доезжали, FakeIP уходил мимо туннеля и сайт «залипал».
        let workerOn = (proto?.providerConfiguration?["dohWorkerURL"] as? String) != nil
        if workerOn || (!proxyDomains.isEmpty && !proxyURLs.isEmpty) {
            routes.append(NEIPv4Route(destinationAddress: "198.18.1.0", subnetMask: "255.255.255.0"))
        }
        // Real-IP фолбэк для упрямых приложений (свой DoH/DoT, проверка
        // bogon-диапазона): заворачиваем подсети CDN, где сидят ИИ-сервисы.
        // ВАЖНО: IP самого прокси и worker'а должны быть ВНЕ этих подсетей
        // (или в excludedRoutes), иначе исходящий сокет закольцуется —
        // DirectStream/ProxyClient привязаны к физическому интерфейсу.
        let cidrs = (proto?.providerConfiguration?["sniCIDRs"] as? [String]) ?? []
        let resolvedCIDRs = Self.parseCIDRs(cidrs)
        self.sniCIDRs = resolvedCIDRs
        for (base, mask) in resolvedCIDRs {
            routes.append(NEIPv4Route(destinationAddress: IPv4Addr.dotted(base),
                                      subnetMask: IPv4Addr.dotted(mask)))
        }
        // IP прокси и worker-фронтов выводим из туннеля на уровне ядра.
        // Без этого SNI-фолбэк с CIDR Cloudflare ловит собственный исходящий
        // коннект к прокси/воркеру и замыкает петлю.
        var excluded = ipv4.excludedRoutes ?? []
        for raw in proxyURLs {
            if let ep = ProxyEndpoint.parse(raw), let ip = IPv4Addr.parse(ep.host) {
                excluded.append(NEIPv4Route(destinationAddress: IPv4Addr.dotted(ip),
                                            subnetMask: "255.255.255.255"))
            }
        }
        // IP воркера НЕ добавляем в excludedRoutes: системный DoH идёт
        // мимо packetFlow (не через utun), а sniCIDRs при включённом
        // воркере не передаются, так что пересечения маршрутов нет.
        // Лишний excluded /32 на адрес самого резолвера мешал iOS
        // установить TLS к нему (этап 2: 0 вызовов от телефона).
        if !excluded.isEmpty { ipv4.excludedRoutes = excluded }
        ipv4.includedRoutes = routes
        if let dohWorkerURL {
            self.dohWorkerActive = true
            // ── Вариант Б: NEDNSOverHTTPSSettings + matchDomains ──────
            // Весь остальной DNS резолвится системой (обычный выборщик).
            // Воркер видит ТОЛЬКО точные домены из matchDomains.
            // НЕ используем [""] — он в 0.3.14 убивал сайты.
            let doh = NEDNSOverHTTPSSettings(servers: dohWorkerIPs)
            doh.serverURL = dohWorkerURL
            doh.matchDomains = dohMatchDomains
            doh.matchDomainsNoSearch = true
            settings.dnsSettings = doh
            NSLog("[WSBridge] DNS: DoH worker %@ match=%d ips=%d",
                  dohWorkerURL.absoluteString, dohMatchDomains.count, dohWorkerIPs.count)
            EventLog.append("cfg:doh=worker match=\(dohMatchDomains.count) ips=\(dohWorkerIPs.count) url=\(dohWorkerURL.absoluteString)")
            EventLog.append("cfg:routes=\(routes.count) fakeip=\(workerOn ? 1 : 0) excluded=\(excluded.count)")
        } else if localDNSEnabled {
            // НЕ объявляем dnsSettings ВООБЩЕ.
            //
            // Проверено на устройстве (журнал 01:21…01:27): при matchDomains
            // iOS считает 198.18.0.3 резолвером для ВСЕХ имён, но UDP:53
            // обрабатывается mDNSResponder'ом выше tun — ответа нет, и все
            // сайты «умирают». Без dnsSettings система резолвит сама (v13),
            // интернет жив; маршрутизация идёт ТОЛЬКО по SNI на реальных IP.
            //
            // LocalDNSResolver и FakeIP оставляем как запасной путь: если
            // на каком-то устройстве UDP:53 всё же доезжает — он сработает.
            settings.dnsSettings = nil
            NSLog("[WSBridge] DNS: system resolver, routing by SNI only, probe=%@", self.dnsProbeMode)
            EventLog.append("cfg:dns=system sni_only cidrs=\(resolvedCIDRs.count) proxy=\(proxyEndpoint != nil ? 1 : 0)")
        } else if let dnsList, !dnsList.isEmpty {
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
            // Несколько worker-доменов через запятую (как в десктопном
            // tg-ws-proxy). Пустые элементы режем; каждый ходит отдельной
            // сессией, распределяются round-robin.
            let domains = wd?.split(separator: ",")
                .map { $0.trimmingCharacters(in: .whitespaces) }
                .filter { !$0.isEmpty } ?? []
            self?.workerDomains = domains
            self?.workerDomain = domains.first
            EventLog.append("cfg:worker=\(self?.workerDomain ?? "-")(x\(domains.count))")
            // «DC → IP» маппинг: строки «номер:IP».
            self?.dcOverride = TunnelSession.parseDCOverride(
                proto?.providerConfiguration?["dcMap"] as? [String])
            if !(self?.dcOverride.isEmpty ?? true) {
                EventLog.append("cfg:dc_map=\(self?.dcOverride.count ?? 0)")
            }
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
            // Локальный DNS: таблица rewrites + upstream. Резолвер создан
            // ДО конфигурации: writePacket требует self.
            let resolver = LocalDNSResolver { [weak self] data in
                self?.writePacket(data)
            }
            self?.localDNS = resolver
            if (proto?.providerConfiguration?["localDNS"] as? Bool) == true {
                let hosts = proto?.providerConfiguration?["localDNSHosts"] as? String
                // Upstream: IP выбранного DNS + опциональный транспорт:
                // localDNSUpstreamDoT (SNI) или localDNSUpstreamDoH (URL);
                // оба пусты = plain UDP:53.
                let upstreams = (proto?.providerConfiguration?["localDNSUpstream"] as? [String]) ?? []
                let doT = proto?.providerConfiguration?["localDNSUpstreamDoT"] as? String
                let doH = proto?.providerConfiguration?["localDNSUpstreamDoH"] as? String
                // Прокси-домены и список прокси (автовыбор уже сделан
                // приложением; сюда доезжает ОДИН рабочий endpoint).
                let proxyDomains = (proto?.providerConfiguration?["proxyDomains"] as? [String]) ?? []
                let proxyURLs = (proto?.providerConfiguration?["proxies"] as? [String]) ?? []
                let proxyEndpoint = proxyURLs.compactMap { ProxyEndpoint.parse($0) }.first
                resolver.configure(hostsText: hosts, upstreams: upstreams,
                                   doT: doT, doHURL: doH,
                                   proxyDomains: proxyDomains)
                let transport = doT != nil ? "dot" : (doH != nil ? "doh" : "udp")
                EventLog.append("cfg:localdns=on rules=\(resolver.rewriteCount) upstream=\(upstreams.first ?? "system"):\(transport)")
                if let pe = proxyEndpoint {
                    self?.proxyEndpoint = pe
                    // SNI-фолбэк работает на тех же правилах, что и FakeIP:
                    // замыкание живёт на lwipQueue, EarlyIP-мапа — внутри LRDNS.
                    self?.proxyDomainMatcher = { [weak resolver] name in
                        resolver?.isProxyDomain(name) ?? false
                    }
                    EventLog.append("cfg:proxy=\(pe.display) domains=\(resolver.proxyDomainCount)")
                }
            } else {
                resolver.configure(hostsText: nil, upstreams: [])
            }
            self?.journalServer.start()
            self?.setupLWIP()
            self?.startTimers()
            self?.readLoop()
            self?.startPathMonitor()
            self?.scheduleLongSessionNudge()
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
            if let ldns = self.localDNS, ldns.rewriteCount > 0 || ldns.statForwarded > 0 {
                EventLog.append("ldns:rw=\(ldns.statRewritten) fwd=\(ldns.statForwarded) fail=\(ldns.statFailed) rules=\(ldns.rewriteCount)")
            }
            // Диагностика DNS: печатается всегда, даже когда всё по нулям —
            // именно нули и есть ответ («пакеты в туннель не приходят»).
            // udp53=0 при живом браузере = dnsSettings не применился.
            if self.localDNS != nil {
                let dstList = self.dnsDstSample.isEmpty
                    ? "-" : self.dnsDstSample.joined(separator: ",")
                EventLog.append("dnsprobe:m=\(self.dnsProbeMode) udp53=\(self.statUDP53) done=\(self.statDNSHandled) udpOth=\(self.statUDPOther) dst=[\(dstList)]")
            }
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
        let dotted = "\(Int((dcIP >> 24) & 255)).\(Int((dcIP >> 16) & 255)).\(Int((dcIP >> 8) & 255)).\(Int(dcIP & 255))"
        NSLog("[WSBridge] accept conn \(connId) dc=\(dcIP) (\(dotted)) port=\(lwip.dstPort(connId: connId))")
        postDarwinEvent("accept")
        EventLog.append("accept:c\(connId):\(dotted):p\(lwip.dstPort(connId: connId)):sni=\(isSNIInterceptCandidate(dcIP) ? 1 : 0):cidrs=\(sniCIDRs.count)")
        let dstPort = lwip.dstPort(connId: connId)
        // ── DoH-воркер: 198.18.1.x — МЕТКА, не мапа ─────────────────
        // Воркер вернул один и тот же FakeIP на все домены из matchDomains.
        // localDNS.proxyDomain(forFakeIP:) пуста (DNS в packetFlow не
        // приходит), поэтому старый путь глух. Домен достаём из TLS SNI
        // первого пакета и сразу идём в прокси по ИМЕНИ.
        // Это и есть роутинг пакета (этап 4), сделанный минимально.
        if dohWorkerActive, let proxy = proxyEndpoint,
           (dcIP >> 24) == 198 && ((dcIP >> 16) & 0xFF) == 18 && ((dcIP >> 8) & 0xFF) == 1 {
            EventLog.append("doh_proxy:conn\(connId):p\(dstPort)")
            let session = TunnelSession(
                connId: connId, dcIP: dcIP, workerDomain: nil,
                dcOverride: [:], bridge: lwip, queue: lwipQueue,
                proxyDomainMatcher: nil,       // не проверяем: воркер уже отфильтровал
                sniProxyEndpoint: proxy,
                dstPort: dstPort,
                sniProxyUnconditional: true)
            sessions[connId] = session
            return
        }
        // Прокси-домен: dst в 198.18.1.0/24 → домен из fake-IP-мапы
        // LRDNS, соединение через SOCKS5/HTTP-прокси.
        if let proxy = proxyEndpoint,
           (dcIP >> 24) == 198 && ((dcIP >> 16) & 0xFF) == 18 && ((dcIP >> 8) & 0xFF) == 1,
           let domain = localDNS?.proxyDomain(forFakeIP: dcIP) {
            EventLog.append("proxy:conn\(connId):\(domain)")
            let session = TunnelSession(
                connId: connId, dcIP: dcIP, workerDomain: domain,
                dcOverride: [:], bridge: lwip, queue: lwipQueue,
                proxyEndpoint: proxy, dstPort: dstPort)
            sessions[connId] = session
            return
        }
        // Real-IP, пришедший по CIDR-маршруту (приложение обошло FakeIP
        // через свой DoH). Даём сессии SNI-парсер: домен в списке → прокси,
        // нет → DIRECT на исходный IP. Telegram сюда не попадает (его
        // подсети обслуживаются WS-веткой ниже и в cidrs не входят).
        if let matcher = proxyDomainMatcher, let proxy = proxyEndpoint,
           isSNIInterceptCandidate(dcIP) {
            EventLog.append("sni:watch:c\(connId)")
            let session = TunnelSession(
                connId: connId, dcIP: dcIP, workerDomain: nil,
                dcOverride: [:], bridge: lwip, queue: lwipQueue,
                proxyDomainMatcher: matcher,
                sniProxyEndpoint: proxy,
                dstPort: dstPort)
            sessions[connId] = session
            return
        }
        // Несколько worker'ов: распределяем соединения round-robin, чтобы
        // CF не троттлил один домен и было живое разнесение нагрузки.
        let domain: String?
        if workerDomains.count > 1 {
            domain = workerDomains[workerRRIndex % workerDomains.count]
            workerRRIndex += 1
        } else {
            domain = workerDomain
        }
        let session = TunnelSession(
            connId: connId, dcIP: dcIP, workerDomain: domain,
            dcOverride: dcOverride, bridge: lwip, queue: lwipQueue)
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
                    // Диагностика: считаем UDP и отдельно UDP:53 ДО всех
                    // фильтров — иначе не отличить «пакет не пришёл» от
                    // «пакет пришёл и был отброшен».
                    if packet.count > 9, packet[9] == 17 {
                        let ihl = Int(packet[0] & 0x0F) * 4
                        if ihl >= 20, packet.count > ihl + 4 {
                            let dstPort = (Int(packet[ihl + 2]) << 8) | Int(packet[ihl + 3])
                            if dstPort == 53 {
                                self.statUDP53 += 1
                                if self.dnsDstSample.count < 8 {
                                    let dst = "\(packet[16]).\(packet[17]).\(packet[18]).\(packet[19])"
                                    self.dnsDstSample.append("\(dst):53")
                                }
                            } else {
                                self.statUDPOther += 1
                            }
                        }
                    }
                    // Локальный DNS-резолвер: запросы к 198.18.0.2:53
                    // потребляет он (rewrites → upstream → системный),
                    // в lwIP они не идут (UDP в стеке выключен).
                    if let resolver = self.localDNS, resolver.tryHandle(packet) {
                        self.statDNSHandled += 1
                        continue
                    }
                    // Только TCP в lwIP; UDP (QUIC) мгновенно сбрасываем
                    // ICMP Port Unreachable — сетевой стек iOS за 0 мс
                    // переключается на TCP TLS вместо ожидания таймаута.
                    guard packet.count > 9, packet[9] == 6 else {
                        EventLog.inOther += 1
                        if packet.count >= 28, packet[9] == 17 {
                            let ihl = Int(packet[0] & 0x0F) * 4
                            if ihl >= 20, packet.count >= ihl + 8 {
                                let dport = (Int(packet[ihl + 2]) << 8) | Int(packet[ihl + 3])
                                if dport == 443 {
                                    self.writePacket(Self.icmpPortUnreachable(for: packet))
                                }
                            }
                        }
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

    /// ICMP Destination Unreachable (code 3 = port unreachable) в ответ на
    /// UDP:443. Заставляет приложение мгновенно сделать фолбэк с QUIC на TCP.
    private static func icmpPortUnreachable(for original: Data) -> Data {
        let ihl = Int(original[0] & 0x0F) * 4
        // ICMP(8) + IP-заголовок исходного пакета + первые 8 байт UDP.
        let payload = original.subdata(in: 0..<min(ihl + 8, original.count))
        var icmp = Data(repeating: 0, count: 8)
        icmp[0] = 3     // type: Destination Unreachable
        icmp[1] = 3     // code: Port Unreachable
        icmp.append(payload)

        var ip = Data(count: 20)
        ip[0] = 0x45
        let total = 20 + icmp.count
        ip[2] = UInt8((total >> 8) & 0xFF)
        ip[3] = UInt8(total & 0xFF)
        ip[8] = 64
        ip[9] = 1       // ICMP
        // src = адрес назначения исходного пакета (кому отвечаем)
        ip.replaceSubrange(12..<16, with: original.subdata(in: 16..<20))
        // dst = отправитель исходного UDP-пакета
        ip.replaceSubrange(16..<20, with: original.subdata(in: 12..<16))
        var sum: UInt32 = 0
        for i in stride(from: 0, to: 20, by: 2) {
            sum += (UInt32(ip[i]) << 8) | UInt32(ip[i + 1])
        }
        while sum >> 16 != 0 { sum = (sum & 0xFFFF) + (sum >> 16) }
        let csum = ~sum & 0xFFFF
        ip[10] = UInt8((csum >> 8) & 0xFF)
        ip[11] = UInt8(csum & 0xFF)

        var out = ip
        out.append(icmp)
        return out
    }

    /// CIDR-строки вида "104.18.0.0/16" → (база, маска) в host-порядке.
    /// Битые/невалидные строки молча пропускаются.
    private static func parseCIDRs(_ raw: [String]) -> [(UInt32, UInt32)] {
        var out: [(UInt32, UInt32)] = []
        for line in raw {
            let parts = line.split(separator: "/")
            guard parts.count == 2,
                  let ip = IPv4Addr.parse(String(parts[0])),
                  let bits = Int(parts[1]), bits >= 0, bits <= 32 else { continue }
            let mask: UInt32 = bits == 0 ? 0 : UInt32.max << (32 - bits)
            out.append((ip & mask, mask))
        }
        return out
    }

    /// Попал ли real-IP в подсети, где мы смотрим SNI. Telegram-диапазоны
    /// сюда не входят: их обслуживает WS-ветка, и парсить у них ClientHello
    /// бессмысленно (MTProto obfuscated — это не TLS).
    private func isSNIInterceptCandidate(_ ip: UInt32) -> Bool {
        guard !sniCIDRs.isEmpty else { return false }
        if (ip >> 24) == 149 && ((ip >> 16) & 0xFF) == 154 { return false }
        if (ip >> 24) == 91 && ((ip >> 16) & 0xFF) == 108 { return false }
        if (ip >> 24) == 198 && ((ip >> 16) & 0xFF) == 18 { return false }
        for (base, mask) in sniCIDRs where (ip & mask) == base { return true }
        return false
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
        // Нудж 6ч гасим ЗДЕСЬ: stopTunnel исполняется всегда, в отличие от
        // кода приложения, которое к этому моменту может быть уже убито.
        cancelLongSessionNudge()
        journalServer.stop()
        pathMonitor?.cancel(); pathMonitor = nil
        pollTimer?.cancel(); pollTimer = nil
        ioTimer?.cancel(); ioTimer = nil
        // ВАЖНО: completionHandler зовём ДО дренажа сессий и НЕ через
        // lwipQueue.sync. Если очередь занята (WS-запись в мёртвую сеть,
        // poll с ретрансмитами), sync не вернётся никогда — iOS не получает
        // подтверждения остановки, убивает провайдер по таймауту и ПОДНИМАЕТ
        // туннель заново. Снаружи это выглядит как «выключил — он сам
        // включился, со второго раза выключается».
        completionHandler()
        lwipQueue.async { [weak self] in
            guard let self else { return }
            for (_, session) in self.sessions { session.handleClose(reason: 1) }
            self.sessions.removeAll()
        }
    }

    /// ponytail: Wi-Fi↔соты и подобные переключения рвут WS-сессии и lwIP-
    /// состояние молча — трафик «протухает» до ручного перезапуска. Мониторим
    /// путь здесь (процесс жив, пока туннель включен) и nudg'им пользователя
    /// локальным уведомлением. Троттлинг 5 мин: флэпы Wi-Fi не спамлят.
    private func startPathMonitor() {
        // Уведомления о смене сети отключены полностью. Причина: при
        // включении/выключении ТУННЕЛЯ NWPathMonitor видит появление/
        // исчезновение собственного utun (тип .other) и считает это
        // «сменой сети» — пользователь получал ложный нудж на каждом
        // старте/стопе, а статус-кнопка в приложении рассинхронизировалась.
        // Оставляем монитор только для строки net_change в журнале.
        let m = NWPathMonitor()
        m.pathUpdateHandler = { [weak self] path in
            guard let self else { return }
            // Берём ТОЛЬКО физические интерфейсы: utun/loopback игнорируем.
            let ifaces = path.availableInterfaces
                .filter { $0.type == .wifi || $0.type == .cellular || $0.type == .wiredEthernet }
                .map { Self.ifaceName($0.type) }
                .sorted()
                .joined(separator: "+")
            let sig = "\(path.status):\(ifaces)"
            defer { self.lastPathSig = sig }
            guard let prev = self.lastPathSig, prev != sig else { return }
            EventLog.append("net_change:\(prev)->\(sig)")
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

    /// Нудж «долго включен»: одноразовый триггер через 6 ч, планирует и
    /// снимает САМО расширение. Раньше это делало приложение с repeats:true —
    /// и после выключения туннеля повторяющийся триггер продолжал жить,
    /// потому что снять его было некому (приложение уже убито системой).
    /// Одноразовость + снятие в stopTunnel (он исполняется всегда) закрывают
    /// этот класс спама полностью.
    private func scheduleLongSessionNudge() {
        let c = UNMutableNotificationContent()
        c.title = "Туннель включен давно"
        c.body = "Больше 6 часов без перезапуска. Если интернет тормозит — перезапусти туннель в WSBridge."
        let req = UNNotificationRequest(
            identifier: Self.longSessionID, content: c,
            trigger: UNTimeIntervalNotificationTrigger(
                timeInterval: 6 * 3600, repeats: false))
        UNUserNotificationCenter.current().add(req) { err in
            EventLog.append("notif_long:\(err?.localizedDescription ?? "ok")")
        }
    }

    private func cancelLongSessionNudge() {
        UNUserNotificationCenter.current()
            .removePendingNotificationRequests(withIdentifiers: [Self.longSessionID])
        UNUserNotificationCenter.current()
            .removeDeliveredNotifications(withIdentifiers: [Self.longSessionID])
    }

    override func handleAppMessage(
        _ messageData: Data,
        completionHandler: ((Data?) -> Void)?
    ) {
        // История по дням копит ПРИЛОЖЕНИЕ — расширение умирает в любой
        // момент и персистентности ему не доверяют. Здесь только отдаём
        // структурированный снапшот уже посчитанных чисел.
        //
        // Снапшот снимается на lwipQueue: handleAppMessage приходит с
        // IPC-потока системы, а sessions (словарь) и счётчики мутируются
        // только на lwipQueue. Чтение с чужого потока во время вставки/
        // удаления — краш расширения (реhash словаря на середине), после
        // которого iOS переподнимает включённый конфиг: статус качается
        // connected↔disconnecting, сокеты умирают пачкой (ENOTCONN),
        // «выключить» не выходит до перезапуска приложения. sync здесь
        // безопасен: вызывающий — IPC-поток приложения, НЕ системный путь
        // остановки (stopTunnel зовёт completionHandler до дренажа).
        lwipQueue.sync {
            let json: [String: Any] = [
                "pkts": packetCount,
                "bytes": byteCount,
                "upBytes": EventLog.upBytes,
                "rxBytes": EventLog.rxBytes,
                "uptime": Int(Date().timeIntervalSince(startedAt)),
                "conns": sessions.count,
            ]
            if let data = try? JSONSerialization.data(withJSONObject: json) {
                completionHandler?(data)
            } else {
                completionHandler?(nil)
            }
        }
    }
}
