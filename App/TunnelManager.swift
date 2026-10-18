import Foundation
import Network
import NetworkExtension
import UserNotifications

/// Читает журнал расширения loopback TCP (127.0.0.1:51001, JournalServer).
/// Nonisolated: колбэки NWConnection приходят с произвольных потоков.
private final class JournalReader {
    private let onText: (String) -> Void
    private var onDone: (() -> Void)?
    private var finished = false
    private var acc = Data()
    private var conn: NWConnection?

    init(onText: @escaping (String) -> Void) { self.onText = onText }

    func run(onDone: @escaping () -> Void) {
        self.onDone = onDone
        let conn = NWConnection(host: "127.0.0.1", port: 51001, using: .tcp)
        self.conn = conn
        conn.stateUpdateHandler = { [weak self] state in
            switch state {
            case .ready: self?.readMore()
            case .failed(let err): self?.finish("журнал недоступен: conn: \(err.localizedDescription)")
            case .cancelled: self?.finish("журнал недоступен: cancelled")
            default: break
            }
        }
        conn.start(queue: .global(qos: .userInitiated))
        DispatchQueue.global().asyncAfter(deadline: .now() + 5) { [weak self] in
            self?.finish("журнал недоступен: timeout 5s")
        }
    }

    private func readMore() {
        conn?.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] data, _, isComplete, error in
            guard let self else { return }
            if let data, !data.isEmpty { self.acc.append(data) }
            if error != nil || isComplete || data == nil {
                if self.acc.isEmpty {
                    self.finish("журнал недоступен: empty response")
                } else {
                    self.finish("журнал:\n" + (String(data: self.acc, encoding: .utf8) ?? "decode error"))
                }
            } else {
                self.readMore()
            }
        }
    }

    private func finish(_ text: String) {
        if finished { return }
        finished = true
        conn?.cancel()
        conn = nil
        if text.hasPrefix("журнал недоступен") {
            onText(text + "\n\nЖурнал живёт внутри процесса туннеля. Включи VPN и обнови — первым блоком будет === PREV RUN ===: лог прошлого запуска с причиной смерти (tunnel_stop:reason=N или обрыв + mem= перед ним).")
        } else {
            onText(text)
        }
        onDone?()
        onDone = nil
    }
}

// ponytail: глобальная ссылка для C-callback Darwin notifications
private var tunnelManagerRef: TunnelManager?
private let darwinEventNames = ["pkts", "accept", "init", "ws_sent", "ws_try", "ws_up", "ws_data", "ws_recv", "ws_close", "ws_fail"]

private extension Array {
    subscript(safe index: Int) -> Element? {
        indices.contains(index) ? self[index] : nil
    }
}

@MainActor
final class TunnelManager: ObservableObject {
    // ponytail: bundle id может измениться при переподписи GBox — выводим из
    // фактического id приложения, а не хардкода. Работает и с исходным, и с
    // переподписанным бандлом. Расширение по-прежнему ищется как "<app id>.tunnel".
    static let providerBundleId: String = {
        let app = Bundle.main.bundleIdentifier ?? "com.l1ratch.WSBridge"
        return app + ".tunnel"
    }()

    @Published private(set) var status: NEVPNStatus = .invalid {
        didSet {
            guard oldValue != status else { return }
            statusHistory.append(
                "\(Self.netTimeFmt.string(from: Date())) \(oldValue) -> \(status)")
            if statusHistory.count > 40 {
                statusHistory.removeFirst(statusHistory.count - 40)
            }
        }
    }
    /// История переходов статуса — диагностика «мёртвой кнопки».
    @Published private(set) var statusHistory: [String] = []
    @Published private(set) var stats: String?
    @Published private(set) var journalText: String?
    @Published private(set) var lastPacketSignal: Date?
    @Published private(set) var lastEvent: String?
    @Published private(set) var lastEventTime: Date?
    @Published private(set) var lastAccept: Date?
    @Published var errorMessage: String?
    /// Домен собственного CF worker'а пользователя (pipe-режим). пустой = kws-каскад.
    @Published var workerDomain: String = UserDefaults.standard.string(forKey: "workerDomain") ?? "" {
        didSet { UserDefaults.standard.set(workerDomain, forKey: "workerDomain") }
    }

    // MARK: - DNS

    struct DNSConfig: Codable, Identifiable, Equatable {
        var id: String
        var name: String
        var description: String
        var servers: [String]       // IP-адреса (bootstrap + plain fallback)
        var dohURL: String?         // DNS-over-HTTPS URL
        var dotHostname: String?    // DNS-over-TLS hostname (SNI)
        var isPreset: Bool
        var site: String?           // офсайт провайдера (обязателен для пресетов)

        /// Какие транспорты конфиг умеет.
        var supportsDoT: Bool {
            !(dotHostname ?? "").trimmingCharacters(in: .whitespaces).isEmpty
        }
        var supportsDoH: Bool {
            !(dohURL ?? "").trimmingCharacters(in: .whitespaces).isEmpty
        }

        /// Короткая метка транспортов для списков.
        var transportsLabel: String {
            switch (supportsDoT, supportsDoH) {
            case (true, true): "DoT · DoH"
            case (true, false): "DoT"
            case (false, true): "DoH"
            default: "без шифрования"
            }
        }
    }

    /// Транспорт шифрованного DNS. По умолчанию DoT: коннект идёт напрямую
    /// к IP:853 с SNI и не требует бутстрап-резолва имени сервера, который
    /// система делает уже под туннелем (эта ступень и ломала DoH).
    enum DNSMode: String, CaseIterable {
        case dot, doh

        var title: String {
            switch self {
            case .dot: "DNS-over-TLS"
            case .doh: "DNS-over-HTTPS"
            }
        }
        var shortTitle: String {
            switch self {
            case .dot: "DoT"
            case .doh: "DoH"
            }
        }
        var hint: String {
            switch self {
            case .dot: "Порт 853. Прямой коннект к IP сервера — без резолва имени под туннелем."
            case .doh: "Порт 443. Маскируется под обычный HTTPS, но требует резолва имени сервера."
            }
        }
    }

    /// Пресеты: не удаляются и не редактируются. Подписи статичные и
    /// короткие: базовые резолверы — «без фильтрации», остальные — обход.
    static let dnsPresets: [DNSConfig] = [
        DNSConfig(id: "system", name: "Системный",
                  description: "DNS устройства, туннель его не трогает",
                  servers: [], dohURL: nil, dotHostname: nil, isPreset: true, site: nil),
        DNSConfig(id: "cloudflare", name: "Cloudflare",
                  description: "Базовый, без фильтрации",
                  servers: ["1.1.1.1", "1.0.0.1"],
                  dohURL: "https://cloudflare-dns.com/dns-query",
                  dotHostname: "one.one.one.one", isPreset: true,
                  site: "https://one.one.one.one/"),
        DNSConfig(id: "google", name: "Google",
                  description: "Базовый, без фильтрации",
                  servers: ["8.8.8.8", "8.8.4.4"],
                  dohURL: "https://dns.google/dns-query",
                  dotHostname: "dns.google", isPreset: true,
                  site: "https://developers.google.com/speed/public-dns"),
        DNSConfig(id: "comss", name: "Comss.one",
                  description: "Для обхода гео-блокировок",
                  servers: ["83.220.169.155", "212.109.195.93"],
                  dohURL: "https://dns.comss.one/dns-query",
                  dotHostname: "dns.comss.one", isPreset: true,
                  site: "https://www.comss.ru/page.php?id=7315"),
        DNSConfig(id: "malw", name: "Malw.link",
                  description: "Для обхода гео-блокировок",
                  servers: ["179.254.166.171", "164.5.224.81"],
                  dohURL: "https://dns.malw.link/dns-query",
                  dotHostname: "dns.malw.link", isPreset: true,
                  site: "https://info.dns.malw.link/"),
        DNSConfig(id: "geohide", name: "GeoHide",
                  description: "Для обхода гео-блокировок",
                  // 159.194.200.33 из офсписка мёртв (53/853/443 закрыты) — не тащим.
                  servers: ["193.233.112.68", "193.233.112.67", "193.233.112.88",
                            "37.230.192.51"],
                  dohURL: "https://geohide.ru/dns-query",
                  dotHostname: "geohide.ru", isPreset: true,
                  site: "https://geohide.ru/"),
        DNSConfig(id: "xbox", name: "XBox DNS",
                  description: "Для обхода гео-блокировок",
                  // .55/853 живой, .54 — нет; .56/.57 — то, куда резолвится офхост.
                  servers: ["111.88.96.55", "111.88.96.54"],
                  dohURL: "https://xbox-dns.ru/dns-query",
                  dotHostname: "xbox-dns.ru", isPreset: true,
                  site: "https://xbox-dns.ru/#faq"),
        DNSConfig(id: "malw-gateway", name: "Cloudflare Gateway",
                  description: "Для обхода гео-блокировок",
                  servers: ["162.159.36.5", "162.159.36.20"],
                  dohURL: "https://5u35p8m9i7.cloudflare-gateway.com/dns-query",
                  dotHostname: "5u35p8m9i7.cloudflare-gateway.com", isPreset: true,
                  site: "https://info.dns.malw.link/"),
    ]

    /// Выбранный транспорт шифрованного DNS (по умолчанию DoT).
    @Published var dnsModeRaw: String =
        UserDefaults.standard.string(forKey: "dnsMode") ?? DNSMode.dot.rawValue {
        didSet { UserDefaults.standard.set(dnsModeRaw, forKey: "dnsMode") }
    }

    var dnsMode: DNSMode { DNSMode(rawValue: dnsModeRaw) ?? .dot }

    /// Фактический транспорт для выбранного конфига: если предпочитаемый
    /// недоступен у конфига — берём второй, если и его нет — nil (plain :53).
    var effectiveDNSMode: DNSMode? {
        switch dnsMode {
        case .dot: return selectedDNS.supportsDoT ? .dot
            : (selectedDNS.supportsDoH ? .doh : nil)
        case .doh: return selectedDNS.supportsDoH ? .doh
            : (selectedDNS.supportsDoT ? .dot : nil)
        }
    }

    /// Свои DNS-конфиги (хранятся в UserDefaults).
    @Published var customDNS: [DNSConfig] = {
        guard let data = UserDefaults.standard.data(forKey: "customDNS"),
              let configs = try? JSONDecoder().decode([DNSConfig].self, from: data) else { return [] }
        return configs
    }() {
        didSet {
            if let data = try? JSONEncoder().encode(customDNS) {
                UserDefaults.standard.set(data, forKey: "customDNS")
            }
        }
    }

    /// ID выбранного DNS ("comss" по умолчанию при первой установке).
    @Published var selectedDNSId: String = UserDefaults.standard.string(forKey: "selectedDNSId") ?? "comss" {
        didSet { UserDefaults.standard.set(selectedDNSId, forKey: "selectedDNSId") }
    }

    /// Все DNS: пресеты + свои.
    var allDNS: [DNSConfig] { Self.dnsPresets + customDNS }

    /// Выбранный DNS-конфиг.
    var selectedDNS: DNSConfig {
        allDNS.first { $0.id == selectedDNSId } ?? Self.dnsPresets[0]
    }

    /// IP-адреса для туннеля (пусто = системный).
    var activeDNSServers: [String] { selectedDNS.servers }

    // MARK: - Фронты (hot-обновление без пересборки)

    /// Актуальный список фронтов (базовые домены, без kws{dc}. префикса).
    /// Пусто = встроенный из CFDomains. Хранится в UserDefaults.
    @Published private(set) var frontBases: [String] = {
        guard let saved = UserDefaults.standard.stringArray(forKey: "frontBases"),
              !saved.isEmpty else { return [] }
        return saved
    }() {
        didSet { UserDefaults.standard.set(frontBases, forKey: "frontBases") }
    }

    /// Дата последнего успешного обновления списка фронтов.
    @Published private(set) var frontsUpdatedAt: Date? {
        didSet { UserDefaults.standard.set(frontsUpdatedAt, forKey: "frontsUpdatedAt") }
    }

    /// Статус последнего обновления (для UI).
    @Published var frontsUpdateMessage: String?

    /// URL списка фронтов. Апстрим + два зеркала jsDelivr (GitHub в РФ плавает).
    private static let frontListURLs = [
        "https://raw.githubusercontent.com/Flowseal/tg-ws-proxy/master/.github/cfproxy-domains.txt",
        "https://cdn.jsdelivr.net/gh/Flowseal/tg-ws-proxy@master/.github/cfproxy-domains.txt",
        "https://fastly.jsdelivr.net/gh/Flowseal/tg-ws-proxy@master/.github/cfproxy-domains.txt",
    ]

    /// Скачивает свежий список фронтов (все URL по очереди).
    /// Возвращает (кол-во доменов, дата) или кладёт ошибку в frontsUpdateMessage.
    @discardableResult
    func updateFronts() async -> Bool {
        frontsUpdateMessage = "Обновление…"
        // Причина последнего отказа ПРИ ОТВЕТЕ источника: сеть жива, но файл
        // негодный (битый/протухший). Отличаем от «нет сети».
        var rejection: String?
        for urlString in Self.frontListURLs {
            guard let url = URL(string: urlString) else { continue }
            var request = URLRequest(url: url)
            request.timeoutInterval = 10
            // кэш не нужен — хотим всегда свежее
            request.cachePolicy = .reloadIgnoringLocalCacheData
            do {
                let (data, response) = try await URLSession.shared.data(for: request)
                guard let http = response as? HTTPURLResponse, http.statusCode == 200 else { continue }
                let text = String(data: data, encoding: .utf8) ?? ""
                // Валидация: домены по одному в строке, буквы/цифры/точки/дефисы.
                let domains = text
                    .split(separator: "\n")
                    .map { $0.trimmingCharacters(in: .whitespaces) }
                    .filter { !$0.isEmpty && $0.range(of: "^[a-z0-9][a-z0-9.-]*$", options: .regularExpression, range: $0.startIndex..<$0.endIndex, locale: nil) != nil }
                guard domains.count >= 3 else {
                    rejection = "битый файл (\(domains.count) записей)"
                    continue
                }
                let unique = Array(Set(domains))
                // Android-порт: DNS-резолв каждого домена ДО сохранения —
                // мёртвые не попадают в список, файл с <3 живых = протухший
                // целиком (NXDOMAIN-волны апстрима). Резолв параллельно.
                let alive = await withTaskGroup(of: String?.self) { group in
                    for d in unique {
                        group.addTask {
                            var hints = addrinfo()
                            hints.ai_family = AF_INET
                            var res: UnsafeMutablePointer<addrinfo>?
                            let rc = getaddrinfo(d, nil, &hints, &res)
                            defer { freeaddrinfo(res) }
                            return rc == 0 ? d : nil
                        }
                    }
                    var out: [String] = []
                    for await r in group { if let d = r { out.append(d) } }
                    return out
                }
                guard alive.count >= 3 else {
                    rejection = "протух: живых \(alive.count) из \(unique.count)"
                    continue
                }
                frontBases = alive
                frontsUpdatedAt = Date()
                frontsUpdateMessage = "Обновлено: \(alive.count) живых (из \(unique.count))"
                return true
            } catch {
                continue // следующий URL
            }
        }
        if let rejection {
            // Сеть жива, источник ответил — негодный сам файл. Прежний
            // список frontBases не трогаем, каскад работает на нём.
            frontsUpdateMessage = "Источник ответил, но список негодный: \(rejection). Оставил прежний."
        } else {
            frontsUpdateMessage = "Не удалось обновить (нет сети или источники недоступны)"
        }
        return false
    }

    // ── Смена сети: догонялка через журнал ──────────────────────
    /// In-app алерт «сеть менялась, пока туннель был включен».
    @Published var showNetChangeAlert = false
    /// UN.delegate — слабый; держим презентера навсегда.
    private static let bannerPresenter = BannerPresenter()
    private var lastToggleAt = Date.distantPast
    private var lastActiveAt = Date()
    private static let netTimeFmt: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "HH:mm:ss"
        return f
    }()

    /// Вызывается при выходе приложения на передний план.
    func noteActive() {
        let since = lastActiveAt
        lastActiveAt = Date()
        // Если уведомления разрешены — их постит расширение (UN работают
        // и в фоне, и в форграунде через willPresent). Догонялка через
        // журнал — только при отказе в разрешении, иначе двойные алерты.
        UNUserNotificationCenter.current().getNotificationSettings { settings in
            guard settings.authorizationStatus == .denied else { return }
            DispatchQueue.main.async {
                self.fetchStats()
                DispatchQueue.main.asyncAfter(deadline: .now() + 0.8) {
                    self.alertMissedNetChanges(since: since)
                }
            }
        }
    }

    private func alertMissedNetChanges(since: Date) {
        guard status == .connected, let text = journalText else { return }
        let cal = Calendar.current
        for line in text.split(separator: "\n") where line.contains("net_change:") {
            guard let head = line.split(separator: " ").first,
                  let t = Self.netTimeFmt.date(from: String(head)) else { continue }
            var dt = cal.date(
                bySettingHour: cal.component(.hour, from: t),
                minute: cal.component(.minute, from: t),
                second: cal.component(.second, from: t),
                of: Date()) ?? t
            if dt < since.addingTimeInterval(-43_200) { dt.addTimeInterval(86_400) }
            if dt > since {
                showNetChangeAlert = true
                return
            }
        }
    }

    /// Перезапуск: выкл → дождаться отключения → вкл.
    func restartTunnel() async {
        guard status == .connected || status == .reasserting else { return }
        await toggle(force: true)
        for _ in 0..<40 {
            if status == .disconnected || status == .invalid { break }
            try? await Task.sleep(nanoseconds: 250_000_000)
        }
        await toggle(force: true)
    }

    private var manager: NETunnelProviderManager?
    private var darwinObserver: CFRunLoopObserver?
    nonisolated(unsafe) private static var currentReader: JournalReader?

    init() {
        tunnelManagerRef = self
        NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange, object: nil, queue: .main
        ) { [weak self] note in
            guard let conn = note.object as? NEVPNConnection else { return }
            Task { @MainActor in self?.status = conn.status }
        }
        observeDarwinNotifications()
        // Статус может рассинхрониться с NEVPNStatusDidChange — кнопка
        // «выключить» мертвеет при залипшем .connecting (баг 81/82).
        // Самолечимся: читаем connection.status каждые 5 с, пока живо приложение.
        Timer.scheduledTimer(withTimeInterval: 5, repeats: true) { [weak self] _ in
            guard let self, let m = self.manager else { return }
            let s = m.connection.status
            DispatchQueue.main.async {
                if self.status != s { self.status = s }
            }
        }
        UNUserNotificationCenter.current().delegate = Self.bannerPresenter
        Task { await reload() }
    }

    /// ponytail: Darwin notifications — единственный IPC без entitlements.
    /// Расширение постит события на каждом этапе; приложение слушает.
    private func observeDarwinNotifications() {
        for (index, event) in darwinEventNames.enumerated() {
            let name = "com.l1ratch.WSBridge.\(event)" as CFString
            CFNotificationCenterAddObserver(
                CFNotificationCenterGetDarwinNotifyCenter(),
                UnsafeRawPointer(bitPattern: index + 1),
                { _, observer, _, _, _ in
                    DispatchQueue.main.async {
                        guard let ref = tunnelManagerRef else { return }
                        let idx = (Int(bitPattern: observer) ?? 1) - 1
                        let eventName = darwinEventNames[safe: idx] ?? "unknown"
                        // ponytail: pkts и accept не должны перетирать WS-стадию —
                        // пробы Telegram плодят accept'ы без продолжения и прячут
                        // реальную стадию живой сессии.
                        if eventName == "pkts" {
                            ref.lastPacketSignal = Date()
                        } else if eventName == "accept" {
                            ref.lastAccept = Date()
                        } else {
                            ref.lastEvent = eventName
                            ref.lastEventTime = Date()
                        }
                        ref.updateStatsDisplay()
                    }
                },
                name,
                nil,
                .deliverImmediately
            )
        }
    }

    func updateStatsDisplay() {
        var parts: [String] = []
        if let event = lastEvent, let time = lastEventTime {
            let age = Int(Date().timeIntervalSince(time))
            parts.append("WS-стадия: \(event) (\(age)с назад)")
        } else {
            parts.append("WS-стадия: событий не было")
        }
        if let signal = lastPacketSignal {
            let age = Int(Date().timeIntervalSince(signal))
            parts.append(age < 3 ? "трафик течёт" : "последний трафик \(age)с назад")
        }
        if let accept = lastAccept {
            parts.append("accept: \(Int(Date().timeIntervalSince(accept)))с назад")
        }
        stats = parts.isEmpty ? "сигналов от расширения не было" : parts.joined(separator: "\n")
    }

    func fetchStats() {
        updateStatsDisplay()
        // ponytail: журнал читается loopback TCP с 127.0.0.1:51001 — расширение
        // держит там NWListener (JournalServer). Loopback в туннель не попадает,
        // песочницы сокетам между процессами не мешают.
        journalText = "журнал: читаю…"
        let reader = JournalReader { [weak self] text in
            Task { @MainActor in self?.journalText = text }
        }
        Self.currentReader = reader
        reader.run { Self.currentReader = nil }
    }

    func reload() async {
        manager = try? await NETunnelProviderManager.loadAllFromPreferences().first
        status = manager?.connection.status ?? .invalid
    }

    func toggle(force: Bool = false) async {
        // Дебаунс: параллельные saveToPreferences от дабл-тапов — гонки.
        // Кнопка больше не disabled ни в каком статусе: залипший
        // published-статус не должен убивать тап (баг билдов 81-84);
        // направление решения читается ниже с живого connection.status.
        guard force || Date().timeIntervalSince(lastToggleAt) > 2 else { return }
        lastToggleAt = Date()
        errorMessage = nil
        // Локальные уведомления (нудж «долго включен» + «сеть сменилась»
        // из расширения): разрешение спрашиваем один раз, при включении.
        if status != .connected {
            UNUserNotificationCenter.current()
                .requestAuthorization(options: [.alert]) { _, _ in }
        }
        // Автообновление списка фронтов: тихо, в фоне, ПОСЛЕ включения —
        // не конкурирует с saveToPreferences за UserDefaults и не влияет
        // на старт. Не чаще раза в 30 минут. Применится при след. включении.
        let needsFrontsUpdate = (frontsUpdatedAt?.timeIntervalSinceNow ?? -3600) < -1800
        do {
            let m: NETunnelProviderManager
            if let existing = manager {
                m = existing
            } else {
                // Сохранять свежий менеджер БЕЗ protocolConfiguration нельзя:
                // NEVPNError 1 «Missing protocol or protocol has invalid type».
                // Протокол назначается ниже, до первого saveToPreferences.
                let fresh = NETunnelProviderManager()
                fresh.localizedDescription = "WSBridge"
                m = fresh
            }
            // Конфигурация пересоздаётся при каждом включении: домен worker'а
            // доезжает до расширения через providerConfiguration.
            let proto = NETunnelProviderProtocol()
            proto.providerBundleIdentifier = Self.providerBundleId
            proto.serverAddress = "WSBridge"
            let wd = workerDomain.trimmingCharacters(in: .whitespacesAndNewlines)
            var config: [String: NSObject] = [:]
            if !wd.isEmpty { config["worker"] = wd as NSString }
            if !frontBases.isEmpty { config["fronts"] = frontBases as NSArray }
            if !activeDNSServers.isEmpty {
                config["dns"] = activeDNSServers as NSArray
                // Транспорт выбирает пользователь (свитчер). Передаём РОВНО
                // один ключ: расширение ничего не додумывает за него.
                switch effectiveDNSMode {
                case .doh:
                    if let doh = selectedDNS.dohURL { config["doh"] = doh as NSString }
                case .dot:
                    if let dot = selectedDNS.dotHostname { config["dot"] = dot as NSString }
                case nil:
                    break // ни DoT, ни DoH — plain :53
                }
            }
            proto.providerConfiguration = config.isEmpty ? nil : config
            m.protocolConfiguration = proto
            try await m.saveToPreferences()
            try await m.loadFromPreferences()
            // NEVPNErrorDomain error 2 (configurationDisabled): менеджер по умолчанию
            // сохраняется выключенным — включаем конфигурацию до старта туннеля.
            if !m.isEnabled {
                m.isEnabled = true
                try await m.saveToPreferences()
                try await m.loadFromPreferences()
            }
            manager = m
            switch m.connection.status {
            case .connected, .connecting, .reasserting:
                m.connection.stopVPNTunnel()
            default:
                try m.connection.startVPNTunnel()
                if needsFrontsUpdate {
                    Task { await updateFronts() }
                }
                // Сторож: если за 20с статус не сдвинулся (расширение умерло
                // молча) — показываем ошибку и разблокируем кнопку.
                let startStatus = m.connection.status
                Task { @MainActor [weak self] in
                    try? await Task.sleep(nanoseconds: 20_000_000_000)
                    guard let self, self.status == startStatus,
                          startStatus == .connecting || startStatus == .reasserting else { return }
                    self.errorMessage = "Туннель не запустился. Попробуй ещё раз."
                    if let conn = self.manager?.connection {
                        self.status = conn.status
                    }
                }
            }
            status = m.connection.status
        } catch {
            NSLog("[WSBridge] toggle error: %@", error.localizedDescription)
            errorMessage = error.localizedDescription
            status = manager?.connection.status ?? .invalid
        }
    }
}

/// ponytail: без willPresent UN-уведомления, пришедшие при открытом
/// приложении, молча дропаются системой — а смена сети случается именно
/// когда телефон в руках и приложение на экране. TunnelManager не NSObject,
/// поэтому конформность живёт в отдельном объекте; delegate слабый —
/// держим его в static let навсегда.
final class BannerPresenter: NSObject, UNUserNotificationCenterDelegate {
    func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        willPresent notification: UNNotification
    ) async -> UNNotificationPresentationOptions {
        [.banner]
    }
}
