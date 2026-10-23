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
            // Глобальная статистика: фиксируем включение/выключение сессии
            // (это единственное место, где мы гарантированно видим переход).
            noteSessionEvent()
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
    /// Несколько доменов — через запятую (балансировка round-robin в расширении).
    @Published var workerDomain: String = UserDefaults.standard.string(forKey: "workerDomain") ?? "" {
        didSet { UserDefaults.standard.set(workerDomain, forKey: "workerDomain") }
    }

    /// «DC → IP» маппинг (как в десктопном tg-ws-proxy): строки «номер:IP»
    /// по одной на строку. Пусто = как прилетело от Telegram.
    @Published var dcMapText: String = UserDefaults.standard.string(forKey: "dcMap") ?? "" {
        didSet { UserDefaults.standard.set(dcMapText, forKey: "dcMap") }
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
            if servers.isEmpty { return "как в системе" }
            switch (supportsDoT, supportsDoH) {
            case (true, true): return "DoT · DoH"
            case (true, false): return "DoT"
            case (false, true): return "DoH"
            default: return "без шифрования"
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
        DNSConfig(id: "malw-gateway", name: "Alt Malw.link",
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
    /// Растёт на каждый toggle/restart: сторож старта сравнивает своё
    /// поколение с текущим и не срабатывает на устаревших запусках.
    private var toggleGeneration = 0
    /// Выдана команда stop, подтверждение ещё идёт. Защищает быстрый
    // второй тап по «выкл» от превращения в старт.
    private var pendingStopIssued = false
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
        // Кэш NETunnelProviderManager после фона устаревает — перечитываем,
        // иначе первый тап после возврата уйдёт не в ту сторону.
        Task { await reload() }
        // Догоняем статистику: копим дельту байтов и секунды работы
        // (таймеров нет — только по событию возврата в foreground).
        Task { await recordUsageSnapshot() }
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

    /// Перезапуск: стоп → старт. Без saveToPreferences в фазе стопа:
    /// сохранение конфигурации включенного туннеля заставляет iOS
    /// пересоздать сессию (см. комментарий у stop).
    func restartTunnel() async {
        toggleGeneration += 1
        let gen = toggleGeneration
        let m = await refreshManager() ?? freshManager()
        let s = m.connection.status
        if s == .connected || s == .connecting || s == .reasserting {
            pendingStopIssued = true
            await stop(m, generation: gen)
        }
        // Ждём фактической смерти старой сессии: старт поверх dying
        // iOS не примет.
        for _ in 0..<40 {
            guard toggleGeneration == gen else { return }
            let cur = m.connection.status
            if cur == .disconnected || cur == .invalid { break }
            try? await Task.sleep(nanoseconds: 250_000_000)
        }
        guard toggleGeneration == gen else { return }
        do {
            try await start(m, needsFrontsUpdate: false, generation: gen)
        } catch {
            NSLog("[WSBridge] restart error: %@", error.localizedDescription)
            errorMessage = error.localizedDescription
            status = m.connection.status
        }
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
        // История: тянем снапшот счётчиков у расширения и капаем дельту в
        // дневную агрегацию (событийно, без таймеров — батарея не страдает).
        Task { await recordUsageSnapshot() }
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

    // MARK: - Глобальная статистика по дням

    /// Один день истории. Всё в «сырых» единицах (байты, секунды) —
    /// форматирование на экране.
    struct DayUsage: Codable, Equatable {
        var upBytes: UInt64 = 0        // от клиента (rxBytes расширения)
        var downBytes: UInt64 = 0      // к клиенту
        var seconds: TimeInterval = 0  // время в .connected
        var sessions: Int = 0          // сколько раз включали
    }

    /// Опубликованная история для графиков: [yyyy-MM-dd: DayUsage].
    @Published private(set) var usageHistory: [String: DayUsage] = TunnelManager.loadHistory()

    /// Последний снапшот счётчиков от расширения (монотонные, в рамках
    /// текущего запуска туннеля) — от него считаются дельты.
    private var lastSnapshot: (up: UInt64, down: UInt64, at: Date)?
    /// Время, когда туннель стал .connected в этот раз.
    private var connectedSince: Date?

    private static let historyKey = "usageHistory"
    private static let historyDays = 90

    private static func loadHistory() -> [String: DayUsage] {
        guard let data = UserDefaults.standard.data(forKey: historyKey),
              let dict = try? JSONDecoder().decode([String: DayUsage].self, from: data)
        else { return [:] }
        return dict
    }

    private static func dayKey(_ date: Date = Date()) -> String {
        let f = DateFormatter()
        f.dateFormat = "yyyy-MM-dd"
        return f.string(from: date)
    }

    private static func saveHistory(_ dict: [String: DayUsage]) {
        // Ротация: старше 90 дней — вон.
        let cutoff = Calendar.current.date(byAdding: .day, value: -historyDays, to: Date()) ?? Date()
        let filtered = dict.filter { key, _ in
            guard let d = dayDate(from: key) else { return false }
            return d >= cutoff
        }
        if let data = try? JSONEncoder().encode(filtered) {
            UserDefaults.standard.set(data, forKey: historyKey)
        }
    }

    private static func dayDate(from key: String) -> Date? {
        let f = DateFormatter()
        f.dateFormat = "yyyy-MM-dd"
        return f.date(from: key)
    }

    /// Дневной слот (создаёт при первом обращении).
    private func day(_ key: String) -> DayUsage {
        usageHistory[key] ?? DayUsage()
    }

    private func mutateDay(_ key: String, _ body: (inout DayUsage) -> Void) {
        var d = day(key)
        body(&d)
        usageHistory[key] = d
        Self.saveHistory(usageHistory)
    }

    /// Событийный снапшот: опрашивает расширение через providerMessage,
    /// капает дельту байтов в сегодняшний слот. Вызывается: открытие экрана
    /// статистики, смена статуса, возврат приложения в foreground.
    /// Таймеров НЕТ — батарея не страдает, точности «по дням» хватает.
    func recordUsageSnapshot() async {
        // connectedSince, а не status: stop() зовёт снапшот, когда статус уже
        // оптимистично .disconnecting — сессию ещё можно опросить.
        guard let session = manager?.connection as? NETunnelProviderSession,
              connectedSince != nil
        else { return }
        // Uptime капаем здесь же: секунды, проведённые в .connected с
        // последнего снапшота (день сменился — пишется в новый слот).
        if let since = connectedSince {
            let now = Date()
            var seconds = now.timeIntervalSince(since)
            if seconds > 0 {
                // При переходе через полночь делим пропорционально.
                let key = Self.dayKey(now)
                let startKey = Self.dayKey(since)
                if key == startKey {
                    mutateDay(key) { $0.seconds += seconds }
                } else {
                    let midnight = Calendar.current.startOfDay(for: now)
                    let beforeMidnight = midnight.timeIntervalSince(since)
                    if beforeMidnight > 0 {
                        mutateDay(startKey) { $0.seconds += beforeMidnight }
                        seconds -= beforeMidnight
                    }
                    mutateDay(key) { $0.seconds += max(seconds, 0) }
                }
                connectedSince = now
            }
        }
        let reply: Data? = await withCheckedContinuation { cont in
            do {
                try session.sendProviderMessage(Data("stats".utf8)) { data in
                    cont.resume(returning: data)
                }
            } catch {
                cont.resume(returning: nil)
            }
        }
        guard let reply,
              let json = try? JSONSerialization.jsonObject(with: reply) as? [String: Any],
              let up = json["upBytes"] as? UInt64,
              let down = json["rxBytes"] as? UInt64
        else { return }
        let now = Date()
        if let last = lastSnapshot {
            let dUp = up >= last.up ? up - last.up : 0   // перезапуск счётчиков = 0
            let dDown = down >= last.down ? down - last.down : 0
            if dUp > 0 || dDown > 0 {
                mutateDay(Self.dayKey(now)) {
                    $0.upBytes += dUp
                    $0.downBytes += dDown
                }
            }
        }
        lastSnapshot = (up, down, now)
    }

    /// Смена статуса: фиксируем включение/выключение сессии.
    func noteSessionEvent() {
        switch status {
        case .connected:
            if connectedSince == nil { connectedSince = Date() }
            mutateDay(Self.dayKey()) { $0.sessions += 1 }
            lastSnapshot = nil // счётчики расширения обнулились
        case .disconnected, .invalid:
            // Финальный снапшот байтов — асинхронно, сколько успеем.
            Task { await recordUsageSnapshot() }
            connectedSince = nil
            lastSnapshot = nil
        default:
            break
        }
    }

    /// Для экрана: отсортированные дни за N последних; 0 = за всё время.
    func usageDays(_ n: Int) -> [(day: String, usage: DayUsage)] {
        let keys = n <= 0
            ? usageHistory.keys.sorted()
            : Array(usageHistory.keys.sorted().suffix(n))
        return keys.map { ($0, usageHistory[$0]!) }
    }

    func reload() async {
        let all = (try? await NETunnelProviderManager.loadAllFromPreferences()) ?? []
        if all.count > 1 { await dedupeConfigs(all) }
        manager = (try? await NETunnelProviderManager.loadAllFromPreferences())?.first
        status = manager?.connection.status ?? .invalid
    }

    /// За годы сборок каждый «первый запуск» мог создать свою конфигурацию —
    /// в preferences копились дубликаты VPN-профиля. Живой держим один
    /// (первый, тот же, что видит System Settings); остальные выключенные
    /// удаляем, иначе их соединения путают direction-детект и «поднимают»
    /// туннель неожиданно.
    private func dedupeConfigs(_ all: [NETunnelProviderManager]) async {
        // Живой оставляем активный, иначе первый.
        let active = all.first { m in
            let s = m.connection.status
            return s == .connected || s == .connecting || s == .reasserting
        }
        guard let survivor = active ?? all.first else { return }
        for m in all {
            guard m !== survivor else { continue }
            let s = m.connection.status
            // Удаляем только заведомо неактивные дубликаты — чужую
            // работающую сессию не трогаем.
            guard s == .disconnected || s == .invalid else { continue }
            logStatusEvent("dedupe:remove:\(m.localizedDescription ?? "-")")
            try? await m.removeFromPreferences()
        }
    }

    /// Свежий менеджер из preferences. После фона/сна кэш устаревает:
    /// старый NEVPNConnection перестаёт управлять сессией, и stopVPNTunnel()
    /// тихо уходит в никуда — это и была «мёртвая кнопка».
    private func refreshManager() async -> NETunnelProviderManager? {
        if let fresh = try? await NETunnelProviderManager.loadAllFromPreferences().first {
            manager = fresh
        }
        return manager
    }

    func toggle(force: Bool = false) async {
        // Дебаунс минимальный — глотает только случайный дабл-тап. Быстрый
        // «выкл→вкл» — нормальный сценарий, он не должен съедаться.
        let tapAt = Date()
        let gap = tapAt.timeIntervalSince(lastToggleAt)
        guard force || gap > 0.4 else { return }
        lastToggleAt = tapAt
        errorMessage = nil
        toggleGeneration += 1
        let gen = toggleGeneration

        // МГНОВЕННЫЙ отклик UI: намерение выставляется синхронно, ДО первого
        // await. Иначе между тапом и реакцией экрана стоит IPC
        // loadAllPreferences (сотни мс) — кнопка выглядит «тупой».
        let cached = manager?.connection.status ?? status
        switch cached {
        case .connected, .connecting, .reasserting:
            status = .disconnecting
        default:
            status = .connecting // включая .disconnecting: тап = «включить»
        }

        let m = await refreshManager() ?? freshManager()
        // Направление — ТОЛЬКО по живому статусу, не по published.
        switch m.connection.status {
        case .connected, .connecting, .reasserting:
            pendingStopIssued = true
            await stop(m, generation: gen) // НЕ блокирует: команду отдали и вышли
        case .disconnecting:
            // Сессия ещё умирает. Тап в первые 0.8 с после «выкл» — это
            // дабл-тап по той же кнопке, игнорируем; позже — намерение «вкл»,
            // start() сам дождётся смерти старой сессии.
            if pendingStopIssued && gap < 0.8 {
                logStatusEvent("toggle:dup-stop:ignored")
                return
            }
            pendingStopIssued = false
            do {
                let needsFrontsUpdate =
                    (frontsUpdatedAt?.timeIntervalSinceNow ?? -3600) < -1800
                try await start(m, needsFrontsUpdate: needsFrontsUpdate, generation: gen)
            } catch {
                NSLog("[WSBridge] start error: %@", error.localizedDescription)
                errorMessage = error.localizedDescription
                status = m.connection.status
            }
        default:
            pendingStopIssued = false
            do {
                let needsFrontsUpdate =
                    (frontsUpdatedAt?.timeIntervalSinceNow ?? -3600) < -1800
                try await start(m, needsFrontsUpdate: needsFrontsUpdate, generation: gen)
            } catch {
                NSLog("[WSBridge] start error: %@", error.localizedDescription)
                errorMessage = error.localizedDescription
                status = m.connection.status
            }
        }
    }

    /// Первый запуск: конфигурации ещё нет. Сохранять менеджер без
    /// protocolConfiguration нельзя (NEVPNError 1), но start() заполняет
    /// его до saveToPreferences — поэтому просто отдаём пустой объект.
    private func freshManager() -> NETunnelProviderManager {
        let fresh = NETunnelProviderManager()
        fresh.localizedDescription = "WSBridge"
        return fresh
    }

    /// Выключение НЕ БЛОКИРУЕТ тап: команда stopVPNTunnel отдаётся системе и
    /// toggle возвращается — кнопка свободна сразу, быстрый «выкл→вкл»
    /// работает. Подтверждение отключения, борьба с «переподнялся сам» и
    // last-resort идут фоном под защитой поколения: новый тап гасит старый
    /// вотчер. НИ ОДНОГО saveToPreferences на живом туннеле: сохранение
    /// конфигурации активной сессии пересоздаёт её (симптом «выключил — сам
    /// включился, со второго раза выключается»).
    private func stop(_ m: NETunnelProviderManager, generation: Int) async {
        // Финальный снапшот статистики ДО остановки: после stopVPNTunnel
        // расширение уже не ответит, и последняя дельта байтов потерялась бы.
        await recordUsageSnapshot()
        m.connection.stopVPNTunnel()
        status = .disconnecting
        logStatusEvent("stop:issued:\(m.connection.status)")
        Task { @MainActor [weak self] in
            await self?.confirmStop(m, generation: generation)
        }
    }

    /// Фоновое подтверждение остановки: до 3 попыток, контрольный взгляд на
    /// «воскресение», в самом конце — выключение конфигурации (isEnabled
    /// вернёт start() при следующем включении).
    private func confirmStop(_ m: NETunnelProviderManager, generation: Int) async {
        for attempt in 1...3 {
            var wentDown = false
            for _ in 0..<24 {
                guard toggleGeneration == generation else { return }
                let s = m.connection.status
                if s == .disconnected || s == .invalid {
                    status = s
                    wentDown = true
                    break
                }
                try? await Task.sleep(nanoseconds: 250_000_000)
            }
            guard toggleGeneration == generation else { return }
            if wentDown {
                // Контрольный взгляд через секунду: если сессия поднялась
                // обратно — это и есть «переподнялся сам», гасим ещё раз.
                try? await Task.sleep(nanoseconds: 1_000_000_000)
                guard toggleGeneration == generation else { return }
                let s = m.connection.status
                if s == .disconnected || s == .invalid {
                    pendingStopIssued = false
                    logStatusEvent("stop:done")
                    return
                }
                logStatusEvent("stop:resurrected:\(s)")
                m.connection.stopVPNTunnel()
                continue
            }
            logStatusEvent("stop:timeout:\(m.connection.status)")
            _ = await refreshManager()
        }
        guard toggleGeneration == generation else { return }
        if let m2 = await refreshManager(),
           m2.connection.status != .disconnected, m2.connection.status != .invalid {
            guard toggleGeneration == generation else { return }
            logStatusEvent("stop:disableConfig")
            m2.isEnabled = false
            try? await m2.saveToPreferences()
            try? await m2.loadFromPreferences()
            status = m2.connection.status
            logStatusEvent("stop:disableConfig->\(status)")
        }
        pendingStopIssued = false
        if status == .connected || status == .connecting || status == .reasserting {
            errorMessage = "Туннель не выключился. Попробуй ещё раз."
        }
    }

    /// Строка в историю статусов (видна в Меню → Статистика) — благодаря
    /// ей следующий отчёт «кнопка не работает» будет с фактами, а не с
    /// догадками.
    private func logStatusEvent(_ text: String) {
        statusHistory.append("\(Self.netTimeFmt.string(from: Date())) \(text)")
        if statusHistory.count > 40 {
            statusHistory.removeFirst(statusHistory.count - 40)
        }
    }

    /// Включение: конфигурация пересоздаётся (worker/fronts/DNS доезжают
    /// до расширения только так), затем старт.
    private func start(
        _ m: NETunnelProviderManager,
        needsFrontsUpdate: Bool,
        generation: Int = 0
    ) async throws {
        // Быстрый «выкл→вкл»: старая сессия могла ещё умирать. iOS не
        // поднимет новую поверх dying — дожидаемся слота, оптимистичный
        // .connecting уже показывает намерение на экране.
        for _ in 0..<40 {
            if m.connection.status != .disconnecting { break }
            try? await Task.sleep(nanoseconds: 250_000_000)
        }
        guard toggleGeneration == generation else { return }
        if status != .connected {
            UNUserNotificationCenter.current()
                .requestAuthorization(options: [.alert]) { _, _ in }
        }
        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = Self.providerBundleId
        proto.serverAddress = "WSBridge"
        let wd = workerDomain.trimmingCharacters(in: .whitespacesAndNewlines)
        var config: [String: NSObject] = [:]
        if !wd.isEmpty { config["worker"] = wd as NSString }
        // «DC → IP»: по строке «номер:IP», невалидные расширение отбросит.
        let dcLines = dcMapText
            .split(separator: "\n")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
        if !dcLines.isEmpty { config["dcMap"] = dcLines as NSArray }
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
        try m.connection.startVPNTunnel()
        status = m.connection.status
        if needsFrontsUpdate {
            Task { await updateFronts() }
        }
        // Сторож: статус не сдвинулся за 20 с — расширение умерло молча.
        Task { @MainActor [weak self] in
            try? await Task.sleep(nanoseconds: 20_000_000_000)
            guard let self, self.toggleGeneration == generation,
                  self.status == .connecting || self.status == .reasserting
            else { return }
            self.errorMessage = "Туннель не запустился. Попробуй ещё раз."
            if let conn = self.manager?.connection {
                self.status = conn.status
            }
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
