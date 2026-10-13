import Foundation
import Network
import NetworkExtension

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

    @Published private(set) var status: NEVPNStatus = .invalid
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
        var dohURL: String?         // DNS-over-HTTPS URL (приоритет 1)
        var dotHostname: String?    // DNS-over-TLS hostname (приоритет 2)
        var isPreset: Bool
    }

    /// Пресеты — не удаляются, не редактируются.
    /// Приоритет: DoH > DoT > plain :53 (только для своих без URL).
    static let dnsPresets: [DNSConfig] = [
        DNSConfig(id: "system", name: "Системный", description: "DNS устройства (туннель не трогает DNS)",
                  servers: [], dohURL: nil, dotHostname: nil, isPreset: true),
        DNSConfig(id: "google", name: "Google", description: "Быстрый, надёжный, без фильтрации",
                  servers: ["8.8.8.8", "8.8.4.4"], dohURL: "https://dns.google/dns-query", dotHostname: nil, isPreset: true),
        DNSConfig(id: "cloudflare", name: "Cloudflare", description: "Быстрый, приватный, без фильтрации",
                  servers: ["1.1.1.1", "1.0.0.1"], dohURL: "https://cloudflare-dns.com/dns-query", dotHostname: nil, isPreset: true),
        DNSConfig(id: "comss", name: "Comss.one", description: "Доступ к ИИ, блокировка рекламы, счетчиков, вредоносных сайтов и фишинга",
                  servers: ["83.220.169.155", "212.109.195.93"], dohURL: "https://dns.comss.one/dns-query", dotHostname: nil, isPreset: true),
        DNSConfig(id: "malw", name: "Malw.link", description: "Разблокирует недоступные сайты, блокирует мусор.",
                  servers: ["95.216.204.218", "80.253.249.40"], dohURL: "https://dns.malw.link/dns-query",
                  dotHostname: "dns.malw.link", isPreset: true),
    ]

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

    func toggle() async {
        errorMessage = nil
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
                if let doh = selectedDNS.dohURL {
                    config["doh"] = doh as NSString
                }
                if let dot = selectedDNS.dotHostname {
                    config["dot"] = dot as NSString
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
