import Foundation
import Network
import Security

/// WS-клиент к kws-гейтвею Telegram. Каждый MTProto-пакет — отдельный WS-фрейм.
///
/// ponytail: один общий URLSession на все соединения — расширение имеет лимит ~15MB.
/// Каскад: прямые IP гейтвеев (Host-заголовок маршрутизирует vhost; SNI не нужен —
/// проверено) → ротационные CF-домены → kws{dc}.web.telegram.org (DNS может быть отравлен).
final class WSClient {
    private static let sharedSession: URLSession = {
        let config = URLSessionConfiguration.default
        // ponytail: request-timeout на WS-таске убивает сокет, если гейтвей молчит;
        // resource-timeout убивает сессию через N секунд. Каскадом управляет наш
        // собственный 10с-таймер, поэтому здесь значения заведомо щедрые.
        config.timeoutIntervalForRequest = 300
        config.timeoutIntervalForResource = 86400
        return URLSession(configuration: config, delegate: GatewayTrust(), delegateQueue: nil)
    }()

    /// Прямые IP kws-гейтвеев — РАБОЧИЙ список, на котором Telegram
    /// стабильно поднимался до всех экспериментов. Не трогать: попытка
    /// заменить на DC_DEFAULT_IPS из офф tg-ws-proxy (.167.51 и др.)
    /// вместе с «проверкой живости фронтов» сломала каскад на сотовой.
    private static let gatewayIPs = [
        "149.154.167.220", "149.154.175.205", "149.154.167.99", "149.154.174.100",
    ]

    /// TLS-валидация для соединений по IP: сертификат гейтвея выписан для
    /// *.web.telegram.org, peer name = IP не совпадёт. Подменяем peer domain
    /// и проводим ПОЛНУЮ проверку цепочки — никакого blanket trust.
    private final class GatewayTrust: NSObject, URLSessionDelegate {
        func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
                        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
            let host = challenge.protectionSpace.host
            let method = challenge.protectionSpace.authenticationMethod
            let parts = host.split(separator: ".")
            let isIPv4 = parts.count == 4 && parts.allSatisfy { Int($0) != nil }
            // ДИАГНОСТИКА: видим, дошёл ли вообще TLS-challenge до сессии
            // и что решил delegate. Без этого ws_timeout беспричинен.
            WSClient.postEvent("ws_challenge:\(host):\(method == NSURLAuthenticationMethodServerTrust ? "trust" : "other")")
            guard isIPv4,
                  method == NSURLAuthenticationMethodServerTrust,
                  let trust = challenge.protectionSpace.serverTrust else {
                WSClient.postEvent("ws_challenge:\(host):default")
                completionHandler(.performDefaultHandling, nil)
                return
            }
            for name in ["kws1.web.telegram.org", "web.telegram.org"] {
                SecTrustSetPolicies(trust, SecPolicyCreateSSL(true, name as CFString))
                var err: CFError?
                if SecTrustEvaluateWithError(trust, &err) {
                    WSClient.postEvent("ws_challenge:\(host):accepted")
                    completionHandler(.useCredential, URLCredential(trust: trust))
                    return
                }
            }
            WSClient.postEvent("ws_challenge:\(host):CANCELLED")
            completionHandler(.cancelAuthenticationChallenge, nil)
        }

        /// HTTP-статус handshake: URLSessionWebSocketTask сообщает его через
        /// task-делегат. 101 = успех; 302/403/400 = сервер ответил, но не
        /// апгрейднул; отсутствие строки = ответа не было вообще.
        func urlSession(_ session: URLSession, task: URLSessionTask,
                        didCompleteWithError error: Error?) {
            if let error {
                WSClient.postEvent("ws_taskerr:\((error as NSError).code):\((error as NSError).domain)")
            } else {
                WSClient.postEvent("ws_taskdone")
            }
        }
    }

    private var task: URLSessionWebSocketTask?
    /// Клиент закрыл соединение: каскад обязан остановиться. Без этого
    /// запланированный 10с-таймер всё равно звал tryConnect и поднимал
    /// каскад заново уже для мёртвой сессии (журнал 0.3.34: c1 закрыт
    /// close:fin:12s в 22:40:25, а его ws_try шли до 22:41:15 — 6 лишних
    /// эндпоинтов, каждый помечал живой фронт мёртвым).
    private let closedFlag = ClosedFlag()
    private var connected = false
    private var initFrame: Data?
    private var firstRecv = false
    private var pingOK = false
    private var upPosted = false
    private static var sndErrLogged = 0
    private let tag: String

    init(tag: String = "") { self.tag = tag }

    private func post(_ name: String) {
        Self.postEvent(tag.isEmpty ? name : "\(tag):\(name)")
    }

    /// Подключается к kws-гейтвею. Порядок: CF-фронты (ротация старта) → прямые
    /// IP гейтвеев → kws{dc}.web.telegram.org. Фронты первыми: на LTE они
    /// единственные дают мгновенный 101 (прямые IP к TG-диапазону 149.154.*
    /// на LTE не отвечают, а CF — да); 10с-таймауты на IP не давали
    /// каскаду дойти до фронтов до перезапуска соединения Telegram.
    /// initFrame (64-байтовый MTProto init) шлётся первым фреймом на КАЖДОМ
    /// эндпоинте каскада — при failover старый task со своим init выбрасывается.
    private static var rrStart = 0

    /// Кэш здоровья эндпоинтов: упавший (timeout/ошибка до первых данных)
    /// исключается из каскадов на 10 минут. Убирает долбёжку мёртвых фронтов
    /// кругами (батарея/CPU/лог-шум), когда Telegram держит ~12 соединений.
    /// Если отфильтровать нечего — пробуем всё (фронты могут ожить волной).
    private static var deadUntil: [String: Date] = [:]
    private static let healthLock = NSLock()

    static func markDead(_ host: String) {
        healthLock.lock(); defer { healthLock.unlock() }
        deadUntil[host] = Date().addingTimeInterval(600)
        FrontHealthRegistry.recordFailure(host)
    }

    static func markAlive(_ host: String) {
        healthLock.lock(); defer { healthLock.unlock() }
        deadUntil.removeValue(forKey: host)
        FrontHealthRegistry.recordSuccess(host)
    }

    // MARK: - Адаптивный выбор транспорта (порт cf_websocket.py, tg-ws-proxy 1.12.0)
    //
    // Апстрим добавил авто-fallback TLS↔plain по таймауту. У нас каскад уже
    // содержит оба транспорта, но порядок был статическим: всегда сначала
    // шесть ws://…:80, потом шесть wss://…:443. Если 80 в этой сети фильтруется,
    // каждая сессия платила шесть таймаутов прежде чем дойти до рабочего 443.
    //
    // Порт их механики:
    //   CF_TIMEOUT_COOLDOWN = 30.0        → transportCooldown
    //   CF_CONNECT_TIMEOUTS = (3,3,5,5,10) → connectTimeouts
    //   cf_prefers_tls(): tls >= no_tls   → transportPrefersTLS()
    //
    // Отличие: у них чередование транспорта по чётности таймаутов внутри
    // одного списка доменов; у нас список эндпоинтов уже несёт флаг plain,
    // поэтому эквивалент — переставить группы и дать остывшему транспорту
    // второй шанс в конце списка.

    /// Кулдаун транспорта после таймаута: (host, plain) → момент, когда пробовать снова.
    private static var transportCooldown: [String: Date] = [:]
    /// Счётчики успехов по транспорту — определяют, какой ставить первым.
    private static var tlsWins = 0
    private static var plainWins = 0
    /// Прогрессия таймаутов по числу таймаутов в текущем каскаде.
    private static let connectTimeouts: [Double] = [3, 3, 5, 5, 10]
    private static let transportCooldownSec: TimeInterval = 30

    private static func transportPrefersTLS() -> Bool {
        healthLock.lock(); defer { healthLock.unlock() }
        return tlsWins >= plainWins
    }

    /// Таймаут текущей попытки: остывший транспорт пробуется коротко (3с),
    /// полный 10с остаётся последнему шансу. index — позиция в итоговом списке.
    private static func attemptTimeout(index: Int, cooled: Bool) -> Double {
        let base = connectTimeouts[min(index, connectTimeouts.count - 1)]
        return cooled ? min(base, 3) : base
    }

    static func markTransportTimeout(_ key: String) {
        healthLock.lock(); defer { healthLock.unlock() }
        transportCooldown[key] = Date().addingTimeInterval(transportCooldownSec)
    }

    static func markTransportAlive(_ key: String, plain: Bool) {
        healthLock.lock(); defer { healthLock.unlock() }
        transportCooldown.removeValue(forKey: key)
        if plain { plainWins += 1 } else { tlsWins += 1 }
    }

    /// Идёт ли транспорт в кулдауне — нужно вызывающему, чтобы дать попытке
    /// короткий таймаут вместо полного (экономия батареи на мёртвом пути).
    private static func isTransportCooled(_ key: String) -> Bool {
        healthLock.lock(); defer { healthLock.unlock() }
        guard let until = transportCooldown[key] else { return false }
        return until > Date()
    }

    /// Переставляет группы транспортов: успешный чаще — первым;
    /// остывшие после таймаута — в конец (не выбрасываются: могут ожить).
    /// Сортировка устойчивая (по исходному индексу), чтобы round-robin
    /// порядок фронтов внутри группы не перетасовывался произвольно.
    private static func orderTransports(_ eps: [Endpoint]) -> [Endpoint] {
        let preferTLS = transportPrefersTLS()
        healthLock.lock()
        let now = Date()
        // Побочно вычищаем протухшие кулдауны: словарь не растёт (их код
        // делает то же в connect_cf_domains перед записью нового).
        transportCooldown = transportCooldown.filter { $0.value > now }
        var cooledKeys: Set<String> = []
        for ep in eps {
            let k = healthKey(ep.host, plain: ep.plain)
            if transportCooldown[k] != nil { cooledKeys.insert(k) }
        }
        healthLock.unlock()
        // group: 0 = предпочтительный транспорт, 1 = второй
        func group(_ ep: Endpoint) -> Int {
            (ep.plain == !preferTLS) ? 0 : 1
        }
        let fresh = eps.enumerated().filter { !cooledKeys.contains(Self.healthKey($0.element.host, plain: $0.element.plain)) }
        let cooled = eps.enumerated().filter { cooledKeys.contains(Self.healthKey($0.element.host, plain: $0.element.plain)) }
        func byGroup(_ a: (offset: Int, element: Endpoint), _ b: (offset: Int, element: Endpoint)) -> Bool {
            let ga = group(a.element), gb = group(b.element)
            if ga != gb { return ga < gb }
            return a.offset < b.offset   // устойчиво: исходный порядок
        }
        return fresh.sorted(by: byGroup).map(\.element)
            + cooled.sorted(by: byGroup).map(\.element)
    }

    /// Эндпоинт каскада. `plain` = WS без TLS на порт 80 (см. connect()).
    /// Здоровье считается ПО КЛЮЧУ host+plain: мёртвый 443 не должен
    /// прятать живой 80 того же фронта, и наоборот.
    private typealias Endpoint = (host: String, hostHeader: String?, plain: Bool)

    private static func healthKey(_ host: String, plain: Bool) -> String {
        plain ? "ws80:\(host)" : host
    }

    private static func aliveOnly(_ eps: [Endpoint]) -> [Endpoint] {
        healthLock.lock(); defer { healthLock.unlock() }
        let now = Date()
        return eps.filter { ep in
            let key = healthKey(ep.host, plain: ep.plain)
            guard let until = deadUntil[key] else { return true }
            if until > now { return false }
            deadUntil.removeValue(forKey: key)
            return true
        }
    }

    func connect(dc: Int, isMedia: Bool, isTestDC: Bool, initFrame: Data,
                 tlsFirst: Bool = false, frontsDisabled: Bool = false,
                 onMessage: @escaping (Data) -> Void, onClose: @escaping () -> Void) {
        let path = isTestDC ? "/apiws_test" : "/apiws"
        self.initFrame = initFrame

        // Media-DC у десктопа ходит на kws{dc}-1; обычный — kws{dc}.
        let gwHost = isMedia ? "kws\(dc)-1.web.telegram.org" : "kws\(dc).web.telegram.org"

        // Round-robin старт: Telegram держит ~12 параллельных соединений —
        // каждое начнёт со своего фронта и живые найдутся быстрее.
        // Персистентный реестр здоровья (Android-порт): переупорядочиваем
        // фронтами по lastSuccess (свежие успехи первыми), известные мёртвые
        // (<3 фейлов подряд, без успеха 24ч) отбрасываем.
        let fronts = frontsDisabled ? [] : CFDomains.domains(dc: dc)
        Self.rrStart = (Self.rrStart + 1) % max(fronts.count, 1)
        let start = Self.rrStart
        var rotated = fronts.isEmpty ? [] : Array(fronts[start...] + fronts[..<start])
        if !rotated.isEmpty {
            let (ordered, excluded) = FrontHealthRegistry.orderAndFilter(rotated)
            if excluded > 0 {
                post("health_excl:\(excluded)")
                NSLog("[WSBridge] health registry: excluded \(excluded) endpoints")
                rotated = ordered.isEmpty ? rotated : ordered
            } else {
                rotated = ordered
            }
        }

        // WS/80 БЕЗ TLS для CF-фронтов — обход, который 19.11.2026 массово
        // подтверждён у офф tg-ws-proxy («Выключить TLS для CF-прокси»,
        // Flowseal #1652) и включён по умолчанию в Android-форке v1.11.10
        // (Regstar2 PR #169, ws://…:80/apiws). Участок до CF не шифруется,
        // но MTProto-payload остаётся под собственным obfuscated2.
        //
        // Тумблеры (аналоги no_secure/cfproxy апстрима):
        //  frontsDisabled — CF-фронты исключены целиком, каскад сразу
        //    gatewayIP → kws{dc}: для сетей, где фронты заблокированы волной.
        //  tlsFirst — только wss://…:443, без ws://…:80: для сетей, где
        //    фильтруется 80. Адаптивный порядок ниже это тоже учит, но
        //    явный запрет надёжнее и не тратит попытку.
        let top = rotated.prefix(6)
        var endpoints: [Endpoint] = []
        if !tlsFirst {
            endpoints += top.map { ($0, nil as String?, true) }
        }
        endpoints += top.map { ($0, nil as String?, false) }
        endpoints += Self.gatewayIPs.map { ($0, gwHost as String?, false) }
        endpoints.append((gwHost, nil, false))
        if frontsDisabled { post("cascade:fronts_off") }
        if tlsFirst { post("cascade:tls_first") }

        // Адаптивный порядок транспортов (порт cf_websocket.py 1.12.0):
        // какой транспорт чаще соединялся — тот первым; остывшие после
        // таймаутов — в конец, но не выбрасываются. При tlsFirst в списке
        // нет plain-эндпоинтов, так что перестановка ничего не меняет.
        endpoints = Self.orderTransports(endpoints)

        let healthy = Self.aliveOnly(endpoints)
        tryConnect(endpoints: healthy.isEmpty ? endpoints : healthy, path: path, index: 0, onMessage: onMessage, onClose: onClose)
    }

    private func tryConnect(endpoints: [Endpoint], path: String, index: Int, onMessage: @escaping (Data) -> Void, onClose: @escaping () -> Void) {
        guard !closedFlag.value else { return }
        guard index < endpoints.count else {
            NSLog("[WSBridge] WS: all endpoints failed")
            post("ws_fail")
            onClose()
            return
        }
        let ep = endpoints[index]
        let key = Self.healthKey(ep.host, plain: ep.plain)
        let epCooled = Self.isTransportCooled(key)
        let scheme = ep.plain ? "ws" : "wss"
        let port = ep.plain ? ":80" : ""
        guard let url = URL(string: "\(scheme)://\(ep.host)\(port)\(path)") else {
            tryConnect(endpoints: endpoints, path: path, index: index + 1, onMessage: onMessage, onClose: onClose)
            return
        }
        NSLog("[WSBridge] WS: trying \(key)")
        post("ws_try:\(key)")
        var request = URLRequest(url: url)
        request.setValue("binary", forHTTPHeaderField: "Sec-WebSocket-Protocol")
        if let hh = ep.hostHeader {
            request.setValue(hh, forHTTPHeaderField: "Host")
        }
        let wsTask = Self.sharedSession.webSocketTask(with: request)
        task = wsTask
        wsTask.resume()

        // ДИАГНОСТИКА: снимок состояния задачи на 1с и 3с. Показывает,
        // стартовал ли URLSessionWebSocketTask вообще: state, сколько
        // байт ушло/пришло, есть ли error. Ничего не меняем в логике.
        // По логу (4): за 100+ попыток нет ни ws_challenge, ни ws_taskerr —
        // задача висит на старте. Эти строки покажут, где именно.
        for delay in [1.0, 3.0] {
            DispatchQueue.global().asyncAfter(deadline: .now() + delay) { [weak self] in
                guard let self, self.task === wsTask else { return }
                let st: String
                switch wsTask.state {
                case .running: st = "running"
                case .suspended: st = "suspended"
                case .canceling: st = "canceling"
                case .completed: st = "completed"
                @unknown default: st = "unknown"
                }
                let err = wsTask.error.map { String(($0 as NSError).code) } ?? "-"
                self.post("ws_taskstate:\(Int(delay))s:\(st):sent=\(wsTask.countOfBytesSent):rcvd=\(wsTask.countOfBytesReceived):err=\(err)")
            }
        }

        // Failover валиден, пока гейтвей не прислал ни байта: тот же init
        // отправляется на следующем эндпоинте (CTR-позиции клиента и DC
        // синхронны от init, потерянные кадры MTProto ретраит сам).
        // После первых полученных данных любая ошибка закрывает сессию —
        // Telegram переподключится (новая сессия, новый каскад).
        let state = TryState()
        func advance() {
            guard state.claim() else { return }
            self.task = nil
            self.tryConnect(endpoints: endpoints, path: path, index: index + 1, onMessage: onMessage, onClose: onClose)
        }
        func fail() {
            guard state.claim() else { return }
            self.task = nil
            post("ws_fail:\(ep.host)")
            onClose()
        }

        // init шлём СРАЗУ после resume(), НЕ дожидаясь первого receive.
        // Журнал 0.3.32 (WS/80) показал: гейтвей отвечает CLOSE
        // `code=1000 reason=404`, а он приходит как .failure — значит ветка
        // «отправить init внутри первого успешного receive» не выполнялась
        // НИ РАЗУ (во всех 657 снимках было sent=0). Мы ждали данных,
        // которых сервер не пришлёт, пока не получит init. Так же ведёт
        // себя офф tg-ws-proxy: relay_init уходит сразу после 101, а не
        // после первого сообщения сервера. URLSession буферизует кадр до
        // конца handshake, поэтому ранний send безопасен; если 101 не
        // придёт, сработает наш 10с таймер и каскад пойдёт дальше.
        // sendInit идемпотентен: ровно один кадр на эндпоинт.
        let sentOnce = TryState()
        // Признак «этот эндпоинт прислал кадр данных» — ЛОКАЛЬНЫЙ для
        // попытки. self.firstRecv живёт на весь WSClient и после первого
        // успеха остался бы true навсегда, погасив таймеры всех следующих
        // эндпоинтов каскада (мёртвые держали бы сессию вечно).
        let gotData = GotData()
        func sendInit() {
            guard let initFrame, sentOnce.claim() else { return }
            wsTask.send(.data(initFrame)) { [weak self] error in
                guard let self else { return }
                if let error {
                    self.post("ws_send:err:\((error as NSError).code)")
                } else {
                    if !self.upPosted {
                        self.upPosted = true
                        self.post("ws_up")
                    }
                    self.post("ws_send:ok")
                }
            }
        }
        sendInit()

        wsTask.receive { [weak self] result in
            guard let self, !self.closedFlag.value else { return }
            switch result {
            case .success(let message):
                self.connected = true
                // ЛЮБОЙ успешный receive = эндпоинт жив: гасим таймер сразу,
                // до разбора типа. Иначе строковый кадр оставил бы живое
                // соединение под таймером и мы бы его убили через 10с.
                gotData.set()
                // Первое сообщение гейтвея: тип и размер. CLOSE-фрейм
                // обычно приходит как .failure (см. ниже) с closeCode.
                switch message {
                case .string(let text): self.post("ws_first:string:\(text.prefix(64))")
                case .data(let d): self.post("ws_first:data:\(d.count)B")
                @unknown default: self.post("ws_first:unknown")
                }
                if case .data(let data) = message {
                    self.firstRecv = true
                    Self.markAlive(key)
                    Self.markTransportAlive(key, plain: ep.plain)
                    onMessage(data)
                }
                self.receiveLoop(onMessage: onMessage, onClose: onClose)
            case .failure(let error):
                let ns = error as NSError
                let code = wsTask.closeCode.rawValue
                let reason = wsTask.closeReason.flatMap { String(data: $0, encoding: .utf8) } ?? ""
                post("ws_err:\(key):\(ns.code):\(ns.domain):\(error.localizedDescription)")
                post("ws_closeinfo:\(key):code=\(code):reason=\(reason.prefix(64))")
                NSLog("[WSBridge] WS: \(key) failed (\(error.localizedDescription)), next")
                if self.firstRecv {
                    Self.markAlive(key) // умерла живая сессия — эндпоинт не виноват
                    fail()
                } else {
                    Self.markDead(key)
                    advance()
                }
            }
        }

        // Таймаут попытки: прогрессия 3/3/5/5/10с по позиции в каскаде
        // (порт CF_CONNECT_TIMEOUTS из cf_websocket.py 1.12.0). Остывший
        // после таймаута транспорт пробуется коротко — 3с, не 10.
        // Гасится ТОЛЬКО полученным кадром данных этого эндпоинта.
        // НЕ countOfBytesReceived: журнал 0.3.33 показал, что у
        // URLSessionWebSocketTask эти счётчики остаются 0 даже ПОСЛЕ
        // успешного обмена (ws_first:data:345B, а рядом rcvd=0) — они
        // про HTTP-тело, не про WS-фреймы. Из-за этого таймер убивал
        // живые сессии через 10с: ws_up → data:345B → ws_timeout.
        let started = Date()
        let attemptSec = Self.attemptTimeout(index: index, cooled: epCooled)
        DispatchQueue.global().asyncAfter(deadline: .now() + attemptSec) {
            guard !self.closedFlag.value, !gotData.value, state.claim() else { return }
            let ms = Int(Date().timeIntervalSince(started) * 1000)
            NSLog("[WSBridge] WS: \(key) connect timed out, trying next")
            self.post("ws_timeout:\(key)")
            self.post("ws_timeout:detail:no_data:\(ms)ms")
            self.post("ws_closeinfo:\(key):code=\(wsTask.closeCode.rawValue):reason=\((wsTask.closeReason.flatMap { String(data: $0, encoding: .utf8) } ?? "").prefix(64))")
            Self.markDead(key)
            Self.markTransportTimeout(key)
            wsTask.cancel(with: .goingAway, reason: nil)
            self.task = nil
            self.tryConnect(endpoints: endpoints, path: path, index: index + 1, onMessage: onMessage, onClose: onClose)
        }
    }

    /// «Соединение закрыто клиентом» — ставится из close() на lwipQueue,
    /// читается из receive/таймеров на других потоках, поэтому под замком.
    private final class ClosedFlag {
        private let lock = NSLock()
        private var closed = false
        var value: Bool {
            lock.lock(); defer { lock.unlock() }
            return closed
        }
        func set() {
            lock.lock(); defer { lock.unlock() }
            closed = true
        }
    }

    /// «Эндпоинт прислал кадр данных» — пишется из receive-колбэка,
    /// читается таймером с другого потока, поэтому под замком.
    private final class GotData {
        private let lock = NSLock()
        private var got = false
        var value: Bool {
            lock.lock(); defer { lock.unlock() }
            return got
        }
        func set() {
            lock.lock(); defer { lock.unlock() }
            got = true
        }
    }

    /// ponytail: NSLock вместо атомика — claim() должен быть именно once,
    /// колбэки send/receive/timer приходят с разных потоков.
    private final class TryState {
        private let lock = NSLock()
        private var claimed = false
        func claim() -> Bool {
            lock.lock(); defer { lock.unlock() }
            if claimed { return false }
            claimed = true
            return true
        }
    }

    /// WSBridge Relay (relay/ в репо): WSS к домену релея + ключ авторизации.
    /// Протокол: 101 → {"v":1,"token":…} (первый кадр) → {"ok":true} →
    /// сырой MTProto-поток (оригинальный init парсит СЕРВЕР — клиенту
    /// сплиттер не нужен). Отказ = close 1008 — как у защищённого сервиса.
    /// Использует sharedSession (валидация сертификатов — системная);
    /// заголовка Host-оверрайда нет: nginx терминирует TLS по SNI домена.
    func connectBridge(host: String, token: String,
                       onMessage: @escaping (Data) -> Void,
                       onClose: @escaping () -> Void) {
        var comps = URLComponents()
        comps.scheme = "wss"
        comps.host = host
        comps.path = "/"
        guard let url = comps.url else {
            post("relay_badurl:\(host)")
            onClose()
            return
        }
        post("relayws_try:\(host)")
        let wsTask = Self.sharedSession.webSocketTask(with: URLRequest(url: url))
        task = wsTask
        // Авторизационный кадр шлём сразу: URLSession буферизует его до
        // конца WS-хендшейка (101 отдаётся до проверки ключа — см. relay.py).
        // JSON собираем через JSONSerialization — без force-unwrap.
        let authData = try? JSONSerialization.data(withJSONObject: ["v": 1, "token": token])
        guard let authData, let auth = String(data: authData, encoding: .utf8) else {
            post("relayws_authenc_fail")
            onClose()
            return
        }
        wsTask.resume()
        wsTask.send(.string(auth)) { [weak self] error in
            guard let self else { return }
            if let error {
                self.post("relayws_autherr:\((error as NSError).code)")
            } else {
                self.post("relayws_auth_sent")
            }
        }
        receiveLoop(onMessage: onMessage, onClose: onClose)
        // Watchdog: если за 8с нет ни ответа на auth, ни данных — релей
        // недоступен (порт закрыт / TLS не поднялся / ключ отклонён).
        DispatchQueue.global().asyncAfter(deadline: .now() + 8) { [weak self] in
            guard let self, self.task === wsTask, !self.firstRecv else { return }
            self.post("relayws_slow")
            wsTask.cancel(with: .goingAway, reason: nil)
            self.task = nil
            onClose()
        }
    }

    /// Pipe-режим через СОБСТВЕННЫЙ CF worker пользователя: сырые байты в обе
    /// стороны, worker сам открывает TCP к dst:443 (DC). Ни гейтвея, ни сплиттера:
    /// init уходит частью потока, границы WS-фреймов не важны.
    func connectPipe(workerDomain: String, dst: String, onMessage: @escaping (Data) -> Void, onClose: @escaping () -> Void) {
        var comps = URLComponents()
        comps.scheme = "wss"
        comps.host = workerDomain
        comps.path = "/apiws"
        comps.queryItems = [URLQueryItem(name: "dst", value: dst)]
        guard let url = comps.url else {
            post("ws_badurl:\(workerDomain)")
            onClose()
            return
        }
        post("ws_try:\(workerDomain)")
        let wsTask = Self.sharedSession.webSocketTask(with: URLRequest(url: url))
        task = wsTask
        wsTask.resume()
        // Диагностика: pong = WS реально открыт (CF отвечает на ping сам).
        // ws_ping есть, ws_up нет — воркер жив, но завис его TCP к DC.
        wsTask.sendPing { [weak self] error in
            guard let self else { return }
            if error == nil { self.pingOK = true }
            self.post(error == nil ? "ws_ping" : "ws_pingerr")
        }
        // Watchdog: рвём в 7с ТОЛЬКО если WS не открылся (нет pong).
        // При живом pong воркер здоров, а DC может легитимно думать над
        // тяжёлым getDifference дольше 7с — убив такое соединение, мы
        // перезапускаем catch-up с нуля = вечное «Обновление...».
        // Зависший connect к DC теперь закрывает fail-fast воркера (4с),
        // а молчащий DC добьёт app-watchdog (12с).
        DispatchQueue.global().asyncAfter(deadline: .now() + 7) { [weak self] in
            guard let self, self.task != nil, !self.firstRecv, !self.pingOK else { return }
            self.post("ws_slow")
            self.task?.cancel(with: .goingAway, reason: nil)
            self.task = nil
            onClose()
        }
        receiveLoop(onMessage: onMessage, onClose: onClose)
    }

    private func receiveLoop(onMessage: @escaping (Data) -> Void, onClose: @escaping () -> Void) {
        task?.receive { [weak self] result in
            guard let self else { return }
            switch result {
            case .success(let message):
                if !firstRecv {
                    firstRecv = true
                    if !upPosted {
                        upPosted = true
                        post("ws_up")
                    }
                }
                if case .data(let data) = message {
                    onMessage(data)
                }
                self.receiveLoop(onMessage: onMessage, onClose: onClose)
            case .failure(let error):
                // Код закрытия отличает убийство соединения снаружи (1006)
                // от чистого close-фрейма воркера/DC (1000/1002/1011).
                let code = self.task?.closeCode.rawValue ?? -1
                let reason = self.task?.closeReason.flatMap { String(data: $0, encoding: .utf8) } ?? ""
                self.post("ws_closed:\(code):\(reason):\(error.localizedDescription)")
                self.connected = false
                onClose()
            }
        }
    }

    // ponytail: send сразу после resume() — URLSession сам буферизует до конца
    // handshake. Guard на connected был багом: init дропался, гейтвей молчал.
    func send(_ data: Data) {
        task?.send(.data(data)) { error in
            if let error {
                NSLog("[WSBridge] WS send error: \(error.localizedDescription)")
                if Self.sndErrLogged < 3 {
                    Self.sndErrLogged += 1
                    self.post("ws_snderr:\(error.localizedDescription)")
                }
            }
        }
    }

    func sendBatch(_ parts: [Data]) {
        for part in parts { send(part) }
    }

    func close() {
        connected = false
        closedFlag.set()
        task?.cancel(with: .normalClosure, reason: nil)
        task = nil
    }

    private static func postEvent(_ name: String) {
        EventLog.append(name)
        let cfName = "com.l1ratch.WSBridge.\(name)" as CFString
        CFNotificationCenterPostNotification(
            CFNotificationCenterGetDarwinNotifyCenter(),
            CFNotificationName(cfName),
            nil, nil, true
        )
    }
}
