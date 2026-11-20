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
    private var connected = false
    private var initFrame: Data?
    private var firstRecv = false
    private var pingOK = false
    private var relayConn: NWConnection?
    private var relayReady = false
    private var relayPending = Data()
    private static let relaySecret = "wsb1"
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

    func connect(dc: Int, isMedia: Bool, isTestDC: Bool, initFrame: Data, onMessage: @escaping (Data) -> Void, onClose: @escaping () -> Void) {
        let path = isTestDC ? "/apiws_test" : "/apiws"
        self.initFrame = initFrame

        // Media-DC у десктопа ходит на kws{dc}-1; обычный — kws{dc}.
        let gwHost = isMedia ? "kws\(dc)-1.web.telegram.org" : "kws\(dc).web.telegram.org"

        // Round-robin старт: Telegram держит ~12 параллельных соединений —
        // каждое начнёт со своего фронта и живые найдутся быстрее.
        // Персистентный реестр здоровья (Android-порт): переупорядочиваем
        // фронтами по lastSuccess (свежие успехи первыми), известные мёртвые
        // (<3 фейлов подряд, без успеха 24ч) отбрасываем.
        let fronts = CFDomains.domains(dc: dc)
        Self.rrStart = (Self.rrStart + 1) % max(fronts.count, 1)
        let start = Self.rrStart
        var rotated = Array(fronts[start...] + fronts[..<start])
        let (ordered, excluded) = FrontHealthRegistry.orderAndFilter(rotated)
        if excluded > 0 {
            post("health_excl:\(excluded)")
            NSLog("[WSBridge] health registry: excluded \(excluded) endpoints")
            rotated = ordered.isEmpty ? rotated : ordered
        } else {
            rotated = ordered
        }

        // WS/80 БЕЗ TLS для CF-фронтов — обход, который 19.11.2026 массово
        // подтверждён у офф tg-ws-proxy («Выключить TLS для CF-прокси»,
        // Flowseal #1652) и включён по умолчанию в Android-форке v1.11.10
        // (Regstar2 PR #169, ws://…:80/apiws). Участок до CF не шифруется,
        // но MTProto-payload остаётся под собственным obfuscated2.
        // Порядок: сначала 80 у тех же 6 фронтов, затем ПРЕЖНИЙ каскад
        // (443-фронты → gatewayIP → gwHost) целиком, как fallback.
        let top = rotated.prefix(6)
        var endpoints: [Endpoint] = top.map { ($0, nil as String?, true) }
        endpoints += top.map { ($0, nil as String?, false) }
        endpoints += Self.gatewayIPs.map { ($0, gwHost as String?, false) }
        endpoints.append((gwHost, nil, false))

        let healthy = Self.aliveOnly(endpoints)
        tryConnect(endpoints: healthy.isEmpty ? endpoints : healthy, path: path, index: 0, onMessage: onMessage, onClose: onClose)
    }

    private func tryConnect(endpoints: [Endpoint], path: String, index: Int, onMessage: @escaping (Data) -> Void, onClose: @escaping () -> Void) {
        guard index < endpoints.count else {
            NSLog("[WSBridge] WS: all endpoints failed")
            post("ws_fail")
            onClose()
            return
        }
        let ep = endpoints[index]
        let key = Self.healthKey(ep.host, plain: ep.plain)
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

        // Офф tg-ws-proxy (proxy/raw_websocket.py) сначала ДОЖИДАЕТСЯ
        // `101 Switching Protocols`, и только после этого шлёт relay_init.
        // Раньше мы звали send(initFrame) СРАЗУ после resume(), до конца
        // handshake: URLSession буферизует кадр, но если 101 не приходит,
        // send висит вечно и ws_up не наступает НИ РАЗУ (в логах так и есть).
        // Переносим отправку в момент первого успешного receive — ровно
        // как в рабочей версии для ПК.
        wsTask.receive { [weak self] result in
            guard let self else { return }
            switch result {
            case .success(let message):
                _ = state.claim()
                self.connected = true
                // ЭТАП 1: если первое сообщение — CLOSE-фрейм от гейтвея,
                // логируем код и ПРИЧИНУ. ПК-тест дал `1000 "404"` сразу
                // после 101 на любой init; надо подтвердить то же на iOS.
                switch message {
                case .string(let text): self.post("ws_first:string:\(text.prefix(64))")
                case .data(let d): self.post("ws_first:data:\(d.count)B")
                @unknown default: self.post("ws_first:unknown")
                }
                if let initFrame {
                    self.task?.send(.data(initFrame)) { error in
                        if let error {
                            self.post("ws_send:err:\((error as NSError).code)")
                        } else {
                            state.delivered = true
                            if !self.upPosted {
                                self.upPosted = true
                                self.post("ws_up")
                            }
                            self.post("ws_send:ok")
                        }
                    }
                }
                if case .data(let data) = message {
                    self.firstRecv = true
                    Self.markAlive(key)
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

        // Таймаут 10с, КАК В ОФФ tg-ws-proxy (raw_websocket.py connect
        // timeout=10, pool.py 7-8с). Раньше стояло 5с: на сотовой сети
        // DNS→TCP→TLS→101 стал занимать чуть больше, и мы САМИ убивали
        // задачу (`-999 NSURLErrorDomain:отменено`), не дождавшись 101.
        // Обновление фронтов с timeoutInterval=10 при этом работало —
        // сеть цела, дело было только в нашем преждевременном cancel.
        // Доставленный init (delivered) гасит таймер раньше.
        let started = Date()
        DispatchQueue.global().asyncAfter(deadline: .now() + 10) {
            guard !state.delivered, state.claim() else { return }
            let ms = Int(Date().timeIntervalSince(started) * 1000)
            NSLog("[WSBridge] WS: \(key) connect timed out, trying next")
            self.post("ws_timeout:\(key)")
            self.post("ws_timeout:detail:no_101_no_init:\(ms)ms")
            self.post("ws_closeinfo:\(key):code=\(wsTask.closeCode.rawValue):reason=\((wsTask.closeReason.flatMap { String(data: $0, encoding: .utf8) } ?? "").prefix(64))")
            Self.markDead(key)
            wsTask.cancel(with: .goingAway, reason: nil)
            self.task = nil
            self.tryConnect(endpoints: endpoints, path: path, index: index + 1, onMessage: onMessage, onClose: onClose)
        }
    }

    /// ponytail: NSLock вместо атомика — claim() должен быть именно once,
    /// колбэки send/receive/timer приходят с разных потоков.
    private final class TryState {
        private let lock = NSLock()
        private var claimed = false
        var delivered = false
        func claim() -> Bool {
            lock.lock(); defer { lock.unlock() }
            if claimed { return false }
            claimed = true
            return true
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
        if let rc = relayConn {
            if relayReady {
                rc.send(content: data, completion: .contentProcessed { _ in })
            } else {
                relayPending.append(data)
            }
            return
        }
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
        if let rc = relayConn {
            relayConn = nil
            rc.cancel()
            return
        }
        task?.cancel(with: .normalClosure, reason: nil)
        task = nil
    }

    /// Прямой режим: сырой TCP на своё реле (VPS) — без CF, без WS, без TLS
    /// (ATS не действует на NWConnection, сертификат не нужен). Протокол тот
    /// же, что у воркера: строка «секрет dst\n», дальше сырой поток в обе стороны.
    func connectRelay(host: String, port: UInt16, dst: String, onMessage: @escaping (Data) -> Void, onClose: @escaping () -> Void) {
        post("relay_try:\(host):\(port)")
        guard let nwPort = NWEndpoint.Port(rawValue: port) else {
            post("relay_badport:\(port)")
            onClose()
            return
        }
        let conn = NWConnection(host: NWEndpoint.Host(host), port: nwPort, using: .tcp)
        relayConn = conn
        var finished = false
        let finishOnce = {
            guard !finished else { return }
            finished = true
            self.relayConn = nil
            onClose()
        }
        conn.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .ready:
                self.relayReady = true
                self.post("relay_up")
                var head = Data("\(Self.relaySecret) \(dst)\n".utf8)
                head.append(self.relayPending)
                self.relayPending = Data()
                conn.send(content: head, completion: .contentProcessed { _ in })
                self.relayReceive(onMessage: onMessage, finish: finishOnce)
            case .failed(let error):
                self.post("relay_closed:\(error.localizedDescription)")
                finishOnce()
            case .cancelled:
                finishOnce()
            default:
                break
            }
        }
        conn.start(queue: .global(qos: .userInitiated))
        // Реле принимает мгновенно; нет .ready за 5с — адрес недоступен.
        DispatchQueue.global().asyncAfter(deadline: .now() + 5) { [weak self] in
            guard let self, self.relayConn === conn, !self.relayReady else { return }
            self.post("relay_slow")
            conn.cancel()
            finishOnce()
        }
    }

    private func relayReceive(onMessage: @escaping (Data) -> Void, finish: @escaping () -> Void) {
        relayConn?.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] data, _, isComplete, error in
            guard let self else { return }
            if let data, !data.isEmpty {
                if !self.firstRecv {
                    self.firstRecv = true
                    if !self.upPosted {
                        self.upPosted = true
                        self.post("ws_up") // единая стадия для статистики приложения
                    }
                }
                onMessage(data)
                self.relayReceive(onMessage: onMessage, finish: finish)
                return
            }
            if isComplete || error != nil {
                self.post("relay_closed:end")
                finish()
            }
        }
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
