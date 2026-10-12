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

    /// Прямые IP kws-гейтвеев. .220 — дефолт десктопного tg-ws-proxy (рабочий),
    /// .205 — альтернатива из их доков, .99/.174.100 — текущие ответы DNS
    /// (kws2/kws4 и kws1, получены DoH в обход отравления).
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
            let parts = host.split(separator: ".")
            let isIPv4 = parts.count == 4 && parts.allSatisfy { Int($0) != nil }
            guard isIPv4,
                  challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
                  let trust = challenge.protectionSpace.serverTrust else {
                completionHandler(.performDefaultHandling, nil)
                return
            }
            for name in ["kws1.web.telegram.org", "web.telegram.org"] {
                SecTrustSetPolicies(trust, SecPolicyCreateSSL(true, name as CFString))
                var err: CFError?
                if SecTrustEvaluateWithError(trust, &err) {
                    completionHandler(.useCredential, URLCredential(trust: trust))
                    return
                }
            }
            completionHandler(.cancelAuthenticationChallenge, nil)
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
    private static let relaySecret = "wsb1" // == SECRET в tools/vps_relay.py
    private var upPosted = false
    private static var sndErrLogged = 0
    private let tag: String

    init(tag: String = "") { self.tag = tag }

    private func post(_ name: String) {
        Self.postEvent(tag.isEmpty ? name : "\(tag):\(name)")
    }

    /// Подключается к kws-гейтвею. Порядок: CF-фронты (ротация старта) → прямые
    /// IP гейтвеев → kws{dc}.web.telegram.org. Фронты первыми: на LTE они
    /// единственные дают мгновенный 101 (TG-диапазон 149.154.* сотовые
    /// операторы блокируют на L4, а CF — нет); 10с-таймауты на IP не давали
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

    private static func aliveOnly(_ eps: [(host: String, hostHeader: String?)]) -> [(host: String, hostHeader: String?)] {
        healthLock.lock(); defer { healthLock.unlock() }
        let now = Date()
        return eps.filter { ep in
            guard let until = deadUntil[ep.host] else { return true }
            if until > now { return false }
            deadUntil.removeValue(forKey: ep.host)
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

        var endpoints: [(host: String, hostHeader: String?)] =
            rotated.prefix(6).map { ($0, nil as String?) }
        endpoints += Self.gatewayIPs.map { ($0, gwHost as String?) }
        endpoints.append((gwHost, nil))

        let healthy = Self.aliveOnly(endpoints)
        tryConnect(endpoints: healthy.isEmpty ? endpoints : healthy, path: path, index: 0, onMessage: onMessage, onClose: onClose)
    }

    private func tryConnect(endpoints: [(host: String, hostHeader: String?)], path: String, index: Int, onMessage: @escaping (Data) -> Void, onClose: @escaping () -> Void) {
        guard index < endpoints.count else {
            NSLog("[WSBridge] WS: all endpoints failed")
            post("ws_fail")
            onClose()
            return
        }
        let ep = endpoints[index]
        guard let url = URL(string: "wss://\(ep.host)\(path)") else {
            tryConnect(endpoints: endpoints, path: path, index: index + 1, onMessage: onMessage, onClose: onClose)
            return
        }
        NSLog("[WSBridge] WS: trying \(ep.host)")
        post("ws_try:\(ep.host)")
        var request = URLRequest(url: url)
        request.setValue("binary", forHTTPHeaderField: "Sec-WebSocket-Protocol")
        if let hh = ep.hostHeader {
            request.setValue(hh, forHTTPHeaderField: "Host")
        }
        let wsTask = Self.sharedSession.webSocketTask(with: request)
        task = wsTask
        wsTask.resume()

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

        // Init — первым фреймом (URLSession буферизует до конца handshake).
        // ws_up = init в сокете; с этого момента каскадный таймер выключен.
        if let initFrame {
            wsTask.send(.data(initFrame)) { error in
                if let error {
                    NSLog("[WSBridge] WS init send error: \(error.localizedDescription)")
                } else {
                    state.delivered = true
                    if !self.upPosted {
                        self.upPosted = true
                        self.post("ws_up")
                    }
                }
            }
        }

        wsTask.receive { [weak self] result in
            guard let self else { return }
            switch result {
            case .success(let message):
                _ = state.claim()
                self.connected = true
                if case .data(let data) = message {
                    self.firstRecv = true
                    Self.markAlive(ep.host)
                    onMessage(data)
                }
                self.receiveLoop(onMessage: onMessage, onClose: onClose)
            case .failure(let error):
                NSLog("[WSBridge] WS: \(ep.host) failed (\(error.localizedDescription)), next")
                post("ws_err:\(ep.host):\(error.localizedDescription)")
                if self.firstRecv {
                    Self.markAlive(ep.host) // умерла живая сессия — эндпоинт не виноват
                    fail()
                } else {
                    Self.markDead(ep.host)
                    advance()
                }
            }
        }

        // Таймер только на фазу коннекта (5с: живые фронты дают 101 за <1с,
        // висящие эндпоинты не должны съедать терпение Telegram).
        // Доставленный init (delivered) гасит его.
        DispatchQueue.global().asyncAfter(deadline: .now() + 5) {
            guard !state.delivered, state.claim() else { return }
            NSLog("[WSBridge] WS: \(ep.host) connect timed out, trying next")
            self.post("ws_timeout:\(ep.host)")
            Self.markDead(ep.host)
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
