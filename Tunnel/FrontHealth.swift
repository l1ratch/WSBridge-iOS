import Foundation

/// Персистентный реестр здоровья фронтов (перенос из Android-версии WSBridge-Android).
/// Долгосрочная память между включениями туннеля: число фейлов подряд, время
/// последнего фейла и последнего успеха. Переживает перезапуск расширения.
///
/// Слои защиты:
/// - Runtime: WSClient.deadUntil 10 мин (быстрая реакция внутри сессии);
/// - Реестр (этот файл): долгосрочная память между включениями;
/// - Обновление списка: приложение валидирует домены DNS-резолвом до сохранения.
///
/// Вход в каскад: <3 фейлов подряд ИЛИ успех за последние 24 часа.
/// Порядок: свежие успехи первыми. Встроенные — всегда в начале (fallback).
/// Эвикция: мёртвый >7 дней и пропал из апстрима — удаляется из реестра.
///
/// ponytail: все внутренние функции работают ПОД уже взятым lock'ом;
/// публичные берут lock сами. Ни одного повторного взятия — NSLock
/// нерекурсивный, двойной lock = дедлок (билд 79 подвешивал каскад
/// на первом markAlive).
struct FrontHealth: Codable {
    var failCount: Int = 0
    var lastFail: Date?
    var lastSuccess: Date?
}

enum FrontHealthRegistry {
    /// Extension-процесс пишет в свой UserDefaults (доступен только ему, живёт
    /// между запусками — iOS может убить расширение в любой момент).
    private static let key = "frontHealthRegistry"
    private static var cache: [String: FrontHealth]?
    private static var lastFlush = Date.distantPast
    private static let lock = NSLock()

    /// НЕИЗВЕСТНО снаружи: вызывать только под lock. Загружает кэш один раз.
    private static func loadLocked() -> [String: FrontHealth] {
        if let cache { return cache }
        let loaded = (UserDefaults.standard.data(forKey: key))
            .flatMap { try? JSONDecoder().decode([String: FrontHealth].self, from: $0) } ?? [:]
        cache = loaded
        return loaded
    }

    /// НЕИЗВЕСТНО снаружи: вызывать только под lock.
    private static func flushLocked(immediate: Bool) {
        guard let cache, let data = try? JSONEncoder().encode(cache) else { return }
        let now = Date()
        if !immediate {
            guard now.timeIntervalSince(lastFlush) > 15 else { return }
        }
        UserDefaults.standard.set(data, forKey: key)
        lastFlush = now
    }

    /// Пишет на диск. Троттлинг 15с — кроме fail (самое ценное, пишем сразу).
    static func flush(immediate: Bool = false) {
        lock.lock(); defer { lock.unlock() }
        flushLocked(immediate: immediate)
    }

    static func recordSuccess(_ host: String) {
        lock.lock(); defer { lock.unlock() }
        var reg = loadLocked()
        var e = reg[host] ?? FrontHealth()
        e.failCount = 0
        e.lastSuccess = Date()
        reg[host] = e
        cache = reg
        flushLocked(immediate: false)
    }

    static func recordFailure(_ host: String) {
        lock.lock(); defer { lock.unlock() }
        var reg = loadLocked()
        var e = reg[host] ?? FrontHealth()
        e.failCount += 1
        e.lastFail = Date()
        reg[host] = e
        cache = reg
        flushLocked(immediate: true) // фейл — самое ценное, сразу на диск
    }

    /// Каскадный вид: вход <3 фейлов подряд ИЛИ успех за 24ч.
    /// Сортировка: свежие успехи первыми. Возвращает hosts в приоритетном
    /// порядке и число исключённых.
    static func orderAndFilter(_ hosts: [String]) -> (ordered: [String], excluded: Int) {
        lock.lock(); defer { lock.unlock() }
        let reg = loadLocked()
        let now = Date()
        var alive: [(host: String, lastSuccess: Date?)] = []
        var excluded = 0
        for h in hosts {
            let e = reg[h]
            let failBad = (e?.failCount ?? 0) >= 3
            let recentSuccess = e?.lastSuccess.map { now.timeIntervalSince($0) < 86400 } ?? false
            if failBad && !recentSuccess {
                excluded += 1
                continue
            }
            alive.append((h, e?.lastSuccess))
        }
        // Свежие успехи первыми; без успеха — в исходном порядке после.
        let ordered = alive
            .enumerated()
            .sorted { a, b in
                switch (a.element.lastSuccess, b.element.lastSuccess) {
                case let (l?, r?): return l > r
                case (_?, nil): return true
                case (nil, _?): return false
                default: return a.offset < b.offset
                }
            }
            .map { $0.element.host }
        return (ordered, excluded)
    }

    /// Эвикция протухших: мёртвые >7 дней, которых нет в свежем списке апстрима.
    /// Вызывается при обновлении списка фронтов (startTunnel).
    static func evict(absentFrom current: Set<String>) {
        lock.lock(); defer { lock.unlock() }
        var reg = loadLocked()
        let now = Date()
        let before = reg.count
        for (host, e) in reg where current.contains(host) == false {
            let deadOver7d = e.lastFail.map { now.timeIntervalSince($0) > 7 * 86400 } ?? false
            let noSuccessOver7d = e.lastSuccess.map { now.timeIntervalSince($0) > 7 * 86400 } ?? true
            if deadOver7d && noSuccessOver7d { reg.removeValue(forKey: host) }
        }
        cache = reg
        if reg.count != before { flushLocked(immediate: true) }
    }

    /// Строка для EventLog.
    static func summary() -> String {
        lock.lock(); defer { lock.unlock() }
        let reg = loadLocked()
        let dead = reg.values.filter { $0.failCount >= 3 }.count
        return "known=\(reg.count) bad=\(dead)"
    }
}
