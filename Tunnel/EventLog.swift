import Foundation

/// Журнал событий расширения. Приложение читает его через loopback TCP
/// (JournalServer, 127.0.0.1:51001) — работает всегда, без entitlements.
/// Персистится в файл контейнера: после краха/jetsam следующий запуск
/// отдаёт лог ПРЕДЫДУЩЕГО прогона (loadPrevious) — иначе причину смерти
/// расширения не увидеть никогда.
enum EventLog {
    private static var entries: [(String, Date)] = []
    private static var prevRun: String = ""
    private static var unflushed = 0
    private static let lock = NSLock()
    private static let fmt: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "HH:mm:ss"
        return f
    }()
    private static let fileURL: URL =
        URL(fileURLWithPath: NSHomeDirectory()).appendingPathComponent("Library/journal.log")

    // Счётчики io-строки журнала (пишутся с lwipQueue)
    static var outPkts: UInt64 = 0
    static var wsDown: UInt64 = 0
    static var writeFails: UInt64 = 0
    static var upBytes: UInt64 = 0
    static var rxBytes: UInt64 = 0
    static var pendCur: UInt64 = 0
    static var sentCb: UInt64 = 0
    static var inV4tcp: UInt64 = 0
    static var inV6: UInt64 = 0
    static var inOther: UInt64 = 0

    /// Читает лог прошлого прогона (вызывать ДО первого append).
    static func loadPrevious() {
        lock.lock(); defer { lock.unlock() }
        prevRun = (try? String(contentsOf: fileURL, encoding: .utf8)) ?? ""
    }

    static func append(_ name: String) {
        lock.lock(); defer { lock.unlock() }
        entries.append((name, Date()))
        if entries.count > 200 { entries.removeFirst(entries.count - 200) }
        unflushed += 1
        // ponytail: flush не чаще 20 записей — на крахе теряем максимум
        // 20 строк, зато файл не долбится на каждом ws_recv.
        if unflushed >= 20 { flushLocked() }
    }

    static func flush() {
        lock.lock(); defer { lock.unlock() }
        flushLocked()
    }

    private static func flushLocked() {
        unflushed = 0
        let text = entries.map { "\(fmt.string(from: $0.1)) \($0.0)" }.joined(separator: "\n")
        try? text.write(to: fileURL, atomically: true, encoding: .utf8)
    }

    static func journal() -> String {
        lock.lock(); defer { lock.unlock() }
        let cur = entries.map { "\(fmt.string(from: $0.1)) \($0.0)" }.joined(separator: "\n")
        guard !prevRun.isEmpty else { return cur }
        return "=== PREV RUN ===\n\(prevRun)\n=== CURRENT RUN ===\n\(cur)"
    }
}
