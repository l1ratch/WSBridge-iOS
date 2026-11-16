import Foundation

/// Журнал событий расширения. Приложение читает его через loopback TCP
/// (JournalServer, 127.0.0.1:51001) — работает всегда, без entitlements.
///
/// Каждый запуск туннеля пишется в ОТДЕЛЬНЫЙ файл в Library/Logs/
/// и НЕ обрезается: строки дозаписываются сразу (append), чтобы при
/// jetsam/крахе не терялись ни начало, ни середина. journal() отдаёт
/// текущий прогон целиком плюс прошлые файлы подряд — без «PREV RUN» /
/// «CURRENT RUN», которые раньше путали и всё равно теряли ранние
/// строки из-за кольца на 200 записей.
enum EventLog {
    private static var entries: [(String, Date)] = []
    private static let lock = NSLock()
    private static let fmt: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "HH:mm:ss"
        return f
    }()
    private static let fileFmt: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "yyyyMMdd-HHmmss"
        return f
    }()

    /// Текущий файл прогона. Создаётся лениво при первом append, чтобы
    /// имя содержало реальное время старта, а не время загрузки класса.
    private static var runFileURL: URL?
    private static var runHandle: FileHandle?

    /// Максимум файлов прогонов. При переполнении старые удаляются.
    private static let maxRunFiles = 20

    private static var logsDir: URL =
        URL(fileURLWithPath: NSHomeDirectory())
            .appendingPathComponent("Library/Logs", isDirectory: true)

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

    /// Начало нового прогона. Вызывается из startTunnel ДО первого append.
    /// Прошлые файлы не трогаем — они остаются доступны через journal().
    static func beginRun() {
        lock.lock(); defer { lock.unlock() }
        entries = []
        closeLocked()

        try? FileManager.default.createDirectory(at: logsDir, withIntermediateDirectories: true)
        let name = "run-\(fileFmt.string(from: Date())).log"
        let url = logsDir.appendingPathComponent(name)
        // Если за одну секунду стартовали дважды — не перетираем.
        var finalURL = url
        var suffix = 1
        while FileManager.default.fileExists(atPath: finalURL.path) {
            finalURL = logsDir.appendingPathComponent(
                "run-\(fileFmt.string(from: Date()))-\(suffix).log")
            suffix += 1
        }
        runFileURL = finalURL
        FileManager.default.createFile(atPath: finalURL.path, contents: nil)
        runHandle = try? FileHandle(forWritingTo: finalURL)
        rotateLocked()
    }

    /// Раньше читали «прошлый прогон» в память. Теперь прошлые файлы
    /// читает journal() напрямую. Оставляем метод для совместимости с
    /// вызовом в PacketTunnelProvider — он становится no-op.
    static func loadPrevious() { /* no-op: journal() читает файлы сам */ }

    static func append(_ name: String) {
        lock.lock(); defer { lock.unlock() }
        let date = Date()
        let line = "\(fmt.string(from: date)) \(name)\n"
        entries.append((name, date))
        // Кольца больше нет: пишем строку СРАЗУ в файл прогона.
        if runHandle == nil { openLocked() }
        if let h = runHandle {
            try? h.write(contentsOf: Data(line.utf8))
        }
    }

    static func flush() {
        lock.lock(); defer { lock.unlock() }
        // Дозапись уже идёт построчно; просто синхронизируем дескриптор.
        try? runHandle?.synchronize()
    }

    /// Полный журнал: все файлы прогонов в хронологическом порядке,
    /// затем текущий прогон (он же последний файл, но отдаём из памяти,
    /// чтобы не читать только что записанное с диска дважды).
    static func journal() -> String {
        lock.lock(); defer { lock.unlock() }
        try? runHandle?.synchronize()

        var out = ""
        let files = runFilesLocked()
        // Все файлы, кроме текущего, — это завершённые прогоны.
        for url in files where url != runFileURL {
            if let text = try? String(contentsOf: url, encoding: .utf8), !text.isEmpty {
                out += "=== \(url.lastPathComponent) ===\n\(text)\n"
            }
        }
        // Текущий прогон целиком, без обрезания.
        if !entries.isEmpty {
            let cur = entries.map { "\(fmt.string(from: $0.1)) \($0.0)" }
                .joined(separator: "\n")
            out += "=== \(runFileURL?.lastPathComponent ?? "current") ===\n\(cur)\n"
        }
        return out.isEmpty ? "журнал пуст" : out
    }

    /// Список файлов журналов для экспорта «Поделиться».
    static func logFileURLs() -> [URL] {
        lock.lock(); defer { lock.unlock() }
        try? runHandle?.synchronize()
        return runFilesLocked()
    }

    // MARK: - Приватное

    private static func openLocked() {
        try? FileManager.default.createDirectory(at: logsDir, withIntermediateDirectories: true)
        let name = "run-\(fileFmt.string(from: Date())).log"
        let url = logsDir.appendingPathComponent(name)
        if runFileURL == nil { runFileURL = url }
        if !FileManager.default.fileExists(atPath: url.path) {
            FileManager.default.createFile(atPath: url.path, contents: nil)
        }
        runHandle = try? FileHandle(forWritingTo: runFileURL ?? url)
        try? runHandle?.seekToEnd()
    }

    private static func closeLocked() {
        try? runHandle?.synchronize()
        try? runHandle?.close()
        runHandle = nil
        runFileURL = nil
    }

    private static func runFilesLocked() -> [URL] {
        let fm = FileManager.default
        let files = (try? fm.contentsOfDirectory(
            at: logsDir, includingPropertiesForKeys: [.creationDateKey],
            options: .skipsHiddenFiles)) ?? []
        return files
            .filter { $0.lastPathComponent.hasPrefix("run-") && $0.pathExtension == "log" }
            .sorted { $0.lastPathComponent < $1.lastPathComponent }
    }

    private static func rotateLocked() {
        let files = runFilesLocked()
        guard files.count > maxRunFiles else { return }
        for url in files.prefix(files.count - maxRunFiles) where url != runFileURL {
            try? FileManager.default.removeItem(at: url)
        }
    }
}
