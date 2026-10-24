import SwiftUI
import NetworkExtension
import UIKit
import Charts

/// Главный экран: только молния-кнопка. Меню — системный ellipsis сверху справа.
/// iOS 26: настоящий Liquid Glass (glassEffect); 17-25: деградация в material.
struct ContentView: View {
    @StateObject private var tunnel = TunnelManager()
    @State private var showMenu = false
    @State private var boltFill = false
    @Environment(\.colorScheme) private var colorScheme
    @Environment(\.scenePhase) private var scenePhase
    @State private var showDNS = false

    var body: some View {
        NavigationStack {
            ZStack {
                // Точка слияния: тёмная тема — глубокий navy, светлая — мягкий серо-голубой.
                Color(hex: colorScheme == .dark ? 0x0D1526 : 0xE8EDF5).ignoresSafeArea()

                // Верхнее свечение: одинаковое в обеих темах.
                // ponytail: blur 110 — дорогая операция. Раньше ЦВЕТ свечения
                // анимировался на каждый статус = перерисовка blur каждый кадр
                // (лаги на слабых устройствах, «кнопка тупит»). Теперь два
                // статичных blur-слоя кроссфейдятся по opacity — blur рендерится
                // один раз и кэшируется, анимируется только дешёвая прозрачность.
                ZStack {
                    Ellipse()
                        .fill(Color(hex: 0x1E3A6E))
                        .frame(width: 560, height: 520)
                        .blur(radius: 110)
                        .opacity(tunnel.status == .connected ? 0 : (colorScheme == .dark ? 0.55 : 0.45))
                    Ellipse()
                        .fill(Color(hex: 0x17A05E))
                        .frame(width: 560, height: 520)
                        .blur(radius: 110)
                        .opacity(tunnel.status == .connected ? (colorScheme == .dark ? 0.55 : 0.45) : 0)
                }
                .offset(y: -250)
                .animation(.easeInOut(duration: 0.8), value: tunnel.status)
                .ignoresSafeArea()

                // Нижняя глубина: тёмная тема — почти чёрный, светлая — мягкий тёплый серый.
                Ellipse()
                    .fill(Color(hex: colorScheme == .dark ? 0x040810 : 0xD5DAE4))
                    .frame(width: 700, height: 480)
                    .blur(radius: 130)
                    .opacity(colorScheme == .dark ? 0.85 : 0.6)
                    .offset(y: 400)
                    .ignoresSafeArea()

                VStack(spacing: 20) {
                    // Молния — и индикатор, и кнопка: тап включает/выключает.
                    // Анимация: цвет «заливает» молнию сверху вниз.
                    Button {
                        Task { await tunnel.toggle() }
                    } label: {
                        ZStack {
                            // База: серая молния
                            Image(systemName: "bolt.fill")
                                .font(.system(size: 170, weight: .bold))
                                .foregroundStyle(Color(.systemGray3))

                            // Заливка: зелёная, растёт сверху вниз
                            Image(systemName: "bolt.fill")
                                .font(.system(size: 170, weight: .bold))
                                .foregroundStyle(Color(hex: 0x17A05E))
                                .mask(alignment: .top) {
                                    Rectangle()
                                        .frame(height: boltFill ? 240 : 0)
                                        .animation(.easeOut(duration: 0.5), value: boltFill)
                                }
                        }
                        .shadow(color: boltFill ? Color(hex: 0x17A05E).opacity(0.6) : .black.opacity(0.2),
                                radius: boltFill ? 40 : 8)
                        .padding(48)
                        .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                    // НЕ disabled ни в каком статусе: залипший published-статус
                    // не должен убивать тап (баг билдов 81-84). Направление
                    // решения toggle() читает живой connection.status,
                    // от дабл-тапов защищает дебаунс внутри toggle().
                    .onChange(of: tunnel.status) { _, newStatus in
                        boltFill = (newStatus == .connected)
                    }
                    .onAppear {
                        boltFill = (tunnel.status == .connected)
                    }

                    // DNS-строка: крупнее, ближе к молнии.
                    Button {
                        showDNS = true
                    } label: {
                        HStack(spacing: 8) {
                            Image(systemName: "network")
                            Text(dnsLabel)
                                .font(.body)
                            Circle()
                                .fill(tunnel.activeDNSServers.isEmpty ? Color(.systemGray3) : Color(hex: 0x17A05E))
                                .frame(width: 8, height: 8)
                        }
                        .padding(.horizontal, 12)
                        .padding(.vertical, 6)
                    }
                    .modifier(DNSButtonStyle())
                    .controlSize(.large)

                    // Статус скрыт по просьбе владельца (не удалён).
                    Text(statusText)
                        .font(.headline)
                        .foregroundStyle(.secondary)
                        .hidden()

                    if let errorMessage = tunnel.errorMessage {
                        Text(errorMessage)
                            .font(.caption)
                            .foregroundStyle(.red)
                            .multilineTextAlignment(.center)
                            .padding(.horizontal, 20)
                            .padding(.vertical, 10)
                            .glassCapsule()
                    }
                }

                // Версия и копирайт — одна строка, почти над «Домой».
                // Только маркетинговая версия (0.2.N): её последнее число
                // и есть номер сборки, дублировать его в скобках незачем.
                Text("v\(Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "?") · © 2026 l1ratch")
                    .font(.caption2)
                    .foregroundStyle(.secondary.opacity(0.5))
                    .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .bottom)
                    .padding(.bottom, 8)
            }
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button {
                        showMenu = true
                    } label: {
                        Image(systemName: "ellipsis")
                            .font(.title3.weight(.semibold))
                    }
                }
            }
            .sheet(isPresented: $showMenu) {
                MenuView(tunnel: tunnel)
            }
            .sheet(isPresented: $showDNS) {
                NavigationStack {
                    DNSView(tunnel: tunnel)
                }
            }
            .task { await tunnel.reload() }
            .onChange(of: scenePhase) { _, new in
                // noteActive сам перечитывает менеджер и статус.
                if new == .active { tunnel.noteActive() }
            }
            .alert("Сеть сменилась", isPresented: $tunnel.showNetChangeAlert) {
                Button("Перезапустить туннель") {
                    Task { await tunnel.restartTunnel() }
                }
                Button("Позже", role: .cancel) {}
            } message: {
                Text("Если интернет тормозит — перезапусти туннель.")
            }
        }
    }

    private var statusText: String {
        switch tunnel.status {
        case .connected: "Туннель активен"
        case .connecting: "Подключение…"
        case .reasserting: "Переподключение…"
        case .disconnecting: "Отключение…"
        default: "Туннель выключен"
        }
    }

    /// Подпись DNS-бара: название выбранного DNS.
    private var dnsLabel: String {
        tunnel.selectedDNS.name
    }
}

/// Меню: штатный Form. На iOS 26 система сама рисует Liquid Glass.
struct MenuView: View {
    @ObservedObject var tunnel: TunnelManager
    @Environment(\.dismiss) private var dismiss
    @State private var showLiveInfo = false

    var body: some View {
        NavigationStack {
            Form {
                Section("Диагностика") {
                    NavigationLink {
                        JournalView(tunnel: tunnel)
                    } label: {
                        Label("Журнал туннеля", systemImage: "doc.text")
                    }
                    NavigationLink {
                        StatsView(tunnel: tunnel)
                    } label: {
                        Label("Статистика", systemImage: "chart.bar")
                    }
                }
                Section("Настройки") {
                    Toggle(isOn: $tunnel.liveActivityEnabled) {
                        HStack(spacing: 6) {
                            Label("Live Activity", systemImage: "bolt.badge.clock")
                            // Инфо-бейдж как в системных настройках: описание
                            // живёт в поповере, а не простынёй под тумблером.
                            Image(systemName: "info.circle")
                                .font(.body.weight(.medium))
                                .foregroundStyle(Color.accentColor.opacity(0.8))
                                .onTapGesture { showLiveInfo = true }
                        }
                    }
                    .popover(isPresented: $showLiveInfo) {
                        Text("Молния и таймер аптайма в Dynamic Island и на экране блокировки. Таймер рисует система, на батарею не влияет.")
                            .font(.callout)
                            .padding()
                            .frame(maxWidth: 260)
                            .presentationCompactAdaptation(.popover)
                    }
                    NavigationLink {
                        DNSManageView(tunnel: tunnel)
                    } label: {
                        Label("DNS-серверы", systemImage: "network")
                    }
                    NavigationLink {
                        WorkerView(tunnel: tunnel)
                    } label: {
                        Label("CF Worker", systemImage: "cloud")
                    }
                    // Кнопка на всю область строки; состояние и ответ
                    // обновления — отдельными строками ПОД ней (вместо
                    // описания и вместо крошки внутри кнопки).
                    Button {
                        Task { await tunnel.updateFronts() }
                    } label: {
                        Label("Обновить список фронтов", systemImage: "arrow.triangle.2.circlepath")
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    if tunnel.frontsUpdateMessage != nil || tunnel.frontsUpdatedAt != nil {
                        VStack(alignment: .leading, spacing: 2) {
                            if let msg = tunnel.frontsUpdateMessage {
                                Text(msg)
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                            if let updated = tunnel.frontsUpdatedAt {
                                Text("Список обновлён: \(updated.formatted(date: .abbreviated, time: .shortened))")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                        }
                    }
                }
                Section("Информация") {
                    NavigationLink {
                        AboutView()
                    } label: {
                        Label("О программе", systemImage: "info.circle")
                    }
                }

            }
            .navigationTitle("Меню")
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button("Готово") { dismiss() }
                }
            }
        }
    }
}

/// CF Worker: настройка собственного worker'а или реле + «DC → IP».
struct WorkerView: View {
    @ObservedObject var tunnel: TunnelManager

    var body: some View {
        Form {
            Section("CF Worker или реле") {
                TextField("worker.example.com, второй.doma.in или ip:port", text: $tunnel.workerDomain)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .disabled(tunnel.status == .connected)
                Text(workerHint)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Section("Датацентры Telegram (DC → IP)") {
                TextEditor(text: $tunnel.dcMapText)
                    .font(.system(.body, design: .monospaced))
                    .frame(minHeight: 80)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .disabled(tunnel.status == .connected)
                Text("По одному правилу на строку, формат «номер:IP». Перенаправляет dial worker'а: соединение к DC с этим номером пойдёт на указанный IP. Пусто — как выбрал Telegram. Работает только в режиме CF Worker.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Text("Канонические адреса: DC2 — 149.154.167.220, DC4 — 149.154.167.91. Пример: «2:149.154.167.220»")
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
            }
        }
        .navigationTitle("CF Worker")
        .navigationBarTitleDisplayMode(.inline)
    }

    private var workerHint: String {
        let wd = tunnel.workerDomain.trimmingCharacters(in: .whitespaces)
        if wd.isEmpty {
            return "Пусто = kws-фронты Cloudflare (основной режим)."
        }
        if wd.contains(":") {
            return "Прямой режим: сырой TCP на реле host:port, без CF."
        }
        let count = wd.split(separator: ",").filter { !$0.trimmingCharacters(in: .whitespaces).isEmpty }.count
        if count > 1 {
            return "Pipe-режим, \(count) домена: соединения распределяются round-robin. Перезапусти туннель."
        }
        return "Pipe-режим через свой CF worker. Перезапусти туннель, чтобы применилось."
    }
}

/// Журнал: моноширинный текст + системный toolbar (стеклянный на iOS 26).
struct JournalView: View {
    @ObservedObject var tunnel: TunnelManager

    var body: some View {
        ScrollView {
            Text(tunnel.journalText ?? "")
                .font(.system(.caption, design: .monospaced))
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding()
        }
        .navigationTitle("Журнал")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItemGroup(placement: .bottomBar) {
                Button {
                    tunnel.fetchStats()
                } label: {
                    Label("Обновить", systemImage: "arrow.clockwise")
                }
                Spacer()
                Button {
                    UIPasteboard.general.string = tunnel.journalText ?? ""
                } label: {
                    Label("Скопировать", systemImage: "doc.on.doc")
                }
                .disabled((tunnel.journalText ?? "").isEmpty)
                Spacer()
                if let url = exportFileURL {
                    ShareLink(item: url) {
                        Label("Поделиться", systemImage: "square.and.arrow.up")
                    }
                }
            }
        }
        .onAppear {
            if tunnel.journalText == nil { tunnel.fetchStats() }
        }
    }

    private var exportFileURL: URL? {
        guard let text = tunnel.journalText, !text.isEmpty else { return nil }
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("WSBridge-journal.log")
        do {
            try text.write(to: url, atomically: true, encoding: .utf8)
            return url
        } catch {
            return nil
        }
    }
}

/// Статистика живого туннеля (Darwin-события от расширения).
struct StatsView: View {
    @ObservedObject var tunnel: TunnelManager
    @State private var rangeDays = 7
    /// Свежий снапшот с расширения при открытии экрана.
    @State private var refreshed = false

    private var days: [(day: String, usage: TunnelManager.DayUsage)] {
        tunnel.usageDays(rangeDays)
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                rangePicker
                summaryCards
                trafficChart
                uptimeChart
                livePulse
                diagnosticsSection
            }
            .padding(.vertical)
        }
        .navigationTitle("Статистика")
        .navigationBarTitleDisplayMode(.inline)
        .onAppear {
            tunnel.fetchStats()
            // Опрос счётчиков у расширения — чтобы текущая сессия попала
            // в историю ещё до выключения.
            if !refreshed {
                refreshed = true
                Task { await tunnel.recordUsageSnapshot() }
            }
        }
    }

    /// Период — сегмент-контрол в контенте, НЕ в тулбаре: на iOS 26 тулбар
    /// сам стеклянный, и Picker поверх него рисовал второе стекло.
    private var rangePicker: some View {
        Picker("", selection: $rangeDays) {
            Text("7 дней").tag(7)
            Text("30 дней").tag(30)
            Text("90 дней").tag(90)
            Text("Всё").tag(0)
        }
        .pickerStyle(.segmented)
        .padding(.horizontal)
    }

    // MARK: - Сводка

    private var totalUp: UInt64 { tunnel.usageHistory.values.reduce(0) { $0 + $1.upBytes } }
    private var totalDown: UInt64 { tunnel.usageHistory.values.reduce(0) { $0 + $1.downBytes } }
    private var totalSeconds: TimeInterval { tunnel.usageHistory.values.reduce(0) { $0 + $1.seconds } }
    private var totalSessions: Int { tunnel.usageHistory.values.reduce(0) { $0 + $1.sessions } }

    private var summaryCards: some View {
        VStack(spacing: 10) {
            HStack(spacing: 10) {
                statCard(
                    title: "Всего",
                    value: Self.bytes(totalUp + totalDown),
                    subtitle: "↑\(Self.bytes(totalUp)) ↓\(Self.bytes(totalDown))",
                    icon: "arrow.up.arrow.down", tint: 0x17A05E)
                statCard(
                    title: "Наработано",
                    value: Self.duration(totalSeconds),
                    subtitle: totalSessions > 0 ? "\(totalSessions) включений" : "—",
                    icon: "clock", tint: 0x1E3A6E)
            }
            if tunnel.status == .connected {
                Text("Текущая сессия идёт — данные обновятся при выключении туннеля.")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.horizontal, 4)
            }
        }
        .padding(.horizontal)
    }

    private func statCard(title: String, value: String, subtitle: String,
                          icon: String, tint: UInt32) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 5) {
                Image(systemName: icon)
                    .font(.caption2.weight(.semibold))
                Text(title)
                    .font(.caption2.weight(.semibold))
            }
            .foregroundStyle(Color(hex: tint).opacity(0.9))
            Text(value)
                .font(.system(.title3, design: .rounded).weight(.semibold))
                .minimumScaleFactor(0.7)
                .lineLimit(1)
            Text(subtitle)
                .font(.caption2)
                .foregroundStyle(.secondary)
                .lineLimit(1)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(12)
        .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 14))
    }

    // MARK: - Графики

    private var trafficChart: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Трафик")
                .font(.headline)
                .padding(.horizontal)
            if days.allSatisfy({ $0.usage.upBytes + $0.usage.downBytes == 0 }) {
                emptyHint("Пока пусто — данные появятся после работы туннеля.")
            } else {
                Chart(days, id: \.day) { item in
                    BarMark(
                        x: .value("День", Self.shortDay(item.day)),
                        y: .value("Байт", Double(item.usage.downBytes) / 1_048_576.0)
                    )
                    .foregroundStyle(by: .value("Направление", "Входящий"))
                    .position(by: .value("Направление", "Входящий"))
                    BarMark(
                        x: .value("День", Self.shortDay(item.day)),
                        y: .value("Байт", Double(item.usage.upBytes) / 1_048_576.0)
                    )
                    .foregroundStyle(by: .value("Направление", "Исходящий"))
                    .position(by: .value("Направление", "Исходящий"))
                }
                .chartForegroundStyleScale([
                    "Входящий": Color(hex: 0x17A05E),
                    "Исходящий": Color(hex: 0x4A7BD0),
                ])
                .chartYAxisLabel("МБ")
                .chartLegend(position: .bottom, spacing: 8)
                .frame(height: 190)
                .padding(.horizontal)
            }
        }
    }

    private var uptimeChart: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Время работы")
                .font(.headline)
                .padding(.horizontal)
            if days.allSatisfy({ $0.usage.seconds == 0 }) {
                emptyHint("Пока пусто — данные появятся после работы туннеля.")
            } else {
                Chart(days, id: \.day) { item in
                    BarMark(
                        x: .value("День", Self.shortDay(item.day)),
                        y: .value("Часы", item.usage.seconds / 3600.0)
                    )
                    .foregroundStyle(Color(hex: 0x17A05E).gradient)
                    .cornerRadius(3)
                }
                .chartYAxisLabel("часы")
                .frame(height: 150)
                .padding(.horizontal)
            }
        }
    }

    private func emptyHint(_ text: String) -> some View {
        Text(text)
            .font(.caption)
            .foregroundStyle(.secondary)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.horizontal)
    }

    // MARK: - Живой пульс (бывшая «статистика туннеля»)

    private var livePulse: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Сейчас")
                .font(.headline)
            Text(tunnel.stats ?? "Нет данных — туннель не запущен")
                .font(.system(.footnote, design: .monospaced))
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(12)
                .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 12))
        }
        .padding(.horizontal)
    }

    // MARK: - Диагностика

    private var diagnosticsSection: some View {
        Group {
            if !tunnel.statusHistory.isEmpty {
                VStack(alignment: .leading, spacing: 2) {
                    Text("История статусов (диагностика кнопки)")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    ForEach(Array(tunnel.statusHistory.enumerated()), id: \.offset) { _, line in
                        Text(line)
                            .font(.system(.caption2, design: .monospaced))
                            .textSelection(.enabled)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.horizontal)
                .padding(.top, 8)
            }
        }
    }

    // MARK: - Форматирование

    static func bytes(_ b: UInt64) -> String {
        let mb = Double(b) / 1_048_576.0
        if mb >= 1024 { return String(format: "%.2f ГБ", mb / 1024) }
        if mb >= 1 { return String(format: "%.1f МБ", mb) }
        return String(format: "%.0f КБ", Double(b) / 1024.0)
    }

    static func duration(_ s: TimeInterval) -> String {
        let h = Int(s) / 3600
        let m = (Int(s) % 3600) / 60
        if h > 0 { return "\(h) ч \(m) мин" }
        return "\(m) мин"
    }

    static func shortDay(_ key: String) -> String {
        let f = DateFormatter()
        f.dateFormat = "yyyy-MM-dd"
        guard let d = f.date(from: key) else { return key }
        let out = DateFormatter()
        out.dateFormat = "d MMM"
        out.locale = Locale(identifier: "ru_RU")
        return out.string(from: d)
    }
}

/// О программе: суть, версия, разработчик, ссылка на исходник.
struct AboutView: View {
    var body: some View {
        ScrollView {
            VStack(spacing: 24) {
                // Иконка
                Image(systemName: "bolt.fill")
                    .font(.system(size: 64, weight: .bold))
                    .foregroundStyle(Color(hex: 0x17A05E))
                    .padding(.top, 32)

                Text("WSBridge")
                    .font(.title.weight(.bold))

                Text(versionString)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)

                // Суть — короткое саммари текущего README.
                VStack(alignment: .leading, spacing: 12) {
                    Text("WSBridge — локальный VPN-туннель для iOS. Приложение создаёт виртуальный интерфейс (TUN), встроенный стек lwIP терминирует TCP, и каждый поток переносится зашифрованным WebSocket до гейтвей-эндпоинта.")
                        .font(.body)
                        .foregroundStyle(.secondary)
                    Text("Эндпоинты выбираются каскадом (CDN edge → прямые IP → native) с персистентным реестром здоровья. DNS — DoT или DoH на выбор в приложении. Список эндпоинтов обновляется без пересборки.")
                        .font(.body)
                        .foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.horizontal, 24)

                Divider().padding(.horizontal, 24)

                // Ссылки — без блока «разработчик».
                VStack(alignment: .leading, spacing: 10) {
                    Link(destination: URL(string: "https://github.com/l1ratch/WSBridge-iOS")!) {
                        Label("Исходный код", systemImage: "chevron.left.forwardslash.chevron.right")
                    }
                    Link(destination: URL(string: "https://github.com/Flowseal/tg-ws-proxy")!) {
                        Label("Оригинал: tg-ws-proxy (Flowseal)", systemImage: "arrow.up.right.square")
                    }
                    Text("Лицензия MIT")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.horizontal, 24)

                Spacer(minLength: 40)
            }
        }
        .navigationTitle("О программе")
        .navigationBarTitleDisplayMode(.inline)
    }

    private var versionString: String {
        // 0.2.N — единый формат везде: N и есть номер сборки (WSB_BUILD).
        Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "?"
    }
}

/// Выбор DNS: только выбор + кнопка «Настройки DNS» внизу.
struct DNSView: View {
    @ObservedObject var tunnel: TunnelManager
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        Form {
            Section {
                Text("Изменения применятся при следующем включении туннеля.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            // Свитчер транспорта: DoT по умолчанию (прямой коннект к IP:853,
            // без бутстрап-резолва имени под туннелем), DoH — если хочется
            // маскировку под HTTPS.
            Section("Шифрование DNS") {
                Picker("Транспорт", selection: $tunnel.dnsModeRaw) {
                    ForEach(TunnelManager.DNSMode.allCases, id: \.rawValue) { mode in
                        Text(mode.shortTitle).tag(mode.rawValue)
                    }
                }
                .pickerStyle(.segmented)
                Text(tunnel.dnsMode.hint)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                DNSModeFallbackNote(tunnel: tunnel)
            }

            Section("DNS-серверы") {
                ForEach(tunnel.allDNS) { config in
                    Button {
                        tunnel.selectedDNSId = config.id
                    } label: {
                        HStack {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(config.name)
                                    .foregroundStyle(.primary)
                                Text("\(config.description) · \(config.transportsLabel)")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                            Spacer()
                            if tunnel.selectedDNSId == config.id {
                                Image(systemName: "checkmark.circle.fill")
                                    .foregroundStyle(.green)
                            }
                        }
                    }
                    .buttonStyle(.plain)
                }
            }

            Section {
                NavigationLink {
                    DNSManageView(tunnel: tunnel)
                } label: {
                    Label("Настройки DNS", systemImage: "gearshape")
                }
            }
        }
        .navigationTitle("DNS")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Button("Готово") { dismiss() }
            }
        }
    }
}

/// Если у выбранного сервера нет предпочитаемого транспорта — честно
/// говорим, что пойдёт запасной, а не делаем вид, что всё по свитчеру.
private struct DNSModeFallbackNote: View {
    @ObservedObject var tunnel: TunnelManager

    var body: some View {
        // Пустой список = «Системный»: туннель вообще не трогает DNS,
        // подсказка про транспорты была бы враньём.
        if !tunnel.activeDNSServers.isEmpty,
           tunnel.effectiveDNSMode != tunnel.dnsMode {
            Text(tunnel.effectiveDNSMode == nil
                 ? "У этого сервера нет ни DoT, ни DoH — запросы пойдут простым DNS (порт 53)."
                 : "У этого сервера нет \(tunnel.dnsMode.shortTitle) — будет использован \(tunnel.effectiveDNSMode!.shortTitle).")
                .font(.caption)
                .foregroundStyle(.orange)
        }
    }
}

/// Управление DNS: просмотр, добавление, редактирование, удаление.
struct DNSManageView: View {
    @ObservedObject var tunnel: TunnelManager
    @State private var showAdd = false
    @State private var editConfig: TunnelManager.DNSConfig?
    @State private var viewConfig: TunnelManager.DNSConfig?

    var body: some View {
        Form {
            Section("Пресеты") {
                ForEach(TunnelManager.dnsPresets) { config in
                    Button {
                        viewConfig = config
                    } label: {
                        HStack {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(config.name)
                                    .foregroundStyle(.primary)
                                Text("\(config.description) · \(config.transportsLabel)")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                            Spacer()
                            Image(systemName: "chevron.right")
                                .font(.footnote.weight(.semibold))
                                .foregroundStyle(.tertiary)
                        }
                    }
                    .buttonStyle(.plain)
                }
            }

            Section("Свои серверы") {
                ForEach(tunnel.customDNS) { config in
                    Button {
                        editConfig = config
                    } label: {
                        HStack {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(config.name)
                                    .foregroundStyle(.primary)
                                Text("\(config.description) · \(config.transportsLabel)")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                            Spacer()
                            Image(systemName: "chevron.right")
                                .font(.footnote.weight(.semibold))
                                .foregroundStyle(.tertiary)
                        }
                    }
                    .buttonStyle(.plain)
                }
                Button {
                    showAdd = true
                } label: {
                    Label("Добавить DNS", systemImage: "plus.circle")
                }
            }
        }
        .navigationTitle("Настройки DNS")
        .navigationBarTitleDisplayMode(.inline)
        .sheet(isPresented: $showAdd) {
            NavigationStack {
                DNSEditorView(tunnel: tunnel, config: nil)
            }
        }
        .sheet(item: $editConfig) { config in
            NavigationStack {
                DNSEditorView(tunnel: tunnel, config: config)
            }
        }
        .sheet(item: $viewConfig) { config in
            NavigationStack {
                DNSDetailView(config: config)
            }
        }
    }
}

/// Просмотр DNS-конфига (только чтение).
struct DNSDetailView: View {
    let config: TunnelManager.DNSConfig
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        Form {
            Section("Информация") {
                LabeledContent("Название", value: config.name)
                if !config.description.isEmpty {
                    LabeledContent("Описание", value: config.description)
                }
                LabeledContent("Транспорты", value: config.transportsLabel)
                if let site = config.site, let url = URL(string: site) {
                    Link(destination: url) {
                        Label("Сайт провайдера", systemImage: "safari")
                    }
                }
            }
            if !config.servers.isEmpty {
                Section("Серверы") {
                    ForEach(config.servers, id: \.self) { ip in
                        Text(ip)
                            .font(.system(.body, design: .monospaced))
                    }
                }
            }
            if let doh = config.dohURL {
                Section("DNS-over-HTTPS") {
                    Text(doh)
                        .font(.system(.caption, design: .monospaced))
                        .textSelection(.enabled)
                }
            }
            if let dot = config.dotHostname {
                Section("DNS-over-TLS") {
                    Text(dot)
                        .font(.system(.caption, design: .monospaced))
                        .textSelection(.enabled)
                }
            }
        }
        .navigationTitle(config.name)
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Button("Готово") { dismiss() }
            }
        }
    }
}

/// Конструктор / редактор DNS-конфига (только свои).
struct DNSEditorView: View {
    @ObservedObject var tunnel: TunnelManager
    let config: TunnelManager.DNSConfig?

    @State private var name = ""
    @State private var description = ""
    @State private var servers: [String] = []
    @State private var dohURL = ""
    @State private var dotHostname = ""
    /// Лимит описания: подписи короткие, разъезжаются по строкам иначе.
    private static let descriptionLimit = 60
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        Form {
            Section("Название") {
                TextField("Например: Мой DNS", text: $name)
                TextField("Описание (необязательно)", text: $description)
                    .onChange(of: description) { _, new in
                        if new.count > Self.descriptionLimit {
                            description = String(new.prefix(Self.descriptionLimit))
                        }
                    }
                Text("\(description.count)/\(Self.descriptionLimit)")
                    .font(.caption2)
                    .foregroundStyle(description.count >= Self.descriptionLimit ? .orange : .secondary)
            }
            Section("Серверы (IP)") {
                ForEach(servers.indices, id: \.self) { i in
                    HStack {
                        TextField("IP-адрес", text: Binding(
                            get: { servers[i] },
                            set: { servers[i] = $0 }
                        ))
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .keyboardType(.numbersAndPunctuation)
                        Button {
                            servers.remove(at: i)
                        } label: {
                            Image(systemName: "minus.circle.fill")
                                .foregroundStyle(.red)
                        }
                        .buttonStyle(.plain)
                    }
                }
                Button {
                    servers.append("")
                } label: {
                    Label("Добавить сервер", systemImage: "plus.circle")
                }
            }
            Section("DNS-over-TLS (обязательно)") {
                TextField("dns.example.com", text: $dotHostname)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                Text("Имя хоста сервера для SNI. Коннект идёт напрямую к IP:853 — резолв имени под туннелем не нужен, поэтому DoT самый надёжный вариант.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Section("DNS-over-HTTPS (по желанию)") {
                TextField("https://example.com/dns-query", text: $dohURL)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .keyboardType(.URL)
                Text("Нужен, только если хотите работать через DoH: порт 443, маскировка под обычный HTTPS.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            if dotHostname.trimmingCharacters(in: .whitespaces).isEmpty {
                Section {
                    Label("Укажите DoT-хост: свой DNS без TLS не принимается — незашифрованный резолв перехватывается провайдером.", systemImage: "exclamationmark.triangle")
                        .font(.caption)
                        .foregroundStyle(.orange)
                }
            }
            if config != nil {
                Section {
                    Button("Удалить DNS", role: .destructive) {
                        tunnel.customDNS.removeAll { $0.id == config?.id }
                        if tunnel.selectedDNSId == config?.id {
                            tunnel.selectedDNSId = "system"
                        }
                        dismiss()
                    }
                }
            }
        }
        .navigationTitle(config == nil ? "Новый DNS" : "Настройки DNS")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Button("Сохранить") {
                    save()
                }
                .disabled(name.isEmpty || servers.allSatisfy { $0.isEmpty }
                          || dotHostname.trimmingCharacters(in: .whitespaces).isEmpty)
            }
        }
        .onAppear {
            if let config {
                name = config.name
                description = config.description
                servers = config.servers
                dohURL = config.dohURL ?? ""
                dotHostname = config.dotHostname ?? ""
            }
        }
    }

    private func save() {
        let cleanServers = servers.map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
        let cleanDoh = dohURL.trimmingCharacters(in: .whitespaces)
        let cleanDot = dotHostname.trimmingCharacters(in: .whitespaces)
        if let config {
            if let idx = tunnel.customDNS.firstIndex(where: { $0.id == config.id }) {
                tunnel.customDNS[idx].name = name
                tunnel.customDNS[idx].description = description
                tunnel.customDNS[idx].servers = cleanServers
                tunnel.customDNS[idx].dohURL = cleanDoh.isEmpty ? nil : cleanDoh
                tunnel.customDNS[idx].dotHostname = cleanDot.isEmpty ? nil : cleanDot
            }
        } else {
            let newConfig = TunnelManager.DNSConfig(
                id: UUID().uuidString,
                name: name,
                description: description,
                servers: cleanServers,
                dohURL: cleanDoh.isEmpty ? nil : cleanDoh,
                dotHostname: cleanDot.isEmpty ? nil : cleanDot,
                isPreset: false,
                site: nil
            )
            tunnel.customDNS.append(newConfig)
            tunnel.selectedDNSId = newConfig.id
        }
        dismiss()
    }
}

extension View {
    @ViewBuilder
    func glassCapsule(interactive: Bool = false) -> some View {
        if #available(iOS 26.0, *) {
            self.glassEffect(interactive ? .regular.interactive() : .regular, in: .capsule)
        } else {
            self.background(.ultraThinMaterial, in: .capsule)
        }
    }
}

extension Color {
    init(hex: UInt32) {
        self.init(
            .sRGB,
            red: Double((hex >> 16) & 0xFF) / 255,
            green: Double((hex >> 8) & 0xFF) / 255,
            blue: Double(hex & 0xFF) / 255,
            opacity: 1
        )
    }
}

/// DNS-кнопка: iOS 26 — нативное стекло (.glass), ниже — .bordered.
struct DNSButtonStyle: ViewModifier {
    func body(content: Content) -> some View {
        if #available(iOS 26.0, *) {
            content.buttonStyle(.glass)
        } else {
            content.buttonStyle(.bordered)
        }
    }
}
