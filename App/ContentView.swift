import SwiftUI
import NetworkExtension
import UIKit

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
                Ellipse()
                    .fill(topWashColor)
                    .frame(width: 560, height: 520)
                    .blur(radius: 110)
                    .opacity(colorScheme == .dark ? 0.55 : 0.45)
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

    /// Цвет верхнего свечения: живой изумруд при работе, глубокий индиго в покое.
    private var topWashColor: Color {
        tunnel.status == .connected ? Color(hex: 0x17A05E) : Color(hex: 0x1E3A6E)
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
                    Button {
                        Task { await tunnel.updateFronts() }
                    } label: {
                        HStack {
                            Label("Обновить список фронтов", systemImage: "arrow.triangle.2.circlepath")
                            Spacer()
                            if let msg = tunnel.frontsUpdateMessage {
                                Text(msg)
                                    .font(.caption2)
                                    .foregroundStyle(.secondary)
                                    .lineLimit(1)
                            }
                        }
                    }
                    if let updated = tunnel.frontsUpdatedAt {
                        Text("Список обновлён: \(updated.formatted(date: .abbreviated, time: .shortened))")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    Text("Фронты — входы Cloudflare к серверам Telegram. Апстрим периодически меняет их; обновление подхватится при следующем включении туннеля.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Section("Информация") {
                    NavigationLink {
                        AboutView()
                    } label: {
                        Label("О программе", systemImage: "info.circle")
                    }
                }

                Section {
                    HStack(spacing: 24) {
                        Link(destination: URL(string: "https://github.com/l1ratch/WSBridge-iOS")!) {
                            Image(systemName: "chevron.left.forwardslash.chevron.right")
                                .font(.title2)
                        }
                        Link(destination: URL(string: "https://github.com/Flowseal/tg-ws-proxy")!) {
                            Image(systemName: "arrow.up.right.square")
                                .font(.title2)
                        }
                    }
                    .frame(maxWidth: .infinity)
                    .foregroundStyle(.secondary)
                }
                .listRowBackground(Color.clear)
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

/// CF Worker: настройка собственного worker'а или реле.
struct WorkerView: View {
    @ObservedObject var tunnel: TunnelManager

    var body: some View {
        Form {
            Section("CF Worker или реле") {
                TextField("worker.example.com или ip:port", text: $tunnel.workerDomain)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .disabled(tunnel.status == .connected)
                Text(workerHint)
                    .font(.caption)
                    .foregroundStyle(.secondary)
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

    var body: some View {
        ScrollView {
            Text(tunnel.stats ?? "Нет данных — туннель не запущен")
                .font(.system(.footnote, design: .monospaced))
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding()
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
                .padding(.bottom)
            }
        }
        .navigationTitle("Статистика")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Button("Обновить") { tunnel.fetchStats() }
            }
        }
        .onAppear { tunnel.fetchStats() }
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

                // Суть
                VStack(alignment: .leading, spacing: 12) {
                    Text("Что это")
                        .font(.headline)
                    Text("WSBridge — VPN-туннель, работающий локально на вашем устройстве. Он перехватывает трафик Telegram и перенаправляет его через WebSocket-соединение к серверам Telegram в обход устаревшего сетевого оборудования. Настройка в самом Telegram не требуется.")
                        .font(.body)
                        .foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.horizontal, 24)

                Divider().padding(.horizontal, 24)

                // Разработчик
                VStack(alignment: .leading, spacing: 10) {
                    Text("Разработчик")
                        .font(.headline)
                    LabeledContent("Автор", value: "l1ratch")
                    Link(destination: URL(string: "https://github.com/l1ratch/WSBridge-iOS")!) {
                        Label("Исходный код WSBridge", systemImage: "chevron.left.forwardslash.chevron.right")
                    }
                    Link(destination: URL(string: "https://github.com/Flowseal/tg-ws-proxy")!) {
                        Label("Оригинал: tg-ws-proxy (Flowseal)", systemImage: "arrow.up.right.square")
                    }
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
