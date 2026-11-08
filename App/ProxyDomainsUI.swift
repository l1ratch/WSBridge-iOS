import SwiftUI

/// Прокси-домены: нативный список списков (тумблеры вкл/выкл, Edit-
/// режим с зелёным плюсом и красным минусом — как в системных
/// настройках) + управление прокси (добавление, тест, выбор/автовыбор).
struct ProxyDomainsView: View {
    @ObservedObject var tunnel: TunnelManager

    var body: some View {
        Form {
            Section {
                Text("Включённые списки: их домены LRDNS направляет через прокси. Остальные домены работают как обычно.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Section("Списки") {
                ForEach(tunnel.allProxyLists) { list in
                    Toggle(isOn: Binding(
                        get: { tunnel.enabledProxyListIds.contains(list.id) },
                        set: { on in
                            if on {
                                tunnel.enabledProxyListIds.append(list.id)
                            } else {
                                tunnel.enabledProxyListIds.removeAll { $0 == list.id }
                            }
                        }
                    )) {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(list.name)
                            if !list.isPreset {
                                Text(list.url)
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                                    .lineLimit(1)
                                    .truncationMode(.middle)
                            }
                        }
                    }
                    .disabled(tunnel.status == .connected || tunnel.status == .connecting || tunnel.status == .reasserting)
                }
                .onDelete { offsets in
                    // Удалять можно только свои (пресеты не двигаются).
                    let customs = tunnel.customProxyLists
                    for off in offsets {
                        guard off < tunnel.allProxyLists.count else { continue }
                        let list = tunnel.allProxyLists[off]
                        if !list.isPreset {
                            tunnel.customProxyLists.removeAll { $0.id == list.id }
                            tunnel.enabledProxyListIds.removeAll { $0 == list.id }
                        }
                    }
                    _ = customs
                }
                Button {
                    showAddList = true
                } label: {
                    Label("Добавить список", systemImage: "plus.circle")
                }
                .disabled(tunnel.status == .connected || tunnel.status == .connecting || tunnel.status == .reasserting)
            }

            Section("Прокси") {
                ForEach(tunnel.proxyURLs.indices, id: \.self) { idx in
                    Button {
                        tunnel.selectedProxyIndex = idx
                    } label: {
                        HStack {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(ProxyEndpoint.display(of: tunnel.proxyURLs[idx]))
                                    .font(.callout.monospaced())
                                    .foregroundStyle(.primary)
                                if let ms = tunnel.proxyProbe[tunnel.proxyURLs[idx]] {
                                    Text("задержка \(ms ?? -1) мс")
                                        .font(.caption)
                                        .foregroundStyle(ms == nil ? .red : (ms! > 1000 ? .orange : .green))
                                }
                            }
                            Spacer()
                            if tunnel.selectedProxyIndex == idx {
                                Image(systemName: "checkmark.circle.fill")
                                    .foregroundStyle(.green)
                            }
                        }
                    }
                    .buttonStyle(.plain)
                }
                Button {
                    selectedProxyIndexToAuto()
                } label: {
                    HStack {
                        Text("Автовыбор")
                        Spacer()
                        if tunnel.selectedProxyIndex < 0 {
                            Image(systemName: "checkmark.circle.fill")
                                .foregroundStyle(.green)
                        }
                    }
                }
                .buttonStyle(.plain)
                Button {
                    Task { await tunnel.probeProxies() }
                } label: {
                    HStack {
                        Label("Протестировать прокси", systemImage: "bolt.horizontal")
                        if tunnel.proxyProbeRunning {
                            Spacer()
                            ProgressView()
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
                .disabled(tunnel.proxyProbeRunning || tunnel.proxyURLs.isEmpty)
                Button {
                    showAddProxy = true
                } label: {
                    Label("Добавить прокси", systemImage: "plus.circle")
                }
                .disabled(tunnel.status == .connected || tunnel.status == .connecting || tunnel.status == .reasserting)
                if tunnel.proxyURLs.isEmpty {
                    Text("Формат: socks5://host:port или socks5://user:pass@host:port, http:// аналогично.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }

            Section {
                Text("Прокси-домены работают только при выбранном «Локальный (LRDNS)» в выборщике DNS. Изменения применятся при следующем включении туннеля.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .navigationTitle("Прокси-домены")
        .navigationBarTitleDisplayMode(.inline)
        .sheet(isPresented: $showAddList) {
            NavigationStack {
                ProxyListEditorView(tunnel: tunnel)
            }
        }
        .sheet(isPresented: $showAddProxy) {
            NavigationStack {
                ProxyAddView(tunnel: tunnel)
            }
        }
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                EditButton()
            }
        }
    }

    @State private var showAddList = false
    @State private var showAddProxy = false

    private func selectedProxyIndexToAuto() {
        tunnel.selectedProxyIndex = -1
    }
}

/// Добавление своего списка прокси-доменов (URL на файл домен-в-строке).
struct ProxyListEditorView: View {
    @ObservedObject var tunnel: TunnelManager
    @Environment(\.dismiss) private var dismiss
    @State private var name = ""
    @State private var url = ""

    var body: some View {
        Form {
            Section("Название") {
                TextField("Например: Мой список", text: $name)
            }
            Section("URL списка") {
                TextField("https://…/list.lst", text: $url)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .keyboardType(.URL)
                Text("Формат — домены по одному в строке, # — комментарий.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Section {
                Button("Сохранить") {
                    let cleanName = name.trimmingCharacters(in: .whitespaces)
                    let cleanURL = url.trimmingCharacters(in: .whitespaces)
                    guard !cleanName.isEmpty,
                          URL(string: cleanURL)?.scheme?.hasPrefix("http") == true else { return }
                    let list = TunnelManager.ProxyDomainList(
                        id: "custom-\(UUID().uuidString.prefix(8))",
                        name: cleanName, url: cleanURL, isPreset: false)
                    tunnel.customProxyLists.append(list)
                    tunnel.enabledProxyListIds.append(list.id)
                    dismiss()
                }
                .disabled(name.trimmingCharacters(in: .whitespaces).isEmpty ||
                          URL(string: url.trimmingCharacters(in: .whitespaces))?.scheme?.hasPrefix("http") != true)
            }
        }
        .navigationTitle("Новый список")
        .navigationBarTitleDisplayMode(.inline)
    }
}

/// Добавление прокси (socks5/http URL).
struct ProxyAddView: View {
    @ObservedObject var tunnel: TunnelManager
    @Environment(\.dismiss) private var dismiss
    @State private var raw = ""

    var body: some View {
        Form {
            Section("Прокси") {
                TextField("socks5://user:pass@host:port", text: $raw)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .keyboardType(.URL)
                    .font(.callout.monospaced())
                if !raw.isEmpty && ProxyEndpoint.parse(raw) == nil {
                    Text("Не похоже на прокси: ожидается socks5://… или http://…")
                        .font(.caption)
                        .foregroundStyle(.orange)
                }
            }
            Section {
                Button("Сохранить") {
                    let clean = raw.trimmingCharacters(in: .whitespaces)
                    guard ProxyEndpoint.parse(clean) != nil else { return }
                    tunnel.proxyURLs.append(clean)
                    dismiss()
                }
                .disabled(ProxyEndpoint.parse(raw.trimmingCharacters(in: .whitespaces)) == nil)
            }
        }
        .navigationTitle("Новый прокси")
        .navigationBarTitleDisplayMode(.inline)
    }
}

extension ProxyEndpoint {
    /// Безопасная подпись для UI (по сырой строке).
    static func display(of raw: String) -> String {
        parse(raw)?.display ?? raw
    }
}
