import SwiftUI
import WidgetKit
import ActivityKit

/// Бандл только с Live Activity: домашнего виджета нет, в галерее не светимся.
@main
struct WSBridgeLiveBundle: WidgetBundle {
    var body: some Widget {
        TunnelLiveActivity()
    }
}

struct TunnelLiveActivity: Widget {
    var body: some WidgetConfiguration {
        ActivityConfiguration(for: TunnelActivityAttributes.self) { context in
            // Локскрин / StandBy: молния, статус и живой таймер аптайма.
            HStack(spacing: 10) {
                ZStack {
                    Circle().fill(LinearGradient(
                        colors: [Color(wsbHex: 0x17A05E), Color(wsbHex: 0x0E7A43)],
                        startPoint: .top, endPoint: .bottom))
                    Image(systemName: "bolt.fill")
                        .foregroundStyle(.white)
                        .font(.subheadline.weight(.semibold))
                }
                .frame(width: 36, height: 36)
                // Компоновка без frame(maxWidth:)/fixedSize (в 102 они дали
                // пустую карточку). Место для заголовка освобождаем
                // размерами: болт 36, таймер .body, отступы уже — иначе
                // «Туннель активен» обрезается (баг 103).
                VStack(alignment: .leading, spacing: 2) {
                    Text(context.state.phase == .on ? "Туннель активен" : "Туннель стартует")
                        .font(.subheadline.weight(.semibold))
                        .foregroundStyle(.white)
                        .lineLimit(1)
                    Text("Начало в \(context.state.startDate.formatted(date: .omitted, time: .shortened))")
                        .font(.caption)
                        .foregroundStyle(.white.opacity(0.6))
                        .lineLimit(1)
                }
                Spacer(minLength: 6)
                VStack(alignment: .trailing, spacing: 2) {
                    Text(timerInterval: context.state.startDate...Date.distantFuture, countsDown: false)
                        .font(.system(.body, design: .monospaced).weight(.bold))
                        .foregroundStyle(.white)
                        .monospacedDigit()
                    Text("аптайм")
                        .font(.caption2)
                        .foregroundStyle(.white.opacity(0.55))
                }
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 12)
            // Фон контента: свой градиент поверх системной подложки
            // (activityBackgroundTint умеет только ровный цвет, а
            // containerBackground на локскрине игнорируется). База —
            // navy→indigo, сверху зелёное свечение из правого верха.
            .background {
                ZStack {
                    LinearGradient(
                        colors: [Color(wsbHex: 0x0D1526), Color(wsbHex: 0x1E3A6E)],
                        startPoint: .topLeading, endPoint: .bottomTrailing)
                    RadialGradient(
                        colors: [Color(wsbHex: 0x17A05E).opacity(0.35), .clear],
                        center: .topTrailing, startRadius: 4, endRadius: 180)
                }
            }
            .activityBackgroundTint(.clear)
        } dynamicIsland: { context in
            DynamicIsland {
                DynamicIslandExpandedRegion(.leading) {
                    Label("WSBridge", systemImage: "bolt.fill")
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(.green)
                }
                DynamicIslandExpandedRegion(.center) {
                    Text(timerInterval: context.state.startDate...Date.distantFuture, countsDown: false)
                        .monospacedDigit()
                        .font(.caption.weight(.semibold))
                }
                DynamicIslandExpandedRegion(.trailing) {
                    Text(context.state.phase == .on ? "активен" : "старт")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
            } compactLeading: {
                Image(systemName: "bolt.fill")
                    .foregroundStyle(.green)
            } compactTrailing: {
                Text(timerInterval: context.state.startDate...Date.distantFuture, countsDown: false)
                    .monospacedDigit()
                    .font(.caption2.weight(.semibold))
                    .frame(width: 50)
            } minimal: {
                Image(systemName: "bolt.fill")
                    .foregroundStyle(.green)
            }
        }
    }
}

/// Локальный hex-цвет: app-таргетный Color(hex:) в расширение не доезжает,
/// а общий тащить нельзя — будет дубликат в app-модуле (Shared уже в обоих).
private extension Color {
    init(wsbHex: UInt32) {
        self.init(
            .sRGB,
            red: Double((wsbHex >> 16) & 0xFF) / 255,
            green: Double((wsbHex >> 8) & 0xFF) / 255,
            blue: Double(wsbHex & 0xFF) / 255,
            opacity: 1
        )
    }
}
