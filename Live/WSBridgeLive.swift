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
            HStack(spacing: 14) {
                ZStack {
                    Circle().fill(Color.green.opacity(0.18))
                    Image(systemName: "bolt.fill")
                        .foregroundStyle(.green)
                        .font(.headline)
                }
                .frame(width: 40, height: 40)
                VStack(alignment: .leading, spacing: 2) {
                    Text(context.state.phase == .on ? "Туннель активен" : "Туннель стартует")
                        .font(.headline)
                    Text("Начало в \(context.state.startDate.formatted(date: .omit, time: .shortened))")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                // Системный тикающий таймер: рендерит ОС, процессы не будим.
                Text(timerInterval: context.state.startDate...Date.distantFuture, countsDown: false)
                    .font(.system(.title3, design: .monospaced).weight(.semibold))
                    .monospacedDigit()
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 12)
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
