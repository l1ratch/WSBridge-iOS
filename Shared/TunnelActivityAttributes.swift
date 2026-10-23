import ActivityKit
import Foundation

/// Атрибуты Live Activity «туннель активен». Статичной части нет — всё
/// динамическое в ContentState. Файл лежит в Shared/ и включён в оба
/// таргета: приложение стартует/гасит активность, виджет-расширение рисует.
///
/// ponytail: таймер аптайма рисует СИСТЕМА (Text(timerInterval:)) — нам не
/// нужно будить ни один процесс, чтобы цифры тикали. Батарейно бесплатно.
struct TunnelActivityAttributes: ActivityAttributes {
    enum Phase: String, Codable {
        case starting
        case on
    }

    struct ContentState: Codable, Hashable {
        var phase: Phase
        var startDate: Date
    }
}
