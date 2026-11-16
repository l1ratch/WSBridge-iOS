import Foundation

/// IPv4-утилиты для маршрутов и excludedRoutes.
enum IPv4Addr {
    static func parse(_ str: String) -> UInt32? {
        let parts = str.split(separator: ".")
        guard parts.count == 4 else { return nil }
        var v: UInt32 = 0
        for p in parts {
            guard let octet = UInt32(p), octet <= 255 else { return nil }
            v = (v << 8) | octet
        }
        return v
    }

    static func bytes(_ v: UInt32) -> [UInt8] {
        [UInt8((v >> 24) & 0xFF), UInt8((v >> 16) & 0xFF),
         UInt8((v >> 8) & 0xFF), UInt8(v & 0xFF)]
    }

    static func dotted(_ v: UInt32) -> String {
        "\(Int((v >> 24) & 0xFF)).\(Int((v >> 16) & 0xFF)).\(Int((v >> 8) & 0xFF)).\(Int(v & 0xFF))"
    }
}
