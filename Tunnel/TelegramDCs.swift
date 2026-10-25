import NetworkExtension

enum TelegramDCs {
    // ponytail: полные диапазоны Telegram вместо /32 — Telegram может ходить
    // на любой IP из этих подсетей, а не только на известные DC-адреса.
    // IPv4: 149.154.0.0/16 + 91.108.0.0/16 + 91.105.192.0/24
    // IPv6: 2001:b28:f23d::/48

    static var includedRoutes: [NEIPv4Route] {
        [
            NEIPv4Route(destinationAddress: "149.154.0.0", subnetMask: "255.255.0.0"),
            NEIPv4Route(destinationAddress: "91.108.0.0", subnetMask: "255.255.0.0"),
            NEIPv4Route(destinationAddress: "91.105.192.0", subnetMask: "255.255.255.0"),
        ]
    }

    static var includedRoutes6: [NEIPv6Route] {
        [
            NEIPv6Route(destinationAddress: "2001:b28:f23d::", networkPrefixLength: 48),
        ]
    }
}
