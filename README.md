# WSBridge

iOS Packet Tunnel Provider. Split tunnel: Telegram IPv4/TCP → WebSocket.
RU: [README.ru.md](README.ru.md) · Relay server: [relay/](relay/README.md)

## Data path

```
NEPacketTunnelProvider
  packetFlow.readPackets → lwIP (NO_SYS=1, single queue, IPv4)
  lwIP accept/recv       → TunnelSession
  TunnelSession          → WSClient (URLSessionWebSocketTask)
  WS frames              → endpoint
```

lwIP terminates TCP in-process; each flow becomes a WS frame stream.
Downstream frames are written back through lwIP → `packetFlow.writePackets`.
No IPv6 route is announced (`Tunnel/TelegramDCs.swift` `includedRoutes6` is
defined but unused): lwIP is IPv4-only.

## Routing

`NEIPv4Settings.includedRoutes`:

| CIDR | Source |
|---|---|
| `149.154.0.0/16` | `TelegramDCs.includedRoutes` |
| `91.108.0.0/16` | `TelegramDCs.includedRoutes` |
| `91.105.192.0/24` | `TelegramDCs.includedRoutes` |
| per-list `/24` | `providerConfiguration["routeCIDRs"]`, domain-proxy mode only |

`excludedRoutes`: `/32` per SOCKS5/HTTP proxy host, to prevent the proxy
socket from re-entering utun.

Interface: `198.18.0.2/32`, `tunnelRemoteAddress 198.18.0.1`, MTU 1500.
UDP/ICMP inside routed ranges: dropped. UDP:443 → ICMP port-unreachable.

## Transport modes

Selected in `PacketTunnelProvider.handleAccept`, in order:

| Condition | Mode | Entry point |
|---|---|---|
| `proxyEndpoint != nil && isSNIInterceptCandidate(ip)` | domain proxy (SOCKS5/HTTP CONNECT) | `TunnelSession.startProxy` |
| `relayHost != nil && relayKey != nil` | WSBridge Relay | `TunnelSession.startRelay` → `WSClient.connectBridge` |
| `workerDomain != nil` | CF Worker pipe | `TunnelSession.startPipe` → `WSClient.connectPipe` |
| otherwise | kws cascade | `TunnelSession.startWS` → `WSClient.connect` |

`isSNIInterceptCandidate` returns false for `149.154/16` and `91.108/16`,
so Telegram always reaches the WS branches.

### kws cascade

`WSClient.connect` builds `[Endpoint]` = `(host, hostHeader, plain)`:

```
1..6    ws://kws{dc}.{base}:80/apiws        (plain, 6 rotated fronts)
7..12   wss://kws{dc}.{base}/apiws          (same 6 fronts, TLS)
13..16  wss://{gatewayIP}/apiws             Host: kws{dc}[-1].web.telegram.org
17      wss://kws{dc}[-1].web.telegram.org/apiws
```

`gatewayIPs`: `149.154.167.220`, `149.154.175.205`, `149.154.167.99`,
`149.154.174.100`. Path `/apiws_test` when `dcId >= 10000`.
Media (`dc_idx < 0`) uses `kws{dc}-1`.

Per-attempt state: 10 s timer, gated on `GotData` (any successful `receive`),
not on `countOfBytesSent/Received` — those stay 0 for WS frames.
`initFrame` (64 B) is sent once per endpoint immediately after `resume()`.
Health key is `host` or `ws80:host`; `markDead` → 600 s runtime ban +
`FrontHealthRegistry.recordFailure`.

`FrontHealthRegistry` (UserDefaults): excludes endpoints with ≥3 consecutive
failures and no success in 24 h; orders by `lastSuccess` desc; evicts entries
dead >7 d and absent from the upstream list.

### WSBridge Relay

`wss://{relayHost}/` — see [relay/README.md](relay/README.md) for the wire
protocol. Client sends `{"v":1,"token":…}` as the first frame, then the raw
MTProto stream; the server parses init and frames packets. No client-side
splitter in this mode. Key stored in Keychain (`kSecClassGenericPassword`,
service `WSBridge`, account `relayKey`, `AccessibleAfterFirstUnlock`).
8 s watchdog gated on `firstRecv`.

### CF Worker pipe

`wss://{workerDomain}/apiws?dst={IPv4}` — raw byte pipe, worker dials
`dst:443`. `host:port` form is not supported (legacy raw-TCP removed).
`sendPing` → `ws_ping`; 7 s watchdog gated on `firstRecv || pingOK`.

### Domain proxy

`routeCIDRs` are `/24` blocks resolved from enabled domain lists in the app
process. `TLSSNI.extract` reads ClientHello (buffered up to 2048 B);
match → `ProxyClient.connect` (SOCKS5 or HTTP CONNECT by name),
no match → `DirectStream` (`NWConnection`, bound to physical interface).

## MTProto handling

`InitParser` (64 B obfuscated2): `key = init[8:40]`, `iv = init[40:56]`,
AES-256-CTR decrypt → `proto_tag` at `[56:60]` LE, `dc_idx` at `[60:62]` `<h`.
Valid tags: `0xEFEFEFEF` abridged, `0xEEEEEEEE` intermediate,
`0xDDDDDDDD` padded. `dcId = abs(dc_idx)`, `isMedia = dc_idx < 0`,
`isTestDC = dcId >= 10000`.

`MsgSplitter`: AES-CTR fast-forward 64, decrypts length prefixes only,
emits slices of the original ciphertext. Payload is never re-encrypted;
the client's own init is forwarded verbatim (kws cascade mode).

## Front list update

`CFDomains.builtinBases` — 20 immutable entries, always first.
`TunnelManager.updateFronts` fetches origin + 2 CDN mirrors (10 s timeout,
cache bypass), decodes with the upstream shift cipher, validates format and
DNS resolution; lists with <3 resolving entries are discarded. Merged into
`frontBases`, passed via `providerConfiguration["fronts"]`. Rate limit 30 min,
runs after tunnel start.

## DNS

`NEDNSSettings` is set only when a user preset is active; default is system
resolver (`dnsSettings = nil`). Transports: DoT (`NEDNSOverTLSSettings`,
`serverName` required, connects to IP with SNI), DoH
(`NEDNSOverHTTPSSettings`), plain UDP. DoH/FakeIP routing is not implemented
— see [docs/DoH-Routing.ru.md](docs/DoH-Routing.ru.md) for the closed concept.

## Journal

`EventLog`: per-run file `Library/Logs/run-<yyyyMMdd-HHmmss>.log`, append per
line, 20-file rotation. `JournalServer`: loopback TCP `127.0.0.1:51001`,
commands `journal` / `list` / `file:<name>`. Darwin notifications
`com.l1ratch.WSBridge.<event>` for UI counters.

Key markers: `cfg:relay=`, `cfg:worker=`, `cfg:routeB`, `accept:c<N>`,
`init:conn<N>:DC<n>`, `ws_try:`, `ws_up`, `ws_recv:c<N>:n<K>:<bytes>`,
`ws_closed:<code>:<reason>`, `relayws_try:`, `relayws_auth_sent`,
`relayws_slow`, `io:in/out/wd/wf/up/rx/sent/mem/conns`.

## Build

```sh
xcodegen generate
xcodebuild -project WSBridge.xcodeproj -scheme WSBridge -sdk iphoneos build
```

Targets: `WSBridge` (app), `WSBridgeTunnel` (packet-tunnel-provider),
`WSBridgeLive` (widgetkit-extension). iOS 17.0+, Swift 5.9.
Tunnel ATS: `NSExceptionDomains` for the 20 front bases
(`NSExceptionAllowsInsecureHTTPLoads`, `NSIncludesSubdomains`) — required for
`ws://…:80`. No global `NSAllowsArbitraryLoads`.

Version = `$(WSB_VERSION).$(WSB_BUILD)` from `project.yml`;
`CFBundleVersion = $(WSB_BUILD)`. CI publishes unsigned IPA to the single
`preview` prerelease + gh-pages manifest on every push to `main`, then bumps
`WSB_BUILD`. Tag `vX.Y.N` triggers `release.yml`; it rejects a tag that
differs from the composed version.

## License

MIT © 2026 l1ratch. Portable logic adapted from
[Flowseal/tg-ws-proxy](https://github.com/Flowseal/tg-ws-proxy) (MIT).
lwIP: BSD (`Tunnel/lwip/COPYING`).
