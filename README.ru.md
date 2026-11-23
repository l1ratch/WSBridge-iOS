# WSBridge

iOS Packet Tunnel Provider. Split-туннель: Telegram IPv4/TCP → WebSocket.
EN: [README.md](README.md) · Сервер-релей: [relay/](relay/README.md)

## Путь данных

```
NEPacketTunnelProvider
  packetFlow.readPackets → lwIP (NO_SYS=1, одна очередь, IPv4)
  lwIP accept/recv       → TunnelSession
  TunnelSession          → WSClient (URLSessionWebSocketTask)
  WS-кадры               → эндпоинт
```

lwIP терминирует TCP в процессе; каждый поток становится потоком WS-кадров.
Обратные кадры пишутся через lwIP → `packetFlow.writePackets`.
IPv6-маршрут не анонсируется (`includedRoutes6` определён, но не используется):
lwIP только IPv4.

## Маршрутизация

`NEIPv4Settings.includedRoutes`:

| CIDR | Источник |
|---|---|
| `149.154.0.0/16` | `TelegramDCs.includedRoutes` |
| `91.108.0.0/16` | `TelegramDCs.includedRoutes` |
| `91.105.192.0/24` | `TelegramDCs.includedRoutes` |
| `/24` из списков | `providerConfiguration["routeCIDRs"]`, только режим прокси-доменов |

`excludedRoutes`: `/32` на каждый хост SOCKS5/HTTP-прокси — чтобы сокет
прокси не уехал обратно в utun.

Интерфейс: `198.18.0.2/32`, `tunnelRemoteAddress 198.18.0.1`, MTU 1500.
UDP/ICMP внутри маршрутизируемых диапазонов отбрасываются.
UDP:443 → ICMP port-unreachable.

## Режимы транспорта

Выбор в `PacketTunnelProvider.handleAccept`, по порядку:

| Условие | Режим | Точка входа |
|---|---|---|
| `proxyEndpoint != nil && isSNIInterceptCandidate(ip)` | прокси-домены (SOCKS5/HTTP CONNECT) | `TunnelSession.startProxy` |
| `relayHost != nil && relayKey != nil` | WSBridge Relay | `TunnelSession.startRelay` → `WSClient.connectBridge` |
| `workerDomain != nil` | CF Worker pipe | `TunnelSession.startPipe` → `WSClient.connectPipe` |
| иначе | kws-каскад | `TunnelSession.startWS` → `WSClient.connect` |

`isSNIInterceptCandidate` возвращает false для `149.154/16` и `91.108/16`,
поэтому Telegram всегда попадает в WS-ветки.

### kws-каскад

`WSClient.connect` строит `[Endpoint]` = `(host, hostHeader, plain)`:

```
1..6    ws://kws{dc}.{base}:80/apiws        (plain, 6 ротированных фронтов)
7..12   wss://kws{dc}.{base}/apiws          (те же 6 фронтов, TLS)
13..16  wss://{gatewayIP}/apiws             Host: kws{dc}[-1].web.telegram.org
17      wss://kws{dc}[-1].web.telegram.org/apiws
```

`gatewayIPs`: `149.154.167.220`, `149.154.175.205`, `149.154.167.99`,
`149.154.174.100`. Путь `/apiws_test` при `dcId >= 10000`.
Media (`dc_idx < 0`) использует `kws{dc}-1`.

Состояние попытки: таймер 10 с, гасится по `GotData` (любой успешный
`receive`), а не по `countOfBytesSent/Received` — для WS-кадров они остаются 0.
`initFrame` (64 B) отправляется один раз на эндпоинт сразу после `resume()`.
Ключ здоровья — `host` или `ws80:host`; `markDead` → бан 600 с +
`FrontHealthRegistry.recordFailure`.

`FrontHealthRegistry` (UserDefaults): исключает эндпоинты с ≥3 фейлами подряд
и без успеха за 24 ч; сортирует по `lastSuccess` desc; удаляет записи,
мёртвые >7 суток и отсутствующие в апстрим-списке.

### WSBridge Relay

`wss://{relayHost}/` — протокол в [relay/README.md](relay/README.md).
Клиент шлёт `{"v":1,"token":…}` первым кадром, затем сырой MTProto-поток;
init парсит и кадрирует сервер. Клиентский сплиттер в этом режиме не используется.
Ключ в Keychain (`kSecClassGenericPassword`, service `WSBridge`,
account `relayKey`, `AccessibleAfterFirstUnlock`). Watchdog 8 с по `firstRecv`.

### CF Worker pipe

`wss://{workerDomain}/apiws?dst={IPv4}` — сырая труба байтов, воркер диалит
`dst:443`. Форма `host:port` не поддерживается (legacy raw-TCP удалён).
`sendPing` → `ws_ping`; watchdog 7 с по `firstRecv || pingOK`.

### Прокси-домены

`routeCIDRs` — блоки `/24`, зарезолвленные из включённых списков доменов
в процессе приложения. `TLSSNI.extract` читает ClientHello (буфер до 2048 B);
совпало → `ProxyClient.connect` (SOCKS5 или HTTP CONNECT по имени),
не совпало → `DirectStream` (`NWConnection`, привязка к физическому интерфейсу).

## Обработка MTProto

`InitParser` (64 B obfuscated2): `key = init[8:40]`, `iv = init[40:56]`,
AES-256-CTR decrypt → `proto_tag` в `[56:60]` LE, `dc_idx` в `[60:62]` `<h`.
Валидные теги: `0xEFEFEFEF` abridged, `0xEEEEEEEE` intermediate,
`0xDDDDDDDD` padded. `dcId = abs(dc_idx)`, `isMedia = dc_idx < 0`,
`isTestDC = dcId >= 10000`.

`MsgSplitter`: AES-CTR fast-forward 64, расшифровывает только префиксы длин,
отдаёт срезы исходного шифртекста. Payload не перешифровывается;
init клиента уходит как есть (режим kws-каскада).

## Обновление списка фронтов

`CFDomains.builtinBases` — 20 неизменяемых записей, всегда первыми.
`TunnelManager.updateFronts` качает origin + 2 CDN-зеркала (таймаут 10 с,
обход кэша), декодирует сдвиговым шифром апстрима, валидирует формат и
DNS-резолв; списки с <3 резолвящимися записями отбрасываются. Мердж в
`frontBases`, передача через `providerConfiguration["fronts"]`.
Лимит 30 мин, выполняется после старта туннеля.

## DNS

`NEDNSSettings` выставляется только при активном пользовательском пресете;
по умолчанию системный резолвер (`dnsSettings = nil`). Транспорты: DoT
(`NEDNSOverTLSSettings`, `serverName` обязателен, коннект к IP с SNI), DoH
(`NEDNSOverHTTPSSettings`), plain UDP. DoH/FakeIP-роутинг не реализован —
закрытая концепция в [docs/DoH-Routing.ru.md](docs/DoH-Routing.ru.md).

## Журнал

`EventLog`: файл на прогон `Library/Logs/run-<yyyyMMdd-HHmmss>.log`, дозапись
построчно, ротация 20 файлов. `JournalServer`: loopback TCP `127.0.0.1:51001`,
команды `journal` / `list` / `file:<name>`. Darwin-уведомления
`com.l1ratch.WSBridge.<event>` для счётчиков UI.

Ключевые маркеры: `cfg:relay=`, `cfg:worker=`, `cfg:routeB`, `accept:c<N>`,
`init:conn<N>:DC<n>`, `ws_try:`, `ws_up`, `ws_recv:c<N>:n<K>:<bytes>`,
`ws_closed:<code>:<reason>`, `relayws_try:`, `relayws_auth_sent`,
`relayws_slow`, `io:in/out/wd/wf/up/rx/sent/mem/conns`.

## Сборка

```sh
xcodegen generate
xcodebuild -project WSBridge.xcodeproj -scheme WSBridge -sdk iphoneos build
```

Таргеты: `WSBridge` (app), `WSBridgeTunnel` (packet-tunnel-provider),
`WSBridgeLive` (widgetkit-extension). iOS 17.0+, Swift 5.9.
ATS расширения: `NSExceptionDomains` на 20 базовых доменов фронтов
(`NSExceptionAllowsInsecureHTTPLoads`, `NSIncludesSubdomains`) — нужно для
`ws://…:80`. Глобального `NSAllowsArbitraryLoads` нет.

Версия = `$(WSB_VERSION).$(WSB_BUILD)` из `project.yml`;
`CFBundleVersion = $(WSB_BUILD)`. CI публикует unsigned IPA в единственный
prerelease `preview` + манифест gh-pages на каждый пуш в `main`, затем
поднимает `WSB_BUILD`. Тег `vX.Y.N` запускает `release.yml`; он отклоняет тег,
не совпадающий со склеенной версией.

## Лицензия

MIT © 2026 l1ratch. Портируемая логика —
[Flowseal/tg-ws-proxy](https://github.com/Flowseal/tg-ws-proxy) (MIT).
lwIP: BSD (`Tunnel/lwip/COPYING`).
