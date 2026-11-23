# WSBridge Relay

WS-мост: iOS (IPv4) → VPS → `kws{dc}.web.telegram.org` (IPv6) → Telegram DC.
IPv6 требуется только на VPS. Клиент: [../README.ru.md](../README.ru.md).

```
iPhone ──wss──→ nginx:443 ──http──→ relay:2087 ──tls──→ [kws IPv6]:443
```

## Протокол

```
C→S  GET / HTTP/1.1  Upgrade: websocket  Sec-WebSocket-Version: 13
S→C  101 Switching Protocols                      (до проверки ключа)
C→S  text   {"v":1,"token":"<key>"}
S→C  text   {"ok":true}  |  close 1008
C→S  binary <64B obfuscated2 init>[+ первые MTProto-пакеты]
S→C  binary <MTProto payload>
```

Путь любой (`/`, `/ws`, `/bridge`) — `accept_ws` его не проверяет.
Клиент шлёт `/`.

Кадрирование по RFC 6455: клиент→сервер masked, сервер→клиент unmasked.
`WSConn.mask_outgoing`: `False` для стороны телефона, `True` для kws.
Нарушение → iOS закрывает соединение с `closeCode 0` (protocol error).

`WSConn.__init__` вызывает `set_sock_opts`: `TCP_NODELAY=1` и
`SO_RCVBUF`/`SO_SNDBUF = SOCK_BUF` на обеих сторонах. asyncio выставляет
NODELAY только на исходящих соединениях — на принятых серверных остаётся 0
(замер 23.11.2026), т.е. Нейгл включён и мелкие MTProto-кадры ждут до 40 мс.

Init и первый MTProto-пакет приходят **одним кадром** (`forwardToWS` отдаёт
весь буфер lwIP). Сервер накапливает 64 B из последовательных binary-кадров,
остаток прогоняет через `Splitter` до чтения новых кадров.

## Апстрим

`upstream_connect(dc6, sni, path)`: TLS к `[dc6]:443`, `server_hostname=sni`,
затем `GET {path}` с `Host: {sni}`, `Sec-WebSocket-Protocol: binary`
(обязателен — без него kws отвечает 404).

`sni = kws{dc}[-1].web.telegram.org`, `-1` при `dc_idx < 0`.
`path = /apiws_test` при `abs(dc_idx) >= 10000`, иначе `/apiws`.

`DEFAULT_DC6` (DoH, 22.11.2026):

| DC | IPv6 |
|---|---|
| 1, 3 | `2001:b28:f23d:8005:7:0:109:337` |
| 2, 4, 203 | `2001:67c:4e8:f004::9` |
| 5 | `2001:b28:f23f:9::852:437` |

Переопределение: `--dc6 <dc>=<addr>` (повторяемый).
Обновление адресов: `curl -s 'https://dns.google/resolve?name=kws2.web.telegram.org&type=AAAA'`.

## Константы

| Параметр | Значение | Файл |
|---|---|---|
| `DEFAULT_PORT` | 2087 | `relay.py` |
| `MAX_CONNECTIONS` | 64 (семафор) | `relay.py` |
| `AUTH_TIMEOUT` | 10 с | `relay.py` |
| `INIT_TIMEOUT` | 15 с | `relay.py` |
| `UPSTREAM_TIMEOUT` | 10 с | `relay.py` |
| `IDLE_TIMEOUT` | 600 с | `relay.py` |
| `READ_BUF` | 65536 | `relay.py` |
| `SOCK_BUF` | 262144 (`SO_RCVBUF`/`SO_SNDBUF`) | `relay.py` |
| `STATS_FLUSH_SEC` | 30 с | `relay.py` |
| `MAX_PACKET` | 16 MiB | `mtproto.py` |
| `KEY_BYTES` | 32 (256 бит, base64url 43 симв.) | `state.py` |
| `DIAG_MAX` | 500 записей | `state.py` |
| `DIAG_LINE_MAX` | 300 символов | `state.py` |
| ротация `diag.log` | 512 KiB → `.1` | `state.py` |

`mem_limit: 96m`, `cpus: 0.5`, `network_mode: host`,
`restart: unless-stopped`, `stop_grace_period: 10s`,
docker-логи `json-file` 2×5 MiB, healthcheck `doctor` каждые 60 с
(`docker-compose.yml`). Образ `python:3.12-alpine`, uid 10001, зависимостей нет.

## Состояние (`/data`)

| Файл | Содержимое |
|---|---|
| `relay.key` | JSON `{key, created_at, generation}`, права 0600, атомарная запись |
| `stats.json` | счётчики, флаш каждые 30 с и на SIGTERM |
| `diag.log` | кольцо событий, ≤1 MiB с ротацией |
| `health` | timestamp, touch каждые 30 с |

Ключ генерируется при первом старте, печатается в stdout однократно.
Сравнение — `hmac.compare_digest`. В лог пишется `sha256[:12]`.
`key --rotate` инвалидирует предыдущий ключ немедленно.

Volume именованный (`relay-data:/data`) — наследует владельца из образа.
Bind-mount `./data:/data` создаётся от root → `PermissionError` в `_write_key`;
лечение `chown -R 10001:10001 ./data`.

## CLI

```
python3 relay.py [--host H] [--port P] [--data-dir D] [--dc6 K=V] [--insecure] [-v]
python3 relay.py --data-dir D key [--rotate]
python3 relay.py --data-dir D stats
python3 relay.py --data-dir D diag [-n N]
python3 relay.py --data-dir D doctor
```

`doctor`: чтение ключа, TCP `[2001:67c:4e8:f004::9]:443`, DNS
`kws2.web.telegram.org`. Exit 1 при любой ошибке. Используется как healthcheck.

## Счётчики (`stats`)

`connections_total`, `auth_ok`, `auth_fail`, `sessions_ok`, `sessions_fail`,
`sessions_silent`, `up_bytes`, `down_bytes`, `ws_frames_up`, `ws_frames_down`,
`errors_upstream`, `errors_client`, `active`, `peak_active`, `uptime_sec`.

`sessions_ok` инкрементируется после успешного `upstream_connect`.
`sessions_silent` — сессия закрыта без единого кадра от апстрима.
`up_bytes` учитывает только payload, прошедший через `Splitter` (init отдельно).

## Коды диагностики (`diag`)

| Код | Условие |
|---|---|
| `auth_timeout` | нет кадра за `AUTH_TIMEOUT` |
| `auth_bad_frame` | первый кадр не JSON с `token` |
| `auth_bad_token` | `hmac.compare_digest` не совпал |
| `init_timeout` | 64 B не набраны за `INIT_TIMEOUT` |
| `init_bad_proto` | `proto_tag` не в {efefefef, eeeeeeee, dddddddd} |
| `upstream_tls_fail` | `ssl.SSLError` при коннекте к kws |
| `upstream_ws_fail` | не-101 или таймаут апгрейда |
| `upstream_idle` | апстрим молчал `IDLE_TIMEOUT` |
| `client_idle` | клиент молчал `IDLE_TIMEOUT` |
| `packet_oversized` | буфер сплиттера > `MAX_PACKET` |
| `conn_limit` | семафор `MAX_CONNECTIONS` занят |
| `client_error` | `ConnectionError` / `OSError` / `IncompleteReadError` в сессии |
| `unexpected` | любое иное исключение (с traceback в лог) |
| `key_created`, `server_start`, `server_stop` | события жизненного цикла |

Реальный IP клиента берётся из `X-Real-IP`, затем первого элемента
`X-Forwarded-For`, затем `getpeername()` — nginx проксирует, иначе в логах
был бы только `127.0.0.1`.

## Развёртывание

```bash
git clone https://github.com/l1ratch/WSBridge-iOS.git
cd WSBridge-iOS/relay
curl -6 -sS --max-time 8 https://ipv6.google.com -o /dev/null -w '%{http_code}\n'
docker compose up -d --build
docker compose logs relay | head -20
```

nginx: [`wsb-remote.nginx.conf`](wsb-remote.nginx.conf) — `location /` →
`proxy_pass http://127.0.0.1:2087`, `proxy_http_version 1.1`,
`Upgrade`/`Connection` через `map $http_upgrade`, `proxy_buffering off`,
`proxy_read_timeout 3600s`, `http2 off`.

```bash
sudo cp wsb-remote.nginx.conf /etc/nginx/sites-available/wsb-remote
sudo ln -s /etc/nginx/sites-available/wsb-remote /etc/nginx/sites-enabled/
sudo certbot --nginx -d <поддомен>
sudo nginx -t && sudo systemctl reload nginx
```

ALPN на поддомене должен быть `http/1.1`: `URLSessionWebSocketTask` выполняет
WS только через HTTP/1.1 `Upgrade`, не через extended CONNECT (RFC 8441).
Параметр `http2` в `listen` (устаревший синтаксис) включает h2 на весь сокет
`0.0.0.0:443` для всех виртхостов и перекрывает `http2 off` в server-блоке.

```bash
sudo nginx -T | grep -n 'http2\|listen.*443'
python3 -c "import socket,ssl;c=ssl.create_default_context();c.set_alpn_protocols(['h2','http/1.1']);s=c.wrap_socket(socket.create_connection(('<поддомен>',443),timeout=10),server_hostname='<поддомен>');print(s.selected_alpn_protocol())"
```

Без nginx порт нужно открыть в фаерволе (`ufw allow <port>/tcp`);
при nginx наружу только 443.

## Диагностика кадрирования апстрима

```bash
docker compose exec relay python3 /app/tools/kws-frame-test.py
```

[`tools/kws-frame-test.py`](tools/kws-frame-test.py) отправляет на реальный kws
валидный obfuscated2 init + `req_pq_multi` двумя способами (init+пакет одним
кадром / раздельно) и печатает, какой получил ответ. Использует
`mtproto.AESCTR`, зависимостей не требует.

## Клиент

Поля в приложении: Меню → Релей и воркер → WSBridge Relay → домен + ключ.
Передаются через `providerConfiguration["relayHost"]` / `["relayKey"]`.
Приоритетнее `workerDomain`. Журнал: `cfg:relay=` → `relayws_try:` →
`relayws_auth_sent` → `ws_up` → `ws_recv:`.
