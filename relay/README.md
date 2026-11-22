# WSBridge Relay

WS-мост: **iPhone (IPv4, любая сеть) → ваш VDS → Telegram kws-гейтвеи по IPv6**.

```
iPhone ──WSS──→ VDS:<port> ──TLS──→ kws{dc}.web.telegram.org (IPv6) ──→ Telegram DC
         ↑ IPv4 достаточно      ↑ IPv6 нужен ТОЛЬКО здесь
```

Телефону IPv6 **не нужен** — мост сам перекладывает IPv4-поток в IPv6-соединение
с Telegram. Это работает в мобильной сети без IPv6.

## Почему так

Измерено 22.11.2026: IPv4-адреса Telegram фильтруются (все канонические DC IP
дают таймаут), а kws-гейтвеи по IPv6 живые — TLS + `101` + настоящий MTProto-ответ
для DC1–DC5 включая media. Проверено на реальном устройстве: 11 соединений,
`err=0 silent=0`, до 1.2 КБ в обе стороны на сессию.

## Ресурсы

Требования: стабильность, самоподъём, минимум нагрузки на VDS при 2–5 активных
клиентах, максимум деталей при ошибках.

| Что | Как реализовано |
|---|---|
| Образ | `python:3.12-alpine`, ~55 МБ, **зависимостей нет** (AES реализован в коде) |
| Процесс | один, non-root (uid 10001) |
| Память | потолок `mem_limit: 96m` в compose; реально ~40–60 МБ на 5 клиентов |
| CPU | `cpus: 0.5`; расшифровываются только префиксы длин пакетов |
| Диск | `stats.json` (один JSON), `diag.log` ≤1 МБ с ротацией, docker-логи 2×5 МБ |
| Самоподъём | `restart: unless-stopped` + healthcheck (`doctor`) |
| Соединения | жёсткий лимит 64, idle-таймаут 600 с, backpressure через `drain()` |

## Быстрый старт

### Вариант A: с nginx на выделенном поддомене (рекомендуется)

Весь поддомен (например `wsb-remote.example.com`) — это мост. Снаружи только
443, TLS + WS, выглядит как корпоративный remote-access сервис.

```bash
# 0. DNS: A-запись wsb-remote.example.com -> IP вашего VDS
#    (в панели управления доменом)

# 1. Забрать файлы на сервер
git clone https://github.com/l1ratch/WSBridge-iOS.git
cd WSBridge-iOS/relay

# 2. Проверить IPv6 (нужен для исходящих к Telegram)
curl -6 -sS --max-time 8 https://ipv6.google.com -o /dev/null -w '%{http_code}\n'   # 200

# 3. Запустить релей (слушает 127.0.0.1 внутри compose — наружу не торчит)
docker compose up -d --build

# 4. Ключ выводится ОДИН РАЗ при первом запуске
docker compose logs relay | head -20
# Сохраните ключ!

# 5. nginx: положить конфиг, заменить домен, получить сертификат
sudo cp wsb-remote.nginx.conf /etc/nginx/sites-available/wsb-remote
sudo ln -s /etc/nginx/sites-available/wsb-remote /etc/nginx/sites-enabled/
sudo nano /etc/nginx/sites-available/wsb-remote   # заменить wsb-remote.example.com
sudo certbot --nginx -d wsb-remote.example.com
sudo nginx -t && sudo systemctl reload nginx
```

### Вариант B: без домена, прямой порт

```bash
git clone https://github.com/l1ratch/WSBridge-iOS.git
cd WSBridge-iOS/relay
docker compose up -d --build
docker compose logs relay | head -20        # ключ
sudo ufw allow 2087/tcp                    # ОБЯЗАТЕЛЬНО открыть порт
```

В приложении тогда указывается `IP:2087` — но это без TLS, только для теста.
Для постоянного использования — вариант A.

## Какие файлы нужны

Всё уже в `relay/` репозитории:

| Файл | Назначение |
|---|---|
| `relay.py` | сервер (WS-приём, авторизация, апстрим) |
| `mtproto.py` | AES-CTR, разбор init, сплиттер |
| `state.py` | ключ, статистика, диагностика |
| `Dockerfile` | образ alpine, non-root |
| `docker-compose.yml` | лимиты, healthcheck, restart |
| `wsb-remote.nginx.conf` | готовый конфиг nginx для поддомена |
| `README.md` | этот файл |

Ничего скачивать отдельно не нужно — `git clone` и всё.

**Частый затык:** мост слушает, но `stats: total=0` — порт закрыт UFW.
В варианте A наружу торчит только 443 (уже открыт под nginx); в варианте B —
`sudo ufw allow <port>/tcp`.

**Второй затык (bind-mount):** если заменили volume на `./data:/data`,
каталог на хосте создаётся от root, и процесс в контейнере (uid 10001)
не может записать ключ — трейс с `PermissionError` в `_write_key`.
Лечение: `sudo chown -R 10001:10001 ./data`, либо оставьте именованный
volume из compose по умолчанию — он наследует владельца из образа
и работает сразу.

**Третий затык (HTTP/2) — самый коварный.** Симптомы: в журнале iOS
`relayws_try` → `relayws_auth_sent` → `ws_closed:0::Ошибка протокола`
мгновенно, на каждую попытку; а на релее `connections_total=0`, т.е.
соединение вообще не доходит до Python. Причина: nginx отдаёт **ALPN h2**,
а `URLSessionWebSocketTask` умеет WS только по HTTP/1.1 `Upgrade`
(h2 требует extended CONNECT из RFC 8441, который iOS не использует).

Лечение — **два** места, и это важнее, чем выглядит. Проверено на реальном
сервере (nginx 1.31.9): `http2 off;` в server-блоке поддомена **не помогает**,
если где-то ещё остался устаревший параметр `http2` в `listen`, потому что он
включает HTTP/2 на весь слушающий сокет `0.0.0.0:443` — сразу для всех
виртуальных хостов порта, независимо от их собственных `http2 off`.

```bash
# 1. Найти ВСЕ включения http2 — и директиву, и устаревший параметр listen
sudo nginx -T | grep -n 'http2\|listen.*443'

# 2. Типичный виновник — default/blackhole-блок:
#      listen 443 ssl http2 default_server;        <- устаревший синтаксис
#      listen [::]:443 ssl http2 default_server;
#    Убрать параметр http2 (оставить просто ssl):
#      listen 443 ssl default_server;
#      listen [::]:443 ssl default_server;
#    nginx сам подскажет: [warn] the "listen ... http2" directive is deprecated

# 3. В server-блоке поддомена оставить современный синтаксис:
#      http2 off;

sudo nginx -t && sudo systemctl reload nginx
```

Проверка снаружи — должно быть `http/1.1` (а не `h2`) именно на поддомене
релея; основной сайт может остаться на h2, это нормально:
```bash
python3 -c "import socket,ssl;c=ssl.create_default_context();c.set_alpn_protocols(['h2','http/1.1']);s=c.wrap_socket(socket.create_connection(('ВАШ_ПОДДОМЕН',443),timeout=10),server_hostname='ВАШ_ПОДДОМЕН');print(s.selected_alpn_protocol())"
```

Реальный замер до/после правки (один сервер, два хоста):
```
до:    <поддомен релея>  ALPN=h2         <основной домен>  ALPN=h2
после: <поддомен релея>  ALPN=http/1.1   <основной домен>  ALPN=h2  (сайт цел)
       WS upgrade на поддомене          -> HTTP/1.1 101 Switching Protocols
```

Диагностический A/B, который изначально это доказал (тот же хост, тот же путь):
```
curl --http1.1 + Upgrade: websocket  ->  HTTP/1.1 101 Switching Protocols
ручной HTTP/2 extended CONNECT       ->  :status 200 (nginx умеет, iOS нет)
```

## Подключение в WSBridge

1. Выключить туннель.
2. Меню → **Релей и воркер** → **WSBridge Relay** → домен
   (`wsb-remote.example.com`) и ключ.
3. Включить туннель.

В журнале: `cfg:relay=…` → `relayws_try:…` → `ws_up` → `ws_recv:…` — успех.

## Протокол

```
wss://wsb-remote.example.com/            TLS 1.3 (терминирует nginx)
→ 101 Switching Protocols               ВСЕМ, до проверки ключа
→ {"v":1,"token":"<key>"}               первый кадр, внутри TLS
→ {"ok":true}  |  close 1008            отказ как у защищённого сервиса
→ <64B obfuscated2 init>                ОРИГИНАЛЬНЫЙ формат tg-ws-proxy
→ сервер: DC из init → TLS к kws IPv6 → 101 → MTProto кадрами
```

Три свойства для маскировки:
- `101` отдаётся до проверки ключа — активный пробинг видит рабочий WS;
- токен внутри TLS, не в URL — не попадает в логи nginx;
- отказ = `close 1008` (policy violation) — стандартный код защищённого сервиса.

Релей принимает ЛЮБОЙ путь (`/`, `/ws`, `/bridge` — без разницы): выделенный
поддомен сам по себе и есть адрес. Приложение шлёт на корень `/`.

## Обновление IPv6-адресов

Адреса kws получены через DoH и могут смениться:

```bash
curl -s 'https://dns.google/resolve?name=kws2.web.telegram.org&type=AAAA'
```

Обновить без пересборки — в `docker-compose.yml`:
```yaml
command: ["--port","2087","--data-dir","/data","--dc6","2=НОВЫЙ_IPV6"]
```

## Команды

```bash
docker compose exec relay python3 /app/relay.py --data-dir /data key            # показать ключ
docker compose exec relay python3 /app/relay.py --data-dir /data key --rotate   # перевыпустить
docker compose exec relay python3 /app/relay.py --data-dir /data stats          # сводка JSON
docker compose exec relay python3 /app/relay.py --data-dir /data diag -n 100    # последние события
docker compose exec relay python3 /app/relay.py --data-dir /data doctor         # самопроверка
```

`key --rotate` — старый ключ немедленно перестаёт действовать, все клиенты
нужно перенастроить. Ключ хранится в `data/relay.key` (права 0600), генерируется
один раз при первом запуске и выводится в лог **однократно**.

`doctor` проверяет: ключ читается, IPv6 до kws2 работает, DNS резолвится.
Он же используется как healthcheck.

## Статистика и диагностика

`stats` (JSON, переживает рестарт — `data/stats.json`):

| Поле | Значение |
|---|---|
| `connections_total` | всего TCP-соединений |
| `auth_ok` / `auth_fail` | прошли / не прошли авторизацию |
| `sessions_ok` / `sessions_fail` | дошли до Telegram / упали на init |
| `sessions_silent` | Telegram не ответил (главный индикатор проблем) |
| `up_bytes` / `down_bytes` | трафик в обе стороны |
| `ws_frames_up` / `ws_frames_down` | кадры |
| `errors_upstream` / `errors_client` | ошибки по сторонам |
| `active` / `peak_active` | сейчас / максимум одновременно |

`diag` — последние события с машинно-читаемыми кодами причин:

| Код | Причина |
|---|---|
| `auth_timeout` | клиент не прислал ключ за 10 с |
| `auth_bad_token` | неверный ключ |
| `auth_bad_frame` | первый кадр не JSON с token |
| `init_timeout` | не прислал init за 15 с |
| `init_bad_proto` | init не является MTProto (не наш клиент) |
| `upstream_tls_fail` | TLS к kws не поднялся |
| `upstream_ws_fail` | WS-апгрейд к kws не прошёл / таймаут |
| `upstream_idle` | Telegram молчал 600 с |
| `client_idle` | клиент молчал 600 с |
| `packet_oversized` | пакет >16 МБ (битый поток) |
| `conn_limit` | превышен лимит 64 соединения |

Диагностика ограничена: 500 записей в памяти, файл ≤1 МБ с ротацией.
Ничего не растёт неограниченно.

## Маскировка

Релей слушает `127.0.0.1:2087` и наружу не торчит. nginx терминирует TLS на
выделенном поддомене и проксирует всё на релей. Готовый конфиг —
[`wsb-remote.nginx.conf`](./wsb-remote.nginx.conf).

Со стороны это **обычный HTTPS+WS-сервис на собственном домене**:
- TLS 1.3 с валидным сертификатом Let's Encrypt — неотличимо от любого сайта;
- первый кадр после `101` — авторизационный токен, как у любого защищённого
  remote-access сервиса (ttyd, code-server, Jupyter, TURN-релеи);
- пробинг без ключа получает `close 1008` — стандартное поведение защиты.

Открытый WS-релей, который пускает всех, выглядит как open proxy и палится;
релей с обязательным токеном выглядит как корпоративная удалёнка. Это и есть
главная функция ключа — не только безопасность, но и правдоподобие.

Профиль трафика (симметричный обмен мелкими пакетами, долгие сессии) совпадает
с профилем веб-терминала/remote control, поэтому легенда поддомена как
«удалённого управления» естественна.

**Чего не делать:** голый MTProto-proxy на 443 без TLS — его DPI уже
распознаёт. Ключ — не криптография, а маркер доступа; содержимое защищает
MTProto end-to-end (мост видит только obfuscated2-поток).

## Безопасность

- Ключ: 256 бит (`secrets.token_urlsafe(32)`), сравнение в постоянном времени.
- Ключ **не** в URL и не в логах (в лог пишется только `sha256[:12]`).
- Без ключа — `close 1008`, никакой информации о протоколе.
- Мост не проксирует на произвольные адреса: только kws-гейтвеи Telegram.
- Лимит 64 соединения защищает от исчерпания ресурсов.
- Процесс non-root, `mem_limit`, ротация логов — сервер не забивается.

## Ограничения

- Relay в РФ: риск жалобы хостеру остаётся. Маскировка снижает риск DPI,
  но не отменяет юридический/хостерский.
- Один VDS — один-два пользователя: массовость привлекает внимание.
- `IDLE_TIMEOUT=600` с: соединение без трафика 10 минут закрывается.
