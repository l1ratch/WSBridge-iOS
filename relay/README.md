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

```bash
git clone https://github.com/l1ratch/WSBridge-iOS.git
cd WSBridge-iOS/relay

# 1. Проверьте свободный порт и IPv6 на хосте
sudo ss -tlnp | grep 2087          # должно быть пусто
curl -6 -sS --max-time 8 https://ipv6.google.com -o /dev/null -w '%{http_code}\n'   # 200

# 2. Запуск
docker compose up -d --build

# 3. Ключ выводится ОДИН РАЗ при первом запуске
docker compose logs relay | head -20

# 4. Откройте порт в фаерволе (обязательно!)
sudo ufw allow 2087/tcp
sudo ufw status | grep 2087
```

Порт меняется в `docker-compose.yml` → `command: ["--port", "ВАШ_ПОРТ", ...]`.
На типичном VDS 443/80/8443 заняты nginx, 2053/2083/2084 — контейнерами;
из свободных подходят 2087, 2096, 9443.

**Частый затык:** мост слушает, но `stats: total=0` — порт закрыт UFW.
`sudo ufw allow <port>/tcp` решает.

## Подключение в WSBridge

1. Выключить туннель.
2. Меню → **WSBridge Relay** → домен (`relay.example.com`) и ключ.
3. Включить туннель.

В журнале: `cfg:relay=…` → `relay_up` → `ws_up` → `ws_recv:…` — успех.

## Протокол

```
wss://relay.example.com/bridge          TLS 1.3 (терминирует nginx)
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

Первый MTProto-кадр — **оригинальный init** без самодеятельных заголовков,
байт-в-байт как у официального клиента tg-ws-proxy.

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

## Маскировка (nginx на 443)

Мост слушает `127.0.0.1:2087`, nginx терминирует TLS и разделяет по пути:

```nginx
server {
    listen 443 ssl;
    http2 on;
    server_name relay.example.com;

    ssl_certificate     /etc/letsencrypt/live/relay.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/relay.example.com/privkey.pem;

    # Легенда: настоящий WS-сервис (remote control / live-логи)
    location /term {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 3600s;
    }

    # Наш канал — тот же WS, другой путь
    location /bridge {
        proxy_pass http://127.0.0.1:2087;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
        proxy_buffering off;
    }

    location / {
        root /var/www/relay;
        index index.html;
    }
}
```

Сертификат: `certbot --nginx -d relay.example.com`.

Снаружи `/term` и `/bridge` неразличимы: тот же TLS, тот же WS-апгрейд, тот же
профиль трафика (симметричный обмен мелкими пакетами, долгие сессии). Отличить
можно только зная ключ. Пробинг без ключа получает `close 1008` — как любой
защищённый remote-access сервис.

**Чего не делать:** голый MTProto-proxy на 443 без TLS — его DPI уже
распознаёт. Ключ — не криптография, а маркер доступа; содержимое защищает
MTProto end-to-end (мост видит только obfuscated2-поток).

## Обновление IPv6-адресов

Адреса kws получены через DoH и могут смениться:

```bash
curl -s 'https://dns.google/resolve?name=kws2.web.telegram.org&type=AAAA'
```

Обновить без пересборки — в `docker-compose.yml`:
```yaml
command: ["--port","2087","--data-dir","/data","--dc6","2=НОВЫЙ_IPV6"]
```

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
