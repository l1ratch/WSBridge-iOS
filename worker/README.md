# WSBridge DoH worker

Собственный DoH-эндпоинт для роутинга доменов через прокси в WSBridge.
Концепция: [`docs/DoH-Routing.ru.md`](https://github.com/l1ratch/WSBridge-iOS/blob/main/docs/DoH-Routing.ru.md).

**Это отдельная ветка репозитория `worker`.** CI сборки IPA на `main` её не
трогает. Вы поднимаете воркер сами — общего публичного DoH-сервиса нет,
поэтому «украсть токен» нечего: у каждого свой воркер и свой список ID.

---

## Как это работает (коротко)

1. iOS получает `NEDNSOverHTTPSSettings` с адресом этого воркера и
   `matchDomains` = точные домены из включённых в приложении списков.
2. На воркер уходят **только** запросы по этим доменам; весь остальной DNS
   телефона резолвится системой как обычно.
3. Воркер (**основной режим `MODE="simple"`**) отвечает `A = 198.51.100.1`
   на любой дошедший валидный запрос. Это метка: пакет уходит в узкий
   маршрут туннеля, `TLSSNI` достаёт домен из ClientHello, `ProxyClient`
   идёт в ваш SOCKS5/HTTP-прокси по имени.
4. Домены не из списков воркер не видит → идут напрямую, батарея не тратится.

Воркер **не знает про списки доменов**, не ходит на GitHub, не форвардит
на апстрим. Если он жив — он отвечает. Никакой зависимости от `1.1.1.1`.

---

## Деплой (5 минут)

Нужен аккаунт Cloudflare и `wrangler`:

```bash
npm i -g wrangler
wrangler login
cd worker
```

### 1. Узнайте ID устройства в приложении

WSBridge → «Прокси по доменам» → блок «Воркер» → поле **«ID устройства»**
→ кнопка **«Копировать»**. Это `identifierForVendor` (IDFV). Он **меняется
при удалении/переустановке приложения** — тогда повторите шаг 2.

### 2. Впишите ID в `wrangler.toml`

```toml
[vars]
MODE = "simple"
REQUIRE_ID = "true"
TRUSTED_IDS = "9F3CA71-XXXX-XXXX-XXXX-XXXXXXXXXXXX"   # ваш ID из приложения
FAKE_IP = "198.51.100.1"
```

Несколько устройств — через запятую.

### 3. Задеплойте

```bash
wrangler deploy
```

В выводе будет адрес вида `https://wsbridge-doh.<ваш-поддомен>.workers.dev`.

### 4. Укажите адрес в приложении

WSBridge → «Прокси по доменам» → **«Адрес воркера»** → голый хост
`wsbridge-doh.<ваш-поддомен>.workers.dev` (без `https://`, без пути).
Приложение само склеит `/dns-query/<ID устройства>` и само настроит
системный DoH. Нажмите **«Тест воркера»** — должно быть зелёным.

> Путь в `serverURL` доходит гарантированно: RFC 8484 §4.1 для POST
> обрабатывает URI Template без переменных, а `?dns=` добавляется только
> для GET. Произвольных query-параметров мы поэтому не используем.

### 5. Проверьте вручную (по желанию)

```bash
# Валидный ID → A = 198.51.100.1
curl -s -o /dev/null -w '%{http_code}\n' \
  -H 'Content-Type: application/dns-message' \
  --data-binary @query.bin \
  'https://wsbridge-doh.<поддомен>.workers.dev/dns-query/<ВАШ-ID>'

# Диагностика (JSON, без DNS-тела) — корневой путь
curl -s 'https://wsbridge-doh.<поддомен>.workers.dev/diagnose' | jq

# ...или с ID, чтобы проверить именно его:
curl -s 'https://wsbridge-doh.<поддомен>.workers.dev/dns-query/<ВАШ-ID>/diagnose' | jq
```

`query.bin` — бинарный DNS-запрос (можно снять `dig +binary` или собрать
любым DoH-клиентом). Ответ всегда `200` + `Content-Type:
application/dns-message`, даже для REFUSED/SERVFAIL (RFC 8484 §4.2.1).

---

## `/diagnose` — что видит воркер

Кнопка «Тест воркера» в приложении дёргает `GET /diagnose` (обычный JSON,
не системный DoH). Пример ответа:

```json
{
  "ok": true,
  "version": "1",
  "parsed": {
    "hwid": "9F3CA71-…",
    "hwidTrusted": true,
    "mode": "simple",
    "requireId": true,
    "listsRequested": [],
    "listsActive": [],
    "listsIgnored": [],
    "path": "/dns-query/9F3CA71-…",
    "method": "GET",
    "qname": null,
    "qtype": null,
    "wouldAnswer": "198.51.100.1"
  },
  "config": {
    "mode": "simple",
    "requireId": true,
    "trustedIds": 1,
    "fakeIp": "198.51.100.1",
    "upstream": null,
    "listsConfigured": 11,
    "listsLoaded": 0,
    "cache": "n/a"
  },
  "errors": []
}
```

Возможные `errors`:

| Код | Что делать |
|---|---|
| `HWID_NOT_TRUSTED` | Добавить этот ID в `TRUSTED_IDS` и `wrangler deploy` |
| `ID_CHECK_DISABLED` | `REQUIRE_ID=false` — воркер открыт, это осознанный выбор |
| `UNKNOWN_LIST` | Только в `MODE="lists"`: id нет в `LISTS`, проигнорирован |
| `UPSTREAM_UNAVAILABLE` | Только в `MODE="lists"`: упал `UPSTREAM_DOH` |

На каждый системный DoH-ответ также кладётся заголовок
`X-WSBridge-Debug` (base64 того же JSON) — удобно смотреть в логах CF.

---

## `REQUIRE_ID` — отключение защиты

По умолчанию `true`: запрос без ID или с левым ID получает DNS `REFUSED`.
Если поставить `false`, воркер отвечает FakeIP **всем**. Используйте только
для отладки или в полностью доверенной сети: `/diagnose` покажет
`ID_CHECK_DISABLED`, но `matchDomains` на iOS всё равно ограничивает набор
доменов, которые вообще доезжают до воркера.

---

## Режим `MODE="lists"` — расширение (НЕ нужен сейчас)

Отложенная функциональность: воркер сам тянет `.lst` с GitHub (кэш
`caches.default`), сверяет QNAME, а домены не из списков форвардит на
`UPSTREAM_DOH`. URL при этом получает сегмент активных списков:

```
/dns-query/<HWID>/google-ai+youtube+discord
```

Включается, если:
- понадобилась серверная фильтрация; **или**
- основной Вариант Б (`matchDomains`) подвёл и мы откатываемся на
  резервный Вариант А (весь DNS телефона на воркер).

Чтобы включить: раскомментируйте блок в `wrangler.toml`, поставьте
`MODE = "lists"`, задайте `UPSTREAM_DOH` (**DoH-URL, не голый IP** — CF
Worker не умеет UDP:53), при необходимости поправьте `LISTS` и
`worker/lists.json`, затем `wrangler deploy`.

`DENY_SETS = "telegram"` в этом режиме страхует от попадания телеграм-доменов
в прокси (основная защита — приоритет IP датацентров в самом туннеле).

`lists.json` в простом режиме **не читается** — это заготовка контракта
`id → name → URL` между приложением и воркером.

---

## Безопасность / приватность

- Воркер ваш, чужим ID не отвечает (`TRUSTED_IDS`).
- Домены не из включённых списков до воркера не доходят (`matchDomains`),
  поэтому он не может стать открытым резолвером «на все случаи жизни».
- Весь обмен — HTTPS, DNS-wire в теле POST или `?dns=` для GET, RFC 8484.
- Никаких cookie, KV, D1, Durable Objects, панели и паролей.
- Логи Cloudflare содержат path с ID устройства — это ваш же ID.

---

## Файлы

```
worker/
  src/index.js     # ~200 строк: оба режима + /diagnose, без зависимостей
  wrangler.toml    # конфиг, правится руками
  lists.json       # id → name → URL (только для MODE="lists")
  README.md        # эта инструкция
```

Лицензия — MIT, как и основной проект.
