# haqproxy

Личный intercepting-proxy в духе Caido (лёгкий, быстрый, единый бинарник) —
свой Burp/Caido без лимитов бесплатного тарифа. Переписан с Python-прототипа
(mitmproxy + Flask) на Go + htmx.

Работает на рабочей машине (роль «атакующей»): годится и против домашней лабы,
и против реальных bug bounty целей.

## Что уже есть (этапы 0–2)

- **Proxy + History** — весь HTTP(S)-трафик пишется в SQLite сырыми байтами.
  MITM реализован **собственным парсером поверх `net.Conn`** (не через net/http и
  не через стороннюю библиотеку), поэтому порядок и регистр заголовков
  сохраняются побайтово **и в пассивной истории**, а не только в Replay — важно
  для request smuggling / WAF-байпасов.
- **Replay** — сколько угодно вкладок, ручное редактирование сырого запроса
  байт-в-байт (свой сокет + TLS, без нормализации заголовков).
- **Scope** — список хостов (wildcard `*`) для фильтрации истории.
- **HTTPQL-поиск** — мини-язык запросов по истории, компилируется в
  параметризованный SQL.

Фронтенд — htmx поверх `html/template`, всё встроено в бинарник через `embed`.
Node/сборка не нужны.

### HTTPQL, кратко

```
condition := field.op:"value" | field.op:number
field     := host | method | path | status | body | source
op        := eq | cont | gt | gte | lt | lte   (gt/lt/gte/lte только для status)
expr      := condition (and|or condition)*
```

Примеры: `method.eq:"POST" and status.gte:400`, `host.cont:"api" and source.eq:"replay"`.

## Запуск

```bash
go build -o haqproxy ./cmd/haqproxy
./haqproxy
```

По умолчанию:

- MITM-прокси: `127.0.0.1:8080`
- Веб-UI: `http://127.0.0.1:5050` (открывать в браузере **напрямую**, не через прокси)
- Данные (БД + CA): `~/.haqproxy`

Флаги: `-proxy`, `-web`, `-data`.

### TLS-перехват

При первом запуске генерируется корневой CA (`~/.haqproxy/ca/ca-cert.pem`).
Скачайте его из UI (ссылка «скачать CA-сертификат» внизу сайдбара или
`http://127.0.0.1:5050/ca-cert`) и установите в доверенные корневые сертификаты
той системы/браузера, через которую тестируете. Затем направьте браузер на
HTTP-прокси `127.0.0.1:8080`.

## Архитектура

```
cmd/haqproxy/       — бинарник рабочей машины: proxy + история + веб-UI
cmd/collaborator/   — бинарник для VPS: DNS+HTTP OOB-слушатель (этап 5, заглушка)
internal/
  store/            — SQLite (modernc.org/sqlite, без CGO)
  rawhttp/          — побайтово-точный парсер HTTP/1.x поверх net.Conn
  replay/           — сырой сокет-клиент (порт repeater.py)
  proxy/            — MITM поверх rawhttp + генерация leaf-сертификатов
  ca/               — корневой CA + leaf-сертификаты на лету
  httpql/           — мини-язык запросов → параметризованный SQL
  web/              — HTTP-хендлеры + html/template (htmx)
web/                — встраиваемые шаблоны и статика (htmx, css)
```

## Дальше по ТЗ (`haqproxy.md`)

Этап 3 — AuthMatrix, этап 4 — Scanner-lite, этап 5 — Collaborator (VPS),
этап 6 — DOMLogger-инъекция. Схема БД под эти фичи уже заведена в `internal/store`.

## Осознанные ограничения v1

- Только HTTP/1.1: в ALPN предлагаем `http/1.1`, браузер откатывается с HTTP/2.
  WebSocket/H2-перехват — вне рамок собственного парсера на этом этапе.
- Разбор chunked — по терминатору (эвристика), без строгого RFC-разбора
  chunk-extensions/trailers (как в Python-прототипе).

## Python-прототип

Исходный прототип (`app.py`, `db.py`, `recorder.py`, `repeater.py`, `index.html`)
сохранён в репозитории для истории — архитектура, проверенная на реальном трафике,
из которой портирована Go-версия.
