# haqproxy

Личный intercepting-proxy в духе Caido (лёгкий, быстрый, единый бинарник) —
свой Burp/Caido без лимитов бесплатного тарифа. Переписан с Python-прототипа
(mitmproxy + Flask) на Go + htmx.

Работает на рабочей машине (роль «атакующей»): годится и против домашней лабы,
и против реальных bug bounty целей.

## Что уже есть (этапы 0–6)

- **Proxy + History** — весь HTTP(S)-трафик пишется в SQLite сырыми байтами.
  MITM реализован **собственным парсером поверх `net.Conn`** (не через net/http и
  не через стороннюю библиотеку), поэтому порядок и регистр заголовков
  сохраняются побайтово **и в пассивной истории**, а не только в Replay — важно
  для request smuggling / WAF-байпасов.
- **Replay** — сколько угодно вкладок, ручное редактирование сырого запроса
  байт-в-байт (свой сокет + TLS, без нормализации заголовков).
- **Scope** — список хостов (wildcard `*`) для фильтрации истории.
- **Settings** — конфиг Collaborator (домен/API/секрет, применяется сразу, без
  флагов) и настройки UI: цветовая схема (Tokyo Night / Gruvbox / Rosé Pine /
  Catppuccin + светлые версии) и прозрачность окна (в десктоп-приложении).
- **HTTPQL-поиск** — мини-язык запросов по истории, компилируется в
  параметризованный SQL.
- **AuthMatrix** — прогон одного запроса под разными identity (наборами
  подменяемых Cookie/Authorization) со сравнительной таблицей и эвристикой IDOR.
- **Automate** — Intruder-подобный прогон запроса по списку payload'ов (маркер в
  запросе заменяется на каждую строку), таблица результатов с подсветкой аномалий.
- В каждом окне — кнопка «Очистить» (история/находки/DOM/матрица/токены), чтобы
  не копить данные бесконечно.
- **Scanner-lite** — пассивные правила по каждому проксированному ответу
  (отсутствие security-заголовков, отражение параметра, verbose-ошибки,
  слабые/none JWT, ссылки на чувствительные пути) с бейдж-счётчиком находок.
- **DOM Logger** — для хостов в scope прокси инжектит JS-трекер опасных
  DOM-синков (innerHTML, eval, document.write, insertAdjacentHTML…) первым тегом
  в `<head>`; отчёты идут на «магический» путь того же origin, который прокси
  перехватывает локально (без mixed-content/CORS). История хранит оригинальные
  байты ответа — инъекция видна только в браузере.
- **Collaborator (OOB)** — VPS-бинарник `cmd/collaborator` (авторитативный DNS на
  `miekg/dns` + HTTP-логгер + API с Bearer-авторизацией, своя SQLite) и
  клиентская часть в UI: генерация токенов `<token>.oob.<домен>` с заметками и
  опрос VPS с корреляцией interactions по токену.

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

Два варианта одного и того же UI:

**Нативное окно (десктоп-приложение, macOS):**

```bash
go build -o haqproxy-gui ./cmd/haqproxy-gui   # CGO + WKWebView, только native-сборка
./haqproxy-gui
```

Открывает тот же htmx-интерфейс в нативном окне ОС (не в браузере). UI-сервер
слушает на локальном эфемерном порту, доступ только с loopback.

**Готовый .app-бандл (иконка, запуск из Finder/Dock):**

```bash
./scripts/build-app.sh   # требует ImageMagick, iconutil, sips
open haqproxy.app
```

**Headless (UI в браузере):**

```bash
go build -o haqproxy ./cmd/haqproxy
./haqproxy   # веб-UI на http://127.0.0.1:5050, открывать в браузере НАПРЯМУЮ
```

По умолчанию (оба):

- MITM-прокси: `127.0.0.1:8080`
- Данные (БД + CA): `~/.haqproxy`

Флаги: `-proxy`, `-data`, `-domlogger`, `-collab-*` (у headless ещё `-web`).

### TLS-перехват

При первом запуске генерируется корневой CA (`~/.haqproxy/ca/ca-cert.pem`).
Скачайте его из UI (ссылка «скачать CA-сертификат» внизу сайдбара или
`http://127.0.0.1:5050/ca-cert`) и установите в доверенные корневые сертификаты
той системы/браузера, через которую тестируете. Затем направьте браузер на
HTTP-прокси `127.0.0.1:8080`.

## Архитектура

```
cmd/haqproxy/       — headless-бинарник: proxy + история + веб-UI (браузер)
cmd/haqproxy-gui/   — то же в нативном окне ОС (WKWebView, macOS)
cmd/collaborator/   — бинарник для VPS: DNS+HTTP OOB-слушатель + API
internal/
  app/              — общая обвязка backend (store+CA+proxy+web) для обоих бинарников
  store/            — SQLite (modernc.org/sqlite, без CGO)
  rawhttp/          — побайтово-точный парсер HTTP/1.x поверх net.Conn
  replay/           — сырой сокет-клиент (порт repeater.py)
  proxy/            — MITM поверх rawhttp + генерация leaf-сертификатов
  ca/               — корневой CA + leaf-сертификаты на лету
  httpql/           — мини-язык запросов → параметризованный SQL
  authmatrix/       — прогон запроса под разными identity + эвристика IDOR
  scanner/          — пассивные правила scanner-lite
  domlogger/        — инъекция DOM-sink-трекера + перехват отчётов
  collaborator/     — серверная часть OOB (DNS+HTTP+API) для VPS
  collaboratorclient/ — генерация токенов + опрос VPS
  web/              — HTTP-хендлеры + html/template (htmx)
web/                — встраиваемые шаблоны и статика (htmx, css)
```

## Collaborator: запуск

Схема, когда панель DNS не умеет NS-записи внутри зоны (как у Aeza): берём
**отдельный дешёвый домен** (`.xyz`/`.site`) и делаем VPS авторитативным для
**всего домена** через кастомные nameservers — это операция уровня регистратора,
а не NS-запись в редакторе зоны, поэтому ограничение панели её не касается.

**1. У регистратора дешёвого домена** (напр. `haqoob.xyz`):
- зарегистрировать glue-записи (child nameservers): `ns1.haqoob.xyz → <IP-VPS>`,
  `ns2.haqoob.xyz → <IP-VPS>` (можно один и тот же IP);
- в настройках домена указать эти nameservers: `ns1.haqoob.xyz`, `ns2.haqoob.xyz`.

Наш DNS-сервер авторитативно отвечает на SOA/NS для апекса (их проверяют
pre-delegation проверки регистраторов) и A-записью на IP VPS для **любого**
поддомена — так виден и сам DNS-резолв (проходит через egress-firewall, режущий
исходящий HTTP), и последующий HTTP-хит.

**2. На VPS** (порты 53/80 требуют root или capabilities):

```bash
go build -o collaborator ./cmd/collaborator
HAQPROXY_COLLAB_SECRET=… ./collaborator -zone haqoob.xyz -ip <IP-VPS> \
  -dns :53 -http :80 -api :8081
# ns1/ns2 по умолчанию = ns1.<zone>/ns2.<zone>; переопределяются -ns1/-ns2
```

**3. На рабочей машине** — передать haqproxy домен, адрес API и секрет:

```bash
./haqproxy -collab-domain haqoob.xyz -collab-api http://<IP-VPS>:8081 \
  -collab-secret …   # или через HAQPROXY_COLLAB_SECRET
```

Payload'ы получаются вида `<token>.haqoob.xyz`.

**Проверка делегации** (после того как регистратор применит NS, до суток на
пропагацию): `dig haqoob.xyz SOA` и `dig test123.haqoob.xyz A` с публичного
резолвера должны отвечать вашим VPS.

> Альтернатива без glue: если регистратор дешёвого домена не умеет child
> nameservers, разместите DNS домена на Cloudflare (бесплатно) — там редактор
> **умеет NS-записи**, и делегацию `oob.<домен> NS ns1.<домен>` + `ns1.<домен> A
> <IP-VPS>` можно завести прямо в панели.

## Осознанные ограничения v1

- Только HTTP/1.1: в ALPN предлагаем `http/1.1`, браузер откатывается с HTTP/2.
  WebSocket/H2-перехват — вне рамок собственного парсера на этом этапе.
- Разбор chunked — по терминатору (эвристика), без строгого RFC-разбора
  chunk-extensions/trailers (как в Python-прототипе).

## Python-прототип

Исходный прототип (`app.py`, `db.py`, `recorder.py`, `repeater.py`, `index.html`)
сохранён в репозитории для истории — архитектура, проверенная на реальном трафике,
из которой портирована Go-версия.
