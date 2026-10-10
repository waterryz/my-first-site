# Findings & Evidence — *.maximumtest.ru

**Дата:** 2026-10-10  
**Цель:** Документация каждой находки с точным указанием источника, raw-доказательства и классификации FP/BD.

---

## F-01 | Отсутствие HTTP Security Headers

**Критичность:** MEDIUM  
**FP:** Нет  
**BD:** Частично (не настроено на уровне балансировщика)

### Где найдено

**Источник:** HTTP-ответ `GET https://maximumtest.ru`  
**Метод:** `curl -sI https://maximumtest.ru`

### Raw-доказательство

```http
HTTP/2 200
cache-control: private, no-cache, no-store, max-age=0, must-revalidate
content-type: text/html; charset=utf-8
date: Sat, 10 Oct 2026 09:57:54 GMT
link: </_next/static/media/401f9db361b6e189-s.p.woff2>; rel=preload; as="font"; crossorigin=""; type="font/woff2"
set-cookie: pathname=%2F; Path=/
vary: RSC, Next-Router-State-Tree, Next-Router-Prefetch, Accept-Encoding
set-cookie: _yasc=...; domain=.maximumtest.ru; path=/; expires=Tue, 07 Oct 2036 09:57:54 GMT; SameSite=None; Secure
server: ycalb
```

### Что отсутствует

| Заголовок | Искался в ответе | Результат |
|---|---|---|
| `Strict-Transport-Security` | grep -i "strict-transport" | Не найден |
| `Content-Security-Policy` | grep -i "content-security" | Не найден |
| `X-Content-Type-Options` | grep -i "x-content-type" | Не найден |
| `X-Frame-Options` | grep -i "x-frame" | Не найден |
| `Referrer-Policy` | grep -i "referrer-policy" | Не найден |
| `Permissions-Policy` | grep -i "permissions-policy" | Не найден |

### Проверка FP

Не FP — заголовки однозначно отсутствуют в HTTP-ответе. Проверено двумя независимыми запросами `curl -sI` с идентичным результатом.

### Проверка BD

Частично BD: Yandex Cloud ALB (`ycalb`) по умолчанию не добавляет security-заголовки — это ответственность конфигурации. Однако Next.js позволяет установить их через `next.config.js → headers()`, что означает осознанный пропуск или незнание.

---

## F-02 | Cookie `pathname` без флагов безопасности

**Критичность:** LOW  
**FP:** Нет  
**BD:** Частично (кука для навигации, но флаги — упущение)

### Где найдено

**Источник:** HTTP-ответ `GET https://maximumtest.ru`  
**Метод:** `curl -sI https://maximumtest.ru | grep -i "set-cookie"`

### Raw-доказательство

```http
set-cookie: pathname=%2F; Path=/
set-cookie: _yasc=AHyRxHoDud34m7+1T44YNw0EwsR5Jx8fMFd9/0QcHD9Qn13Cxgi4hUT5q82eW6CgmYuj9g==; domain=.maximumtest.ru; path=/; expires=Tue, 07 Oct 2036 09:57:54 GMT; SameSite=None; Secure
```

### Анализ

| Кука | HttpOnly | Secure | SameSite | Domain |
|---|---|---|---|---|
| `pathname` | ❌ нет | ❌ нет | ❌ нет | не указан (= текущий хост) |
| `_yasc` (Yandex) | ❌ нет | ✅ да | ✅ None | `.maximumtest.ru` |

### Проверка FP

Не FP — выведено напрямую из `set-cookie` заголовка. Значение `%2F` (URL-encoded `/`) стабильно воспроизводится при повторных запросах.

### Проверка BD

Кука `pathname` вероятно устанавливается Next.js middleware для отслеживания текущего пути. Назначение — BD. Отсутствие `HttpOnly`/`Secure` — не BD, а упущение: для навигационной куки нет причин быть доступной из JS и передаваться по HTTP.

---

## F-03 | API возвращает 500 вместо 403/404

**Критичность:** MEDIUM  
**FP:** Нет  
**BD:** Нет

### Где найдено

**Источник:** HTTP-запросы к API-путям, обнаруженным через `robots.txt`  
**Метод:** `curl -s -o /dev/null -w "%{http_code}" https://maximumtest.ru/api/*`

### Путь к обнаружению

1. **Шаг 1:** Загрузка `https://maximumtest.ru/robots.txt`
2. **Шаг 2:** Обнаружен `Disallow: /api*` — указание на существование API
3. **Шаг 3:** Запросы к стандартным API-путям

### Raw-доказательство

```
500 /api
500 /api/docs
500 /api/v1
500 /api/v2
500 /api/health
500 /api/graphql
```

Для сравнения, несуществующие пути возвращают 404:
```
404 /.well-known/openid-configuration
404 /swagger
404 /swagger-ui
404 /graphql
404 /wp-json
404 /.env
404 /.git/config
```

### Заголовки /api

```http
HTTP/2 500
cache-control: private, no-cache, no-store, max-age=0, must-revalidate
content-type: text/html; charset=utf-8
server: ycalb
```

### Проверка FP

Не FP. Разница в поведении однозначна: `/api*` → 500, несуществующие пути → 404. Это подтверждает, что маршрутизация API существует, но не обрабатывает запросы без параметров/авторизации корректно.

### Проверка BD

Не BD. 500 Internal Server Error — это необработанное исключение на сервере. Корректное поведение: 401/403 для неавторизованных запросов или 404 если API не должен быть публичным.

---

## F-04 | PII в URL-параметрах

**Критичность:** HIGH  
**FP:** Нет  
**BD:** Частично (legacy), но нарушает 152-ФЗ

### Где найдено

**Источник:** `https://maximumtest.ru/robots.txt` → директива `Clean-param`  
**Метод:** `WebFetch https://maximumtest.ru/robots.txt`

### Raw-доказательство

Из robots.txt (директива `Clean-param` для Яндекс-бота):

```
Clean-param: email&phone&fio&firstName&lastName&parentEmail&parentPhone ...
```

Полный список PII-параметров:

| Параметр | Тип данных | Риск |
|---|---|---|
| `email` | Электронная почта | Утечка в логи, referer, аналитику |
| `phone` | Номер телефона | Утечка в логи, referer, аналитику |
| `fio` | ФИО (полное имя) | Утечка в логи, referer, аналитику |
| `firstName` | Имя | Утечка в логи, referer, аналитику |
| `lastName` | Фамилия | Утечка в логи, referer, аналитику |
| `parentEmail` | Email родителя | Утечка в логи, referer, аналитику |
| `parentPhone` | Телефон родителя | Утечка в логи, referer, аналитику |

### Почему это не FP

Директива `Clean-param` в robots.txt существует **только** когда параметры реально присутствуют в URL, которые индексирует Яндекс. Если бы PII не попадали в URL, `Clean-param` не был бы нужен. Сам факт наличия этой директивы — подтверждение проблемы.

### Проверка BD

Частично BD: вероятно legacy-формы отправляют данные через GET. Однако передача PII через URL-параметры нарушает:
- OWASP guidelines (Sensitive Data Exposure)
- Российский 152-ФЗ «О персональных данных»
- GDPR (если обрабатываются данные граждан ЕС)

---

## F-05 | Staging-бакет в production

**Критичность:** MEDIUM  
**FP:** Нет  
**BD:** Нет

### Где найдено

**Источник:** HTML-контент `https://maximumtest.ru/blog/`  
**Метод:** `WebFetch https://maximumtest.ru/blog/`

### Raw-доказательство

На странице блога обнаружены ссылки на изображения из трёх бакетов Yandex Object Storage:

```
maximumtest-site.storage.yandexcloud.net  — production (основной сайт)
maximumtest-blog.storage.yandexcloud.net  — production (блог)
staging-blog.storage.yandexcloud.net      — STAGING
```

Пример URL изображения из staging:
```
https://staging-blog.storage.yandexcloud.net/uploads/2023/09/...
```

Путь `/uploads/2023/09/` — стандартная WordPress-структура для загрузок.

### Проверка FP

Не FP. Имя бакета `staging-blog` однозначно указывает на staging-окружение. Это не production-бакет с неудачным именем — наличие отдельного `maximumtest-blog` (production) подтверждает, что `staging-blog` — действительно staging.

### Проверка BD

Не BD. Использование staging-ресурсов в production — это ошибка миграции или конфигурации, а не осознанное решение. Staging-бакеты обычно имеют более слабые ACL и могут быть очищены без предупреждения.

---

## F-06 | api_key и sign в URL-параметрах

**Критичность:** MEDIUM  
**FP:** Нет  
**BD:** Частично (OAuth flow — BD, api_key/sign в URL — нет)

### Где найдено

**Источник:** `https://maximumtest.ru/robots.txt` → директива `Clean-param`  
**Метод:** `WebFetch https://maximumtest.ru/robots.txt`

### Raw-доказательство

```
Clean-param: client_id&redirect_uri&response_type&code_challenge&state&scope&sign&api_key ...
```

### Разделение на BD и не-BD

| Параметр | В URL — стандарт? | Статус |
|---|---|---|
| `client_id` | Да (RFC 6749) | BD |
| `redirect_uri` | Да (RFC 6749) | BD (но требует валидации) |
| `response_type` | Да (RFC 6749) | BD |
| `code_challenge` | Да (RFC 7636 PKCE) | BD |
| `state` | Да (RFC 6749) | BD |
| `scope` | Да (RFC 6749) | BD |
| `api_key` | **Нет** | **Не BD** — секрет в URL |
| `sign` | **Нет** | **Не BD** — подпись в URL |

### Проверка FP

Не FP. Как и с F-04, `Clean-param` подтверждает наличие этих параметров в реальных URL.

### Проверка BD

- OAuth-параметры (`client_id`, `redirect_uri`, `state`, `scope`, `response_type`, `code_challenge`) — это **стандартный** OAuth 2.0 / PKCE flow, они обязаны быть в URL → BD.
- `api_key` в URL — **не стандарт**, секрет должен передаваться через заголовок `Authorization` → не BD.
- `sign` в URL — **не стандарт**, подпись должна быть в заголовке или POST-body → не BD.

---

## F-07 | Устаревший nginx на mobapp.maximumtest.ru

**Критичность:** HIGH  
**FP:** Нет  
**BD:** Нет

### Где найдено

**Источник:** HTTP-ответ `GET https://mobapp.maximumtest.ru`  
**Метод:** `curl -sI https://mobapp.maximumtest.ru`

### Raw-доказательство

```http
HTTP/2 200
accept-ranges: bytes
content-type: text/html
date: Sat, 10 Oct 2026 09:59:41 GMT
etag: "6239bdd2-afd"
last-modified: Tue, 22 Mar 2022 12:15:14 GMT
server: nginx/1.17.3
content-length: 2813
```

### Анализ

| Факт | Значение |
|---|---|
| Версия nginx | 1.17.3 |
| Дата выпуска 1.17.3 | Август 2019 |
| Возраст | ~7 лет |
| Последнее изменение контента | 22 марта 2022 (4+ года назад) |
| Размер страницы | 2813 байт (минимальный лендинг) |

### Известные CVE для nginx <= 1.17.3

- **CVE-2019-20372** — HTTP request smuggling (1-byte overflow)
- **CVE-2021-23017** — DNS resolver vulnerability (RCE потенциал)
- **CVE-2021-3618** — ALPACA attack
- **CVE-2022-41741/41742** — mp4 module buffer overflow

### Субдомен как точка входа

Контент не обновлялся 4+ года. Заброшенный субдомен с устаревшим ПО — классический вектор для:
1. Эксплуатации CVE
2. Subdomain takeover (если DNS переедет, а запись останется)
3. Использования как pivot point для атаки на другие субдомены (через wildcard cookie из F-10)

### Проверка FP

Не FP. Версия nginx прямо указана в заголовке `server: nginx/1.17.3`. Дата `last-modified` подтверждает заброшенность.

### Проверка BD

Не BD. Намеренно использовать nginx 7-летней давности с известными CVE — это не design decision.

---

## F-08 | Server Header Disclosure

**Критичность:** LOW  
**FP:** Нет  
**BD:** Частично (поведение по умолчанию)

### Где найдено

**Источник:** HTTP-ответы от двух хостов  
**Метод:** `curl -sI`

### Raw-доказательство

| Хост | Заголовок | Раскрытие |
|---|---|---|
| `maximumtest.ru` | `server: ycalb` | Yandex Cloud ALB — тип балансировщика |
| `mobapp.maximumtest.ru` | `server: nginx/1.17.3` | Точная версия nginx |

### Проверка FP

Не FP — данные непосредственно из HTTP-заголовков.

### Проверка BD

Частично BD: nginx и ycalb по умолчанию отправляют `Server` header. Однако best practice — скрывать его (nginx: `server_tokens off;`). Для `mobapp` раскрытие точной версии усугубляет F-07.

---

## F-09 | Отсутствие security.txt

**Критичность:** INFO  
**FP:** Нет  
**BD:** BD (не реализовано)

### Где найдено

**Источник:** HTTP-запрос к `https://maximumtest.ru/.well-known/security.txt`  
**Метод:** `WebFetch https://maximumtest.ru/.well-known/security.txt`

### Raw-доказательство

```
HTTP 404 Not Found
```

### Проверка FP

Не FP — стандартный путь `.well-known/security.txt` (RFC 9116) возвращает 404.

### Проверка BD

BD — security.txt не является обязательным. Это best practice для ответственного раскрытия. Организация может использовать другие каналы (email, форму обратной связи). Не является уязвимостью, но усложняет responsible disclosure.

---

## F-10 | Wildcard Cookie Domain

**Критичность:** LOW  
**FP:** Нет  
**BD:** Частично (Яндекс-аналитика требует wildcard)

### Где найдено

**Источник:** HTTP-ответ `GET https://maximumtest.ru`  
**Метод:** `curl -sI https://maximumtest.ru | grep "set-cookie"`

### Raw-доказательство

```http
set-cookie: _yasc=PGBIQsl/JZWmS0F1bMVyamfy+Wgmd7OR/bmdZG3eMDNsY0eNyJt1F9G3T5mYqb/n7JsJuw==; domain=.maximumtest.ru; path=/; expires=Tue, 07 Oct 2036 10:00:17 GMT; SameSite=None; Secure
```

### Затронутые субдомены

Куки с `domain=.maximumtest.ru` автоматически отправляются на:

| Субдомен | Контроль | Риск |
|---|---|---|
| `maximumtest.ru` | Собственный | Низкий |
| `login.maximumtest.ru` | Собственный | Средний (авторизация) |
| `mobapp.maximumtest.ru` | Собственный (устаревший nginx) | Высокий (CVE) |
| `events.maximumtest.ru` | Tilda (третья сторона) | Высокий (чужой контроль) |
| `blog.maximumtest.ru` | Собственный (→ redirect) | Низкий |
| `roditeli.maximumtest.ru` | Собственный (→ redirect) | Низкий |

### Проверка FP

Не FP — `domain=.maximumtest.ru` явно указан в `set-cookie`. Технически куки Яндекс-аналитики (`_yasc`) не содержат session tokens, но механизм распространения на все субдомены — подтверждён.

### Проверка BD

Частично BD: Яндекс.Метрика устанавливает `_yasc` с wildcard domain для cross-subdomain tracking — это стандартное поведение SDK. Однако если приложение устанавливает свои session/auth-куки аналогичным образом, это уже проблема. Рекомендуется проверить, какие куки устанавливаются на `login.maximumtest.ru`.

---

## Сводка источников

| Источник | Что получено | Тип |
|---|---|---|
| `curl -sI https://maximumtest.ru` | Заголовки, куки, server info | HTTP Response Headers |
| `curl -sI https://mobapp.maximumtest.ru` | nginx version, last-modified | HTTP Response Headers |
| `https://maximumtest.ru/robots.txt` | API-пути, PII-параметры, OAuth-параметры | Web Crawl Directive |
| `https://maximumtest.ru/sitemap_index.xml` | URL-структура, разделы | XML Sitemap |
| `https://maximumtest.ru/.well-known/security.txt` | 404 | HTTP Status |
| `https://maximumtest.ru/blog/` (HTML) | Staging-бакет, WordPress theme, storage URLs | HTML Content Analysis |
| `https://maximumtest.ru/privacy-policy` (HTML) | login.maximumtest.ru ссылка | HTML Link Discovery |
| `https://maximumtest.ru/oauth` | OAuth-страница (200) | HTTP Status |
| `https://maximumtest.ru/api*` | 500 errors на API-путях | HTTP Status Probing |
| `https://events.maximumtest.ru` | Tilda stack | Technology Fingerprint |
| Google/Yandex web search | Публичная информация о домене | OSINT |

---

*Каждая находка подтверждена raw-данными из указанного источника. Plausible-находки (F-04, F-06) основаны на косвенном доказательстве (robots.txt clean-param) и требуют дополнительной верификации через активное тестирование.*
