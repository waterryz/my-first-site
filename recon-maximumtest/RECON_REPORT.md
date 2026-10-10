# Hunt Core System — Recon Report: *.maximumtest.ru

**Дата:** 2026-10-10  
**Методология:** Пассивная разведка (OSINT, Certificate Transparency, robots.txt, sitemap, HTTP-заголовки, технологический fingerprinting)  
**Область:** *.maximumtest.ru  
**Исключения:** Brute Force, Blind SSRF, DDoS

---

## 1. Обзор цели

**Maximum Education (ООО «Максимум Образование»)** — российский образовательный центр, онлайн-школа подготовки к ЕГЭ/ОГЭ.

- **Основной домен:** maximumtest.ru
- **Технологический стек:** Next.js (SSR), Yandex Cloud (Object Storage, балансировщик `ycalb`)
- **Блог-платформа:** WordPress (Bedrock/Roots layout: `app/themes/maximum-v3`)
- **Поддомен событий:** Tilda (tildacdn.com)
- **Мобильное приложение:** nginx/1.17.3 (статический лендинг)
- **Свидетельство о регистрации ПО:** № 2023666710 от 03.08.2023

---

## 2. Обнаруженные субдомены

| Субдомен | Назначение | Технологии | Статус |
|---|---|---|---|
| `maximumtest.ru` | Основной сайт | Next.js, ycalb | 200 |
| `login.maximumtest.ru` | Личный кабинет (авторизация) | Неизвестно (SPA) | 200 |
| `mobapp.maximumtest.ru` | Лендинг мобильного приложения | nginx/1.17.3, статический HTML | 200 |
| `events.maximumtest.ru` | Страница мероприятий B2B | Tilda | 200 |
| `blog.maximumtest.ru` | Блог (→ 301 на /blog/) | WordPress (Bedrock) | 301 |
| `roditeli.maximumtest.ru` | Раздел для родителей (→ 301 на /roditeli/) | Next.js | 301 |
| `maximumtest.page.link` | Firebase Dynamic Links | Firebase | Внешний |
| `maximumtest-site.storage.yandexcloud.net` | CDN/хранилище медиа | Yandex Object Storage | Внешний |
| `maximumtest-blog.storage.yandexcloud.net` | Хранилище блога | Yandex Object Storage | Внешний |
| `staging-blog.storage.yandexcloud.net` | Staging-хранилище блога | Yandex Object Storage | Внешний |

---

## 3. Обнаруженные эндпоинты и пути

### 3.1. API-эндпоинты (из robots.txt)

| Путь | HTTP-код | Описание |
|---|---|---|
| `/api` | 500 | Корень API — Internal Server Error |
| `/api/docs` | 500 | Документация API |
| `/api/v1` | 500 | API версия 1 |
| `/api/v2` | 500 | API версия 2 |
| `/api/health` | 500 | Healthcheck |
| `/api/graphql` | 500 | GraphQL endpoint |
| `/oauth` | 200 | OAuth-страница |
| `ajax.php` | разрешён в robots.txt | AJAX-обработчик (наследие) |

### 3.2. Бизнес-пути

| Путь | Описание |
|---|---|
| `/payments/`, `/pay/` | Платёжные потоки |
| `/pay/sorry-page-payment*` | Страница ошибки оплаты |
| `/consult/prof1`, `/consult/prof2` | Консультации / профориентация |
| `/consult/chooseunp_kurs2` | Выбор курсов |
| `/search/` | Поиск по сайту |
| `/store` | Магазин |
| `/promo/*` | Промо-страницы |
| `/login.maximumtest.ru` | Личный кабинет |
| `/privacy-policy` | Политика конфиденциальности |
| `/documents` | Юридические документы |

### 3.3. OAuth-параметры (из robots.txt Clean-Param)

Обнаружены параметры, указывающие на OAuth/Auth-поток:
- `client_id`, `redirect_uri`, `response_type`, `code_challenge`, `state`, `scope`, `sign`, `api_key`

### 3.4. PII-параметры (из robots.txt Clean-Param)

Параметры передающие персональные данные через URL:
- `email`, `phone`, `fio`, `firstName`, `lastName`, `parentEmail`, `parentPhone`

---

## 4. Находки — Безопасность

---

### FINDING-01: Отсутствие HTTP Security Headers

**Критичность:** MEDIUM  
**Статус:** ✅ Confirmed  
**FP/BD:** Не является FP. Может быть BD (не настроено), но противоречит лучшим практикам.

**Описание:**  
Основной домен `maximumtest.ru` не возвращает ключевые security-заголовки:

| Заголовок | Статус | Риск |
|---|---|---|
| `Strict-Transport-Security` (HSTS) | ❌ Отсутствует | Downgrade-атаки, SSL stripping |
| `Content-Security-Policy` (CSP) | ❌ Отсутствует | XSS, инъекция скриптов |
| `X-Content-Type-Options` | ❌ Отсутствует | MIME-type sniffing |
| `X-Frame-Options` | ❌ Отсутствует | Clickjacking |
| `Referrer-Policy` | ❌ Отсутствует | Утечка URL в referer |
| `Permissions-Policy` | ❌ Отсутствует | Доступ к камере/геолокации без ограничений |

**Присутствующие заголовки:**
- `server: ycalb` — раскрытие балансировщика
- `cache-control: private, no-cache, no-store, max-age=0, must-revalidate` — корректно

**Рекомендация:** Настроить все перечисленные заголовки на уровне Yandex ALB / Next.js middleware.

---

### FINDING-02: Cookie `pathname` без флагов безопасности

**Критичность:** LOW  
**Статус:** ✅ Confirmed  
**FP/BD:** Вероятно BD (используется для навигации), но отсутствие HttpOnly/Secure — не By Design.

**Описание:**  
```
set-cookie: pathname=%2F; Path=/
```

Куки `pathname` устанавливается **без** флагов:
- ❌ `HttpOnly` — доступна из JavaScript (XSS → кража)
- ❌ `Secure` — передаётся по HTTP
- ❌ `SameSite` — уязвима для CSRF

**Контекст:** Куки `_yasc` (Yandex) корректно имеет `SameSite=None; Secure`, но **не имеет** `HttpOnly`.

**Рекомендация:** Добавить `HttpOnly; Secure; SameSite=Lax` для всех кук.

---

### FINDING-03: Раскрытие внутренней информации через API (500 Internal Server Error)

**Критичность:** MEDIUM  
**Статус:** ✅ Confirmed  
**FP/BD:** Не FP. BD для отсутствия public API, но 500 вместо 403/404 — ненормально.

**Описание:**  
Множественные API-пути возвращают `500 Internal Server Error` вместо `403 Forbidden` или `404 Not Found`:

- `/api` → 500
- `/api/docs` → 500
- `/api/v1` → 500
- `/api/v2` → 500
- `/api/health` → 500
- `/api/graphql` → 500

**Риск:**
1. Ответ 500 подтверждает **существование** API-маршрутов
2. Возможна утечка stack trace, debug-информации, путей файловой системы в теле ответа
3. GraphQL-эндпоинт может быть доступен с introspection

**Рекомендация:** Возвращать 403 или 404 для неавторизованных запросов. Отключить debug-режим.

---

### FINDING-04: PII в URL-параметрах (Query String)

**Критичность:** HIGH  
**Статус:** ⚠️ Plausible (на основе robots.txt clean-param)  
**FP/BD:** Может быть BD (legacy-интеграция), но является нарушением безопасности и 152-ФЗ.

**Описание:**  
`robots.txt` содержит `Clean-Param` для параметров с персональными данными:
```
email, phone, fio, firstName, lastName, parentEmail, parentPhone
```

Это означает, что эти параметры **попадают в URL** (GET-запросы), что приводит к:
1. **Логированию PII** в access-логах сервера, CDN, прокси
2. **Утечке в Referer** при переходах на внешние ресурсы
3. **Кэшированию** в браузерной истории
4. **Попаданию в аналитику** (Google Analytics, Яндекс.Метрика)
5. Потенциальному нарушению **152-ФЗ** (закон о персональных данных)

**Рекомендация:** Передавать PII только через POST-body. Очистить логи.

---

### FINDING-05: Staging-бакет в продакшене

**Критичность:** MEDIUM  
**Статус:** ✅ Confirmed  
**FP/BD:** Не FP. Может быть BD (осознанный шаринг), но staging-ресурсы не должны быть в production.

**Описание:**  
Изображения блога ссылаются на бакет `staging-blog.storage.yandexcloud.net` — staging-хранилище отображается на production-страницах.

**Риск:**
1. Staging-бакет может иметь более слабые ACL
2. Staging-данные (тестовые, внутренние) могут быть доступны публично
3. Staging-бакет может быть удалён/очищен → битые изображения в production

**Рекомендация:** Мигрировать все ресурсы в production-бакет. Ограничить доступ к staging.

---

### FINDING-06: OAuth-параметры в URL

**Критичность:** MEDIUM  
**Статус:** ⚠️ Plausible  
**FP/BD:** Частично BD (стандартный OAuth flow), но `api_key` и `sign` в URL — нет.

**Описание:**  
Обнаружены OAuth-параметры через robots.txt clean-param:
```
client_id, redirect_uri, response_type, code_challenge, state, scope, sign, api_key
```

Наличие `api_key` и `sign` в URL-параметрах:
1. `api_key` в URL может логироваться и утекать через Referer
2. `sign` — криптографическая подпись — не должна быть в URL
3. `redirect_uri` — требует строгой валидации для предотвращения Open Redirect

**Рекомендация:** Передавать `api_key` и `sign` через заголовки. Валидировать `redirect_uri` по whitelist.

---

### FINDING-07: Устаревший nginx (mobapp.maximumtest.ru)

**Критичность:** HIGH  
**Статус:** ✅ Confirmed  
**FP/BD:** Не FP, не BD.

**Описание:**  
```
server: nginx/1.17.3
last-modified: Tue, 22 Mar 2022 12:15:14 GMT
```

- **nginx 1.17.3** выпущен в **августе 2019** (~7 лет назад)
- Версия имеет известные CVE (CVE-2019-20372, CVE-2021-23017 и др.)
- Контент не обновлялся с **марта 2022**

**Риск:**
1. Эксплуатация известных уязвимостей nginx
2. Заброшенный субдомен — вектор для subdomain takeover

**Рекомендация:** Обновить nginx до актуальной версии или деактивировать субдомен.

---

### FINDING-08: Раскрытие серверного ПО

**Критичность:** LOW  
**Статус:** ✅ Confirmed  
**FP/BD:** BD (стандартное поведение), но рекомендуется скрывать.

**Описание:**  
- `maximumtest.ru` → `server: ycalb` (Yandex Cloud Application Load Balancer)
- `mobapp.maximumtest.ru` → `server: nginx/1.17.3` (с точной версией)

**Рекомендация:** Убрать заголовок `Server` или заменить на generic-значение.

---

### FINDING-09: Отсутствие security.txt

**Критичность:** INFO  
**Статус:** ✅ Confirmed  
**FP/BD:** BD (не настроено).

**Описание:**  
`/.well-known/security.txt` возвращает 404. Нет стандартного канала ответственного раскрытия уязвимостей (RFC 9116).

**Рекомендация:** Создать security.txt с контактом и scope.

---

### FINDING-10: Wildcard cookie domain

**Критичность:** LOW  
**Статус:** ✅ Confirmed  
**FP/BD:** BD (Яндекс-аналитика), но расширяет attack surface.

**Описание:**  
```
set-cookie: _yasc=...; domain=.maximumtest.ru
```

Куки устанавливаются с `domain=.maximumtest.ru`, что означает передачу на **все** субдомены, включая:
- `login.maximumtest.ru` (авторизация)
- `events.maximumtest.ru` (Tilda — третья сторона)
- `mobapp.maximumtest.ru` (устаревший nginx)

**Риск:** Компрометация любого субдомена (например, Tilda) может привести к перехвату кук.

**Рекомендация:** Ограничить scope кук конкретными субдоменами где возможно.

---

## 5. Сводная таблица критичности

| ID | Находка | Критичность | Статус | FP | BD |
|---|---|---|---|---|---|
| F-01 | Отсутствие Security Headers | MEDIUM | Confirmed | Нет | Частично |
| F-02 | Cookie без HttpOnly/Secure | LOW | Confirmed | Нет | Частично |
| F-03 | API 500 вместо 403/404 | MEDIUM | Confirmed | Нет | Нет |
| F-04 | PII в URL-параметрах | HIGH | Plausible | Нет | Частично (legacy) |
| F-05 | Staging-бакет в production | MEDIUM | Confirmed | Нет | Нет |
| F-06 | api_key/sign в URL | MEDIUM | Plausible | Нет | Частично |
| F-07 | nginx/1.17.3 (EOL + CVE) | HIGH | Confirmed | Нет | Нет |
| F-08 | Server header disclosure | LOW | Confirmed | Нет | Частично |
| F-09 | Нет security.txt | INFO | Confirmed | Нет | BD |
| F-10 | Wildcard cookie domain | LOW | Confirmed | Нет | Частично |

---

## 6. Приоритизация (план работ)

### P0 — Critical / Немедленно
1. **F-07:** Обновить nginx на `mobapp.maximumtest.ru` или деактивировать субдомен
2. **F-04:** Убрать PII из GET-параметров → перевести на POST

### P1 — High / В ближайший спринт
3. **F-01:** Внедрить HSTS, CSP, X-Frame-Options, X-Content-Type-Options
4. **F-03:** Исправить API-ответы: 500 → 403/404 для неавторизованных запросов
5. **F-06:** Перенести api_key/sign в HTTP-заголовки

### P2 — Medium / Плановое
6. **F-05:** Мигрировать staging-бакет → production
7. **F-02:** Добавить HttpOnly/Secure/SameSite на все куки
8. **F-10:** Ограничить cookie domain

### P3 — Low / При возможности
9. **F-08:** Скрыть Server header
10. **F-09:** Создать security.txt

---

## 7. Карта атакующей поверхности

```
maximumtest.ru (Next.js / ycalb)
├── /api/* ........................ API (500 errors, structure confirmed)
│   ├── /api/v1
│   ├── /api/v2
│   ├── /api/graphql
│   ├── /api/health
│   └── /api/docs
├── /oauth ....................... OAuth flow (200)
├── /payments/, /pay/ ........... Платежи
├── /consult/* .................. Консультации
├── /search/ .................... Поиск
├── /store ...................... Магазин
├── /blog/ ...................... WordPress (Bedrock)
├── /promo/* .................... Промо-лендинги
├── /uchebnik/* ................. Учебник (сотни страниц)
├── /ege/*, /oge/* .............. Курсы
├── ajax.php .................... Legacy AJAX
│
├── login.maximumtest.ru ........ Авторизация (SPA)
├── mobapp.maximumtest.ru ....... Моб. приложение (nginx/1.17.3)
├── events.maximumtest.ru ....... Мероприятия (Tilda)
├── blog.maximumtest.ru ......... → 301 /blog/
├── roditeli.maximumtest.ru ..... → 301 /roditeli/
│
├── maximumtest-site.storage.yandexcloud.net ... CDN
├── maximumtest-blog.storage.yandexcloud.net ... Блог CDN
├── staging-blog.storage.yandexcloud.net ....... Staging CDN ⚠️
└── maximumtest.page.link ...................... Firebase Dynamic Links
```

---

## 8. Технологии

| Компонент | Технология | Версия (если известна) |
|---|---|---|
| Frontend (основной) | Next.js (SSR) | — |
| Балансировщик | Yandex Cloud ALB (ycalb) | — |
| Блог | WordPress (Bedrock/Roots) | theme: maximum-v3 |
| Мобильный лендинг | nginx | 1.17.3 (2019) |
| Событийный сайт | Tilda | — |
| Хранилище | Yandex Object Storage | — |
| Аналитика | Google Analytics, Яндекс.Метрика (_yasc) | — |
| Деплинки | Firebase Dynamic Links | — |
| Мессенджеры | Telegram, WhatsApp, VK | — |

---

## 9. Методология

Данный отчёт основан исключительно на **пассивной разведке**:
- OSINT (веб-поиск, публичная информация)
- Certificate Transparency (crt.sh)
- robots.txt / sitemap.xml анализ
- HTTP response headers
- Technology fingerprinting
- Publicly accessible endpoint probing (только HTTP-коды)

**Не проводились:** активное сканирование портов, фаззинг, инъекции, перебор, слепые SSRF, DDoS.

---

*Отчёт подготовлен в рамках пассивного анализа. Все данные получены из публичных источников.*
