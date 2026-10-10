# Hunt Core System: *.ispring.ru — Находки

> Дата: 2026-10-10
> Цель: `*.ispring.ru` / `api-learn.ispringlearn.ru`
> Метод: Пассивный recon — OpenAPI spec, публичные сканеры, CVE базы
> Активного тестирования НЕ проводилось

---

## Исключения (out of scope)

- Brute Force
- Blind SSRF
- DDoS

---

## Источники данных

| # | Источник | URL | Что получено |
|---|---|---|---|
| S-1 | OpenAPI 3.0.0 spec | `https://api-learn.ispringlearn.ru/docs/rest-api` | Полная схема REST API: 137 endpoints, request/response schemas |
| S-2 | UpGuard Security Report | `https://www.upguard.com/security-report/ispring-solutions` | Внешний скан заголовков, TLS, DNS, репутация |
| S-3 | Docs iSpring (RU) | `https://docs.ispring.ru/pages/viewpage.action?pageId=18808961` | Структура API: разделы, SOAP/REST, вебхуки |
| S-4 | NVD / CVE базы | `https://nvd.nist.gov/vuln/detail/cve-2025-23922` | CVE для iSpring Embedder |
| S-5 | GitHub API Profile | `https://github.com/api-evangelist/ispring` | Сторонний профиль API, хосты, auth flow |

---

## Раздел 1 — Подтверждённые находки (Confirmed)

Это факты, подтверждённые внешними источниками. Не гипотезы.

---

### C-01. CSP: unsafe-inline без nonce + unsafe-eval

**Где нашёл:** UpGuard Security Report (S-2)
**Что именно:**
- Content-Security-Policy содержит `unsafe-inline` без nonce/hash
- Content-Security-Policy содержит `unsafe-eval`

**Почему это проблема:** `unsafe-inline` разрешает инлайн-скрипты — XSS-пейлоад выполнится без блокировки CSP. `unsafe-eval` разрешает `eval()`, `Function()`, `setTimeout("string")`.

**FP:** Нет. Внешний скан, данные публичны.
**BD:** Вероятно частично. LMS может требовать `unsafe-inline` для рендеринга SCORM-контента. `unsafe-eval` сложнее оправдать.

---

### C-02. X-Frame-Options не установлен

**Где нашёл:** UpGuard Security Report (S-2)
**Что именно:** Заголовок `X-Frame-Options` не установлен в `DENY` или `SAMEORIGIN`.

**Почему это проблема:** Страницы можно встроить в `<iframe>` → clickjacking на авторизованных пользователей.

**FP:** Нет.
**BD:** Возможно. iSpring может намеренно разрешать iframe-встраивание для интеграции курсов в сторонние порталы.

---

### C-03. X-Content-Type-Options отсутствует

**Где нашёл:** UpGuard Security Report (S-2)
**Что именно:** Заголовок `X-Content-Type-Options: nosniff` не установлен.

**Почему это проблема:** Браузер может MIME-sniff ответы, интерпретируя данные как исполняемый код.

**FP:** Нет.
**BD:** Нет. Нет причин не ставить этот заголовок.

---

### C-04. HSTS без includeSubDomains

**Где нашёл:** UpGuard Security Report (S-2)
**Что именно:** HSTS заголовок есть, но без директивы `includeSubDomains`.

**Почему это проблема:** Поддомены (`docs.ispring.ru`, `api-learn.ispringlearn.ru`, клиентские аккаунты) не защищены HSTS — могут обслуживаться по HTTP.

**FP:** Нет.
**BD:** Возможно. Если есть legacy-поддомены без HTTPS-сертификата, `includeSubDomains` сломает их.

---

### C-05. Нет HSTS Preload

**Где нашёл:** UpGuard Security Report (S-2)
**Что именно:** Домен не в HSTS preload list.

**Почему это проблема:** Первое подключение (до кеширования HSTS) уязвимо к SSL stripping.

**FP:** Нет.
**BD:** Да. Preload — opt-in и необратимый. Многие вендоры не используют.

---

### C-06. DNSSEC не включён

**Где нашёл:** UpGuard Security Report (S-2)
**Что именно:** DNSSEC не настроен для домена.

**Почему это проблема:** DNS-ответы можно подделать → перенаправление трафика на фишинговые сайты.

**FP:** Нет.
**BD:** Вероятно. Глобальное покрытие DNSSEC ~30%. Многие вендоры не внедряют.

---

### C-07. Индикатор infostealer-малвари на инфраструктуре

**Где нашёл:** UpGuard Security Report (S-2)
**Что именно:** Цитата из отчёта:
> "Infostealer malware detected on systems associated with the organization, indicating a potential data breach."

**Почему это проблема:** Если актуально — скомпрометированы учётные данные, токены, ключи API.

**FP:** Возможно. UpGuard не раскрывает методологию. "Associated with the organization" может означать устройства сотрудников, а не production-серверы.
**BD:** Нет.

---

### C-08. CVE-2025-23922 — CSRF в iSpring Embedder (WordPress plugin)

**Где нашёл:** NVD (S-4)
**Что именно:** WordPress-плагин "Harsh iSpring Embedder" (≤ 1.0) — CSRF, позволяющий загрузку web shell. CVSS 10.0. Патча нет.

**Почему это проблема:** Полный захват WordPress-сайтов, использующих плагин для встраивания iSpring-контента.

**FP:** Нет. Публичный CVE.
**BD:** Нет.
**Примечание:** Adjacent finding — это плагин экосистемы, не core `*.ispring.ru`.

---

### C-09. Deprecated API endpoints остаются активными

**Где нашёл:** OpenAPI spec (S-1) — поле `deprecated: true` на endpoints
**Что именно:** Следующие endpoints помечены deprecated, но присутствуют в текущей спеке:

```
GET  /content
GET  /contents
POST /contents
GET  /content/{contentId}
GET  /content/{contentId}/final_statuses
GET  /courses/modules
GET  /courses_tree
GET  /users
```

**Почему это проблема:** Deprecated endpoints могут иметь более слабую валидацию, чем их замены. Двойная поверхность атаки.

**FP:** Нет. Факт из спеки.
**BD:** Частично. Обратная совместимость — нормально. Отсутствие hard removal date — риск.

---

### C-10. 404 vs 403 — различимые ошибки позволяют перечисление ID

**Где нашёл:** OpenAPI spec (S-1) — секция responses на endpoints
**Что именно:** Спека определяет разные ответы:
- `403 PermissionDenied` — объект существует, доступа нет
- `404 NotFound` — объект не существует

Конкретные 404-сообщения из спеки: `"Unknown content item"`, `"Issued certificate not found"`, `"Session not found"`.

**Почему это проблема:** Атакующий может перебирать ID и различать "существует, но нет доступа" от "не существует".

**FP:** Нет. Факт из спеки.
**BD:** Да. REST-конвенция — 404 для not found, 403 для forbidden. Возвращать 404 для обоих — hardening, который большинство API не делает.

---

### C-11. Нет ограничений пагинации на bulk-list endpoints

**Где нашёл:** OpenAPI spec (S-1) — параметры endpoints
**Что именно:** Следующие endpoints не имеют обязательной пагинации, все фильтры опциональны:

```
GET /enrollment
GET /gamification/points
GET /group
GET /department
GET /learning_track/courses
GET /report/active-users-by-period
```

Массивные параметры (`contentItemIds[]`, `userIds[]`, `courseIds[]`) не имеют `maxItems`.

**Почему это проблема:** Можно выгрузить весь датасет одним запросом.

**FP:** Возможно. Сервер может иметь runtime-лимиты, не описанные в спеке.
**BD:** Частично. Пагинация может существовать на уровне сервера.

---

### C-12. SOAP + REST — двойная поверхность атаки

**Где нашёл:** Docs iSpring (S-3) — страница API overview
**Что именно:** Одновременно активны:
- REST API (OpenAPI 3.0.0)
- SOAP API (WSDL 2.0 и 3.0)

Оба покрывают: users, groups, departments, content, assignments, points, events.

**Почему это проблема:** Патч на одном API может не быть применён на другом. Авторизационные модели могут различаться.

**FP:** Нет.
**BD:** Да. Обратная совместимость с legacy-интеграциями.

---

### C-13. XML accepted на REST endpoints

**Где нашёл:** OpenAPI spec (S-1) — `consumes` / `requestBody.content`
**Что именно:** Несколько REST endpoints принимают `application/xml` наряду с `application/json`:

```
POST /course/list
POST /contents
POST /course/tree
POST /api/v3/token
```

**Почему это проблема:** XML-парсинг = потенциальный вектор для XXE (XML External Entity). Но это **гипотеза**, не подтверждённый эксплойт.

**FP:** Возможно. Современные фреймворки отключают external entities по умолчанию.
**BD:** Частично. Принимать XML на REST, когда основной формат JSON — расширяет поверхность без необходимости.

---

## Раздел 2 — Гипотезы из спеки (Needs Active Testing)

Это **НЕ найденные уязвимости**. Это паттерны в OpenAPI-спецификации, которые **могут** указывать на проблемы. Без отправки запросов к API подтвердить или опровергнуть нельзя.

---

### H-01. Поле `role` принимается при создании/обновлении пользователя

**Где увидел:** OpenAPI spec (S-1) — schema `NewUser` и `UpdateUser`
**Что в спеке:**

```
POST /user       — body принимает: role, roleId, roles, manageableDepartmentIds, groupIds
POST /user/{id}  — body принимает: role, roleId, roles, manageableDepartmentIds, groupIds
```

`role` enum: `learner`, `administrator`, `department_administrator`, `publisher`, `custom`, `owner`, `supervisor`, `studio_author`

**Гипотеза:** Если сервер не фильтрует эти поля по роли вызывающего — можно повысить себе роль до `administrator`.
**Что нужно проверить:** Отправить `POST /user/{myId}` с `role: "administrator"` токеном learner'а. Если 200 и роль сменилась → уязвимость. Если 403 → FP.

---

### H-02. userId как path parameter без проверки ownership

**Где увидел:** OpenAPI spec (S-1) — path definitions
**Что в спеке:** 7 endpoints принимают `{userId}` в пути:

```
GET    /user/{userId}
POST   /user/{userId}
DELETE /user/{userId}
POST   /user/{userId}/password
POST   /user/{userId}/status
POST   /user/{userId}/subordination
GET    /user/{userId}/v2
```

Спека определяет `403 PermissionDenied`, но не описывает, по какой логике сервер решает — можно или нет.

**Гипотеза:** Если авторизация не проверяет, что вызывающий имеет право на этот конкретный userId — IDOR.
**Что нужно проверить:** Два пользователя, разные роли. User A запрашивает `GET /user/{userB_id}`. Если отдаёт профиль → IDOR. Если 403 → FP.

---

### H-03. Смена пароля без текущего пароля

**Где увидел:** OpenAPI spec (S-1) — schema `UpdateUserPassword`
**Что в спеке:**

```
POST /user/{userId}/password
Body: { "password": "<new>" }
```

Нет поля `currentPassword` или механизма re-authentication.

**Гипотеза:** Если неадмин может вызвать этот endpoint для чужого userId → account takeover.
**Что нужно проверить:** Вызвать с non-admin токеном для чужого userId. Если принимает → уязвимость. Если 403 для non-admin → BD (админы легитимно сбрасывают пароли).

---

### H-04. Массовые операции terminate/deactivate без scope

**Где увидел:** OpenAPI spec (S-1) — path definitions
**Что в спеке:**

```
POST /users/activate      — принимает массив userIds
POST /users/deactivate    — принимает массив userIds
POST /users/terminate     — принимает массив userIds
```

Нет документированного ограничения по department scope.

**Гипотеза:** department_administrator может отправить userIds из чужого department.
**Что нужно проверить:** Вызвать с dept-admin токеном, передав userId из другого department. Если выполняет → уязвимость. Если 403 → FP.

---

### H-05. Произвольные enrollments

**Где увидел:** OpenAPI spec (S-1) — schema `NewEnrollment`
**Что в спеке:**

```
POST /enrollment — body: { "courseIds": [...], "learnerIds": [...] }
POST /enrollment/delete — body: { "enrollmentIds": [...] }
```

**Гипотеза:** Можно записать любого пользователя на любой курс или удалить чужой enrollment.
**Что нужно проверить:** Создать enrollment для user из чужого department. Если создаётся → уязвимость.

---

### H-06. Фальсификация оценок и статусов

**Где увидел:** OpenAPI spec (S-1) — schemas `UpdateCourseStatus`, `AssignmentAttemptGrades`
**Что в спеке:**

```
POST   /statistics/course  — body: courseId, enrollmentIds, status, awardedScore (0-100)
POST   /statistics/module  — body: enrollmentIds, moduleStatuses
DELETE /statistics/module  — сброс статистики модуля
POST   /assignments/attempts/grade — выставление оценок
```

**Гипотеза:** Если нет проверки, что вызывающий — инструктор/админ этого курса → можно подделать прохождение compliance-тренингов.
**Что нужно проверить:** Обновить статус чужого enrollment токеном другого пользователя.

---

### H-07. Webhook callbackUrl без валидации

**Где увидел:** OpenAPI spec (S-1) — schema `SubscriberRequest`
**Что в спеке:**

```
POST /webhook/register
Body: { "subscriberName": "...", "callbackUrl": "...", "secret": "..." }
```

`callbackUrl` — plain string, формат не указан. Есть flow подтверждения (`/webhook/code/send` → `/webhook/confirm`).

**Гипотеза:** Если сервер при подтверждении не валидирует IP (приватные диапазоны) и следует редиректам → confirmed SSRF (не blind, т.к. код подтверждения доставляется на URL).
**Что нужно проверить:** Зарегистрировать webhook с `callbackUrl` = redirect chain → internal IP.

---

### H-08. Инъекция permissions в appraisal sessions

**Где увидел:** OpenAPI spec (S-1) — performance-management endpoints
**Что в спеке:**

```
POST /performance-management/appraisal/session/{id}/permissions/add
POST /performance-management/appraisal/session/{id}/employee-card/reviewer/replace
```

**Гипотеза:** Добавить себя ревьюером на чужую 360° сессию → доступ к HR-данным.
**Что нужно проверить:** Вызвать permissions/add для чужой сессии.

---

## Итог

| Категория | Количество | Статус |
|---|---|---|
| **Confirmed** (внешние сканы + факты из спеки) | 13 | Не требуют active testing |
| **Гипотезы** (паттерны из спеки) | 8 | Требуют отправки запросов к API |
| **Итого** | **21** | |

| BD (by design) | 4 | C-05, C-06, C-10, C-12 |
| Partial BD | 5 | C-01, C-04, C-09, C-11, C-13 |
| FP | 0 подтверждённых | Гипотезы H-01..H-08 могут оказаться FP после active testing |
