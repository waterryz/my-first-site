# HUNT CORE SYSTEM v3

Модульная система для автоматизированного bug bounty аудита веб-приложений через Claude Code + HexStrike AI MCP.

## Структура

| Файл | Назначение | Триггер |
|------|-----------|---------|
| `HUNT_CORE.md` | Командир: init, счётчик, фильтр P0/P1, бесконечный цикл | Старт сессии |
| `M1_RECON.md` | Рекон: subfinder, httpx, katana, JS-бандлы, shadow endpoints, crt.sh | Сразу после init |
| `M2_IDOR_BFLA.md` | IDOR read/write/enum, BFLA, mass PII, 403 bypass, trust headers | Найден user_id / object_id |
| `M3_AUTH_BYPASS.md` | JWT (alg:none, kid, jku, brute), OAuth, ATO, mass-assign, авторег | Найден JWT / OAuth / login |
| `M4_INJECT.md` | SQLi, SSTI, SSRF, LFI, XSS (stored), XXE, file upload | 500 error / SQL error / upload |
| `M5_BUSINESS.md` | Race conditions, negative amounts, step skip, price injection | Найден /pay /checkout /promo |
| `M6_NONSTANDARD.md` | HTTP smuggling, cache deception, WebSocket, Next.js, proto pollution, GraphQL | 45+ мин без P0 |
| `M7_OMEGA.md` | Burp Pro + ZAP оркестрация, Autorize, Turbo Intruder, JWT Editor | Burp :1337 отвечает |

## Быстрый старт

### 1. Предварительные требования

- **Claude Code** (CLI или Desktop App)
- **HexStrike AI MCP** — offensive-security оркестратор (111+ инструментов через WSL2 Kali)
- **Burp Suite Pro** (опционально, для M7) — localhost:1337
- **ZAP** (опционально, для M7) — localhost:8090
- **Interactsh** — OOB-коллаборатор для blind SSRF/XSS

### 2. Запуск HexStrike AI (WSL2 Kali)

```bash
wsl -d kali-linux -u root -- bash /root/runserver.sh
```

После запуска/перезапуска обязательно:
```
clear_cache → server_health
```

### 3. Запуск аудита

Открой Claude Code в директории проекта и скажи:

```
/hunt target.com
```

Или вручную:

```
Прочитай C:\path\to\hunt-core-system\HUNT_CORE.md и запусти аудит на target.com
```

Claude прочитает HUNT_CORE.md, инициализирует окружение (ZAP, HexStrike, Interactsh) и автоматически загрузит нужные модули M1-M7 по триггерам.

### 4. Настройка CLAUDE.md (рекомендуется)

Добавь в `.claude/CLAUDE.md` проекта:

```markdown
## Hunt Core

- Путь к системе: hunt-core-system/
- При команде /hunt или "аудит" — читать hunt-core-system/HUNT_CORE.md и исполнять
- Формат находок: [P0] тип | endpoint | impact
- Фильтр: только P0/P1 (см. HUNT_CORE.md FILTER)
- Молчать между находками, скрипты <= 30 строк
```

### 5. Правила scope

**Перед запуском проверь:**

- Разрешены ли автосканеры (nuclei, Burp active scan, ZAP ascan)? Если нет — установи `AUTOSCAN=off` в M1 и пропусти M7 O1/O2
- Нужен ли идентификационный заголовок (`X-Bug-Bounty`)? Добавь в `ID_HEADER`
- Manual-only программы: MBANK, СберФакторинг, Flowwow, Kaspi, NITEC и др.

### 6. Ограничения (RAILS)

- Только авторизованные хосты + *.domain
- Rate ~5 req/s, max 2 тяжёлых скана одновременно
- sqlmap: без `--dump` / `--os-shell` / `--sql-shell`
- Max 3 записи как PoC, без DoS
- Race: max 50 параллельных, одна подтверждённая попытка
- SSRF: OOB + internal PoC, не читать реальные данные пользователей

## Цикл работы

```
Init → M1 Recon → [триггеры] → M2/M3/M4/M5 параллельно
  ↓ 45 мин без P0
M6 Nonstandard → M7 Omega (если Burp/ZAP)
  ↓ все модули исчерпаны
Loop 2: staging/dev, mobile API, old versions, APK reverse
Loop 3: race, cache, smuggling, deserialization
Loop N: новый угол каждый раз → до команды "stop"
```

## Формат находок

```
[P0] IDOR-read | GET /api/users/123 | email+phone 20M users
[P1] OAuth-redirect | /oauth/authorize?redirect_uri=evil.com | code leak → ATO
```

Полный PoC по запросу: curl + response + impact.
