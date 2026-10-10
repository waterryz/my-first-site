# M1_RECON — Reconnaissance + Attack Surface
# Trigger: immediately after HUNT_CORE init
# Output: prioritized endpoint list → triggers for other modules

TARGET="{TARGET_DOMAIN}"
ID_HEADER="X-Bug-Bounty: {HANDLE}"   # BI.ZONE/Alfa/МКБ и др. ТРЕБУЮТ идентификатор запросов — без него бан (ср. Basecamp IP-block)
AUTOSCAN=on                          # off на manual-only / no-autoscanner scope (MBANK, Kaspi, Flowwow, NITEC, СберФакторинг…) → nuclei НЕ запускать

## [R1] HexStrike — запуск. ВНИМАНИЕ: katana/nuclei зависят от live_hosts (httpx), стартуют после него; остальное параллельно

subfinder_scan(domain=TARGET)
httpx_probe(target=<subs>, tech_detect=True, status_code=True, title=True)   # + additional_headers=ID_HEADER
katana_crawl(url=<live_hosts>, depth=3, js_crawl=True, headless=True)
gau_discovery(domain=TARGET)
waybackurls_discovery(domain=TARGET)
paramspider_discovery(domain=TARGET)
wafw00f_scan(url=TARGET)
# nuclei = автосканер → ТОЛЬКО при AUTOSCAN=on; на manual-only scope пропустить (правило CLAUDE.md «NO autoscanners где запрещено»)
[ "$AUTOSCAN" = "on" ] && nuclei_scan(target=<live_hosts>, severity="critical,high",
            tags="exposure,disclosure,default-login,unauth,misconfig,takeover")   # + additional_headers=ID_HEADER

## [R2] JS bundles — read IMMEDIATELY while scanners run

# НЕ хардкодить main.js (Next.js чанки хешированы → 404). Сначала вытащить все script src из HTML:
JS=$(curl -sk -H "$ID_HEADER" "https://$TARGET/" | grep -Eo 'src="[^"]+\.js"' | cut -d'"' -f2)
for u in $JS; do curl -sk -H "$ID_HEADER" "$u"; done > /tmp/bundle.js
grep -Eo '"/api/[^"]+"|"/(admin|staff|internal|system)[^"]*"' /tmp/bundle.js | sort -u
# Look for: /admin /staff /internal /system /debug /v0 roles field names with "role" "admin" "is_staff"
# Look for: hardcoded tokens, internal URLs, feature flags

## [R3] Shadow endpoints — always without auth

# HOSTS = live-хосты из R1 (httpx), не только apex: actuator/.env/.git чаще на api./staging./admin.
for host in $HOSTS; do
for ep in health healthz actuator/env actuator/heapdump metrics prometheus \
           .env .env.local .env.production openapi.json docs swagger.json \
           api-docs redoc debug debug/vars .git/config .git/HEAD backup.zip \
           api/v0/users api/v1/users api/admin api/internal api/staff; do
  STATUS=$(curl -sk -H "$ID_HEADER" -o /dev/null -w "%{http_code}" "https://$host/$ep")
  # 200=открыто; 401/403=цель для M3 + 403-bypass (ср. «Admin 403 → M2»); 500=иногда течёт stack/heapdump
  case "$STATUS" in 200|401|403|500) echo "HIT: https://$host/$ep → $STATUS"; \
    [ "$STATUS" = 200 ] && curl -sk -H "$ID_HEADER" "https://$host/$ep" | head -20;; esac
done; done

## [R4] Certificate Transparency

# crt.sh часто rate-limit/down → при пустом ответе дублировать subfinder/amass. /tmp виден только из WSL/Git Bash.
curl -s "https://crt.sh/?q=%.$TARGET&output=json" | \
  python3 -c "import sys,json; [print(r['name_value']) for r in json.load(sys.stdin)]" | \
  grep -v '\*' | sort -u > /tmp/subs.txt
# результат НЕ оставлять мёртвым — прогнать через httpx и влить в R1-пул live_hosts:
httpx_probe(target=/tmp/subs.txt, tech_detect=True, status_code=True, title=True)   # staging/dev/internal/admin/api

## [R5] Stack detection → fill immediately after httpx

# STACK: Next.js | FastAPI | Rails | PHP | Java/Spring | Node | Django | unknown
# JWT: found? → [P: M3_AUTH_BYPASS]
# GraphQL /graphql? → run introspection
# Upload endpoint? → M4_INJECT
# Payment /pay /checkout /transfer? → [P: M5_BUSINESS]
# Admin 403? → [P: M2_IDOR_BFLA] immediately

## [R6] Scoring — what to attack first

PRIORITY (top to bottom):
1. /admin/* /staff/* /internal/* → any status except 404
2. /api/users /api/accounts /api/members → GET without auth
3. All endpoints with ?id= &user_id= &order_id= in URL
4. /api/*/export /api/*/download /api/*/report
5. /api/auth/* /oauth/* /login /forgot-password /reset-password
6. /api/pay* /api/checkout /api/transfer /api/coupon /api/promo
7. Everything else with parameters

## TRIGGERS after R6

→ Found user_id / object_id → Read "C:\HUNT CORE SYSTEM\M2_IDOR_BFLA.md"
→ Found JWT / OAuth / /login → Read "C:\HUNT CORE SYSTEM\M3_AUTH_BYPASS.md"
→ Found /pay /checkout /promo → Read "C:\HUNT CORE SYSTEM\M5_BUSINESS.md"
→ Found /upload → Read "C:\HUNT CORE SYSTEM\M4_INJECT.md" (section [I5])
→ >50% endpoints behind auth → Read "C:\HUNT CORE SYSTEM\M3_AUTH_BYPASS.md" [B0] auto-register
→ After nuclei_scan → read findings → load matching module
→ 45+ min without P0 → Read "C:\HUNT CORE SYSTEM\M6_NONSTANDARD.md"
→ All modules exhausted → LOOP: expand surface (see HUNT_CORE INFINITE LOOP)
