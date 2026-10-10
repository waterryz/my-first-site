# M7_OMEGA — Burp Pro + ZAP (when both are running)
# Trigger: Burp localhost:1337 responds + ZAP localhost:8090 responds
# Needs: TARGET · TOKEN · COLLAB_URL · SCAN_IDs · LIVE_HOSTS (from M1_RECON)
#
# ⚠️ PRECONDITION — АКТИВНЫЙ СКАНЕР. Запускать O1/O2 (Burp audit / ZAP ascan+ajaxSpider)
#    ТОЛЬКО на программах, где автосканирование ЯВНО разрешено. Сначала проверить scope.
#    Manual-only / NO-autoscan (MBANK, СберФакторинг, Flowwow, Kaspi, NITEC-VDP, Yandex,
#    МКБ и др.) → O1/O2 ПРОПУСТИТЬ: только passive proxy + ручные расширения (O3/O7/O8/O9).

TARGET="target.com"            # bare host, NO scheme (иначе https://https:// во всех URL ниже)
TOKEN="Bearer JWT"
COLLAB_URL="xyz.oastify.com"   # from Burp Collaborator Client

## [O0] Health check

curl -s http://localhost:1337/v0.1/ | python3 -c "import sys,json; d=json.load(sys.stdin); print('BURP OK:', d.get('version',''))" || echo "BURP DOWN"
curl -s "http://localhost:8090/JSON/core/view/version/" || echo "ZAP DOWN"

## [O1] Burp scope + launch scans

# NB: в Burp REST API (v0.1) НЕТ эндпоинта PUT /target/scope — он отдаёт 404.
#     Scope задаётся ПРЯМО в теле POST /scan через "scope":{"include":[...],"exclude":[...]}.
#     Без этого скан уходит за scope (риск нарушения правил программы).

# Launch scan on each live host (LIVE_HOSTS from M1_RECON)
for HOST in $LIVE_HOSTS; do
  TASK=$(curl -s -X POST "http://localhost:1337/v0.1/scan" \
    -H "Content-Type: application/json" \
    -d "{\"urls\":[\"https://$HOST\"],
         \"scope\":{\"include\":[{\"rule\":\"https://$HOST\"}],\"exclude\":[]},
         \"scan_configurations\":[{\"name\":\"Audit coverage - maximum\",\"type\":\"NamedConfiguration\"}]}")
  echo "Burp scan started: $HOST → task $(echo $TASK | python3 -c 'import sys,json; print(json.load(sys.stdin).get(\"task_id\",\"?\"))')"
done

## [O2] ZAP spider + active scan + Replacer (with auth)

# Scope
curl -s "http://localhost:8090/JSON/context/action/includeInContext/?contextName=target&regex=https://.*$TARGET.*"
curl -s "http://localhost:8090/JSON/context/action/excludeFromContext/?contextName=target&regex=.*(logout|signout|delete|remove|unsubscribe|password|email|transfer|pay|purchase|order|invite).*"

# Auth token in Replacer
curl -s "http://localhost:8090/JSON/replacer/action/addRule/" \
  --data-urlencode "description=auth" \
  --data-urlencode "enabled=true" \
  --data-urlencode "matchType=REQ_HEADER" \
  --data-urlencode "matchString=Authorization" \
  --data-urlencode "matchRegex=false" \
  --data-urlencode "replacement=$TOKEN"

# Spider
curl -s "http://localhost:8090/JSON/spider/action/scan/?url=https://$TARGET&contextName=target&recurse=true"
curl -s "http://localhost:8090/JSON/ajaxSpider/action/scan/?url=https://$TARGET&contextName=target"

# Active scan — ТОЛЬКО после завершения spider (иначе неполное покрытие).
# Дождаться: GET /JSON/spider/view/status/?scanId=<id> == 100, потом запускать ascan.
curl -s "http://localhost:8090/JSON/ascan/action/scan/?url=https://$TARGET&contextName=target&recurse=true"

echo "ZAP + Burp running in background → continue M2/M3/M4 while they scan"

## [O3] Burp extensions — launch via computer-use

# computer-use → Burp → Extender → tabs:
# 1. Param Miner: Proxy History → RMB on request → Extensions → Param Miner → Guess everything
# 2. Backslash Powered Scanner: BPS → Scan selected items
# 3. HTTP Request Smuggler: Extensions → HTTP Request Smuggler → Smuggle probe
# 4. Autorize: Extensions → Autorize → paste second_user_token → Start
# 5. JWT Editor: click on JWT request → JWT Editor tab → attacks

## [O4] Collaborator URL — get it now

# computer-use → Burp → Collaborator → Copy to clipboard
# Use $COLLAB_URL in all M4 SSRF / M3 Host Header / M4 XSS

## [O5] Read Burp alerts (ongoing)

python3 - <<'EOF'
import urllib.request, json, sys

for task_id in range(1, 10):
    try:
        url = f"http://localhost:1337/v0.1/scan/{task_id}"
        with urllib.request.urlopen(url, timeout=3) as r:
            d = json.loads(r.read())
        for ev in d.get("issue_events", []):
            issue = ev.get("issue", {})
            sev = issue.get("severity", "")
            if sev in ("critical", "high"):
                print(f"[BURP][{sev.upper()}] {issue['name']} | {issue.get('path','')}")
    except:
        pass
EOF


# React to Burp findings:
# SQL Injection → M4_INJECT [I1] sqlmap immediately
# XSS → M4_INJECT [I6] dalfox
# SSRF → M4_INJECT [I3] internal network
# Path traversal → M4_INJECT [I4] LFI chain
# Auth bypass → M3_AUTH_BYPASS
# IDOR → M2_IDOR_BFLA

## [O6] ZAP harvest — read after 20+ min

# High alerts
curl -s "http://localhost:8090/JSON/alert/view/alerts/?baseurl=https://$TARGET&riskId=3" | \
  python3 -c "
import sys, json
d = json.load(sys.stdin)
for a in d.get('alerts', []):
    print(f\"[ZAP][HIGH] {a['alert']} | {a['url'][:80]}\")
"

# Spider results → new endpoints → M2/M4
curl -s "http://localhost:8090/JSON/spider/view/results/?scanId=0" | \
  python3 -c "
import sys, json
d = json.load(sys.stdin)
for u in d.get('urls', []):
    if any(x in u for x in ['/admin','/api','/internal','/export','id=','user_id=']):
        print(u)
"

## [O7] Autorize — IDOR/BFLA via Burp

# computer-use → Burp → Autorize tab:
# 1. Paste user_B token in "Auth Header" field
# 2. Intercept → browse as user_A → Autorize automatically replays with user_B
# 3. Look for "Bypassed!" in the table
# 4. Red row = user_B sees user_A data = IDOR P0

## [O8] Turbo Intruder — race conditions

# computer-use → Burp → Proxy History → request to /redeem-coupon → RMB → Send to Turbo Intruder
# Script: concurrent requests → max 50 threads → check duplicates
#

## [O9] JWT Editor via computer-use

# computer-use → Burp → Proxy History → request with JWT → Send to Repeater
# JWT Editor tab:
# Attack 1: alg:none → "none" button → Remove signature → Send
# Attack 2: HS256 brute → JOSEPH tool (if installed)
# Attack 3: Embedded JWK → Generate RSA → Embed → Sign → Send
# Attack 4: JKU hijack → serve own JWKS → forge admin JWT
#

## TRIGGERS

→ Burp finds SQLi → M4_INJECT [I1] sqlmap immediately
→ Burp finds SSRF → M4_INJECT [I3] internal network
→ Autorize "Bypassed" → M2_IDOR_BFLA detailed PoC
→ JWT Editor success → M3_AUTH_BYPASS full exploitation
