#!/bin/bash
# Docker Health Check Tool — runtime container health verification
# Called by Phase-4 when 3+ consecutive auditor crashes detected.
# Usage: bash tools/docker_health.sh [container_name]
# Returns: exit 0 if healthy, exit 1 if critical failure, exit 2 if degraded

set -uo pipefail

CONTAINER="${1:-php_audit_target}"
PASS=0
FAIL=0
WARN=0

echo "=== Docker Health Check: $CONTAINER ==="
echo ""

# --- 1. Container running ---
echo -n "[1/5] Container running... "
STATUS=$(docker ps --filter "name=$CONTAINER" --format '{{.Status}}' 2>/dev/null || echo "")
if echo "$STATUS" | grep -q "Up"; then
    echo "✅ $STATUS"
    PASS=$((PASS + 1))
else
    echo "❌ ${STATUS:-not found}"
    FAIL=$((FAIL + 1))
    # Attempt recovery
    echo "       → Attempting: docker start $CONTAINER"
    if docker start "$CONTAINER" >/dev/null 2>&1; then
        sleep 2
        NEW_STATUS=$(docker ps --filter "name=$CONTAINER" --format '{{.Status}}' 2>/dev/null || echo "")
        if echo "$NEW_STATUS" | grep -q "Up"; then
            echo "       → Recovery: ✅ Container started ($NEW_STATUS)"
            FAIL=$((FAIL - 1))
            WARN=$((WARN + 1))
        else
            echo "       → Recovery: ❌ Failed to start"
        fi
    else
        echo "       → Recovery: ❌ docker start failed"
    fi
fi

# --- 2. HTTP response ---
echo -n "[2/5] HTTP responds... "
HTTP_CODE=""
for port in 80 8080 8000 443; do
    HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://localhost:$port/" 2>/dev/null || echo "000")
    if [ "$HTTP_CODE" != "000" ]; then
        echo "✅ Port $port → HTTP $HTTP_CODE"
        PASS=$((PASS + 1))
        break
    fi
done
if [ "$HTTP_CODE" = "000" ]; then
    echo "❌ No HTTP response on ports 80/8080/8000/443"
    FAIL=$((FAIL + 1))
    echo "       → Attempting: docker exec $CONTAINER service apache2 restart"
    docker exec "$CONTAINER" service apache2 restart >/dev/null 2>&1 || \
    docker exec "$CONTAINER" service nginx restart >/dev/null 2>&1 || \
    docker exec "$CONTAINER" apachectl restart >/dev/null 2>&1 || true
fi

# --- 3. Database ---
echo -n "[3/5] Database connection... "
DB_OK=false
# Try MySQL
if docker exec "$CONTAINER" mysqladmin ping --silent 2>/dev/null; then
    echo "✅ MySQL responding"
    DB_OK=true
    PASS=$((PASS + 1))
fi
# Try PostgreSQL
if ! $DB_OK && docker exec "$CONTAINER" pg_isready 2>/dev/null | grep -q "accepting"; then
    echo "✅ PostgreSQL responding"
    DB_OK=true
    PASS=$((PASS + 1))
fi
# Try SQLite (just check if PHP can use it)
if ! $DB_OK && docker exec "$CONTAINER" php -r "new SQLite3('/tmp/test.db');" 2>/dev/null; then
    echo "✅ SQLite available"
    DB_OK=true
    PASS=$((PASS + 1))
fi
if ! $DB_OK; then
    echo "⚠️ Could not verify database (may not be applicable)"
    WARN=$((WARN + 1))
fi

# --- 4. Disk space ---
echo -n "[4/5] Disk space... "
DISK_PCT=$(docker exec "$CONTAINER" df -h / 2>/dev/null | tail -1 | awk '{gsub(/%/,""); print $5}' || echo "")
if [ -n "$DISK_PCT" ] && [ "$DISK_PCT" -lt 90 ]; then
    echo "✅ ${DISK_PCT}% used"
    PASS=$((PASS + 1))
elif [ -n "$DISK_PCT" ]; then
    echo "❌ ${DISK_PCT}% used (>90%)"
    FAIL=$((FAIL + 1))
    echo "       → Cleaning: docker exec $CONTAINER find /tmp -type f -delete"
    docker exec "$CONTAINER" find /tmp -type f -delete 2>/dev/null || true
else
    echo "⚠️ Could not determine disk usage"
    WARN=$((WARN + 1))
fi

# --- 5. Memory ---
echo -n "[5/5] Memory usage... "
MEM_PCT=$(docker stats --no-stream "$CONTAINER" --format '{{.MemPerc}}' 2>/dev/null | tr -d '%' || echo "")
if [ -n "$MEM_PCT" ]; then
    MEM_INT=${MEM_PCT%.*}
    if [ "$MEM_INT" -lt 95 ]; then
        echo "✅ ${MEM_PCT}%"
        PASS=$((PASS + 1))
    else
        echo "❌ ${MEM_PCT}% (>95%)"
        FAIL=$((FAIL + 1))
    fi
else
    echo "⚠️ Could not determine memory usage"
    WARN=$((WARN + 1))
fi

# --- Summary ---
echo ""
echo "=== Health Summary ==="
echo "Pass: $PASS  Fail: $FAIL  Warn: $WARN"

if [ "$FAIL" -ge 3 ]; then
    echo "Result: ❌ CRITICAL — container needs full restart/rebuild"
    echo "Action: docker stop $CONTAINER && docker rm $CONTAINER && rebuild from snapshot"
    exit 1
elif [ "$FAIL" -ge 1 ]; then
    echo "Result: ⚠️ DEGRADED — some checks failed, audit may produce incomplete results"
    exit 2
else
    echo "Result: ✅ HEALTHY — container operational"
    exit 0
fi
