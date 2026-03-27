#!/bin/bash
# Preflight Check — verify environment prerequisites before starting audit
# Called at Phase-1 ENTER to validate Docker, filesystem, and tool availability.
# Usage: bash tools/preflight_check.sh <target_path> [docker_container_name]

set -euo pipefail

TARGET_PATH="${1:-}"
CONTAINER_NAME="${2:-php_audit_target}"
ERRORS=0
WARNINGS=0

echo "=== PHP Audit Preflight Check ==="
echo ""

# --- Check 1: Target path exists and contains PHP files ---
echo -n "[1/8] Target path exists... "
if [ -z "$TARGET_PATH" ]; then
    echo "❌ FAIL: No target path provided"
    ERRORS=$((ERRORS + 1))
elif [ ! -d "$TARGET_PATH" ]; then
    echo "❌ FAIL: $TARGET_PATH does not exist"
    ERRORS=$((ERRORS + 1))
else
    PHP_COUNT=$(find "$TARGET_PATH" -name "*.php" -not -path "*/vendor/*" 2>/dev/null | wc -l | tr -d ' ')
    if [ "$PHP_COUNT" -eq 0 ]; then
        echo "❌ FAIL: No .php files found (excluding vendor/)"
        ERRORS=$((ERRORS + 1))
    else
        echo "✅ PASS ($PHP_COUNT PHP files found)"
    fi
fi

# --- Check 2: Docker daemon running ---
echo -n "[2/8] Docker daemon... "
if docker info >/dev/null 2>&1; then
    echo "✅ PASS"
else
    echo "❌ FAIL: Docker daemon not running"
    ERRORS=$((ERRORS + 1))
fi

# --- Check 3: Target container exists ---
echo -n "[3/8] Target container ($CONTAINER_NAME)... "
CONTAINER_STATUS=$(docker ps -a --filter "name=$CONTAINER_NAME" --format '{{.Status}}' 2>/dev/null || echo "")
if [ -z "$CONTAINER_STATUS" ]; then
    echo "⚠️ WARN: Container not found (will be created by docker_builder)"
    WARNINGS=$((WARNINGS + 1))
elif echo "$CONTAINER_STATUS" | grep -q "Up"; then
    echo "✅ PASS (Running)"
else
    echo "⚠️ WARN: Container exists but not running ($CONTAINER_STATUS)"
    WARNINGS=$((WARNINGS + 1))
fi

# --- Check 4: Required tools available ---
echo -n "[4/8] Required tools... "
MISSING_TOOLS=""
for tool in php python3 jq curl composer; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        MISSING_TOOLS="$MISSING_TOOLS $tool"
    fi
done
if [ -z "$MISSING_TOOLS" ]; then
    echo "✅ PASS (php, python3, jq, curl, composer)"
else
    echo "❌ FAIL: Missing:$MISSING_TOOLS"
    ERRORS=$((ERRORS + 1))
fi

# --- Check 5: WORK_DIR writable ---
echo -n "[5/8] WORK_DIR writable... "
WORK_DIR="${WORK_DIR:-/tmp/php_audit_workdir}"
if [ -d "$WORK_DIR" ] && [ -w "$WORK_DIR" ]; then
    echo "✅ PASS ($WORK_DIR)"
elif mkdir -p "$WORK_DIR" 2>/dev/null; then
    echo "✅ PASS (created $WORK_DIR)"
else
    echo "❌ FAIL: Cannot create/write to $WORK_DIR"
    ERRORS=$((ERRORS + 1))
fi

# --- Check 6: Disk space ---
echo -n "[6/8] Disk space... "
AVAIL_KB=$(df -k "$WORK_DIR" 2>/dev/null | tail -1 | awk '{print $4}')
if [ -n "$AVAIL_KB" ] && [ "$AVAIL_KB" -gt 524288 ]; then
    AVAIL_MB=$((AVAIL_KB / 1024))
    echo "✅ PASS (${AVAIL_MB}MB available)"
elif [ -n "$AVAIL_KB" ]; then
    AVAIL_MB=$((AVAIL_KB / 1024))
    echo "⚠️ WARN: Only ${AVAIL_MB}MB available (recommend >512MB)"
    WARNINGS=$((WARNINGS + 1))
else
    echo "⚠️ WARN: Could not determine disk space"
    WARNINGS=$((WARNINGS + 1))
fi

# --- Check 7: Schemas directory ---
echo -n "[7/8] Schemas directory... "
SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SCHEMA_COUNT=$(find "$SCRIPT_DIR/schemas" -name "*.schema.json" 2>/dev/null | wc -l | tr -d ' ')
if [ "$SCHEMA_COUNT" -gt 0 ]; then
    echo "✅ PASS ($SCHEMA_COUNT schemas found)"
else
    echo "❌ FAIL: No schemas found in $SCRIPT_DIR/schemas/"
    ERRORS=$((ERRORS + 1))
fi

# --- Check 8: PHP extensions for tools ---
echo -n "[8/8] PHP extensions... "
MISSING_EXT=""
for ext in curl json mbstring; do
    if ! php -m 2>/dev/null | grep -qi "^$ext$"; then
        MISSING_EXT="$MISSING_EXT $ext"
    fi
done
if [ -z "$MISSING_EXT" ]; then
    echo "✅ PASS"
else
    echo "⚠️ WARN: Missing PHP extensions:$MISSING_EXT"
    WARNINGS=$((WARNINGS + 1))
fi

# --- Summary ---
echo ""
echo "=== Preflight Summary ==="
echo "Errors:   $ERRORS"
echo "Warnings: $WARNINGS"

if [ "$ERRORS" -gt 0 ]; then
    echo "Result:   ❌ FAIL — fix $ERRORS error(s) before starting audit"
    exit 1
elif [ "$WARNINGS" -gt 0 ]; then
    echo "Result:   ⚠️ CONDITIONAL_PASS — $WARNINGS warning(s), audit can proceed with limitations"
    exit 0
else
    echo "Result:   ✅ PASS — all checks passed"
    exit 0
fi
