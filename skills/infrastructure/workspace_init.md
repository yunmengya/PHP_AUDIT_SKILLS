# Skill S-002: Workspace Initialization

## IDENTITY
- **Skill ID**: S-002
- **Phase**: Pre-Phase (INIT)
- **Responsibility**: Create working directory tree, generate gate_check.sh and phase_transition.sh, initialize databases and state machine.

## INPUT CONTRACT

| Input | Source | Required | Fields Used |
|-------|--------|----------|-------------|
| `$ARGUMENTS` | User CLI input | Yes | Absolute path to target PHP project |

## FILL-IN PROCEDURE

### Step 1: Sanitize Project Name

```bash
PROJECT_NAME=$(basename "$ARGUMENTS" | tr -d '[:space:]' | tr -cd 'a-zA-Z0-9._-')
# Sanitize: remove spaces and special characters to prevent path issues
if [ -z "$PROJECT_NAME" ]; then
  PROJECT_NAME="unknown_project"
fi
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
WORK_DIR="/tmp/${PROJECT_NAME}/${TIMESTAMP}"
```

### Step 2: Create Directory Tree

```bash
mkdir -p "$WORK_DIR" || { echo "🛑 Cannot create working directory: $WORK_DIR"; exit 1; }
# Agent working directories (internal, agents write to these paths)
mkdir -p "$WORK_DIR/.audit_state"
mkdir -p "$WORK_DIR/exploits"
mkdir -p "$WORK_DIR/context_packs"
mkdir -p "$WORK_DIR/traces"
mkdir -p "$WORK_DIR/research"
# User-visible output directories (organized in Phase-5)
mkdir -p "$WORK_DIR/报告"
mkdir -p "$WORK_DIR/PoC脚本"
mkdir -p "$WORK_DIR/修复补丁"
mkdir -p "$WORK_DIR/经验沉淀"
mkdir -p "$WORK_DIR/质量报告"
mkdir -p "$WORK_DIR/原始数据"
```

### Step 3: Initialize Databases

```bash
bash tools/audit_db.sh init-memory  # Attack memory database
bash tools/audit_db.sh init-graph   # Relationship graph database
```

### Step 4: Initialize Phase State Machine

```bash
echo "INIT" > "$WORK_DIR/.audit_state/current_phase"
echo "$(date +%s)" > "$WORK_DIR/.audit_state/global_start_time"
```

### Step 5: Generate gate_check.sh

Write the following script to `$WORK_DIR/.audit_state/gate_check.sh`:

```bash
cat > "$WORK_DIR/.audit_state/gate_check.sh" << 'GATE_EOF'
#!/bin/bash
# Usage: bash gate_check.sh <GATE_NAME> <file1> [file2] ...
# Returns: exit 0 on PASS, exit 1 on FAIL
# Validates: existence, non-empty, JSON syntax, directory non-empty, UTF-8 encoding
GATE_NAME="$1"; shift
ALL_PASS=true
for f in "$@"; do
  if [ ! -f "$f" ] && [ ! -d "$f" ]; then
    echo "❌ ${GATE_NAME} FAIL: missing ${f}"
    ALL_PASS=false
  elif [ -d "$f" ]; then
    # Directory: must contain at least 1 file
    if [ -z "$(ls -A "$f" 2>/dev/null)" ]; then
      echo "❌ ${GATE_NAME} FAIL: empty directory ${f}"
      ALL_PASS=false
    fi
  elif [ -f "$f" ] && [ ! -s "$f" ]; then
    echo "❌ ${GATE_NAME} FAIL: empty file ${f}"
    ALL_PASS=false
  elif [ -f "$f" ] && [[ "$f" == *.json ]]; then
    # JSON: syntax check
    jq empty "$f" 2>/dev/null || { echo "❌ ${GATE_NAME} FAIL: invalid JSON ${f}"; ALL_PASS=false; continue; }
    # JSON: encoding check (must be UTF-8 or ASCII)
    ENCODING=$(file --mime-encoding "$f" 2>/dev/null | awk -F': ' '{print $2}')
    if [[ "$ENCODING" != "utf-8" && "$ENCODING" != "us-ascii" ]]; then
      echo "❌ ${GATE_NAME} FAIL: non-UTF-8 encoding (${ENCODING}) in ${f}"
      ALL_PASS=false
    fi
    # JSON: schema spot-check for critical files
    BASENAME=$(basename "$f")
    case "$BASENAME" in
      environment_status.json)
        jq -e '.php_version and .framework and .framework_version' "$f" >/dev/null 2>&1 \
          || { echo "❌ ${GATE_NAME} FAIL: missing required fields in ${BASENAME}"; ALL_PASS=false; } ;;
      priority_queue.json)
        jq -e 'type == "array"' "$f" >/dev/null 2>&1 \
          || { echo "❌ ${GATE_NAME} FAIL: invalid structure in ${BASENAME} (must be array)"; ALL_PASS=false; } ;;
      exploit_summary.json)
        jq -e 'has("total_audited") and has("exploits")' "$f" >/dev/null 2>&1 \
          || { echo "❌ ${GATE_NAME} FAIL: missing required fields in ${BASENAME}"; ALL_PASS=false; } ;;
    esac
  fi
done
if $ALL_PASS; then
  echo "✅ ${GATE_NAME} PASS"
  exit 0
else
  echo "❌ ${GATE_NAME} FAIL"
  exit 1
fi
GATE_EOF
chmod +x "$WORK_DIR/.audit_state/gate_check.sh"
```

### Step 6: Generate phase_transition.sh

Write the following script to `$WORK_DIR/.audit_state/phase_transition.sh`:

```bash
cat > "$WORK_DIR/.audit_state/phase_transition.sh" << 'PHASE_EOF'
#!/bin/bash
# Usage: bash phase_transition.sh <EXPECTED_CURRENT> <NEXT_PHASE>
# Enforces: can only move from EXPECTED_CURRENT → NEXT_PHASE
STATE_FILE="$(dirname "$0")/current_phase"
CURRENT=$(cat "$STATE_FILE" 2>/dev/null || echo "UNKNOWN")
EXPECTED="$1"
NEXT="$2"
if [ "$CURRENT" != "$EXPECTED" ]; then
  echo "🚫 PHASE TRANSITION BLOCKED: current=$CURRENT, expected=$EXPECTED, requested=$NEXT"
  echo "🚫 You MUST complete $EXPECTED before entering $NEXT"
  exit 1
fi
echo "$NEXT" > "$STATE_FILE"
echo "✅ Phase transition: $CURRENT → $NEXT"
exit 0
PHASE_EOF
chmod +x "$WORK_DIR/.audit_state/phase_transition.sh"
```

## OUTPUT CONTRACT

| Output | Path | Description |
|--------|------|-------------|
| Working directory tree | `$WORK_DIR/` | 12 subdirectories created |
| gate_check.sh | `$WORK_DIR/.audit_state/gate_check.sh` | Gate validation script (executable) |
| phase_transition.sh | `$WORK_DIR/.audit_state/phase_transition.sh` | State machine transition script (executable) |
| current_phase | `$WORK_DIR/.audit_state/current_phase` | Contains "INIT" |
| global_start_time | `$WORK_DIR/.audit_state/global_start_time` | Unix timestamp |
| Memory DB | via audit_db.sh | Attack memory + graph initialized |

## EXAMPLES

✅ GOOD — Complete initialization:
```
$WORK_DIR = /tmp/my_laravel_app/20240101_120000/
├── .audit_state/
│   ├── current_phase          → "INIT"
│   ├── global_start_time      → "1704110400"
│   ├── gate_check.sh          → executable, 50 lines
│   └── phase_transition.sh    → executable, 15 lines
├── exploits/
├── context_packs/
├── traces/
├── research/
├── 报告/
├── PoC脚本/
├── 修复补丁/
├── 经验沉淀/
├── 质量报告/
└── 原始数据/
```

❌ BAD — Missing directories:
```
$WORK_DIR = /tmp/my_app/20240101/
├── exploits/
└── reports/            ← WRONG: should be 报告/ (Chinese)
                        ← MISSING: .audit_state/, context_packs/, traces/, etc.
```

❌ BAD — Scripts not executable:
```
.audit_state/gate_check.sh    → permission: -rw-r--r-- (WRONG, must be -rwxr-xr-x)
.audit_state/phase_transition.sh → permission: -rw-r--r-- (WRONG)
```

## ERROR HANDLING

| Error | Action |
|-------|--------|
| Cannot create WORK_DIR (permission denied) | Print "🛑 Cannot create working directory", abort |
| audit_db.sh init-memory fails | Print warning, continue (non-critical for Phase-1) |
| basename returns empty string | Use fallback "unknown_project" |

## NOTE

> Phase-produced JSON files (e.g., `environment_status.json`, `team4_progress.json`) and `audit_session.db` do NOT need pre-creation — each agent creates them on first write. JSON Schema files in `schemas/` are format constraints only, not runtime dependencies.
