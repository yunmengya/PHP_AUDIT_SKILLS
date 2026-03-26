---
name: php-audit
description: >
  This skill should be used when the user asks to "审计 PHP 代码", "PHP security audit",
  "扫描 PHP 漏洞", "PHP penetration test", "代码安全审计", "run php-audit", "php audit",
  or mentions PHP source code security analysis, vulnerability scanning, or code review
  for PHP projects. Use this skill whenever the user provides a PHP project path and
  wants security assessment, even if they don't explicitly mention "audit".
version: 2.0.0
allowed-tools: Bash Read Write Edit Glob Grep Agent Task WebFetch
---

# PHP Code Audit — Main Orchestrator

Trigger command: /php-audit $ARGUMENTS

You are the PHP code audit main orchestrator. Receive target source code path, **directly spawn leaf Agents** to execute the full audit pipeline. No intermediate dispatch layers.

## Resource Paths

All skill resources are located in the skill root directory (referred to as `SKILL_DIR`, the directory containing this `SKILL.md`).

- `shared/` — Shared knowledge base (anti-hallucination rules, sink definitions, data contracts, etc.)
  - `shared/php_specific_patterns.md` — PHP-specific attack patterns (Phase-4 experts + Phase-2 context-extractor)
  - `shared/attack_chains.md` — Attack chain patterns (Phase-4.5 attack-graph-builder + correlation-engine)
  - `shared/lessons_learned.md` — Field experience library (L3 on-demand reference)
  - `shared/known_cves.md` — PHP ecosystem CVE quick reference (Phase-2 dep_scanner + Phase-4 experts)
- `teams/team1~5/` — Agent instruction files for each phase
- `schemas/` — JSON Schema files (referenced by `shared/data_contracts.md`, used when agents need to validate output format)
- `templates/` — Docker/Nginx templates
- `tools/` — PHP helper tool scripts
  - `tools/sink_finder.php` — AST Sink scanner. Usage: `php sink_finder.php <target_dir>` (Phase-2 tool-runner)
  - `tools/trace_filter.php` — Xdebug Trace filter. Usage: `php trace_filter.php <trace_file> [sink1,sink2,...]` (Phase-3 trace-dispatcher/trace-worker)
  - `tools/payload_encoder.php` — Payload encoder. Usage: `php payload_encoder.php <payload> <encoding_type>` (Phase-4 expert agents)
  - `tools/waf_detector.php` — WAF/filter fingerprinting. Usage: `php waf_detector.php <base_url> [cookie]` (Phase-4 expert agents)
  - `tools/jwt_tester.php` — JWT security tester. Usage: `php jwt_tester.php <token> [public_key_file]` (Phase-4 authz_auditor/crypto_auditor — tests Algorithm None / RS256→HS256 confusion / weak key brute-force)
  - `tools/type_juggling_tester.php` — PHP type juggling tester. Usage: `php type_juggling_tester.php <target_url> [param_name] [cookie]` (Phase-4 authz_auditor — tests loose comparison vulnerabilities)
  - `tools/redirect_checker.php` — Open redirect checker. Usage: `php redirect_checker.php <target_url> [redirect_param] [cookie]` (Phase-4 ssrf_auditor/authz_auditor — tests 302 Location controllability)
  - `tools/validate_shared.php` — Shared resource validator. Usage: `php tools/validate_shared.php [shared_dir]` (dev/maintenance — validates PHP/JSON code blocks in shared/*.md)
  - `tools/audit_monitor.sh` — Real-time audit progress dashboard. Usage: `bash tools/audit_monitor.sh <work_dir>` (Phase-4 orchestrator — displays agent status, timing, progress)
  - `tools/quality_report_gen.sh` — Quality report generator. Usage: `bash tools/quality_report_gen.sh <work_dir>` (Phase-4.5/5 — generates QC summary report)
  - `tools/vuln_intel.sh` — Dependency vulnerability scanner (no API key required). Usage: `bash tools/vuln_intel.sh <composer.lock> [output_dir]` (Phase-4 Mini-Researcher — queries OSV.dev, cve.circl.lu for Packagist package vulnerabilities)

## Input Parameters

- `$ARGUMENTS`: Absolute path to the target PHP project source code

## Execution Flow

### Step 1: Environment Prerequisites Check

**Docker check**:
```bash
docker --version
docker compose version
docker ps >/dev/null 2>&1  # Verify daemon is running, not just installed
df -h /var/lib/docker 2>/dev/null || df -h /tmp
```

- Docker not installed → prompt user to install Docker Desktop or Docker Engine
- Docker daemon not running → prompt user to start Docker (`systemctl start docker` or open Docker Desktop)
- docker compose not installed → prompt user to install docker-compose-plugin
- Disk space < 5GB → warn insufficient space

**tmux hint** (optional): If user is not running in tmux, print "建议在 tmux 会话中运行以获得分屏效果（`Shift+Up/Down` 切换 teammate 视图）". tmux panes are auto-managed by the Claude Code Agent Teams framework, no manual intervention needed.

### Step 2: Target Path Validation

- Verify `$ARGUMENTS` path exists
- Verify path contains `.php` files (recursive search, excluding vendor/)
- Path missing or no .php files → abort and prompt user

### Step 3: Create Working Directory

```bash
PROJECT_NAME=$(basename "$ARGUMENTS" | tr -d '[:space:]' | tr -cd 'a-zA-Z0-9._-')
# Sanitize: remove spaces and special characters to prevent path issues
if [ -z "$PROJECT_NAME" ]; then
  PROJECT_NAME="unknown_project"
fi
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
WORK_DIR="/tmp/${PROJECT_NAME}/${TIMESTAMP}"
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
bash tools/audit_db.sh init-memory  # 确保记忆库存在
bash tools/audit_db.sh init-graph   # 确保关系型图表存在

# ── Phase State Machine initialization ──
echo "INIT" > "$WORK_DIR/.audit_state/current_phase"

# ── Unified Gate Check function ──
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

# ── Phase Transition function ──
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

> **Note**: Phase-produced JSON files (e.g., `environment_status.json`, `team4_progress.json`) and `audit_session.db` do NOT need pre-creation — each agent creates them on first write. JSON Schema files in `schemas/` are format constraints only, not runtime dependencies.

checkpoint.json format: see `schemas/checkpoint.schema.json`. Core fields: `completed` (completed phase list), `current` (current phase), `mode` (full/degraded), `phase_timings`, `framework`, `total_sinks`, `confirmed_vulns`, `agent_states`, `phases` (per-phase degradation tracking).

**phases Degradation Tracking**: checkpoint.json includes a `phases` object recording per-phase status:
```json
{
  "completed": ["env", "scan", "trace"],
  "current": "exploit",
  "mode": "degraded",
  "phases": {
    "phase1": {"mode": "full"},
    "phase2": {"mode": "full"},
    "phase3": {"mode": "degraded", "degradation_reason": "auth simulation failed"}
  },
  "agent_states": { ... }
}
```

When writing degradation status, ALWAYS use this path format:
```bash
jq '.phases.phase3.mode = "degraded" | .phases.phase3.degradation_reason = "REASON"' \
    "$WORK_DIR/checkpoint.json" > "$WORK_DIR/checkpoint.json.tmp" && mv "$WORK_DIR/checkpoint.json.tmp" "$WORK_DIR/checkpoint.json"
```

**agent_states Lifecycle Tracking**: checkpoint.json includes an `agent_states` object tracking each agent's runtime status:
```json
{
  "agent_states": {
    "rce_auditor": {
      "status": "passed",
      "spawned_at": "2024-01-01T10:00:00Z",
      "completed_at": "2024-01-01T10:12:00Z",
      "qc_verdict": "pass",
      "redo_count": 0,
      "pivot_triggered": false
    },
    "sqli_auditor": {
      "status": "retrying",
      "spawned_at": "2024-01-01T10:00:00Z",
      "completed_at": null,
      "qc_verdict": "fail",
      "redo_count": 1,
      "pivot_triggered": true,
      "pivot_target": "second_order_sqli"
    }
  }
}
```

Agent status enum: `spawned` → `running` → `passed` (QC pass) / `failed` (QC fail) / `retrying` (redo) / `degraded` (retries exhausted) / `timed_out` (exceeded timeout)

### Step 4: Resume Detection

Check if `${HOME}/.php_audit/${PROJECT_NAME}/` contains a recent directory with `checkpoint.json`:

- Not found → fresh start
- Found → read checkpoint, ask user whether to resume from breakpoint
  - No → use new WORK_DIR, fresh start
  - Yes → execute **Resume Protocol** (below)

**Resume Protocol:**
```
0. Validate checkpoint.json integrity before reading:
   jq empty < "$WORK_DIR/checkpoint.json" 2>/dev/null
   If invalid → check for backup:
     if [ -f "$WORK_DIR/checkpoint.json.bak" ]; then
       cp "$WORK_DIR/checkpoint.json.bak" "$WORK_DIR/checkpoint.json"
       Print: "⚠️ checkpoint.json was corrupted, restored from backup"
     else → halt, ask user to provide last known phase
   On every successful checkpoint read, save backup:
     cp "$WORK_DIR/checkpoint.json" "$WORK_DIR/checkpoint.json.bak"

1. Read checkpoint.json → get last_completed_phase + mode (full/degraded)
2. Set WORK_DIR to the previous audit directory
2.5. Re-validate runtime environment matches saved state:
   - Compare current `php -v` output with environment_status.json php_version
   - Verify Docker daemon still running: `docker ps >/dev/null 2>&1`
   - If mismatch → warn user, ask whether to continue or re-run Phase-1
3. Verify ALL artifacts from completed phases actually exist AND are valid:
   - Phase-1 done? → verify environment_status.json:
     • File exists and non-empty
     • Valid JSON (jq . < file >/dev/null 2>&1)
     • Required fields present: php_version, framework, framework_version
   - Phase-2 done? → verify priority_queue.json + context_packs/:
     • priority_queue.json is valid JSON with at least 1 entry
     • context_packs/ directory exists and has ≥1 .json file
     • Each context_pack JSON is parseable
   - Phase-3 done? → verify credentials.json:
     • File exists and is valid JSON
     • If checkpoint `.phases.phase3.mode` == "degraded": accept missing credentials
       but mark Phase-4 as NOT_VERIFIED mode
   - Phase-4 done? → verify exploits/*.json:
     • At least 1 exploit JSON exists and is valid
     • exploit_summary.json exists (generated at Phase-4 exit, not during attack)
4. Find the LAST phase whose artifacts are ALL valid → that is the TRUE resume point
5. Carry forward degradation flags:
   - If any completed phase has mode="degraded" in checkpoint → set
     DEGRADED_PHASES list and propagate to downstream phase instructions
6. Resume from the NEXT phase after the validated one
   Example: checkpoint says Phase-3 done, but credentials.json is missing
            → re-run from Phase-3 (not Phase-4)
7. IMPORTANT: Never skip a phase. Resume means "start from a verified point",
   not "mark phases as done without running them".
```

### Step 4.5: Incremental Audit Mode

Check if target project is a Git repo with a prior complete audit:

```bash
cd "$ARGUMENTS"
git rev-parse --git-dir 2>/dev/null
```

- Not a Git repo → skip incremental, run full audit
- Is a Git repo:
  1. Find most recent `${HOME}/.php_audit/${PROJECT_NAME}/*/checkpoint.json` with `current=done`
  2. Read `git_commit_hash` field from it
  3. Compare: `git diff --name-only {old_hash} HEAD -- "*.php"`
  4. If changed files < 10 and no new route files:
     - Ask user: "检测到仅 {n} 个 PHP 文件变更，是否执行增量审计？（仅审计变更文件关联的路由和 Sink）"
     - User agrees → set `INCREMENTAL_MODE=true`, record changed file list
     - User declines → full audit
  5. If changed files >= 10 or new routes exist → auto full audit

Incremental mode effects:
- Phase-2: context_extractor only extracts sinks from changed files
- Phase-2: risk_classifier only re-rates changed-file-related sinks
- Phase-4: only launch expert agents matching changed sink types
- Phase-5: report marked "增量审计" with changed file list

### Step 5: Load Shared Resources

Read shared resource files from `shared/` and `teams/qc/` (path prefix: `${SKILL_DIR}/`), inject into each agent's prompt.

**L1 MUST-inject (all agents)**: `anti_hallucination.md`, `data_contracts.md`, `evidence_contract.md`
**L2 Role-based inject**: `sink_definitions.md`, `php_specific_patterns.md`, `payload_templates.md`, `waf_bypass.md`, `framework_patterns.md`, `attack_chains.md`, `known_cves.md`, `docker_snapshot.md`, `realtime_sharing.md`, `second_order.md`, `false_positive_patterns.md`, `env_selfheal.md`, `context_compression.md`, `pivot_strategy.md`, `attack_memory.md`, `attack_memory_graph.md`
**L3 On-demand**: `lessons_learned.md`
**QC-specific**: `references/quality_check_templates.md`, `shared/output_standard.md`, `teams/qc/quality_checker.md`, `teams/qc/qc_dispatcher.md`

> Injection tier rules: see `references/agent_injection_framework.md`

### Step 6: Team + Task Dispatch

#### Step 6.1: Create Audit Team

```
TeamCreate(team_name="php-audit", description="PHP Code Audit - Target: {PROJECT_NAME}")
```

#### Step 6.2: Create Flat Tasks (Phase 1-3 Static Tasks)

Create all known tasks upfront, set blockedBy dependencies via TaskUpdate. Phase 4/5 dynamic tasks are created after Phase-2 completes.

```
Phase-1 (Environment):
  task-1: "env_detective — framework fingerprint"  activeForm="Analyzing environment"    (no deps)
  task-2: "schema_reconstructor"                   activeForm="Rebuilding DB schema"     (no deps)
  task-3: "docker_builder"                         activeForm="Building Docker env"      (blockedBy: [1, 2])
  task-4: "QC: environment build"                  activeForm="QC verifying environment" (blockedBy: [3])

Phase-2 (Recon):
  task-5: "tool_runner Psalm/Progpilot"            activeForm="Running static analysis"  (blockedBy: [4])
  task-6: "route_mapper"                           activeForm="Parsing route table"      (blockedBy: [4])
  task-7: "auth_auditor"                           activeForm="Analyzing auth mechanism" (blockedBy: [4])
  task-8: "dep_scanner"                            activeForm="Scanning dependencies"    (blockedBy: [4])
  task-9: "context_extractor"                     activeForm="Extracting sink context" (blockedBy: [5,6,7,8])
  task-10: "risk_classifier"                      activeForm="Severity classification" (blockedBy: [9])
  task-11: "QC: static recon"                     activeForm="QC verifying recon"      (blockedBy: [10])

Phase-3 (Tracing):
  task-12: "auth_simulator"                       activeForm="Simulating auth"         (blockedBy: [11])
  task-13: "trace_dispatcher"                     activeForm="Dynamic tracing"         (blockedBy: [12])
  task-14: "QC: dynamic trace"                    activeForm="QC verifying traces"     (blockedBy: [13])
```

**Resume Integration**: If checkpoint.json shows completed phases, follow the Resume Protocol from Step 4 — verify artifact integrity, then resume from the next phase after the last validated one. **NEVER mark tasks as completed without verifying their artifacts.**

#### Step 6.3: Strict Sequential Dispatch — Phase-by-Phase Blocking Execution

**🚫🚫🚫 ORCHESTRATOR IRON LAWS (HIGHEST PRIORITY — violating ANY one = audit failure) 🚫🚫🚫**

1. **You are a dispatcher, NOT an auditor.** Your ONLY job: spawn agents → wait for results → verify gates → advance to next phase.
2. **NEVER analyze code yourself.** Do NOT read target PHP source code. Do NOT discover vulnerabilities. Do NOT output any vulnerability conclusions. ALL code analysis is done by agents.
3. **NEVER skip any Phase.** MUST execute strictly: Phase-1 → Phase-2 → Phase-3 → Phase-4 → Phase-4.5 → Phase-5. Use `phase_transition.sh` to enforce.
4. **NEVER output results early.** Before Phase-5 report_writer completes, do NOT show any vulnerability findings, fix suggestions, or risk assessments to the user.
5. **MUST block-wait every Phase.** Spawn agents → wait ALL completed → run gate_check.sh → PASS before entering next phase.
6. **MUST respect blockedBy deps.** Upstream task NOT completed → downstream task MUST NOT spawn.

**Agent Prompt Construction Template** — inject this at the beginning of every spawned agent's prompt:
```
Your Task ID is #{TASK_ID}.
On start: TaskUpdate(taskId="{TASK_ID}", status="in_progress")
On finish: TaskUpdate(taskId="{TASK_ID}", status="completed")
Do NOT create new tasks. Do NOT write checkpoint.json.

--- Lifecycle ---
On shutdown_request:
1. Confirm all output files written to disk
2. Clean up temp resources
3. Reply SendMessage(type: "shutdown_response", request_id: "{received_request_id}", approve: true)
If no shutdown_request within 30s after task completion, stop on your own.

TARGET_PATH={TARGET_PATH}
WORK_DIR={WORK_DIR}

--- Shared Resources ---
{shared/anti_hallucination.md content}
{shared/data_contracts.md content}
{shared/evidence_contract.md content}

--- Your Task Instructions ---
{teams/teamN/xxx.md content}
```

---

#### Phase State Machine (MUST follow this exact order, NO jumps allowed):

```
INIT → PHASE_1 → GATE_1_PASS → PHASE_2 → GATE_2_PASS → CREATE_DYNAMIC_TASKS → PHASE_3 → GATE_3_PASS → PHASE_4 → GATE_4_PASS → PHASE_4_5 → GATE_4_5_PASS → PHASE_5 → DONE
```

#### Unified 5-Step Phase Template (ALL phases follow this exact pattern):

```
Step 1 — ENTER:  Run phase_transition.sh to verify + lock state. Print phase banner.
                 Record phase start timestamp: PHASE_START=$(date +%s)
Step 2 — SPAWN:  Read teams/teamN/*.md. Spawn agents (parallel=background, serial=foreground).
                 On each agent spawn, update checkpoint.json agent_states:
                   jq '.agent_states["AGENT_ID"] = {"status":"spawned","spawned_at":"TIMESTAMP","redo_count":0}'
Step 3 — WAIT:   Block-wait ALL agents completed. Run inline QC where required.
                 On each agent completion, update checkpoint.json agent_states:
                   jq '.agent_states["AGENT_ID"].status = "passed" | .agent_states["AGENT_ID"].completed_at = "TIMESTAMP"'
                   (Use "failed" if inline QC rejects the agent output; "passed" if accepted)
                 Check elapsed time: if (now - PHASE_START) > phase timeout → trigger timeout recovery
Step 4 — GATE:   Run gate_check.sh to verify artifacts. On FAIL → 3-level recovery.
Step 5 — EXIT:   Write checkpoint. Print pipeline view. State machine advances.
```

#### Checkpoint Write Safety

ALL checkpoint.json writes MUST use atomic write pattern to prevent corruption from concurrent access:
```bash
# Atomic write: write to temp file in same filesystem, then rename
jq 'MODIFICATIONS' "$WORK_DIR/checkpoint.json" > "$WORK_DIR/checkpoint.json.tmp" && \
    mv "$WORK_DIR/checkpoint.json.tmp" "$WORK_DIR/checkpoint.json"
# NEVER use /tmp/cp.json — temp file MUST be on same filesystem as target for atomic mv
```

During Phase-4 parallel execution, checkpoint updates MUST be serialized:
- ONLY the orchestrator writes checkpoint.json (agents use TaskUpdate/SendMessage)
- Orchestrator processes agent completions ONE AT A TIME, updating checkpoint after each

#### 3-Level Gate Failure Recovery (applies to ALL gates):

```
Level 1 — AUTO RETRY:  Re-spawn failed agent(s) with same inputs. Max 2 retries.
Level 2 — DEGRADED:    If retries exhausted, write degraded status to checkpoint:
                        jq '.phases.CURRENT_PHASE_NAME.mode = "degraded" |
                            .phases.CURRENT_PHASE_NAME.degradation_reason = "REASON" |
                            .mode = "degraded"'
                            "$WORK_DIR/checkpoint.json" > "$WORK_DIR/checkpoint.json.tmp" &&
                            mv "$WORK_DIR/checkpoint.json.tmp" "$WORK_DIR/checkpoint.json"
                        Continue to next phase with available artifacts.
                        Print: "⚠️ Phase-N degraded: {reason}. Continuing with partial data."
Level 3 — USER HALT:   If critical artifacts missing (no fallback possible), STOP.
                        Print: "🛑 Phase-N failed: {missing artifacts}. 需要用户介入。"
                        Wait for user input before continuing.
```

**🚫 During Step 3 (WAIT), the orchestrator MUST ONLY:**
- Wait for agent SendMessage events
- Reply to agent questions if needed
- Print progress: "⏳ Waiting for {agent_name}..."
- **NEVER:** Read target project code, analyze vulnerabilities, output conclusions

---

### Phase-1: 环境智能识别与构建

> 📋 Detailed flow: `references/phase1_environment.md`
> 📄 Agent instructions: `phases/phase1-env.md`

**Step 1 — ENTER:**
```bash
bash "$WORK_DIR/.audit_state/phase_transition.sh" "INIT" "PHASE_1"
# If exit code != 0 → STOP. State machine violation.
PHASE_TIMEOUT_MIN=20
echo "$(date +%s)" > "$WORK_DIR/.audit_state/phase_start_time"
```
```
打印: ━━━ 进入 Phase-1: 环境智能识别与构建 ━━━
```

**Step 2 — SPAWN:**
```
spawn env_detective        (Task #1, background, read teams/team1/env_detective.md)
spawn schema_reconstructor (Task #2, background, read teams/team1/schema_reconstructor.md)
→ WAIT for Task #1, #2 completed
spawn docker_builder       (Task #3, foreground, read teams/team1/docker_builder.md)
  — depends on #1 and #2, MUST NOT spawn until both completed
```

**Step 3 — WAIT + QC:**
```
⏳ Block-wait Task #3 completed
spawn quality_checker (Task #4, foreground, read teams/qc/quality_checker.md)
⏳ Block-wait QC result
  — QC PASS → continue
  — QC FAIL → re-send failed_items to docker_builder, check redo_count:
    # Phase-1 allows 3 retries (vs 2 for other phases) because environment setup
    # is a hard prerequisite — there is no degraded fallback. More retries before halt.
    if redo_count < 3 → increment redo_count, retry
    if redo_count >= 3 → halt for user intervention (Phase-1 cannot degrade)
```

**Step 4 — GATE:**
```bash
bash "$WORK_DIR/.audit_state/gate_check.sh" "GATE-1" "$WORK_DIR/environment_status.json"
# PASS → continue to Step 5
# FAIL → 3-level recovery (Level 3 for Phase-1: Docker MUST succeed, no degradation allowed)
```
```bash
# Version alert warnings (print only, do not block):
ALERTS=$(cat "$WORK_DIR/environment_status.json" | jq -r '.version_alerts[]? | select(.severity == "critical" or .severity == "high") | "⚠️ \(.component) \(.detected_version): \(.cve_id) [\(.severity)]"')
[ -n "$ALERTS" ] && echo "━━━ 版本安全预判警告 ━━━" && echo "$ALERTS"
```

**Step 5 — EXIT:**
```bash
bash "$WORK_DIR/.audit_state/phase_transition.sh" "PHASE_1" "GATE_1_PASS"
```
```
Write checkpoint.json: {"completed": ["env"], "current": "scan"}
Print pipeline: Phase-1 ✅ | Phase-2~5 ⏳
```

**🚫 ONLY after Step 5 completes may you proceed to Phase-2. NOTHING from Phase-2 may happen during Phase-1.**

---

### Phase-2: 静态资产侦察

> 📋 Detailed flow: `references/phase2_recon.md`
> 📄 Agent instructions: `phases/phase2-recon.md`
> 📄 Dynamic task template: `phases/phase2-tasks-dynamic.md`

**Step 1 — ENTER:**
```bash
bash "$WORK_DIR/.audit_state/phase_transition.sh" "GATE_1_PASS" "PHASE_2"
PHASE_TIMEOUT_MIN=25
echo "$(date +%s)" > "$WORK_DIR/.audit_state/phase_start_time"
```
```
打印: ━━━ 进入 Phase-2: 静态资产侦察 ━━━
```

**Step 2 — SPAWN:**
```
spawn tool_runner       (Task #5, background, read teams/team2/tool_runner.md)
spawn route_mapper      (Task #6, background, read teams/team2/route_mapper.md)
spawn auth_auditor      (Task #7, background, read teams/team2/auth_auditor.md)
spawn dep_scanner       (Task #8, background, read teams/team2/dep_scanner.md)
→ WAIT for Task #5,#6,#7,#8 ALL completed
spawn context_extractor (Task #9, foreground, read teams/team2/context_extractor.md)
→ WAIT for Task #9 completed
spawn risk_classifier   (Task #10, foreground, read teams/team2/risk_classifier.md)
→ WAIT for Task #10 completed
```

**Step 3 — WAIT + QC:**
```
spawn quality_checker (Task #11, foreground)
⏳ Block-wait QC result
  — QC PASS → continue
  — QC FAIL → identify failing agent, check redo_count:
    if redo_count < 2 → increment redo_count, re-run with failed_items
    if redo_count >= 2 → mark degraded, continue with available results
```

**Step 4 — GATE:**
```bash
bash "$WORK_DIR/.audit_state/gate_check.sh" "GATE-2" \
  "$WORK_DIR/priority_queue.json" \
  "$WORK_DIR/context_packs"
# PASS → continue
# FAIL → Level 1: retry context_extractor/risk_classifier
#         Level 2: if still fails, continue with partial context_packs (degraded)
#         Level 3: if priority_queue.json missing entirely → USER HALT
```

**Step 5 — EXIT:**
```bash
bash "$WORK_DIR/.audit_state/phase_transition.sh" "PHASE_2" "GATE_2_PASS"
```
```
Write checkpoint: {"completed": ["env", "scan"], "current": "trace"}
Print pipeline: Phase-1 ✅ | Phase-2 ✅ | Phase-3~5 ⏳
```

**🚫 ONLY now proceed to dynamic task creation + Phase-3.**

---

### Dynamic Task Creation (immediately after GATE-2 PASS)

```bash
bash "$WORK_DIR/.audit_state/phase_transition.sh" "GATE_2_PASS" "CREATE_DYNAMIC_TASKS"
```

Read `$WORK_DIR/priority_queue.json`.
Map sink_type → auditor agent using this table:

  sink_type → agent mapping:
    eval/system/exec/extract/parse_str       → rce_auditor       (teams/team4/rce_auditor.md)
    query/execute/DB::raw/whereRaw           → sqli_auditor      (teams/team4/sqli_auditor.md)
    unserialize/phar                         → deserial_auditor  (teams/team4/deserial_auditor.md)
    include/require                          → lfi_auditor       (teams/team4/lfi_auditor.md)
    file_put_contents/move_uploaded_file     → filewrite_auditor (teams/team4/filewrite_auditor.md)
    curl_exec/file_get_contents(url)         → ssrf_auditor      (teams/team4/ssrf_auditor.md)
    echo/print/template rendering            → xss_ssti_auditor  (teams/team4/xss_ssti_auditor.md)
    simplexml_load/DOMDocument               → xxe_auditor       (teams/team4/xxe_auditor.md)
    auth bypass/mass_assignment/loose compare → authz_auditor     (teams/team4/authz_auditor.md)
    config issues                            → config_auditor    (teams/team4/config_auditor.md)
    info leak                                → infoleak_auditor  (teams/team4/infoleak_auditor.md)
    MongoDB/$where/Redis                     → nosql_auditor     (teams/team4/nosql_auditor.md)
    race condition/TOCTOU                    → race_condition_auditor (teams/team4/race_condition_auditor.md)
    md5/sha1/rand/mt_rand/weak crypto        → crypto_auditor    (teams/team4/crypto_auditor.md)
    wp_ajax/xmlrpc/shortcode/WP-specific     → wordpress_auditor (teams/team4/wordpress_auditor.md)
    price tampering/flow bypass/biz logic    → business_logic_auditor (teams/team4/business_logic_auditor.md)
    CRLF injection/header splitting          → crlf_auditor      (teams/team4/crlf_auditor.md)
    CSRF/missing token                       → csrf_auditor      (teams/team4/csrf_auditor.md)
    session fixation/cookie flags            → session_auditor   (teams/team4/session_auditor.md)
    ldap_search/ldap_bind                    → ldap_auditor      (teams/team4/ldap_auditor.md)
    log injection/sensitive data in logs     → logging_auditor   (teams/team4/logging_auditor.md)

  Framework-adaptive forced dispatch (based on environment_status.json `framework` field):

    WordPress → FORCE wordpress_auditor (even without matching sinks)
    Laravel   → FORCE config_auditor (APP_DEBUG, Telescope)
                + authz_auditor (Mass Assignment, Gate/Policy)
    ThinkPHP  → FORCE rce_auditor (ThinkPHP historical RCEs)
                + sqli_auditor (ThinkPHP ORM injection risks)
    Symfony   → FORCE config_auditor (Profiler, debug routes)
    ALL frameworks → FORCE infoleak_auditor + business_logic_auditor
                   + csrf_auditor + session_auditor + logging_auditor

  Version-aware dispatch (based on environment_status.json `framework` + `php_version`):

    Laravel < 8.x   → Mass Assignment audit weight ×2 ($guarded default empty)
    Laravel >= 9.x   → Add Vite manifest leak + debug route exposure checks
    ThinkPHP 5.x     → FORCE RCE audit (think\Request RCE, s= param injection)
    ThinkPHP 3.x     → FORCE SQLi audit (M()->where() string concat, I() incomplete filter)
    WordPress < 6.0  → Trigger known Core CVE checks (match shared/known_cves.md)
    PHP < 8.0        → Type Juggling risk elevated (== loose compare + 0e hash collision)
    PHP < 5.3.4      → Null Byte truncation LFI viable (include $_GET['f'].'.php' + %00)

  **Anti-skip rule**: If priority_queue.json is empty or missing:
    → MUST proceed to Phase-4 without halting
    → Launch framework-adaptive forced agents
    → Print: "⚠️ 未检测到高优先级 Sink，但仍执行框架强制审计项"

  Create tasks for each required expert:
    task-15+: "{type} expert audit" activeForm="Auditing {type}" (blockedBy: [14])

  Create QC task (inline QC after each auditor, then final comprehensive QC):
    task-N: "QC: Phase-4 comprehensive" activeForm="Evidence verification" (blockedBy: [all exploit tasks])

  Create Phase-4.5 tasks:
    task-M:   "Attack graph builder"     (blockedBy: [N])
    task-M+1: "Cross-auditor correlation" (blockedBy: [N])
    task-M+2: "Remediation generation"    (blockedBy: [M, M+1])
    task-M+3: "PoC script generation"     (blockedBy: [M, M+1])

  Create Phase-5 tasks:
    task-N+1: "Environment cleanup"       (blockedBy: [N])
    task-N+2: "Report writing"            (blockedBy: [N])
    task-N+3: "QC: Final report"          (blockedBy: [N+1, N+2])

### Phase-3: Authentication Simulation & Dynamic Tracing

> 📋 Detailed flow: `references/phase3_tracing.md`
> 📄 Agent instructions: `phases/phase3-trace.md`

**Step 1 — ENTER:**
```bash
bash "$WORK_DIR/.audit_state/phase_transition.sh" "CREATE_DYNAMIC_TASKS" "PHASE_3"
PHASE_TIMEOUT_MIN=20
echo "$(date +%s)" > "$WORK_DIR/.audit_state/phase_start_time"
```
```
打印: ━━━ 进入 Phase-3: 鉴权模拟与动态追踪 ━━━
```

**Step 2 — SPAWN:**
```
spawn auth_simulator (Task #12, foreground, read teams/team3/auth_simulator.md)
  inject: environment_status.json + route_map.json + auth_matrix.json + Docker env info
→ WAIT for Task #12 completed
spawn trace_dispatcher  (Task #13, foreground, read teams/team3/trace_dispatcher.md)
  inject: credentials.json + context_packs/
→ WAIT for Task #13 completed
```

**Step 3 — WAIT + QC:**
```
spawn quality_checker (Task #14, foreground)
⏳ Block-wait QC result
  — QC PASS → continue
  — QC FAIL → check trace_dispatcher redo_count:
    if redo_count < 2 → increment redo_count, re-run with failed items
    if redo_count >= 2 → mark degraded, fall back to static analysis
```

**Step 4 — GATE:**
```bash
bash "$WORK_DIR/.audit_state/gate_check.sh" "GATE-3" "$WORK_DIR/credentials.json"
# PASS → continue
# FAIL → Level 1: retry auth_simulator
#         Level 2: if auth fails, fall back to static analysis mode (no credentials)
#                  Write degraded flag:
#                  jq '.phases.phase3.mode = "degraded" | .phases.phase3.degradation_reason = "auth simulation failed"' \
#                      "$WORK_DIR/checkpoint.json" > "$WORK_DIR/checkpoint.json.tmp" && mv "$WORK_DIR/checkpoint.json.tmp" "$WORK_DIR/checkpoint.json"
#                  Print: "⚠️ Phase-3 degraded: 鉴权模拟失败，退回静态分析模式"
#                  ⚠️ DOWNSTREAM IMPACT: Phase-4 auditors MUST tag all auth-dependent
#                     conclusions with [NOT_VERIFIED: Missing auth credentials].
#                     Inject flag into each Phase-4 auditor prompt:
#                     PHASE3_DEGRADED=true — mark auth-dependent findings as "suspected" not "confirmed"
#         Level 3: N/A (Phase-3 can always degrade)
```

**Step 5 — EXIT:**
```bash
bash "$WORK_DIR/.audit_state/phase_transition.sh" "PHASE_3" "GATE_3_PASS"
```
```
Write checkpoint: {"completed": ["env", "scan", "trace"], "current": "exploit"}
Print pipeline: Phase-1 ✅ | Phase-2 ✅ | Phase-3 ✅ | Phase-4~5 ⏳
```

**🚫 ONLY now may you enter Phase-4.**

---

### Phase-4: 深度对抗审计（并行分析 + 串行攻击）

> 📋 Detailed flow: `references/phase4_attack_logic.md`
> 📄 Agent instructions: `phases/phase4-exploit.md`
> **⚠️ This phase is the ONLY source of Burp reproduction packets and physical evidence. MUST NOT skip.**

**Step 1 — ENTER:**
```bash
bash "$WORK_DIR/.audit_state/phase_transition.sh" "GATE_3_PASS" "PHASE_4"
```
```
RESEARCH_COUNT=0   # Initialize Mini-Researcher dispatch counter
PHASE_TIMEOUT_MIN=60
AGENT_TIMEOUT_MIN=20  # per-auditor timeout
echo "$(date +%s)" > "$WORK_DIR/.audit_state/phase_start_time"
打印: ━━━ 进入 Phase-4: 深度对抗审计 ━━━
```

**Step 2 — SPAWN (priority batches):**
```
Read $WORK_DIR/priority_queue.json → determine auditor list
Add framework-adaptive forced auditors

# Exploit file naming: each auditor writes to $WORK_DIR/exploits/{sink_id}.json
# sink_id is unique per priority_queue entry (e.g., sink_001, sink_002)
# Framework-forced auditors without a sink_id use: {auditor_type}_forced.json
# This ensures NO two auditors write to the same file.

# Check Phase-3 degradation flag for downstream impact
PHASE3_MODE=$(jq -r '.phases.phase3.mode // "full"' "$WORK_DIR/checkpoint.json")
if PHASE3_MODE == "degraded":
    Inject PHASE3_DEGRADED=true into ALL Phase-4 auditor prompts
    Print: "⚠️ Phase-3 was degraded — auth-dependent findings will be marked 'suspected'"

Batch spawn by priority:
  # GUARD: skip empty priority tiers — if no P0 sinks exist, proceed directly to P1
  P0 auditors: if P0 list is non-empty → spawn ALL (background), record spawned_at for each in checkpoint.agent_states
    Each auditor starts in Stage-1 (analysis only)
  → WAIT for ALL P0 Stage-1 completed
    Per-auditor timeout: if any auditor exceeds AGENT_TIMEOUT_MIN (20 min) without
    completing Stage-1, force-terminate it and mark as "timed_out" in agent_states.
  → Send START_ATTACK signal to all P0 auditors:
    SendMessage(agent_id, type="start_attack_signal", payload={"stage": 2, "max_rounds": 10})
  → WAIT for ALL P0 Stage-2 (attack) completed
    Per-auditor timeout: same AGENT_TIMEOUT_MIN check per auditor

  P1 auditors: if P1 list is non-empty → spawn ALL (background), record spawned_at
  → WAIT for ALL P1 Stage-1 completed (with per-auditor timeout)
  → Send START_ATTACK signal to all P1 auditors
  → WAIT for ALL P1 Stage-2 completed (with per-auditor timeout)

  P2/P3 auditors: if P2/P3 list is non-empty → spawn ALL (background), record spawned_at
  → WAIT for ALL P2/P3 Stage-1 completed (with per-auditor timeout)
  → Send START_ATTACK signal to all P2/P3 auditors
  → WAIT for ALL P2/P3 Stage-2 completed

After EACH auditor completes: run inline QC immediately
  — QC FAIL → check redo_count:
    if redo_count < 2 → increment redo_count, re-run auditor
    if redo_count >= 2 → mark auditor as "degraded" in checkpoint, do NOT retry
      jq '.agent_states["AGENT_ID"].status = "degraded"' checkpoint.json
      Print: "⚠️ {agent} exhausted retries (2/2), marking degraded"
```

**🔒 auth_matrix Immutability Law:**
- `auth_matrix.json` is generated by Phase-2 risk_classifier. Phase-4 auditors MUST read-only, NEVER modify.
- Auditor `prerequisite_conditions.auth_requirement` MUST match `auth_matrix.json` `auth_level` exactly.
- If auditor disagrees with auth_matrix → note objection in exploit JSON `notes` field, but MUST NOT change the auth determination.
- QC finds auth_requirement ≠ auth_matrix.auth_level → automatic FAIL.

**🔬 Mini-Researcher On-Demand Dispatch:**
During Phase-4, orchestrator checks these trigger conditions after each auditor attack round. If ANY condition met, spawn `teams/team4/mini_researcher.md`:
- **MR-1**: Auditor encounters a third-party component not in `framework_patterns.md`
- **MR-2**: `version_alerts` has Critical CVE but `known_cves.md` has no PoC
- **MR-3**: Auditor fails 5 consecutive rounds AND `filter_strength_score ≥ 61`
- **MR-4**: After pivot, still 3 consecutive failures (secondary deadlock)
- **MR-5**: Encounters unrecognizable security middleware/filter

Enforcement mechanism:
```
RESEARCH_COUNT=0  # Global counter, initialize at Phase-4 ENTER

After each auditor completes Stage-2:
  Read auditor result → check for trigger conditions:
    - result.unknown_component exists?                          → MR-1
    - result.cve_id exists AND not in known_cves.md?            → MR-2
    - result.consecutive_failures >= 5 AND filter_score >= 61?  → MR-3
    - result.pivot_triggered AND result.post_pivot_failures >= 3? → MR-4
    - result.unknown_middleware exists?                          → MR-5

  If ANY trigger matched AND RESEARCH_COUNT < 10:
    RESEARCH_COUNT=$((RESEARCH_COUNT + 1))
    spawn mini_researcher with trigger context + 3-minute timeout
    Inject research result back into auditor via SendMessage
  If RESEARCH_COUNT >= 10:
    Print: "⚠️ Research dispatch limit reached (10/10), skipping further research"
```

Constraint: max **10** research dispatches per audit (global counter), each limited to **3 minutes**.
Research result injection format: see `phases/phase4-exploit.md` and `references/phase4_attack_logic.md`.

**Step 3 — WAIT + Final QC:**
```
spawn quality_checker (comprehensive verification, foreground)
⏳ Block-wait comprehensive QC completed
```

**Step 4 — GATE:**
```bash
bash "$WORK_DIR/.audit_state/gate_check.sh" "GATE-4" "$WORK_DIR/exploits"
# Additional check: at least one exploit JSON exists
ls "$WORK_DIR/exploits/"*.json >/dev/null 2>&1 || echo "❌ GATE-4 FAIL: exploits/ empty"
```
```
PASS → generate exploit_summary.json:
```
```bash
# Generate exploit_summary.json (orchestrator inline action)
CONFIRMED=$(cat "$WORK_DIR/exploits/"*.json 2>/dev/null | jq -s '[.[] | select(.final_verdict=="confirmed")] | length')
SUSPECTED=$(cat "$WORK_DIR/exploits/"*.json 2>/dev/null | jq -s '[.[] | select(.final_verdict=="suspected")] | length')
SAFE=$(cat "$WORK_DIR/exploits/"*.json 2>/dev/null | jq -s '[.[] | select(.final_verdict=="not_vulnerable")] | length')
TOTAL=$(ls "$WORK_DIR/exploits/"*.json 2>/dev/null | wc -l)
cat > "$WORK_DIR/exploit_summary.json" << EOF
{
  "total_audited": $TOTAL,
  "confirmed": $CONFIRMED,
  "suspected": $SUSPECTED,
  "safe": $SAFE,
  "severity_breakdown": $(cat "$WORK_DIR/exploits/"*.json 2>/dev/null | jq -s 'group_by(.severity) | map({(.[0].severity // "unknown"): length}) | add // {}'),
  "exploits": $(cat "$WORK_DIR/exploits/"*.json 2>/dev/null | jq -s '[.[] | {id: .vuln_id, type: .vuln_type, severity: .severity, verdict: .final_verdict, title: .title}]')
}
EOF
```
# FAIL → Diagnostics:
```
```bash
# Diagnostic on FAIL:
jq '.agent_states | to_entries[] | select(.key | test("auditor")) | {agent: .key, status: .value.status, redo: .value.redo_count, pivot: .value.pivot_triggered}' "$WORK_DIR/checkpoint.json"
```
```
  — agent status=spawned, no completed_at → agent stuck, terminate and re-spawn
  — status=failed, redo_count < 2 → re-send failed_items
  — status=timeout → keep partial results, mark degraded
  — no entries → agent never spawned, spawn immediately
  — all passed but exploits/ empty → all sinks confirmed safe, generate "no vulnerabilities" report
```

**Step 5 — EXIT:**
```bash
bash "$WORK_DIR/.audit_state/phase_transition.sh" "PHASE_4" "GATE_4_PASS"
```
```
Write checkpoint: {"completed": ["env", "scan", "trace", "exploit"], "current": "post_exploit"}
Print pipeline: Phase-1~4 ✅ | Phase-4.5~5 ⏳
```

**🚫 ONLY now may you enter Phase-4.5.**

---

### Phase-4.5: 后渗透智能分析

> 📋 Detailed flow: `references/phase4_5_correlation.md`
> 📄 Agent instructions: `phases/phase45-post.md`
> **⚠️ This phase is the ONLY source of PoC scripts. MUST NOT skip.**

**Step 1 — ENTER:**
```bash
bash "$WORK_DIR/.audit_state/phase_transition.sh" "GATE_4_PASS" "PHASE_4_5"
PHASE_TIMEOUT_MIN=15
echo "$(date +%s)" > "$WORK_DIR/.audit_state/phase_start_time"
```
```
打印: ━━━ 进入 Phase-4.5: 后渗透智能分析 ━━━
```

**Step 2 — SPAWN:**
```
spawn attack_graph_builder  (background, read teams/team4.5/attack_graph_builder.md)
spawn correlation_engine    (background, read teams/team4.5/correlation_engine.md)
→ WAIT for both completed
spawn remediation_generator (background, read teams/team4.5/remediation_generator.md)
spawn poc_generator         (background, read teams/team4.5/poc_generator.md)
→ WAIT for both completed
```

**Step 3 — WAIT:**
```
⏳ Block-wait ALL Phase-4.5 agents completed (no separate QC for this phase)
```

**Step 4 — GATE:**
```bash
bash "$WORK_DIR/.audit_state/gate_check.sh" "GATE-4.5" "$WORK_DIR/PoC脚本" "$WORK_DIR/修复补丁"
ls "$WORK_DIR/PoC脚本/"*.py >/dev/null 2>&1 || echo "❌ GATE-4.5 FAIL: PoC脚本/ empty"
# PASS → continue
# FAIL → Level 1: retry poc_generator / remediation_generator
#         Level 2: if still fails, continue to Phase-5 with partial results (degraded)
#         Level 3: N/A (can always degrade)
```

**Step 5 — EXIT:**
```bash
bash "$WORK_DIR/.audit_state/phase_transition.sh" "PHASE_4_5" "GATE_4_5_PASS"
```
```
Write checkpoint: {"completed": ["env", "scan", "trace", "exploit", "post_exploit"], "current": "report"}
Print pipeline: Phase-1~4.5 ✅ | Phase-5 ⏳
```

**🚫 ONLY now may you enter Phase-5.**

---

### Phase-5: 清理与报告

> 📋 Detailed flow: `references/phase5_reporting.md`
> 📄 Agent instructions: `phases/phase5-report.md`

**Step 1 — ENTER:**
```bash
bash "$WORK_DIR/.audit_state/phase_transition.sh" "GATE_4_5_PASS" "PHASE_5"
PHASE_TIMEOUT_MIN=15
echo "$(date +%s)" > "$WORK_DIR/.audit_state/phase_start_time"
```
```
打印: ━━━ 进入 Phase-5: 清理与报告 ━━━
```

**Step 2 — SPAWN:**
```
spawn cleanup_agent (foreground, read teams/team5/env_cleaner.md)
  — Stop Docker containers, clean temp files
→ WAIT for cleanup completed

spawn report_writer (foreground, read teams/team5/report_writer.md)
  inject: exploit_summary.json + exploits/*.json + PoC脚本/*.py + 修复补丁/*.php
→ WAIT for report completed
```

**Step 3 — WAIT + Final QC:**
```
spawn quality_checker (final report QC, foreground)
⏳ Block-wait final QC result
  — QC PASS → continue
  — QC FAIL → check report_writer redo_count:
    if redo_count < 2 → increment redo_count, revise and resubmit
    if redo_count >= 2 → force output whatever is available
```

**Step 4 — GATE + File Reorganization:**
```bash
bash "$WORK_DIR/.audit_state/gate_check.sh" "GATE-5" "$WORK_DIR/报告/审计报告.md"
# PASS → reorganize files
# FAIL → Level 1: retry report_writer
#         Level 2: force output whatever is available
#         Level 3: N/A
```
```bash
# Move all intermediate artifacts to 原始数据/ for clean user view
for f in environment_status.json route_map.json auth_matrix.json ast_sinks.json \
         priority_queue.json credentials.json dep_risk.json exploit_summary.json \
         attack_graph.json correlation_report.json checkpoint.json; do
  [ -f "$WORK_DIR/$f" ] && mv "$WORK_DIR/$f" "$WORK_DIR/原始数据/"
done
[ -d "$WORK_DIR/exploits" ] && mv "$WORK_DIR/exploits" "$WORK_DIR/原始数据/"
[ -d "$WORK_DIR/context_packs" ] && mv "$WORK_DIR/context_packs" "$WORK_DIR/原始数据/"
[ -d "$WORK_DIR/traces" ] && mv "$WORK_DIR/traces" "$WORK_DIR/原始数据/"
[ -d "$WORK_DIR/research" ] && mv "$WORK_DIR/research" "$WORK_DIR/原始数据/"
# NOTE: .audit_state is moved AFTER phase_transition.sh call in Step 5
```

**Step 5 — EXIT:**
```bash
bash "$WORK_DIR/.audit_state/phase_transition.sh" "PHASE_5" "DONE"
# NOW safe to move .audit_state (transition is complete)
[ -d "$WORK_DIR/.audit_state" ] && mv "$WORK_DIR/.audit_state" "$WORK_DIR/原始数据/"
# Write final checkpoint to 原始数据/
cat > "$WORK_DIR/原始数据/checkpoint.json" << EOF
{"completed": ["env", "scan", "trace", "exploit", "post_exploit", "report"], "current": "done"}
EOF
```
```
Print pipeline: ALL ✅

━━━ 审计完成 ━━━
📋 审计报告: $WORK_DIR/报告/审计报告.md
📊 SARIF:    $WORK_DIR/报告/audit_report.sarif.json
🔧 PoC脚本: $WORK_DIR/PoC脚本/
🩹 修复补丁: $WORK_DIR/修复补丁/
📝 经验沉淀: $WORK_DIR/经验沉淀/
📊 质量报告: $WORK_DIR/质量报告/质量报告.md
📁 原始数据: $WORK_DIR/原始数据/
━━━━━━━━━━━━━━━
```

**🚫 ONLY after Phase-5 Step 5 completes (phase_transition.sh returns 0 and checkpoint.json shows `"current": "done"`) may you show ANY vulnerability findings or fix suggestions to the user.**

### QC Failure Recovery Strategy

**CRITICAL: On QC failure, MUST continue to all subsequent phases. Each QC has independent recovery.**

- Phase-1 QC FAIL (env build) → re-send failed_items to docker-builder, all retries exhausted → halt for user intervention. **NO degradation allowed — Docker MUST succeed.**
- Phase-2 QC FAIL (static recon) → identify responsible agent via failed_items, re-run. Note coverage gap in report. **MUST continue to Phase-3, Phase-4, Phase-5.**
- Phase-3 QC FAIL (dynamic trace) → fall back to static analysis for broken routes. **MUST continue to Phase-4, Phase-5.**
- Phase-4 QC FAIL (evidence) → mark as degraded. **MUST continue to Phase-4.5, Phase-5.**

### Agent Injection Layer System

> 📋 Full specification: `references/agent_injection_framework.md` (L1/L2/L3 injection tiers + token budget rules)

### Timeout Control

#### Tiered Timeout Limits

| Level | Timeout | Recovery Strategy |
|-------|---------|-------------------|
| **Single Agent** | 15 min | Terminate agent, record timeout, continue to next |
| **Phase-1** | 20 min | Retry docker-builder once, still fails → halt for user |
| **Phase-2** | 25 min | Continue with available tool results, mark degraded |
| **Phase-3** | 20 min | Skip incomplete traces, fall back to static analysis |
| **Phase-4 single expert** | 20 min (analysis+attack) | Terminate expert, keep partial results, continue next |
| **Phase-4 total** | 60 min | Terminate remaining experts, use available results for Phase-4.5 |
| **Phase-4.5** | 15 min | Generate partial report with available data |
| **Phase-5** | 15 min | Force output whatever content is generated |
| **Global** | 2.5 hours | Save progress + generate partial report + prompt resume |

#### Timeout Enforcement Mechanism

Record global start time on Step 1 of SKILL.md:
```bash
echo "$(date +%s)" > "$WORK_DIR/.audit_state/global_start_time"
```

**On Resume**: Reset global start time to avoid false timeout from stale timestamps:
```bash
# In Resume Protocol, after setting WORK_DIR:
echo "$(date +%s)" > "$WORK_DIR/.audit_state/global_start_time"
```

Per-phase timeout mapping (set at each ENTER step):
```bash
# Phase-1
PHASE_TIMEOUT_MIN=20
echo "$(date +%s)" > "$WORK_DIR/.audit_state/phase_start_time"

# Phase-2
PHASE_TIMEOUT_MIN=25

# Phase-3
PHASE_TIMEOUT_MIN=20

# Phase-4
PHASE_TIMEOUT_MIN=60
AGENT_TIMEOUT_MIN=20  # per-auditor timeout

# Phase-4.5
PHASE_TIMEOUT_MIN=15

# Phase-5
PHASE_TIMEOUT_MIN=15
```

During WAIT step, check elapsed time after each agent completion:
```bash
PHASE_START=$(cat "$WORK_DIR/.audit_state/phase_start_time")
GLOBAL_START=$(cat "$WORK_DIR/.audit_state/global_start_time")
NOW=$(date +%s)
PHASE_ELAPSED=$(( (NOW - PHASE_START) / 60 ))
GLOBAL_ELAPSED=$(( (NOW - GLOBAL_START) / 60 ))

# Phase timeout check
if [ "$PHASE_ELAPSED" -ge "$PHASE_TIMEOUT_MIN" ]; then
  echo "⏱️ Phase timeout reached (${PHASE_ELAPSED}min / ${PHASE_TIMEOUT_MIN}min limit)"
  # Execute phase-specific recovery from table above
fi

# Global timeout check (150 min = 2.5 hours)
if [ "$GLOBAL_ELAPSED" -ge 150 ]; then
  echo "⏱️ Global timeout reached (${GLOBAL_ELAPSED}min)"
  # Save checkpoint, generate partial report, TeamDelete(), prompt resume
fi
```

#### Timeout Handling Flow

On any timeout:
1. Send shutdown_request to timed-out agent (wait 10s for graceful exit)
2. Update agent_states: `jq '.agent_states["AGENT_ID"].status = "timeout"'`
3. Save current progress to checkpoint.json
4. Mark ⏱️ timeout in pipeline view
5. Continue to next step — proceeding is MANDATORY regardless of timeout

On global timeout:
- Save progress to checkpoint.json
- Generate report from completed phases
- TeamDelete()
- 提示用户可使用断点续审继续

## 输出

最终输出目录结构:
```
$WORK_DIR/
├── 报告/
│   ├── 审计报告.md              ← 主报告（全中文，含 Burp 模板 + 攻击链 + AI验证标记）
│   └── audit_report.sarif.json  ← 机器可读报告
├── PoC脚本/
│   ├── poc_{sink_id}.py
│   └── 一键运行.sh
├── 修复补丁/
│   └── {finding_id}.patch
├── 经验沉淀/
│   ├── 经验总结.md
│   └── 共享文件更新建议.md
├── 质量报告/
│   └── 质量报告.md
└── 原始数据/                    ← 中间产物归档
    ├── exploits/, traces/, context_packs/ 等
    └── checkpoint.json
```
