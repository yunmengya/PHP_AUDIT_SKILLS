# Phase 1: Intelligent Environment Detection & Setup

The main dispatcher has set variables: TARGET_PATH, WORK_DIR, SKILL_DIR, SHARED_RESOURCES

## 5-Step Orchestration Template

**Step 1 — ENTER:**
```bash
bash "$WORK_DIR/.audit_state/phase_transition.sh" "INIT" "PHASE_1"
# If exit code != 0 → STOP. State machine violation.
PHASE_TIMEOUT_MIN=20
echo "$(date +%s)" > "$WORK_DIR/.audit_state/phase_start_time"
```
```
Print: ━━━ 进入 Phase-1: 环境智能识别与构建 ━━━
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
[ -n "$ALERTS" ] && echo "━━━ Version Security Warning (版本安全预判警告) ━━━" && echo "$ALERTS"
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

## Agent Prompt Template

Each Agent's prompt SHALL be constructed using this template:

```
Your assigned Task ID is #{TASK_ID}.
When starting work: TaskUpdate(taskId="{TASK_ID}", status="in_progress")
When completing work: TaskUpdate(taskId="{TASK_ID}", status="completed")
You MUST NOT create new tasks or write checkpoint.json.

--- Lifecycle Management ---
When you receive a shutdown_request:
1. Confirm all output files have been written to disk
2. Reply with SendMessage(type: "shutdown_response", request_id: "{received request_id}", approve: true)
If no shutdown_request is received within 30 seconds, you MAY stop on your own after task completion.

TARGET_PATH={TARGET_PATH}
WORK_DIR={WORK_DIR}

--- Shared Resources ---
{SHARED_RESOURCES}

--- Task Instructions ---
{Agent .md file contents}
```

## Execution Steps

### Parallel Step

Read the following file contents:
- ${SKILL_DIR}/teams/team1/env_detective.md
- ${SKILL_DIR}/teams/team1/schema_reconstructor.md

Spawn two Agents simultaneously (background mode, true parallelism):

**Agent 1: env-detective**
```
Agent(
  name="env-detective",
  team_name="php-audit",
  run_in_background=true,
  mode="bypassPermissions",
  subagent_type="general-purpose",
  prompt= Prompt template(TASK_ID=1) + env_detective.md contents
)
```
Output: Environment analysis results (framework / PHP version / DB type / extensions, etc.)

**Agent 2: schema-reconstructor**
```
Agent(
  name="schema-reconstructor",
  team_name="php-audit",
  run_in_background=true,
  mode="bypassPermissions",
  subagent_type="general-purpose",
  prompt= Prompt template(TASK_ID=2) + schema_reconstructor.md contents
)
```
Output: $WORK_DIR/reconstructed_schema.sql

**Wait for both to complete.**

### Sequential Step 1: docker-builder

Read the following file contents:
- ${SKILL_DIR}/teams/team1/docker_builder.md
- ${SKILL_DIR}/shared/env_selfheal.md

**Agent 3: docker-builder**
```
Agent(
  name="docker-builder",
  team_name="php-audit",
  mode="bypassPermissions",
  subagent_type="general-purpose",
  prompt= Prompt template(TASK_ID=3) + docker_builder.md + env_selfheal.md + env-detective return results
)
```
Output: $WORK_DIR/environment_status.json, $WORK_DIR/docker-compose.yml, $WORK_DIR/docker/

**Wait for completion.**

### Sequential Step 2: quality-checker-1

Read: ${SKILL_DIR}/teams/qc/quality_checker.md + ${SKILL_DIR}/references/quality_check_templates.md

**Agent 4: quality-checker-1**
```
Agent(
  name="quality-checker-1",
  team_name="php-audit",
  mode="bypassPermissions",
  subagent_type="general-purpose",
  prompt= Prompt template(TASK_ID=4) + teams/qc/quality_checker.md + references/quality_check_templates.md (corresponding phase section) + shared/output_standard.md
)
```
Output: Phase-1 quality check result JSON

**Wait for completion.**

## Result Parsing

Parse the Phase-1 quality check return result:
- Pass → Set MODE=full, continue
- Fail → Re-spawn docker-builder (inject previous failure logs), repeat Step 1 ~ Step 2 until quality check passes
  - Self-healing loop (Phase A 5 rounds + Phase B 3 rounds) all fail → Pause, request user intervention via AskUserQuestion
  - After user fix, continue retrying — **downgrading to static-only MUST NOT be permitted**
