# Phase 3: Authentication Simulation & Dynamic Tracing

> 📄 **Trace sub-skills**: `skills/trace/` (S-036a~S-036f, S-037a~S-037h)

> 📄 **Auth sub-skills**: `skills/auth/` (S-038a~S-038i)

The main dispatcher has set variables: TARGET_PATH, WORK_DIR, SKILL_DIR, SHARED_RESOURCES, MODE
Refer to the prompt template in phase1-env.md.

**Note**: This Phase MUST only be entered after the Docker environment has been successfully built.

## 5-Step Orchestration Template

**Step 1 — ENTER:**
```bash
bash "$WORK_DIR/.audit_state/phase_transition.sh" "CREATE_DYNAMIC_TASKS" "PHASE_3"
PHASE_TIMEOUT_MIN=20
echo "$(date +%s)" > "$WORK_DIR/.audit_state/phase_start_time"
```
```
Print: ━━━ 进入 Phase-3: 鉴权模拟与动态追踪 ━━━
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
#                  Print: "⚠️ Phase-3 degraded: auth simulation failed, falling back to static analysis mode"
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

## Execution Steps

### Sequential Step 1: auth-simulator

Read: ${SKILL_DIR}/teams/team3/auth_simulator.md

**Agent 1: auth-simulator**
```
Agent(
  name="auth-simulator",
  team_name="php-audit",
  mode="bypassPermissions",
  subagent_type="general-purpose",
  prompt= Prompt template(TASK_ID=12) + auth_simulator.md contents
)
```
Output: $WORK_DIR/credentials.json

**Wait for completion.**

### Sequential Step 2: trace-dispatcher

Read:
- ${SKILL_DIR}/teams/team3/trace_dispatcher.md
- ${SKILL_DIR}/teams/team3/trace_worker.md (injected into dispatcher prompt for internal worker spawning)

**Agent 2: trace-dispatcher**
```
Agent(
  name="trace-dispatcher",
  team_name="php-audit",
  mode="bypassPermissions",
  subagent_type="general-purpose",
  prompt= Prompt template(TASK_ID=13) + trace_dispatcher.md + trace_worker.md contents
)
```
Internally spawns up to 2 trace-workers in parallel.
Output: $WORK_DIR/traces/*.json

**Wait for completion.**

### Sequential Step 3: quality-checker-3

Read: ${SKILL_DIR}/teams/qc/quality_checker.md + ${SKILL_DIR}/references/quality_check_templates.md

**Agent 3: quality-checker-3**
```
Agent(
  name="quality-checker-3",
  team_name="php-audit",
  mode="bypassPermissions",
  subagent_type="general-purpose",
  prompt= Prompt template(TASK_ID=14) + teams/qc/quality_checker.md + references/quality_check_templates.md (corresponding phase section) + shared/output_standard.md
)
```
Output: Phase-3 quality check result JSON

**Wait for completion.** Parse Phase-3 quality check result (failure → break chain and fall back to static analysis; MUST NOT block).
