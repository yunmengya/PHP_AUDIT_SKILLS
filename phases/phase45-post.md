# Phase 4.5: Post-Exploitation Intelligent Analysis

> 📄 **Correlation rules**: `skills/correlation/` (S-070 ~ S-074)

The main dispatcher has set variables: TARGET_PATH, WORK_DIR, SKILL_DIR, SHARED_RESOURCES
Refer to the prompt template in phase1-env.md.
Dynamic TASK_ID mappings were recorded during the phase2-tasks-dynamic.md stage.

**This Phase is the SOLE source of PoC scripts — it MUST NOT be skipped.**

## 5-Step Orchestration Template

**Step 1 — ENTER:**
```bash
bash "$WORK_DIR/.audit_state/phase_transition.sh" "GATE_4_PASS" "PHASE_4_5"
PHASE_TIMEOUT_MIN=15
echo "$(date +%s)" > "$WORK_DIR/.audit_state/phase_start_time"
```
```
Print: ━━━ 进入 Phase-4.5: 后渗透智能分析 ━━━
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
# GATE-4.5 validation:
#   REQUIRED: PoC脚本/ MUST contain ≥1 .py file
#   OPTIONAL: 修复补丁/ may be empty (some vulnerabilities have no simple patch)
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

## Execution Steps

### Parallel Step 1: Attack Graph + Correlation Analysis

Read the following file contents:
- ${SKILL_DIR}/teams/team4.5/attack_graph_builder.md
- ${SKILL_DIR}/teams/team4.5/correlation_engine.md
- ${SKILL_DIR}/shared/false_positive_patterns.md
- ${SKILL_DIR}/shared/second_order.md

Spawn two Agents simultaneously (background mode):

**Agent 1: attack-graph-builder**
```
Agent(
  name="attack-graph-builder",
  team_name="php-audit",
  run_in_background=true,
  mode="bypassPermissions",
  subagent_type="general-purpose",
  prompt= Prompt template(TASK_ID=M) + attack_graph_builder.md contents
)
```
Output: $WORK_DIR/attack_graph.json

**Agent 2: correlation-engine**
```
Agent(
  name="correlation-engine",
  team_name="php-audit",
  run_in_background=true,
  mode="bypassPermissions",
  subagent_type="general-purpose",
  prompt= Prompt template(TASK_ID=M+1)
        + correlation_engine.md
        + false_positive_patterns.md
        + second_order.md contents
)
```
Output: $WORK_DIR/correlation_report.json, $WORK_DIR/second_order/correlations.json

**Wait for both to complete.**

### Parallel Step 2: Remediation Patches + PoC Scripts

Read the following file contents:
- ${SKILL_DIR}/teams/team4.5/remediation_generator.md
- ${SKILL_DIR}/teams/team4.5/poc_generator.md
- ${SKILL_DIR}/shared/framework_patterns.md

Spawn two Agents simultaneously (background mode):

**Agent 3: remediation-generator**
```
Agent(
  name="remediation-generator",
  team_name="php-audit",
  run_in_background=true,
  mode="bypassPermissions",
  subagent_type="general-purpose",
  prompt= Prompt template(TASK_ID=M+2)
        + remediation_generator.md
        + framework_patterns.md contents
)
```
Output: $WORK_DIR/修复补丁/*.patch, $WORK_DIR/修复补丁/remediation_summary.json

**Agent 4: poc-generator**
```
Agent(
  name="poc-generator",
  team_name="php-audit",
  run_in_background=true,
  mode="bypassPermissions",
  subagent_type="general-purpose",
  prompt= Prompt template(TASK_ID=M+3) + poc_generator.md contents
)
```
Output: $WORK_DIR/PoC脚本/poc_*.py, $WORK_DIR/PoC脚本/poc_summary.json, $WORK_DIR/PoC脚本/一键运行.sh

**Wait for both to complete.**
