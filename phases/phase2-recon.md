# Phase 2: Static Asset Reconnaissance

> 📄 **Route sub-skills**: `skills/routes/` (S-030a~S-030h)

The main dispatcher has set variables: TARGET_PATH, WORK_DIR, SKILL_DIR, SHARED_RESOURCES
Refer to the prompt template in phase1-env.md.

## 5-Step Orchestration Template

**Step 1 — ENTER:**
```bash
bash "$WORK_DIR/.audit_state/phase_transition.sh" "GATE_1_PASS" "PHASE_2"
PHASE_TIMEOUT_MIN=25
echo "$(date +%s)" > "$WORK_DIR/.audit_state/phase_start_time"
```
```
Print: ━━━ 进入 Phase-2: 静态资产侦察 ━━━
```

**Input Integrity Check (MANDATORY before SPAWN):**
```
| # | Required Upstream Artifact | Check Command | Result | Pass |
|---|--------------------------|---------------|--------|------|
| 1 | environment_status.json exists | test -f "$WORK_DIR/environment_status.json" | {exists/missing} | {✅/❌} |
| 2 | environment_status.json valid JSON | python3 -m json.tool "$WORK_DIR/environment_status.json" | {valid/invalid} | {✅/❌} |
| 3 | framework field present | jq -e '.framework' "$WORK_DIR/environment_status.json" | {value} | {✅/❌} |
IF any ❌ → DO NOT spawn agents. Return to Phase-1 recovery (see failure_recovery.md).
```

**Step 2 — SPAWN:**
```
spawn psalm-scanner         (Task #5a, background, read skills/scanners/psalm_scanner.md)
spawn progpilot-scanner     (Task #5b, background, read skills/scanners/progpilot_scanner.md)
spawn ast-scanner           (Task #5c, background, read skills/scanners/ast_scanner.md)
spawn phpstan-scanner       (Task #5d, background, read skills/scanners/phpstan_scanner.md)
spawn semgrep-scanner       (Task #5e, background, read skills/scanners/semgrep_scanner.md)
spawn composer-audit-scanner(Task #5f, background, read skills/scanners/composer_audit_scanner.md)
spawn codeql-scanner        (Task #5g, background, optional, read skills/scanners/codeql_scanner.md)
spawn route_mapper          (Task #6, background, read teams/team2/route_mapper.md)
spawn auth_auditor          (Task #7, background, read teams/team2/auth_auditor.md)
spawn dep_scanner           (Task #8, background, read teams/team2/dep_scanner.md)
→ WAIT for Task #5a~#5g,#6,#7,#8 ALL completed
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
  — QC FAIL →
    1. Read QC report from $WORK_DIR/质量报告/quality_report_phase2.json
    2. Extract all items where status = "❌"
    3. Map each failed item to its responsible agent (see teams/qc/qc_dispatcher.md Phase-2 mapping)
    4. For EACH responsible agent, build the structured redo prompt per teams/qc/qc_dispatcher.md "Redo Information Delivery" template
    5. Re-invoke each responsible agent with its filled-in redo prompt injected into context
    6. Check redo_count:
       if redo_count < 2 → increment redo_count, re-run
       if redo_count >= 2 → mark degraded, continue with available results
```

**Step 4 — GATE:**
```bash
bash "$WORK_DIR/.audit_state/gate_check.sh" "GATE-2" \
  "$WORK_DIR/priority_queue.json" \
  "$WORK_DIR/context_packs"
# PASS → continue
# FAIL → Level 1: retry the specific failing component (context_extractor or risk_classifier), max 2 retries
#         Level 2: if retries exhausted and priority_queue.json EXISTS → mark as degraded, continue
#         Level 3: if priority_queue.json is MISSING entirely → USER HALT (cannot proceed without task queue)
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

## Execution Steps

### Parallel Step 1: Scanners + Route + Auth + Dep (10 agents)

Read the following scanner skill files:
- ${SKILL_DIR}/skills/scanners/psalm_scanner.md (S-020)
- ${SKILL_DIR}/skills/scanners/progpilot_scanner.md (S-021)
- ${SKILL_DIR}/skills/scanners/ast_scanner.md (S-022)
- ${SKILL_DIR}/skills/scanners/phpstan_scanner.md (S-023)
- ${SKILL_DIR}/skills/scanners/semgrep_scanner.md (S-024)
- ${SKILL_DIR}/skills/scanners/composer_audit_scanner.md (S-025)
- ${SKILL_DIR}/skills/scanners/codeql_scanner.md (S-026, optional)

Read the following agent files:
- ${SKILL_DIR}/teams/team2/route_mapper.md (S-030)
- ${SKILL_DIR}/teams/team2/auth_auditor.md
- ${SKILL_DIR}/teams/team2/dep_scanner.md

Spawn 10 Agents simultaneously (background mode, true parallelism):

**Agent 1: psalm-scanner**
```
Agent(
  name="psalm-scanner",
  team_name="php-audit",
  run_in_background=true,
  mode="bypassPermissions",
  subagent_type="general-purpose",
  prompt= Prompt template(TASK_ID=5a) + psalm_scanner.md contents
)
```
Output: $WORK_DIR/psalm_taint.json

**Agent 2: progpilot-scanner**
```
Agent(
  name="progpilot-scanner",
  team_name="php-audit",
  run_in_background=true,
  mode="bypassPermissions",
  subagent_type="general-purpose",
  prompt= Prompt template(TASK_ID=5b) + progpilot_scanner.md contents
)
```
Output: $WORK_DIR/progpilot.json

**Agent 3: ast-scanner**
```
Agent(
  name="ast-scanner",
  team_name="php-audit",
  run_in_background=true,
  mode="bypassPermissions",
  subagent_type="general-purpose",
  prompt= Prompt template(TASK_ID=5c) + ast_scanner.md contents
)
```
Output: $WORK_DIR/ast_sinks.json

**Agent 4: phpstan-scanner**
```
Agent(
  name="phpstan-scanner",
  team_name="php-audit",
  run_in_background=true,
  mode="bypassPermissions",
  subagent_type="general-purpose",
  prompt= Prompt template(TASK_ID=5d) + phpstan_scanner.md contents
)
```
Output: $WORK_DIR/phpstan.json

**Agent 5: semgrep-scanner**
```
Agent(
  name="semgrep-scanner",
  team_name="php-audit",
  run_in_background=true,
  mode="bypassPermissions",
  subagent_type="general-purpose",
  prompt= Prompt template(TASK_ID=5e) + semgrep_scanner.md contents
)
```
Output: $WORK_DIR/semgrep.json

**Agent 6: composer-audit-scanner**
```
Agent(
  name="composer-audit-scanner",
  team_name="php-audit",
  run_in_background=true,
  mode="bypassPermissions",
  subagent_type="general-purpose",
  prompt= Prompt template(TASK_ID=5f) + composer_audit_scanner.md contents
)
```
Output: $WORK_DIR/composer_audit.json

**Agent 7: codeql-scanner** (optional — skip on install failure)
```
Agent(
  name="codeql-scanner",
  team_name="php-audit",
  run_in_background=true,
  mode="bypassPermissions",
  subagent_type="general-purpose",
  prompt= Prompt template(TASK_ID=5g) + codeql_scanner.md contents
)
```
Output: $WORK_DIR/codeql.json

**Agent 8: route-mapper**
```
Agent(
  name="route-mapper",
  team_name="php-audit",
  run_in_background=true,
  mode="bypassPermissions",
  subagent_type="general-purpose",
  prompt= Prompt template(TASK_ID=6) + route_mapper.md contents
)
```
Output: $WORK_DIR/route_map.json

**Agent 9: auth-auditor**
```
Agent(
  name="auth-auditor",
  team_name="php-audit",
  run_in_background=true,
  mode="bypassPermissions",
  subagent_type="general-purpose",
  prompt= Prompt template(TASK_ID=7) + auth_auditor.md contents
)
```
Output: $WORK_DIR/auth_matrix.json

**Agent 10: dep-scanner**
```
Agent(
  name="dep-scanner",
  team_name="php-audit",
  run_in_background=true,
  mode="bypassPermissions",
  subagent_type="general-purpose",
  prompt= Prompt template(TASK_ID=8) + dep_scanner.md contents
)
```
Output: $WORK_DIR/dep_risk.json

**Wait for all ten to complete.**

### Sequential Step 1: context-extractor

Read: ${SKILL_DIR}/teams/team2/context_extractor.md

**Agent 11: context-extractor**
```
Agent(
  name="context-extractor",
  team_name="php-audit",
  mode="bypassPermissions",
  subagent_type="general-purpose",
  prompt= Prompt template(TASK_ID=9) + context_extractor.md contents
)
```
Output: $WORK_DIR/context_packs/*.json

**Wait for completion.**

### Sequential Step 2: risk-classifier

Read: ${SKILL_DIR}/teams/team2/risk_classifier.md

**Agent 12: risk-classifier**
```
Agent(
  name="risk-classifier",
  team_name="php-audit",
  mode="bypassPermissions",
  subagent_type="general-purpose",
  prompt= Prompt template(TASK_ID=10) + risk_classifier.md contents
)
```
Output: $WORK_DIR/priority_queue.json

**Wait for completion.**

### Sequential Step 3: quality-checker-2

Read: ${SKILL_DIR}/teams/qc/quality_checker.md + ${SKILL_DIR}/references/quality_check_templates.md

**Agent 13: quality-checker-2**
```
Agent(
  name="quality-checker-2",
  team_name="php-audit",
  mode="bypassPermissions",
  subagent_type="general-purpose",
  prompt= Prompt template(TASK_ID=11) + teams/qc/quality_checker.md + references/quality_check_templates.md (corresponding phase section) + shared/output_standard.md
)
```
Output: Phase-2 quality check result JSON

**Wait for completion.** Parse Phase-2 quality check result (failure MUST NOT block — annotate coverage and continue).
