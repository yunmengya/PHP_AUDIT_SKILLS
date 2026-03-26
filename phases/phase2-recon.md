# Phase 2: Static Asset Reconnaissance

The main dispatcher has set variables: TARGET_PATH, WORK_DIR, SKILL_DIR, SHARED_RESOURCES
Refer to the prompt template in phase1-env.md.

## Execution Steps

### Parallel Step

Read the following file contents:
- ${SKILL_DIR}/teams/team2/tool_runner.md
- ${SKILL_DIR}/teams/team2/route_mapper.md
- ${SKILL_DIR}/teams/team2/auth_auditor.md
- ${SKILL_DIR}/teams/team2/dep_scanner.md

Spawn four Agents simultaneously (background mode, true parallelism):

**Agent 1: tool-runner**
```
Agent(
  name="tool-runner",
  team_name="php-audit",
  run_in_background=true,
  mode="bypassPermissions",
  subagent_type="general-purpose",
  prompt= Prompt template(TASK_ID=5) + tool_runner.md contents
)
```
Output: $WORK_DIR/psalm_taint.json, $WORK_DIR/progpilot.json, $WORK_DIR/ast_sinks.json, $WORK_DIR/phpstan.json, $WORK_DIR/semgrep.json, $WORK_DIR/composer_audit.json, $WORK_DIR/codeql.json

**Agent 2: route-mapper**
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

**Agent 3: auth-auditor**
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

**Agent 4: dep-scanner**
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

**Wait for all four to complete.**

### Sequential Step 1: context-extractor

Read: ${SKILL_DIR}/teams/team2/context_extractor.md

**Agent 5: context-extractor**
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

**Agent 6: risk-classifier**
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

**Agent 7: quality-checker-2**
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
