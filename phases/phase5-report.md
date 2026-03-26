# Phase 5: Cleanup & Report

The main dispatcher has set variables: TARGET_PATH, WORK_DIR, SKILL_DIR, SHARED_RESOURCES
Refer to the prompt template in phase1-env.md.
Dynamic TASK_ID mappings were recorded during the phase2-tasks-dynamic.md stage.

## Execution Steps

### Parallel Step: Cleanup + Report + SARIF

Read the following file contents:
- ${SKILL_DIR}/teams/team5/env_cleaner.md
- ${SKILL_DIR}/teams/team5/report_writer.md
- ${SKILL_DIR}/teams/team5/sarif_exporter.md

Spawn three Agents simultaneously (background mode, mutually independent):

**Agent 1: env-cleaner**
```
Agent(
  name="env-cleaner",
  team_name="php-audit",
  run_in_background=true,
  mode="bypassPermissions",
  subagent_type="general-purpose",
  prompt= Prompt template(TASK_ID=N+1) + env_cleaner.md contents
)
```
Responsibilities: Stop Xdebug, restore code, clean up traces, reset database

**Agent 2: report-writer**
```
Agent(
  name="report-writer",
  team_name="php-audit",
  run_in_background=true,
  mode="bypassPermissions",
  subagent_type="general-purpose",
  prompt= Prompt template(TASK_ID=N+2) + report_writer.md contents
)
```
Output: $WORK_DIR/报告/审计报告.md

**Agent 3: sarif-exporter**
```
Agent(
  name="sarif-exporter",
  team_name="php-audit",
  run_in_background=true,
  mode="bypassPermissions",
  subagent_type="general-purpose",
  prompt= Prompt template(TASK_ID=N+3) + sarif_exporter.md contents
)
```
Output: $WORK_DIR/报告/audit_report.sarif.json

**Wait for all three to complete.**

### Sequential Step: quality-checker-final

Read: ${SKILL_DIR}/teams/qc/quality_checker.md + ${SKILL_DIR}/references/quality_check_templates.md

**Agent 4: quality-checker-final**
```
Agent(
  name="quality-checker-final",
  team_name="php-audit",
  mode="bypassPermissions",
  subagent_type="general-purpose",
  prompt= Prompt template(TASK_ID=N+4) + teams/qc/quality_checker.md + references/quality_check_templates.md (corresponding phase section) + shared/output_standard.md
)
```
Output: Final quality check result JSON

**Wait for completion.**

### Post Step: Sensitive Data Cleanup + File Organization (after final quality check passes)

After the final quality check (quality-checker-final) passes, execute sensitive data cleanup and file organization:

```bash
# Executed directly by the main dispatcher (no Agent spawn required)

# 1. Securely delete audit_session.db (contains plaintext credentials)
if [ -f "$WORK_DIR/audit_session.db" ]; then
  dd if=/dev/urandom of="$WORK_DIR/audit_session.db" bs=1k count=$(stat -f%z "$WORK_DIR/audit_session.db" 2>/dev/null || stat -c%s "$WORK_DIR/audit_session.db" 2>/dev/null) 2>/dev/null
  rm -f "$WORK_DIR/audit_session.db" "$WORK_DIR/audit_session.db-wal" "$WORK_DIR/audit_session.db-shm"
fi
rm -rf "$WORK_DIR/second_order/" 2>/dev/null || true
rm -f "$WORK_DIR/.shared_findings.lock" 2>/dev/null || true

# 2. File organization: archive intermediate artifacts to 原始数据/
for f in environment_status.json route_map.json auth_matrix.json ast_sinks.json \
         priority_queue.json credentials.json dep_risk.json exploit_summary.json \
         attack_graph.json correlation_report.json attack_graph_data.json checkpoint.json; do
  [ -f "$WORK_DIR/$f" ] && mv "$WORK_DIR/$f" "$WORK_DIR/原始数据/"
done
[ -d "$WORK_DIR/exploits" ] && mv "$WORK_DIR/exploits" "$WORK_DIR/原始数据/"
[ -d "$WORK_DIR/context_packs" ] && mv "$WORK_DIR/context_packs" "$WORK_DIR/原始数据/"
[ -d "$WORK_DIR/traces" ] && mv "$WORK_DIR/traces" "$WORK_DIR/原始数据/"
[ -d "$WORK_DIR/research" ] && mv "$WORK_DIR/research" "$WORK_DIR/原始数据/"
[ -d "$WORK_DIR/.audit_state" ] && mv "$WORK_DIR/.audit_state" "$WORK_DIR/原始数据/"
```
