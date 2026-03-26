# Phase 5: Cleanup and Report Generation (Detailed Flow)

> This file is extracted from SKILL.md; the main orchestrator loads it by reference.

### Phase-5: Cleanup and Reporting

── parallel step ──

Spawn three Agents simultaneously (background mode):

  Agent(name="env-cleaner", team_name="php-audit", run_in_background=true, mode="bypassPermissions", subagent_type="general-purpose")
    → prompt: Task #N+1 instructions + teams/team5/env_cleaner.md + shared resources + WORK_DIR

  Agent(name="report-writer", team_name="php-audit", run_in_background=true, mode="bypassPermissions", subagent_type="general-purpose")
    → prompt: Task #N+2 instructions + teams/team5/report_writer.md + shared resources + TARGET_PATH + WORK_DIR

  Agent(name="sarif-exporter", team_name="php-audit", run_in_background=true, mode="bypassPermissions", subagent_type="general-purpose")
    → prompt: Task #N+3 instructions + teams/team5/sarif_exporter.md + shared resources + WORK_DIR

Wait for all three to complete
── sequential step ──

  Agent(name="quality-checker-final", team_name="php-audit", foreground, mode="bypassPermissions", subagent_type="general-purpose")
    → prompt: teams/qc/quality_checker.md
            + references/quality_check_templates.md (Phase 5: report generation validation + final quality report template)
            + shared/output_standard.md + shared/data_contracts.md + shared/evidence_contract.md
            + PHASE=5, TARGET_AGENT=team5, OUTPUT_FILES=audit_report.md,audit_report.sarif.json,poc/,poc/run_all.sh
            + WORK_DIR

Completed
Parse quality check results:
  - verdict=fail → send back to report-writer for correction (max 2 rounds)
  - verdict=pass → quality checker generates $WORK_DIR/quality_report.md (using final quality report template)

Write checkpoint.json: {"completed": ["env", "scan", "trace", "exploit", "report"], "current": "done"}
Print final pipeline view

#### Step 6.4: Cumulative Pipeline View

Print the complete pipeline view after each Phase completes; see `references/pipeline_view.md` for details.

Status markers: ✅=completed | ⚠️=degraded | ❌=failed | ⏳=waiting | 🔄=skipped

#### Step 6.5: Agent Lifecycle Management and Team Cleanup

**Agent Shutdown Protocol**: After each Agent passes QC validation, the main orchestrator sends a shutdown_request for graceful shutdown:

```
For each completed Agent (in Phase order):
  SendMessage(to="{agent-name}", message={type: "shutdown_request", reason: "任务完成，QC 已通过"})
  Wait for shutdown_response (max 30 seconds)
  If timeout with no response → log warning and continue (MUST NOT block subsequent flow)
```

**Shutdown Order**:
- After each Phase's quality checker passes, shut down all Agents for that Phase
- After the final quality checker (quality-checker-final) passes, shut down all remaining Agents
- Finally execute TeamDelete()

```
Iterate over all still-active teammates, send shutdown_request to each
Wait for all shutdown_response or timeout
TeamDelete()
```

**tmux Cleanup (Fallback Logic)**: The framework SHOULD automatically reclaim Agent panes, but in practice idle Agent processes MAY not exit, leaving residual panes. Execute the following fallback cleanup after TeamDelete:

```bash
# Find and close all residual panes created by Claude Code Agent Teams
# Keep only the current main pane (pane index 0)
CURRENT_PANE=$(tmux display-message -p '#{pane_id}' 2>/dev/null)
if [ -n "$CURRENT_PANE" ]; then
  tmux list-panes -F '#{pane_id}' 2>/dev/null | while read pane; do
    [ "$pane" != "$CURRENT_PANE" ] && tmux kill-pane -t "$pane" 2>/dev/null
  done
  echo "tmux 残留 pane 已清理"
fi
```

```
告知用户: "审计完成！报告文件: $WORK_DIR/audit_report.md"
```
