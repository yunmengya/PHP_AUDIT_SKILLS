# Phase 5: Cleanup & Report

> 📄 **Report chapter skills**: `skills/report/` (S-090a~S-090g)

The main dispatcher has set variables: TARGET_PATH, WORK_DIR, SKILL_DIR, SHARED_RESOURCES
Refer to the prompt template in phase1-env.md.
Dynamic TASK_ID mappings were recorded during the phase2-tasks-dynamic.md stage.

## 5-Step Orchestration Template

**Step 1 — ENTER:**
```bash
bash "$WORK_DIR/.audit_state/phase_transition.sh" "GATE_4_5_PASS" "PHASE_5"
PHASE_TIMEOUT_MIN=15
echo "$(date +%s)" > "$WORK_DIR/.audit_state/phase_start_time"
```
```
Print: ━━━ 进入 Phase-5: 清理与报告 ━━━
```

**Input Integrity Check (MANDATORY before SPAWN):**
```
| # | Required Upstream Artifact | Check Command | Result | Pass |
|---|--------------------------|---------------|--------|------|
| 1 | exploits/ has ≥1 JSON file | ls "$WORK_DIR/exploits/"*.json 2>/dev/null | wc -l | {count} | {✅/❌} |
| 2 | exploit_summary.json exists | test -f "$WORK_DIR/exploit_summary.json" | {exists/missing} | {✅/❌} |
| 3 | correlation_report.json exists | test -f "$WORK_DIR/correlation_report.json" | {exists/missing} | {✅/❌} |
| 4 | PHASE4_DEGRADED flag | echo "${PHASE4_DEGRADED:-false}" | {true/false} | {info} |
IF #1 ❌ AND #2 ❌ → generate "no vulnerabilities found" report. If PHASE4_DEGRADED=true → add [INCOMPLETE AUDIT] disclaimer to report.
```

**Step 2 — SPAWN:**
```
spawn cleanup_agent (foreground, read teams/team5/env_cleaner.md)
  — Stop Docker containers, clean temp files
→ WAIT for cleanup completed

# 7 chapter writers run in parallel (see skills/report/report_index.md)
spawn cover_page_writer     (background, read skills/report/cover_page_writer.md)     → S-090a
spawn vuln_summary_writer   (background, read skills/report/vuln_summary_writer.md)   → S-090b
spawn vuln_detail_writer    (background, read skills/report/vuln_detail_writer.md)     → S-090c
spawn attack_chain_writer   (background, read skills/report/attack_chain_writer.md)    → S-090d
spawn coverage_stats_writer (background, read skills/report/coverage_stats_writer.md)  → S-090e
spawn risk_pool_writer      (background, read skills/report/risk_pool_writer.md)       → S-090f
spawn lessons_writer        (background, read skills/report/lessons_writer.md)         → S-090g
  inject: exploit_summary.json + exploits/*.json + traces/*.json + 修复补丁/*.diff + attack_graph.json
→ WAIT for all 7 chapter writers completed
→ Assemble chapters sequentially: 00→01→02→03→04→05 → 审计报告.md

spawn sarif_exporter (background, read teams/team5/sarif_exporter.md)
→ WAIT for sarif completed
```

**Step 3 — WAIT + Final QC:**
```
spawn quality_checker (final report QC, foreground)
⏳ Block-wait final QC result
  — QC PASS → continue
  — QC FAIL →
    1. Read QC report from $WORK_DIR/质量报告/quality_report_phase5.json
    2. Extract all items where status = "❌"
    3. Build the structured redo prompt per teams/qc/qc_dispatcher.md "Redo Information Delivery" template
    4. Re-invoke report_writer with the filled-in redo prompt injected into its context
    5. Check report_writer redo_count:
       if redo_count < 2 → increment redo_count, revise and resubmit
       if redo_count >= 2 → force output whatever is available (mark with WARN)
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

---

## Execution Steps

### Parallel Step: Cleanup + Report Chapters + SARIF

Read the following file contents:
- ${SKILL_DIR}/teams/team5/env_cleaner.md
- ${SKILL_DIR}/skills/report/report_index.md (master index for chapter assembly order)
- ${SKILL_DIR}/skills/report/cover_page_writer.md
- ${SKILL_DIR}/skills/report/vuln_summary_writer.md
- ${SKILL_DIR}/skills/report/vuln_detail_writer.md
- ${SKILL_DIR}/skills/report/attack_chain_writer.md
- ${SKILL_DIR}/skills/report/coverage_stats_writer.md
- ${SKILL_DIR}/skills/report/risk_pool_writer.md
- ${SKILL_DIR}/skills/report/lessons_writer.md
- ${SKILL_DIR}/teams/team5/sarif_exporter.md

Spawn Agents simultaneously (background mode, mutually independent):

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

**Agents 2-8: Report Chapter Writers (7 parallel agents)**

Each chapter writer runs as an independent background agent reading from shared Phase-4 outputs:

```
# All 7 spawn simultaneously — no dependencies between chapters
Agent(name="cover-page-writer",     skill=cover_page_writer.md,     TASK_ID=N+2)  → S-090a
Agent(name="vuln-summary-writer",   skill=vuln_summary_writer.md,   TASK_ID=N+3)  → S-090b
Agent(name="vuln-detail-writer",    skill=vuln_detail_writer.md,    TASK_ID=N+4)  → S-090c
Agent(name="attack-chain-writer",   skill=attack_chain_writer.md,   TASK_ID=N+5)  → S-090d
Agent(name="coverage-stats-writer", skill=coverage_stats_writer.md, TASK_ID=N+6)  → S-090e
Agent(name="risk-pool-writer",      skill=risk_pool_writer.md,      TASK_ID=N+7)  → S-090f
Agent(name="lessons-writer",        skill=lessons_writer.md,        TASK_ID=N+8)  → S-090g
```

Each agent config:
```
Agent(
  name="{chapter-name}",
  team_name="php-audit",
  run_in_background=true,
  mode="bypassPermissions",
  subagent_type="general-purpose",
  prompt= Prompt template(TASK_ID=N+X) + {chapter_skill}.md contents
)
```

**Agent 9: sarif-exporter**
```
Agent(
  name="sarif-exporter",
  team_name="php-audit",
  run_in_background=true,
  mode="bypassPermissions",
  subagent_type="general-purpose",
  prompt= Prompt template(TASK_ID=N+9) + sarif_exporter.md contents
)
```
Output: $WORK_DIR/报告/audit_report.sarif.json

**Wait for all 9 agents to complete (1 env-cleaner + 7 chapter writers + 1 sarif-exporter).**

After all chapter writers complete, assemble chapters sequentially into final report:
```
cat 00_封面.md 01_漏洞汇总表.md 02_漏洞详情_*.md 03_攻击链分析.md 04_覆盖率统计.md 05_未验证风险池.md > 审计报告.md
```

### Sequential Step: quality-checker-final

Read: ${SKILL_DIR}/teams/qc/quality_checker.md + ${SKILL_DIR}/references/quality_check_templates.md

**Agent 10: quality-checker-final**
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
