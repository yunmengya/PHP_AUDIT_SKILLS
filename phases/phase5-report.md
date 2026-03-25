# Phase 5: 清理与报告

主调度器已设置变量: TARGET_PATH, WORK_DIR, SKILL_DIR, SHARED_RESOURCES
提示词模板参考 phase1-env.md 中的模板。
动态 TASK_ID 映射由 phase2-tasks-dynamic.md 阶段记录。

## 执行步骤

### 并行 Step: 清理 + 报告 + SARIF

读取以下文件内容:
- ${SKILL_DIR}/teams/team5/env_cleaner.md
- ${SKILL_DIR}/teams/team5/report_writer.md
- ${SKILL_DIR}/teams/team5/sarif_exporter.md

同时 spawn 三个 Agent（background 模式，互不依赖）:

**Agent 1: env-cleaner**
```
Agent(
  name="env-cleaner",
  team_name="php-audit",
  run_in_background=true,
  mode="bypassPermissions",
  subagent_type="general-purpose",
  prompt= 提示词模板(TASK_ID=N+1) + env_cleaner.md 内容
)
```
职责: 停 Xdebug、还原代码、清理痕迹、重置数据库

**Agent 2: report-writer**
```
Agent(
  name="report-writer",
  team_name="php-audit",
  run_in_background=true,
  mode="bypassPermissions",
  subagent_type="general-purpose",
  prompt= 提示词模板(TASK_ID=N+2) + report_writer.md 内容
)
```
输出: $WORK_DIR/audit_report.md

**Agent 3: sarif-exporter**
```
Agent(
  name="sarif-exporter",
  team_name="php-audit",
  run_in_background=true,
  mode="bypassPermissions",
  subagent_type="general-purpose",
  prompt= 提示词模板(TASK_ID=N+3) + sarif_exporter.md 内容
)
```
输出: $WORK_DIR/audit_report.sarif.json

**等待三者全部完成。**

### 串行 Step: quality-checker-final

读取: ${SKILL_DIR}/teams/qc/quality_checker.md + ${SKILL_DIR}/references/quality_check_templates.md

**Agent 4: quality-checker-final**
```
Agent(
  name="quality-checker-final",
  team_name="php-audit",
  mode="bypassPermissions",
  subagent_type="general-purpose",
  prompt= 提示词模板(TASK_ID=N+4) + teams/qc/quality_checker.md + references/quality_check_templates.md（对应阶段章节）+ shared/output_standard.md
)
```
输出: 最终质检结果 JSON

**等待完成。**

### 后置 Step: 敏感数据清理（最终质检通过后）

最终质检（quality-checker-final）验证通过后，执行敏感数据清理:

```bash
# 由主调度器直接执行（无需 spawn Agent）
# 安全删除 audit_session.db（含明文凭证）
if [ -f "$WORK_DIR/audit_session.db" ]; then
  dd if=/dev/urandom of="$WORK_DIR/audit_session.db" bs=1k count=$(stat -f%z "$WORK_DIR/audit_session.db" 2>/dev/null || stat -c%s "$WORK_DIR/audit_session.db" 2>/dev/null) 2>/dev/null
  rm -f "$WORK_DIR/audit_session.db" "$WORK_DIR/audit_session.db-wal" "$WORK_DIR/audit_session.db-shm"
fi
rm -rf "$WORK_DIR/second_order/" 2>/dev/null || true
rm -f "$WORK_DIR/.shared_findings.lock" 2>/dev/null || true
```
