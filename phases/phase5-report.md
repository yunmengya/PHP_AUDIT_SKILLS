# Phase 5: 清理与报告

主调度器已设置变量: TARGET_PATH, WORK_DIR, SKILL_DIR, SHARED_RESOURCES
提示词模板参考 phase1-env.md 中的模板。
动态 TASK_ID 映射由 phase2-tasks-dynamic.md 阶段记录。

## 执行步骤

### 并行 Step: 清理 + 报告 + SARIF

读取以下文件内容:
- ${SKILL_DIR}/teams/team5/env_cleaner.md
- ${SKILL_DIR}/teams/team5/report_writer.md

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
  prompt= "将 $WORK_DIR/exploits/*.json 转换为 SARIF 2.1.0 格式。
            每个 confirmed/suspected 漏洞映射为一条 SARIF result。
            severity 映射: confirmed→error, suspected→warning, potential→note。
            包含 physicalLocation（文件+行号）和 message（漏洞描述）。
            输出: $WORK_DIR/audit_report.sarif.json"
)
```
输出: $WORK_DIR/audit_report.sarif.json

**等待三者全部完成。**

### 串行 Step: qc-final

读取: ${SKILL_DIR}/teams/team5/qc_final.md

**Agent 4: qc-final**
```
Agent(
  name="qc-final",
  team_name="php-audit",
  mode="bypassPermissions",
  subagent_type="general-purpose",
  prompt= 提示词模板(TASK_ID=N+3) + qc_final.md 内容
)
```
输出: QC-Final 验证结果 JSON

**等待完成。**
