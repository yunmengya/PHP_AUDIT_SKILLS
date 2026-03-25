# Phase 2: 静态资产侦察

主调度器已设置变量: TARGET_PATH, WORK_DIR, SKILL_DIR, SHARED_RESOURCES
提示词模板参考 phase1-env.md 中的模板。

## 执行步骤

### 并行 Step

读取以下文件内容:
- ${SKILL_DIR}/teams/team2/tool_runner.md
- ${SKILL_DIR}/teams/team2/route_mapper.md
- ${SKILL_DIR}/teams/team2/auth_auditor.md
- ${SKILL_DIR}/teams/team2/dep_scanner.md

同时 spawn 四个 Agent（background 模式，真正并行）:

**Agent 1: tool-runner**
```
Agent(
  name="tool-runner",
  team_name="php-audit",
  run_in_background=true,
  mode="bypassPermissions",
  subagent_type="general-purpose",
  prompt= 提示词模板(TASK_ID=5) + tool_runner.md 内容
)
```
输出: $WORK_DIR/psalm_taint.json, $WORK_DIR/progpilot.json, $WORK_DIR/ast_sinks.json, $WORK_DIR/phpstan_results.json, $WORK_DIR/semgrep_results.json, $WORK_DIR/composer_audit.json, $WORK_DIR/codeql_results.json

**Agent 2: route-mapper**
```
Agent(
  name="route-mapper",
  team_name="php-audit",
  run_in_background=true,
  mode="bypassPermissions",
  subagent_type="general-purpose",
  prompt= 提示词模板(TASK_ID=6) + route_mapper.md 内容
)
```
输出: $WORK_DIR/route_map.json

**Agent 3: auth-auditor**
```
Agent(
  name="auth-auditor",
  team_name="php-audit",
  run_in_background=true,
  mode="bypassPermissions",
  subagent_type="general-purpose",
  prompt= 提示词模板(TASK_ID=7) + auth_auditor.md 内容
)
```
输出: $WORK_DIR/auth_matrix.json

**Agent 4: dep-scanner**
```
Agent(
  name="dep-scanner",
  team_name="php-audit",
  run_in_background=true,
  mode="bypassPermissions",
  subagent_type="general-purpose",
  prompt= 提示词模板(TASK_ID=8) + dep_scanner.md 内容
)
```
输出: $WORK_DIR/dep_risk.json

**等待四者全部完成。**

### 串行 Step 1: context-extractor

读取: ${SKILL_DIR}/teams/team2/context_extractor.md

**Agent 5: context-extractor**
```
Agent(
  name="context-extractor",
  team_name="php-audit",
  mode="bypassPermissions",
  subagent_type="general-purpose",
  prompt= 提示词模板(TASK_ID=9) + context_extractor.md 内容
)
```
输出: $WORK_DIR/context_packs/*.json

**等待完成。**

### 串行 Step 2: risk-classifier

读取: ${SKILL_DIR}/teams/team2/risk_classifier.md

**Agent 6: risk-classifier**
```
Agent(
  name="risk-classifier",
  team_name="php-audit",
  mode="bypassPermissions",
  subagent_type="general-purpose",
  prompt= 提示词模板(TASK_ID=10) + risk_classifier.md 内容
)
```
输出: $WORK_DIR/priority_queue.json

**等待完成。**

### 串行 Step 3: quality-checker-2

读取: ${SKILL_DIR}/teams/qc/quality_checker.md + ${SKILL_DIR}/references/quality_check_templates.md

**Agent 7: quality-checker-2**
```
Agent(
  name="quality-checker-2",
  team_name="php-audit",
  mode="bypassPermissions",
  subagent_type="general-purpose",
  prompt= 提示词模板(TASK_ID=11) + teams/qc/quality_checker.md + references/quality_check_templates.md（对应阶段章节）+ shared/output_standard.md
)
```
输出: Phase-2 质检结果 JSON

**等待完成。** 解析 Phase-2 质检结果（失败不阻塞，标注覆盖率继续）。
