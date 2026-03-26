# Phase 4.5: 后渗透智能分析

主调度器已设置变量: TARGET_PATH, WORK_DIR, SKILL_DIR, SHARED_RESOURCES
提示词模板参考 phase1-env.md 中的模板。
动态 TASK_ID 映射由 phase2-tasks-dynamic.md 阶段记录。

**此 Phase 是 PoC 脚本的唯一来源，绝对不可跳过。**

## 执行步骤

### 并行 Step 1: 攻击图谱 + 关联分析

读取以下文件内容:
- ${SKILL_DIR}/teams/team4.5/attack_graph_builder.md
- ${SKILL_DIR}/teams/team4.5/correlation_engine.md
- ${SKILL_DIR}/shared/false_positive_patterns.md
- ${SKILL_DIR}/shared/second_order.md

同时 spawn 两个 Agent（background 模式）:

**Agent 1: attack-graph-builder**
```
Agent(
  name="attack-graph-builder",
  team_name="php-audit",
  run_in_background=true,
  mode="bypassPermissions",
  subagent_type="general-purpose",
  prompt= 提示词模板(TASK_ID=M) + attack_graph_builder.md 内容
)
```
输出: $WORK_DIR/attack_graph.json

**Agent 2: correlation-engine**
```
Agent(
  name="correlation-engine",
  team_name="php-audit",
  run_in_background=true,
  mode="bypassPermissions",
  subagent_type="general-purpose",
  prompt= 提示词模板(TASK_ID=M+1)
        + correlation_engine.md
        + false_positive_patterns.md
        + second_order.md 内容
)
```
输出: $WORK_DIR/correlation_report.json, $WORK_DIR/second_order/correlations.json

**等待两者完成。**

### 并行 Step 2: 修复 Patch + PoC 脚本

读取以下文件内容:
- ${SKILL_DIR}/teams/team4.5/remediation_generator.md
- ${SKILL_DIR}/teams/team4.5/poc_generator.md
- ${SKILL_DIR}/shared/framework_patterns.md

同时 spawn 两个 Agent（background 模式）:

**Agent 3: remediation-generator**
```
Agent(
  name="remediation-generator",
  team_name="php-audit",
  run_in_background=true,
  mode="bypassPermissions",
  subagent_type="general-purpose",
  prompt= 提示词模板(TASK_ID=M+2)
        + remediation_generator.md
        + framework_patterns.md 内容
)
```
输出: $WORK_DIR/patches/*.patch, $WORK_DIR/patches/remediation_summary.json

**Agent 4: poc-generator**
```
Agent(
  name="poc-generator",
  team_name="php-audit",
  run_in_background=true,
  mode="bypassPermissions",
  subagent_type="general-purpose",
  prompt= 提示词模板(TASK_ID=M+3) + poc_generator.md 内容
)
```
输出: $WORK_DIR/PoC脚本/poc_*.py, $WORK_DIR/PoC脚本/poc_summary.json, $WORK_DIR/PoC脚本/一键运行.sh

**等待两者完成。**
