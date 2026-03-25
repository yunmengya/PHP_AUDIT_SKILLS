# Phase 3: 鉴权模拟与动态追踪

主调度器已设置变量: TARGET_PATH, WORK_DIR, SKILL_DIR, SHARED_RESOURCES, MODE
提示词模板参考 phase1-env.md 中的模板。

**注意**: Docker 环境必须构建成功后才会进入此 Phase。

## 执行步骤

### 串行 Step 1: auth-simulator

读取: ${SKILL_DIR}/teams/team3/auth_simulator.md

**Agent 1: auth-simulator**
```
Agent(
  name="auth-simulator",
  team_name="php-audit",
  mode="bypassPermissions",
  subagent_type="general-purpose",
  prompt= 提示词模板(TASK_ID=12) + auth_simulator.md 内容
)
```
输出: $WORK_DIR/credentials.json

**等待完成。**

### 串行 Step 2: trace-dispatcher

读取:
- ${SKILL_DIR}/teams/team3/trace_dispatcher.md
- ${SKILL_DIR}/teams/team3/trace_worker.md（注入到 dispatcher prompt 中，供其内部 spawn worker）

**Agent 2: trace-dispatcher**
```
Agent(
  name="trace-dispatcher",
  team_name="php-audit",
  mode="bypassPermissions",
  subagent_type="general-purpose",
  prompt= 提示词模板(TASK_ID=13) + trace_dispatcher.md + trace_worker.md 内容
)
```
内部并行 spawn 最多 2 个 trace-worker。
输出: $WORK_DIR/traces/*.json

**等待完成。**

### 串行 Step 3: quality-checker-3

读取: ${SKILL_DIR}/teams/qc/quality_checker.md + ${SKILL_DIR}/references/quality_check_templates.md

**Agent 3: quality-checker-3**
```
Agent(
  name="quality-checker-3",
  team_name="php-audit",
  mode="bypassPermissions",
  subagent_type="general-purpose",
  prompt= 提示词模板(TASK_ID=14) + teams/qc/quality_checker.md + references/quality_check_templates.md（对应阶段章节）+ shared/output_standard.md
)
```
输出: Phase-3 质检结果 JSON

**等待完成。** 解析 Phase-3 质检结果（失败 → 断链路由退回静态分析，不阻塞）。
