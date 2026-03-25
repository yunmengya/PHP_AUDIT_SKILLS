# Phase 1: 环境智能识别与构建

主调度器已设置变量: TARGET_PATH, WORK_DIR, SKILL_DIR, SHARED_RESOURCES

## Agent 提示词模板

每个 Agent 的 prompt 按此模板构建:

```
你负责的 Task ID 是 #{TASK_ID}。
开始工作时: TaskUpdate(taskId="{TASK_ID}", status="in_progress")
完成工作时: TaskUpdate(taskId="{TASK_ID}", status="completed")
不要创建新任务、不要写 checkpoint.json。

--- 生命周期管理 ---
当你收到 shutdown_request 时:
1. 确认所有输出文件已写入磁盘
2. 回复 SendMessage(type: "shutdown_response", request_id: "{收到的request_id}", approve: true)
若 30 秒内未收到 shutdown_request，任务完成后自行停止即可。

TARGET_PATH={TARGET_PATH}
WORK_DIR={WORK_DIR}

--- 共享资源 ---
{SHARED_RESOURCES}

--- 任务指令 ---
{Agent .md 文件内容}
```

## 执行步骤

### 并行 Step

读取以下文件内容:
- ${SKILL_DIR}/teams/team1/env_detective.md
- ${SKILL_DIR}/teams/team1/schema_reconstructor.md

同时 spawn 两个 Agent（background 模式，真正并行）:

**Agent 1: env-detective**
```
Agent(
  name="env-detective",
  team_name="php-audit",
  run_in_background=true,
  mode="bypassPermissions",
  subagent_type="general-purpose",
  prompt= 提示词模板(TASK_ID=1) + env_detective.md 内容
)
```
输出: 环境分析结果（框架/PHP版本/DB类型/扩展等）

**Agent 2: schema-reconstructor**
```
Agent(
  name="schema-reconstructor",
  team_name="php-audit",
  run_in_background=true,
  mode="bypassPermissions",
  subagent_type="general-purpose",
  prompt= 提示词模板(TASK_ID=2) + schema_reconstructor.md 内容
)
```
输出: $WORK_DIR/reconstructed_schema.sql

**等待两者全部完成。**

### 串行 Step 1: docker-builder

读取以下文件内容:
- ${SKILL_DIR}/teams/team1/docker_builder.md
- ${SKILL_DIR}/shared/env_selfheal.md

**Agent 3: docker-builder**
```
Agent(
  name="docker-builder",
  team_name="php-audit",
  mode="bypassPermissions",
  subagent_type="general-purpose",
  prompt= 提示词模板(TASK_ID=3) + docker_builder.md + env_selfheal.md + env-detective 的返回结果
)
```
输出: $WORK_DIR/environment_status.json, $WORK_DIR/docker-compose.yml, $WORK_DIR/docker/

**等待完成。**

### 串行 Step 2: quality-checker-1

读取: ${SKILL_DIR}/teams/qc/quality_checker.md + ${SKILL_DIR}/references/quality_check_templates.md

**Agent 4: quality-checker-1**
```
Agent(
  name="quality-checker-1",
  team_name="php-audit",
  mode="bypassPermissions",
  subagent_type="general-purpose",
  prompt= 提示词模板(TASK_ID=4) + teams/qc/quality_checker.md + references/quality_check_templates.md（对应阶段章节）+ shared/output_standard.md
)
```
输出: Phase-1 质检结果 JSON

**等待完成。**

## 结果解析

解析 Phase-1 质检返回结果:
- 通过 → 设置 MODE=full，继续
- 失败 → 重新 spawn docker-builder（注入上次失败日志），重复 Step 1 ~ Step 2 直到质检通过
  - 自愈循环（Phase A 5 轮 + Phase B 3 轮）全部失败 → 暂停，通过 AskUserQuestion 请求用户介入修复
  - 用户修复后继续重试，**不允许降级为 static-only**
