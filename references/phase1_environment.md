# Phase 1：环境智能识别（详细流程）

> 本文件由 SKILL.md 提取，主调度器通过引用加载。

### Phase-1: 环境智能识别与构建

── 并行 step ──

读取 teams/team1/env_detective.md + 共享资源
读取 teams/team1/schema_reconstructor.md + 共享资源

同时 spawn 两个 Agent（background 模式）:

  Agent(name="env-detective", team_name="php-audit", run_in_background=true, mode="bypassPermissions", subagent_type="general-purpose")
    → prompt: Task #1 指令 + teams/team1/env_detective.md + 共享资源 + TARGET_PATH + WORK_DIR

  Agent(name="schema-reconstructor", team_name="php-audit", run_in_background=true, mode="bypassPermissions", subagent_type="general-purpose")
    → prompt: Task #2 指令 + teams/team1/schema_reconstructor.md + 共享资源 + TARGET_PATH + WORK_DIR

等待两者全部完成
── 串行 step ──

  Agent(name="docker-builder", team_name="php-audit", foreground, mode="bypassPermissions", subagent_type="general-purpose")
    → prompt: Task #3 指令 + teams/team1/docker_builder.md + shared/env_selfheal.md + 共享资源
            + @env-detective 的返回结果 + TARGET_PATH + WORK_DIR

完成
  Agent(name="quality-checker-1", team_name="php-audit", foreground, mode="bypassPermissions", subagent_type="general-purpose")
    → prompt: Task #4 指令 + teams/qc/quality_checker.md
            + references/quality_check_templates.md（阶段 1 章节）
            + shared/output_standard.md + shared/data_contracts.md
            + PHASE=1, TARGET_AGENT=docker_builder, OUTPUT_FILES=environment_status.json
            + WORK_DIR

完成
**质检结果处理（必须通过）**:
```
解析质检员返回结果:
  - verdict=pass → MODE="full"，关闭 quality-checker-1，继续正常流程
  - verdict=fail → 将 failed_items 发回 docker-builder 重做
    → 重做后再次 spawn 质检员校验（最多 3 次）
    → 3 次不通过 → 降级为 partial 模式（跳过 Phase 3，Team-4 退回 context_pack）
    → 自愈循环全部失败 → 暂停，通过 AskUserQuestion 请求用户介入
```

写入 checkpoint.json: {"completed": ["env"], "current": "scan"}
打印流水线视图

