# Phase 4.5：后渗透智能分析（关联分析 + Patch 验证）

> 本文件由 SKILL.md 提取，主调度器通过引用加载。

### Phase-4.5: 后渗透智能分析

**⚠️ 此 Phase 是 PoC 脚本的唯一来源，绝对不可跳过。**

── 并行 step ──

同时 spawn 两个 Agent（background 模式）:

  Agent(name="attack-graph-builder", team_name="php-audit", run_in_background=true, mode="bypassPermissions", subagent_type="general-purpose")
    → prompt: Task #M 指令 + teams/team4.5/attack_graph_builder.md
            + shared/attack_chains.md + 共享资源 + WORK_DIR

  Agent(name="correlation-engine", team_name="php-audit", run_in_background=true, mode="bypassPermissions", subagent_type="general-purpose")
    → prompt: Task #M+1 指令 + teams/team4.5/correlation_engine.md
            + shared/false_positive_patterns.md + shared/second_order.md
            + shared/attack_chains.md + 共享资源 + WORK_DIR

等待两者完成
── 并行 step ──

同时 spawn 两个 Agent（background 模式）:

  Agent(name="remediation-generator", team_name="php-audit", run_in_background=true, mode="bypassPermissions", subagent_type="general-purpose")
    → prompt: Task #M+2 指令 + teams/team4.5/remediation_generator.md
            + shared/framework_patterns.md + 共享资源 + TARGET_PATH + WORK_DIR

  Agent(name="poc-generator", team_name="php-audit", run_in_background=true, mode="bypassPermissions", subagent_type="general-purpose")
    → prompt: Task #M+3 指令 + teams/team4.5/poc_generator.md
            + shared/payload_templates.md + shared/waf_bypass.md + 共享资源 + WORK_DIR

等待两者完成

**Phase-4.5 Gate 验证**（必须执行）:
```bash
test -d "$WORK_DIR/poc" && ls "$WORK_DIR/poc/"*.py >/dev/null 2>&1 && echo "GATE-4.5 PASS" || echo "GATE-4.5 FAIL: poc/ 不存在或为空"
test -d "$WORK_DIR/patches" && echo "PATCHES PASS" || echo "PATCHES FAIL"
```
GATE-4.5 PASS → 写入 checkpoint.json: {"completed": ["env", "scan", "trace", "exploit", "post_exploit"], "current": "report"}
GATE-4.5 FAIL → 检查 poc-generator / remediation-generator 是否实际执行并返回结果

打印流水线视图
