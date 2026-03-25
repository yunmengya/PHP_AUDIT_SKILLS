# Phase 2：静态资产侦察（详细流程）

> 本文件由 SKILL.md 提取，主调度器通过引用加载。

### Phase-2: 静态资产侦察

── 并行 step ──

同时 spawn 四个 Agent（background 模式）:

  Agent(name="tool-runner", team_name="php-audit", run_in_background=true, mode="bypassPermissions", subagent_type="general-purpose")
    → prompt: Task #5 指令 + teams/team2/tool_runner.md + 共享资源
            + tools/sink_finder.php（告知路径和用法）+ TARGET_PATH + WORK_DIR

  Agent(name="route-mapper", team_name="php-audit", run_in_background=true, mode="bypassPermissions", subagent_type="general-purpose")
    → prompt: Task #6 指令 + teams/team2/route_mapper.md + 共享资源 + TARGET_PATH + WORK_DIR

  Agent(name="auth_auditor", team_name="php-audit", run_in_background=true, mode="bypassPermissions", subagent_type="general-purpose")
    → prompt: Task #7 指令 + teams/team2/auth_auditor.md + 共享资源 + TARGET_PATH + WORK_DIR

  Agent(name="dep-scanner", team_name="php-audit", run_in_background=true, mode="bypassPermissions", subagent_type="general-purpose")
    → prompt: Task #8 指令 + teams/team2/dep_scanner.md + shared/known_cves.md
            + 共享资源 + TARGET_PATH + WORK_DIR

等待四者全部完成
── 串行 step ──

  Agent(name="context-extractor", team_name="php-audit", foreground, mode="bypassPermissions", subagent_type="general-purpose")
    → prompt: Task #9 指令 + teams/team2/context_extractor.md + shared/framework_patterns.md
            + shared/php_specific_patterns.md + 共享资源 + TARGET_PATH + WORK_DIR

完成
  Agent(name="risk-classifier", team_name="php-audit", foreground, mode="bypassPermissions", subagent_type="general-purpose")
    → prompt: Task #10 指令 + teams/team2/risk_classifier.md + shared/framework_patterns.md
            + 共享资源 + TARGET_PATH + WORK_DIR

完成
  Agent(name="quality-checker-2", team_name="php-audit", foreground, mode="bypassPermissions", subagent_type="general-purpose")
    → prompt: Task #11 指令 + teams/qc/quality_checker.md
            + references/quality_check_templates.md（阶段 2 章节）
            + shared/output_standard.md + shared/data_contracts.md
            + PHASE=2, TARGET_AGENT=team2, OUTPUT_FILES=route_map.json,auth_matrix.json,ast_sinks.json,priority_queue.json,context_packs/,dep_risk.json
            + WORK_DIR

完成
解析质检结果（verdict=fail → 按 failed_items 定位责任 Agent 重做，最多 2 次；不阻塞，标注覆盖率继续）

**Phase-2 Gate 验证**（必须执行）:
```bash
test -f "$WORK_DIR/priority_queue.json" && test -d "$WORK_DIR/context_packs" && echo "GATE-2 PASS" || echo "GATE-2 FAIL"
```
GATE-2 PASS → 写入 checkpoint.json: {"completed": ["env", "scan"], "current": "trace"}
GATE-2 FAIL → 不写入 checkpoint，检查 context-extractor / risk-classifier 是否正常执行

打印流水线视图

