# Phase 3：鉴权模拟与动态追踪（详细流程）

> 本文件由 SKILL.md 提取，主调度器通过引用加载。

### Phase-3: 鉴权模拟与动态追踪

── 串行 step ──

  Agent(name="auth-simulator", team_name="php-audit", foreground, mode="bypassPermissions", subagent_type="general-purpose")
    → prompt: Task #12 指令 + teams/team3/auth_simulator.md + 共享资源 + TARGET_PATH + WORK_DIR

完成
  Agent(name="trace-dispatcher", team_name="php-audit", foreground, mode="bypassPermissions", subagent_type="general-purpose")
    → prompt: Task #13 指令 + teams/team3/trace_dispatcher.md + 共享资源
            + teams/team3/trace_worker.md（注入 worker prompt 供其内部 spawn）
            + tools/trace_filter.php（告知路径和用法）
            + TARGET_PATH + WORK_DIR
    → 内部并行 spawn 最多 2 个 trace-worker

完成
  Agent(name="quality-checker-3", team_name="php-audit", foreground, mode="bypassPermissions", subagent_type="general-purpose")
    → prompt: Task #14 指令 + teams/qc/quality_checker.md
            + references/quality_check_templates.md（阶段 3 章节）
            + shared/output_standard.md + shared/data_contracts.md + shared/evidence_contract.md
            + PHASE=3, TARGET_AGENT=team3, OUTPUT_FILES=credentials.json,traces/
            + WORK_DIR

完成
解析质检结果（verdict=fail → 断链路由退回静态分析，不阻塞）

**Phase-3 Gate 验证**（必须执行）:
```bash
test -f "$WORK_DIR/credentials.json" && echo "GATE-3 PASS" || echo "GATE-3 FAIL"
```
写入 checkpoint.json: {"completed": ["env", "scan", "trace"], "current": "exploit"}
打印流水线视图

**auth-simulator 降级策略**: 如果 auth-simulator 无法获取有效凭证:
- 登录失败 → 尝试默认凭证组合（admin/admin, test/test, admin/123456）
- 注册接口可用 → 自动注册测试账号
- 全部失败 → 设置 `credentials.json` 中 authenticated/admin 为 null，Phase-4 仅测试 anonymous 路由
- 在 checkpoint.json 中标注 `"mode": "degraded"`，报告中注明 "⚠️ 未获取认证凭证，仅测试匿名可访问接口"

