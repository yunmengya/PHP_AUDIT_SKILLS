# Phase 3: Authentication Simulation & Dynamic Tracing (Detailed Flow)

> This file is extracted from SKILL.md and loaded by reference by the main orchestrator.

### Phase-3: Authentication Simulation & Dynamic Tracing

── Sequential step ──

  Agent(name="auth-simulator", team_name="php-audit", foreground, mode="bypassPermissions", subagent_type="general-purpose")
    → prompt: Task #12 instructions + teams/team3/auth_simulator.md + shared resources + TARGET_PATH + WORK_DIR

Completed
  Agent(name="trace-dispatcher", team_name="php-audit", foreground, mode="bypassPermissions", subagent_type="general-purpose")
    → prompt: Task #13 instructions + teams/team3/trace_dispatcher.md + shared resources
            + teams/team3/trace_worker.md (injected as worker prompt for internal spawning)
            + tools/trace_filter.php (provide path and usage)
            + TARGET_PATH + WORK_DIR
    → Internally spawns up to 2 trace-workers in parallel

Completed
  Agent(name="quality-checker-3", team_name="php-audit", foreground, mode="bypassPermissions", subagent_type="general-purpose")
    → prompt: Task #14 instructions + teams/qc/quality_checker.md
            + references/quality_check_templates.md (Phase 3 section)
            + shared/output_standard.md + shared/data_contracts.md + shared/evidence_contract.md
            + PHASE=3, TARGET_AGENT=team3, OUTPUT_FILES=credentials.json,traces/
            + WORK_DIR

Completed
Parse quality check results (verdict=fail → broken chain routes back to static analysis, non-blocking)

**Phase-3 Gate Verification** (MUST execute):
```bash
test -f "$WORK_DIR/credentials.json" && echo "GATE-3 PASS" || echo "GATE-3 FAIL"
```
Write to checkpoint.json: {"completed": ["env", "scan", "trace"], "current": "exploit"}
Print pipeline view

**auth-simulator Degradation Strategy**: If auth-simulator cannot obtain valid credentials:
- Login failure → Try default credential combinations (admin/admin, test/test, admin/123456)
- Registration endpoint available → Auto-register a test account
- All failed → Set authenticated/admin to null in `credentials.json`, Phase-4 only tests anonymous routes
- Mark `"mode": "degraded"` in checkpoint.json, note in report "⚠️ 未获取认证凭证，仅测试匿名可访问接口"

