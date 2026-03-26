# Phase 4.5: Post-Exploitation Intelligent Analysis (Correlation Analysis + Patch Verification)

> This file is extracted from SKILL.md and loaded by reference by the main orchestrator.

### Phase-4.5: Post-Exploitation Intelligent Analysis

**⚠️ This Phase is the sole source of PoC scripts; it MUST NOT under any circumstances be skipped.**

── Parallel step ──

Spawn two Agents simultaneously (background mode):

  Agent(name="attack-graph-builder", team_name="php-audit", run_in_background=true, mode="bypassPermissions", subagent_type="general-purpose")
    → prompt: Task #M instructions + teams/team4.5/attack_graph_builder.md
            + shared/attack_chains.md + shared resources + WORK_DIR

  Agent(name="correlation-engine", team_name="php-audit", run_in_background=true, mode="bypassPermissions", subagent_type="general-purpose")
    → prompt: Task #M+1 instructions + teams/team4.5/correlation_engine.md
            + shared/false_positive_patterns.md + shared/second_order.md
            + shared/attack_chains.md + shared resources + WORK_DIR

Wait for both to complete
── Parallel step ──

Spawn two Agents simultaneously (background mode):

  Agent(name="remediation-generator", team_name="php-audit", run_in_background=true, mode="bypassPermissions", subagent_type="general-purpose")
    → prompt: Task #M+2 instructions + teams/team4.5/remediation_generator.md
            + shared/framework_patterns.md + shared resources + TARGET_PATH + WORK_DIR

  Agent(name="poc-generator", team_name="php-audit", run_in_background=true, mode="bypassPermissions", subagent_type="general-purpose")
    → prompt: Task #M+3 instructions + teams/team4.5/poc_generator.md
            + shared/payload_templates.md + shared/waf_bypass.md + shared resources + WORK_DIR

Wait for both to complete

**Phase-4.5 Gate Verification** (MUST execute):
```bash
test -d "$WORK_DIR/PoC脚本" && ls "$WORK_DIR/PoC脚本/"*.py >/dev/null 2>&1 && echo "GATE-4.5 PASS" || echo "GATE-4.5 FAIL: PoC脚本/ 不存在或为空"
test -d "$WORK_DIR/修复补丁" && echo "PATCHES PASS" || echo "PATCHES FAIL"
```
GATE-4.5 PASS → Write to checkpoint.json: {"completed": ["env", "scan", "trace", "exploit", "post_exploit"], "current": "report"}
GATE-4.5 FAIL → Check whether poc-generator / remediation-generator actually executed and returned results

Print pipeline view
