# Phase 2: Static Asset Reconnaissance (Detailed Flow)

> This file is extracted from SKILL.md and loaded by the main orchestrator via reference.

### Phase-2: Static Asset Reconnaissance

── Parallel Step ──

Spawn ten Agents simultaneously (background mode):

  Agent(name="psalm-scanner", team_name="php-audit", run_in_background=true, mode="bypassPermissions", subagent_type="general-purpose")
    → prompt: Task #5a instructions + skills/scanners/psalm_scanner.md + shared resources + TARGET_PATH + WORK_DIR

  Agent(name="progpilot-scanner", team_name="php-audit", run_in_background=true, mode="bypassPermissions", subagent_type="general-purpose")
    → prompt: Task #5b instructions + skills/scanners/progpilot_scanner.md + shared resources + TARGET_PATH + WORK_DIR

  (... 5 more scanners: ast, phpstan, semgrep, composer-audit, codeql ...)

  Agent(name="route-mapper", team_name="php-audit", run_in_background=true, mode="bypassPermissions", subagent_type="general-purpose")
    → prompt: Task #6 instructions + teams/team2/route_mapper.md + shared resources + TARGET_PATH + WORK_DIR

  Agent(name="auth_auditor", team_name="php-audit", run_in_background=true, mode="bypassPermissions", subagent_type="general-purpose")
    → prompt: Task #7 instructions + teams/team2/auth_auditor.md + shared resources + TARGET_PATH + WORK_DIR

  Agent(name="dep-scanner", team_name="php-audit", run_in_background=true, mode="bypassPermissions", subagent_type="general-purpose")
    → prompt: Task #8 instructions + teams/team2/dep_scanner.md + shared/known_cves.md
            + shared resources + TARGET_PATH + WORK_DIR

Wait for all four to complete
── Serial Step ──

  Agent(name="context-extractor", team_name="php-audit", foreground, mode="bypassPermissions", subagent_type="general-purpose")
    → prompt: Task #9 instructions + teams/team2/context_extractor.md + shared/framework_patterns.md
            + shared/php_specific_patterns.md + shared resources + TARGET_PATH + WORK_DIR

Complete
  Agent(name="risk-classifier", team_name="php-audit", foreground, mode="bypassPermissions", subagent_type="general-purpose")
    → prompt: Task #10 instructions + teams/team2/risk_classifier.md + shared/framework_patterns.md
            + shared resources + TARGET_PATH + WORK_DIR

Complete
  Agent(name="quality-checker-2", team_name="php-audit", foreground, mode="bypassPermissions", subagent_type="general-purpose")
    → prompt: Task #11 instructions + teams/qc/quality_checker.md
            + references/quality_check_templates.md (Phase 2 section)
            + shared/output_standard.md + shared/data_contracts.md
            + PHASE=2, TARGET_AGENT=team2, OUTPUT_FILES=route_map.json,auth_matrix.json,ast_sinks.json,priority_queue.json,context_packs/,dep_risk.json
            + WORK_DIR

Complete
Parse QC results (verdict=fail → locate responsible Agent by failed_items for redo, max 2 times; non-blocking, annotate coverage and continue)

**Phase-2 Gate Validation** (MUST execute):
```bash
test -f "$WORK_DIR/priority_queue.json" && test -d "$WORK_DIR/context_packs" && echo "GATE-2 PASS" || echo "GATE-2 FAIL"
```
GATE-2 PASS → Write checkpoint.json: {"completed": ["env", "scan"], "current": "trace"}
GATE-2 FAIL → Do not write checkpoint; verify whether context-extractor / risk-classifier executed normally

Print pipeline view

