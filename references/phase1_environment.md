# Phase 1: Intelligent Environment Detection (Detailed Flow)

> This file is extracted from SKILL.md and loaded by the main orchestrator via reference.

### Phase-1: Intelligent Environment Detection and Build

── Parallel Step ──

Read teams/team1/env_detective.md + shared resources
Read teams/team1/schema_reconstructor.md + shared resources

Spawn two Agents simultaneously (background mode):

  Agent(name="env-detective", team_name="php-audit", run_in_background=true, mode="bypassPermissions", subagent_type="general-purpose")
    → prompt: Task #1 instructions + teams/team1/env_detective.md + shared resources + TARGET_PATH + WORK_DIR

  Agent(name="schema-reconstructor", team_name="php-audit", run_in_background=true, mode="bypassPermissions", subagent_type="general-purpose")
    → prompt: Task #2 instructions + teams/team1/schema_reconstructor.md + shared resources + TARGET_PATH + WORK_DIR

Wait for both to complete
── Serial Step ──

  Agent(name="docker-builder", team_name="php-audit", foreground, mode="bypassPermissions", subagent_type="general-purpose")
    → prompt: Task #3 instructions + teams/team1/docker_builder.md + shared/env_selfheal.md + shared resources
            + @env-detective's return results + TARGET_PATH + WORK_DIR

Complete
  Agent(name="quality-checker-1", team_name="php-audit", foreground, mode="bypassPermissions", subagent_type="general-purpose")
    → prompt: Task #4 instructions + teams/qc/quality_checker.md
            + references/quality_check_templates.md (Phase 1 section)
            + shared/output_standard.md + shared/data_contracts.md
            + PHASE=1, TARGET_AGENT=docker_builder, OUTPUT_FILES=environment_status.json
            + WORK_DIR

Complete
**QC Result Handling (MUST pass)**:
```
Parse quality checker return results:
  - verdict=pass → MODE="full", close quality-checker-1, continue normal flow
  - verdict=fail → send failed_items back to docker-builder for redo
    → spawn quality checker again for verification after redo (max 3 times)
    → 3 failures → demote to partial mode (skip Phase 3, Team-4 falls back to context_pack)
    → all self-heal cycles failed → pause, request user intervention via AskUserQuestion
```

Write checkpoint.json: {"completed": ["env"], "current": "scan"}
Print pipeline view

