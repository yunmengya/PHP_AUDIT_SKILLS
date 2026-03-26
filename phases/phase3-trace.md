# Phase 3: Authentication Simulation & Dynamic Tracing

The main dispatcher has set variables: TARGET_PATH, WORK_DIR, SKILL_DIR, SHARED_RESOURCES, MODE
Refer to the prompt template in phase1-env.md.

**Note**: This Phase MUST only be entered after the Docker environment has been successfully built.

## Execution Steps

### Sequential Step 1: auth-simulator

Read: ${SKILL_DIR}/teams/team3/auth_simulator.md

**Agent 1: auth-simulator**
```
Agent(
  name="auth-simulator",
  team_name="php-audit",
  mode="bypassPermissions",
  subagent_type="general-purpose",
  prompt= Prompt template(TASK_ID=12) + auth_simulator.md contents
)
```
Output: $WORK_DIR/credentials.json

**Wait for completion.**

### Sequential Step 2: trace-dispatcher

Read:
- ${SKILL_DIR}/teams/team3/trace_dispatcher.md
- ${SKILL_DIR}/teams/team3/trace_worker.md (injected into dispatcher prompt for internal worker spawning)

**Agent 2: trace-dispatcher**
```
Agent(
  name="trace-dispatcher",
  team_name="php-audit",
  mode="bypassPermissions",
  subagent_type="general-purpose",
  prompt= Prompt template(TASK_ID=13) + trace_dispatcher.md + trace_worker.md contents
)
```
Internally spawns up to 2 trace-workers in parallel.
Output: $WORK_DIR/traces/*.json

**Wait for completion.**

### Sequential Step 3: quality-checker-3

Read: ${SKILL_DIR}/teams/qc/quality_checker.md + ${SKILL_DIR}/references/quality_check_templates.md

**Agent 3: quality-checker-3**
```
Agent(
  name="quality-checker-3",
  team_name="php-audit",
  mode="bypassPermissions",
  subagent_type="general-purpose",
  prompt= Prompt template(TASK_ID=14) + teams/qc/quality_checker.md + references/quality_check_templates.md (corresponding phase section) + shared/output_standard.md
)
```
Output: Phase-3 quality check result JSON

**Wait for completion.** Parse Phase-3 quality check result (failure → break chain and fall back to static analysis; MUST NOT block).
