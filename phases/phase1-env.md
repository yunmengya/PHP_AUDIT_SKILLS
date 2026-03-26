# Phase 1: Intelligent Environment Detection & Setup

The main dispatcher has set variables: TARGET_PATH, WORK_DIR, SKILL_DIR, SHARED_RESOURCES

## Agent Prompt Template

Each Agent's prompt SHALL be constructed using this template:

```
Your assigned Task ID is #{TASK_ID}.
When starting work: TaskUpdate(taskId="{TASK_ID}", status="in_progress")
When completing work: TaskUpdate(taskId="{TASK_ID}", status="completed")
You MUST NOT create new tasks or write checkpoint.json.

--- Lifecycle Management ---
When you receive a shutdown_request:
1. Confirm all output files have been written to disk
2. Reply with SendMessage(type: "shutdown_response", request_id: "{received request_id}", approve: true)
If no shutdown_request is received within 30 seconds, you MAY stop on your own after task completion.

TARGET_PATH={TARGET_PATH}
WORK_DIR={WORK_DIR}

--- Shared Resources ---
{SHARED_RESOURCES}

--- Task Instructions ---
{Agent .md file contents}
```

## Execution Steps

### Parallel Step

Read the following file contents:
- ${SKILL_DIR}/teams/team1/env_detective.md
- ${SKILL_DIR}/teams/team1/schema_reconstructor.md

Spawn two Agents simultaneously (background mode, true parallelism):

**Agent 1: env-detective**
```
Agent(
  name="env-detective",
  team_name="php-audit",
  run_in_background=true,
  mode="bypassPermissions",
  subagent_type="general-purpose",
  prompt= Prompt template(TASK_ID=1) + env_detective.md contents
)
```
Output: Environment analysis results (framework / PHP version / DB type / extensions, etc.)

**Agent 2: schema-reconstructor**
```
Agent(
  name="schema-reconstructor",
  team_name="php-audit",
  run_in_background=true,
  mode="bypassPermissions",
  subagent_type="general-purpose",
  prompt= Prompt template(TASK_ID=2) + schema_reconstructor.md contents
)
```
Output: $WORK_DIR/reconstructed_schema.sql

**Wait for both to complete.**

### Sequential Step 1: docker-builder

Read the following file contents:
- ${SKILL_DIR}/teams/team1/docker_builder.md
- ${SKILL_DIR}/shared/env_selfheal.md

**Agent 3: docker-builder**
```
Agent(
  name="docker-builder",
  team_name="php-audit",
  mode="bypassPermissions",
  subagent_type="general-purpose",
  prompt= Prompt template(TASK_ID=3) + docker_builder.md + env_selfheal.md + env-detective return results
)
```
Output: $WORK_DIR/environment_status.json, $WORK_DIR/docker-compose.yml, $WORK_DIR/docker/

**Wait for completion.**

### Sequential Step 2: quality-checker-1

Read: ${SKILL_DIR}/teams/qc/quality_checker.md + ${SKILL_DIR}/references/quality_check_templates.md

**Agent 4: quality-checker-1**
```
Agent(
  name="quality-checker-1",
  team_name="php-audit",
  mode="bypassPermissions",
  subagent_type="general-purpose",
  prompt= Prompt template(TASK_ID=4) + teams/qc/quality_checker.md + references/quality_check_templates.md (corresponding phase section) + shared/output_standard.md
)
```
Output: Phase-1 quality check result JSON

**Wait for completion.**

## Result Parsing

Parse the Phase-1 quality check return result:
- Pass → Set MODE=full, continue
- Fail → Re-spawn docker-builder (inject previous failure logs), repeat Step 1 ~ Step 2 until quality check passes
  - Self-healing loop (Phase A 5 rounds + Phase B 3 rounds) all fail → Pause, request user intervention via AskUserQuestion
  - After user fix, continue retrying — **downgrading to static-only MUST NOT be permitted**
