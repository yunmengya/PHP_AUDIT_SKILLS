# Phase 4.5: Post-Exploitation Intelligent Analysis

The main dispatcher has set variables: TARGET_PATH, WORK_DIR, SKILL_DIR, SHARED_RESOURCES
Refer to the prompt template in phase1-env.md.
Dynamic TASK_ID mappings were recorded during the phase2-tasks-dynamic.md stage.

**This Phase is the SOLE source of PoC scripts — it MUST NOT be skipped.**

## Execution Steps

### Parallel Step 1: Attack Graph + Correlation Analysis

Read the following file contents:
- ${SKILL_DIR}/teams/team4.5/attack_graph_builder.md
- ${SKILL_DIR}/teams/team4.5/correlation_engine.md
- ${SKILL_DIR}/shared/false_positive_patterns.md
- ${SKILL_DIR}/shared/second_order.md

Spawn two Agents simultaneously (background mode):

**Agent 1: attack-graph-builder**
```
Agent(
  name="attack-graph-builder",
  team_name="php-audit",
  run_in_background=true,
  mode="bypassPermissions",
  subagent_type="general-purpose",
  prompt= Prompt template(TASK_ID=M) + attack_graph_builder.md contents
)
```
Output: $WORK_DIR/attack_graph.json

**Agent 2: correlation-engine**
```
Agent(
  name="correlation-engine",
  team_name="php-audit",
  run_in_background=true,
  mode="bypassPermissions",
  subagent_type="general-purpose",
  prompt= Prompt template(TASK_ID=M+1)
        + correlation_engine.md
        + false_positive_patterns.md
        + second_order.md contents
)
```
Output: $WORK_DIR/correlation_report.json, $WORK_DIR/second_order/correlations.json

**Wait for both to complete.**

### Parallel Step 2: Remediation Patches + PoC Scripts

Read the following file contents:
- ${SKILL_DIR}/teams/team4.5/remediation_generator.md
- ${SKILL_DIR}/teams/team4.5/poc_generator.md
- ${SKILL_DIR}/shared/framework_patterns.md

Spawn two Agents simultaneously (background mode):

**Agent 3: remediation-generator**
```
Agent(
  name="remediation-generator",
  team_name="php-audit",
  run_in_background=true,
  mode="bypassPermissions",
  subagent_type="general-purpose",
  prompt= Prompt template(TASK_ID=M+2)
        + remediation_generator.md
        + framework_patterns.md contents
)
```
Output: $WORK_DIR/patches/*.patch, $WORK_DIR/patches/remediation_summary.json

**Agent 4: poc-generator**
```
Agent(
  name="poc-generator",
  team_name="php-audit",
  run_in_background=true,
  mode="bypassPermissions",
  subagent_type="general-purpose",
  prompt= Prompt template(TASK_ID=M+3) + poc_generator.md contents
)
```
Output: $WORK_DIR/PoC脚本/poc_*.py, $WORK_DIR/PoC脚本/poc_summary.json, $WORK_DIR/PoC脚本/一键运行.sh

**Wait for both to complete.**
