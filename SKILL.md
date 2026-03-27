---
name: php-audit
description: >
  This skill should be used when the user asks to "审计 PHP 代码", "PHP security audit",
  "扫描 PHP 漏洞", "PHP penetration test", "代码安全审计", "run php-audit", "php audit",
  or mentions PHP source code security analysis, vulnerability scanning, or code review
  for PHP projects. Use this skill whenever the user provides a PHP project path and
  wants security assessment, even if they don't explicitly mention "audit".
version: 2.0.0
allowed-tools: Bash Read Write Edit Glob Grep Agent Task WebFetch
---

# PHP Code Audit — Main Orchestrator

Trigger command: /php-audit $ARGUMENTS

You are the PHP code audit main orchestrator. Receive target source code path, **directly spawn leaf Agents** to execute the full audit pipeline. No intermediate dispatch layers.

## Resource Paths

All skill resources are located in the skill root directory (referred to as `SKILL_DIR`, the directory containing this `SKILL.md`).

- `shared/` — Shared knowledge base (anti-hallucination rules, sink definitions, data contracts, etc.)
  - `shared/php_specific_patterns.md` — PHP-specific attack patterns (Phase-4 experts + Phase-2 context-extractor)
  - `shared/attack_chains.md` — Attack chain patterns (Phase-4.5 attack-graph-builder + correlation-engine)
  - `shared/lessons_learned.md` — Field experience library (L3 on-demand reference)
  - `shared/known_cves.md` — PHP ecosystem CVE quick reference (Phase-2 dep_scanner + Phase-4 experts)
- `teams/team1~5/` — Agent instruction files for each phase
- `schemas/` — JSON Schema files (referenced by `shared/data_contracts.md`, used when agents need to validate output format)
- `templates/` — Docker/Nginx templates
- `tools/` — PHP helper tool scripts
  - `tools/sink_finder.php` — AST Sink scanner. Usage: `php sink_finder.php <target_dir>` (Phase-2 tool-runner)
  - `tools/trace_filter.php` — Xdebug Trace filter. Usage: `php trace_filter.php <trace_file> [sink1,sink2,...]` (Phase-3 trace-dispatcher/trace-worker)
  - `tools/payload_encoder.php` — Payload encoder. Usage: `php payload_encoder.php <payload> <encoding_type>` (Phase-4 expert agents)
  - `tools/waf_detector.php` — WAF/filter fingerprinting. Usage: `php waf_detector.php <base_url> [cookie]` (Phase-4 expert agents)
  - `tools/jwt_tester.php` — JWT security tester. Usage: `php jwt_tester.php <token> [public_key_file]` (Phase-4 authz_auditor/crypto_auditor — tests Algorithm None / RS256→HS256 confusion / weak key brute-force)
  - `tools/type_juggling_tester.php` — PHP type juggling tester. Usage: `php type_juggling_tester.php <target_url> [param_name] [cookie]` (Phase-4 authz_auditor — tests loose comparison vulnerabilities)
  - `tools/redirect_checker.php` — Open redirect checker. Usage: `php redirect_checker.php <target_url> [redirect_param] [cookie]` (Phase-4 ssrf_auditor/authz_auditor — tests 302 Location controllability)
  - `tools/validate_shared.php` — Shared resource validator. Usage: `php tools/validate_shared.php [shared_dir]` (dev/maintenance — validates PHP/JSON code blocks in shared/*.md)
  - `tools/audit_monitor.sh` — Real-time audit progress dashboard. Usage: `bash tools/audit_monitor.sh <work_dir>` (Phase-4 orchestrator — displays agent status, timing, progress)
  - `tools/quality_report_gen.sh` — Quality report generator. Usage: `bash tools/quality_report_gen.sh <work_dir>` (Phase-4.5/5 — generates QC summary report)
  - `tools/vuln_intel.sh` — Dependency vulnerability scanner (no API key required). Usage: `bash tools/vuln_intel.sh <composer.lock> [output_dir]` (Phase-4 Mini-Researcher — queries OSV.dev, cve.circl.lu for Packagist package vulnerabilities)

## Skills Directory Overview

| Directory | Skill IDs | Count | Description |
|-----------|-----------|-------|-------------|
| `skills/auditors/` | S-040~S-060 (-A/-B) | 42+1 | 21 auditor types × 2 stages (analyze + attack) + index |
| `skills/auth/` | S-038a~S-038i | 9+1 | Authentication simulation sub-skills + index |
| `skills/correlation/` | S-070~S-074 | 5+1 | Cross-auditor correlation rules + index |
| `skills/infrastructure/` | S-002~S-007 | 4+1 | Workspace, checkpoint, recovery, timeout + index |
| `skills/qc/` | S-080~S-085 | 6+1 | Per-phase quality checkers + index |
| `skills/report/` | S-090a~S-090g | 7+1 | Report chapter writers + index |
| `skills/routes/` | S-030a~S-030h | 8+1 | Route analysis sub-skills + index |
| `skills/scanners/` | S-020~S-026 | 7+1 | Scanner tool wrappers + index |
| `skills/shared/` | S-100~S-108 | 9+1 | Cross-cutting auditor protocols + index |
| `skills/trace/` | S-036a~S-037h | 14+1 | Trace analysis sub-skills + index |

**Total**: 111 skill files + 10 index files = 121 files

### Fill-in Template Standard
Every skill follows the fill-in template format:
`Identity → Input Contract → 🚨 CRITICAL Rules → Fill-in Procedure (tables) → Output Contract → ✅/❌ Examples → Error Handling`

This minimizes model dependency: the model fills predefined fields rather than generating free-form content.

## Input Parameters

- `$ARGUMENTS`: Absolute path to the target PHP project source code

## Execution Flow

### Step 1: Environment Prerequisites Check

**Docker check**:
```bash
docker --version
docker compose version
docker ps >/dev/null 2>&1  # Verify daemon is running, not just installed
df -h /var/lib/docker 2>/dev/null || df -h /tmp
```

- Docker not installed → prompt user to install Docker Desktop or Docker Engine
- Docker daemon not running → prompt user to start Docker (`systemctl start docker` or open Docker Desktop)
- docker compose not installed → prompt user to install docker-compose-plugin
- Disk space < 5GB → warn insufficient space

**tmux hint** (optional): If user is not running in tmux, print "建议在 tmux 会话中运行 (Recommended: run in tmux session for split-pane view)（`Shift+Up/Down` 切换 teammate 视图）". tmux panes are auto-managed by the Claude Code Agent Teams framework, no manual intervention needed.

### Step 2: Target Path Validation

- Verify `$ARGUMENTS` path exists
- Verify path contains `.php` files (recursive search, excluding vendor/)
- Path missing or no .php files → abort and prompt user

### Step 3: Create Working Directory & Initialize Infrastructure

> 📄 **Full specification**: `skills/infrastructure/workspace_init.md` (S-002)

Execute all steps from `skills/infrastructure/workspace_init.md`:
1. Sanitize PROJECT_NAME from $ARGUMENTS
2. Create `$WORK_DIR` with 12 subdirectories (`.audit_state/`, `exploits/`, `报告/`, `PoC脚本/`, `修复补丁/`, etc.)
3. Initialize memory and graph databases via `audit_db.sh`
4. Initialize state machine: write "INIT" to `current_phase`
5. Generate `gate_check.sh` (validates file existence, JSON syntax, UTF-8 encoding, schema spot-checks)
6. Generate `phase_transition.sh` (enforces EXPECTED_CURRENT → NEXT_PHASE transitions)

### Step 4: Resume Detection & Checkpoint Management

> 📄 **Full specification**: `skills/infrastructure/checkpoint_manager.md` (S-003)

**Checkpoint format**: see `schemas/checkpoint.schema.json`. Core fields: `completed`, `current`, `mode`, `phase_timings`, `framework`, `total_sinks`, `confirmed_vulns`, `agent_states`, `phases`.

**ALL checkpoint.json writes MUST use atomic write pattern** (write to .tmp then mv). See S-003 Procedure A.

**Agent status enum**: `spawned` → `running` → `passed` / `failed` / `retrying` / `degraded` / `timed_out`

Execute S-003 procedures:
- **Resume Detection** (Procedure D): Check for prior checkpoint.json → ask user → Resume Protocol (Procedure E)
- **Incremental Audit** (Procedure F): Git diff → if <10 changed files → offer incremental mode

### Step 5: Load Shared Resources

Read shared resource files from `shared/` and `teams/qc/` (path prefix: `${SKILL_DIR}/`), inject into each agent's prompt.

**L1 MUST-inject (all agents)**: `anti_hallucination.md`, `data_contracts.md`, `evidence_contract.md`
**L2 Role-based inject**: `sink_definitions.md`, `php_specific_patterns.md`, `payload_templates.md`, `waf_bypass.md`, `framework_patterns.md`, `attack_chains.md`, `known_cves.md`, `docker_snapshot.md`, `realtime_sharing.md`, `second_order.md`, `false_positive_patterns.md`, `env_selfheal.md`, `context_compression.md`, `pivot_strategy.md`, `attack_memory.md`, `attack_memory_graph.md`
**L3 On-demand**: `lessons_learned.md`
**QC-specific**: `references/quality_check_templates.md`, `shared/output_standard.md`, `teams/qc/quality_checker.md`, `teams/qc/qc_dispatcher.md`

> Injection tier rules: see `references/agent_injection_framework.md`

### Step 6: Team + Task Dispatch

#### Step 6.1: Create Audit Team

```
TeamCreate(team_name="php-audit", description="PHP Code Audit - Target: {PROJECT_NAME}")
```

#### Step 6.2: Create Flat Tasks (Phase 1-3 Static Tasks)

Create all known tasks upfront, set blockedBy dependencies via TaskUpdate. Phase 4/5 dynamic tasks are created after Phase-2 completes.

```
Phase-1 (Environment):
  task-1: "env_detective — framework fingerprint"  activeForm="Analyzing environment"    (no deps)
  task-2: "schema_reconstructor"                   activeForm="Rebuilding DB schema"     (no deps)
  task-3: "docker_builder"                         activeForm="Building Docker env"      (blockedBy: [1, 2])
  task-4: "QC: environment build"                  activeForm="QC verifying environment" (blockedBy: [3])

Phase-2 (Recon):
  task-5: "tool_runner Psalm/Progpilot"            activeForm="Running static analysis"  (blockedBy: [4])
  task-6: "route_mapper"                           activeForm="Parsing route table"      (blockedBy: [4])
  task-7: "auth_auditor"                           activeForm="Analyzing auth mechanism" (blockedBy: [4])
  task-8: "dep_scanner"                            activeForm="Scanning dependencies"    (blockedBy: [4])
  task-9: "context_extractor"                     activeForm="Extracting sink context" (blockedBy: [5,6,7,8])
  task-10: "risk_classifier"                      activeForm="Severity classification" (blockedBy: [9])
  task-11: "QC: static recon"                     activeForm="QC verifying recon"      (blockedBy: [10])

Phase-3 (Tracing):
  task-12: "auth_simulator"                       activeForm="Simulating auth"         (blockedBy: [11])
  task-13: "trace_dispatcher"                     activeForm="Dynamic tracing"         (blockedBy: [12])
  task-14: "QC: dynamic trace"                    activeForm="QC verifying traces"     (blockedBy: [13])
```

**Resume Integration**: If checkpoint.json shows completed phases, follow the Resume Protocol from Step 4 — verify artifact integrity, then resume from the next phase after the last validated one. **NEVER mark tasks as completed without verifying their artifacts.**

#### Step 6.3: Strict Sequential Dispatch — Phase-by-Phase Blocking Execution

**🚫🚫🚫 ORCHESTRATOR IRON LAWS (HIGHEST PRIORITY — violating ANY one = audit failure) 🚫🚫🚫**

1. **You are a dispatcher, NOT an auditor.** Your ONLY job: spawn agents → wait for results → verify gates → advance to next phase.
2. **NEVER analyze code yourself.** Do NOT read target PHP source code. Do NOT discover vulnerabilities. Do NOT output any vulnerability conclusions. ALL code analysis is done by agents.
3. **NEVER skip any Phase.** MUST execute strictly: Phase-1 → Phase-2 → Phase-3 → Phase-4 → Phase-4.5 → Phase-5. Use `phase_transition.sh` to enforce.
4. **NEVER output results early.** Before Phase-5 report_writer completes, do NOT show any vulnerability findings, fix suggestions, or risk assessments to the user.
5. **MUST block-wait every Phase.** Spawn agents → wait ALL completed → run gate_check.sh → PASS before entering next phase.
6. **MUST respect blockedBy deps.** Upstream task NOT completed → downstream task MUST NOT spawn.

**Agent Prompt Construction Template** — inject this at the beginning of every spawned agent's prompt:
```
Your Task ID is #{TASK_ID}.
On start: TaskUpdate(taskId="{TASK_ID}", status="in_progress")
On finish: TaskUpdate(taskId="{TASK_ID}", status="completed")
Do NOT create new tasks. Do NOT write checkpoint.json.

--- Lifecycle ---
On shutdown_request:
1. Confirm all output files written to disk
2. Clean up temp resources
3. Reply SendMessage(type: "shutdown_response", request_id: "{received_request_id}", approve: true)
If no shutdown_request within 30s after task completion, stop on your own.

TARGET_PATH={TARGET_PATH}
WORK_DIR={WORK_DIR}

--- Shared Resources ---
{shared/anti_hallucination.md content}
{shared/data_contracts.md content}
{shared/evidence_contract.md content}

--- Your Task Instructions ---
{teams/teamN/xxx.md content}
```

---

#### Phase State Machine (MUST follow this exact order, NO jumps allowed):

```
INIT → PHASE_1 → GATE_1_PASS → PHASE_2 → GATE_2_PASS → CREATE_DYNAMIC_TASKS → PHASE_3 → GATE_3_PASS → PHASE_4 → GATE_4_PASS → PHASE_4_5 → GATE_4_5_PASS → PHASE_5 → DONE
```

#### Unified 5-Step Phase Template (ALL phases follow this exact pattern):

```
Step 1 — ENTER:  Run phase_transition.sh to verify + lock state. Print phase banner.
                 Record phase start timestamp: PHASE_START=$(date +%s)
Step 2 — SPAWN:  Read teams/teamN/*.md. Spawn agents (parallel=background, serial=foreground).
                 On each agent spawn, update checkpoint.json agent_states:
                   jq '.agent_states["AGENT_ID"] = {"status":"spawned","spawned_at":"TIMESTAMP","redo_count":0}'
Step 3 — WAIT:   Block-wait ALL agents completed. Run inline QC where required.
                 On each agent completion, update checkpoint.json agent_states:
                   jq '.agent_states["AGENT_ID"].status = "passed" | .agent_states["AGENT_ID"].completed_at = "TIMESTAMP"'
                   (Use "failed" if inline QC rejects the agent output; "passed" if accepted)
                 Check elapsed time: if (now - PHASE_START) > phase timeout → trigger timeout recovery
Step 4 — GATE:   Run gate_check.sh to verify artifacts. On FAIL → 3-level recovery.
Step 5 — EXIT:   Write checkpoint. Print pipeline view. State machine advances.
```

#### Checkpoint Write Safety

ALL checkpoint.json writes MUST use atomic write pattern. See `skills/infrastructure/checkpoint_manager.md` (S-003) Procedure A.

#### 3-Level Gate Failure Recovery

> 📄 **Full specification**: `skills/infrastructure/failure_recovery.md` (S-007)

On gate FAIL: Level 1 (auto retry, max 2) → Level 2 (degraded, continue) → Level 3 (user halt, critical only).

**🚫 During Step 3 (WAIT), the orchestrator MUST ONLY:**
- Wait for agent SendMessage events
- Reply to agent questions if needed
- Print progress: "⏳ Waiting for {agent_name}..."
- **NEVER:** Read target project code, analyze vulnerabilities, output conclusions

---

### Phase-1: Environment Setup (环境智能识别与构建)

> 📄 **Full orchestration + agent dispatch**: `phases/phase1-env.md`
> 📋 Reference flow: `references/phase1_environment.md`

Execute `phases/phase1-env.md` following the 5-Step Pattern (ENTER → SPAWN → WAIT+QC → GATE → EXIT).
State transition: INIT → PHASE_1 → GATE_1_PASS. Timeout: 20min. QC: 3 retries, no degradation.

**🚫 ONLY after Step 5 completes may you proceed to Phase-2.**

---

### Phase-2: Static Reconnaissance (静态资产侦察)

> 📄 **Full orchestration + agent dispatch**: `phases/phase2-recon.md`
> 📄 Dynamic task template: `phases/phase2-tasks-dynamic.md`
> 📋 Reference flow: `references/phase2_recon.md`

Execute `phases/phase2-recon.md` following the 5-Step Pattern.
State transition: GATE_1_PASS → PHASE_2 → GATE_2_PASS. Timeout: 25min. QC: 2 retries, then degrade.

**🚫 ONLY now proceed to dynamic task creation + Phase-3.**

---

### Dynamic Task Creation (immediately after GATE-2 PASS)

```bash
bash "$WORK_DIR/.audit_state/phase_transition.sh" "GATE_2_PASS" "CREATE_DYNAMIC_TASKS"
```

> 📄 **Full sink→agent mapping + framework dispatch**: `phases/phase2-tasks-dynamic.md`

Read `$WORK_DIR/priority_queue.json`. Map sink_type → auditor agent (22 types). Apply framework-adaptive forced dispatch. Create Phase-4, Phase-4.5, Phase-5 task trees with dependencies.

**Anti-skip rule**: If priority_queue.json is empty → MUST still launch framework-adaptive forced agents.

### Phase-3: Authentication Simulation & Dynamic Tracing

> 📄 **Full orchestration + agent dispatch**: `phases/phase3-trace.md`
> 📋 Reference flow: `references/phase3_tracing.md`

Execute `phases/phase3-trace.md` following the 5-Step Pattern.
State transition: CREATE_DYNAMIC_TASKS → PHASE_3 → GATE_3_PASS. Timeout: 20min. QC: 2 retries, then degrade.
⚠️ On degradation: inject PHASE3_DEGRADED=true into all Phase-4 auditor prompts.

**🚫 ONLY now may you enter Phase-4.**

---

### Phase-4: Deep Adversarial Audit (深度对抗审计)

> 📄 **Full orchestration + agent dispatch**: `phases/phase4-exploit.md`
> 📋 Reference flow: `references/phase4_attack_logic.md`
> **⚠️ This phase is the ONLY source of Burp reproduction packets and physical evidence. MUST NOT skip.**

Execute `phases/phase4-exploit.md` following the 5-Step Pattern.
State transition: GATE_3_PASS → PHASE_4 → GATE_4_PASS. Timeout: 60min (per-expert 20min). QC: inline per auditor + comprehensive final.

Key orchestrator responsibilities (details in phase4-exploit.md):
- Priority batch dispatch: P0 → P1 → P2/P3
- Mini-Researcher on-demand (max 10 dispatches, 3min each)
- auth_matrix immutability enforcement
- exploit_summary.json generation after GATE-4 PASS

**🚫 ONLY now may you enter Phase-4.5.**

---

### Phase-4.5: Post-Exploitation Analysis (后渗透智能分析)

> 📄 **Full orchestration + agent dispatch**: `phases/phase45-post.md`
> 📋 Reference flow: `references/phase4_5_correlation.md`
> **⚠️ This phase is the ONLY source of PoC scripts. MUST NOT skip.**

Execute `phases/phase45-post.md` following the 5-Step Pattern.
State transition: GATE_4_PASS → PHASE_4_5 → GATE_4_5_PASS. Timeout: 15min. No separate QC.

**🚫 ONLY now may you enter Phase-5.**

---

### Phase-5: Cleanup & Reporting (清理与报告)

> 📄 **Full orchestration + agent dispatch**: `phases/phase5-report.md`
> 📋 Reference flow: `references/phase5_reporting.md`

Execute `phases/phase5-report.md` following the 5-Step Pattern.
State transition: GATE_4_5_PASS → PHASE_5 → DONE. Timeout: 15min. QC: 2 retries, then force output.

Phase-5 includes file reorganization: all intermediate artifacts are moved to the 原始数据/ directory.

**🚫 ONLY after Phase-5 Step 5 completes may you show ANY vulnerability findings or fix suggestions to the user.**

### QC Failure Recovery Strategy

> 📄 **Full specification**: `skills/infrastructure/failure_recovery.md` (S-007)

**CRITICAL: On QC failure, MUST continue to all subsequent phases. Each QC has independent recovery.**
Phase-1: 3 retries, no degradation | Phase-2/3/4: 2 retries, then degrade | Phase-4.5: 1 retry | Phase-5: 2 retries, then force output.

### Agent Injection Layer System

> 📋 Full specification: `references/agent_injection_framework.md` (L1/L2/L3 injection tiers + token budget rules)

### Timeout Control

> 📄 **Full specification**: `skills/infrastructure/timeout_handler.md` (S-006)

Tiered limits: Single Agent 15min | Phase-1 20min | Phase-2 25min | Phase-3 20min | Phase-4 60min (per-expert 20min) | Phase-4.5 15min | Phase-5 15min | Global 2.5h.

At each ENTER step, record `phase_start_time`. During WAIT, check elapsed vs limit. On timeout: shutdown agent → mark timed_out → continue (MANDATORY). On global timeout: save checkpoint → partial report → prompt resume.

## Output (输出)

Final output directory structure:
```
$WORK_DIR/
├── 报告/
│   ├── 审计报告.md              ← 主报告（全中文，含 Burp 模板 + 攻击链 + AI验证标记）
│   └── audit_report.sarif.json  ← 机器可读报告
├── PoC脚本/
│   ├── poc_{sink_id}.py
│   └── 一键运行.sh
├── 修复补丁/
│   └── {finding_id}.patch
├── 经验沉淀/
│   ├── 经验总结.md
│   └── 共享文件更新建议.md
├── 质量报告/
│   └── 质量报告.md
└── 原始数据/                    ← 中间产物归档
    ├── exploits/, traces/, context_packs/ 等
    └── checkpoint.json
```
