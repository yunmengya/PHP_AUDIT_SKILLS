# Quality Check Dispatcher

> This file defines how the lead (SKILL.md main dispatcher) dispatches the quality checker pool. Embedded into the dispatch logic of SKILL.md.

---

## Core Principle: Verify Each as It Completes

After each Agent completes its task, the lead MUST **immediately** spawn a quality checker to verify its output. Do not wait for other Agents in the same phase.

## Quality Checker Pool Management

### Naming Convention
- `quality-checker-1`, `quality-checker-2`, ..., `quality-checker-N`
- Sequence numbers are globally incrementing, never reset

### Lifecycle
```
Agent completes → Lead checks for idle quality checker →
  Available → Assign to idle quality checker
  None available → Spawn new quality checker
→ Quality checker verifies → Reports result →
  Pass → Quality checker marked idle, awaits next task
  Fail → Lead notifies the verified Agent to redo → After redo, assign quality checker again
```

### Concurrency Limits
- Phase 1/2/3: Maximum **3** concurrent quality checkers
- Phase 4 (auditor level): Maximum **5** concurrent quality checkers
- Phase 4.5/5: Maximum **2** concurrent quality checkers

### Reclaim Strategy
- Once all verifications for the current phase are complete, shut down all quality checkers for that phase
- Spawn new ones as needed for the next phase

---

## Per-Phase Dispatch Plan

### Phase 1 Environment Setup

```
docker_builder completes → spawn quality-checker-1
  Verification template: Phase 1: Environment Setup Verification
  Output files: environment_status.json
  → Pass → Close quality-checker-1, write GATE-1 checkpoint
  → Fail → Notify docker_builder to redo per fix requirements (max 3 attempts)
```

### Phase 2 Static Reconnaissance

```
Team-2 all Agents complete → spawn quality-checker-1
  Verification template: Phase 2: Static Reconnaissance Verification
  Output files: route_map.json, auth_matrix.json, ast_sinks.json, priority_queue.json, context_packs/, dep_risk.json
  → Pass → Close quality-checker-1, write GATE-2 checkpoint
  → Fail → Notify responsible Agent to supplement (locate responsible Agent based on failed items)
```

**Phase 2 Failed Item Responsibility Mapping:**
| Failed Item | Responsible Agent |
|---------|-----------|
| route_map related | route_mapper |
| auth_matrix related | auth_auditor |
| ast_sinks related | tool_runner (AST scan) |
| context_packs related | context_extractor |
| priority_queue related | risk_classifier |
| dep_risk related | dep_scanner |

### Phase 3 Dynamic Tracing

```
Team-3 all Agents complete → spawn quality-checker-1
  Verification template: Phase 3: Dynamic Tracing Verification
  Output files: credentials.json, traces/*.json
  → Pass → Close quality-checker-1, write GATE-3 checkpoint
  → Fail → Notify responsible Agent to supplement
```

### Phase 4 Exploit Development (Core: Auditor-Level Verification)

**Do NOT verify after Stage 1 (analysis stage) completes; wait until the attack stage completes before verifying.**

```
Each Auditor's attack stage completes → Assign to idle quality checker (or spawn new one)
  Verification template: Phase 4: Individual Auditor Verification
  Output files: exploits/{sink_id}.json (all exploits from that Auditor)
  → Pass → That Auditor closes, quality checker marked idle
  → Fail → Notify that Auditor to supplement evidence/correct (max 2 attempts)

All Auditors pass verification → Assign one quality checker for comprehensive verification
  Verification template: Phase 4: Physical Forensics Comprehensive Verification
  Output files: team4_progress.json + exploits/
  → Pass → Write GATE-4 checkpoint
  → Fail → Locate specific Auditor to supplement
```

**Phase 4 Dispatch Example (assuming 6 Auditors dispatched):**
```
sqli_auditor completes    → quality-checker-1 verifies
rce_auditor completes     → quality-checker-2 verifies
xss_ssti_auditor completes → quality-checker-3 verifies (or reuse idle 1/2)
lfi_auditor completes     → quality-checker-4 verifies
xxe_auditor completes     → Reuse idle quality checker
ssrf_auditor completes    → Reuse idle quality checker
All pass                  → Any quality checker performs comprehensive verification
```

### Phase 4.5 Correlation Analysis

```
Team-4.5 completes → spawn quality-checker-1
  Verification template: Phase 4.5: Correlation Analysis Verification
  Output files: attack_graph.json, correlation_report.json, patches/*.patch
  → Pass → Write GATE-4.5 checkpoint
  → Fail → Notify correlation_engine/attack_graph_builder to supplement
```

### Phase 5 Report Generation

```
report_writer + sarif_exporter complete → spawn quality-checker-1
  Verification template: Phase 5: Report Generation Verification
  Output files: 报告/审计报告.md, 报告/audit_report.sarif.json, PoC脚本/, 修复补丁/, 经验沉淀/
  → Pass → Quality checker generates 质量报告/质量报告.md → Process ends
  → Fail → Notify report_writer to correct (max 2 rounds)
```

---

## Agent State Synchronization (checkpoint.json)

After each quality check completes, the lead (main dispatcher) MUST synchronize the `agent_states` in `checkpoint.json`:

### State Update Timing

| Event | agent_states Update |
|------|-------------------|
| Agent spawn | `{status: "spawned", spawned_at: now()}` |
| Stage-1 analysis starts | `{status: "analyzing"}` |
| Stage-2 attack starts | `{status: "attacking"}` |
| Agent completes output | `{status: "completed", completed_at: now()}` |
| QC verdict=pass | `{status: "passed", qc_verdict: "pass"}` |
| QC verdict=fail | `{status: "failed", qc_verdict: "fail", redo_count: +1}` |
| Agent redo completes | `{status: "completed"}` (awaiting QC again) |
| Agent timeout | `{status: "timeout", completed_at: now()}` |
| Pivot triggered | `{pivot_triggered: true, pivot_target: "..."}` |

### Sync Command

```bash
# Update single agent status (executed by main dispatcher at each state transition point)
jq --arg agent "$AGENT_NAME" --arg status "$NEW_STATUS" \
  '.agent_states[$agent].status = $status' \
  "$WORK_DIR/checkpoint.json" > "$WORK_DIR/checkpoint.json.tmp" && \
  mv "$WORK_DIR/checkpoint.json.tmp" "$WORK_DIR/checkpoint.json"
```

### State Query on GATE Failure

```bash
# Query all agents with non-passed status (for GATE FAIL diagnosis)
jq '.agent_states | to_entries[] | select(.value.status != "passed") | {agent: .key, status: .value.status, redo: .value.redo_count}' "$WORK_DIR/checkpoint.json"
```

---

## Redo Closed Loop

### Redo Count Tracking
Each verified Agent's redo count is recorded in SQLite:
```bash
bash tools/audit_db.sh qc-write "$WORK_DIR" '{"agent":"xxx", "redo_count": N, ...}'
```

### Redo Limits
| Phase | Max Redo Count | Over-Limit Handling |
|------|:----------:|---------|
| Phase 1 | 3 | Degrade to partial mode |
| Phase 2 | 2 | Mark as degraded, continue with available data |
| Phase 3 | 2 | Broken chain route falls back to context_pack |
| Phase 4 (individual Auditor) | 2 | Mark insufficient evidence, degrade confidence level |
| Phase 4.5 | 1 | Use team4_progress.json to proceed directly to report |
| Phase 5 | 2 | Force generation (mark with WARN) |

### Redo Information Delivery
On failure, the lead SHALL send the following information to the verified Agent:
```
Your output did not pass quality check. Below are the failed items and fix requirements:

[Paste the quality checker's failed_items list]

Please address each fix requirement and resubmit.
```

---

## Final Quality Report Generation

After all phases pass verification, the lead SHALL assign the report generation task to the last quality checker:

1. Read the "Final Quality Report Template" at the end of `references/quality_check_templates.md`
2. Read all QC records from SQLite:
   ```bash
   bash tools/audit_db.sh qc-read "$WORK_DIR"
   ```
3. Consolidate verification results from all phases
4. Generate `$WORK_DIR/质量报告/质量报告.md`
5. Close all quality checkers, completing the entire audit process
