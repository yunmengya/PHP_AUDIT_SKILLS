# Skill S-007: Failure Recovery

## IDENTITY
- **Skill ID**: S-007
- **Phase**: Cross-phase infrastructure
- **Responsibility**: Define and execute the 3-level gate failure recovery strategy and QC failure recovery strategy for all phases.

## INPUT CONTRACT

| Input | Source | Required | Fields Used |
|-------|--------|----------|-------------|
| Gate result | gate_check.sh output | Yes | PASS/FAIL + failure details |
| QC result | quality_checker output | Yes | pass/fail + failed_items |
| checkpoint.json | S-003 | Yes | agent_states, phases, redo_count |

## 3-LEVEL GATE FAILURE RECOVERY

Applies to ALL gates (GATE-1 through GATE-5):

```
Level 1 — AUTO RETRY:
  Re-spawn failed agent(s) with same inputs. Max 2 retries.

Level 2 — DEGRADED:
  If retries exhausted, write degraded status to checkpoint:
    jq '.phases.CURRENT_PHASE_NAME.mode = "degraded" |
        .phases.CURRENT_PHASE_NAME.degradation_reason = "REASON" |
        .mode = "degraded"'
        "$WORK_DIR/checkpoint.json" > "$WORK_DIR/checkpoint.json.tmp" &&
        mv "$WORK_DIR/checkpoint.json.tmp" "$WORK_DIR/checkpoint.json"
  Continue to next phase with available artifacts.
  Print: "⚠️ Phase-N degraded: {reason}. Continuing with partial data."

Level 3 — USER HALT:
  If critical artifacts missing (no fallback possible), STOP.
  Print: "🛑 Phase-N failed: {missing artifacts}. 需要用户介入。"
  Wait for user input before continuing.
```

## QC FAILURE RECOVERY STRATEGY

**CRITICAL: On QC failure, MUST continue to all subsequent phases. Each QC has independent recovery.**

| Phase | QC Failure Recovery | Redo Limit | Over-Limit Action |
|-------|--------------------|------------|-------------------|
| **Phase-1** (env build) | Re-send failed_items to docker-builder | **3** retries | Halt for user intervention — **NO degradation allowed**, Docker MUST succeed |
| **Phase-2** (static recon) | Identify responsible agent via failed_items, re-run | **2** retries | Mark degraded, note coverage gap in report. **MUST continue to Phase-3, Phase-4, Phase-5** |
| **Phase-3** (dynamic trace) | Re-run trace_dispatcher with failed items | **2** retries | Fall back to static analysis for broken routes. **MUST continue to Phase-4, Phase-5** |
| **Phase-4** (evidence) | Re-run failed auditor | **2** retries | Mark as degraded, downgrade verdict to "insufficient evidence". **MUST continue to Phase-4.5, Phase-5** |
| **Phase-4.5** (correlation) | Re-run failed agent | **1** retry | Use team4_progress.json directly. **MUST continue to Phase-5** |
| **Phase-5** (report) | Revise and resubmit | **2** retries | Force output whatever is available (with WARN tag) |

## FILL-IN PROCEDURE

### Step 1: On Gate FAIL — Determine Recovery Level

```
Read gate_check.sh output → identify which files/checks failed
Check agent_states in checkpoint.json → get redo_count for failed agent

IF redo_count < max_retries_for_phase:
  → Level 1: AUTO RETRY
  → Increment redo_count in checkpoint.json
  → Re-spawn failed agent with same inputs + failed_items hint
  → Return to WAIT step

ELSE IF phase has degraded fallback:
  → Level 2: DEGRADED
  → Write degradation to checkpoint.json (atomic)
  → Continue to next phase

ELSE:
  → Level 3: USER HALT
  → Print error details
  → Wait for user input
```

### Step 2: On QC FAIL — Route Fix to Responsible Agent

```
Read QC report → extract failed_items list
Map failed_items to responsible agent:
  - route_map.json failed → route_mapper
  - auth_matrix.json failed → auth_auditor
  - exploits/{sink_id}.json failed → corresponding auditor
  - 审计报告.md failed → report_writer

Check redo_count for that agent in checkpoint.json
IF under limit → re-spawn agent with fix_requirements
ELSE → apply over-limit action from table above
```

### Step 3: Downstream Impact Propagation

When a phase degrades, inject degradation flag into ALL downstream agents:

```
Phase-3 degraded (auth failed):
  → Inject PHASE3_DEGRADED=true into ALL Phase-4 auditor prompts
  → All auth-dependent findings marked "suspected" not "confirmed"
  → Print: "⚠️ Phase-3 was degraded — auth-dependent findings will be marked 'suspected'"

Phase-2 degraded (partial context):
  → Inject PHASE2_DEGRADED=true into Phase-3 and Phase-4 prompts
  → Missing context_packs → auditors skip those sinks

Phase-4 degraded (auditor failed):
  → Phase-4.5 correlation uses available exploits/ only
  → Phase-5 report notes "部分审计器未完成，结果可能不完整"
```

## OUTPUT CONTRACT

| Output | Path | Description |
|--------|------|-------------|
| Updated checkpoint.json | `$WORK_DIR/checkpoint.json` | Degradation flags, redo_counts |
| Console output | stdout | Recovery action messages (⚠️/🛑) |
| Downstream flags | Agent prompt injection | PHASE{N}_DEGRADED=true |

## EXAMPLES

✅ GOOD — Phase-3 QC fail with graceful degradation:
```
QC-Phase3 FAIL: credentials.json missing "admin" level
→ Check redo_count: 0 < 2 → Level 1: retry auth_simulator
→ Auth_simulator retry → still fails
→ redo_count: 1 < 2 → Level 1: retry again
→ Auth_simulator retry → still fails
→ redo_count: 2 >= 2 → Level 2: DEGRADED
→ Write: .phases.phase3.mode = "degraded"
→ Print: "⚠️ Phase-3 degraded: 鉴权模拟失败，退回静态分析模式"
→ Inject PHASE3_DEGRADED=true into Phase-4 prompts
→ Continue to Phase-4
```

❌ BAD — Skipping remaining phases on failure:
```
Phase-3 QC FAIL → "🛑 Audit aborted due to Phase-3 failure"
← WRONG: MUST continue to Phase-4, Phase-5 (with degraded flag)
```

❌ BAD — Retrying beyond limit:
```
Phase-4 auditor QC FAIL, redo_count=2
→ "Retrying auditor (attempt 3/2)"
← WRONG: redo limit is 2, must mark degraded and continue
```

## ERROR HANDLING

| Error | Action |
|-------|--------|
| Cannot determine which agent failed | Re-run entire phase (last resort) |
| Degradation flag not propagated | QC in downstream phase catches inconsistency |
| checkpoint.json write fails during recovery | Retry write; if persistent, log to stderr and continue |
