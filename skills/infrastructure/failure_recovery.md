# Failure Recovery

## Identity
| Field | Value |
|-------|-------|
| Skill ID | S-005 |
| Category | Infrastructure |
| Responsibility | Define and execute the 3-level gate failure recovery strategy and QC failure recovery strategy for all phases |

## Input Contract
| File | Source | Required | Fields Used |
|------|--------|----------|-------------|
| Gate result | gate_check.sh output | Yes | PASS/FAIL + failure details |
| QC result | quality_checker output | Yes | pass/fail + failed_items |
| checkpoint.json | S-003 | Yes | agent_states, phases, redo_count |

## 🚨 CRITICAL Rules
| # | Rule | Consequence |
|---|------|-------------|
| CR-1 | On QC failure, MUST continue to all subsequent phases — each QC has independent recovery | Skipping downstream phases = audit abort, violates pipeline integrity |
| CR-2 | Phase-1 (env build) does NOT allow degradation — Docker MUST succeed | If Phase-1 retries exhausted, halt for user intervention (Level 3) |
| CR-3 | Never retry beyond the phase redo limit | Exceeding redo limit wastes time; must escalate to degraded or halt |
| CR-4 | When a phase degrades, inject degradation flag (PHASE{N}_DEGRADED=true) into ALL downstream agent prompts | Missing flag causes downstream agents to treat partial data as complete |
| CR-5 | Degraded status write to checkpoint.json MUST be atomic (write to .tmp then mv) | Non-atomic write risks checkpoint corruption on crash |

## Fill-in Procedure

### Procedure A: 3-Level Gate Failure Recovery

Applies to ALL gates (GATE-1 through GATE-5). On gate FAIL, determine recovery level:

| Field | Fill-in Value |
|-------|--------------|
| Failed Gate | `GATE-___` (1–5) |
| Failed Agent(s) | `___` (from gate_check.sh output) |
| Failed Files/Checks | `___` (from gate_check.sh failure details) |
| Current redo_count | `___` (from checkpoint.json agent_states) |
| Max Retries for Phase | `___` (see QC Failure Recovery table below) |
| Recovery Level | `Level ___` (1 = Auto Retry / 2 = Degraded / 3 = User Halt) |

**Decision logic:**

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

**Level 2 — Degraded status write (bash):**

```bash
jq '.phases.CURRENT_PHASE_NAME.mode = "degraded" |
    .phases.CURRENT_PHASE_NAME.degradation_reason = "REASON" |
    .mode = "degraded"' \
    "$WORK_DIR/checkpoint.json" > "$WORK_DIR/checkpoint.json.tmp" && \
    mv "$WORK_DIR/checkpoint.json.tmp" "$WORK_DIR/checkpoint.json"
```

**Level 2 output:** `"⚠️ Phase-N degraded: {reason}. Continuing with partial data."`

**Level 3 output:** `"🛑 Phase-N failed: {missing artifacts}. User intervention required."`

### Procedure B: QC Failure — Route Fix to Responsible Agent

On QC FAIL, identify the responsible agent and apply per-phase recovery:

| Field | Fill-in Value |
|-------|--------------|
| Failed Phase | `Phase-___` (1 / 2 / 3 / 4 / 4.5 / 5) |
| Failed Items | `___` (from QC report `item_results` where `status = "❌"`) |
| Responsible Agent | `___` (mapped from failed artifact, see mapping below) |
| Current redo_count | `___` (from checkpoint.json) |
| Phase Redo Limit | `___` (from recovery table below) |
| Action Taken | `___` (re-spawn with structured redo prompt / over-limit action) |

**Failed-item to agent mapping:**

```
route_map.json failed          → route_mapper
auth_matrix.json failed        → auth_auditor
ast_sinks.json failed          → ast_scanner
priority_queue.json failed     → risk_classifier
context_packs/ failed          → context_extractor
dep_risk.json failed           → dep_scanner
credentials.json failed        → auth_simulator
traces/*.json failed           → trace_dispatcher
exploits/{sink_id}.json failed → corresponding auditor
审计报告.md failed               → report_writer
```

**Redo Prompt Delivery:**

When re-invoking the responsible agent, MUST use the structured redo prompt template defined in `teams/qc/qc_dispatcher.md` § "Redo Information Delivery". The redo prompt MUST contain:
1. Phase, Agent Role, Redo Attempt count — from this procedure's fill-in table above
2. Failed Items table — populated from QC report `item_results` where `status = "❌"`, with `expected`, `actual`, and concrete `Fix Requirement`
3. Constraints block — copied verbatim from the template

Free-form messages like "QC failed, please redo" are **PROHIBITED** — the agent receives no actionable information from such messages.

**QC Failure Recovery table (per-phase redo limits and over-limit actions):**

| Phase | QC Failure Recovery | Redo Limit | Over-Limit Action |
|-------|--------------------|------------|-------------------|
| Phase-1 (env build) | Re-invoke docker-builder with structured redo prompt | 3 | If Docker absolutely cannot start: switch to static-only mode — set `PHASE1_DEGRADED=true`, generate minimal `environment_status.json` with `docker_status: "unavailable"`, skip container-dependent phases (Phase-3 auth, Phase-4 Stage-2 attacks). MUST continue to Phase-2 in static-only mode |
| Phase-2 (static recon) | Map failed items → responsible agents, re-invoke each with structured redo prompt | 2 | Mark degraded, note coverage gap in report. MUST continue to Phase-3, Phase-4, Phase-5 |
| Phase-3 (dynamic trace) | Re-invoke trace_dispatcher with structured redo prompt | 2 | Fall back to static analysis for broken routes. MUST continue to Phase-4, Phase-5 |
| Phase-4 (evidence) | Re-invoke failed auditor with structured redo prompt | 2 | Mark as degraded, downgrade verdict to "insufficient evidence". MUST continue to Phase-4.5, Phase-5 |
| Phase-4.5 (correlation) | Re-invoke failed agent with structured redo prompt | 1 | Use team4_progress.json directly. MUST continue to Phase-5 |
| Phase-5 (report) | Re-invoke report_writer with structured redo prompt | 2 | Force output whatever is available (with WARN tag) |

### Procedure C: Downstream Impact Propagation

When a phase degrades, fill in the propagation targets:

| Field | Fill-in Value |
|-------|--------------|
| Degraded Phase | `Phase-___` |
| Degradation Reason | `___` |
| Flag Name | `PHASE____DEGRADED=true` |
| Downstream Phases Affected | `Phase-___, Phase-___, ...` |
| Impact on Findings | `___` (e.g., mark as "suspected", skip sinks, note incomplete) |

### Procedure C2: Minimum Viable Data Threshold

Before proceeding from a degraded phase, verify the output meets minimum usable levels:

| Phase | Minimum Viable Output | Check | Pass |
|-------|-----------------------|-------|------|
| Phase-1 | `environment_status.json` exists with `framework` field | {fill-in: framework value or "MISSING"} | {✅/❌} |
| Phase-2 | `route_map.json` has ≥ 1 route AND `ast_sinks.json` has ≥ 1 sink | {fill-in: route_count, sink_count} | {✅/❌} |
| Phase-3 | `credentials.json` exists (even if empty array) AND ≥ 1 trace file | {fill-in: cred_count, trace_count} | {✅/❌} |
| Phase-4 | ≥ 60% sink coverage AND 100% P0 coverage | {fill-in: coverage %, P0 %} | {✅/❌} |
| Phase-4.5 | `correlation_report.json` exists | {fill-in: exists true/false} | {✅/❌} |

**Threshold enforcement:**
- ANY ❌ AND NOT degraded → GATE FAIL, trigger retry
- ANY ❌ AND degraded → proceed with `[MINIMUM DATA NOT MET]` tag, downstream agents receive warning
- Phase-2 with 0 routes AND 0 sinks → HALT (nothing to audit)

**Propagation rules by degraded phase:**

```
Phase-2 degraded (partial context):
  → Inject PHASE2_DEGRADED=true into Phase-3 and Phase-4 prompts
  → Missing context_packs → auditors skip those sinks

Phase-3 degraded (auth failed):
  → Inject PHASE3_DEGRADED=true into ALL Phase-4 auditor prompts
  → All auth-dependent findings marked "suspected" not "confirmed"
  → Print: "⚠️ Phase-3 was degraded — auth-dependent findings will be marked 'suspected'"

Phase-4 degraded (auditor failed):
  → Phase-4.5 correlation uses available exploits/ only
  → Phase-5 report notes incomplete audit coverage
```

## Output Contract
| Output File | Path | Schema | Description |
|-------------|------|--------|-------------|
| checkpoint.json | `$WORK_DIR/checkpoint.json` | JSON with .phases, .agent_states, .mode | Degradation flags, redo_counts, agent status |
| Console output | stdout | Text with ⚠️/🛑 prefixes | Recovery action messages |
| Downstream flags | Agent prompt injection | `PHASE{N}_DEGRADED=true` | Degradation awareness for downstream agents |

## Examples

### ✅ GOOD: Phase-3 QC fail with graceful degradation
```
QC-Phase3 FAIL: credentials.json missing "admin" level
→ Check redo_count: 0 < 2 → Level 1: retry auth_simulator
→ Auth_simulator retry → still fails
→ redo_count: 1 < 2 → Level 1: retry again
→ Auth_simulator retry → still fails
→ redo_count: 2 >= 2 → Level 2: DEGRADED
→ Write: .phases.phase3.mode = "degraded"
→ Print: "⚠️ Phase-3 degraded: auth simulation failed, falling back to static analysis"
→ Inject PHASE3_DEGRADED=true into Phase-4 prompts
→ Continue to Phase-4
```
Explanation: Exhausts retries within limit, then properly degrades and propagates flag downstream before continuing ✅

### ❌ BAD: Skipping remaining phases on failure
```
Phase-3 QC FAIL → "🛑 Audit aborted due to Phase-3 failure"
```
What's wrong: MUST continue to Phase-4, Phase-5 with degraded flag — violates CR-1 ❌

### ❌ BAD: Retrying beyond limit
```
Phase-4 auditor QC FAIL, redo_count=2
→ "Retrying auditor (attempt 3/2)"
```
What's wrong: Redo limit is 2, must mark degraded and continue — violates CR-3 ❌

## Error Handling
| Error | Action |
|-------|--------|
| Cannot determine which agent failed | Re-run entire phase (last resort) |
| Degradation flag not propagated | QC in downstream phase catches inconsistency |
| checkpoint.json write fails during recovery | Retry write; if persistent, log to stderr and continue |
