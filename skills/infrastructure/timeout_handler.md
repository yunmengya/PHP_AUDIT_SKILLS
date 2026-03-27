# Timeout Handler

## Identity
| Field | Value |
|-------|-------|
| Skill ID | S-007 |
| Category | Infrastructure |
| Responsibility | Monitor and enforce tiered timeout limits for individual agents, phases, and global audit duration |

## Input Contract
| File | Source | Required | Fields Used |
|------|--------|----------|-------------|
| phase_start_time | `$WORK_DIR/.audit_state/phase_start_time` | Yes | Unix timestamp |
| global_start_time | `$WORK_DIR/.audit_state/global_start_time` | Yes | Unix timestamp |
| PHASE_TIMEOUT_MIN | Phase ENTER step | Yes | Timeout limit in minutes |
| AGENT_TIMEOUT_MIN | Phase-4 ENTER step | Phase-4 only | Per-auditor timeout (20 min) |

## 🚨 CRITICAL Rules
| # | Rule | Consequence |
|---|------|-------------|
| CR-1 | Proceeding is MANDATORY regardless of timeout — never stop the audit on timeout | Stopping on timeout = audit abort, violates pipeline continuity |
| CR-2 | Global timeout limit is 150 minutes (2.5 hours) — non-negotiable | Exceeding global limit wastes resources; must save progress and prompt resume |
| CR-3 | On resume, MUST reset global_start_time to current timestamp | Stale timestamp causes immediate global timeout trigger |
| CR-4 | Send shutdown_request and wait 10s for graceful exit before force terminating | Abrupt termination may corrupt partial results |
| CR-5 | Each phase has a specific timeout value — do not use defaults across phases | Wrong timeout value causes premature or delayed timeout detection |

## Fill-in Procedure

### Procedure A: Record Phase Start Time

At each phase ENTER step, fill in timeout value and record start time:

| Field | Fill-in Value |
|-------|--------------|
| Current Phase | `Phase-___` (1 / 2 / 3 / 4 / 4.5 / 5) |
| PHASE_TIMEOUT_MIN | `___` (from timeout reference table below) |
| AGENT_TIMEOUT_MIN | `___` (Phase-4 only, otherwise N/A) |

**Timeout reference table:**

| Level | Timeout | Recovery Strategy |
|-------|---------|-------------------|
| Single Agent | 15 min | Terminate agent, record timeout, continue to next |
| Phase-1 | 20 min | Retry docker-builder once, still fails → halt for user |
| Phase-2 | 25 min | Continue with available tool results, mark degraded |
| Phase-3 | 20 min | Skip incomplete traces, fall back to static analysis |
| Phase-4 single expert | 20 min | Terminate expert, keep partial results, continue next |
| Phase-4 total | 60 min | Terminate remaining experts, use available results for Phase-4.5 |
| Phase-4.5 | 15 min | Generate partial report with available data |
| Phase-5 | 15 min | Force output whatever content is generated |
| Global | 150 min (2.5 hours) | Save progress + generate partial report + prompt resume |

**Bash — record phase start time:**

```bash
PHASE_TIMEOUT_MIN=___  # Fill in from timeout reference table
echo "$(date +%s)" > "$WORK_DIR/.audit_state/phase_start_time"
```

**Per-phase timeout mapping reference:**

```bash
# Phase-1:   PHASE_TIMEOUT_MIN=20
# Phase-2:   PHASE_TIMEOUT_MIN=25
# Phase-3:   PHASE_TIMEOUT_MIN=20
# Phase-4:   PHASE_TIMEOUT_MIN=60, AGENT_TIMEOUT_MIN=20
# Phase-4.5: PHASE_TIMEOUT_MIN=15
# Phase-5:   PHASE_TIMEOUT_MIN=15
```

### Procedure B: Check Elapsed Time

During WAIT step, after each agent completion, fill in elapsed time check:

| Field | Fill-in Value |
|-------|--------------|
| Phase Elapsed (minutes) | `___` (computed) |
| Global Elapsed (minutes) | `___` (computed) |
| Phase Timeout Exceeded? | `___` (Yes / No) |
| Global Timeout Exceeded? | `___` (Yes / No) |
| Triggered Action | `___` (phase recovery / global shutdown / none) |

**Bash — elapsed time check:**

```bash
PHASE_START=$(cat "$WORK_DIR/.audit_state/phase_start_time")
GLOBAL_START=$(cat "$WORK_DIR/.audit_state/global_start_time")
NOW=$(date +%s)
PHASE_ELAPSED=$(( (NOW - PHASE_START) / 60 ))
GLOBAL_ELAPSED=$(( (NOW - GLOBAL_START) / 60 ))

# Phase timeout check
if [ "$PHASE_ELAPSED" -ge "$PHASE_TIMEOUT_MIN" ]; then
  echo "⏱️ Phase timeout reached (${PHASE_ELAPSED}min / ${PHASE_TIMEOUT_MIN}min limit)"
  # Execute phase-specific recovery from timeout reference table
fi

# Global timeout check (150 min = 2.5 hours)
if [ "$GLOBAL_ELAPSED" -ge 150 ]; then
  echo "⏱️ Global timeout reached (${GLOBAL_ELAPSED}min)"
  # Save checkpoint, generate partial report, TeamDelete(), prompt resume
fi
```

### Procedure C: Timeout Handling Flow

On agent/phase timeout, fill in the handling steps:

| Field | Fill-in Value |
|-------|--------------|
| Timed-out Agent ID | `___` |
| Timeout Type | `___` (agent / phase / global) |
| Shutdown Request Sent? | `___` (Yes + timestamp) |
| Graceful Exit Within 10s? | `___` (Yes / No → force terminate) |
| Agent Status Written | `"timed_out"` in checkpoint.json |
| Next Action | `___` (continue to next agent / next phase / save & prompt resume) |

**Agent/phase timeout steps:**
1. Send `shutdown_request` to timed-out agent (wait 10s for graceful exit)
2. Update agent_states: `jq '.agent_states["AGENT_ID"].status = "timed_out"'`
3. Save current progress to checkpoint.json
4. Mark ⏱️ timeout in pipeline view
5. Continue to next step — proceeding is MANDATORY regardless of timeout

**Global timeout steps:**
1. Save progress to checkpoint.json
2. Generate report from completed phases
3. TeamDelete()
4. Print: `"⏱️ Global timeout, progress saved. Resume with checkpoint: /php-audit $ARGUMENTS"`

### Procedure D: Reset Timers on Resume

On resume from checkpoint, fill in timer reset:

| Field | Fill-in Value |
|-------|--------------|
| Resume Phase | `Phase-___` |
| New global_start_time | `___` (current Unix timestamp) |
| New phase_start_time | `___` (current Unix timestamp) |

**Bash — reset global timer on resume:**

```bash
# In Resume Protocol, after setting WORK_DIR:
echo "$(date +%s)" > "$WORK_DIR/.audit_state/global_start_time"
```

## Output Contract
| Output File | Path | Schema | Description |
|-------------|------|--------|-------------|
| phase_start_time | `$WORK_DIR/.audit_state/phase_start_time` | Unix timestamp (plaintext) | Updated at each phase ENTER |
| global_start_time | `$WORK_DIR/.audit_state/global_start_time` | Unix timestamp (plaintext) | Set once at INIT, reset on resume |
| Agent status updates | `checkpoint.json` → `.agent_states` | `"timed_out"` status value | Timeout status recorded per agent |

## Examples

### ✅ GOOD: Phase-4 per-auditor timeout with graceful handling
```
sqli_auditor spawned at 10:00, AGENT_TIMEOUT_MIN=20
sqli_auditor still running at 10:20
→ Send shutdown_request
→ Wait 10s for graceful exit
→ jq '.agent_states["sqli_auditor"].status = "timed_out"' checkpoint.json
→ Print: "⏱️ sqli_auditor timed out (20min), keeping partial results"
→ Continue to next auditor
```
Explanation: Properly sends shutdown request, waits for graceful exit, records status, and continues ✅

### ❌ BAD: Stopping audit on timeout
```
Phase-4 timeout reached (60min)
→ "🛑 Audit failed due to timeout"
```
What's wrong: Must continue to Phase-4.5 with available results — violates CR-1 ❌

### ❌ BAD: Not resetting timer on resume
```
Resume from Phase-3 at 14:00
global_start_time still reads 10:00 from previous run
→ Global timeout triggers immediately
```
What's wrong: Must reset global_start_time to current timestamp on resume — violates CR-3 ❌

## Error Handling
| Error | Action |
|-------|--------|
| phase_start_time file missing | Use global_start_time as fallback |
| global_start_time file missing | Create with current timestamp |
| Agent does not respond to shutdown_request within 10s | Force terminate |
| All Phase-4 auditors timed out | Continue to Phase-4.5 with empty exploits/ (generate "no findings" report) |
