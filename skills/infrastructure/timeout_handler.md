# Skill S-006: Timeout Handler

## IDENTITY
- **Skill ID**: S-006
- **Phase**: Cross-phase infrastructure
- **Responsibility**: Monitor and enforce tiered timeout limits for individual agents, phases, and global audit duration. Trigger phase-specific recovery on timeout.

## INPUT CONTRACT

| Input | Source | Required | Fields Used |
|-------|--------|----------|-------------|
| `phase_start_time` | `$WORK_DIR/.audit_state/phase_start_time` | Yes | Unix timestamp |
| `global_start_time` | `$WORK_DIR/.audit_state/global_start_time` | Yes | Unix timestamp |
| `PHASE_TIMEOUT_MIN` | Phase ENTER step | Yes | Timeout limit in minutes |
| `AGENT_TIMEOUT_MIN` | Phase-4 ENTER step | Phase-4 only | Per-auditor timeout (20 min) |

## TIERED TIMEOUT LIMITS

| Level | Timeout | Recovery Strategy |
|-------|---------|-------------------|
| **Single Agent** | 15 min | Terminate agent, record timeout, continue to next |
| **Phase-1** | 20 min | Retry docker-builder once, still fails → halt for user |
| **Phase-2** | 25 min | Continue with available tool results, mark degraded |
| **Phase-3** | 20 min | Skip incomplete traces, fall back to static analysis |
| **Phase-4 single expert** | 20 min (analysis+attack) | Terminate expert, keep partial results, continue next |
| **Phase-4 total** | 60 min | Terminate remaining experts, use available results for Phase-4.5 |
| **Phase-4.5** | 15 min | Generate partial report with available data |
| **Phase-5** | 15 min | Force output whatever content is generated |
| **Global** | 2.5 hours (150 min) | Save progress + generate partial report + prompt resume |

## FILL-IN PROCEDURE

### Step 1: Record Phase Start Time (at each ENTER step)

```bash
PHASE_TIMEOUT_MIN=【按上表填写】
echo "$(date +%s)" > "$WORK_DIR/.audit_state/phase_start_time"
```

Per-phase timeout mapping:
```bash
# Phase-1:   PHASE_TIMEOUT_MIN=20
# Phase-2:   PHASE_TIMEOUT_MIN=25
# Phase-3:   PHASE_TIMEOUT_MIN=20
# Phase-4:   PHASE_TIMEOUT_MIN=60, AGENT_TIMEOUT_MIN=20
# Phase-4.5: PHASE_TIMEOUT_MIN=15
# Phase-5:   PHASE_TIMEOUT_MIN=15
```

### Step 2: Check Elapsed Time (during WAIT step, after each agent completion)

```bash
PHASE_START=$(cat "$WORK_DIR/.audit_state/phase_start_time")
GLOBAL_START=$(cat "$WORK_DIR/.audit_state/global_start_time")
NOW=$(date +%s)
PHASE_ELAPSED=$(( (NOW - PHASE_START) / 60 ))
GLOBAL_ELAPSED=$(( (NOW - GLOBAL_START) / 60 ))

# Phase timeout check
if [ "$PHASE_ELAPSED" -ge "$PHASE_TIMEOUT_MIN" ]; then
  echo "⏱️ Phase timeout reached (${PHASE_ELAPSED}min / ${PHASE_TIMEOUT_MIN}min limit)"
  # Execute phase-specific recovery from table above
fi

# Global timeout check (150 min = 2.5 hours)
if [ "$GLOBAL_ELAPSED" -ge 150 ]; then
  echo "⏱️ Global timeout reached (${GLOBAL_ELAPSED}min)"
  # Save checkpoint, generate partial report, TeamDelete(), prompt resume
fi
```

### Step 3: Timeout Handling Flow

On any agent/phase timeout:
1. Send `shutdown_request` to timed-out agent (wait 10s for graceful exit)
2. Update agent_states: `jq '.agent_states["AGENT_ID"].status = "timed_out"'`
3. Save current progress to checkpoint.json
4. Mark ⏱️ timeout in pipeline view
5. Continue to next step — **proceeding is MANDATORY regardless of timeout**

On global timeout:
1. Save progress to checkpoint.json
2. Generate report from completed phases
3. TeamDelete()
4. Print: "⏱️ 全局超时，已保存进度。使用断点续审继续：/php-audit $ARGUMENTS"

### Step 4: On Resume — Reset Timers

```bash
# In Resume Protocol, after setting WORK_DIR:
echo "$(date +%s)" > "$WORK_DIR/.audit_state/global_start_time"
```

## OUTPUT CONTRACT

| Output | Path | Description |
|--------|------|-------------|
| phase_start_time | `$WORK_DIR/.audit_state/phase_start_time` | Updated at each phase ENTER |
| global_start_time | `$WORK_DIR/.audit_state/global_start_time` | Set once at INIT, reset on resume |
| Agent status updates | `checkpoint.json .agent_states` | `"timed_out"` status on timeout |

## EXAMPLES

✅ GOOD — Phase-4 per-auditor timeout:
```
sqli_auditor spawned at 10:00, AGENT_TIMEOUT_MIN=20
sqli_auditor still running at 10:20
→ Send shutdown_request
→ Wait 10s for graceful exit
→ jq '.agent_states["sqli_auditor"].status = "timed_out"' checkpoint.json
→ Print: "⏱️ sqli_auditor timed out (20min), keeping partial results"
→ Continue to next auditor
```

❌ BAD — Stopping audit on timeout:
```
Phase-4 timeout reached (60min)
→ "🛑 Audit failed due to timeout"  ← WRONG: must continue to Phase-4.5
```

❌ BAD — Not resetting timer on resume:
```
Resume from Phase-3 at 14:00
global_start_time still reads 10:00 from previous run
→ Global timeout triggers immediately  ← WRONG: must reset to current time
```

## ERROR HANDLING

| Error | Action |
|-------|--------|
| phase_start_time file missing | Use global_start_time as fallback |
| global_start_time file missing | Create with current timestamp |
| Agent does not respond to shutdown_request within 10s | Force terminate |
| All Phase-4 auditors timed out | Continue to Phase-4.5 with empty exploits/ (generate "no findings" report) |
