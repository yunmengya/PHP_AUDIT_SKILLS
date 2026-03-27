# Checkpoint Manager

## Identity
| Field | Value |
|-------|-------|
| Skill ID | S-003 |
| Category | Infrastructure |
| Responsibility | Manage checkpoint.json lifecycle — atomic read/write, validation, resume from breakpoint, incremental audit detection |

## Input Contract
| File | Source | Required | Fields Used |
|------|--------|----------|-------------|
| `$WORK_DIR` | S-002 workspace_init | Yes | Base working directory |
| `checkpoint.json` | Previous audit run | No | Resume detection — `completed`, `current`, `mode`, `agent_states`, `phases` |
| `schemas/checkpoint.schema.json` | SKILL_DIR | Yes | Format reference for validation |

## Checkpoint Format Reference

checkpoint.json core fields (see `schemas/checkpoint.schema.json`):

```json
{
  "completed": ["env", "scan", "trace"],
  "current": "exploit",
  "mode": "full",
  "phase_timings": {
    "phase1": {"start": "2024-01-01T10:00:00Z", "end": "2024-01-01T10:12:00Z", "duration_min": 12}
  },
  "framework": "Laravel",
  "total_sinks": 45,
  "confirmed_vulns": 3,
  "agent_states": {
    "rce_auditor": {
      "status": "passed",
      "spawned_at": "2024-01-01T10:00:00Z",
      "completed_at": "2024-01-01T10:12:00Z",
      "qc_verdict": "pass",
      "redo_count": 0,
      "pivot_triggered": false
    }
  },
  "phases": {
    "phase1": {"mode": "full"},
    "phase2": {"mode": "full"},
    "phase3": {"mode": "degraded", "degradation_reason": "auth simulation failed"}
  }
}
```

Agent status enum: `spawned` → `running` → `passed` (QC pass) / `failed` (QC fail) / `retrying` (redo) / `degraded` (retries exhausted) / `timed_out` (exceeded timeout)

## 🚨 CRITICAL Rules
| # | Rule | Consequence |
|---|------|-------------|
| CR-1 | ALL checkpoint writes MUST be atomic (write to .tmp then mv) | Direct writes risk corruption during concurrent reads |
| CR-2 | Temp file MUST be on same filesystem as checkpoint.json (use `$WORK_DIR/checkpoint.json.tmp`, NEVER `/tmp/`) | Cross-filesystem mv degrades to copy+delete, losing atomicity |
| CR-3 | During Phase-4 parallel execution, ONLY the orchestrator writes checkpoint.json | Concurrent agent writes cause race conditions and data loss |
| CR-4 | On every successful checkpoint read, save backup to checkpoint.json.bak | Without backup, corruption leads to unrecoverable state |
| CR-5 | Resume must validate artifacts from ALL claimed-completed phases before resuming | Trusting checkpoint claims without verification leads to missing-artifact failures |
| CR-6 | Never skip a phase on resume — resume from NEXT phase after last VERIFIED phase | Skipping phases produces incomplete audit with missing data |
| CR-7 | Agent status must follow enum: spawned → running → passed/failed/retrying/degraded/timed_out | Invalid status values break orchestrator state machine logic |

## Fill-in Procedure

### Procedure A: Atomic Write
| Field | Fill-in Value |
|-------|---------------|
| Target file | `$WORK_DIR/checkpoint.json` |
| Temp file | `$WORK_DIR/checkpoint.json.tmp` |
| jq modification expression | ______ |
| Write successful | ______ (yes/no) |

```bash
# Atomic write: write to temp file in same filesystem, then rename
jq 'MODIFICATIONS' "$WORK_DIR/checkpoint.json" > "$WORK_DIR/checkpoint.json.tmp" && \
    mv "$WORK_DIR/checkpoint.json.tmp" "$WORK_DIR/checkpoint.json"
# NEVER use /tmp/cp.json — temp file MUST be on same filesystem as target for atomic mv
```

Concurrency rule during Phase-4 parallel execution:
- ONLY the orchestrator writes checkpoint.json (agents use TaskUpdate/SendMessage)
- Orchestrator processes agent completions ONE AT A TIME, updating checkpoint after each

### Procedure B: Degradation Tracking
| Field | Fill-in Value |
|-------|---------------|
| Phase being degraded | ______ (e.g., phase3) |
| Degradation reason | ______ |
| jq path | `.phases.{PHASE}.mode` = `"degraded"` |
| Write successful | ______ (yes/no) |

```bash
jq '.phases.phase3.mode = "degraded" | .phases.phase3.degradation_reason = "REASON"' \
    "$WORK_DIR/checkpoint.json" > "$WORK_DIR/checkpoint.json.tmp" && mv "$WORK_DIR/checkpoint.json.tmp" "$WORK_DIR/checkpoint.json"
```

### Procedure C: Agent State Updates
| Field | Fill-in Value |
|-------|---------------|
| Agent ID | ______ |
| Operation | ______ (spawn / completion) |
| Timestamp | ______ |
| Status set | ______ (spawned / passed / failed / retrying / degraded / timed_out) |
| redo_count | ______ (integer, 0 on spawn) |
| Write successful | ______ (yes/no) |

**On agent spawn:**
```bash
jq '.agent_states["AGENT_ID"] = {"status":"spawned","spawned_at":"TIMESTAMP","redo_count":0}' \
    "$WORK_DIR/checkpoint.json" > "$WORK_DIR/checkpoint.json.tmp" && mv "$WORK_DIR/checkpoint.json.tmp" "$WORK_DIR/checkpoint.json"
```

**On agent completion:**
```bash
jq '.agent_states["AGENT_ID"].status = "passed" | .agent_states["AGENT_ID"].completed_at = "TIMESTAMP"' \
    "$WORK_DIR/checkpoint.json" > "$WORK_DIR/checkpoint.json.tmp" && mv "$WORK_DIR/checkpoint.json.tmp" "$WORK_DIR/checkpoint.json"
# Use "failed" if inline QC rejects the agent output; "passed" if accepted
```

### Procedure D: Resume Detection
| Field | Fill-in Value |
|-------|---------------|
| Search path | `${HOME}/.php_audit/${PROJECT_NAME}/` |
| Previous checkpoint found | ______ (yes/no) |
| Previous checkpoint path | ______ |
| User chose to resume | ______ (yes/no/not-asked) |
| Decision | ______ (fresh_start / resume_protocol) |

Logic:
- Previous checkpoint NOT found → fresh start
- Previous checkpoint found → read checkpoint, ask user whether to resume from breakpoint
  - User says No → use new WORK_DIR, fresh start
  - User says Yes → execute **Procedure E: Resume Protocol**

### Procedure E: Resume Protocol
| Field | Fill-in Value |
|-------|---------------|
| Checkpoint JSON valid | ______ (yes / restored-from-bak / halted) |
| Backup saved | ______ (yes/no) |
| Last completed phase (claimed) | ______ |
| Mode (full/degraded) | ______ |
| WORK_DIR set to | ______ (previous audit directory) |
| PHP version match | ______ (match / mismatch) |
| Docker running | ______ (yes / no) |
| Environment action | ______ (continue / re-run Phase-1) |
| Phase-1 artifacts valid | ______ (yes/no/skipped) — environment_status.json |
| Phase-2 artifacts valid | ______ (yes/no/skipped) — priority_queue.json + context_packs/ |
| Phase-3 artifacts valid | ______ (yes/no/skipped) — credentials.json |
| Phase-4 artifacts valid | ______ (yes/no/skipped) — exploits/*.json + exploit_summary.json |
| TRUE resume point | Phase ______ |
| Degraded phases carried forward | ______ |
| Timers reset | ______ (yes/no) |

**Step 0 — Validate checkpoint integrity:**
```bash
jq empty < "$WORK_DIR/checkpoint.json" 2>/dev/null
# If invalid → check for backup:
if [ -f "$WORK_DIR/checkpoint.json.bak" ]; then
  cp "$WORK_DIR/checkpoint.json.bak" "$WORK_DIR/checkpoint.json"
  # Print: "⚠️ checkpoint.json was corrupted, restored from backup"
fi
# On every successful checkpoint read, save backup:
cp "$WORK_DIR/checkpoint.json" "$WORK_DIR/checkpoint.json.bak"
```

**Step 1 — Read checkpoint state:**
- Read checkpoint.json → get `last_completed_phase` + `mode` (full/degraded)

**Step 2 — Set WORK_DIR:**
- Set WORK_DIR to the previous audit directory

**Step 2.5 — Re-validate runtime environment:**
- Compare current `php -v` output with `environment_status.json` php_version
- Verify Docker daemon still running: `docker ps >/dev/null 2>&1`
- If mismatch → warn user, ask whether to continue or re-run Phase-1

**Step 3 — Verify artifacts from completed phases:**
- Phase-1 done? → verify `environment_status.json`: exists, non-empty, valid JSON, has `php_version`, `framework`, `framework_version`
- Phase-2 done? → verify `priority_queue.json` (valid JSON, ≥1 entry) + `context_packs/` (≥1 parseable .json file)
- Phase-3 done? → verify `credentials.json` (exists, valid JSON). If `.phases.phase3.mode == "degraded"`: accept missing credentials but mark Phase-4 as NOT_VERIFIED mode
- Phase-4 done? → verify `exploits/*.json` (≥1 valid JSON) + `exploit_summary.json` exists

**Step 4 — Determine TRUE resume point:**
- Find the LAST phase whose artifacts are ALL valid → that is the TRUE resume point

**Step 5 — Carry forward degradation flags:**
- If any completed phase has `mode="degraded"` → set DEGRADED_PHASES list and propagate

**Step 6 — Resume from NEXT phase after validated one:**
- Example: checkpoint says Phase-3 done, but credentials.json missing → re-run from Phase-3

**Step 7 — Reset timers:**
```bash
echo "$(date +%s)" > "$WORK_DIR/.audit_state/global_start_time"
```

### Procedure F: Incremental Audit Mode
| Field | Fill-in Value |
|-------|---------------|
| Target path | `$ARGUMENTS` = ______ |
| Is Git repo | ______ (yes/no) |
| Prior complete audit found | ______ (yes/no) |
| Previous commit hash | ______ |
| Changed PHP files count | ______ |
| New route files detected | ______ (yes/no) |
| User chose incremental | ______ (yes/no/not-asked) |
| INCREMENTAL_MODE | ______ (true/false) |
| Changed file list | ______ |

**Step 1 — Check if Git repo:**
```bash
cd "$ARGUMENTS"
git rev-parse --git-dir 2>/dev/null
```

**Step 2 — Decision logic:**
- Not a Git repo → skip incremental, run full audit
- Is a Git repo:
  1. Find most recent `${HOME}/.php_audit/${PROJECT_NAME}/*/checkpoint.json` with `current=done`
  2. Read `git_commit_hash` field from it
  3. Compare: `git diff --name-only {old_hash} HEAD -- "*.php"`
  4. If changed files < 10 and no new route files → ask user to confirm incremental mode
  5. If changed files ≥ 10 or new routes exist → auto full audit

**Incremental mode effects on downstream phases:**
- Phase-2: context_extractor only extracts sinks from changed files
- Phase-2: risk_classifier only re-rates changed-file-related sinks
- Phase-4: only launch expert agents matching changed sink types
- Phase-5: report marked as incremental audit with changed file list

## Output Contract
| Output File | Path | Schema | Description |
|-------------|------|--------|-------------|
| checkpoint.json | `$WORK_DIR/checkpoint.json` | `schemas/checkpoint.schema.json` | Audit state snapshot (atomic writes only) |
| checkpoint.json.bak | `$WORK_DIR/checkpoint.json.bak` | Same as checkpoint.json | Backup saved on each successful read |

## Examples

### ✅ GOOD: Atomic Write with Degradation
```bash
jq '.phases.phase3.mode = "degraded" | .phases.phase3.degradation_reason = "auth simulation failed" | .mode = "degraded"' \
    "$WORK_DIR/checkpoint.json" > "$WORK_DIR/checkpoint.json.tmp" && \
    mv "$WORK_DIR/checkpoint.json.tmp" "$WORK_DIR/checkpoint.json"
```
Explanation: Uses .tmp on same filesystem, atomic mv, single jq pipeline for all modifications ✅

### ❌ BAD: Direct Write (Corruption Risk)
```bash
echo '{"completed": ["env"]}' > "$WORK_DIR/checkpoint.json"
# WRONG: not atomic, will corrupt if concurrent read happens
```
Violates CR-1 (all writes must be atomic via .tmp + mv) ❌

### ❌ BAD: Temp File on Different Filesystem
```bash
jq '.current = "scan"' "$WORK_DIR/checkpoint.json" > /tmp/cp.json && mv /tmp/cp.json "$WORK_DIR/checkpoint.json"
# WRONG: /tmp may be different filesystem, mv becomes copy+delete (not atomic)
```
Violates CR-2 (temp file must be on same filesystem as target) ❌

## Error Handling
| Error | Action |
|-------|--------|
| checkpoint.json corrupted | Restore from .bak; if no .bak → halt, ask user for last known phase |
| Artifact integrity check fails on resume | Resume from last VERIFIED phase, not checkpoint-claimed phase |
| Docker mismatch on resume | Warn user, offer to re-run Phase-1 |
| jq not installed | Print error, abort (jq is required dependency) |
| Concurrent agent checkpoint write attempted | Reject — only orchestrator may write checkpoint.json during Phase-4 |
