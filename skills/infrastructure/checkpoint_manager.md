# Skill S-003: Checkpoint Manager

## IDENTITY
- **Skill ID**: S-003
- **Phase**: Cross-phase infrastructure
- **Responsibility**: Manage checkpoint.json lifecycle — read, write (atomic), validate, resume from breakpoint, incremental audit detection.

## INPUT CONTRACT

| Input | Source | Required | Fields Used |
|-------|--------|----------|-------------|
| `$WORK_DIR` | S-002 workspace_init | Yes | Base working directory |
| `checkpoint.json` | Previous audit run | No | Resume detection |
| `schemas/checkpoint.schema.json` | SKILL_DIR | Yes | Format reference |

## CHECKPOINT FORMAT

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

## FILL-IN PROCEDURE

### Procedure A: Atomic Write (used by ALL checkpoint modifications)

```bash
# Atomic write: write to temp file in same filesystem, then rename
jq 'MODIFICATIONS' "$WORK_DIR/checkpoint.json" > "$WORK_DIR/checkpoint.json.tmp" && \
    mv "$WORK_DIR/checkpoint.json.tmp" "$WORK_DIR/checkpoint.json"
# NEVER use /tmp/cp.json — temp file MUST be on same filesystem as target for atomic mv
```

During Phase-4 parallel execution, checkpoint updates MUST be serialized:
- ONLY the orchestrator writes checkpoint.json (agents use TaskUpdate/SendMessage)
- Orchestrator processes agent completions ONE AT A TIME, updating checkpoint after each

### Procedure B: Degradation Tracking

When writing degradation status, ALWAYS use this path format:
```bash
jq '.phases.phase3.mode = "degraded" | .phases.phase3.degradation_reason = "REASON"' \
    "$WORK_DIR/checkpoint.json" > "$WORK_DIR/checkpoint.json.tmp" && mv "$WORK_DIR/checkpoint.json.tmp" "$WORK_DIR/checkpoint.json"
```

### Procedure C: Agent State Updates

On each agent spawn:
```bash
jq '.agent_states["AGENT_ID"] = {"status":"spawned","spawned_at":"TIMESTAMP","redo_count":0}' \
    "$WORK_DIR/checkpoint.json" > "$WORK_DIR/checkpoint.json.tmp" && mv "$WORK_DIR/checkpoint.json.tmp" "$WORK_DIR/checkpoint.json"
```

On each agent completion:
```bash
jq '.agent_states["AGENT_ID"].status = "passed" | .agent_states["AGENT_ID"].completed_at = "TIMESTAMP"' \
    "$WORK_DIR/checkpoint.json" > "$WORK_DIR/checkpoint.json.tmp" && mv "$WORK_DIR/checkpoint.json.tmp" "$WORK_DIR/checkpoint.json"
# Use "failed" if inline QC rejects the agent output; "passed" if accepted
```

### Procedure D: Resume Detection

Check if `${HOME}/.php_audit/${PROJECT_NAME}/` contains a recent directory with `checkpoint.json`:

- Not found → fresh start
- Found → read checkpoint, ask user whether to resume from breakpoint
  - No → use new WORK_DIR, fresh start
  - Yes → execute **Resume Protocol** (below)

### Procedure E: Resume Protocol

```
0. Validate checkpoint.json integrity before reading:
   jq empty < "$WORK_DIR/checkpoint.json" 2>/dev/null
   If invalid → check for backup:
     if [ -f "$WORK_DIR/checkpoint.json.bak" ]; then
       cp "$WORK_DIR/checkpoint.json.bak" "$WORK_DIR/checkpoint.json"
       Print: "⚠️ checkpoint.json was corrupted, restored from backup"
     else → halt, ask user to provide last known phase
   On every successful checkpoint read, save backup:
     cp "$WORK_DIR/checkpoint.json" "$WORK_DIR/checkpoint.json.bak"

1. Read checkpoint.json → get last_completed_phase + mode (full/degraded)
2. Set WORK_DIR to the previous audit directory
2.5. Re-validate runtime environment matches saved state:
   - Compare current `php -v` output with environment_status.json php_version
   - Verify Docker daemon still running: `docker ps >/dev/null 2>&1`
   - If mismatch → warn user, ask whether to continue or re-run Phase-1
3. Verify ALL artifacts from completed phases actually exist AND are valid:
   - Phase-1 done? → verify environment_status.json:
     • File exists and non-empty
     • Valid JSON (jq . < file >/dev/null 2>&1)
     • Required fields present: php_version, framework, framework_version
   - Phase-2 done? → verify priority_queue.json + context_packs/:
     • priority_queue.json is valid JSON with at least 1 entry
     • context_packs/ directory exists and has ≥1 .json file
     • Each context_pack JSON is parseable
   - Phase-3 done? → verify credentials.json:
     • File exists and is valid JSON
     • If checkpoint `.phases.phase3.mode` == "degraded": accept missing credentials
       but mark Phase-4 as NOT_VERIFIED mode
   - Phase-4 done? → verify exploits/*.json:
     • At least 1 exploit JSON exists and is valid
     • exploit_summary.json exists (generated at Phase-4 exit, not during attack)
4. Find the LAST phase whose artifacts are ALL valid → that is the TRUE resume point
5. Carry forward degradation flags:
   - If any completed phase has mode="degraded" in checkpoint → set
     DEGRADED_PHASES list and propagate to downstream phase instructions
6. Resume from the NEXT phase after the validated one
   Example: checkpoint says Phase-3 done, but credentials.json is missing
            → re-run from Phase-3 (not Phase-4)
7. IMPORTANT: Never skip a phase. Resume means "start from a verified point",
   not "mark phases as done without running them".
```

On Resume, reset timers:
```bash
echo "$(date +%s)" > "$WORK_DIR/.audit_state/global_start_time"
```

### Procedure F: Incremental Audit Mode

Check if target project is a Git repo with a prior complete audit:

```bash
cd "$ARGUMENTS"
git rev-parse --git-dir 2>/dev/null
```

- Not a Git repo → skip incremental, run full audit
- Is a Git repo:
  1. Find most recent `${HOME}/.php_audit/${PROJECT_NAME}/*/checkpoint.json` with `current=done`
  2. Read `git_commit_hash` field from it
  3. Compare: `git diff --name-only {old_hash} HEAD -- "*.php"`
  4. If changed files < 10 and no new route files:
     - Ask user: "检测到仅 {n} 个 PHP 文件变更，是否执行增量审计？（仅审计变更文件关联的路由和 Sink）"
     - User agrees → set `INCREMENTAL_MODE=true`, record changed file list
     - User declines → full audit
  5. If changed files >= 10 or new routes exist → auto full audit

Incremental mode effects:
- Phase-2: context_extractor only extracts sinks from changed files
- Phase-2: risk_classifier only re-rates changed-file-related sinks
- Phase-4: only launch expert agents matching changed sink types
- Phase-5: report marked "增量审计" with changed file list

## OUTPUT CONTRACT

| Output | Path | Description |
|--------|------|-------------|
| checkpoint.json | `$WORK_DIR/checkpoint.json` | Audit state snapshot (atomic writes only) |
| checkpoint.json.bak | `$WORK_DIR/checkpoint.json.bak` | Backup on each successful read |

## EXAMPLES

✅ GOOD — Atomic write with degradation:
```bash
jq '.phases.phase3.mode = "degraded" | .phases.phase3.degradation_reason = "auth simulation failed" | .mode = "degraded"' \
    "$WORK_DIR/checkpoint.json" > "$WORK_DIR/checkpoint.json.tmp" && \
    mv "$WORK_DIR/checkpoint.json.tmp" "$WORK_DIR/checkpoint.json"
```

❌ BAD — Direct write (risk of corruption):
```bash
echo '{"completed": ["env"]}' > "$WORK_DIR/checkpoint.json"
# WRONG: not atomic, will corrupt if concurrent read happens
```

❌ BAD — Temp file on different filesystem:
```bash
jq '.current = "scan"' "$WORK_DIR/checkpoint.json" > /tmp/cp.json && mv /tmp/cp.json "$WORK_DIR/checkpoint.json"
# WRONG: /tmp may be different filesystem, mv becomes copy+delete (not atomic)
```

## ERROR HANDLING

| Error | Action |
|-------|--------|
| checkpoint.json corrupted | Restore from .bak; if no .bak → halt, ask user last known phase |
| Artifact integrity check fails on resume | Resume from last VERIFIED phase, not checkpoint-claimed phase |
| Docker mismatch on resume | Warn user, offer to re-run Phase-1 |
| jq not installed | Print error, abort (jq is required dependency) |
