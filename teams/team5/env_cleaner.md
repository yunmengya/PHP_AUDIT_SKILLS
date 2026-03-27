> **Skill ID**: S-092 | **Phase**: 5 | **Role**: Clean up Docker environment and restore clean state
> **Input**: TARGET_PATH, WORK_DIR
> **Output**: Cleanup status report

# Env-Cleaner — Fill-in Template

---

## 1. Identity

| Field | Value |
|-------|-------|
| Skill ID | S-092 |
| Skill Name | Env-Cleaner |
| Phase | 5 — Post-Audit |
| Purpose | Restore Docker environment to a clean state: stop traces, restore code, remove artifacts, reset DB, wipe sensitive data |
| Agent Persona | You are the Env-Cleaner agent. You undo all changes the audit made to the target environment. |

---

## 2. Input Contract

| # | Parameter | Source | Required | Description |
|---|-----------|--------|----------|-------------|
| 1 | `TARGET_PATH` | Orchestrator | ✅ Yes | Absolute path to the target application source code |
| 2 | `WORK_DIR` | Orchestrator | ✅ Yes | Absolute path to the audit working directory |

---

## 3. CRITICAL Rules

1. Cleanup failures MUST NOT block report generation — only log warnings.
2. NEVER delete business files; only remove files created by the audit toolchain.
3. Procedure F (Sensitive Data Cleanup) is **NOT** run during the initial parallel phase — it is triggered separately by the orchestrator after the final quality check passes, to avoid race conditions with the report-writer.
4. Securely overwrite `audit_session.db` before deletion (it contains plaintext credentials).
5. All results must be reported in the final JSON status object.

---

## 4. Fill-in Procedure

### Procedure A — Stop Xdebug

Stop any remaining Xdebug trace processes inside the container.

| # | Item | Command | Expected Result | Actual |
|---|------|---------|-----------------|--------|
| 1 | Kill Xdebug processes | `docker exec php pkill -f xdebug 2>/dev/null \|\| true` | No xdebug processes remain | `____` |

---

### Procedure B — Restore Code

Restore all source code inside the container to its pre-audit state.

| # | Restoration Method | Command | Status |
|---|-------------------|---------|--------|
| 1 | Git — discard modifications | `docker exec php git checkout . 2>/dev/null \|\| true` | `____` |
| 2 | Git — remove untracked files | `docker exec php git clean -fd 2>/dev/null \|\| true` | `____` |
| 3 | *(Fallback)* Volume remount | Rely on docker compose volume mounts to keep source intact; manually delete temp files | `____` |

- Use method 1 + 2 when git is available inside the container.
- Fall back to method 3 only if git is not present.

---

### Procedure C — Clean Artifacts

Remove all test artifacts created during the audit. Fill in the checklist:

| # | Artifact Category | Path Pattern | Command | Removed? |
|---|-------------------|-------------|---------|----------|
| 1 | RCE proof files | `/tmp/rce_proof_*` | `docker exec php rm -rf /tmp/rce_proof_* 2>/dev/null \|\| true` | `____` |
| 2 | Deserialization proof files | `/tmp/deserial_proof_*` | `docker exec php rm -rf /tmp/deserial_proof_* 2>/dev/null \|\| true` | `____` |
| 3 | Xdebug trace files | `/tmp/xdebug_traces/*` | `docker exec php rm -rf /tmp/xdebug_traces/* 2>/dev/null \|\| true` | `____` |
| 4 | WebShell proof files | `/var/www/html/shell_proof.*` | `docker exec php rm -f /var/www/html/shell_proof.* 2>/dev/null \|\| true` | `____` |
| 5 | Shell test scripts | `/var/www/html/shell_test_*.php` | `docker exec php rm -f /var/www/html/shell_test_*.php 2>/dev/null \|\| true` | `____` |
| 6 | RCE test scripts | `/var/www/html/rce_test_*.php` | `docker exec php rm -f /var/www/html/rce_test_*.php 2>/dev/null \|\| true` | `____` |
| 7 | Upload test scripts | `/var/www/html/upload_test_*.php` | `docker exec php rm -f /var/www/html/upload_test_*.php 2>/dev/null \|\| true` | `____` |
| 8 | Sink finder tool | `/tmp/sink_finder.php` | `docker exec php rm -f /tmp/sink_finder.php 2>/dev/null \|\| true` | `____` |
| 9 | Trace filter tool | `/tmp/trace_filter.php` | `docker exec php rm -f /tmp/trace_filter.php 2>/dev/null \|\| true` | `____` |

---

### Procedure D — Reset Database

Choose the reset method based on the detected framework. Fill in:

| # | Framework | Reset Command | Status |
|---|-----------|---------------|--------|
| 1 | Laravel | `docker exec php php artisan migrate:fresh --force 2>/dev/null \|\| true` | `____` |
| 2 | Generic (MySQL) | `docker exec -i db mysql -uroot -paudit_root_pass audit_db < $WORK_DIR/reconstructed_schema.sql 2>/dev/null \|\| true` | `____` |

Then clean up test data regardless of framework:

| # | Test Data Type | Cleanup Command | Status |
|---|---------------|-----------------|--------|
| 1 | Test user accounts | `docker exec db mysql -uroot -paudit_root_pass audit_db -e "DELETE FROM users WHERE email LIKE '%@test.com';" 2>/dev/null \|\| true` | `____` |

---

### Procedure E — Verify Restoration

Run verification checks and fill in the results:

| # | Check | Command | Expected | Actual | Pass? |
|---|-------|---------|----------|--------|-------|
| 1 | Code status clean | `docker exec php git status 2>/dev/null` | Clean (no modified files) | `____` | `____` |
| 2 | Web service accessible | `docker exec php curl -sS -o /dev/null -w "%{http_code}" http://nginx:80/` | `200` or `302` | `____` | `____` |
| 3 | No RCE proof files remain | `docker exec php ls /tmp/rce_proof_* 2>/dev/null` | "No such file" | `____` | `____` |
| 4 | No shell proof files remain | `docker exec php ls /var/www/html/shell_proof.* 2>/dev/null` | "No such file" | `____` | `____` |

---

### Procedure F — Sensitive Data Cleanup

> ⚠️ **Trigger**: This procedure is **NOT** executed during the initial env-cleaner run. It is triggered by the orchestrator via a separate spawn/message **after** the final quality check (`quality-checker-final`) passes. This prevents race conditions with the report-writer that may still be reading these files.

| # | Data Type | Location | Cleanup Command | Securely Deleted? |
|---|-----------|----------|-----------------|-------------------|
| 1 | Audit session DB (contains plaintext credentials) | `$WORK_DIR/audit_session.db` | Overwrite with urandom then `rm -f` | `____` |
| 2 | WAL file | `$WORK_DIR/audit_session.db-wal` | `rm -f` | `____` |
| 3 | SHM file | `$WORK_DIR/audit_session.db-shm` | `rm -f` | `____` |
| 4 | Second-order exploit data | `$WORK_DIR/second_order/` | `rm -rf` | `____` |
| 5 | Flock lock file | `$WORK_DIR/.shared_findings.lock` | `rm -f` | `____` |

Secure deletion command for `audit_session.db`:

```bash
if [ -f "$WORK_DIR/audit_session.db" ]; then
  dd if=/dev/urandom of="$WORK_DIR/audit_session.db" \
    bs=1k count=$(stat -f%z "$WORK_DIR/audit_session.db" 2>/dev/null \
    || stat -c%s "$WORK_DIR/audit_session.db" 2>/dev/null) 2>/dev/null
  rm -f "$WORK_DIR/audit_session.db" "$WORK_DIR/audit_session.db-wal" "$WORK_DIR/audit_session.db-shm"
fi
rm -rf "$WORK_DIR/second_order/" 2>/dev/null || true
rm -f "$WORK_DIR/.shared_findings.lock" 2>/dev/null || true
```

---

## 5. Output Contract

| Field | Value |
|-------|-------|
| Format | JSON object |
| Destination | Returned to orchestrator (not written to file) |

Output structure:

```json
{
  "cleanup_status": "completed",
  "code_restored": true,
  "traces_cleaned": true,
  "proof_files_cleaned": true,
  "sensitive_data_cleaned": true,
  "database_reset": true,
  "web_accessible": true,
  "remaining_issues": []
}
```

- Set each boolean to `false` if the corresponding procedure failed.
- Append any failure descriptions to `remaining_issues`.

---

## 6. Examples

### ✅ GOOD — Complete cleanup with all items checked

```json
{
  "cleanup_status": "completed",
  "code_restored": true,
  "traces_cleaned": true,
  "proof_files_cleaned": true,
  "sensitive_data_cleaned": true,
  "database_reset": true,
  "web_accessible": true,
  "remaining_issues": []
}
```

**Why this is correct:**
- All procedures (A–F) executed successfully.
- Every checklist item was filled in and verified.
- `remaining_issues` is empty — nothing was left behind.

### ❌ BAD — Missed Xdebug traces, left test accounts in DB

```json
{
  "cleanup_status": "completed",
  "code_restored": true,
  "traces_cleaned": true,
  "proof_files_cleaned": true,
  "sensitive_data_cleaned": false,
  "database_reset": true,
  "web_accessible": true,
  "remaining_issues": []
}
```

**Problems:**
1. `traces_cleaned` is `true` but Xdebug trace files still exist under `/tmp/xdebug_traces/` — Procedure A and C were not verified.
2. `database_reset` is `true` but test accounts (`*@test.com`) remain in the `users` table — Procedure D test-data cleanup was skipped.
3. `sensitive_data_cleaned` is `false` but `remaining_issues` is empty — failures must be described.
4. Procedure E verification checklist was never filled in.

---

## 7. Error Handling

| # | Scenario | Handling |
|---|----------|----------|
| 1 | Docker container not running | Log warning; mark affected procedures as failed; do NOT block report generation |
| 2 | Git not available in container | Fall back to volume-based restoration (Procedure B method 3) |
| 3 | Database connection failure | Log warning; set `database_reset` to `false`; add to `remaining_issues` |
| 4 | `rm` command fails for artifact | Log warning; set `proof_files_cleaned` to `false`; add to `remaining_issues` |
| 5 | Web service unreachable after cleanup | Log warning; set `web_accessible` to `false`; add to `remaining_issues` |
| 6 | `audit_session.db` already deleted | Skip secure-delete step; note in log |
| 7 | Procedure F triggered too early (report-writer still running) | MUST NOT execute — return error to orchestrator |
