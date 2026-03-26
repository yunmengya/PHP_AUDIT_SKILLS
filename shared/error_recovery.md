# Error Recovery Guide

Abnormal scenarios that MAY occur during the audit process, and their recovery procedures.

---

## 1. SQLite Database Corruption

### Symptoms
- `audit_db.sh` commands return `database disk image is malformed`
- Queries return empty results when data should exist

### Recovery Procedure

```bash
# 1. Check integrity
sqlite3 "$MEMORY_DB" "PRAGMA integrity_check;"
# Expected output: ok

# 2. If corrupted — export recoverable data
sqlite3 "$MEMORY_DB" ".dump" > /tmp/memory_backup.sql

# 3. Rebuild the database
mv "$MEMORY_DB" "${MEMORY_DB}.corrupted.$(date +%s)"
sqlite3 "$MEMORY_DB" < /tmp/memory_backup.sql

# 4. Re-initialize (ensure table structure is complete)
bash tools/audit_db.sh init-memory
```

### Session Database Corruption (audit_session.db)
```bash
# Session database corruption only affects the current audit
# If Phase-4 already has exploits/*.json output, it can be safely rebuilt
mv "$WORK_DIR/audit_session.db" "${WORK_DIR}/audit_session.db.corrupted"
bash tools/audit_db.sh init-session "$WORK_DIR"
# Note: shared_findings and qc_records will be lost, but exploit results are unaffected
```

### Prevention
- `audit_db.sh` has WAL mode enabled (`PRAGMA journal_mode=WAL`), providing strong crash recovery
- Avoid manually operating .db files during audit
- SQLite fails silently when disk space is insufficient — ensure ≥ 500MB available space before audit

## 2. Phase-4 Auditor Crash/Timeout

### Symptoms
- Agent unresponsive for more than 10 minutes
- checkpoint.json `agent_states` shows `status: "attacking"` with no updates
- Docker container in unknown state

### Recovery Procedure

```bash
# 1. Check Agent status
jq '.agent_states' "$WORK_DIR/checkpoint.json"

# 2. Rollback Docker snapshot (restore to pre-attack state)
docker commit php_audit_target php_audit_snapshot_recovery
docker stop php_audit_target 2>/dev/null
docker rm php_audit_target 2>/dev/null
docker run -d --name php_audit_target php_audit_snapshot_pre_attack

# 3. Check for existing partial results
ls -la "$WORK_DIR/exploits/${SINK_ID}_plan.json"  # Phase 1 analysis results
ls -la "$WORK_DIR/exploits/${SINK_ID}.json"        # Phase 2 attack results (may be incomplete)

# 4. Update Agent status
jq --arg agent "$AGENT_NAME" \
   '.agent_states[$agent].status = "timeout" | .agent_states[$agent].error = "Agent crashed, snapshot restored"' \
   "$WORK_DIR/checkpoint.json" > /tmp/cp.json && mv /tmp/cp.json "$WORK_DIR/checkpoint.json"

# 5. Decision
# - If _plan.json exists → can re-spawn Agent to execute Phase 2 only
# - If _plan.json does not exist → requires full re-spawn (from Phase 1)
# - If partial exploit results exist → mark as partial, continue to next Auditor
```

### Notes
- Each Auditor MAY be retried at most **2 times** (redo_count limit)
- If 3 consecutive Auditors crash → pause the audit and check Docker environment health
- Partial results from crashed Auditors SHALL be retained with `"confidence": "low"`

## 3. Token Budget Overflow

### Symptoms
- Agent output is truncated
- QC reviewer reports "incomplete output"
- LLM returns "context length exceeded" error

### Recovery Procedure

**Stage 1 — Automatic Degradation (defined in agent_injection_framework.md):**
1. The main orchestrator counts total L1 + L2 lines before injection
2. If budget exceeded → degrade L2 resources to L3 one by one, from largest to smallest by line count
3. Degradation log is written to `$WORK_DIR/.audit_state/injection_log.json`

**Stage 2 — Manual Degradation (when automatic degradation is still insufficient):**
```bash
# Force-degrade the largest L2 resources to L3
# Degradation priority order (largest to smallest):
# 1. php_specific_patterns.md (568 lines)
# 2. second_order.md (535 lines)
# 3. attack_chains.md (492 lines)
# 4. false_positive_patterns.md (475 lines)

# In the Agent prompt, retain only path references:
echo "--- 按需引用资源（L3）---
以下资源因 Token 预算限制未全文注入:
- ${SKILL_DIR}/shared/php_specific_patterns.md（568 行）
  摘要: PHP 特有安全模式库
"
```

**Stage 3 — Emergency Mode (still over budget):**
- Inject only L1 (3 files) + that Auditor's .md file + context_pack
- Mark `"mode": "degraded"` in checkpoint.json
- Lower the QC pass threshold (all SHOULD-PASS changed to WARN)

## 4. Concurrent Audit Conflict

### Symptoms
- Two audits using the same Docker container simultaneously
- attack_memory.db write conflicts (SQLite WAL can handle concurrent reads, but concurrent writes MAY timeout)

### Prevention Mechanism

```bash
# Create lock file when audit starts
LOCK_FILE="$WORK_DIR/.audit_lock"

if [ -f "$LOCK_FILE" ]; then
    LOCK_PID=$(cat "$LOCK_FILE")
    if kill -0 "$LOCK_PID" 2>/dev/null; then
        echo "❌ 审计冲突: PID $LOCK_PID 正在使用此工作目录"
        echo "   如果确认前一审计已结束，手动删除: rm $LOCK_FILE"
        exit 1
    else
        echo "⚠️ 发现过期锁文件（PID $LOCK_PID 已退出），自动清理"
        rm "$LOCK_FILE"
    fi
fi
echo $$ > "$LOCK_FILE"
trap "rm -f '$LOCK_FILE'" EXIT
```

### Global Memory Database Concurrency
- `attack_memory.db` uses WAL mode, supporting multiple readers + 1 writer
- `audit_db.sh` sets `.timeout 5000` (5-second lock wait)
- Edge case: lock wait exceeds 5 seconds → write fails but does not affect audit results (memory writes are best-effort)

## 5. Insufficient Disk Space

### Detection
```bash
# Pre-audit check (SHOULD be performed in Phase-1)
AVAIL_MB=$(df -m "$WORK_DIR" | tail -1 | awk '{print $4}')
if [ "$AVAIL_MB" -lt 500 ]; then
    echo "⚠️ 磁盘空间不足: ${AVAIL_MB}MB（建议 ≥ 500MB）"
    echo "   Docker 镜像 + 快照 + 日志 + 数据库可能需要 200-500MB"
fi
```

### Recovery
```bash
# Clean up unnecessary Docker images
docker image prune -f
# Clean up old snapshots (keep the most recent 2)
docker images --format '{{.Repository}}:{{.Tag}}' | grep 'snapshot' | tail -n +3 | xargs -r docker rmi
# Compress old audit logs
gzip "$WORK_DIR"/*.log 2>/dev/null
```

## Constraints

- Recovery operations MUST NOT modify already-generated `exploits/*.json` (confirmed vulnerability evidence is immutable)
- All recovery operations MUST be logged to `$WORK_DIR/.audit_state/recovery_log.json`
- After recovery, the current Phase's GATE verification MUST be re-executed
