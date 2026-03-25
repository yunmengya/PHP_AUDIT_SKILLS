# 错误恢复指南（Error Recovery Guide）

审计过程中可能遇到的异常场景及恢复流程。

---

## 1. SQLite 数据库损坏

### 症状
- `audit_db.sh` 命令返回 `database disk image is malformed`
- 查询返回空结果但数据应存在

### 恢复流程

```bash
# 1. 检测完整性
sqlite3 "$MEMORY_DB" "PRAGMA integrity_check;"
# 期望输出: ok

# 2. 如果损坏 — 导出可恢复的数据
sqlite3 "$MEMORY_DB" ".dump" > /tmp/memory_backup.sql

# 3. 重建数据库
mv "$MEMORY_DB" "${MEMORY_DB}.corrupted.$(date +%s)"
sqlite3 "$MEMORY_DB" < /tmp/memory_backup.sql

# 4. 重新初始化（确保表结构完整）
bash tools/audit_db.sh init-memory
```

### 会话库损坏（audit_session.db）
```bash
# 会话库损坏影响范围仅限当前审计
# 如果 Phase-4 已有 exploits/*.json 输出，可安全重建
mv "$WORK_DIR/audit_session.db" "${WORK_DIR}/audit_session.db.corrupted"
bash tools/audit_db.sh init-session "$WORK_DIR"
# 注意: shared_findings 和 qc_records 会丢失，但 exploit 结果不受影响
```

### 预防
- `audit_db.sh` 已启用 WAL 模式（`PRAGMA journal_mode=WAL`），崩溃恢复能力强
- 避免在审计期间手动操作 .db 文件
- 磁盘空间不足时 SQLite 会静默失败 — 审计前确保 ≥ 500MB 可用空间

## 2. Phase-4 Auditor 崩溃/超时

### 症状
- Agent 无响应超过 10 分钟
- checkpoint.json 中 agent_states 显示 `status: "attacking"` 但无更新
- Docker 容器处于未知状态

### 恢复流程

```bash
# 1. 检查 Agent 状态
jq '.agent_states' "$WORK_DIR/checkpoint.json"

# 2. 回滚 Docker 快照（恢复到攻击前状态）
docker commit php_audit_target php_audit_snapshot_recovery
docker stop php_audit_target 2>/dev/null
docker rm php_audit_target 2>/dev/null
docker run -d --name php_audit_target php_audit_snapshot_pre_attack

# 3. 检查已有部分结果
ls -la "$WORK_DIR/exploits/${SINK_ID}_plan.json"  # 阶段 1 分析结果
ls -la "$WORK_DIR/exploits/${SINK_ID}.json"        # 阶段 2 攻击结果（可能不完整）

# 4. 更新 Agent 状态
jq --arg agent "$AGENT_NAME" \
   '.agent_states[$agent].status = "timeout" | .agent_states[$agent].error = "Agent 崩溃，已恢复快照"' \
   "$WORK_DIR/checkpoint.json" > /tmp/cp.json && mv /tmp/cp.json "$WORK_DIR/checkpoint.json"

# 5. 决策
# - 如果 _plan.json 存在 → 可重新 spawn Agent 仅执行阶段 2
# - 如果 _plan.json 不存在 → 需完全重新 spawn（从阶段 1 开始）
# - 如果已有部分 exploit 结果 → 标记 partial，继续下一个 Auditor
```

### 注意
- 每个 Auditor 最多重试 **2 次**（redo_count 上限）
- 连续 3 个 Auditor 崩溃 → 暂停审计，检查 Docker 环境健康状态
- 崩溃 Auditor 的部分结果标记 `"confidence": "low"` 保留

## 3. Token 预算溢出

### 症状
- Agent 输出被截断
- 质检员报告 "输出不完整"
- LLM 返回 "context length exceeded" 错误

### 恢复流程

**阶段 1 — 自动降级（agent_injection_framework.md 已定义）:**
1. 主调度器在注入前统计 L1 + L2 总行数
2. 超过预算 → 按文件行数从大到小，逐个将 L2 资源降级为 L3
3. 降级日志写入 `$WORK_DIR/.audit_state/injection_log.json`

**阶段 2 — 手动降级（自动降级仍不够时）:**
```bash
# 将最大的 L2 资源强制降级为 L3
# 降级优先顺序（从最大到最小）:
# 1. php_specific_patterns.md (568 行)
# 2. second_order.md (535 行)
# 3. attack_chains.md (492 行)
# 4. false_positive_patterns.md (475 行)

# 在 Agent prompt 中仅保留路径引用:
echo "--- 按需引用资源（L3）---
以下资源因 Token 预算限制未全文注入:
- ${SKILL_DIR}/shared/php_specific_patterns.md（568 行）
  摘要: PHP 特有安全模式库
"
```

**阶段 3 — 紧急模式（仍超预算）:**
- 仅注入 L1（3 个文件）+ 该 Auditor 的 .md 文件 + context_pack
- 在 checkpoint.json 标注 `"mode": "degraded"`
- 质检降低通过门槛（SHOULD-PASS 全部改为 WARN）

## 4. 并发审计冲突

### 症状
- 两个审计同时使用同一 Docker 容器
- attack_memory.db 写入冲突（SQLite WAL 可处理并发读，但并发写可能超时）

### 预防机制

```bash
# 审计启动时创建锁文件
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

### 全局记忆库并发
- `attack_memory.db` 使用 WAL 模式，支持多个读者 + 1 个写者
- `audit_db.sh` 设置 `.timeout 5000`（5 秒等待锁释放）
- 极端情况: 超过 5 秒锁等待 → 写入失败但不影响审计结果（记忆写入为 best-effort）

## 5. 磁盘空间不足

### 检测
```bash
# 审计前检查（建议在 Phase-1 执行）
AVAIL_MB=$(df -m "$WORK_DIR" | tail -1 | awk '{print $4}')
if [ "$AVAIL_MB" -lt 500 ]; then
    echo "⚠️ 磁盘空间不足: ${AVAIL_MB}MB（建议 ≥ 500MB）"
    echo "   Docker 镜像 + 快照 + 日志 + 数据库可能需要 200-500MB"
fi
```

### 恢复
```bash
# 清理不必要的 Docker 镜像
docker image prune -f
# 清理旧快照（保留最近 2 个）
docker images --format '{{.Repository}}:{{.Tag}}' | grep 'snapshot' | tail -n +3 | xargs -r docker rmi
# 压缩旧审计日志
gzip "$WORK_DIR"/*.log 2>/dev/null
```

## 约束

- 恢复操作不得修改已生成的 `exploits/*.json`（已确认的漏洞证据不可变）
- 所有恢复操作记录到 `$WORK_DIR/.audit_state/recovery_log.json`
- 恢复后必须重新执行当前 Phase 的 GATE 验证
