# Quality Check Dispatcher（质检调度协议）

> 本文件定义负责人（SKILL.md 主调度器）如何调度质检员池。嵌入到 SKILL.md 的调度逻辑中。

---

## 核心原则：完成一个、校验一个

每个 Agent 完成任务后，负责人**立即** spawn 一个质检员校验其输出。不等待同阶段其他 Agent。

## 质检员池管理

### 命名规则
- `quality-checker-1`, `quality-checker-2`, ..., `quality-checker-N`
- 序号全局递增，不重置

### 生命周期
```
Agent 完成 → 负责人检查有无空闲质检员 → 
  有 → 分配给空闲质检员
  无 → spawn 新质检员
→ 质检员校验 → 报告结果 → 
  通过 → 质检员标记为空闲，等待下一个任务
  不通过 → 负责人通知被校验 Agent 重做 → 重做后再次分配质检员
```

### 并发上限
- Phase 1/2/3: 最多 **3** 个质检员并发
- Phase 4（auditor 级别）: 最多 **5** 个质检员并发
- Phase 4.5/5: 最多 **2** 个质检员并发

### 回收策略
- 当前阶段所有校验完成后，关闭该阶段全部质检员
- 下一阶段按需重新 spawn

---

## 各阶段调度方案

### Phase 1 环境构建

```
docker_builder 完成 → spawn quality-checker-1
  校验模板: 阶段 1：环境构建校验
  输出文件: environment_status.json
  → 通过 → 关闭 quality-checker-1，写 GATE-1 checkpoint
  → 不通过 → 通知 docker_builder 按修复要求重做（最多 3 次）
```

### Phase 2 静态侦察

```
Team-2 全体 Agent 完成 → spawn quality-checker-1
  校验模板: 阶段 2：静态侦察校验
  输出文件: route_map.json, auth_matrix.json, ast_sinks.json, priority_queue.json, context_packs/, dep_risk.json
  → 通过 → 关闭 quality-checker-1，写 GATE-2 checkpoint
  → 不通过 → 通知对应 Agent 补充（根据不通过项定位责任 Agent）
```

**Phase 2 不通过项的责任映射:**
| 不通过项 | 责任 Agent |
|---------|-----------|
| route_map 相关 | route_mapper |
| auth_matrix 相关 | auth_auditor |
| ast_sinks 相关 | tool_runner (AST 扫描) |
| context_packs 相关 | context_builder |
| priority_queue 相关 | priority_ranker |
| dep_risk 相关 | dep_scanner |

### Phase 3 动态追踪

```
Team-3 全体 Agent 完成 → spawn quality-checker-1
  校验模板: 阶段 3：动态追踪校验
  输出文件: credentials.json, traces/*.json
  → 通过 → 关闭 quality-checker-1，写 GATE-3 checkpoint
  → 不通过 → 通知对应 Agent 补充
```

### Phase 4 漏洞利用（核心：Auditor 级别校验）

**阶段 1（分析阶段）完成后不校验，等攻击阶段完成才校验。**

```
每个 Auditor 的攻击阶段完成 → 分配给空闲质检员（或 spawn 新的）
  校验模板: 阶段 4：单个 Auditor 校验
  输出文件: exploits/{sink_id}.json（该 Auditor 的所有 exploit）
  → 通过 → 该 Auditor 关闭，质检员标记空闲
  → 不通过 → 通知该 Auditor 补充物证/修正（最多 2 次）

全部 Auditor 校验通过 → 分配一个质检员做综合校验
  校验模板: 阶段 4：物理取证综合校验
  输出文件: team4_progress.json + exploits/
  → 通过 → 写 GATE-4 checkpoint
  → 不通过 → 定位具体 Auditor 补充
```

**Phase 4 调度示例（假设 6 个 Auditor 被调度）:**
```
sqli_auditor 完成    → quality-checker-1 校验
rce_auditor 完成     → quality-checker-2 校验
xss_ssti_auditor 完成 → quality-checker-3 校验（或复用已空闲的 1/2）
lfi_auditor 完成     → quality-checker-4 校验
xxe_auditor 完成     → 复用空闲质检员
ssrf_auditor 完成    → 复用空闲质检员
全部通过             → 任一质检员做综合校验
```

### Phase 4.5 关联分析

```
Team-4.5 完成 → spawn quality-checker-1
  校验模板: 阶段 4.5：关联分析校验
  输出文件: attack_graph.json, correlation_report.json, patches/*.patch
  → 通过 → 写 GATE-4.5 checkpoint
  → 不通过 → 通知 correlation_engine/attack_graph_builder 补充
```

### Phase 5 报告生成

```
report_writer + sarif_exporter 完成 → spawn quality-checker-1
  校验模板: 阶段 5：报告生成校验
  输出文件: audit_report.md, audit_report.sarif.json, poc/*.py, poc/run_all.sh
  → 通过 → 质检员生成 quality_report.md → 流程结束
  → 不通过 → 通知 report_writer 修正（最多 2 轮）
```

---

## Agent 状态同步（checkpoint.json）

每次质检完成后，负责人（主调度器）必须同步更新 `checkpoint.json` 的 `agent_states`:

### 状态更新时机

| 事件 | agent_states 更新 |
|------|-------------------|
| Agent spawn | `{status: "spawned", spawned_at: now()}` |
| Stage-1 分析开始 | `{status: "analyzing"}` |
| Stage-2 攻击开始 | `{status: "attacking"}` |
| Agent 完成输出 | `{status: "completed", completed_at: now()}` |
| QC verdict=pass | `{status: "passed", qc_verdict: "pass"}` |
| QC verdict=fail | `{status: "failed", qc_verdict: "fail", redo_count: +1}` |
| Agent 重做完成 | `{status: "completed"}` (等待再次 QC) |
| Agent 超时 | `{status: "timeout", completed_at: now()}` |
| Pivot 触发 | `{pivot_triggered: true, pivot_target: "..."}` |

### 同步命令

```bash
# 更新单个 agent 状态（由主调度器在每个状态转换点执行）
jq --arg agent "$AGENT_NAME" --arg status "$NEW_STATUS" \
  '.agent_states[$agent].status = $status' \
  "$WORK_DIR/checkpoint.json" > "$WORK_DIR/checkpoint.json.tmp" && \
  mv "$WORK_DIR/checkpoint.json.tmp" "$WORK_DIR/checkpoint.json"
```

### GATE 失败时的状态查询

```bash
# 查询所有非 passed 状态的 agent（用于 GATE FAIL 诊断）
jq '.agent_states | to_entries[] | select(.value.status != "passed") | {agent: .key, status: .value.status, redo: .value.redo_count}' "$WORK_DIR/checkpoint.json"
```

---

## 重做闭环

### 重做次数追踪
每个被校验 Agent 的重做次数记录在 SQLite 中：
```bash
bash tools/audit_db.sh qc-write "$WORK_DIR" '{"agent":"xxx", "redo_count": N, ...}'
```

### 重做上限
| 阶段 | 最大重做次数 | 超限处理 |
|------|:----------:|---------|
| Phase 1 | 3 | 降级为 partial 模式 |
| Phase 2 | 2 | 标记降级，用已有数据继续 |
| Phase 3 | 2 | 断链路由退回 context_pack |
| Phase 4 (单个 Auditor) | 2 | 标注物证不足，降级可信度 |
| Phase 4.5 | 1 | 用 team4_progress.json 直接进报告 |
| Phase 5 | 2 | 强制生成（标注 WARN） |

### 重做信息传递
不通过时，负责人将以下信息发送给被校验 Agent：
```
你的输出未通过质检。以下是不通过项和修复要求：

[粘贴质检员的 failed_items 列表]

请按照修复要求逐项补充后重新提交。
```

---

## 最终质量报告生成

全部阶段校验通过后，负责人将生成任务分配给最后一个质检员：

1. 读取 `references/quality_check_templates.md` 末尾的「最终质量报告模板」
2. 从 SQLite 读取所有 QC 记录：
   ```bash
   bash tools/audit_db.sh qc-read "$WORK_DIR"
   ```
3. 整合所有阶段校验结果
4. 生成 `$WORK_DIR/quality_report.md`
5. 关闭所有质检员，完成整个审计流程
