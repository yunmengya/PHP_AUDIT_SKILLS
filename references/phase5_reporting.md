# Phase 5：清理与报告生成（详细流程）

> 本文件由 SKILL.md 提取，主调度器通过引用加载。

### Phase-5: 清理与报告

── 并行 step ──

同时 spawn 三个 Agent（background 模式）:

  Agent(name="env-cleaner", team_name="php-audit", run_in_background=true, mode="bypassPermissions", subagent_type="general-purpose")
    → prompt: Task #N+1 指令 + teams/team5/env_cleaner.md + 共享资源 + WORK_DIR

  Agent(name="report-writer", team_name="php-audit", run_in_background=true, mode="bypassPermissions", subagent_type="general-purpose")
    → prompt: Task #N+2 指令 + teams/team5/report_writer.md + 共享资源 + TARGET_PATH + WORK_DIR

  Agent(name="sarif-exporter", team_name="php-audit", run_in_background=true, mode="bypassPermissions", subagent_type="general-purpose")
    → prompt: Task #N+3 指令 + teams/team5/sarif_exporter.md + 共享资源 + WORK_DIR

等待三者全部完成
── 串行 step ──

  Agent(name="quality-checker-final", team_name="php-audit", foreground, mode="bypassPermissions", subagent_type="general-purpose")
    → prompt: teams/qc/quality_checker.md
            + references/quality_check_templates.md（阶段 5：报告生成校验 + 最终质量报告模板）
            + shared/output_standard.md + shared/data_contracts.md + shared/evidence_contract.md
            + PHASE=5, TARGET_AGENT=team5, OUTPUT_FILES=audit_report.md,audit_report.sarif.json,poc/,poc/run_all.sh
            + WORK_DIR

完成
解析质检结果:
  - verdict=fail → 发回 report-writer 修正（最多 2 轮）
  - verdict=pass → 质检员生成 $WORK_DIR/quality_report.md（使用最终质量报告模板）

写入 checkpoint.json: {"completed": ["env", "scan", "trace", "exploit", "report"], "current": "done"}
打印最终流水线视图

#### Step 6.4: 累积流水线视图

每个 Phase 完成后打印完整流水线视图，详见 `references/pipeline_view.md`。

状态标记: ✅=完成 | ⚠️=降级 | ❌=失败 | ⏳=等待 | 🔄=跳过

#### Step 6.5: Agent 生命周期管理与团队清理

**Agent 关闭协议**: 每个 Agent 通过 QC 校验后，主调度器发送 shutdown_request 优雅关闭:

```
对于每个已完成的 Agent（按 Phase 顺序）:
  SendMessage(to="{agent-name}", message={type: "shutdown_request", reason: "任务完成，QC 已通过"})
  等待 shutdown_response（最多 30 秒）
  若超时未响应 → 记录警告并继续（不阻塞后续流程）
```

**关闭顺序**:
- 每个 Phase 的质检员通过后，关闭该 Phase 的所有 Agent
- 最终质检员（quality-checker-final）通过后，关闭剩余所有 Agent
- 最后执行 TeamDelete()

```
遍历所有仍活跃的 teammate，逐个发送 shutdown_request
等待所有 shutdown_response 或超时
TeamDelete()
```

**tmux 清理（保底逻辑）**: 框架应自动回收 Agent pane，但实践中 idle Agent 进程可能未退出导致 pane 残留。TeamDelete 后执行以下保底清理:

```bash
# 查找并关闭所有 Claude Code Agent Teams 创建的残留 pane
# 仅保留当前主 pane（pane index 0）
CURRENT_PANE=$(tmux display-message -p '#{pane_id}' 2>/dev/null)
if [ -n "$CURRENT_PANE" ]; then
  tmux list-panes -F '#{pane_id}' 2>/dev/null | while read pane; do
    [ "$pane" != "$CURRENT_PANE" ] && tmux kill-pane -t "$pane" 2>/dev/null
  done
  echo "tmux 残留 pane 已清理"
fi
```

```
告知用户: "审计完成！报告文件: $WORK_DIR/audit_report.md"
```
