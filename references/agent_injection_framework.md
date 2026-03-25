# Agent 注入分层体系（Prompt 构建规范）

> 本文件由 SKILL.md 提取，主调度器通过引用加载。

### Section 12: Agent 注入分层体系

为控制每个 Agent 的 prompt token 用量，共享资源按注入优先级分为三个层级:

#### 注入层级定义

| 层级 | 名称 | 策略 | 说明 |
|------|------|------|------|
| **L1** | 必注入 (All Agents) | 全文注入到所有 Agent prompt | 核心规则，缺失会导致幻觉或格式错误 |
| **L2** | 按角色注入 (Role-based) | 仅注入给需要该资源的 Agent | 领域知识，按 Agent 职责选择性注入 |
| **L3** | 按需引用 (On-demand) | 仅注入文件路径 + 单行摘要，Agent 需要时自行 Read | 大型参考库，全文注入会超出 token 预算 |

#### L1 必注入资源（所有 Agent）

- `shared/anti_hallucination.md` — 反幻觉规则
- `shared/data_contracts.md` — JSON Schema 数据合约
- `shared/evidence_contract.md` — EVID_* 证据点字典（Phase-4 专家输出结论时的证据引用规范）

> **注**: `shared/sink_definitions.md` 已从 L1 降级为 L2，仅注入给需要 Sink 定义的 Agent（Phase-2 tool-runner/context-extractor/risk-classifier + Phase-4 专家）。这可节省约 25KB（~6000 tokens）的上下文空间，减少非相关 Agent 的注意力分散。

#### L2 按角色注入资源

| 资源文件 | 注入目标 Agent |
|----------|----------------|
| `shared/sink_definitions.md` | Phase-2 tool-runner, context-extractor, risk-classifier + 所有 Phase-4 专家 |
| `shared/php_specific_patterns.md` | 所有 Phase-4 专家 + Phase-2 context-extractor |
| `shared/attack_chains.md` | Phase-4.5 attack-graph-builder + correlation-engine |
| `shared/known_cves.md` | Phase-2 dep-scanner + 所有 Phase-4 专家 |
| `shared/payload_templates.md` | 所有 Phase-4 专家 |
| `shared/waf_bypass.md` | 所有 Phase-4 专家 |
| `shared/context_compression.md` | 所有 Phase-4 专家 |
| `shared/pivot_strategy.md` | 所有 Phase-4 专家 |
| `shared/attack_memory.md` | 所有 Phase-4 专家 |
| `shared/attack_memory_graph.md` | 所有 Phase-4 专家 + Phase-4.5 correlation-engine + attack-graph-builder |
| `shared/framework_patterns.md` | Phase-2 context-extractor/risk-classifier + Phase-4 专家 + Phase-4.5 remediation-generator |
| `shared/docker_snapshot.md` | Phase-4 专家（阶段 2 攻击时） |
| `shared/realtime_sharing.md` | Phase-4 专家 |
| `shared/second_order.md` | Phase-4 专家 + Phase-4.5 correlation-engine |
| `shared/false_positive_patterns.md` | 质检员 + Phase-4.5 correlation-engine |
| `shared/env_selfheal.md` | Phase-1 docker-builder |

> **环境条件化注入**: 当 `environment_status.json` 中检测到 WAF 时，`shared/waf_bypass.md` 从 L2 提升为 **L1.5**（强制全文注入给所有 Phase-4 专家，而非仅按需引用）。
> 当目标为 WordPress 时，`shared/known_cves.md` 中的 WordPress 相关章节全文注入给 wordpress_auditor，其余专家仍按 L3 引用。

#### L3 按需引用资源

以下资源**不全文注入**，仅在 Agent prompt 中注入路径和摘要。Agent 在需要时使用 Read 工具自行读取:

- `shared/lessons_learned.md` — 实战经验库（历史审计踩坑记录与解决方案）
- `teams/team4/mini_researcher.md` — 按需研究员 Agent（当 Auditor 遇到未知组件或连续失败需要新方向时，由主调度器委派 spawn）

**L3 注入模板**（写入 Agent prompt 的格式）:
```
--- 按需引用资源（L3）---
以下资源未全文注入，需要时使用 Read 工具读取:

- ${SKILL_DIR}/shared/lessons_learned.md
  摘要: 历史审计实战经验库，包含常见踩坑场景、误报/漏报案例、环境兼容性问题的解决方案。
  使用场景: 当你遇到异常行为、不确定的 Sink 判定、或攻击连续失败时，建议先查阅此文件获取参考。
```

#### Token 预算规则

每个 Agent 的 L1 + L2 注入内容（不含任务指令文件本身）须遵守以下行数上限:

| Agent 类型 | L1 + L2 行数上限 |
|------------|-------------------|
| Phase-4 专家 Agent | **<= 1500 行** |
| Phase-4.5 Agent | **<= 800 行** |
| Phase-2 Agent | **<= 500 行** |

**超预算自动降级规则**: 构建 Agent prompt 时，主调度器应在注入前统计 L1 + L2 总行数:
- 若超出该 Agent 类型的行数上限 → 打印警告:
  `"⚠️ Agent {name} 的 L1+L2 注入内容为 {actual} 行，超出预算 {limit} 行。自动将最大的 L2 资源降级为 L3（仅注入路径+摘要）。"`
- 降级顺序: 按文件行数从大到小，逐个将 L2 资源降级为 L3，直到总行数 <= 上限
- 降级后的资源按 L3 模板格式注入路径和摘要

