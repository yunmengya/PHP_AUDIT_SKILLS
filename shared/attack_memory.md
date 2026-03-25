# 攻击记忆系统（Attack Memory System）

Phase-4 专家 Agent 的跨审计经验复用机制。通过结构化记录每次攻击的成功/失败经验，使后续审计能够复用历史知识，提高首轮命中率，减少无效尝试。

---

## 设计原理

借鉴 PentAGI 的 Smart Memory System 思路，使用 SQLite 数据库提供 ACID 事务和索引查询（零安装，macOS/PHP/Python 均内置）：

- **写入时机**: 每个 Phase-4 专家完成攻击后，将经验写入记忆库
- **读取时机**: Phase-4 专家启动攻击阶段前，查询匹配的历史记忆
- **匹配维度**: `sink_type + framework + PHP版本段 + WAF类型`
- **存储位置**: `${HOME}/.php_audit/attack_memory.db`（SQLite，跨项目持久化）
- **工具脚本**: `tools/audit_db.sh`（封装所有数据库操作）

## 初始化

首次审计前自动初始化（幂等操作）:

```bash
bash tools/audit_db.sh init-memory
```

创建 `attack_memory` 表，含索引 `(sink_type, framework, status)` 和 `(sink_type, php_version)`。

## 记忆数据结构

Schema 参见 `schemas/attack_memory_entry.schema.json`，SQLite 表字段与之一一对应:

| 字段 | 类型 | 说明 |
|------|------|------|
| sink_type | TEXT | rce/sqli/xss/ssrf/lfi/... |
| sink_function | TEXT | system/eval/query/... |
| framework | TEXT | Laravel/ThinkPHP/WordPress/... |
| php_version | TEXT | 8.1.27 |
| waf_type | TEXT | none/ModSecurity/Cloudflare |
| status | TEXT | confirmed/failed/partial |
| rounds_used | INTEGER | 实际使用轮次 |
| successful_round | INTEGER | 成功轮次（仅 confirmed） |
| successful_payload_type | TEXT | 策略类型 |
| bypass_technique | TEXT | 绕过手法 |
| eliminated_strategies | TEXT | JSON 数组，已排除的策略 |
| failure_reason | TEXT | 失败原因分类 |

## 写入协议（攻击完成后）

每个 Phase-4 专家在完成所有攻击轮次后，**必须**执行以下写入流程:

### 1. 写入记忆

从攻击结果和环境信息构建 JSON 并写入:

```bash
# 使用 audit_db.sh 写入（内置事务保护，无需 flock）
bash tools/audit_db.sh memory-write '{
  "sink_type":"rce",
  "sink_function":"system",
  "framework":"Laravel",
  "php_version":"8.1.27",
  "waf_type":"none",
  "status":"confirmed",
  "rounds_used":3,
  "successful_round":3,
  "successful_payload_type":"IFS_substitution",
  "successful_payload_summary":"$IFS替代空格绕过参数过滤",
  "bypass_technique":"IFS_substitution",
  "eliminated_strategies":["basic_separators","url_encoding"]
}'
```

### 2. 写入条件

| 攻击结果 | 记录内容 | 目的 |
|---------|---------|------|
| ✅ confirmed | 成功的 payload 类型 + 绕过手法 + 成功轮次 | 下次优先使用 |
| ❌ failed (max_rounds) | 所有已排除策略 + 失败原因 | 下次直接跳过 |
| ⚠️ partial | 部分成功的策略 + 阻塞原因 | 下次参考调整 |
| ❌ failed (< 3 轮) | **不记录** | 数据量不足，不具参考价值 |

### 3. 脱敏要求

- Payload 中的具体 URL、路径、IP 替换为占位符
- 不记录 credentials.json 中的凭证信息
- 不记录具体的项目名称或业务数据

## 读取协议（攻击开始前）

Phase-4 专家在**阶段 2（攻击阶段）**启动时，按以下流程查询历史记忆:

### 1. 匹配查询

```bash
# 精确查询: sink_type + framework + PHP大版本 + WAF
bash tools/audit_db.sh memory-query rce Laravel 8 none

# 宽松查询: 仅 sink_type + framework
bash tools/audit_db.sh memory-query rce Laravel

# 最宽松: 仅 sink_type
bash tools/audit_db.sh memory-query rce
```

返回 JSON 数组，按 confirmed → partial → failed 排序，最多 20 条。

### 2. 匹配优先级

| 匹配级别 | 条件 | 权重 |
|---------|------|------|
| 精确匹配 | sink_type + framework + PHP版本段 + WAF类型 全部一致 | ⭐⭐⭐ |
| 高度匹配 | sink_type + framework + PHP版本段 一致 | ⭐⭐ |
| 部分匹配 | sink_type + PHP版本段 一致 | ⭐ |
| 不匹配 | 仅 sink_type 一致 | 仅作参考 |

### 3. 应用策略

根据匹配到的历史记录调整攻击计划:

**有 confirmed 记录**:
```
历史匹配: Laravel + RCE + PHP8.x → R3 使用 $IFS 替代成功
调整: 将 $IFS 策略从 R3 提前到 R1，跳过基础分隔符测试
预期: 首轮即命中，节省 2 轮
```

**有 failed 记录**:
```
历史匹配: Laravel + SQLi + PHP8.x + ModSecurity → 8轮全败，原因=framework_filter
调整: 已排除策略 [union, boolean_blind, error_based, ...] 不再尝试
      直接从 R1 尝试非常规路径（second_order / JSON 注入 / 子查询）
预期: 避免重复浪费 5+ 轮
```

**无匹配记录**:
```
无历史数据，按默认轮次顺序执行
```

### 4. 记忆注入格式

查询结果注入到专家 Agent prompt 中的格式:

```
## 历史攻击记忆（自动检索）

匹配到 {n} 条相关记录:

✅ 成功记录 (优先参考):
- [Laravel+RCE+PHP8.x] R3 使用 IFS_substitution 成功，绕过手法: $IFS替代空格
- [Laravel+RCE+PHP7.4] R5 使用 LD_PRELOAD+mail() 成功

❌ 失败记录 (避免重复):
- [Laravel+SQLi+PHP8.x+ModSecurity] 8轮全败，已排除: union/boolean_blind/error_based/stacked/time_blind
  失败原因: Eloquent ORM 的参数绑定无法绕过

建议调整:
- R1 优先尝试: IFS_substitution (历史成功率 100%)
- 跳过策略: basic_separators, url_encoding (历史成功率 0%)
```

## 记忆维护

### 容量控制

```bash
# 自动维护: 超过 1000 条时保留 confirmed + 最近 500 条
bash tools/audit_db.sh memory-maintain
```

### 统计概览

```bash
# 查看记忆库统计
bash tools/audit_db.sh memory-stats
```

### 初始化

首次审计时，记忆库不存在，`init-memory` 自动创建。所有专家按默认轮次顺序执行。记忆系统**零配置启动**，随使用自动积累。

### 从 JSONL 迁移

如果已有历史 JSONL 记忆文件，可一键迁移:

```bash
bash tools/audit_db.sh migrate-memory
# 默认读取 ~/.php_audit/attack_memory.jsonl → 写入 attack_memory.db
```

## 与其他系统的关系

| 系统 | 关系 |
|------|------|
| `lessons_learned.md` | 人工可读的经验总结（文本），记忆系统是机器可读的结构化数据（SQLite） |
| `context_compression.md` | 单次审计内的上下文管理，记忆系统是跨审计的经验复用 |
| `audit_session.db` → `shared_findings` | 单次审计内的实时发现共享（同为 SQLite），记忆系统跨项目持久化 |
| `payload_templates.md` | 静态 payload 库，记忆系统记录哪些 payload 在什么条件下有效/无效 |

---

## 关系型记忆扩展（Graph Layer）

> 详见 `shared/attack_memory_graph.md` — 完整的实体-关系图模型定义。

在上述平面记忆（`attack_memory` 表）的基础上，同一个 `attack_memory.db` 文件中增加两张图表（`memory_nodes` + `memory_edges`），记录漏洞之间的语义关系。

### 扩展写入规则

每个 Phase-4 专家在执行 **写入协议** 时，**必须同时**执行以下关系型写入：

#### 规则 GW-1: 攻击完成后写入节点

在写入 `attack_memory` 表（平面记录）的同时，写入 `memory_nodes` 表：

```bash
# 平面记忆写入（已有流程，不变）
bash tools/audit_db.sh memory-write '{...}'

# 关系型记忆写入（新增，必须紧跟平面写入）
bash tools/audit_db.sh graph-node-write '{
  "node_id": "{project_hash}_{sink_id}",
  "vuln_type": "{sink_type}",
  "sink_id": "{sink_id}",
  "route": "{攻击的路由路径}",
  "severity": "{三维评分后的等级}",
  "status": "{confirmed/failed/partial}",
  "framework": "{framework}",
  "data_object": "{涉及的数据对象，如 users 表/session/cookie}",
  "summary": "{一句话攻击结果摘要}"
}'
```

**data_object 识别规则**：
- SQL 类漏洞 → 涉及的表名（如 `users`, `orders`）
- 文件类漏洞 → 涉及的文件路径模式（如 `/uploads/*`, `/config/.env`）
- Session 类漏洞 → `session`
- 认证类漏洞 → `auth_token` 或 `credentials`
- 配置类漏洞 → `config`

#### 规则 GW-2: 发现跨 Sink 关系时写入边

当 Auditor 在分析或攻击过程中发现与其他 Sink 的关联时，写入 `memory_edges` 表：

**触发条件**（满足任一即写入边）：
1. 当前 Sink 的输出数据可作为另一个 Sink 的输入 → `data_flows_to`
2. 当前 Sink 的利用需要另一个漏洞先成功 → `enables`（反向写入）
3. 当前 Sink 与另一个 Sink 操作同一数据表/文件 → `shares_data_object`
4. 当前 Sink 与另一个 Sink 共享同一入口路由 → `same_entry_point`
5. 从 `shared_findings` 表中发现已确认的相关漏洞 → 评估是否构成 `escalates_to`

```bash
bash tools/audit_db.sh graph-edge-write '{
  "source_node": "{project_hash}_{当前sink_id}",
  "target_node": "{project_hash}_{关联sink_id}",
  "relation": "{关系类型}",
  "confidence": "{confirmed/probable/speculative}",
  "evidence": "{关系证据：具体描述数据如何流动/为何构成升级}"
}'
```

**confidence 判定标准**：
- `confirmed`: 已通过 PoC 验证的关系（如实际注入数据在另一端点被渲染）
- `probable`: 代码分析确认数据流存在，但未实际验证
- `speculative`: 基于模式推测（如同表操作但未确认具体字段关联）

#### 规则 GW-3: 不写入条件

以下情况**不写入**关系型记忆（与平面记忆的不写入条件一致）：
- 攻击轮次 < 3 轮就失败（数据量不足）
- 仅为 `speculative` 且无任何代码级证据
- data_object 无法确定（不要猜测）

### 扩展读取规则

Phase-4 专家在攻击阶段 2 启动时，除了查询平面记忆外，**额外**查询关系图：

```bash
# 平面记忆查询（已有流程，不变）
bash tools/audit_db.sh memory-query {sink_type} {framework}

# 关系图查询（新增）— 查询当前 Sink 涉及的数据对象的完整攻击面
bash tools/audit_db.sh graph-by-data-object "{data_object}"
```

**注入格式**（追加在现有"历史攻击记忆"之后）：

```
## 关联漏洞情报（图记忆）

涉及数据对象 "{data_object}" 的已知漏洞:
- [SQLi → users 表] sink_023: ORDER BY 注入(confirmed) — 可读取任意字段
- [XSS → users 表] sink_045: 模板渲染 users.bio(suspected) — 未转义输出

关系链:
- sink_023 --[data_flows_to]--> sink_045: SQLi 写入 bio 字段 → XSS 渲染 bio 字段
  → 组合利用可升级为 Stored XSS (High)

建议: 优先验证 data_flows_to 关系链，若 source 已 confirmed 则 target 成功率大幅提升。
```
