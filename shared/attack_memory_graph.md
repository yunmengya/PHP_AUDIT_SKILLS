# 关系型攻击记忆（Attack Memory Graph）

在 `attack_memory.md` 的平面记录基础上，增加实体关系型记忆层，记录漏洞之间的**语义关系**，使 correlation_engine 和后续审计能发现跨 Sink 的攻击链。

---

## 设计原理

借鉴 PentAGI 的 Graphiti 知识图谱思路，使用 SQLite 关系表模拟图结构（零依赖，无需 Neo4j）:

- **节点（Node）**: 每个发现的漏洞/弱点/配置问题
- **边（Edge）**: 漏洞之间的利用关系（数据流、权限提升、组合攻击）
- **属性（Property）**: 节点和边的元数据（严重度、可达性、前置条件）

## 数据结构

### 节点表: `memory_nodes`

```sql
CREATE TABLE IF NOT EXISTS memory_nodes (
    node_id     TEXT PRIMARY KEY,     -- 格式: {project_hash}_{sink_id}
    vuln_type   TEXT NOT NULL,        -- sqli/rce/xss/ssrf/lfi/authz/config/...
    sink_id     TEXT NOT NULL,        -- 对应的 sink_id
    route       TEXT,                 -- 关联路由路径
    severity    TEXT,                 -- critical/high/medium/low/info
    status      TEXT,                 -- confirmed/suspected/potential
    framework   TEXT,                 -- Laravel/ThinkPHP/...
    data_object TEXT,                 -- 涉及的数据对象（如 users 表, session cookie）
    summary     TEXT,                 -- 一句话描述
    created_at  TEXT DEFAULT (datetime('now'))
);
CREATE INDEX idx_nodes_type ON memory_nodes(vuln_type);
CREATE INDEX idx_nodes_data ON memory_nodes(data_object);
```

### 边表: `memory_edges`

```sql
CREATE TABLE IF NOT EXISTS memory_edges (
    edge_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    source_node TEXT NOT NULL REFERENCES memory_nodes(node_id),
    target_node TEXT NOT NULL REFERENCES memory_nodes(node_id),
    relation    TEXT NOT NULL,         -- 关系类型（见下方枚举）
    direction   TEXT DEFAULT 'forward', -- forward/bidirectional
    confidence  TEXT DEFAULT 'probable', -- confirmed/probable/speculative
    evidence    TEXT,                  -- 关系证据描述
    combined_severity TEXT,           -- 组合后的严重度（升级后）
    created_at  TEXT DEFAULT (datetime('now')),
    UNIQUE(source_node, target_node, relation)
);
CREATE INDEX idx_edges_relation ON memory_edges(relation);
CREATE INDEX idx_edges_source ON memory_edges(source_node);
```

### 关系类型枚举

| relation 值 | 含义 | 示例 |
|-------------|------|------|
| `data_flows_to` | A 的输出数据流入 B 的输入 | SQLi 写入 DB → Stored XSS 读取 DB |
| `enables` | A 的利用是 B 的前置条件 | Config 泄露 .env → 获取密钥 → 伪造 Token |
| `escalates_to` | A + B 组合后严重度升级 | SSRF(Medium) + Docker API(Info) → Host RCE(Critical) |
| `shares_data_object` | A 和 B 操作同一数据对象 | 注册 Mass Assignment + 导出 IDOR 共享 users 表 |
| `same_entry_point` | A 和 B 共享同一入口路由 | 同一端点同时存在 SQLi 和 XSS |
| `auth_chain` | A 的认证绕过使 B 可达 | Auth Bypass → 访问管理面板 → RCE |
| `pivot_from` | A 失败后 pivot 到 B | RCE disable_functions → 反序列化 RCE |

## 写入协议

### 时机 1: Phase-4 Auditor 攻击完成后

每个 Auditor 在写入 `attack_memory.db` 的同时，写入节点:

```bash
bash tools/audit_db.sh graph-node-write '{
  "node_id": "a1b2c3_sink_012",
  "vuln_type": "sqli",
  "sink_id": "sink_012",
  "route": "/api/users?sort=",
  "severity": "high",
  "status": "confirmed",
  "framework": "Laravel",
  "data_object": "users",
  "summary": "ORDER BY 注入，可 UNION SELECT 读取任意表"
}'
```

### 时机 2: Phase-4 Auditor 发现跨 Sink 关系时

当 Auditor 在分析或攻击中发现与其他 Sink 的关联时，写入边:

```bash
bash tools/audit_db.sh graph-edge-write '{
  "source_node": "a1b2c3_sink_012",
  "target_node": "a1b2c3_sink_045",
  "relation": "data_flows_to",
  "confidence": "probable",
  "evidence": "sink_012 的 SQLi 可写入 users.bio 字段，sink_045 的模板渲染未转义读取 users.bio"
}'
```

### 时机 3: Phase-4.5 Correlation Engine 关联分析后

Correlation Engine 在执行跨审计员关联时，将发现的攻击链写入:

```bash
bash tools/audit_db.sh graph-edge-write '{
  "source_node": "a1b2c3_sink_012",
  "target_node": "a1b2c3_sink_045",
  "relation": "escalates_to",
  "confidence": "confirmed",
  "evidence": "SQLi(High) + SSTI(Medium) 组合 → RCE(Critical)，已通过 PoC 验证",
  "combined_severity": "critical"
}'
```

## 读取协议

### 查询 1: 获取某个节点的所有关联（供 Auditor 参考）

```bash
# 查询与 sink_012 关联的所有节点和边
bash tools/audit_db.sh graph-neighbors "a1b2c3_sink_012"
```

返回: 该节点的所有入边和出边 + 关联节点摘要

### 查询 2: 获取某个数据对象的完整攻击面（供 Correlation Engine 使用）

```bash
# 查询操作 users 表的所有漏洞节点
bash tools/audit_db.sh graph-by-data-object "users"
```

返回: 所有 `data_object = "users"` 的节点 + 它们之间的边

### 查询 3: 获取完整攻击图（供 Report Writer 使用）

```bash
# 导出完整图结构为 JSON
bash tools/audit_db.sh graph-export "$WORK_DIR"
```

返回: 全部节点 + 全部边的 JSON，用于生成攻击图谱可视化

## 与现有系统的集成

| 系统 | 集成方式 |
|------|----------|
| `attack_memory.md` (平面记忆) | 图节点是平面记录的扩展，每个 confirmed/failed 记录同时生成节点 |
| `correlation_engine.md` | Step 2/3 执行完毕后，将 escalations 和 second_order 结果写入图的边 |
| `attack_graph_builder.md` | 读取图的 `escalates_to` 和 `auth_chain` 边，直接用于攻击图谱构建 |
| `shared_findings` (SQLite) | 单次审计内的实时共享，图记忆是持久化的跨审计关系 |
| `report_writer.md` | 读取 graph-export 生成"漏洞关系图"章节 |

## 约束

- 节点 ID 必须包含项目 hash 前缀，避免跨项目冲突
- 边的 confidence 必须有 evidence 支撑，不得凭空推测关系
- `combined_severity` 仅在 `escalates_to` 关系中填写
- 图记忆与平面记忆（attack_memory 表）共存于同一 SQLite 文件 `attack_memory.db`
- 容量控制: 节点超过 5000 条时，按 created_at 清理最老的 speculative 节点
