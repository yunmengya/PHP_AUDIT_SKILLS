# 实时发现共享协议（Realtime Finding Sharing Protocol）

本文件定义 Phase-4 审计员之间的实时信息共享规范。所有审计员在发现可供其他审计员利用的关键信息时，必须写入共享发现数据库。

---

## 共享数据库

`$WORK_DIR/audit_session.db` → `shared_findings` 表（SQLite，WAL 模式，支持并发读写）。

初始化（Phase-4 启动时自动执行，幂等操作）:
```bash
bash tools/audit_db.sh init-session "$WORK_DIR"
```

## 写入规则

### 何时写入

审计员在以下情况下**必须**写入共享发现:

1. **发现有效凭证**: 数据库密码、API 密钥、JWT Secret、Token、Session Cookie
2. **发现内网地址**: 内部 IP、内部 API 端点、服务端口
3. **发现密钥材料**: APP_KEY、加密密钥、HMAC Secret、私钥
4. **发现可利用端点**: 无鉴权管理端点、调试端点、文件上传端点
5. **确认绕过方法**: WAF 绕过技巧、编码方式、HTTP 方法绕过

### 写入命令

```bash
bash tools/audit_db.sh finding-write "$WORK_DIR" '{
  "source_agent": "infoleak-auditor",
  "finding_type": "secret_key",
  "priority": "critical",
  "data": {
    "key": "JWT_SECRET",
    "value": "super_secret_key_123",
    "context": "从 .env 文件泄露获取",
    "source_location": "GET /.env"
  },
  "target_agents": ["authz-auditor", "crypto-auditor"]
}'
```

**优势**: 内置 UNIQUE 约束自动去重（相同 source_agent + finding_type + data_key + data_value 不会重复插入），无需手动判重。

### 写入格式

| 字段 | 类型 | 说明 |
|------|------|------|
| source_agent | TEXT | 写入方 Agent 名 |
| finding_type | TEXT | credential/internal_url/secret_key/endpoint/bypass_method/config_value |
| priority | TEXT | critical/high/medium |
| data.key | TEXT | 发现的名称/标识 |
| data.value | TEXT | 发现的值 |
| data.context | TEXT | 上下文描述 |
| data.source_location | TEXT | 来源: file:line 或 HTTP 端点 |
| target_agents | JSON数组 | 建议的消费方 Agent 名 |

## 读取规则

### 何时读取

审计员在以下时机读取共享发现:

1. **攻击阶段开始前**: 检查是否有其他审计员提供的凭证/密钥可直接利用
2. **每轮攻击失败后**: 检查是否有新的绕过方法或内部端点可尝试
3. **组合链构建时(R8)**: 获取所有跨审计员发现用于链式利用

### 读取命令

```bash
# 读取所有发现（按 critical → high → medium 排序）
bash tools/audit_db.sh finding-read "$WORK_DIR"

# 仅读取特定类型
bash tools/audit_db.sh finding-read "$WORK_DIR" credential

# 仅读取本 agent 未消费的发现
bash tools/audit_db.sh finding-read "$WORK_DIR" "" sqli-auditor
```

返回 JSON 数组，可直接用 `jq` 解析:

```bash
# 示例: 提取所有未消费的凭证
bash tools/audit_db.sh finding-read "$WORK_DIR" credential sqli-auditor \
  | jq -r '.[] | "\(.data_key)=\(.data_value)"'
```

### 消费标记

消费方读取发现后，标记已消费:

```bash
bash tools/audit_db.sh finding-consume "$WORK_DIR" 1 authz-auditor
# 参数: WORK_DIR, finding_id, agent_name
```

### 消费方行为

| finding_type | 消费方 | 行为 |
|---|---|---|
| credential (DB密码) | sqli-auditor | 尝试直接数据库连接验证 |
| credential (API密钥) | infoleak-auditor | 验证密钥是否活跃、权限范围 |
| secret_key (JWT_SECRET) | authz-auditor | 用于 JWT Token 伪造 (R5) |
| secret_key (APP_KEY) | config-auditor | 用于 Cookie 解密/签名 URL 伪造 (R8) |
| internal_url | ssrf-auditor | 添加到 SSRF 目标列表 |
| internal_url (Redis) | nosql-auditor | 尝试 Redis 命令注入 |
| endpoint (admin) | authz-auditor | 添加到越权测试端点列表 |
| bypass_method | 所有审计员 | 在失败轮次中应用绕过技巧 |
| config_value | crypto-auditor | 用于密码学分析 |

## 并发安全

SQLite WAL 模式天然支持并发:
- **多个 reader 同时读取**: 无需任何锁，不阻塞
- **单 writer 写入时不阻塞 reader**: WAL 提供快照隔离
- **写入冲突**: SQLite 自动重试（5 秒超时），对审计场景完全够用
- **ACID 事务**: 每次写入都是原子的，不会出现半写入行

无需 `flock` 文件锁。

## 统计

```bash
# 查看当前审计的发现统计
bash tools/audit_db.sh finding-stats "$WORK_DIR"
```

输出示例:
```
=== 共享发现统计 ===
总发现: 12
  critical: 3
  high: 5
  medium: 4
---
按类型:
  credential: 4
  secret_key: 3
  internal_url: 3
  bypass_method: 2
---
按来源:
  infoleak-auditor: 5
  config-auditor: 3
  ssrf-auditor: 2
  sqli-auditor: 2
---
未消费: 4
```

## 从 JSONL 迁移

如果审计过程中需要迁移已有的 JSONL 数据:

```bash
bash tools/audit_db.sh migrate-findings "$WORK_DIR"
```

## 图记忆节点桥接

当审计员写入高置信度图节点（`status = "confirmed"`）时，应**同时**写入共享发现，使其他审计员能在实时共享中感知关联漏洞:

```bash
# 写入图节点后，同步写入共享发现
bash tools/audit_db.sh finding-write "$WORK_DIR" '{
  "source_agent": "{当前 auditor 名}",
  "finding_type": "endpoint",
  "priority": "high",
  "data_key": "graph_node_{sink_id}",
  "data_value": "{vuln_type}: {summary}",
  "data_context": "关系型图节点 confirmed — data_object={data_object}, severity={severity}",
  "source_location": "{route}",
  "target_agents": ["correlation_engine", "相关 auditor"]
}'
```

**桥接条件**（满足全部才桥接）:
- 图节点 `status = "confirmed"`（不桥接 suspected/speculative）
- 图节点 `data_object` 非空（有明确的数据对象关联）
- 该 data_object 尚未被其他审计员在 shared_findings 中报告过

**目的**: 确保关系型图记忆（全局持久化 `attack_memory.db`）与会话级实时共享（`audit_session.db`）双向互通，不存在信息孤岛。

## 约束

- 写入的值必须是**实际获取到的数据**，禁止推测
- 敏感凭证在报告中脱敏（仅在 audit_session.db 中保留原文供审计使用）
- audit_session.db 在 Phase-5 清理时由 env-cleaner 安全删除（`shred` 或 `dd` 覆写后 `rm`）
