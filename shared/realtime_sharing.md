# 实时发现共享协议（Realtime Finding Sharing Protocol）

本文件定义 Phase-4 审计员之间的实时信息共享规范。所有审计员在发现可供其他审计员利用的关键信息时，必须追加写入共享发现文件。

---

## 共享文件

`$WORK_DIR/shared_findings.jsonl` — JSON Lines 格式，每行一条发现。

## 写入规则

### 何时写入

审计员在以下情况下**必须**写入 shared_findings.jsonl:

1. **发现有效凭证**: 数据库密码、API 密钥、JWT Secret、Token、Session Cookie
2. **发现内网地址**: 内部 IP、内部 API 端点、服务端口
3. **发现密钥材料**: APP_KEY、加密密钥、HMAC Secret、私钥
4. **发现可利用端点**: 无鉴权管理端点、调试端点、文件上传端点
5. **确认绕过方法**: WAF 绕过技巧、编码方式、HTTP 方法绕过

### 写入格式

```json
{
  "timestamp": "ISO-8601",
  "source_agent": "string (写入方 Agent 名，如 infoleak-auditor)",
  "finding_type": "string (credential|internal_url|secret_key|endpoint|bypass_method|config_value)",
  "priority": "string (critical|high|medium)",
  "data": {
    "key": "string (发现的名称/标识)",
    "value": "string (发现的值)",
    "context": "string (发现的上下文描述)",
    "source_location": "string (发现来源: 文件路径:行号 或 HTTP 端点)"
  },
  "target_agents": ["string (建议的消费方 Agent 名)"],
  "consumed_by": []
}
```

### 示例

```jsonl
{"timestamp":"2024-01-15T10:30:00Z","source_agent":"infoleak-auditor","finding_type":"secret_key","priority":"critical","data":{"key":"JWT_SECRET","value":"super_secret_key_123","context":"从 .env 文件泄露获取","source_location":"GET /.env"},"target_agents":["authz-auditor","crypto-auditor"],"consumed_by":[]}
{"timestamp":"2024-01-15T10:31:00Z","source_agent":"config-auditor","finding_type":"credential","priority":"critical","data":{"key":"DB_PASSWORD","value":"prod_db_pass","context":"phpinfo() 环境变量暴露","source_location":"GET /phpinfo.php"},"target_agents":["sqli-auditor","infoleak-auditor"],"consumed_by":[]}
{"timestamp":"2024-01-15T10:32:00Z","source_agent":"ssrf-auditor","finding_type":"internal_url","priority":"high","data":{"key":"REDIS_HOST","value":"redis://10.0.0.5:6379","context":"SSRF 探测发现内部 Redis","source_location":"POST /api/fetch?url=http://10.0.0.5:6379"},"target_agents":["nosql-auditor"],"consumed_by":[]}
{"timestamp":"2024-01-15T10:33:00Z","source_agent":"infoleak-auditor","finding_type":"bypass_method","priority":"medium","data":{"key":"WAF_BYPASS","value":"双重URL编码可绕过 ModSecurity SQLi 规则","context":"测试中发现的绕过方法","source_location":"POST /api/search"},"target_agents":["sqli-auditor","xss-auditor","rce-auditor"],"consumed_by":[]}
```

## 读取规则

### 何时读取

审计员在以下时机读取 shared_findings.jsonl:

1. **攻击阶段开始前**: 检查是否有其他审计员提供的凭证/密钥可直接利用
2. **每轮攻击失败后**: 检查是否有新的绕过方法或内部端点可尝试
3. **组合链构建时(R8)**: 获取所有跨审计员发现用于链式利用

### 读取与标记

消费方读取发现后，将自己的 Agent 名追加到 `consumed_by` 数组:

```bash
# 原子追加（避免竞争条件）
jq -c 'if .data.key == "JWT_SECRET" then .consumed_by += ["authz-auditor"] else . end' shared_findings.jsonl > tmp && mv tmp shared_findings.jsonl
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

## 冲突处理

- 多个审计员同时写入: 使用文件追加模式（`>>`），JSONL 格式天然支持并发追加
- 重复发现: 消费方通过 `data.key` 去重
- 过时发现: 不删除旧发现，消费方根据 timestamp 判断时效性

## 约束

- 写入的值必须是**实际获取到的数据**，禁止推测
- 敏感凭证在报告中脱敏（仅在 shared_findings.jsonl 中保留原文供审计使用）
- shared_findings.jsonl 在 Phase-5 清理时由 env-cleaner 安全删除
