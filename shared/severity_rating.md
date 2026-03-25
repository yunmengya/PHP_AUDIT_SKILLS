# 漏洞严重度三维评分标准

> 所有 Phase-4 Auditor 必须按本标准为每个发现计算严重度分数。
> 质检员使用本标准校验评分合理性。

## 评分公式

```
Score = R × 0.40 + I × 0.35 + C × 0.25
CVSS  = (Score / 3.0) × 10.0
```

- **R** = Reachability（可达性）
- **I** = Impact（影响力）
- **C** = Complexity（复杂度，反转计分：越容易利用分越高）

## 维度定义

### R — 可达性（权重 40%）

| 值 | 条件 | PHP 场景示例 |
|:--:|------|-------------|
| 3 | 无鉴权，HTTP 直接可达 | 匿名可访问的 API 端点、公开上传接口 |
| 2 | 需要普通用户鉴权 | 登录后的个人中心、评论接口 |
| 1 | 需要管理员权限或内网访问 | admin 面板、内部 API、cron 脚本 |
| 0 | 代码不可达 / 死代码 | 未注册路由、被注释的函数、废弃接口 |

**与 auth_matrix 的关系：**
- `auth_level = "anonymous"` → R = 3
- `auth_level = "authenticated"` → R = 2
- `auth_level = "admin"` → R = 1
- 路由不存在于 route_map → R = 0

### I — 影响力（权重 35%）

| 值 | 条件 | PHP 场景示例 |
|:--:|------|-------------|
| 3 | RCE / 任意文件写入 / 完整数据泄露 / 系统沦陷 | eval() 注入、Webshell 上传、全表 UNION 注入 |
| 2 | 敏感数据泄露 / 权限提升 / 部分文件读取 | .env 泄露、IDOR 越权、LFI 读 /etc/passwd |
| 1 | 有限信息泄露 / 非敏感配置读取 | phpinfo 暴露、目录列表、错误堆栈 |
| 0 | 无实际安全影响 | 纯样式问题、无效的 XSS（CSP 阻断） |

### C — 复杂度（权重 25%，反转计分）

| 值 | 条件 | PHP 场景示例 |
|:--:|------|-------------|
| 3 | 单请求即可，无前置条件 | 直接 `?id=1 UNION SELECT` 或 `?cmd=id` |
| 2 | 需要特殊 Payload 或多步骤 | 需 Base64 编码、需先获取 CSRF Token |
| 1 | 需特定环境 / 竞争条件 / 链式利用 | disable_functions 绕过、反序列化 POP 链、TOCTOU |
| 0 | 存在有效防御，无法利用 | WAF 完全阻断、参数化查询、CSP strict-dynamic |

## 严重度等级映射

| 等级 | ID 前缀 | Score 区间 | CVSS 区间 | 含义 |
|:----:|:-------:|:----------:|:---------:|------|
| **C** (Critical) | C- | 2.70 — 3.00 | 9.0 — 10.0 | 可直接导致系统沦陷 |
| **H** (High) | H- | 2.10 — 2.69 | 7.0 — 8.9 | 可造成重大损害 |
| **M** (Medium) | M- | 1.20 — 2.09 | 4.0 — 6.9 | 中等风险 |
| **L** (Low) | L- | 0.10 — 1.19 | 0.1 — 3.9 | 安全加固建议 |

**漏洞 ID 格式：** `{Level}-{Type}-{Sequence}`
- 例：`C-RCE-001`、`H-SQLI-002`、`M-AUTH-003`、`L-CONFIG-001`

## 可利用性对评分的影响

| exploitability_judgment | R 影响 | C 影响 |
|------------------------|--------|--------|
| directly_exploitable | 使用实际值 | 使用实际值 |
| conditionally_exploitable | 使用实际值 | C 降 1 级（更保守） |
| not_exploitable | R = 0 | C = 0 |

**规则：** `not_exploitable` → Score 强制 = 0 → 最高 verdict = `potential`

## PHP 场景速查表

| 漏洞类型 | 典型 R | 典型 I | 典型 C | 典型 Score | 典型等级 |
|----------|:------:|:------:|:------:|:----------:|:--------:|
| eval() + 无鉴权 | 3 | 3 | 3 | 3.00 | C |
| SQLi UNION + 无鉴权 | 3 | 3 | 3 | 3.00 | C |
| 文件上传 Webshell + 无类型检查 | 3 | 3 | 2 | 2.75 | C |
| XXE 回显 + 需登录 | 2 | 3 | 3 | 2.60 | H |
| SSRF 内网探测 + 无鉴权 | 3 | 2 | 2 | 2.40 | H |
| IDOR 越权读取 + 需登录 | 2 | 2 | 3 | 2.25 | H |
| 反序列化 RCE + POP 链 | 2 | 3 | 1 | 2.10 | H |
| Stored XSS + 需登录 | 2 | 2 | 2 | 2.00 | M |
| CSRF 状态修改 + 需钓鱼 | 2 | 2 | 1 | 1.75 | M |
| 弱密码哈希 (MD5) | 2 | 1 | 2 | 1.65 | M |
| Session 配置不安全 | 2 | 1 | 1 | 1.40 | M |
| phpinfo 暴露 | 3 | 1 | 3 | 2.30 | H |
| 错误堆栈泄露 | 3 | 1 | 3 | 2.30 | H |
| .env 文件可下载 + 无鉴权 | 3 | 2 | 3 | 2.65 | H |
| 日志投毒 + LFI 链 | 2 | 3 | 1 | 2.10 | H |
| LDAP 注入 + 需管理员 | 1 | 2 | 2 | 1.60 | M |
| CRLF 头注入 (PHP ≥7.0) | 2 | 1 | 1 | 1.40 | M |
| 竞争条件 (余额) | 2 | 2 | 1 | 1.75 | M |

## Auditor 输出要求

在 `exploits/{sink_id}.json` 的 `severity` 对象中填写：

```json
{
  "severity": {
    "reachability": 3,
    "reachability_reason": "anonymous endpoint, no middleware",
    "impact": 3,
    "impact_reason": "eval() allows arbitrary code execution",
    "complexity": 2,
    "complexity_reason": "need base64 encoding to bypass WAF",
    "score": 2.75,
    "cvss": 9.2,
    "level": "C",
    "vuln_id": "C-RCE-001"
  }
}
```

**必须同时填写 reason 字段。** 纯数字无解释 → 质检不通过。

## 与 evidence_score 的关系

| severity.score | 对应 evidence_score 范围 | 说明 |
|:--------------:|:------------------------:|------|
| ≥ 2.10 | 7 — 10 | 高危/严重发现，evidence_score 不得低于 7 |
| 1.20 — 2.09 | 4 — 6 | 中危发现 |
| 0.10 — 1.19 | 1 — 3 | 低危发现 |
| 0 | 0 | 不可利用 |

**一致性规则：** 若 severity.score ≥ 2.70 但 evidence_score < 7 → 质检标记为矛盾项。
