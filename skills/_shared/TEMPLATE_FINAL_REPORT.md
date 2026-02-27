# 最终报告模板（含 Debug 证据闭环）

## 基本信息
- 项目名称：
- 审计时间：
- 环境：Docker PHP 7.4.3
- 审计方式：静态证据链 + 动态 Debug 验证

## 漏洞摘要
| ID | 类型 | 入口 | 结论 | Debug 证据 |
|---|---|---|---|---|
| SQLI-001 | sql_injection | GET /user?id= | confirmed | debug_verify/debug_evidence.json |

## 单条漏洞（模板）
### {case_id}
- 类型：{vuln_type}
- 入口：{entry}
- 证据链：{trace_chain}
- Source 路径：{source_path}
- Sink：{sink}

#### Debug 验证
- 输入值：{input}
- 最终值：{final_value}
- 变化类型：{change_type}
- 判定结果：{result}
- 备注：{notes}

#### Burp 复现格式（可选）
**Request**
```http
GET /path?param=value HTTP/1.1
Host: example.com
```

**Response**
```http
HTTP/1.1 200 OK
Content-Type: text/plain

...
```

## 说明
- Debug 证据必须可追溯到 debug_evidence.json/.md
- 所有漏洞必须有对应的 debug_evidence 记录
