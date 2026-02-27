# ai-audit-mcp

目标：基于 `ai_audit` 生成的上下文进行 **全 AI 审计**，输出 AI 发现列表。

## 输入
- `ai_audit` 上下文目录：
  - `{out}/ai_audit/ai_audit_context/<entry_id>/context.json`

## 执行
脚本位置：`/Users/dream/vscode_code/php_skills/skills/ai-audit-mcp/scripts/ai_audit_mcp.py`
```bash
python3 /Users/dream/vscode_code/php_skills/skills/ai-audit-mcp/scripts/ai_audit_mcp.py --project {project} --out {out} --workers 4
```
依赖：本机 `claude` CLI（默认模型 `sonnet`，可通过 `AI_AUDIT_MODEL` 指定）

每个 `context.json` 已包含：
- 路由与 trace
- 可达调用图子图（nodes + edges + unresolved_calls）
- 可达函数体（functions）
- 相关文件完整内容（files）

## 输出
- `{out}/mcp_raw/ai-audit-mcp.json`

该文件包含：
- `results`: AI 审计结果列表
- `meta`: 运行信息（模型、轮数、耗时）
- `trace`: 每次运行的计数/错误

输出 JSON 结构：
```json
{
  "results": [
    {
      "id": "SQLI-001",
      "title": "UserController::detail SQL 注入",
      "route": {"method": "GET", "path": "/user/detail", "controller": "UserController", "action": "detail"},
      "sink": {"type": "sql", "file": "app/Http/Controller/UserController.php", "line": 128, "code": "mysqli_query(...)"},
      "source": {"file": "app/Http/Controller/UserController.php", "line": 120, "param": "id", "kind": "GET"},
      "taint": [
        {"file": "app/Http/Controller/UserController.php", "line": 120, "code": "$id = $_GET['id'];"}
      ],
      "validation": [],
      "controllability": "fully",
      "confidence": 0.86,
      "notes": "可控输入直达 SQL 拼接，未见过滤",
      "poc": "curl -G 'http://target/user/detail' --data-urlencode \"id=1' OR 1=1 -- \""
    }
  ]
}
```

## 必填字段
- `id`, `title`, `route`, `sink`, `source`, `taint`, `validation`, `controllability`, `confidence`, `notes`, `poc`

## 一致性标注（自动附加）
- `ai_consensus`: `high|low`
- `consensus_score`: 0.0~1.0

## 约束
- 必须基于 `context.json` 的完整上下文
- 不脱敏
- 不调用外部 OpenAI 或第三方 API
