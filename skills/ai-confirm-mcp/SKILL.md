---
name: ai-confirm-mcp
description: Use AI to confirm exploitability for PHP audit findings using full context.
---

# ai-confirm-mcp

## 目标
对审计发现进行 AI 可利用性确认（仅由 skill 产出结果）。

## 输入
- PROJECT_AUDIT/ai_context/FINDING_ID/context.json
  - 包含：finding + trace + call_graph 子图 + 相关函数体 + 相关文件完整内容（不脱敏）

## 输出
- PROJECT_AUDIT/mcp_raw/ai-confirm-mcp.json

## 输出格式（必须）
```json
{
  "results": [
    {
      "id": "SQLI-001",
      "title_label": "[SQLI-001] UserController::detail SQL 注入",
      "severity_label": "Critical (CVSS 9.8)",
      "reachability": { "score": 3, "desc": "通过 HTTP 服务直接调用" },
      "impact": { "score": 3, "desc": "可读取服务器敏感文件" },
      "complexity": { "score": 0, "desc": "无有效过滤" },
      "exploitability": "已确认|高可能|待验证",
      "location": "UserController::detail (app/Http/Controller/UserController.php:128)",
      "trigger": "mysqli_query",
      "input_source": "REQUEST: id",
      "output_mode": "echo/print",
      "evidence": [
        { "file": "app/Http/Controller/UserController.php", "line": 128, "note": "sink" }
      ],
      "poc": "curl \"http://target/user/detail?id=1' OR 1=1 -- -\"",
      "confidence": 0.86,
      "rationale": "可控输入直达 SQL 拼接，未见过滤"
    }
  ]
}
```

## 规则
- 必须为每条 finding 输出结果（以 id 匹配）。
- 表格字段必须完整：title_label/severity_label/reachability/impact/complexity/exploitability/location/trigger/input_source/output_mode/evidence。
- R/I/C 必须包含 score + desc。
- evidence 至少 1 条，必须包含 file+line。
- 可利用性只能使用：已确认 / 高可能 / 待验证。
- 输出不做脱敏，保持原始上下文。
- `poc` 可选，尽量提供；如缺失将使用模板兜底生成。
