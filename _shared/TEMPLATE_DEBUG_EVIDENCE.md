# Debug 证据模板（统一格式）

> 说明：所有漏洞动态验证必须输出 debug_evidence.json/.md，字段固定如下。

## JSON 字段（必填）
- case_id
- vuln_type
- entry
- input
- final_value
- sink
- result
- notes
- change_type
- trace_chain
- source_path

## 字段说明
- case_id：与 findings.json 的 id 对应
- vuln_type：漏洞类型（如 sql_injection / xss / ssrf）
- entry：入口（方法+路径或函数入口）
- input：输入值（字符串或结构体）
- final_value：进入 sink 前的最终值
- sink：危险点（文件/行/函数）
- result：confirmed | conditional | rejected | skipped
- notes：补充说明（含 skip_reason）
- change_type：no_change | weak_change | strong_change | unknown
- trace_chain：入口→中间处理→sink 的证据链
- source_path：相对路径+行号（如 app/Service.php:42）

## JSON 示例
```json
{
  "case_id": "SQLI-001",
  "vuln_type": "sql_injection",
  "entry": "GET /user?id=",
  "input": "1 OR 1=1",
  "final_value": "1 OR 1=1",
  "sink": {"file":"app/Repo.php","line":88,"function":"query"},
  "result": "confirmed",
  "notes": "变量未过滤，1:1 拼接成立",
  "change_type": "no_change",
  "trace_chain": [
    {"file":"app/Controller.php","line":12,"code":"$id=$_GET['id'];"},
    {"file":"app/Repo.php","line":88,"code":"$sql=...$id"}
  ],
  "source_path": "app/Repo.php:88"
}
```

## Markdown 输出（debug_evidence.md）
建议包含表格：
- case_id | vuln_type | entry | change_type | result | source_path | notes
