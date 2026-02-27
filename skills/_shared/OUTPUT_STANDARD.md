# 输出规范（统一证据链）

## 目录结构
默认输出根目录：`/tmp/php_skills_audit/{project}_audit_{timestamp}/`
```
/tmp/php_skills_audit/{project}_audit_{timestamp}/
  meta.json
  _meta/
    phase1_map.md
    phase2_risk_map.md
    phase3_trace_log.md
    phase4_attack_chain.md
    phase5_report_index.md
  route_mapper/
    routes.json
    routes.md
    burp_templates/
  route_tracer/
    call_graph.json
    call_graph.md
    {route_name}/
      trace.json
      trace.md
      sinks.json
  sql_audit/
    findings.json
    findings.md
    {project}_sql_audit_{timestamp}.md
  auth_audit/
    auth_routes.md
    auth_findings.md
    auth_evidence.json
    {project}_auth_audit_{timestamp}.md
    {project}_auth_mapping_{timestamp}.md
    {project}_auth_README_{timestamp}.md
  vuln_report/
    composer_audit.json
    composer_audit.md   (末尾追加“触发点分析”段落)
  file_audit/
    findings.json
    findings.md
    {project}_file_audit_{timestamp}.md
  rce_audit/
    findings.json
    findings.md
    {project}_rce_audit_{timestamp}.md
  ssrf_xxe_audit/
    findings.json
    findings.md
    {project}_ssrf_xxe_audit_{timestamp}.md
  xss_ssti_audit/
    findings.json
    findings.md
    {project}_xss_ssti_audit_{timestamp}.md
  csrf_audit/
    findings.json
    findings.md
    {project}_csrf_audit_{timestamp}.md
  var_override_audit/
    findings.json
    findings.md
    {project}_var_override_audit_{timestamp}.md
  serialize_audit/
    findings.json
    findings.md
    {project}_serialize_audit_{timestamp}.md
  debug_verify/
    debug_cases.json
    debug_evidence.json
    debug_evidence.md
    slices/
  final_report.json
  final_report.md
  evidence_check.json
  evidence_check.md
```

## findings.json（统一字段）
- 文件内为数组，每个元素代表一条漏洞证据链
- 关键字段：
  - id: 规则或序号（如 SQLI-001）
  - title: 简短标题
  - severity: high | medium | low | info
  - independent_severity: C | H | M | L | high | medium | low | info
  - combined_severity: C | H | M | L | high | medium | low | info
  - confidence: high | medium | low
  - route: 路由或入口描述
  - source: 入口参数与位置
  - taint: 传播路径（关键片段）
  - sink: 最终危险点
  - validation: 过滤/校验说明
  - controllability: fully | conditional | none
  - poc: PoC 模板（不执行）
  - notes: 其他补充

### source / sink 结构建议
```
source: {
  file: "path/to/file.php",
  line: 123,
  param: "id",
  kind: "GET|POST|COOKIE|HEADER|BODY|CLI|ENV"
}

sink: {
  file: "path/to/file.php",
  line: 456,
  function: "query",
  arg: "sql"
}
```

### taint 结构建议
```
taint: [
  { file: "path/a.php", line: 10, code: "$id = $_GET['id'];" },
  { file: "path/b.php", line: 30, code: "$sql = "..." . $id;" }
]
```

## PoC 模板（不执行）
```
method: GET
path: /api/user
params:
  id: "1' OR 1=1 -- "
notes: "仅模板，不执行"
```

## debug_evidence.json（动态验证证据）
- 必须输出 debug_evidence.json/.md
- 字段固定：
  - case_id
  - vuln_type
  - entry
  - input
  - final_value
  - sink
  - result
  - notes
  - change_type（no_change / weak_change / strong_change / unknown）
  - trace_chain
  - source_path

### change_type 判定规则
- no_change → 成立
- weak_change（轻微变化）→ 条件成立
- strong_change（强过滤/白名单/参数化）→ 不成立
- 示例：`_samples/debug_evidence_sample/`

## auth_audit 三文件约定
- auth_routes.md: 列出所有需要鉴权的路由与鉴权机制
- auth_findings.md: 缺失鉴权或越权风险摘要
- auth_evidence.json: 结构化证据链（使用 findings.json 字段）

### auth 三文件（对外交付）
- {project}_auth_audit_{timestamp}.md
  - 只包含漏洞分析与风险摘要
  - 不重复完整路由清单
- {project}_auth_mapping_{timestamp}.md
  - 只包含路由 → 鉴权机制映射
  - 不包含漏洞分析或 PoC
- {project}_auth_README_{timestamp}.md
  - 说明文件结构与使用方法
  - 不包含分析正文

## SQL 综合报告（对外交付）
- {project}_sql_audit_{timestamp}.md 必须包含：
  - SQL 操作映射表（类/方法/框架/参数化状态/可控性）
  - 风险详情（证据链、sink、PoC 模板、修复建议）
  - 结论区引用 tracer 的 controllability 字段

## 依赖漏洞触发点分析（对外交付）
- composer_audit.md 末尾追加“触发点分析”段落，包含：
  - 项目环境识别（框架/容器/入口）
  - 组件触发点说明
  - 危险代码模式
  - 受影响路由或功能点

## 说明
- 行号以 1 为起点
- 若证据链断链，controllability 标记为 conditional 并说明断链点

## 完整性检查清单
- SQL：映射表存在、风险详情完整、PoC 模板存在、controllability 引用明确
- Auth：三文件存在且职责分离（主报告不含完整路由清单）
- Vuln：composer_audit.md 末尾存在“触发点分析”段落
- 其他模块：存在 {project}_{module}_audit_{timestamp}.md 综合报告
- Debug：debug_evidence.json/.md 存在，字段齐全，change_type 合法
- Meta：_meta/ 目录与 Phase 1~5 文件存在，Q1/Q2/Q3 终止判断完整
- 全局：文件名与链接一致、目录结构符合约定

## evidence_check 输出说明
- debug_evidence 缺失/字段缺失会报错
- result=skipped 时允许 change_type=unknown

## call_graph.json（结构）
```
{
  "nodes": [
    {
      "id": "ns\\Class::method",
      "type": "method|function",
      "name": "method",
      "class": "Class",
      "namespace": "ns",
      "file": "path/to/file.php",
      "line": 123,
      "params": ["id", "userId"],
      "summary": {
        "returns": ["id"],
        "param_sinks": { "id": ["sql", "rce"] }
      }
    }
  ],
  "edges": [
    {
      "caller": "ns\\Class::action",
      "callee": "ns\\Service::find",
      "callsite": { "file": "...", "line": 88 },
      "unresolved": false,
      "raw": "$this->find"
    }
  ]
}
```
