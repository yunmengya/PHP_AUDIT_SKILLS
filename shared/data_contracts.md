# 数据合约（Data Contracts）

本文件定义所有 Agent 间通信的 JSON 数据格式。对应的 JSON Schema 文件在 `schemas/` 目录下。

---

## 1. route_map.json — 路由表

```json
{
  "routes": [{
    "id": "string (唯一标识，格式: route_001)",
    "url": "string (路由路径，如 /api/user/{id})",
    "method": "string (GET/POST/PUT/DELETE/PATCH/ANY)",
    "controller": "string (控制器类::方法，如 UserController::show)",
    "file": "string (控制器文件路径，相对于项目根目录)",
    "line": "number (方法定义的行号)",
    "params": ["string (参数名列表)"],
    "param_sources": ["string (参数来源: $_GET/$_POST/$_FILES/$_REQUEST/Request)"],
    "middleware": ["string (中间件名列表)"],
    "auth_level": "string (anonymous/authenticated/admin)",
    "route_type": "string (A=可访问/B=部分报错/C=完全不可访问)"
  }]
}
```

## 2. auth_matrix.json — 权限矩阵

```json
{
  "matrix": [{
    "route_id": "string (关联 route_map 的 id)",
    "url": "string (路由路径)",
    "auth_level": "string (anonymous/authenticated/admin)",
    "auth_mechanism": "string (鉴权机制描述，如 session_check/jwt_verify/middleware:auth)",
    "bypass_notes": "string|null (潜在绕过注记，如 '缺少 CSRF 校验')"
  }]
}
```

## 3. priority_queue.json — 优先级队列

```json
[{
  "id": "string (唯一标识，格式: sink_001)",
  "priority": "string (P0/P1/P2/P3)",
  "route_id": "string (关联 route_map 的 id)",
  "route_url": "string (路由路径)",
  "sink_function": "string (Sink 函数名)",
  "sink_file": "string (Sink 所在文件路径)",
  "sink_line": "number (Sink 所在行号)",
  "auth_level": "string (该路由的鉴权等级)",
  "reason": "string (定级理由)",
  "source_count": "number (多少个数据源确认了此条)",
  "sources": ["string (数据来源: psalm/progpilot/ast_sinks/context_extractor)"]
}]
```

### 定级规则

| 优先级 | 条件 |
|--------|------|
| P0（紧急） | 无鉴权 + 高危 Sink（RCE/反序列化/文件包含） |
| P1（高危） | 无鉴权 + 中危 Sink，或 低权限 + 高危 Sink |
| P2（中危） | 有鉴权 + 中危 Sink，或 无鉴权 + 低危 Sink |
| P3（低危） | 高权限 + 低危 Sink |

## 4. context_pack.json — 上下文包（每个 Sink 一份）

```json
{
  "sink_id": "string (关联 priority_queue 的 id)",
  "sink_function": "string (Sink 函数名)",
  "priority": "string (P0/P1/P2/P3)",
  "trace_depth": "number (追踪深度)",
  "layers": [{
    "layer": "number (层级，0=Sink层，越大越接近 Source)",
    "role": "string (SINK/CALLER/ROUTE)",
    "file": "string (文件路径)",
    "function": "string (函数名)",
    "lines": "string (起止行号，如 45-67)",
    "code": "string (完整函数代码)",
    "analysis_notes": {
      "source": "string|null (数据来源)",
      "sink_arg": "string|null (传入 Sink 的参数)",
      "filters": ["string (路径上的过滤函数)"],
      "bypass_hint": "string|null (潜在绕过提示)"
    }
  }],
  "data_flow_summary": "string (Source→...→Sink 单行摘要)",
  "filters_in_path": [{
    "function": "string (过滤函数名)",
    "effective": "boolean (是否有效)",
    "reason": "string (有效/无效的原因)"
  }],
  "global_filters": [{
    "type": "string (middleware/waf/function)",
    "file": "string (文件路径)",
    "code": "string (过滤代码)",
    "affects": "string (影响范围描述)"
  }]
}
```

## 5. credentials.json — 凭证池

```json
{
  "anonymous": {},
  "authenticated": {
    "method": "string (cookie/jwt/session)",
    "cookie": "string|null (Cookie 值)",
    "token": "string|null (JWT/Bearer Token)",
    "user_id": "number|null",
    "username": "string"
  },
  "admin": {
    "method": "string (cookie/jwt/session)",
    "cookie": "string|null",
    "token": "string|null",
    "user_id": "number|null",
    "username": "string"
  }
}
```

## 6. trace_record.json — 追踪记录（每条路由一份）

```json
{
  "route_id": "string (关联 route_map 的 id)",
  "route_url": "string (路由路径)",
  "call_chain": ["string (函数调用描述，如 'index.php → Router::dispatch → UserController::show → DB::raw')"],
  "filters_encountered": [{
    "function": "string (过滤函数名)",
    "effective": "boolean",
    "reason": "string"
  }],
  "dynamic_bindings": [{
    "type": "string (call_user_func/variable_method/dynamic_include)",
    "resolved": "string (实际解析结果)"
  }],
  "raw_request": "string (发送的完整 HTTP 请求)",
  "raw_response_status": "number (HTTP 状态码)",
  "error_point": "string|null (类型 B 路由: 报错在哪个函数)",
  "error_vs_sink": "string|null (before_sink/after_sink)"
}
```

## 7. environment_status.json — 环境状态

```json
{
  "mode": "string (full=完整环境/partial=部分可用)",
  "framework": "string (Laravel/ThinkPHP/Yii2/Symfony/CakePHP/CodeIgniter/Native)",
  "framework_version": "string (如 8.1.0)",
  "php_version": "string (如 7.4)",
  "db_type": "string (mysql/pgsql/sqlite)",
  "startup_rounds": "number (启动尝试轮次)",
  "fixes_applied": ["string (修复记录，如 'composer require xxx')"],
  "web_accessible": "boolean (Web 是否可访问)",
  "routes_accessible": "number (类型 A 路由数量)",
  "routes_error": "number (类型 B 路由数量)",
  "routes_inaccessible": "number (类型 C 路由数量)",
  "routes_error_details": [{
    "route": "string (路由路径)",
    "error": "string (错误信息)",
    "reason": "string (原因分析)",
    "impact": "string (对审计的影响)"
  }],
  "xdebug_working": "boolean",
  "db_tables_total": "number (数据库总表数)",
  "db_tables_from_migration": "number (来自迁移文件的表数)",
  "db_tables_from_inference": "number (来自推断的表数)",
  "disabled_features": ["string (因缺依赖而禁用的功能)"],
  "encrypted_files": ["string (ionCube/Zend Guard 加密的文件路径)"]
}
```

## 8. dep_risk.json — 组件风险

```json
[{
  "package": "string (包名，如 laravel/framework)",
  "installed_version": "string (安装版本)",
  "cve": "string (CVE 编号)",
  "severity": "string (CRITICAL/HIGH/MEDIUM/LOW)",
  "type": "string (漏洞类型，如 RCE/SQLi/XSS)",
  "description": "string (漏洞描述)",
  "fixed_version": "string (修复版本)"
}]
```

## 9. exploit_result.json — 攻击结果（每个 Sink 一份）

```json
{
  "sink_id": "string (关联 priority_queue 的 id，如 sink_001)",
  "route_url": "string (路由路径)",
  "sink_function": "string (Sink 函数名，如 DB::raw)",
  "specialist": "string (执行攻击的专家 Agent 名，如 sqli_auditor)",
  "route_type": "string (A/B/C)",
  "rounds_executed": "number (实际执行的攻击轮数)",
  "rounds_skipped": "number (智能跳过的轮数)",
  "skip_reason": "string|null (跳过原因)",
  "results": [{
    "round": "number (轮次序号 1-8)",
    "strategy": "string (策略名称，如 basic_union_select)",
    "payload": "string (实际发送的 Payload)",
    "injection_point": "string (注入点描述，如 POST body param 'name')",
    "request": "string (完整 HTTP 请求)",
    "response_status": "number (HTTP 状态码)",
    "response_body_snippet": "string (响应体前 500 字符)",
    "evidence_type": "string|null (证据类型: time_based/union_based/error_based/file_proof/blind 等)",
    "evidence_detail": "string|null (证据详情)",
    "result": "string (confirmed/suspected/failed)",
    "failure_reason": "string|null (失败原因分析)"
  }],
  "race_condition_results": {
    "tested": "boolean (是否测试了竞态条件)",
    "concurrent_requests": "number (并发请求数)",
    "result": "string|null (vulnerable/not_vulnerable)",
    "detail": "string|null (竞态漏洞详情)"
  },
  "final_verdict": "string (confirmed/suspected/potential/not_vulnerable)",
  "confidence": "string (high/medium/low)"
}
```

### 攻击结果摘要 — exploit_summary.json

由主调度器在 Phase-4 全部完成后汇总生成:

```json
{
  "total_sinks": "number (总 Sink 数)",
  "type_a_tested": "number (Type A 实战测试数)",
  "type_b_after_tested": "number (Type B after_sink 测试数)",
  "type_b_before_static": "number (Type B before_sink 静态分析数)",
  "type_c_static": "number (Type C 静态分析数)",
  "vulnerabilities_confirmed": "number (已确认漏洞数)",
  "vulnerabilities_suspected": "number (疑似漏洞数)",
  "race_conditions_found": "number (竞态条件漏洞数)"
}
```

---

## 去重规则

漏洞去重以 **"文件路径 + 行号 + Sink 函数"** 为唯一键。多个来源指向同一点时，合并记录并标注来源数量（来源越多可信度越高）。

---

## 10. race_condition_result.json — 竞态条件测试结果

```json
{
  "sink_id": "string (关联 priority_queue 的 id)",
  "route_url": "string (路由路径)",
  "specialist": "race_condition_auditor",
  "test_type": "string (TOCTOU/double_spend/token_replay/rate_limit/session_race/db_transaction)",
  "rounds_executed": "number",
  "results": [{
    "round": "number",
    "strategy": "string",
    "concurrent_requests": "number (并发请求数)",
    "total_attempts": "number (总尝试次数)",
    "success_count": "number (成功触发次数)",
    "success_rate": "number (成功率 0.0-1.0)",
    "time_window_ms": "number (攻击时间窗口毫秒)",
    "payload": "string",
    "evidence_detail": "string|null",
    "result": "string (confirmed/suspected/failed)",
    "baseline_comparison": "string (对比正常请求的差异描述)"
  }],
  "final_verdict": "string (confirmed/suspected/potential/not_vulnerable)",
  "confidence": "string (high/medium/low)"
}
```

## 11. crypto_audit_result.json — 密码学审计结果

```json
{
  "sink_id": "string",
  "category": "string (password_hashing/random_number/encryption/jwt/session_token/signature/key_management)",
  "specialist": "crypto_auditor",
  "rounds_executed": "number",
  "results": [{
    "round": "number",
    "strategy": "string",
    "target_function": "string (被审计的密码学函数)",
    "target_file": "string (文件路径)",
    "target_line": "number",
    "weakness": "string (弱点描述)",
    "evidence": "string (证据: 可预测输出/弱密钥/算法降级等)",
    "exploitability": "string (直接可利用/需要条件/理论可能)",
    "result": "string (confirmed/suspected/failed)"
  }],
  "final_verdict": "string",
  "confidence": "string"
}
```

## 12. nosql_result.json — NoSQL 注入测试结果

```json
{
  "sink_id": "string",
  "route_url": "string",
  "specialist": "nosql_auditor",
  "db_type": "string (mongodb/redis/elasticsearch/memcached)",
  "rounds_executed": "number",
  "results": [{
    "round": "number",
    "strategy": "string (operator_injection/where_js/regex_dos/aggregation/json_pollution/redis_crlf/orm_bypass)",
    "payload": "string",
    "injection_point": "string",
    "request": "string",
    "response_status": "number",
    "response_body_snippet": "string",
    "query_semantic_change": "boolean (查询语义是否被改变)",
    "evidence_detail": "string|null",
    "result": "string (confirmed/suspected/failed)"
  }],
  "final_verdict": "string",
  "confidence": "string"
}
```

## 13. wordpress_result.json — WordPress 审计结果

```json
{
  "sink_id": "string",
  "specialist": "wordpress_auditor",
  "scope": "string (core/plugin/theme)",
  "component_name": "string (WordPress 核心 / 插件名 / 主题名)",
  "component_version": "string",
  "rounds_executed": "number",
  "results": [{
    "round": "number",
    "strategy": "string (core_cve/plugin_audit/xmlrpc/rest_api/shortcode/nonce_bypass/editor_rce)",
    "endpoint": "string",
    "payload": "string",
    "evidence_detail": "string|null",
    "cve_id": "string|null (关联的 CVE 编号)",
    "result": "string (confirmed/suspected/failed)"
  }],
  "final_verdict": "string",
  "confidence": "string"
}
```

## 14. business_logic_result.json — 业务逻辑审计结果

```json
{
  "sink_id": "string",
  "route_url": "string",
  "specialist": "business_logic_auditor",
  "business_flow": "string (受影响的业务流程描述)",
  "rounds_executed": "number",
  "results": [{
    "round": "number",
    "strategy": "string (price_tamper/coupon_abuse/payment_bypass/flow_skip/negative_value/sms_bomb/state_machine)",
    "payload": "string",
    "business_impact": "string (业务影响描述: 资金损失/数据泄露/流程绕过等)",
    "state_before": "string (操作前状态)",
    "state_after": "string (操作后状态)",
    "persisted": "boolean (异常状态是否被持久化)",
    "evidence_detail": "string|null",
    "result": "string (confirmed/suspected/failed)"
  }],
  "final_verdict": "string",
  "confidence": "string"
}
```

## 15. credentials.json 扩展字段

在原有 anonymous/authenticated/admin 基础上，新增以下可选字段:

```json
{
  "anonymous": {},
  "authenticated": { "...原有字段..." },
  "admin": { "...原有字段..." },
  "oauth2": {
    "access_token": "string",
    "refresh_token": "string|null",
    "token_type": "string (Bearer)",
    "scope": "string",
    "expires_in": "number",
    "client_id": "string",
    "grant_type": "string (password/client_credentials/authorization_code)"
  },
  "api_key": {
    "key": "string",
    "header_name": "string (如 X-API-Key)",
    "location": "string (header/query/cookie)"
  },
  "multi_tenant": [{
    "tenant_id": "string",
    "tenant_name": "string",
    "credentials": { "...同 authenticated 结构..." }
  }],
  "websocket": {
    "url": "string (ws://...)",
    "auth_message": "string|null (连接后发送的认证消息)"
  }
}
```

## 16. CVSS 3.1 评分附加字段

在 priority_queue.json 的每条记录中可附加:

```json
{
  "...原有字段...",
  "cvss": {
    "score": "number (0.0-10.0)",
    "vector": "string (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)",
    "severity": "string (CRITICAL/HIGH/MEDIUM/LOW/NONE)",
    "attack_vector": "string (Network/Adjacent/Local/Physical)",
    "attack_complexity": "string (Low/High)",
    "privileges_required": "string (None/Low/High)",
    "user_interaction": "string (None/Required)",
    "scope": "string (Unchanged/Changed)",
    "confidentiality": "string (None/Low/High)",
    "integrity": "string (None/Low/High)",
    "availability": "string (None/Low/High)"
  },
  "attack_surface_score": "number (0-100, 攻击面量化评分)",
  "business_impact": ["string (financial/pii_exposure/auth_bypass/service_disruption)"]
}
```

---

## 17. attack_graph.json — 攻击图谱

```json
{
  "generated_at": "string (ISO-8601)",
  "total_nodes": "number (漏洞节点总数)",
  "total_edges": "number (关联边总数)",
  "total_paths": "number (攻击路径总数)",
  "nodes": [{
    "node_id": "string (V-001 格式)",
    "vuln_type": "string",
    "sub_type": "string",
    "endpoint": "string",
    "confidence": "string (confirmed/highly_suspected/potential_risk)",
    "output_data": "string (此漏洞产出的数据/能力)",
    "required_access": "string (anonymous/authenticated/admin)",
    "grants_access": "string (获得的访问级别)",
    "severity": "string (Critical/High/Medium/Low/Info)"
  }],
  "edges": [{
    "from": "string (起点 node_id)",
    "to": "string (终点 node_id)",
    "relationship": "string (credential_reuse/token_forge/privilege_escalation/data_extraction/lateral_movement)",
    "description": "string"
  }],
  "paths": [{
    "path_id": "string (P-001 格式)",
    "score": "number (路径评分)",
    "confidence": "string (high/medium/low)",
    "nodes": ["string (有序 node_id 列表)"],
    "entry_point": "string",
    "final_impact": "string",
    "narrative": "string (攻击叙事)",
    "remediation_priority": "string (P0/P1/P2)"
  }],
  "escalation_patterns": [{
    "pattern_name": "string",
    "involved_vulns": ["string (node_id 列表)"],
    "individual_severity": "string",
    "combined_severity": "string",
    "explanation": "string"
  }],
  "mermaid_diagram": "string (完整 Mermaid 图谱代码)"
}
```

## 18. correlation_report.json — 跨审计员关联报告

```json
{
  "generated_at": "string (ISO-8601)",
  "escalations": [{
    "pattern_name": "string (风险升级模式名)",
    "condition_a": {
      "finding_id": "string",
      "vuln_type": "string",
      "original_severity": "string"
    },
    "condition_b": {
      "finding_id": "string",
      "vuln_type": "string",
      "original_severity": "string"
    },
    "combined_severity": "string",
    "combined_impact": "string",
    "explanation": "string"
  }],
  "second_order_candidates": [{
    "store_point": {
      "endpoint": "string",
      "param": "string",
      "table": "string",
      "column": "string",
      "sanitization": "string (none/partial/full)"
    },
    "use_point": {
      "endpoint": "string",
      "source_table": "string",
      "source_column": "string",
      "usage_sink": "string",
      "output_sanitization": "string (none/partial/full)"
    },
    "vuln_type": "string (second_order_sqli/stored_xss/second_order_rce/...)",
    "risk_level": "string (high/medium/low)",
    "sanitization_gap": "string"
  }],
  "coverage_gaps": [{
    "area": "string",
    "risk_level": "string",
    "recommendation": "string"
  }],
  "potential_false_positives": [{
    "finding_id": "string",
    "reason": "string",
    "matched_pattern": "string (如 FP-SQL-001)"
  }]
}
```

## 19. shared_findings.jsonl — 实时共享发现（JSON Lines）

每行一条记录:

```json
{
  "timestamp": "string (ISO-8601)",
  "source_agent": "string (写入方 Agent 名)",
  "finding_type": "string (credential|internal_url|secret_key|endpoint|bypass_method|config_value)",
  "priority": "string (critical|high|medium)",
  "data": {
    "key": "string (发现的名称/标识)",
    "value": "string (发现的值)",
    "context": "string (发现的上下文描述)",
    "source_location": "string (发现来源)"
  },
  "target_agents": ["string (建议的消费方 Agent 名)"],
  "consumed_by": ["string (已消费的 Agent 名)"]
}
```

## 20. second_order 追踪文件

### store_points.jsonl — 存入点记录

```json
{
  "store_id": "string (STORE-001 格式)",
  "endpoint": "string (写入端点)",
  "param": "string (参数名)",
  "storage": "string (database/file/cache/session)",
  "table": "string (表名，数据库存储时)",
  "column": "string (列名)",
  "sanitization": "string (none/partial/full)",
  "sanitization_detail": "string",
  "recorded_by": "string (记录方 Agent 名)"
}
```

### use_points.jsonl — 使用点记录

```json
{
  "use_id": "string (USE-001 格式)",
  "endpoint": "string (使用端点)",
  "source_table": "string",
  "source_column": "string",
  "usage_sink": "string (Sink 函数名)",
  "usage_file": "string (文件路径)",
  "usage_line": "number",
  "output_sanitization": "string (none/partial/full)",
  "output_sanitization_detail": "string",
  "recorded_by": "string"
}
```

### correlations.json — 关联结果

```json
{
  "generated_at": "string (ISO-8601)",
  "correlations": [{
    "store_id": "string",
    "use_id": "string",
    "data_path": "string (table.column)",
    "vuln_type": "string",
    "risk_level": "string",
    "sanitization_gap": "string",
    "needs_testing": "boolean"
  }]
}
```

## 21. remediation_summary.json — 修复摘要

```json
{
  "generated_at": "string (ISO-8601)",
  "total_vulns": "number",
  "patches_generated": "number",
  "patches_skipped": "number",
  "skip_reasons": ["string"],
  "patches": [{
    "sink_id": "string",
    "vuln_type": "string",
    "file": "string (修改的源文件路径)",
    "patch_file": "string (Patch 文件路径)",
    "fix_strategy": "string (修复策略描述)",
    "breaking_change": "boolean",
    "verification": "string (验证建议)"
  }]
}
```

## 22. poc_summary.json — PoC 脚本摘要

```json
{
  "generated_at": "string (ISO-8601)",
  "total_confirmed": "number",
  "poc_generated": "number",
  "poc_skipped": "number",
  "scripts": [{
    "sink_id": "string",
    "vuln_type": "string",
    "file": "string (PoC 脚本文件名)",
    "endpoint": "string",
    "auth_required": "boolean",
    "curl_command": "string (等效 curl 命令)"
  }]
}
```

## 23. evidence_quality 扩展字段

在 team4_progress.json 的每个 finding 中附加:

```json
{
  "...原有字段...",
  "evidence_quality": "number (0-10, 证据质量评分)",
  "cross_validation": {
    "variant_payload": "string (变体 Payload)",
    "variant_result": "string (success/failed)",
    "independent_reproduction": "boolean"
  },
  "false_positive_check": {
    "checked": "boolean",
    "matched_patterns": ["string (匹配的误报模式 ID)"],
    "conclusion": "string (not_false_positive/false_positive/uncertain)",
    "reason": "string"
  }
}
```
