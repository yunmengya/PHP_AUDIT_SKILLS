# Data Contracts

This document defines the JSON data formats for all inter-Agent communication. Corresponding JSON Schema files are in the `schemas/` directory.

---

## 1. route_map.json — Route Map

```json
{
  "routes": [{
    "id": "string (unique identifier, format: route_001)",
    "url": "string (route path, e.g., /api/user/{id})",
    "method": "string (GET/POST/PUT/DELETE/PATCH/ANY)",
    "controller": "string (controller class::method, e.g., UserController::show)",
    "file": "string (controller file path, relative to project root)",
    "line": "number (line number of method definition)",
    "params": ["string (parameter name list)"],
    "param_sources": ["string (parameter source: $_GET/$_POST/$_FILES/$_REQUEST/Request)"],
    "middleware": ["string (middleware name list)"],
    "auth_level": "string (anonymous/authenticated/admin)",
    "route_type": "string (A=accessible/B=partial error/C=completely inaccessible)"
  }]
}
```

## 2. auth_matrix.json — Auth Matrix

```json
{
  "matrix": [{
    "route_id": "string (references route_map id)",
    "url": "string (route path)",
    "auth_level": "string (anonymous/authenticated/admin)",
    "auth_mechanism": "string (auth mechanism description, e.g., session_check/jwt_verify/middleware:auth)",
    "bypass_notes": "string|null (potential bypass notes, e.g., 'missing CSRF validation')"
  }]
}
```

## 3. priority_queue.json — Priority Queue

```json
[{
  "id": "string (unique identifier, format: sink_001)",
  "priority": "string (P0/P1/P2/P3)",
  "route_id": "string (references route_map id)",
  "route_url": "string (route path)",
  "sink_function": "string (Sink function name)",
  "sink_file": "string (Sink file path)",
  "sink_line": "number (Sink line number)",
  "auth_level": "string (auth level for this route)",
  "reason": "string (classification rationale)",
  "source_count": "number (how many data sources confirmed this entry)",
  "sources": ["string (data source: psalm/progpilot/ast_sinks/context_extractor)"]
}]
```

### Classification Rules

| Priority | Condition |
|--------|------|
| P0 (Critical) | No auth + high-risk Sink (RCE/deserialization/file inclusion) |
| P1 (High) | No auth + medium-risk Sink, or low privilege + high-risk Sink |
| P2 (Medium) | Auth required + medium-risk Sink, or no auth + low-risk Sink |
| P3 (Low) | High privilege + low-risk Sink |

## 4. context_pack.json — Context Pack (one per Sink)

```json
{
  "sink_id": "string (references priority_queue id)",
  "sink_function": "string (Sink function name)",
  "priority": "string (P0/P1/P2/P3)",
  "trace_depth": "number (trace depth)",
  "layers": [{
    "layer": "number (layer level, 0=Sink layer, higher=closer to Source)",
    "role": "string (SINK/CALLER/ROUTE)",
    "file": "string (file path)",
    "function": "string (function name)",
    "lines": "string (line range, e.g., 45-67)",
    "code": "string (complete function code)",
    "analysis_notes": {
      "source": "string|null (data source)",
      "sink_arg": "string|null (argument passed to Sink)",
      "filters": ["string (filter functions on the path)"],
      "bypass_hint": "string|null (potential bypass hint)"
    }
  }],
  "data_flow_summary": "string (Source→...→Sink one-line summary)",
  "filters_in_path": [{
    "function": "string (filter function name)",
    "effective": "boolean (whether effective)",
    "reason": "string (reason for effectiveness/ineffectiveness)"
  }],
  "global_filters": [{
    "type": "string (middleware/waf/function)",
    "file": "string (file path)",
    "code": "string (filter code)",
    "affects": "string (scope of effect description)"
  }]
}
```

## 5. credentials.json — Credential Pool

```json
{
  "anonymous": {},
  "authenticated": {
    "method": "string (cookie/jwt/session)",
    "cookie": "string|null (Cookie value)",
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

## 6. trace_record.json — Trace Record (one per route)

```json
{
  "route_id": "string (references route_map id)",
  "route_url": "string (route path)",
  "call_chain": ["string (function call description, e.g., 'index.php → Router::dispatch → UserController::show → DB::raw')"],
  "filters_encountered": [{
    "function": "string (filter function name)",
    "effective": "boolean",
    "reason": "string"
  }],
  "dynamic_bindings": [{
    "type": "string (call_user_func/variable_method/dynamic_include)",
    "resolved": "string (actual resolution result)"
  }],
  "raw_request": "string (complete HTTP request sent)",
  "raw_response_status": "number (HTTP status code)",
  "error_point": "string|null (Type B route: which function raised the error)",
  "error_vs_sink": "string|null (before_sink/after_sink)"
}
```

## 7. environment_status.json — Environment Status

```json
{
  "mode": "string (full=complete environment/partial=partially available)",
  "framework": "string (Laravel/ThinkPHP/Yii2/Symfony/CakePHP/CodeIgniter/Native)",
  "framework_version": "string (e.g., 8.1.0)",
  "php_version": "string (e.g., 7.4)",
  "db_type": "string (mysql/pgsql/sqlite)",
  "startup_rounds": "number (startup attempt rounds)",
  "fixes_applied": ["string (fix records, e.g., 'composer require xxx')"],
  "web_accessible": "boolean (whether Web is accessible)",
  "routes_accessible": "number (Type A route count)",
  "routes_error": "number (Type B route count)",
  "routes_inaccessible": "number (Type C route count)",
  "routes_error_details": [{
    "route": "string (route path)",
    "error": "string (error message)",
    "reason": "string (cause analysis)",
    "impact": "string (impact on audit)"
  }],
  "xdebug_working": "boolean",
  "db_tables_total": "number (total database tables)",
  "db_tables_from_migration": "number (tables from migration files)",
  "db_tables_from_inference": "number (tables from inference)",
  "disabled_features": ["string (features disabled due to missing dependencies)"],
  "encrypted_files": ["string (ionCube/Zend Guard encrypted file paths)"]
}
```

## 8. dep_risk.json — Dependency Risk

```json
[{
  "package": "string (package name, e.g., laravel/framework)",
  "installed_version": "string (installed version)",
  "cve": "string (CVE identifier)",
  "severity": "string (CRITICAL/HIGH/MEDIUM/LOW)",
  "type": "string (vulnerability type, e.g., RCE/SQLi/XSS)",
  "description": "string (vulnerability description)",
  "fixed_version": "string (fixed version)"
}]
```

## 9. exploit_result.json — Exploit Result (one per Sink)

```json
{
  "sink_id": "string (references priority_queue id, e.g., sink_001)",
  "route_url": "string (route path)",
  "sink_function": "string (Sink function name, e.g., DB::raw)",
  "specialist": "string (specialist agent name that executed the attack, e.g., sqli_auditor)",
  "route_type": "string (A/B/C)",
  "rounds_executed": "number (actual attack rounds executed)",
  "rounds_skipped": "number (rounds intelligently skipped)",
  "skip_reason": "string|null (reason for skipping)",
  "results": [{
    "round": "number (round number 1-8)",
    "strategy": "string (strategy name, e.g., basic_union_select)",
    "payload": "string (actual payload sent)",
    "injection_point": "string (injection point description, e.g., POST body param 'name')",
    "request": "string (complete HTTP request)",
    "response_status": "number (HTTP status code)",
    "response_body_snippet": "string (first 500 characters of response body)",
    "evidence_type": "string|null (evidence type: time_based/union_based/error_based/file_proof/blind etc.)",
    "evidence_detail": "string|null (evidence detail)",
    "result": "string (confirmed/suspected/failed)",
    "failure_reason": "string|null (failure reason analysis)"
  }],
  "race_condition_results": {
    "tested": "boolean (whether race condition was tested)",
    "concurrent_requests": "number (concurrent request count)",
    "result": "string|null (vulnerable/not_vulnerable)",
    "detail": "string|null (race condition vulnerability detail)"
  },
  "final_verdict": "string (confirmed/suspected/potential/not_vulnerable)",
  "confidence": "string (high/medium/low)"
}
```

## 9.5. exploit_plan.json — Attack Plan (Phase-4 Stage 1 output, one per Sink)

```json
{
  "sink_id": "string (references priority_queue id)",
  "specialist": "string (specialist agent name)",
  "analysis_summary": "string (static analysis summary: filter mechanisms, bypassable points, attack surface assessment)",
  "target_endpoint": "string (target URL)",
  "injection_points": [{
    "param_name": "string (parameter name)",
    "param_location": "string (query/body/header/cookie/path)",
    "data_type": "string (string/int/array/json)",
    "current_filters": ["string (identified filter functions)"],
    "bypass_strategies": ["string (bypass strategies)"]
  }],
  "attack_rounds": [{
    "round": "number (round 1-8)",
    "strategy": "string (strategy name)",
    "rationale": "string (why this strategy was chosen)",
    "payload_template": "string (payload template)",
    "expected_evidence": "string (expected evidence type)",
    "fallback": "string|null (fallback strategy on failure)"
  }],
  "waf_detection": {
    "detected": "boolean",
    "type": "string|null (ModSecurity/Cloudflare/Custom etc.)",
    "bypass_notes": "string|null"
  },
  "shared_findings_consumed": ["string (consumed shared_findings entry keys)"],
  "estimated_rounds": "number (estimated attack rounds needed)"
}
```

### Exploit Result Summary — exploit_summary.json

Generated by the main orchestrator after all of Phase-4 is complete:

```json
{
  "total_sinks": "number (total Sink count)",
  "type_a_tested": "number (Type A live-tested count)",
  "type_b_after_tested": "number (Type B after_sink tested count)",
  "type_b_before_static": "number (Type B before_sink static analysis count)",
  "type_c_static": "number (Type C static analysis count)",
  "vulnerabilities_confirmed": "number (confirmed vulnerability count)",
  "vulnerabilities_suspected": "number (suspected vulnerability count)",
  "race_conditions_found": "number (race condition vulnerability count)"
}
```

---

## Deduplication Rules

Vulnerability deduplication uses **"file path + line number + Sink function"** as the unique key. When multiple sources point to the same location, records are merged and the source count is annotated (more sources = higher confidence).

---

## 10. race_condition_result.json — Race Condition Test Result

```json
{
  "sink_id": "string (references priority_queue id)",
  "route_url": "string (route path)",
  "specialist": "race_condition_auditor",
  "test_type": "string (TOCTOU/double_spend/token_replay/rate_limit/session_race/db_transaction)",
  "rounds_executed": "number",
  "results": [{
    "round": "number",
    "strategy": "string",
    "concurrent_requests": "number (concurrent request count)",
    "total_attempts": "number (total attempt count)",
    "success_count": "number (successful trigger count)",
    "success_rate": "number (success rate 0.0-1.0)",
    "time_window_ms": "number (attack time window in milliseconds)",
    "payload": "string",
    "evidence_detail": "string|null",
    "result": "string (confirmed/suspected/failed)",
    "baseline_comparison": "string (difference description compared to normal requests)"
  }],
  "final_verdict": "string (confirmed/suspected/potential/not_vulnerable)",
  "confidence": "string (high/medium/low)"
}
```

## 11. crypto_audit_result.json — Cryptographic Audit Result

```json
{
  "sink_id": "string",
  "category": "string (password_hashing/random_number/encryption/jwt/session_token/signature/key_management)",
  "specialist": "crypto_auditor",
  "rounds_executed": "number",
  "results": [{
    "round": "number",
    "strategy": "string",
    "target_function": "string (audited cryptographic function)",
    "target_file": "string (file path)",
    "target_line": "number",
    "weakness": "string (weakness description)",
    "evidence": "string (evidence: predictable output/weak key/algorithm downgrade etc.)",
    "exploitability": "string (directly exploitable/requires conditions/theoretically possible)",
    "result": "string (confirmed/suspected/failed)"
  }],
  "final_verdict": "string",
  "confidence": "string"
}
```

## 12. nosql_result.json — NoSQL Injection Test Result

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
    "query_semantic_change": "boolean (whether query semantics were altered)",
    "evidence_detail": "string|null",
    "result": "string (confirmed/suspected/failed)"
  }],
  "final_verdict": "string",
  "confidence": "string"
}
```

## 13. wordpress_result.json — WordPress Audit Result

```json
{
  "sink_id": "string",
  "specialist": "wordpress_auditor",
  "scope": "string (core/plugin/theme)",
  "component_name": "string (WordPress core / plugin name / theme name)",
  "component_version": "string",
  "rounds_executed": "number",
  "results": [{
    "round": "number",
    "strategy": "string (core_cve/plugin_audit/xmlrpc/rest_api/shortcode/nonce_bypass/editor_rce)",
    "endpoint": "string",
    "payload": "string",
    "evidence_detail": "string|null",
    "cve_id": "string|null (associated CVE identifier)",
    "result": "string (confirmed/suspected/failed)"
  }],
  "final_verdict": "string",
  "confidence": "string"
}
```

## 14. business_logic_result.json — Business Logic Audit Result

```json
{
  "sink_id": "string",
  "route_url": "string",
  "specialist": "business_logic_auditor",
  "business_flow": "string (affected business flow description)",
  "rounds_executed": "number",
  "results": [{
    "round": "number",
    "strategy": "string (price_tamper/coupon_abuse/payment_bypass/flow_skip/negative_value/sms_bomb/state_machine)",
    "payload": "string",
    "business_impact": "string (business impact description: financial loss/data leak/flow bypass etc.)",
    "state_before": "string (state before operation)",
    "state_after": "string (state after operation)",
    "persisted": "boolean (whether anomalous state is persisted)",
    "evidence_detail": "string|null",
    "result": "string (confirmed/suspected/failed)"
  }],
  "final_verdict": "string",
  "confidence": "string"
}
```

## 15. credentials.json Extended Fields

In addition to the existing anonymous/authenticated/admin fields, the following optional fields are added:

```json
{
  "anonymous": {},
  "authenticated": { "...existing fields..." },
  "admin": { "...existing fields..." },
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
    "header_name": "string (e.g., X-API-Key)",
    "location": "string (header/query/cookie)"
  },
  "multi_tenant": [{
    "tenant_id": "string",
    "tenant_name": "string",
    "credentials": { "...same structure as authenticated..." }
  }],
  "websocket": {
    "url": "string (ws://...)",
    "auth_message": "string|null (auth message sent after connection)"
  }
}
```

## 16. CVSS 3.1 Scoring Additional Fields

MAY be appended to each record in priority_queue.json:

```json
{
  "...existing fields...",
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
  "attack_surface_score": "number (0-100, attack surface quantitative score)",
  "business_impact": ["string (financial/pii_exposure/auth_bypass/service_disruption)"]
}
```

---

## 17. attack_graph.json — Attack Graph

```json
{
  "generated_at": "string (ISO-8601)",
  "total_nodes": "number (total vulnerability node count)",
  "total_edges": "number (total edge count)",
  "total_paths": "number (total attack path count)",
  "nodes": [{
    "node_id": "string (V-001 format)",
    "vuln_type": "string",
    "sub_type": "string",
    "endpoint": "string",
    "confidence": "string (confirmed/highly_suspected/potential_risk)",
    "output_data": "string (data/capability produced by this vulnerability)",
    "required_access": "string (anonymous/authenticated/admin)",
    "grants_access": "string (access level gained)",
    "severity": "string (Critical/High/Medium/Low/Info)"
  }],
  "edges": [{
    "from": "string (source node_id)",
    "to": "string (target node_id)",
    "relationship": "string (credential_reuse/token_forge/privilege_escalation/data_extraction/lateral_movement)",
    "description": "string"
  }],
  "paths": [{
    "path_id": "string (P-001 format)",
    "score": "number (path score)",
    "confidence": "string (high/medium/low)",
    "nodes": ["string (ordered node_id list)"],
    "entry_point": "string",
    "final_impact": "string",
    "narrative": "string (attack narrative)",
    "remediation_priority": "string (P0/P1/P2)"
  }],
  "escalation_patterns": [{
    "pattern_name": "string",
    "involved_vulns": ["string (node_id list)"],
    "individual_severity": "string",
    "combined_severity": "string",
    "explanation": "string"
  }],
  "mermaid_diagram": "string (complete Mermaid diagram code)"
}
```

## 18. correlation_report.json — Cross-Auditor Correlation Report

```json
{
  "generated_at": "string (ISO-8601)",
  "escalations": [{
    "pattern_name": "string (risk escalation pattern name)",
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
    "matched_pattern": "string (e.g., FP-SQL-001)"
  }]
}
```

## 19. audit_session.db → shared_findings — Realtime Shared Findings (SQLite)

Record structure per entry:

```json
{
  "timestamp": "string (ISO-8601)",
  "source_agent": "string (writing agent name)",
  "finding_type": "string (credential|internal_url|secret_key|endpoint|bypass_method|config_value)",
  "priority": "string (critical|high|medium)",
  "data": {
    "key": "string (finding name/identifier)",
    "value": "string (finding value)",
    "context": "string (finding context description)",
    "source_location": "string (finding source)"
  },
  "target_agents": ["string (suggested consumer agent names)"],
  "consumed_by": ["string (agent names that have consumed this)"]
}
```

## 20. second_order Tracking Files

### store_points.jsonl — Storage Point Records

```json
{
  "store_id": "string (STORE-001 format)",
  "endpoint": "string (write endpoint)",
  "param": "string (parameter name)",
  "storage": "string (database/file/cache/session)",
  "table": "string (table name, for database storage)",
  "column": "string (column name)",
  "sanitization": "string (none/partial/full)",
  "sanitization_detail": "string",
  "recorded_by": "string (recording agent name)"
}
```

### use_points.jsonl — Usage Point Records

```json
{
  "use_id": "string (USE-001 format)",
  "endpoint": "string (usage endpoint)",
  "source_table": "string",
  "source_column": "string",
  "usage_sink": "string (Sink function name)",
  "usage_file": "string (file path)",
  "usage_line": "number",
  "output_sanitization": "string (none/partial/full)",
  "output_sanitization_detail": "string",
  "recorded_by": "string"
}
```

### correlations.json — Correlation Results

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

## 21. remediation_summary.json — Remediation Summary

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
    "file": "string (modified source file path)",
    "patch_file": "string (patch file path)",
    "fix_strategy": "string (fix strategy description)",
    "breaking_change": "boolean",
    "verification": "string (verification recommendation)"
  }]
}
```

## 22. poc_summary.json — PoC Script Summary

```json
{
  "generated_at": "string (ISO-8601)",
  "total_confirmed": "number",
  "poc_generated": "number",
  "poc_skipped": "number",
  "scripts": [{
    "sink_id": "string",
    "vuln_type": "string",
    "file": "string (PoC script filename)",
    "endpoint": "string",
    "auth_required": "boolean",
    "curl_command": "string (equivalent curl command)"
  }]
}
```

## 23. evidence_quality Extended Fields

Appended to each finding in team4_progress.json:

```json
{
  "...existing fields...",
  "evidence_quality": "number (0-10, evidence quality score)",
  "cross_validation": {
    "variant_payload": "string (variant payload)",
    "variant_result": "string (success/failed)",
    "independent_reproduction": "boolean"
  },
  "false_positive_check": {
    "checked": "boolean",
    "matched_patterns": ["string (matched false positive pattern IDs)"],
    "conclusion": "string (not_false_positive/false_positive/uncertain)",
    "reason": "string"
  }
}
```

## 24. auth_gap_report.json

Route security gap report (Phase-2 route_mapper output → Phase-3 auth_simulator input).

```json
{
  "generated_by": "route_mapper",
  "total_routes": "number",
  "unprotected_routes": [
    {
      "path": "string (route path)",
      "method": "string (HTTP method)",
      "controller": "string (controller#method)",
      "missing_middleware": ["string"],
      "risk_level": "high | medium | low"
    }
  ],
  "summary": {
    "total_unprotected": "number",
    "high_risk_count": "number"
  }
}
```

## 25. auth_credentials.json

Authentication credentials and role matrix (generated and consumed internally by Phase-3 auth_simulator).

```json
{
  "generated_by": "auth_simulator",
  "credentials": [
    {
      "role": "string (role name: admin/editor/subscriber/anonymous)",
      "username": "string",
      "password": "string",
      "token": "string (optional, JWT/session)",
      "auth_method": "cookie | bearer | basic | api_key",
      "permissions": ["string (known permission list)"]
    }
  ],
  "role_hierarchy": {
    "admin": ["editor", "subscriber", "anonymous"],
    "editor": ["subscriber", "anonymous"],
    "subscriber": ["anonymous"]
  },
  "test_matrix": [
    {
      "action": "string (test operation description)",
      "endpoint": "string (API endpoint)",
      "expected_roles": ["string (roles that should have permission)"],
      "test_with_roles": ["string (roles actually tested)"]
    }
  ]
}
```

## 26. severity_score Extended Fields (Three-Dimensional Severity Scoring)

Appended to the `severity_score` field in each exploit_result:

```json
{
  "severity_score": {
    "reachability": "number (0-10, reachability: anonymous=10, authenticated=7, admin=4, internal_only=2)",
    "impact": "number (0-10, impact: RCE=10, SQLi_data=9, file_write=8, XSS_stored=7, info_leak=5, config=4)",
    "complexity": "number (0-10, exploitation complexity inverted: trivial=10, low=8, medium=5, high=3, theoretical=1)",
    "weighted_score": "number (= R×0.40 + I×0.35 + C×0.25)",
    "cvss_estimate": "number (≈ weighted_score, 0-10 range)"
  }
}
```

Scoring guidelines:
- **Reachability (R)**: Based on auth_level — anonymous routes score highest
- **Impact (I)**: Based on vulnerability type — RCE > SQLi > file write > XSS > information leak > config issues
- **Complexity (C)**: Easier to exploit = higher score — directly exploitable=10, multi-step=5, theoretical only=1
- **Weighted Score**: `Score = R × 0.40 + I × 0.35 + C × 0.25`
- **CVSS Estimate**: Use weighted_score directly as CVSS approximation

## 27. evidence Extended Fields (EVID Evidence References)

Appended to the `evidence` field in each exploit_result:

```json
{
  "evidence": {
    "EVID_XXX_YYY": "string (evidence description: file:line + key information)",
    "EVID_XXX_ZZZ": "[not obtained: reason]"
  }
}
```

Reference specification: see `shared/evidence_contract.md`.
