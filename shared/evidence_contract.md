# 证据合约系统（Evidence Contract System）

本文件定义标准化的证据点 ID 字典（EVID_*），用于所有 Phase-4 专家输出结论时的证据引用。
灵感来自 0xShe/PHP-Code-Audit-Skill 的 Trace-Gate 机制，适配本项目的动态攻击架构。

---

## 核心原则

1. **每个漏洞结论必须引用至少一个 EVID_* 证据点**，无证据 = 无结论
2. **auth_matrix 不可变传播** — `auth_matrix.json` 由 Phase-2 生成后，Phase-4 所有 Auditor 只读引用、禁止修改。`prerequisite_conditions.auth_requirement` 必须与 `auth_matrix.json` 中该路由的 `auth_level` 严格一致，不一致则质检不通过
2. **证据来源优先级**: 动态攻击响应 > Xdebug trace > 静态源码分析
3. **置信度与证据完备性挂钩**:
   - `✅已确认` → 所有必填 EVID 项均有实证（HTTP 请求/响应 + 源码定位）
   - `⚠️高度疑似` → 必填 EVID 项部分缺失，但有合理推断链
   - `⚡需验证` → 仅有静态源码级证据，未经动态验证
4. **EVID 缺失处理**: 若某必填 EVID 无法获取，标注 `EVID_XXX: [未获取:原因]`，结论自动降级

---

## 证据点字典

### CMD — 命令执行（rce_auditor）

| 证据点 ID | 说明 | 必填 |
|---|---|---|
| `EVID_CMD_EXEC_POINT` | 命令执行函数位置 (file:line)，如 system/exec/passthru/shell_exec/popen | ✅ |
| `EVID_CMD_STRING_CONSTRUCTION` | 命令字符串构造/拼接位置，参数如何进入命令 | ✅ |
| `EVID_CMD_USER_PARAM_MAPPING` | 用户可控参数到命令片段的完整映射（Source→Sink 路径） | ✅ |
| `EVID_CMD_EXECUTION_RESPONSE` | 攻击请求的 HTTP 响应 + 命令执行证据（回显/时间差/外带） | 确认时必填 |

### SQL — SQL 注入（sqli_auditor）

| 证据点 ID | 说明 | 必填 |
|---|---|---|
| `EVID_SQL_EXEC_POINT` | SQL 执行函数/语句位置 (file:line) | ✅ |
| `EVID_SQL_STRING_CONSTRUCTION` | SQL 字符串构造/拼接位置 | ✅ |
| `EVID_SQL_USER_PARAM_MAPPING` | 用户可控参数到 SQL 片段的映射 | ✅ |
| `EVID_SQL_EXECUTION_RESPONSE` | 注入 Payload 的响应差异（报错/布尔/时间盲注证据） | 确认时必填 |

### NOSQL — NoSQL 注入（nosql_auditor）

| 证据点 ID | 说明 | 必填 |
|---|---|---|
| `EVID_NOSQL_QUERY_CONSTRUCTION` | NoSQL 查询构造点 (find/update/delete) | ✅ |
| `EVID_NOSQL_USER_INPUT_MAPPING` | 用户输入进入查询条件结构的证据 | ✅ |
| `EVID_NOSQL_OPERATOR_INJECTION` | operator 注入字段证据 ($ne/$gt/$or/$where) | ✅ |
| `EVID_NOSQL_QUERY_SEMANTIC_DIFF` | 正常查询 vs 注入查询的返回结果差异 | 确认时必填 |

### FILE — 文件包含（lfi_auditor）

| 证据点 ID | 说明 | 必填 |
|---|---|---|
| `EVID_FILE_WRAPPER_PREFIX` | 流包装前缀使用方式 (php:///phar:///zip://) | ✅ |
| `EVID_FILE_RESOLVED_TARGET` | 包含/读取的最终解析目标路径 | ✅ |
| `EVID_FILE_INCLUDE_EXEC_BOUNDARY` | include/require 的执行边界（执行 PHP vs 仅读取） | ✅ |
| `EVID_FILE_TRAVERSAL_RESPONSE` | 路径遍历攻击的 HTTP 响应（文件内容泄露证据） | 确认时必填 |

### WRITE — 文件写入（filewrite_auditor）

| 证据点 ID | 说明 | 必填 |
|---|---|---|
| `EVID_WRITE_CALLSITE` | 写入函数调用位置 (file_put_contents/fwrite/move_uploaded_file) | ✅ |
| `EVID_WRITE_DESTPATH_RESOLVED` | 目的路径最终解析结果（是否逃逸 base 目录） | ✅ |
| `EVID_WRITE_CONTENT_SOURCE` | 写入内容与用户可控输入的映射 | ✅ |
| `EVID_WRITE_EXEC_ACCESSIBILITY` | 写入后文件的可执行性/可访问性证据 | ✅ |
| `EVID_WRITE_UPLOAD_RESPONSE` | 上传/写入攻击的 HTTP 响应 + webshell 访问证据 | 确认时必填 |

### SSRF — 服务端请求伪造（ssrf_auditor）

| 证据点 ID | 说明 | 必填 |
|---|---|---|
| `EVID_SSRF_URL_NORMALIZATION` | URL 归一化处理步骤 | ✅ |
| `EVID_SSRF_FINAL_URL` | 发起请求前的最终 URL/Host/Port | ✅ |
| `EVID_SSRF_REDIRECT_CHAIN` | 重定向链跟踪证据（若有跟随跳转） | 条件必填 |
| `EVID_SSRF_DNS_INNER_BLOCK` | DNS/IP 解析与内网拦截判定 | ✅ |
| `EVID_SSRF_EXECUTION_RESPONSE` | SSRF 攻击响应（内网数据泄露/端口探测结果） | 确认时必填 |

### XSS — 跨站脚本 + SSTI（xss_ssti_auditor）

| 证据点 ID | 说明 | 必填 |
|---|---|---|
| `EVID_XSS_OUTPUT_POINT` | 响应输出点位置 (echo/模板输出/script 上下文) | ✅ |
| `EVID_XSS_USER_INPUT_MAPPING` | 用户输入进入输出的路径 | ✅ |
| `EVID_XSS_ESCAPE_STATUS` | 转义/编码/raw 输出状态证据 | ✅ |
| `EVID_XSS_PAYLOAD_REFLECTION` | Payload 在响应中的反射/执行证据 | 确认时必填 |
| `EVID_TPL_ENGINE_ENTRY` | 模板引擎渲染/解析入口 (SSTI 时必填) | 条件必填 |
| `EVID_TPL_EXPR_CONTROL` | 模板表达式是否可控证据 (SSTI 时必填) | 条件必填 |

### XXE — XML 外部实体注入（xxe_auditor）

| 证据点 ID | 说明 | 必填 |
|---|---|---|
| `EVID_XXE_PARSER_CALL` | XML 解析器调用位置 (DOMDocument/simplexml/XMLReader) | ✅ |
| `EVID_XXE_INPUT_SOURCE` | 输入流来源 (php://input/上传/参数) | ✅ |
| `EVID_XXE_ENTITY_SAFETY` | 外部实体/DOCTYPE 禁用配置证据 | ✅ |
| `EVID_XXE_EXECUTION_RESPONSE` | XXE Payload 的响应（文件读取/SSRF/RCE 证据） | 确认时必填 |

### DESER — 反序列化（deserial_auditor）

| 证据点 ID | 说明 | 必填 |
|---|---|---|
| `EVID_DESER_CALLSITE` | 反序列化调用位置 (unserialize/phar) | ✅ |
| `EVID_DESER_INPUT_SOURCE` | 入参用户可控来源 | ✅ |
| `EVID_DESER_GADGET_CHAIN` | POP chain / gadget 链路证据（类→魔术方法→敏感操作） | ✅ |
| `EVID_DESER_EXECUTION_RESPONSE` | 反序列化攻击的执行证据（命令回显/文件创建） | 确认时必填 |

### AUTH — 认证授权（authz_auditor）

| 证据点 ID | 说明 | 必填 |
|---|---|---|
| `EVID_AUTH_PATH_MATCH` | 路由进入受保护 handler 的匹配证据 | ✅ |
| `EVID_AUTH_TOKEN_JUDGMENT` | Token/Session 解码与判断逻辑 | ✅ |
| `EVID_AUTH_PERMISSION_CHECK` | 权限判断函数/条件语句执行证据 | ✅ |
| `EVID_AUTH_IDOR_OWNERSHIP` | IDOR 归属校验条件（WHERE owner_id/user_id） | 条件必填 |
| `EVID_AUTH_BYPASS_RESPONSE` | 越权访问/绕过的 HTTP 请求+响应 | 确认时必填 |

### CFG — 安全配置（config_auditor）

| 证据点 ID | 说明 | 必填 |
|---|---|---|
| `EVID_CFG_CONFIG_LOCATION` | 配置文件/环境变量位置 (.env/config/php.ini) | ✅ |
| `EVID_CFG_RUNTIME_SETTING` | 运行时设置代码位置 (ini_set/中间件) | 条件必填 |
| `EVID_CFG_IMPACT_SCOPE` | 受影响的路由/响应范围 | ✅ |
| `EVID_CFG_SECURITY_SWITCH` | 安全头/错误暴露/CORS/危险开关证据 | ✅ |

### INFOLEAK — 信息泄露（infoleak_auditor）

| 证据点 ID | 说明 | 必填 |
|---|---|---|
| `EVID_LEAK_SOURCE_POINT` | 信息泄露源位置 (file:line) | ✅ |
| `EVID_LEAK_DATA_TYPE` | 泄露数据类型（源码/凭证/内部路径/调试信息/堆栈） | ✅ |
| `EVID_LEAK_ACCESS_PATH` | 外部可达的访问路径证据 | ✅ |
| `EVID_LEAK_RESPONSE_CONTENT` | 实际泄露内容的 HTTP 响应证据 | 确认时必填 |

### RACE — 竞态条件（race_condition_auditor）

| 证据点 ID | 说明 | 必填 |
|---|---|---|
| `EVID_RACE_CRITICAL_SECTION` | 临界区代码位置（读取→检查→操作序列） | ✅ |
| `EVID_RACE_SHARED_RESOURCE` | 共享资源标识（数据库行/文件/缓存键） | ✅ |
| `EVID_RACE_WINDOW_ANALYSIS` | 竞态窗口分析（操作间隔/锁机制缺失） | ✅ |
| `EVID_RACE_STATISTICAL_RESULT` | 并发测试统计结果（请求数/成功率/时间窗口，≥20次） | 确认时必填 |

### CRYPTO — 密码学（crypto_auditor）

| 证据点 ID | 说明 | 必填 |
|---|---|---|
| `EVID_CRYPTO_ALGORITHM_USAGE` | 加密/哈希算法使用位置及上下文 | ✅ |
| `EVID_CRYPTO_KEY_MANAGEMENT` | 密钥管理（硬编码/弱密钥/可预测） | ✅ |
| `EVID_CRYPTO_SECURITY_CONTEXT` | 安全场景判定（密码存储 vs 缓存键 vs 签名） | ✅ |
| `EVID_CRYPTO_EXPLOIT_PROOF` | 实际利用证据（破解结果/伪造签名/预测随机数） | 确认时必填 |

### WP — WordPress 专项（wordpress_auditor）

| 证据点 ID | 说明 | 必填 |
|---|---|---|
| `EVID_WP_COMPONENT_SCOPE` | 影响范围（核心/插件名+版本/主题名+版本） | ✅ |
| `EVID_WP_HOOK_ENTRY` | Hook/Action/Filter 入口 (wp_ajax/xmlrpc/shortcode) | ✅ |
| `EVID_WP_NONCE_STATUS` | Nonce 校验状态证据 | 条件必填 |
| `EVID_WP_CVE_VERSION_MATCH` | CVE 版本匹配验证（当前版本 ∈ 受影响范围） | 条件必填 |
| `EVID_WP_EXPLOIT_RESPONSE` | 攻击 HTTP 请求+响应 | 确认时必填 |

### BIZLOGIC — 业务逻辑（business_logic_auditor）

| 证据点 ID | 说明 | 必填 |
|---|---|---|
| `EVID_BIZ_FLOW_DESCRIPTION` | 完整业务流程描述（正常路径） | ✅ |
| `EVID_BIZ_BYPASS_POINT` | 被绕过的环节/校验位置 | ✅ |
| `EVID_BIZ_STATE_PERSISTENCE` | 绕过后状态是否被持久化（数据库/文件变更） | ✅ |
| `EVID_BIZ_EXPLOIT_RESPONSE` | 业务逻辑攻击的完整请求链+响应 | 确认时必填 |

### CRLF — CRLF 注入 / HTTP 响应拆分（crlf_auditor）

| 证据点 ID | 说明 | 必填 |
|---|---|---|
| `EVID_CRLF_INJECTION_POINT` | header()/setcookie()/mail() 调用位置 (file:line) | ✅ |
| `EVID_CRLF_USER_INPUT_PATH` | 用户输入到头部值的完整数据流（Source→header 参数） | ✅ |
| `EVID_CRLF_SANITIZATION_STATUS` | 换行符过滤/转义机制证据（有无 str_replace/preg_replace/header 参数校验） | ✅ |
| `EVID_CRLF_INJECTION_RESPONSE` | 注入成功的 HTTP 响应（含注入的头部/拆分的响应体） | 确认时必填 |

### CSRF — 跨站请求伪造（csrf_auditor）

| 证据点 ID | 说明 | 必填 |
|---|---|---|
| `EVID_CSRF_ENDPOINT_IDENTITY` | 受影响的状态变更端点 (METHOD /path) + 对应的业务操作描述 | ✅ |
| `EVID_CSRF_TOKEN_STATUS` | Token 存在性/验证逻辑/中间件配置证据 | ✅ |
| `EVID_CSRF_SAMESITE_STATUS` | SameSite cookie 属性配置及其对跨站请求的影响 | ✅ |
| `EVID_CSRF_CROSS_ORIGIN_RESPONSE` | 跨域请求成功执行状态变更的 HTTP 请求+响应证据 | 确认时必填 |

### SESS — Session/Cookie 安全（session_auditor）

| 证据点 ID | 说明 | 必填 |
|---|---|---|
| `EVID_SESS_CONFIG_STATE` | php.ini / runtime session 配置项及安全等级评估 | ✅ |
| `EVID_SESS_COOKIE_FLAGS` | 实际 Set-Cookie 响应头中的 HttpOnly/Secure/SameSite/Path/Domain 值 | ✅ |
| `EVID_SESS_LIFECYCLE_FLOW` | Session 创建→认证绑定→使用→销毁的完整生命周期代码路径 | ✅ |
| `EVID_SESS_EXPLOIT_RESPONSE` | Session 攻击的 HTTP 证据（fixation 成功/cookie 泄露/ID 可预测统计） | 确认时必填 |

### LDAP — LDAP 注入（ldap_auditor）

| 证据点 ID | 说明 | 必填 |
|---|---|---|
| `EVID_LDAP_QUERY_POINT` | ldap_search/ldap_bind/ldap_list 调用位置 (file:line) | ✅ |
| `EVID_LDAP_FILTER_CONSTRUCTION` | LDAP filter 字符串构造/拼接位置及方式 | ✅ |
| `EVID_LDAP_USER_INPUT_PATH` | 用户输入到 LDAP filter/DN 的完整数据流 | ✅ |
| `EVID_LDAP_INJECTION_RESPONSE` | LDAP 注入成功的响应差异（返回数据变化/认证绕过） | 确认时必填 |

### LOG — 日志安全（logging_auditor）

| 证据点 ID | 说明 | 必填 |
|---|---|---|
| `EVID_LOG_WRITE_POINT` | 日志写入函数/方法位置 (error_log/Log::/syslog 等) (file:line) | ✅ |
| `EVID_LOG_CONTENT_ANALYSIS` | 日志内容中的敏感数据/注入可能性/格式化缺陷证据 | ✅ |
| `EVID_LOG_ACCESS_CONTROL` | 日志文件路径、权限、Web 可达性证据 | ✅ |
| `EVID_LOG_EXPLOIT_RESPONSE` | 日志注入或日志包含攻击的 HTTP 响应证据 | 确认时必填 |

---

## 使用规范

### 1. 输出格式

每个漏洞结论必须包含 `evidence` 字段，列出引用的 EVID：

```json
{
  "sink_id": "SINK-042",
  "vuln_type": "sqli",
  "status": "confirmed",
  "evidence": {
    "EVID_SQL_EXEC_POINT": "app/Models/User.php:89 — DB::select(\"SELECT * FROM users WHERE id = $id\")",
    "EVID_SQL_STRING_CONSTRUCTION": "app/Http/Controllers/UserController.php:34 — $id = $request->input('id') 直接拼接",
    "EVID_SQL_USER_PARAM_MAPPING": "GET /api/user?id={user_input} → UserController::show() → User::findRaw($id) → DB::select()",
    "EVID_SQL_EXECUTION_RESPONSE": "GET /api/user?id=1'+OR+1=1-- → HTTP 200, 返回全部用户数据（正常仅返回 1 条）"
  }
}
```

### 2. 证据缺失标注

```json
{
  "EVID_SQL_EXECUTION_RESPONSE": "[未获取: 容器未启动，无法发送动态请求]"
}
```

此时结论自动从 `confirmed` 降级为 `suspected`。

### 3. 与 anti_hallucination.md 的关系

本证据合约是 anti_hallucination.md 规则 2（结论必须附带源码片段）、规则 4（调用链每环必须有代码支撑）、规则 10（已确认漏洞必须有完整复现材料）的**结构化实现**。anti_hallucination.md 定义"什么必须做"，本文件定义"具体怎么做"。

---

## 三维评分要求

每个漏洞的 `exploits/{sink_id}.json` 必须包含 `severity` 对象，按 `shared/severity_rating.md` 标准填写：

| 必填字段 | 类型 | 说明 |
|----------|------|------|
| reachability | 0-3 | 与 prerequisite_conditions.auth_requirement 对应 |
| reachability_reason | string | 判定依据，不得为空 |
| impact | 0-3 | 与漏洞类型和实际影响对应 |
| impact_reason | string | 判定依据，不得为空 |
| complexity | 0-3 | 反转计分：越容易利用分越高 |
| complexity_reason | string | 判定依据，不得为空 |
| score | number | `R×0.40 + I×0.35 + C×0.25`（自行计算） |
| cvss | number | `(score / 3.0) × 10.0` |
| level | C/H/M/L | 按 score 区间映射 |
| vuln_id | string | 格式 `{Level}-{Type}-{Sequence}`，如 `C-RCE-001` |

**一致性规则：**
- `severity.score ≥ 2.70` 但 `evidence_score < 7` → 矛盾，质检不通过
- `exploitability_judgment = "not_exploitable"` → `severity.score` 强制为 0
- reason 字段为空 → 质检不通过

---

## 前置条件要求

每个漏洞的 `exploits/{sink_id}.json` 必须包含 `prerequisite_conditions` 对象：

| 必填字段 | 类型 | 说明 |
|----------|------|------|
| auth_requirement | enum | `anonymous` / `authenticated` / `admin` / `internal_network` |
| bypass_method | string\|null | 鉴权绕过方法（如"IDOR via user_id"），无绕过则 null |
| other_preconditions | string[] | 其他前提条件列表（如 `["APP_DEBUG=true", "allow_url_include=On"]`） |
| exploitability_judgment | enum | `directly_exploitable` / `conditionally_exploitable` / `not_exploitable` |

**降级规则：**
- `not_exploitable` → `final_verdict` 最高为 `potential`，`confidence` 最高为 `low`
- `conditionally_exploitable` → `severity.complexity` 降 1 级（更保守估计）
- `auth_requirement` 必须与 `auth_matrix.json` 中该路由的 `auth_level` 一致
