# 质检校验模板（强制填充式）

> 本文件是 quality-checker Agent 的唯一校验依据。质检员必须逐行填写「实际」和「状态」列，禁止用一句话概括或省略任何校验项。

---

## ⛔ 6 条铁律（违反任何一条 → 自动判定不通过）

| # | 铁律 | 说明 |
|---|------|------|
| R1 | **禁止新增章节** | 校验报告只能包含本模板定义的章节，不得自行添加任何章节或子节 |
| R2 | **禁止删除/重排章节** | 所有章节必须按本模板定义的顺序出现，不得跳过、合并或调换 |
| R3 | **禁止修改表格列** | 校验表格的列（序号/校验项/预期/实际/状态）不得增删或改名 |
| R4 | **禁止残留占位符** | 提交时所有【填写】必须已替换为实际内容；`grep '【填写】'` 命中数必须为 0 |
| R5 | **禁止合并多个校验报告** | 每次校验产出独立报告，不得将多个被校验 Agent 的结果混写在同一份报告中 |
| R6 | **禁止修改校验项标题** | 「校验项」列的文字是固定的，质检员只能填写「实际」和「状态」列 |

**自动检测脚本（质检员必须在提交前执行）：**
```bash
# 检测残留占位符
grep -rn '【填写】\|TODO\|TBD\|PLACEHOLDER' "$QC_REPORT" && echo "❌ R4 违规：存在残留占位符" && exit 1
# 检测 JSON 语法（如适用）
python3 -m json.tool "$OUTPUT_FILE" > /dev/null 2>&1 || echo "❌ JSON 语法错误"
# 检测编码
file --mime-encoding "$QC_REPORT" | grep -qE 'utf-8|us-ascii' || echo "❌ 编码非 UTF-8"
```

---

## 通用报告结构

每份校验报告必须包含以下三个部分，缺一不可：

````markdown
# 校验报告：{被校验 Agent 名称}

## 基本信息
- 质检员：quality-checker-{N}
- 校验对象：{被校验 Agent 名称}
- 所属阶段：{Phase-1 / Phase-2 / Phase-3 / Phase-4 / Phase-4.5 / Phase-5}
- 校验文件：{实际读取的输出文件路径，多个用逗号分隔}
- 关联 Schema：{对应的 schemas/*.schema.json 文件路径，无则标注 N/A}

## 逐项校验结果

{使用下方对应阶段的校验清单表格，逐行填写「实际」和「状态」列}

## 最终判定
- 状态：**✅通过** / **❌不通过**
- 通过项：{M}/{N}
- 不通过项清单（如有）：
  - {序号}. {校验项名称}：{具体缺失内容及修复要求}
- 修复要求：{针对不通过项，要求被校验 Agent 补充什么}
````

> **铁律**：质检员生成的每份报告必须严格遵循此结构。缺少任何部分 → 报告无效，需重新生成。

---

## 阶段 1：环境构建校验（Team-1 输出）

**被校验 Agent:** docker_builder（Team-1）
**校验依据文件:** `$WORK_DIR/environment_status.json`
**关联 Schema:** `schemas/environment_status.schema.json`

| 序号 | 校验项 | 预期 | 实际 | 状态 |
|:----:|--------|------|------|:----:|
| 1 | 容器状态 | 所有服务 `running`，无 `restarting`/`exited` | 【填写】 | ⬜ |
| 2 | PHP 版本一致性 | 实际版本 = environment_status.json.php_version | 【填写】 | ⬜ |
| 3 | PHP 必需扩展 | 已加载: pdo, pdo_mysql/pdo_pgsql, mbstring, xml, curl, json, Xdebug | 【填写】 | ⬜ |
| 4 | Web 可访问 | `http://nginx:80/` 返回 200/301/302 | 【填写】 | ⬜ |
| 5 | 数据库连接 | PDO 连接成功（MySQL 或 PostgreSQL） | 【填写】 | ⬜ |
| 6 | Xdebug trace 模式 | `xdebug.mode` 包含 `trace` | 【填写】 | ⬜ |
| 7 | SSRF 靶标可达 | `http://ssrf-target:80/` 返回 200 | 【填写】 | ⬜ |
| 8 | 路由分类完成 | routes_accessible + routes_error + routes_inaccessible > 0 | 【填写】 | ⬜ |
| 9 | JSON Schema 校验 | environment_status.json 通过 schema 验证 | 【填写】 | ⬜ |

**量化阈值:**
- 必需服务启动成功率 = **100%**（项 1-4 全 PASS 才通过）
- 项 5-9 允许部分 FAIL（记录降级影响）

**最终判定:**
- 状态: 【填写：✅通过 / ❌不通过】
- 通过项比例: 【填写：M/9】
- 不通过项清单: 【填写：列出序号+具体问题】
- 修复要求: 【填写：针对每个不通过项的修复指令】
- 降级影响: 【填写：若项 5-9 有 FAIL，说明降级范围】

**失败重做规则:**
- 第 1 次不通过 → 返回 docker_builder 按修复要求重做
- 第 2 次不通过 → 更换修复策略重做
- 第 3 次不通过 → 降级为 `partial` 模式（跳过 Phase 3 动态追踪，Team-4 退回 context_pack 分析）

---

## 阶段 2：静态侦察校验（Team-2 输出）

**被校验 Agent:** route_scanner, auth_analyzer, ast_scanner, dep_scanner, context_builder, priority_ranker（Team-2 全体）
**校验依据文件:** route_map.json, auth_matrix.json, ast_sinks.json, context_packs/, priority_queue.json, dep_risk.json
**关联 Schema:** schemas/ 下对应 schema 文件

| 序号 | 校验项 | 预期 | 实际 | 状态 |
|:----:|--------|------|------|:----:|
| 1 | route_map.json 存在且非空 | 文件存在，路由数 > 0 | 【填写：路由数=?】 | ⬜ |
| 2 | 路由源码可定位 | 每条路由的 `controller` 文件 + `file:line` 在源码中真实存在 | 【填写：抽验3条结果】 | ⬜ |
| 3 | auth_matrix 覆盖率 | 覆盖率 = matrix条目数/routes条目数 × 100% ≥ **80%** | 【填写：覆盖率=?%】 | ⬜ |
| 4 | ast_sinks.json 完整性 | 文件存在，Sink 数 > 0，每个 Sink 有 file+line | 【填写：Sink数=?】 | ⬜ |
| 5 | Sink 源码抽验 | 随机抽样 3 个 Sink，源码中确实存在该函数调用 | 【填写：抽验结果】 | ⬜ |
| 6 | context_packs 完整性 | 目录存在，断点率 = 有断点包数/总包数 ≤ **50%** | 【填写：断点率=?%】 | ⬜ |
| 7 | context_pack 代码完整 | 每层 `code` 字段非空（有实际代码） | 【填写：空代码层数=?】 | ⬜ |
| 8 | priority_queue P0 合理性 | 0 < P0 数 ≤ 20，无重复条目 | 【填写：P0=?, 重复=?】 | ⬜ |
| 9 | 路由覆盖率 | 已分析路由数/总路由数 × 100% ≥ **90%** | 【填写：覆盖率=?%】 | ⬜ |
| 10 | Sink 扫描覆盖率 | 已识别 Sink 类型数/sink_definitions.md 定义类型数 ≥ **85%** | 【填写：覆盖率=?%】 | ⬜ |
| 11 | JSON Schema 校验 | 所有输出文件通过对应 schema 验证 | 【填写：通过数/总数】 | ⬜ |
| 12 | 工具扫描结果 | psalm_taint.json + progpilot.json 存在（允许 status=failed） | 【填写：存在情况】 | ⬜ |
| 13 | dep_risk.json 完整性 | 依赖风险评估存在，已查外部 CVE 源 | 【填写：CVE 匹配数=?】 | ⬜ |

**量化阈值汇总:**
- auth_matrix 覆盖率 ≥ **80%**（WARN 阈值，低于此降级处理）
- 路由覆盖率 ≥ **90%**
- Sink 扫描覆盖率 ≥ **85%**
- context_pack 断点率 ≤ **50%**
- P0 数量: 0 < P0 ≤ 20

**最终判定:**
- 状态: 【填写：✅通过 / ❌不通过】
- 通过项比例: 【填写：M/13】
- 不通过项清单: 【填写：列出序号+具体问题】
- 修复要求: 【填写：针对每个不通过项的具体修复指令】
- 覆盖率汇总: 路由=【?%】/ Auth=【?%】/ Sink=【?%】/ 断点率=【?%】

**必须通过项:** 1, 4, 8（route_map存在 + ast_sinks存在 + priority_queue合理）
**允许 WARN 项:** 3, 6, 9, 10, 11, 12, 13

---

## 阶段 3：动态追踪校验（Team-3 输出）

**被校验 Agent:** credential_harvester, trace_executor（Team-3）
**校验依据文件:** credentials.json, traces/*.json
**关联 Schema:** schemas/credentials.schema.json, schemas/trace_record.schema.json

| 序号 | 校验项 | 预期 | 实际 | 状态 |
|:----:|--------|------|------|:----:|
| 1 | credentials.json 存在 | 文件存在且非空 | 【填写】 | ⬜ |
| 2 | 凭证有效性 - anonymous | 无需认证端点可访问 | 【填写】 | ⬜ |
| 3 | 凭证有效性 - authenticated | 使用凭证访问受保护端点返回 200 | 【填写】 | ⬜ |
| 4 | 凭证有效性 - admin | 使用凭证访问管理端点返回 200 | 【填写】 | ⬜ |
| 5 | 凭证可用率 | 3级凭证中有效数 ≥ **1** | 【填写：有效数=?/3】 | ⬜ |
| 6 | 调用链非空 | 每份 trace_record 的 `call_chain` 非空 | 【填写：空链数=?】 | ⬜ |
| 7 | 调用链结构完整 | 链首=入口文件，链尾=目标 Sink，中间无不合理跳跃 | 【填写：抽验3条结果】 | ⬜ |
| 8 | 调用链完整率 | 完整链数/总链数 × 100% ≥ **70%** | 【填写：完整率=?%】 | ⬜ |
| 9 | 动态绑定已解析 | 所有 `dynamic_bindings` 的 `resolved` 字段非空 | 【填写：未解析数=?】 | ⬜ |
| 10 | 过滤函数标注 | 所有 `filters_encountered` 有 `effective` + `reason` | 【填写：缺失数=?】 | ⬜ |
| 11 | 与 context_packs 交叉验证 | 动态 vs 静态调用链比对，差异已记录 | 【填写：差异数=?】 | ⬜ |
| 12 | 类型 B 路由处理 | `error_vs_sink` 已标注，before_sink 已退回 context_pack | 【填写：B类路由数=?】 | ⬜ |
| 13 | JSON Schema 校验 | traces/*.json + credentials.json 通过 schema 验证 | 【填写：通过数/总数】 | ⬜ |

**量化阈值汇总:**
- 凭证可用率 ≥ **1/3 级别**
- 调用链完整率 ≥ **70%**

**最终判定:**
- 状态: 【填写：✅通过 / ❌不通过】
- 通过项比例: 【填写：M/13】
- 不通过项清单: 【填写】
- 修复要求: 【填写】
- 降级说明: 【填写：凭证失败→仅审计 anonymous 路由；断链→退回 context_pack】

**必须通过项:** 1, 6（credentials 存在 + 调用链非空）
**允许 WARN 项:** 3, 4, 9, 10, 11, 12

---

## 阶段 4：漏洞利用 — 单个 Auditor 校验（每个 Auditor 完成后立即校验）

**被校验 Agent:** 21 个专项 Auditor（sqli_auditor, xss_ssti_auditor, rce_auditor 等）
**校验依据:** 该 Auditor 提交的 exploit JSON + 对应 Sink 的 context_pack
**关联文档:** shared/evidence_contract.md, shared/sink_definitions.md

> 以下模板适用于每一个 Auditor 的独立校验。质检员根据 Auditor 类型调整具体预期。

| 序号 | 校验项 | 预期 | 实际 | 状态 |
|:----:|--------|------|------|:----:|
| 1 | exploit JSON 存在 | `exploits/{sink_id}.json` 文件存在且非空 | 【填写】 | ⬜ |
| 2 | 必填字段完整 | 包含: vuln_type, endpoint, payload, response, confidence, evidence_summary, severity, prerequisite_conditions | 【填写：缺失字段】 | ⬜ |
| 3 | 可信度标注正确 | confirmed 必须有物理证据；无证据不得标 confirmed | 【填写】 | ⬜ |
| 4 | HTTP 请求完整 | Burp 格式：METHOD URL HTTP/1.1 + Headers + Body | 【填写】 | ⬜ |
| 5 | HTTP 响应记录 | 包含状态码 + 关键响应体（证据部分） | 【填写】 | ⬜ |
| 6 | 物证匹配类型矩阵 | 物证符合该漏洞类型的验证标准（见下方矩阵） | 【填写：匹配项】 | ⬜ |
| 7 | evidence_score 合理 | confirmed: score ≥ **7**; suspected: 4-6; potential: 1-3 | 【填写：score=?】 | ⬜ |
| 8 | 修复方案具体 | 有修复前/修复后代码对比，非泛泛建议 | 【填写】 | ⬜ |
| 9 | Trace-Gate 合规 | trace_status=RESOLVED 才能 confirmed；UNRESOLVED/INCOMPLETE 最高 suspected | 【填写】 | ⬜ |
| 10 | 三维评分完整 | severity 对象包含 R/I/C 值 + reason + score + cvss + level + vuln_id（详见 shared/severity_rating.md） | 【填写：R=? I=? C=? Score=? CVSS=?】 | ⬜ |
| 11 | 评分一致性 | severity.score 与 evidence_score 范围匹配（≥2.10→≥7, 1.20-2.09→4-6, <1.20→1-3）；不一致=矛盾 | 【填写：矛盾数=?】 | ⬜ |
| 12 | 前置条件完整 | prerequisite_conditions 包含 4 子项: auth_requirement + bypass_method + other_preconditions + exploitability_judgment | 【填写：缺失子项】 | ⬜ |
| 13 | 可利用性合规 | exploitability=not_exploitable → final_verdict 最高 potential；exploitability=conditionally → severity.C 降 1 级 | 【填写】 | ⬜ |
| 14 | auth 与 R 值一致 | prerequisite_conditions.auth_requirement 与 severity.reachability 的映射正确（anonymous→3, authenticated→2, admin→1） | 【填写】 | ⬜ |

**物证类型矩阵速查（质检员按被校验 Auditor 类型选用）:**

| Auditor | 核心物证要求 |
|---------|-------------|
| rce_auditor | 文件写入+存在验证 或 命令执行输出匹配 |
| sqli_auditor | 时间延迟/回显/报错/UNION 至少一项 |
| xss_ssti_auditor | 响应 HTML 含未转义注入 或 模板表达式求值结果 |
| lfi_auditor | 响应含 `/etc/passwd` 等敏感文件内容 |
| xxe_auditor | 实体返回文件内容 或 OOB 回调确认 |
| ssrf_auditor | 响应含内部服务数据/元数据 |
| authz_auditor | 低权限完成高权限操作 |
| deserial_auditor | POP 链触发+副作用验证 |
| filewrite_auditor | 写入文件+文件存在验证 |
| csrf_auditor | 跨域请求成功修改状态 |
| config_auditor | 敏感文件可下载/默认凭证可用/debug 泄露 |
| infoleak_auditor | 泄露凭证有效/PII 真实 |
| race_condition_auditor | 并发 N 次 > 1 次成功 |
| nosql_auditor | 查询语义改变+非预期数据返回 |
| business_logic_auditor | 业务状态异常修改且持久化 |
| crypto_auditor | 弱算法利用成功（预测Token/破解密码/伪造签名） |
| session_auditor | Session 固定/劫持成功 |
| crlf_auditor | 注入 Header 出现在响应头 |
| ldap_auditor | LDAP 查询语义改变 |
| wordpress_auditor | WP 特有漏洞触发（XML-RPC/REST API/短代码） |
| logging_auditor | 日志投毒+LFI 包含执行 |

**最终判定:**
- 状态: 【填写：✅通过 / ❌不通过】
- 通过项比例: 【填写：M/14】
- Auditor 名称: 【填写】
- 发现数: confirmed=【?】/ suspected=【?】/ potential=【?】/ discarded=【?】
- 不通过项清单: 【填写】
- 修复要求: 【填写：针对不通过项，要求 Auditor 补充什么】

**必须通过项:** 1, 2, 3, 6, 9, 10, 12, 13（JSON完整 + 物证匹配 + Trace合规 + 评分完整 + 前置条件 + 可利用性）
**允许 WARN 项:** 4, 5, 7, 8, 11, 14

### 各 Auditor 专项校验规格

> 质检员在完成通用 9 项校验后，还必须根据 Auditor 类型执行以下专项检查。每种 Auditor 有独立的物证完整性、Payload 变体和修复代码要求。

#### sqli_auditor 专项

| 序号 | 专项校验 | 预期 | 实际 | 状态 |
|:----:|----------|------|------|:----:|
| S1 | 注入类型标注 | 明确标注: time-based / error-based / union-based / boolean-blind | 【填写】 | ⬜ |
| S2 | 延迟时间证据 | time-based: 延迟 ≥ 5s，附 2 组对比(有/无 sleep) | 【填写：延迟=?s】 | ⬜ |
| S3 | UNION 列数确认 | union-based: ORDER BY / UNION SELECT NULL 确认列数，有回显 | 【填写：列数=?】 | ⬜ |
| S4 | 参数化修复 | 修复代码使用 PDO prepare/bind 或 ORM 参数化，非 addslashes | 【填写】 | ⬜ |
| S5 | WAF 绕过记录 | 若目标有过滤，需记录绕过手法（大小写/内联注释/编码） | 【填写】 | ⬜ |

#### rce_auditor 专项

| 序号 | 专项校验 | 预期 | 实际 | 状态 |
|:----:|----------|------|------|:----:|
| S1 | 执行方式标注 | 明确标注: eval / system / exec / proc_open / backtick / assert | 【填写】 | ⬜ |
| S2 | 命令回显验证 | 执行 `id` 或 `whoami`，响应含 uid/username | 【填写】 | ⬜ |
| S3 | 文件写入验证 | 若通过文件写入证明: 写入 → 读取 → 删除 三步完整 | 【填写】 | ⬜ |
| S4 | disable_functions 检查 | 记录已禁用函数列表，标注绕过方式(若有) | 【填写】 | ⬜ |
| S5 | 修复方案 | 移除危险函数调用 或 白名单参数校验，非仅 escapeshellarg | 【填写】 | ⬜ |

#### xss_ssti_auditor 专项

| 序号 | 专项校验 | 预期 | 实际 | 状态 |
|:----:|----------|------|------|:----:|
| S1 | XSS 类型标注 | reflected / stored / DOM-based / SSTI 明确区分 | 【填写】 | ⬜ |
| S2 | DOM 上下文标注 | HTML body / attribute / JavaScript / URL 哪个注入点 | 【填写】 | ⬜ |
| S3 | 编码绕过记录 | 若 htmlspecialchars 存在: 记录上下文逃逸方式(属性/事件/JS) | 【填写】 | ⬜ |
| S4 | SSTI 引擎识别 | SSTI 场景: 标注模板引擎(Twig/Blade/Smarty) + 表达式求值证据 | 【填写】 | ⬜ |
| S5 | 修复方案 | 输出编码(htmlspecialchars/Blade {{ }}) 或 CSP 策略 | 【填写】 | ⬜ |

#### lfi_auditor 专项

| 序号 | 专项校验 | 预期 | 实际 | 状态 |
|:----:|----------|------|------|:----:|
| S1 | 路径遍历层数 | 记录成功的 `../` 层数 或 php://filter 链 | 【填写：层数=?】 | ⬜ |
| S2 | 敏感文件读取 | 至少读取 /etc/passwd 或源码文件(.php)之一 | 【填写】 | ⬜ |
| S3 | filter chain 测试 | 尝试 `php://filter/convert.base64-encode/resource=` 并解码验证 | 【填写】 | ⬜ |
| S4 | open_basedir 状态 | 记录 open_basedir 值及绕过方式(若有) | 【填写】 | ⬜ |
| S5 | 修复方案 | realpath + 白名单目录，非仅 str_replace('../','') | 【填写】 | ⬜ |

#### filewrite_auditor 专项

| 序号 | 专项校验 | 预期 | 实际 | 状态 |
|:----:|----------|------|------|:----:|
| S1 | 写入方式标注 | file_put_contents / move_uploaded_file / fwrite 明确标注 | 【填写】 | ⬜ |
| S2 | 写入验证链 | 写入文件 → HTTP 访问该文件 → 确认可执行/可下载 | 【填写】 | ⬜ |
| S3 | 文件类型绕过 | 若有类型限制: 记录绕过方式(双扩展名/MIME 伪造/null byte) | 【填写】 | ⬜ |
| S4 | Webshell 证据 | 若写入 PHP 代码: 通过访问执行 `phpinfo()` 或 `id` 确认 | 【填写】 | ⬜ |
| S5 | 修复方案 | 文件名随机化 + 扩展名白名单 + 存储目录禁止执行 | 【填写】 | ⬜ |

#### ssrf_auditor 专项

| 序号 | 专项校验 | 预期 | 实际 | 状态 |
|:----:|----------|------|------|:----:|
| S1 | 协议标注 | http / gopher / dict / file 哪些可用 | 【填写】 | ⬜ |
| S2 | 内网探测证据 | 访问 127.0.0.1 / 169.254.169.254 / 内网服务 有响应差异 | 【填写】 | ⬜ |
| S3 | OOB 回调确认 | 若无直接回显: OOB DNS/HTTP 回调成功 | 【填写】 | ⬜ |
| S4 | 协议走私测试 | gopher:// 尝试发送原始 TCP 数据(Redis/MySQL) | 【填写】 | ⬜ |
| S5 | 修复方案 | URL 白名单 + 协议限制(仅 http/https) + 内网 IP 黑名单 | 【填写】 | ⬜ |

#### xxe_auditor 专项

| 序号 | 专项校验 | 预期 | 实际 | 状态 |
|:----:|----------|------|------|:----:|
| S1 | 解析器标注 | simplexml_load_string / DOMDocument / XMLReader 明确标注 | 【填写】 | ⬜ |
| S2 | 实体扩展证据 | 内部实体 `<!ENTITY xxe SYSTEM "file:///etc/passwd">` 读取成功 | 【填写】 | ⬜ |
| S3 | OOB XXE 证据 | 若无直接回显: 外部 DTD + OOB HTTP/FTP 数据外带确认 | 【填写】 | ⬜ |
| S4 | Billion Laughs 测试 | 是否测试 DoS 向量(记录结果即可，不要求成功) | 【填写】 | ⬜ |
| S5 | 修复方案 | `libxml_disable_entity_loader(true)` + `LIBXML_NOENT` 移除 | 【填写】 | ⬜ |

#### authz_auditor 专项

| 序号 | 专项校验 | 预期 | 实际 | 状态 |
|:----:|----------|------|------|:----:|
| S1 | 越权类型标注 | 水平越权(IDOR) / 垂直越权(权限提升) / 未授权访问 | 【填写】 | ⬜ |
| S2 | 权限对比证据 | 同一操作: 正常用户 vs 攻击者 的响应对比 | 【填写】 | ⬜ |
| S3 | 参数篡改记录 | 修改的参数(user_id/role_id 等) + 原值 vs 篡改值 | 【填写】 | ⬜ |
| S4 | Mass Assignment | 若有批量赋值: 标注可控字段列表 + 成功修改的高权限字段 | 【填写】 | ⬜ |
| S5 | 修复方案 | 服务端权限校验(非前端隐藏) + $fillable 白名单 | 【填写】 | ⬜ |

#### deserial_auditor 专项

| 序号 | 专项校验 | 预期 | 实际 | 状态 |
|:----:|----------|------|------|:----:|
| S1 | 入口点标注 | unserialize() / phar:// / __wakeup 触发路径 | 【填写】 | ⬜ |
| S2 | POP 链完整 | 起点类 → 中间类 → 终点类(危险函数) 链路完整，每环有代码引用 | 【填写：链长=?】 | ⬜ |
| S3 | 副作用验证 | 链触发后的副作用证据: 文件创建/命令输出/DNS 回调 | 【填写】 | ⬜ |
| S4 | Gadget 来源 | 标注 gadget 来自: 框架内置 / Composer 依赖 / 自定义代码 | 【填写】 | ⬜ |
| S5 | 修复方案 | 禁用 unserialize 用户输入 或 __unserialize + allowed_classes | 【填写】 | ⬜ |

#### config_auditor 专项

| 序号 | 专项校验 | 预期 | 实际 | 状态 |
|:----:|----------|------|------|:----:|
| S1 | 暴露文件列表 | 逐个列出可访问的敏感文件(.env/phpinfo/debug bar 等) | 【填写：文件数=?】 | ⬜ |
| S2 | 默认凭证测试 | admin/admin, root/root 等默认凭证测试结果 | 【填写：可用数=?】 | ⬜ |
| S3 | 安全头缺失 | X-Frame-Options / CSP / HSTS / X-Content-Type-Options | 【填写：缺失头=?】 | ⬜ |
| S4 | Debug 模式 | APP_DEBUG=true 暴露堆栈/路径/配置信息 | 【填写】 | ⬜ |
| S5 | 修复方案 | 各项具体配置修改命令/代码，非泛泛"关闭 debug" | 【填写】 | ⬜ |

#### infoleak_auditor 专项

| 序号 | 专项校验 | 预期 | 实际 | 状态 |
|:----:|----------|------|------|:----:|
| S1 | 泄露类型标注 | 凭证泄露 / PII / 源码 / Git 历史 / API 过度暴露 / 用户枚举 | 【填写】 | ⬜ |
| S2 | 有效性验证 | 泄露的凭证可登录 或 PII 可关联到真实用户 | 【填写】 | ⬜ |
| S3 | Git 暴露检查 | .git/HEAD 可访问 → 尝试提取 .git/config 或源码 | 【填写】 | ⬜ |
| S4 | API 枚举 | 可遍历 user ID/email → 获取非授权数据 | 【填写】 | ⬜ |
| S5 | 修复方案 | 敏感路径访问控制 + API 速率限制 + 响应字段最小化 | 【填写】 | ⬜ |

#### nosql_auditor 专项

| 序号 | 专项校验 | 预期 | 实际 | 状态 |
|:----:|----------|------|------|:----:|
| S1 | 数据库类型 | MongoDB / Redis / Elasticsearch 明确标注 | 【填写】 | ⬜ |
| S2 | 注入操作符证据 | `$gt` / `$ne` / `$where` / `$regex` 至少一个成功 | 【填写】 | ⬜ |
| S3 | 认证绕过 | 使用 `{"$gt":""}` 绕过密码验证 | 【填写】 | ⬜ |
| S4 | 数据提取 | 通过注入获取非授权数据(与正常响应对比) | 【填写】 | ⬜ |
| S5 | 修复方案 | 输入类型强制转换 + 禁用 `$where` + 参数化查询 | 【填写】 | ⬜ |

#### race_condition_auditor 专项

| 序号 | 专项校验 | 预期 | 实际 | 状态 |
|:----:|----------|------|------|:----:|
| S1 | 竞争场景标注 | 余额扣减 / 优惠券使用 / 库存扣减 / 投票 等 | 【填写】 | ⬜ |
| S2 | 并发证据 | 并发 N 次请求，记录 N 值和成功次数(>1 = 漏洞) | 【填写：N=?, 成功=?】 | ⬜ |
| S3 | 状态验证 | 竞争后数据库状态异常(余额负数/重复领取) | 【填写】 | ⬜ |
| S4 | 时间窗口 | 记录竞争成功所需时间窗口(ms 级) | 【填写：窗口=?ms】 | ⬜ |
| S5 | 修复方案 | 数据库锁(SELECT FOR UPDATE) / 唯一索引 / 原子操作 | 【填写】 | ⬜ |

#### crypto_auditor 专项

| 序号 | 专项校验 | 预期 | 实际 | 状态 |
|:----:|----------|------|------|:----:|
| S1 | 弱算法标注 | md5 / sha1 / DES / ECB / 弱 PRNG 具体标注 | 【填写】 | ⬜ |
| S2 | 利用证据 | Token 可预测/密码可破解/签名可伪造 至少一项 | 【填写】 | ⬜ |
| S3 | JWT 检查 | alg:none / 弱密钥 / kid 注入 测试结果 | 【填写】 | ⬜ |
| S4 | 密钥管理 | 硬编码密钥 / 弱密钥长度 / 密钥可提取 | 【填写】 | ⬜ |
| S5 | 修复方案 | 具体替换算法(bcrypt/AES-256-GCM/RS256) + 密钥轮换 | 【填写】 | ⬜ |

#### wordpress_auditor 专项

| 序号 | 专项校验 | 预期 | 实际 | 状态 |
|:----:|----------|------|------|:----:|
| S1 | WP 版本识别 | 核心版本 + 已知 CVE 匹配 | 【填写：版本=?】 | ⬜ |
| S2 | XML-RPC 暴露 | xmlrpc.php 可访问 + system.multicall 可用 | 【填写】 | ⬜ |
| S3 | REST API 未鉴权 | /wp-json/wp/v2/users 等端点未鉴权可枚举 | 【填写】 | ⬜ |
| S4 | 插件漏洞 | 已安装插件清单 + 已知漏洞匹配 + 利用验证 | 【填写：插件数=?, 漏洞数=?】 | ⬜ |
| S5 | 修复方案 | 禁用 XML-RPC + 限制 REST API + 升级插件/核心 | 【填写】 | ⬜ |

#### business_logic_auditor 专项

| 序号 | 专项校验 | 预期 | 实际 | 状态 |
|:----:|----------|------|------|:----:|
| S1 | 业务场景描述 | 价格篡改 / 流程跳步 / 规则绕过 等场景清晰描述 | 【填写】 | ⬜ |
| S2 | 状态对比证据 | 操作前后数据库/API 状态对比(不仅是 HTTP 响应) | 【填写】 | ⬜ |
| S3 | 持久化确认 | 异常状态不因刷新/重新登录恢复(确认写入数据库) | 【填写】 | ⬜ |
| S4 | 影响范围 | 影响的用户/金额/数据范围评估 | 【填写】 | ⬜ |
| S5 | 修复方案 | 服务端业务规则校验 + 事务隔离 + 审计日志 | 【填写】 | ⬜ |

#### crlf_auditor 专项

| 序号 | 专项校验 | 预期 | 实际 | 状态 |
|:----:|----------|------|------|:----:|
| S1 | 注入点标注 | header() / setcookie() / Location 重定向 / mail() | 【填写】 | ⬜ |
| S2 | 响应头证据 | 注入的自定义 Header 出现在 HTTP 响应头中 | 【填写】 | ⬜ |
| S3 | HTTP 响应拆分 | \r\n\r\n 后注入 HTML body 成功(升级为 XSS) | 【填写】 | ⬜ |
| S4 | PHP 版本影响 | PHP ≥7.0 header() 内置防护 → 标注绕过方式或 N/A | 【填写】 | ⬜ |
| S5 | 修复方案 | 移除用户输入中的 \r\n + 使用框架 Response 封装 | 【填写】 | ⬜ |

#### csrf_auditor 专项

| 序号 | 专项校验 | 预期 | 实际 | 状态 |
|:----:|----------|------|------|:----:|
| S1 | 缺失/绕过方式 | 无 Token / Token 不校验 / Token 可复用 / $except 排除 | 【填写】 | ⬜ |
| S2 | PoC HTML 完整 | 提供可直接执行的 HTML form 或 fetch() PoC | 【填写】 | ⬜ |
| S3 | 状态修改确认 | 跨域提交后，目标数据库/会话状态确实改变 | 【填写】 | ⬜ |
| S4 | CORS 关联 | 检查 Access-Control-Allow-Origin 配置是否放大攻击面 | 【填写】 | ⬜ |
| S5 | 修复方案 | 启用 CSRF 中间件 + SameSite=Strict/Lax cookie | 【填写】 | ⬜ |

#### session_auditor 专项

| 序号 | 专项校验 | 预期 | 实际 | 状态 |
|:----:|----------|------|------|:----:|
| S1 | 攻击类型 | Session Fixation / Session Hijacking / Cookie 篡改 | 【填写】 | ⬜ |
| S2 | Fixation 证据 | 登录前后 Session ID 未变(固定成功) | 【填写】 | ⬜ |
| S3 | Cookie 属性 | HttpOnly / Secure / SameSite / Path / Expires 检查结果 | 【填写】 | ⬜ |
| S4 | 序列化处理器 | session.serialize_handler 一致性检查(php vs php_serialize) | 【填写】 | ⬜ |
| S5 | 修复方案 | regenerate_id + strict_mode + HttpOnly + Secure | 【填写】 | ⬜ |

#### ldap_auditor 专项

| 序号 | 专项校验 | 预期 | 实际 | 状态 |
|:----:|----------|------|------|:----:|
| S1 | 注入点标注 | ldap_search / ldap_bind / DN 构造 具体位置 | 【填写】 | ⬜ |
| S2 | 过滤器注入 | `*)(uid=*))(|(uid=*` 类向量改变查询语义 | 【填写】 | ⬜ |
| S3 | 匿名绑定 | ldap_bind 空密码/匿名测试结果 | 【填写】 | ⬜ |
| S4 | 数据提取 | 注入后返回非授权用户/组数据 | 【填写】 | ⬜ |
| S5 | 修复方案 | ldap_escape() + 参数化 DN + 禁止匿名绑定 | 【填写】 | ⬜ |

#### logging_auditor 专项

| 序号 | 专项校验 | 预期 | 实际 | 状态 |
|:----:|----------|------|------|:----:|
| S1 | 注入方式 | User-Agent / Referer / 表单字段 → 日志写入 | 【填写】 | ⬜ |
| S2 | 日志投毒证据 | PHP 代码成功写入日志文件(cat 日志确认) | 【填写】 | ⬜ |
| S3 | LFI 链证据 | 日志投毒 + LFI 包含日志 → PHP 代码执行 | 【填写】 | ⬜ |
| S4 | 敏感数据泄露 | 日志中记录密码/Token/Session ID 等敏感字段 | 【填写】 | ⬜ |
| S5 | 修复方案 | 日志输入过滤 + 日志目录禁止 Web 访问 + 脱敏 | 【填写】 | ⬜ |

---

## 跨阶段数据一致性校验

> 本节由最终质检员（quality-checker-final）在阶段 5 校验之后执行。用于验证多阶段之间的数据流一致性和完整性，确保无幻觉(hallucination)、无遗漏。

### 规则 1：P0 路由 ↔ 漏洞利用全覆盖

**校验逻辑:** `priority_queue.json` 中 `priority=P0` 的每条 Sink 都必须在 `exploits/` 中有对应结果。

| 序号 | 校验项 | 预期 | 实际 | 状态 |
|:----:|--------|------|------|:----:|
| C1 | P0 Sink 全覆盖 | priority_queue 中 P0 数 = exploits 中 P0 结果数 | 【填写：P0=?个, 已覆盖=?个】 | ⬜ |
| C2 | P1 Sink 全覆盖 | priority_queue 中 P1 数 = exploits 中 P1 结果数 | 【填写：P1=?个, 已覆盖=?个】 | ⬜ |
| C3 | 报告章节完整 | P0/P1 每条在 audit_report.md 中有独立章节 | 【填写：缺失=?条】 | ⬜ |
| C4 | 无遗漏声明 | 未测试的 P0 必须有跳过原因(not_applicable + reason) | 【填写】 | ⬜ |

**验证脚本:**
```bash
P0_TOTAL=$(jq '[.[] | select(.priority=="P0")] | length' "$WORK_DIR/priority_queue.json")
P0_TESTED=$(ls "$WORK_DIR/exploits/"*.json 2>/dev/null | xargs -I{} jq -r 'select(.priority=="P0") | .sink_id' {} | sort -u | wc -l)
echo "P0 覆盖率: $P0_TESTED / $P0_TOTAL"
[ "$P0_TOTAL" -eq "$P0_TESTED" ] && echo "✅ P0 全覆盖" || echo "❌ P0 有遗漏"
```

### 规则 2：auth_matrix ↔ 漏洞利用凭证一致

**校验逻辑:** Exploit 使用的认证级别必须与 auth_matrix 中该路由的要求一致。

| 序号 | 校验项 | 预期 | 实际 | 状态 |
|:----:|--------|------|------|:----:|
| C5 | 匿名路由测试凭证 | auth_level=anonymous 的路由，exploit 未使用 authenticated/admin 凭证 | 【填写：违规=?条】 | ⬜ |
| C6 | 鉴权路由凭证匹配 | auth_level=authenticated/admin 的路由，exploit 使用对应级别凭证 | 【填写：不匹配=?条】 | ⬜ |
| C7 | 越权发现一致 | 低权限成功访问高权限路由 → 必须标记为 authz 漏洞(IDOR/提权) | 【填写：未标记=?条】 | ⬜ |
| C8 | bypass_notes 引用 | auth_matrix 中有 bypass_notes 的路由，exploit 应引用或验证 | 【填写：未验证=?条】 | ⬜ |

### 规则 3：Sink 类型 ↔ Auditor 覆盖

**校验逻辑:** Phase 2 识别的每种 Sink 类型都必须有对应的 Auditor 执行。

| 序号 | 校验项 | 预期 | 实际 | 状态 |
|:----:|--------|------|------|:----:|
| C9 | Sink 类型全覆盖 | priority_queue 中的 sink_type 集合 ⊆ 已执行 Auditor 类型集合 | 【填写：未覆盖类型=?】 | ⬜ |
| C10 | Auditor 分配正确 | eval/system → rce_auditor, DB::raw → sqli_auditor 等映射正确 | 【填写：错误分配=?】 | ⬜ |
| C11 | not_applicable 有理由 | 标记为 not_applicable 的 Auditor 必须说明原因 | 【填写：无理由=?个】 | ⬜ |

**Sink → Auditor 映射表:**
```
eval/system/exec/proc_open/backtick/assert → rce_auditor
DB::raw/whereRaw/query/execute → sqli_auditor
echo/print/{!! !!}/->display() → xss_ssti_auditor
include/require/file_get_contents(local) → lfi_auditor
file_put_contents/move_uploaded_file/fwrite → filewrite_auditor
curl_exec/file_get_contents(url)/guzzle → ssrf_auditor
simplexml_load/DOMDocument/XMLReader → xxe_auditor
unserialize/phar:// → deserial_auditor
$where/$gt/Redis → nosql_auditor
ldap_search/ldap_bind → ldap_auditor
```

### 规则 4：过滤函数 ↔ 绕过记录

**校验逻辑:** context_pack 中标注了过滤函数的 Sink，exploit 中必须记录绕过方式或标注无法绕过。

| 序号 | 校验项 | 预期 | 实际 | 状态 |
|:----:|--------|------|------|:----:|
| C12 | 过滤函数已处理 | context_pack.filters_in_path 中每个 effective=true 的过滤器，exploit 有绕过记录或无法绕过标注 | 【填写：未处理=?个】 | ⬜ |
| C13 | 绕过策略合理 | 绕过方式与过滤函数类型匹配(如 htmlspecialchars 不应用 SQL 注释绕过) | 【填写：不合理=?个】 | ⬜ |

### 规则 5：凭证可用性 ↔ 测试深度

**校验逻辑:** 可用凭证级别决定测试深度，确保不因凭证缺失跳过必要测试。

| 序号 | 校验项 | 预期 | 实际 | 状态 |
|:----:|--------|------|------|:----:|
| C14 | 凭证覆盖 | credentials.json 有 ≥1/3 级别(anonymous/authenticated/admin) | 【填写：可用级别=?/3】 | ⬜ |
| C15 | 测试深度匹配 | authenticated 可用 → 所有 auth 路由需测试; admin 可用 → admin 路由需测试 | 【填写：跳过的鉴权路由=?条】 | ⬜ |

### 规则 6：EVID 证据链完整性（零幻觉）

**校验逻辑:** 所有 confirmed 发现的 EVID_* 引用必须在 exploit JSON 中有实际内容，禁止占位符或空值。

| 序号 | 校验项 | 预期 | 实际 | 状态 |
|:----:|--------|------|------|:----:|
| C16 | EVID 引用有内容 | 每个 EVID_* 引用点在 evidence 对象中有实际数据(非空/非占位符) | 【填写：空 EVID=?个】 | ⬜ |
| C17 | HTTP 请求可重放 | confirmed 的 Burp 请求格式完整，URL/Method/Headers/Body 齐全 | 【填写：不完整=?个】 | ⬜ |
| C18 | 响应与声称一致 | evidence_summary 中描述的现象在 HTTP 响应中可找到 | 【填写：不一致=?个】 | ⬜ |

**最终判定（跨阶段一致性）:**
- 状态: 【填写：✅通过 / ❌不通过】
- 通过项比例: 【填写：M/18】
- MUST-PASS 项(C1-C4, C16-C18): 【?/7】— 全部通过才算合格
- SHOULD-PASS 项(C5-C15): 【?/11】— 允许 ≤2 项 WARN
- 不通过项清单: 【填写】
- 修复要求: 【填写：定位到具体 Phase 的 Agent 发回补充】

---

### 阶段 4：Mini-Researcher 与图记忆校验

> 仅在 Mini-Researcher 被触发或图记忆被写入时适用。

| 编号 | 校验项 | 标准 | 结果 | 通过 |
|------|--------|------|------|------|
| MR1 | 研究触发合理性 | Mini-Researcher 的 trigger_condition（MR-1~MR-5）与实际场景匹配，非无故触发 | 【填写】 | ⬜ |
| MR2 | 研究结果格式 | `$WORK_DIR/research/{research_id}.json` 通过 `schemas/research_result.schema.json` 校验 | 【填写】 | ⬜ |
| MR3 | 建议可执行性 | `recommendations` 字段包含具体可尝试的攻击方向，非泛泛而谈 | 【填写】 | ⬜ |
| G1 | 图节点写入完整 | 每个 `status=confirmed` 的 exploit 在 `memory_nodes` 表中有对应节点 | 【填写】 | ⬜ |
| G2 | 关系边质量 | `memory_edges` 中的边有 `evidence` 描述且 `confidence` 合理；`escalates_to` 边有 `combined_severity` | 【填写】 | ⬜ |

---

## 阶段 4：物理取证综合校验（全部 Auditor 通过后）

**被校验对象:** Team-4 全体输出的 team4_progress.json + 所有 exploits/*.json
**校验执行者:** 任一空闲质检员

| 序号 | 校验项 | 预期 | 实际 | 状态 |
|:----:|--------|------|------|:----:|
| 1 | team4_progress.json 完整 | 包含 total_findings + 各级别计数 + findings 数组 | 【填写】 | ⬜ |
| 2 | 交叉验证覆盖 | 所有 confirmed 都执行了变体 Payload 验证 | 【填写：已验证/总数】 | ⬜ |
| 3 | 误报比对完成 | 所有 confirmed/suspected 与 false_positive_patterns.md 比对 | 【填写：比对数】 | ⬜ |
| 4 | 攻击链验证 | 多步骤链每步有独立物证，链断裂则整条降级 | 【填写：链数=?，完整链=?】 | ⬜ |
| 5 | evidence_score 分布 | confirmed 均 ≥ 7, suspected 均 4-6, potential 均 1-3 | 【填写：违规数=?】 | ⬜ |
| 6 | Sink 覆盖率 | 已审计 Sink 数/priority_queue Sink 总数 ≥ **90%** | 【填写：覆盖率=?%】 | ⬜ |
| 7 | 8轮回退标注 | 8轮全失败的标注 `potential_risk` + 失败原因 | 【填写：回退数=?】 | ⬜ |
| 8 | Auditor 覆盖矩阵 | 21 个 Auditor 全部有状态（executed/not_applicable/deferred/failed） | 【填写：已覆盖/21】 | ⬜ |

**最终判定:**
- 状态: 【填写：✅通过 / ❌不通过】
- 通过项比例: 【填写：M/8】
- 漏洞统计: confirmed=【?】/ suspected=【?】/ potential=【?】
- Sink 覆盖率: 【?%】
- 不通过项清单: 【填写】
- 修复要求: 【填写】

---

## 阶段 4.5：关联分析校验（Team-4.5 输出）

**被校验 Agent:** correlation_engine, attack_graph_builder（Team-4.5）
**校验依据文件:** attack_graph.json, correlation_report.json, patches/*.patch

| 序号 | 校验项 | 预期 | 实际 | 状态 |
|:----:|--------|------|------|:----:|
| 1 | attack_graph.json 存在 | 文件存在，包含 nodes + edges | 【填写：nodes=?, edges=?】 | ⬜ |
| 2 | 关联报告存在 | correlation_report.json 存在且非空 | 【填写】 | ⬜ |
| 3 | 攻击链路径合理 | 图中路径对应实际可利用的漏洞组合 | 【填写：路径数=?】 | ⬜ |
| 4 | patches 完整性 | 每个 confirmed 漏洞有对应 .patch 文件 | 【填写：patch数/confirmed数】 | ⬜ |
| 5 | patch 可应用 | 每个 patch 通过 `patch --dry-run` 验证 | 【填写：通过数/总数】 | ⬜ |
| 6 | 关联引用准确 | 关联报告引用的 finding ID 在 team4_progress.json 中存在 | 【填写：无效引用数=?】 | ⬜ |

**最终判定:**
- 状态: 【填写：✅通过 / ❌不通过】
- 通过项比例: 【填写：M/6】
- 不通过项清单: 【填写】
- 修复要求: 【填写】

---

## 阶段 5：报告生成校验（Team-5 输出）

**被校验 Agent:** report_writer, sarif_exporter（Team-5）
**校验依据文件:** audit_report.md, audit_report.sarif.json, poc/*.py, poc/run_all.sh

| 序号 | 校验项 | 预期 | 实际 | 状态 |
|:----:|--------|------|------|:----:|
| 1 | P0/P1 漏洞全覆盖 | priority_queue.json 中所有 P0/P1 在报告中有完整章节 | 【填写：覆盖率=?%】 | ⬜ |
| 2 | confirmed 物证完整 | 每条 ✅ 有: Burp HTTP 请求 + HTTP 响应 + docker exec 验证（如适用） | 【填写：完整数/confirmed数】 | ⬜ |
| 3 | 修复方案具体 | 每条有修复前/修复后代码对比，非泛泛建议 | 【填写：具体方案数/总数】 | ⬜ |
| 4 | Burp 格式正确 | METHOD URL HTTP/1.1 + Headers + Body，可直接 Repeater 重放 | 【填写：格式正确数/总数】 | ⬜ |
| 5 | 可信度一致性 | ✅=有物证, ⚠️=代码可利用无物证, ⚡=纯静态；无矛盾 | 【填写：矛盾数=?】 | ⬜ |
| 6 | 漏洞去重 | 同一 file+line+sink 只出现一次 | 【填写：重复数=?】 | ⬜ |
| 7 | 覆盖率统计准确 | 已审计路由数+跳过路由数=总路由数 | 【填写：差值=?】 | ⬜ |
| 8 | Markdown 格式 | 表格渲染正常、代码块语法正确、无断裂链接 | 【填写】 | ⬜ |
| 9 | SARIF 合法性 | 合法 JSON, version=2.1.0, results 数=报告漏洞数 | 【填写：results数=?, 报告数=?】 | ⬜ |
| 10 | SARIF severity 映射 | confirmed→error, suspected→warning, potential→note | 【填写：映射错误数=?】 | ⬜ |
| 11 | PoC 语法通过 | 所有 .py 通过 `python3 -c "compile(...)"` | 【填写：通过率=?%】 | ⬜ |
| 12 | PoC run_all.sh 存在 | poc/run_all.sh 存在且包含所有 PoC 执行命令 | 【填写】 | ⬜ |
| 13 | PoC URL 一致 | 脚本中目标 URL 与报告一致 | 【填写：不一致数=?】 | ⬜ |
| 14 | Agent 覆盖矩阵 | 21 个 Phase-4 Agent 全部出现，含状态+Sink数+确认数 | 【填写：覆盖/21】 | ⬜ |
| 15 | EVID 证据完整性 | 所有 confirmed 有该类型全部必填 EVID_* 点 | 【填写：缺失 EVID 数=?】 | ⬜ |
| 16 | P0/P1 覆盖率 | = **100%**（所有 P0/P1 必须在报告中） | 【填写：覆盖率=?%】 | ⬜ |
| 17 | PoC 通过率 | = **100%**（所有 PoC 必须通过语法检查） | 【填写：通过率=?%】 | ⬜ |

**量化阈值汇总:**
- P0/P1 漏洞覆盖率 = **100%**
- PoC 语法通过率 = **100%**
- confirmed 物证完整率 ≥ **100%**（缺物证的不应为 confirmed）

**最终判定:**
- 状态: 【填写：✅通过 / ❌不通过】
- 通过项比例: 【填写：M/17】
- 不通过项清单: 【填写】
- 修复要求: 【填写：发回 report_writer 修正的具体指令】
- 最多修正轮数: **2 轮**

**必须通过项:** 1, 2, 3, 14, 15（漏洞覆盖 + 物证完整 + 修复具体 + Agent矩阵 + EVID）
**允许 WARN 项:** 4, 6, 7, 8, 9, 10, 11, 12, 13

---

## 最终质量报告模板

> 全部阶段校验通过后，最后一个质检员汇总生成 `$WORK_DIR/quality_report.md`。

```markdown
# 审计质量报告

## 总览

| 指标 | 值 |
|------|-----|
| 审计目标 | 【填写：项目名称】 |
| 审计时间 | 【填写：起止时间】 |
| 总阶段数 | 6（Phase 1-5 + Phase 4.5） |
| 各阶段通过率 | Phase1:【?】/ Phase2:【?】/ Phase3:【?】/ Phase4:【?】/ Phase4.5:【?】/ Phase5:【?】 |
| 总校验项 | 【?】项，通过【?】项，WARN【?】项，FAIL【?】项 |
| 重做次数 | Phase1:【?】/ Phase2:【?】/ Phase3:【?】/ Phase4:【?】/ Phase5:【?】 |
| 降级记录 | 【填写：哪些环节降级、原因】 |

## 各阶段校验明细

### Phase 1 环境构建
- 通过项: 【M/N】
- 不通过/WARN 项: 【列表】
- 重做次数: 【?】

### Phase 2 静态侦察
- 通过项: 【M/N】
- 覆盖率: 路由=【?%】/ Auth=【?%】/ Sink=【?%】
- 重做次数: 【?】

### Phase 3 动态追踪
- 通过项: 【M/N】
- 调用链完整率: 【?%】
- 凭证可用: 【?/3级】
- 重做次数: 【?】

### Phase 4 漏洞利用
- 通过项: 【M/N】
- Auditor 执行: executed=【?】/ not_applicable=【?】/ deferred=【?】/ failed=【?】
- Sink 覆盖率: 【?%】
- 漏洞统计: confirmed=【?】/ suspected=【?】/ potential=【?】
- 重做次数（含 Auditor 级别）: 【?】

### Phase 4.5 关联分析
- 通过项: 【M/N】
- 攻击路径数: 【?】
- Patch 可应用率: 【?%】

### Phase 5 报告生成
- 通过项: 【M/N】
- P0/P1 覆盖: 【?%】
- PoC 通过: 【?%】
- 修正轮数: 【?/2】

## Agent 覆盖率矩阵

| Agent | 阶段 | 状态 | Sink 数 | confirmed | suspected | potential | 重做次数 |
|-------|------|------|---------|-----------|-----------|-----------|----------|
| docker_builder | 1 | 【?】 | - | - | - | - | 【?】 |
| route_scanner | 2 | 【?】 | - | - | - | - | 【?】 |
| ... | ... | ... | ... | ... | ... | ... | ... |

## 质量结论

- 整体评级: 【填写：A/B/C/D】
  - A: 全部通过，无降级
  - B: 全部通过，有 WARN 或降级
  - C: 有不通过项但已修正
  - D: 有未修正的不通过项
- 遗留风险: 【填写】
- 建议: 【填写】
```
