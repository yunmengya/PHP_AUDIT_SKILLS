# Phase 4：深度对抗审计（攻击逻辑 + 质检调度）

> 本文件由 SKILL.md 提取，主调度器通过引用加载。

### Phase-4: 深度对抗审计（并行分析 + 串行攻击）

**⚠️ 此 Phase 是 Burp 复现包和物理证据的唯一来源，绝对不可跳过。**

**容器冲突规避策略**: 多个专家不能同时操作同一个 Docker 容器。
采用**两阶段模式**: 先并行做静态分析（读文件，不碰容器），再串行做动态攻击（独占容器）。

每个专家 Agent 的 prompt 中注入以下指令:
```
你的工作分两阶段:

阶段 1（分析阶段）: 读取 context_packs、traces、源码，分析过滤机制，规划攻击策略，
  生成每轮的 Payload 和注入点。此阶段不发送任何 HTTP 请求、不操作 Docker 容器。
  将分析结果和攻击计划写入 $WORK_DIR/exploits/{sink_id}_plan.json。

阶段 2（攻击阶段）: 读取 $WORK_DIR/exploits/{sink_id}_plan.json，
  按计划逐轮执行攻击、采集证据、快照回滚。
  将最终结果写入 $WORK_DIR/exploits/{sink_id}.json。

在两个阶段中，发现关键信息时写入 $WORK_DIR/audit_session.db 的 shared_findings 表（参考 shared/realtime_sharing.md）。
攻击阶段开始前先读取共享发现库获取其他审计员的发现。
记录存入点和使用点到 $WORK_DIR/second_order/（参考 shared/second_order.md）。

当你收到 "START_ATTACK" 信号时才进入阶段 2。在此之前只做阶段 1。
```

> **攻击记忆**: Phase-4 专家启动攻击阶段前，自动查询 `~/.php_audit/attack_memory.db` 中匹配 (sink_type + framework + PHP版本段) 的历史记录，优先使用历史成功 payload，跳过已知无效策略。攻击完成后将经验写入记忆库。详见 `shared/attack_memory.md`。

── Step 1: 并行分析（所有专家同时工作，不碰容器）──

同时 spawn 所有专家 Agent（background 模式）:

  例如（按需 spawn，无对应 sink 则不启动，但框架强制项必须启动）:

  Agent(name="rce_auditor", team_name="php-audit", run_in_background=true, mode="bypassPermissions", subagent_type="general-purpose")
    → prompt: Task #{id} 指令（阶段1模式）+ teams/team4/rce_auditor.md + shared/docker_snapshot.md
            + shared/payload_templates.md + shared/waf_bypass.md + shared/framework_patterns.md
            + 共享资源 + 对应 sink 的 context_packs + traces + credentials
            + tools/payload_encoder.php（告知路径和用法）+ tools/waf_detector.php（告知路径和用法）
            + TARGET_PATH + WORK_DIR

  **增强上下文注入**（每个专家 Agent 均适用）:
  从 context_pack 中提取增强字段，注入到 Agent prompt 尾部:
  ```
  --- 增强上下文 ---
  路由优先级: {context_pack.route_priority}（P0=最高危 P3=低风险）
  鉴权绕过摘要: auth_type={auth_bypass_summary.auth_type}, bypass_possibility={auth_bypass_summary.bypass_possibility}
    可用绕过方法: {auth_bypass_summary.bypass_methods}
  过滤强度评分: {filter_strength_score}/100
    → ≤30: 防御薄弱，优先尝试直接注入
    → 31-60: 存在过滤但可能绕过，优先尝试编码/变形 payload
    → 61-90: 过滤较严，优先尝试逻辑绕过或上下文切换
    → ≥91: 几乎无法绕过，记录防御有效并尝试 pivot
  版本预判: {version_alerts 中与本 Auditor 匹配的 CVE 列表，如有则优先利用}
  ```

  **策略选择规则**:
  - `filter_strength_score ≤ 30` → 直接攻击模式（标准 payload 起步）
  - `filter_strength_score 31-60` → 编码绕过模式（base64/hex/double-url 编码优先）
  - `filter_strength_score ≥ 61` → 逻辑绕过模式（类型混淆/二阶注入/上下文切换优先）
  - `auth_bypass_summary.bypass_possibility = "none"` → 必须使用合法凭证（从 credentials.json 获取）
  - `version_alert_priority = true` → 将已知 CVE 利用方案置于攻击计划首位

  Agent(name="sqli_auditor", ...) 等其他专家...（所有专家均使用 mode="bypassPermissions"）
  （所有 Phase-4 专家 Agent 均需注入: shared/payload_templates.md + shared/waf_bypass.md
    + shared/framework_patterns.md + shared/php_specific_patterns.md + shared/known_cves.md
    + tools/payload_encoder.php + tools/waf_detector.php）

等待全部分析完成
── Step 2: 串行攻击（逐个专家独占容器执行）──

按优先级排序专家（P0 sink 对应的专家优先）:

  遍历每个已完成分析的专家:

    Agent(name="{type}-auditor-attack", team_name="php-audit", foreground, mode="bypassPermissions", subagent_type="general-purpose")
      → prompt: "START_ATTACK 信号 + 你已完成阶段1分析，现在执行阶段2。
                读取 $WORK_DIR/exploits/{sink_id}_plan.json，按计划逐轮攻击。"
              + teams/team4/{type}_auditor.md + shared/docker_snapshot.md
              + shared/payload_templates.md + shared/waf_bypass.md + shared/framework_patterns.md
              + 共享资源 + tools/payload_encoder.php（告知路径和用法）+ tools/waf_detector.php（告知路径和用法）
              + TARGET_PATH + WORK_DIR

    完成 → 下一个专家

    **异常处理**: 如果专家 Agent 非正常退出（crash/超时/错误）:
    1. 记录异常信息到 `$WORK_DIR/exploits/{sink_id}_error.json`:
       ```json
       {"sink_id": "...", "specialist": "...", "error": "Agent 异常退出", "partial_results": true}
       ```
    2. 检查 `$WORK_DIR/exploits/{sink_id}_plan.json` 是否存在（保留阶段 1 分析结果）
    3. 在流水线视图中标注 ⚠️
    4. **继续下一个专家**（不中断整体流程）

── Step 3: Pivot When Stuck（卡住时自动转向）──

#### Pivot 预判（环境预过滤）

在 Stage-1 分析阶段，每个 Auditor 根据 `environment_status.json` 预判哪些 Pivot 路径不可用，避免攻击阶段无效尝试:

| 环境条件 | 不可用 Pivot | 原因 |
|----------|-------------|------|
| `allow_url_include = Off` | php://filter chain RCE | 无法通过 include 加载远程流 |
| `disable_functions` 含 `mail` | mail() 头注入 pivot | mail() 被禁用 |
| 无 `unserialize()` 入口且无 phar:// | 反序列化 RCE pivot | 无反序列化触发点 |
| 非 MySQL 或无宽字节编码 | 宽字节 SQLi pivot | 宽字节绕过仅适用于 GBK/GB2312 编码的 MySQL |
| PHP ≥ 8.0 | Type Juggling `0e` hash | PHP 8.0 严格化了字符串/数字比较 |
| 无 LDAP 扩展 | LDAP 认证绕过 pivot | 目标无 LDAP 依赖 |
| 框架 CSRF 中间件覆盖所有路由 | CSRF except 路由 pivot | 无排除路由可利用 |

**预判输出**: 每个 Auditor 在 `{sink_id}_plan.json` 中增加 `available_pivots` 和 `excluded_pivots` 字段:
```json
{
  "available_pivots": ["second_order_sqli", "blind_sqli_oob"],
  "excluded_pivots": [
    {"pivot": "widechar_sqli", "reason": "DB 编码为 utf8mb4，非宽字节"}
  ]
}
```

当某个专家 Agent 在阶段 2 攻击中持续失败，触发以下 pivot 规则自动切换审计策略:

| 触发条件 (Trigger) | 切换目标 (Switch To) | 额外资源 (Additional Resources) |
|---|---|---|
| **sqli_auditor 连续 8 轮 Payload 全部失败**（无报错差异、无时间差异、无回显差异） | 切换到 **二阶 SQLi 审计**: 让 context-extractor 追踪数据从 DB 取出后的使用点（存储→读取→拼接 SQL），重新构造 payload 打存入点 | `shared/second_order.md` + context-extractor 的 data-flow 输出; 需要回溯 INSERT/UPDATE 语句对应的 SELECT 消费路径 |
| **xss_ssti_auditor 被 WAF/htmlspecialchars 完全阻断**（所有 XSS vector 均被过滤，无法绕过） | 自动尝试 **SSTI 审计**: 同一注入点可能是模板引擎渲染入口（Twig/Blade/Smarty），用 `{{7*7}}` / `${7*7}` 探测 | `teams/team4/xss_ssti_auditor.md` 中 SSTI 部分; 需要 `shared/framework_patterns.md` 确认模板引擎类型 |
| **lfi_auditor 路径遍历被过滤**（`../` 被 replace、realpath 限制、open_basedir 阻断） | pivot 到 **php://filter chain** 攻击: 不使用文件系统路径，通过 `php://filter/convert.base64-encode/resource=` 或 filter chain RCE 绕过 | `shared/payload_templates.md` 中 LFI filter chain 模板; 需要确认 `allow_url_include` 状态 |
| **rce_auditor 危险函数被 disable_functions 禁用**（system/exec/passthru/shell_exec 全部在 disabled list） | pivot 到 **反序列化 RCE**: 寻找 `unserialize()` 入口，通过 POP chain 触发 `__destruct`/`__wakeup` 实现代码执行 | `teams/team4/deserial_auditor.md` + `shared/payload_templates.md` 反序列化部分; 需要 Composer 依赖列表构造 gadget chain |
| **ssrf_auditor 内网地址不可达**（目标服务器网络隔离，127.0.0.1/内网段被过滤或无法回连） | pivot 到 **DNS Rebinding**: 使用可控 DNS 记录（TTL=0）让目标先解析到外部 IP 通过校验，再 rebind 到内网地址 | 需要 DNS rebinding 服务（如 rbndr.us 或自建）; `shared/payload_templates.md` 中 SSRF DNS rebinding 模板 |
| **crlf_auditor PHP ≥7.0 header() 内置防护无法绕过**（原生 header() 检测到 `\r\n` 直接抛 Warning） | pivot 到 **mail() 头注入**: 转向 `mail()` 的 `additional_headers` 参数（不受 header() 保护），或审查框架响应头封装方法是否绕过原生检查 | `shared/payload_templates.md` 中 CRLF 模板; 检查框架版本对 header 封装的处理方式 |
| **csrf_auditor Token 验证严格无法绕过**（框架 CSRF 中间件正确实现，Token 不可复用/预测） | pivot 到 **JSON CSRF + CORS 审查**: 检查 API 端点是否存在宽松 CORS 配置 (`Access-Control-Allow-Origin: *`) 允许跨域携带凭证，或找出被 `$except` 排除的路由 | `teams/team4/config_auditor.md` 的 CORS 审查结果; 检查 `VerifyCsrfToken::$except` 和 API 路由中间件组 |
| **session_auditor Session 管理均已加固**（strict_mode=1, regenerate_id 正确, HttpOnly/Secure 均设置） | pivot 到 **Session 序列化注入**: 检查 `session.serialize_handler` 不一致（php vs php_serialize）导致的反序列化注入，或 Session 存储后端（Redis/Memcached）的认证缺失 | `teams/team4/deserial_auditor.md` 反序列化知识; `shared/framework_patterns.md` Session 驱动配置 |
| **ldap_auditor LDAP 过滤器已正确转义**（使用 `ldap_escape()` 或参数化查询） | pivot 到 **LDAP 认证绕过**: 检查 `ldap_bind()` 空密码/匿名绑定、DN 组件注入、LDAP 引用跟随（referral following）配置 | 无额外资源; 关注 LDAP 服务器配置而非代码层面 |
| **logging_auditor 日志记录安全无注入**（日志内容已转义、无敏感数据） | pivot 到 **日志文件包含链**: 检查日志文件路径是否与 LFI 审计的包含路径重叠，构造"日志注入 PHP 代码 → LFI 包含日志文件"攻击链 | `teams/team4/lfi_auditor.md` LFI 知识; 需确认日志文件路径和 LFI 可控路径的交集 |

> **智能 Pivot（v2）**: 上述静态映射为基础策略。当连续 3 轮失败且静态映射不匹配时，触发智能 Pivot 子流程（详见 `shared/pivot_strategy.md`）：先执行 Mini-Researcher 重新侦察目标代码 → 查阅 shared_findings 交叉情报 → 按失败模式决策树选择新攻击方向。若 Pivot 后仍无法突破，提前终止并给出人工审查建议。

── Mini-Researcher 委派机制（按需触发）──

> 详见 `teams/team4/mini_researcher.md` — 完整的研究员 Agent 定义。

**设计原则**: 借鉴 PentAGI 的 Expert Delegation 模式 — 当 Auditor 遇到超出其知识范围的问题时，不应盲目尝试，而应委派专门的研究员 Agent 获取情报后再行动。

**触发条件**（满足任一即由主调度器 spawn Mini-Researcher）:

| 编号 | 触发场景 | 判断标准 | 委派内容 |
|------|----------|----------|----------|
| MR-1 | Auditor 遇到未知第三方组件 | `dep_scanner` 输出中存在不在 `framework_patterns.md` 中的组件 | 搜索该组件的已知 CVE + 利用方法 |
| MR-2 | version_alerts 有 Critical CVE 但缺利用细节 | `version_alerts[].severity = "critical"` 且 `known_cves.md` 中无对应 PoC | 搜索具体 CVE 的利用链 + 前置条件 |
| MR-3 | Auditor 连续 5 轮失败且 filter_strength_score ≥ 61 | 攻击日志中连续 5 个 round 的 verdict 均为 failed | 研究目标过滤机制的已知绕过技术 |
| MR-4 | Pivot 后仍失败（二次卡死） | pivot_triggered = true 后又连续 3 轮失败 | 全面搜索目标环境下的替代攻击面 |
| MR-5 | 发现非标准框架特性 | Auditor 在分析阶段遇到无法识别的安全中间件/过滤器 | 该特性的安全影响 + 绕过方法 |

**委派流程**:

1. **主调度器检测触发条件**: 在 Step 2 串行攻击循环中，每个 Auditor 的每轮攻击后检查上述 5 个条件
2. **构造研究请求**:
   ```json
   {
     "research_query": "Laravel Sanctum 2.x 的 token 验证是否存在时间竞争绕过",
     "context": "authz_auditor 在 /api/admin/* 路由连续 5 轮失败，所有 token 伪造尝试被正确拒绝",
     "target_component": "laravel/sanctum@2.15.1"
   }
   ```
3. **Spawn Mini-Researcher**:
   ```
   Agent(name="mini-researcher-{N}", team_name="php-audit", foreground, mode="bypassPermissions", subagent_type="general-purpose")
     → prompt: teams/team4/mini_researcher.md
             + RESEARCH_QUERY + CONTEXT + TARGET_COMPONENT
             + WORK_DIR + SKILL_DIR
   ```
4. **注入研究结果**: 研究员输出 `$WORK_DIR/research/{research_id}.json` 后，主调度器将结果摘要注入请求研究的 Auditor 的下一轮攻击 prompt 中:
   ```
   ## 研究员情报（自动注入）
   针对你的问题: "{research_query}"
   研究员发现: {findings 摘要}
   建议尝试: {recommendations}
   置信度: {confidence} | 来源: {sources}
   ```
5. **Auditor 继续攻击**: 收到研究结果后，Auditor 根据情报调整策略，继续剩余攻击轮次

**约束**:
- 每次审计最多触发 **10 次**研究委派（全局计数器 `research_count`，超限则跳过）
- 每次研究限时 **3 分钟**，超时返回已有部分结果
- Mini-Researcher 只研究不攻击（不发送 HTTP 请求、不操作容器）
- 研究结果必须标注来源和置信度，Auditor 不得将 `low` 置信度的情报作为唯一依据

**pivot 执行流程**:
1. 专家 Agent 在攻击日志中标记 `pivot_triggered: true` + 原因
2. 主调度器检测到 pivot 标记后，spawn 对应的新专家（或复用同一专家的不同模式）
3. 新专家继承原专家的 context_packs 和已收集的信息，避免重复侦察
4. pivot 结果写入 `$WORK_DIR/exploits/{sink_id}_pivot.json`，与原结果合并

── Step 4: 每个 Auditor 攻击完成后立即质检（"完成一个、校验一个"）──

  **质检员池管理:** 维护一个 quality-checker 池，最大并发 min(活跃 Auditor 数, 5)。
  优先复用空闲质检员，不足时 spawn 新实例。池中质检员在 Phase 4 结束前不关闭。

  每个 Auditor 攻击阶段完成后:

  1. 检查质检员池中是否有空闲质检员:
     - 有 → 复用该质检员（write_agent 发送新任务）
     - 无且未达上限 → spawn 新质检员
     - 无且已达上限 → 等待最先完成的质检员

  2. 分配质检任务（通用 9 项 + 专项校验）:

  Agent(name="quality-checker-N", team_name="php-audit", foreground, mode="bypassPermissions", subagent_type="general-purpose")
    → prompt: teams/qc/quality_checker.md
            + references/quality_check_templates.md（阶段 4：单个 Auditor 校验 + 对应 Auditor 专项校验）
            + shared/output_standard.md + shared/evidence_contract.md
            + PHASE=4-auditor, TARGET_AGENT={auditor_name}, OUTPUT_FILES=exploits/{sink_id}.json
            + WORK_DIR

  **专项校验分配:** 质检员根据 TARGET_AGENT 类型，在 quality_check_templates.md 中定位对应专项表格:
  - rce_auditor → "rce_auditor 专项" 5 项
  - sqli_auditor → "sqli_auditor 专项" 5 项
  - xss_ssti_auditor → "xss_ssti_auditor 专项" 5 项
  - ... 共 21 种 Auditor 各有专项校验（每种 5 项）

  质检员必须同时填写: 通用 9 项表格 + 对应专项 5 项表格 = 总计 14 项校验。

  3. 处理质检结果:
  - verdict=pass → 关闭该 Auditor，质检员标记空闲可复用
  - verdict=fail → 将 failed_items(含专项不通过项) 发回该 Auditor 补充:
    * 第 1 次重做: Auditor 按修复要求补充物证
    * 第 2 次重做: 仍不通过 → 降级该 Auditor 的 confidence（confirmed → suspected），不再重做
  - 所有 redo 记录写入 SQLite: `bash tools/audit_db.sh qc-write "$WORK_DIR" '{...}'`

  **并行质检示例:** 若 sqli_auditor、rce_auditor、xss_ssti_auditor 依次完成攻击:
  ```
  sqli_auditor 完成 → spawn quality-checker-1（校验 sqli 通用+专项）
  rce_auditor 完成  → spawn quality-checker-2（校验 rce 通用+专项）
  xss_ssti_auditor 完成 → quality-checker-1 空闲 → 复用（校验 xss 通用+专项）
  ```

── Step 5: Phase 4 综合校验 + 跨阶段一致性校验 ──

  全部 Auditor 单独校验通过后，spawn 一个质检员做综合校验:

  Agent(name="quality-checker-final-phase4", team_name="php-audit", foreground, mode="bypassPermissions", subagent_type="general-purpose")
    → prompt: teams/qc/quality_checker.md
            + references/quality_check_templates.md（阶段 4：物理取证综合校验 + 跨阶段数据一致性校验）
            + shared/output_standard.md + shared/evidence_contract.md + shared/false_positive_patterns.md
            + PHASE=4, TARGET_AGENT=team4, OUTPUT_FILES=team4_progress.json,exploits/,priority_queue.json,auth_matrix.json,credentials.json
            + WORK_DIR

  综合质检员执行两部分:
  (a) 物理取证综合校验（8 项）— team4_progress.json + exploits/*.json 完整性
  (b) 跨阶段数据一致性校验（18 项）— P0覆盖/auth一致/Sink映射/过滤绕过/凭证深度/EVID完整

  verdict=fail:
  - 综合校验不通过 → 定位具体 Auditor 补充（不启动新 redo 计数器，属 Phase 4 整体流程）
  - 跨阶段一致性 MUST-PASS(C1-C4,C16-C18) 不通过 → 强制修复
  - 跨阶段一致性 SHOULD-PASS(C5-C15) 允许 ≤2 项 WARN → 标注降级继续

完成
解析综合质检结果，关闭 Phase 4 质检员池中所有质检员

**Phase-4 Gate 验证**（必须执行）:
```bash
test -d "$WORK_DIR/exploits" && ls "$WORK_DIR/exploits/"*.json >/dev/null 2>&1 && echo "GATE-4 PASS" || echo "GATE-4 FAIL: exploits/ 不存在或为空，report-writer 将无法生成 Burp 复现包"
```
GATE-4 PASS → 写入 checkpoint.json: {"completed": ["env", "scan", "trace", "exploit"], "current": "report"}

**生成漏洞汇总**: GATE-4 PASS 后立即执行:
```bash
# 汇总所有 exploit 结果生成 exploit_summary.json
CONFIRMED=$(cat "$WORK_DIR/exploits/"*.json 2>/dev/null | jq -s '[.[] | select(.final_verdict=="confirmed")] | length')
SUSPECTED=$(cat "$WORK_DIR/exploits/"*.json 2>/dev/null | jq -s '[.[] | select(.final_verdict=="suspected")] | length')
TOTAL=$(ls "$WORK_DIR/exploits/"*.json 2>/dev/null | wc -l)
RACE=$(cat "$WORK_DIR/exploits/"*.json 2>/dev/null | jq -s '[.[] | select(.race_condition_results.result=="vulnerable")] | length')
cat > "$WORK_DIR/exploit_summary.json" << EOF
{
  "total_sinks": $TOTAL,
  "vulnerabilities_confirmed": $CONFIRMED,
  "vulnerabilities_suspected": $SUSPECTED,
  "race_conditions_found": $RACE
}
EOF
```

GATE-4 FAIL → **不写入 checkpoint**。检查 Phase-4 专家 Agent 是否实际被 spawn。如果未 spawn，立即回到 Phase-4 Step 1 执行。

打印流水线视图

