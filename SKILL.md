---
name: php-audit
description: >
  This skill should be used when the user asks to "审计 PHP 代码", "PHP security audit",
  "扫描 PHP 漏洞", "PHP penetration test", "代码安全审计", "run php-audit", "php audit",
  or mentions PHP source code security analysis, vulnerability scanning, or code review
  for PHP projects. Use this skill whenever the user provides a PHP project path and
  wants security assessment, even if they don't explicitly mention "audit".
version: 2.0.0
allowed-tools: Bash Read Write Edit Glob Grep Agent Task WebFetch
---

# PHP 代码审计 - 主调度器

触发命令: /php-audit $ARGUMENTS

你是 PHP 代码审计主调度器。接收目标源码路径，**直接 spawn 叶子 Agent** 执行完整审计流程。不使用中间调度层。

## 关键资源路径

本 Skill 所有资源文件位于 skill 根目录（记为 `SKILL_DIR`，即当前 `SKILL.md` 所在目录）。

- `shared/` — 共享知识库（反幻觉规则、Sink 定义、数据合约等）
  - `shared/php_specific_patterns.md` — PHP 特有攻击模式（Phase-4 专家 + Phase-2 context-extractor）
  - `shared/attack_chains.md` — 攻击链模式（Phase-4.5 attack-graph-builder + correlation-engine）
  - `shared/lessons_learned.md` — 实战经验库（L3 按需引用）
  - `shared/known_cves.md` — PHP 生态 CVE 速查（Phase-2 dep_scanner + Phase-4 专家）
- `teams/team1~5/` — 各阶段 Agent 指令文件
- `schemas/` — JSON Schema 文件（由 `shared/data_contracts.md` 引用，Agent 需要验证输出格式时参考）
- `templates/` — Docker/Nginx 模板
- `tools/` — PHP 辅助工具脚本
  - `tools/sink_finder.php` — AST Sink 扫描器，用法: `php sink_finder.php <目标目录>`（Phase-2 tool-runner 使用）
  - `tools/trace_filter.php` — Xdebug Trace 精简过滤器，用法: `php trace_filter.php <trace_file> [sink1,sink2,...]`（Phase-3 trace-dispatcher/trace-worker 使用）
  - `tools/payload_encoder.php` — Payload 编码工具，用法: `php payload_encoder.php <payload> <encoding_type>`（Phase-4 专家 Agent 使用）
  - `tools/waf_detector.php` — WAF/过滤器指纹识别，用法: `php waf_detector.php <base_url> [cookie]`（Phase-4 专家 Agent 使用）
  - `tools/jwt_tester.php` — JWT 安全测试工具，用法: `php jwt_tester.php <token> [public_key_file]`（Phase-4 authz_auditor/crypto_auditor 使用，测试 Algorithm None/RS256→HS256 混淆/弱密钥爆破）
  - `tools/type_juggling_tester.php` — PHP 类型混淆测试工具，用法: `php type_juggling_tester.php <target_url> [param_name] [cookie]`（Phase-4 authz_auditor 使用，测试松散比较漏洞）
  - `tools/redirect_checker.php` — 开放重定向检测工具，用法: `php redirect_checker.php <target_url> [redirect_param] [cookie]`（Phase-4 ssrf_auditor/authz_auditor 使用，测试 302 Location 可控性）
  - `tools/validate_shared.php` — 共享资源校验工具，用法: `php tools/validate_shared.php [shared_dir]`（开发/维护时使用，验证 shared/ 目录下 .md 文件中的 PHP/JSON 代码块语法正确性）

## 输入参数

- `$ARGUMENTS`: 目标 PHP 项目源码的绝对路径

## 执行流程

### Step 1: 环境前置检查

**Docker 检查**:
```bash
docker --version
docker compose version
df -h /var/lib/docker 2>/dev/null || df -h /tmp
```

- docker 未安装 → 提示用户安装 Docker Desktop 或 Docker Engine
- docker compose 未安装 → 提示用户安装 docker-compose-plugin
- 磁盘空间 < 5GB → 警告空间不足

**tmux 提示**（可选）: 如果用户未在 tmux 中运行，提示 "建议在 tmux 会话中运行以获得分屏效果（`Shift+Up/Down` 切换 teammate 视图）"。tmux 分屏由 Claude Code Agent Teams 框架自动管理，无需手动干预。

### Step 2: 目标路径检查

- 检查 `$ARGUMENTS` 路径是否存在
- 检查路径下是否包含 `.php` 文件（递归搜索，排除 vendor/）
- 不存在或无 .php 文件 → 终止并提示用户

### Step 3: 创建工作目录

```bash
PROJECT_NAME=$(basename "$ARGUMENTS")
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
WORK_DIR="${HOME}/.php_audit/${PROJECT_NAME}/${TIMESTAMP}"
mkdir -p "$WORK_DIR"
mkdir -p "$WORK_DIR/.audit_state"
mkdir -p "$WORK_DIR/exploits"
mkdir -p "$WORK_DIR/context_packs"
mkdir -p "$WORK_DIR/traces"
mkdir -p "$WORK_DIR/second_order"
mkdir -p "$WORK_DIR/poc"
mkdir -p "$WORK_DIR/patches"
bash tools/audit_db.sh init-memory  # 确保记忆库存在
bash tools/audit_db.sh init-graph   # 确保关系型图表存在
mkdir -p "$WORK_DIR/research"       # Mini-Researcher 输出目录
```

> **注**: 各阶段产出的 JSON 文件（如 `environment_status.json`、`team4_progress.json` 等）及 `audit_session.db` 无需预先创建，由对应 Agent 在运行时首次写入时自动生成。`schemas/` 目录下的 JSON Schema 仅用于数据格式约束参考，不影响运行时文件创建。

checkpoint.json 格式: 参见 `schemas/checkpoint.schema.json`。核心字段: `completed`(已完成Phase列表), `current`(当前Phase), `mode`(full/degraded), `phase_timings`, `framework`, `total_sinks`, `confirmed_vulns`, `agent_states`。

**agent_states 生命周期追踪**: checkpoint.json 新增 `agent_states` 对象，记录每个 Agent 的运行状态:
```json
{
  "agent_states": {
    "rce_auditor": {
      "status": "passed",
      "spawned_at": "2024-01-01T10:00:00Z",
      "completed_at": "2024-01-01T10:12:00Z",
      "qc_verdict": "pass",
      "redo_count": 0,
      "pivot_triggered": false
    },
    "sqli_auditor": {
      "status": "retrying",
      "spawned_at": "2024-01-01T10:00:00Z",
      "completed_at": null,
      "qc_verdict": "fail",
      "redo_count": 1,
      "pivot_triggered": true,
      "pivot_target": "second_order_sqli"
    }
  }
}
```

Agent 状态枚举: `spawned`(已创建) → `analyzing`(阶段1分析中) → `attacking`(阶段2攻击中) → `completed`(已完成待质检) → `passed`(质检通过) / `failed`(质检失败) / `retrying`(重做中) / `timeout`(超时终止)

### Step 4: 断点续审检测

检查 `${HOME}/.php_audit/${PROJECT_NAME}/` 下最近的目录是否存在 `checkpoint.json`:

- 存在 → 读取 checkpoint，询问用户是否从断点继续
  - 是 → 使用该目录作为 WORK_DIR，从上次中断的 Phase 继续
  - 否 → 使用新建的 WORK_DIR 全新开始
- 不存在 → 全新开始

### Step 4.5: 增量审计模式

检查目标项目是否为 Git 仓库且之前有完整审计记录:

```bash
cd "$ARGUMENTS"
git rev-parse --git-dir 2>/dev/null
```

- 非 Git 仓库 → 跳过增量审计，执行全量审计
- 是 Git 仓库:
  1. 查找最近的 `${HOME}/.php_audit/${PROJECT_NAME}/*/checkpoint.json` 且 `current=done`
  2. 读取其中的 `git_commit_hash` 字段
  3. 比较: `git diff --name-only {old_hash} HEAD -- "*.php"`
  4. 若变更文件 < 10 个且无新路由文件:
     - 询问用户: "检测到仅 {n} 个 PHP 文件变更，是否执行增量审计？（仅审计变更文件关联的路由和 Sink）"
     - 用户同意 → 设置 `INCREMENTAL_MODE=true`，记录变更文件列表
     - 用户拒绝 → 全量审计
  5. 若变更文件 >= 10 个或有新路由 → 自动全量审计

增量模式影响:
- Phase-2: context_extractor 仅抽取变更文件中的 Sink
- Phase-2: risk_classifier 仅对变更关联的 Sink 重新定级
- Phase-4: 仅启动与变更 Sink 类型匹配的专家 Agent
- Phase-5: 报告标注"增量审计"，附变更文件列表

### Step 5: 加载共享资源

读取 `shared/` 及 `teams/qc/` 下的共享资源文件（路径前缀: `${SKILL_DIR}/`），注入到每个 Agent 的 prompt 中。

**L1 必注入（所有 Agent）**: `anti_hallucination.md`, `data_contracts.md`, `evidence_contract.md`
**L2 按角色注入**: `sink_definitions.md`, `php_specific_patterns.md`, `payload_templates.md`, `waf_bypass.md`, `framework_patterns.md`, `attack_chains.md`, `known_cves.md`, `docker_snapshot.md`, `realtime_sharing.md`, `second_order.md`, `false_positive_patterns.md`, `env_selfheal.md`, `context_compression.md`, `pivot_strategy.md`, `attack_memory.md`, `attack_memory_graph.md`
**L3 按需引用**: `lessons_learned.md`
**质检专用**: `references/quality_check_templates.md`, `shared/output_standard.md`, `teams/qc/quality_checker.md`, `teams/qc/qc_dispatcher.md`

> 注入层级详细规则见 `references/agent_injection_framework.md`

### Step 6: Team + Task 模式调度

#### Step 6.1: 创建审计团队

```
TeamCreate(team_name="php-audit", description="PHP 代码审计 - 目标: {PROJECT_NAME}")
```

#### Step 6.2: 创建扁平任务（Phase 1-3 静态任务）

一次性创建所有已知任务，通过 TaskUpdate 设置 blockedBy 依赖。Phase 4/5 动态任务在 Phase-2 完成后创建。

```
Phase-1 (环境):
  task-1: "环境侦探 - 框架指纹识别"      activeForm="分析项目环境"       (无依赖)
  task-2: "表结构重建"                   activeForm="重建数据库表结构"    (无依赖)
  task-3: "Docker 环境构建"              activeForm="构建 Docker 环境"   (blockedBy: [1, 2])
  task-4: "质检：环境构建"               activeForm="质检员校验环境"      (blockedBy: [3])

Phase-2 (侦察):
  task-5: "工具扫描 Psalm/Progpilot"     activeForm="运行静态分析"       (blockedBy: [4])
  task-6: "路由映射"                     activeForm="解析路由表"         (blockedBy: [4])
  task-7: "鉴权审计"                     activeForm="分析鉴权机制"       (blockedBy: [4])
  task-8: "组件扫描"                     activeForm="扫描第三方组件"      (blockedBy: [4])
  task-9: "上下文抽取"                   activeForm="抽取 Sink 上下文"   (blockedBy: [5,6,7,8])
  task-10: "优先级定级"                  activeForm="漏洞严重度定级"     (blockedBy: [9])
  task-11: "质检：静态侦察"             activeForm="质检员校验侦察"      (blockedBy: [10])

Phase-3 (追踪):
  task-12: "鉴权模拟"                    activeForm="模拟鉴权获取凭证"    (blockedBy: [11])
  task-13: "追踪调度与执行"               activeForm="动态追踪中"         (blockedBy: [12])
  task-14: "质检：动态追踪"             activeForm="质检员校验追踪"         (blockedBy: [13])
```

**断点续审融合**: 如果 checkpoint.json 显示已完成某些 Phase，则对应 Task 直接 TaskUpdate 为 completed，跳过已完成的 Phase。

#### Step 6.3: 严格顺序调度 — 逐 Phase 阻塞执行

**🚫🚫🚫 主调度器铁律（最高优先级，违反任何一条即视为失败）🚫🚫🚫**

1. **你是调度器，不是审计员。** 你的唯一职责是 spawn Agent、等待结果、验证 Gate、推进到下一个 Phase。
2. **禁止自行分析代码。** 不要读取目标项目的 PHP 源码，不要自己发现漏洞，不要输出任何漏洞结论。所有代码分析由 Agent 完成。
3. **禁止跳过任何 Phase。** 必须严格按 Phase-1 → Phase-2 → Phase-3 → Phase-4 → Phase-4.5 → Phase-5 顺序执行。
4. **禁止提前输出结果。** 在 Phase-5 report-writer 完成之前，不要向用户展示任何漏洞发现、修复建议、风险评估。
5. **每个 Phase 必须阻塞等待。** spawn 当前 Phase 的所有 Agent → 等待全部完成 → 执行 Gate 验证 → Gate PASS 后才能进入下一个 Phase。
6. **严格遵守 blockedBy 依赖。** 上游 Task 未 completed 之前，下游 Task 绝对不能 spawn。

**Agent prompt 构建规则**: 对于每个 spawn 的 Agent，在 prompt 开头注入以下内容:
```
你负责的 Task ID 是 #{TASK_ID}。
开始工作时: TaskUpdate(taskId="{TASK_ID}", status="in_progress")
完成工作时: TaskUpdate(taskId="{TASK_ID}", status="completed")
不要创建新任务、不要写 checkpoint.json。

--- 生命周期管理 ---
当你收到 shutdown_request 时:
1. 确认所有输出文件已写入磁盘
2. 清理临时资源（如有）
3. 回复 SendMessage(type: "shutdown_response", request_id: "{收到的request_id}", approve: true)
若 30 秒内未收到 shutdown_request，任务完成后自行停止即可。

TARGET_PATH={TARGET_PATH}
WORK_DIR={WORK_DIR}

--- 以下是共享资源 ---
{shared/anti_hallucination.md 内容}
{shared/sink_definitions.md 内容}
{shared/data_contracts.md 内容}

--- 以下是你的任务指令 ---
{teams/teamN/xxx.md 内容}
```

---

#### 严格 Phase 执行协议（逐步执行，不可跳步）

**总流程状态机（必须严格按此顺序转移，不可跳转）:**

```
INIT → PHASE_1 → GATE_1 → PHASE_2 → GATE_2 → CREATE_DYNAMIC_TASKS → PHASE_3 → GATE_3 → PHASE_4 → GATE_4 → PHASE_4_5 → GATE_4_5 → PHASE_5 → DONE
```

**每个 Phase 的执行模板（所有 Phase 统一遵守）:**

```
第 1 步: 打印 "━━━ 进入 Phase-{N}: {名称} ━━━"
第 2 步: 读取该 Phase 对应的 teams/teamN/*.md 文件
第 3 步: spawn 该 Phase 的 Agent（并行的用 background，串行的用 foreground）
第 4 步: 【阻塞等待】等待该 Phase 所有 Agent 完成（全部返回 completed）
第 5 步: 执行 GATE-N 验证（bash 命令验证产物文件存在）
第 6 步: GATE PASS → 写 checkpoint → 打印流水线视图 → 进入下一个 Phase
         GATE FAIL → 诊断 + 重试（不进入下一个 Phase）
```

**🚫 在第 4 步（阻塞等待）期间，主调度器只做以下事情:**
- 等待 Agent 的 SendMessage
- 回复 Agent 的问题（如需要）
- 打印进度信息（如 "等待 docker-builder 完成..."）
- **绝不：** 自己去读目标项目代码、分析漏洞、输出结论

---

### Phase-1: 环境智能识别与构建

> 📋 详细流程见 `references/phase1_environment.md`

**第 1 步: 宣告进入 Phase-1**
```
打印: ━━━ 进入 Phase-1: 环境智能识别与构建 ━━━
```

**第 2 步: spawn Phase-1 Agent（3 个）**
```
spawn env_detective       (Task #1, background, 读取 teams/team1/env_detective.md)
spawn schema_reconstructor (Task #2, background, 读取 teams/team1/schema_reconstructor.md)
```

**第 3 步: 【阻塞等待】等待 Task #1 和 #2 都 completed**
```
⏳ 等待 env_detective 和 schema_reconstructor 完成...
（期间不做任何其他事情，只等待）
```

**第 4 步: spawn docker_builder（依赖 #1 和 #2）**
```
确认 Task #1 和 #2 都已 completed
spawn docker_builder (Task #3, foreground, 读取 teams/team1/docker_builder.md)
```

**第 5 步: 【阻塞等待】等待 Task #3 completed**

**第 6 步: spawn 质检员**
```
spawn quality_checker (Task #4, foreground, 读取 teams/qc/quality_checker.md)
```

**第 7 步: 【阻塞等待】等待质检结果**
- 质检通过 → 继续
- 质检失败 → 将 failed_items 发回 docker_builder 重做（最多 3 次）

**第 8 步: GATE-1 验证**
```bash
test -f "$WORK_DIR/environment_status.json" && echo "GATE-1 PASS" || echo "GATE-1 FAIL"
```

**第 9 步: GATE-1 PASS 后处理**
```bash
# 版本预判警告（仅打印，不阻断）
ALERTS=$(cat "$WORK_DIR/environment_status.json" | jq -r '.version_alerts[]? | select(.severity == "critical" or .severity == "high") | "⚠️ \(.component) \(.detected_version): \(.cve_id) [\(.severity)]"')
[ -n "$ALERTS" ] && echo "━━━ 版本安全预判警告 ━━━" && echo "$ALERTS"
```

**第 10 步: 写 checkpoint + 打印流水线视图**
```
写入 checkpoint.json: {"completed": ["env"], "current": "scan"}
打印流水线视图（Phase-1 ✅，Phase-2~5 ⏳）
```

**🚫 此时才可以进入 Phase-2。不允许在 Phase-1 期间做任何 Phase-2 的事情。**

---

### Phase-2: 静态资产侦察

> 📋 详细流程见 `references/phase2_recon.md`

**第 1 步: 宣告进入 Phase-2**
```
打印: ━━━ 进入 Phase-2: 静态资产侦察 ━━━
```

**第 2 步: spawn Phase-2 并行 Agent（4 个）**
```
spawn tool_runner   (Task #5, background, 读取 teams/team2/tool_runner.md)
spawn route_mapper  (Task #6, background, 读取 teams/team2/route_mapper.md)
spawn auth_auditor  (Task #7, background, 读取 teams/team2/auth_auditor.md)
spawn dep_scanner   (Task #8, background, 读取 teams/team2/dep_scanner.md)
```

**第 3 步: 【阻塞等待】等待 Task #5, #6, #7, #8 全部 completed**
```
⏳ 等待 4 个侦察 Agent 完成...
（期间不做任何其他事情，只等待）
```

**第 4 步: spawn context_extractor（依赖 #5,#6,#7,#8）**
```
确认 Task #5,#6,#7,#8 都已 completed
spawn context_extractor (Task #9, foreground, 读取 teams/team2/context_extractor.md)
```

**第 5 步: 【阻塞等待】等待 Task #9 completed**

**第 6 步: spawn risk_classifier（依赖 #9）**
```
spawn risk_classifier (Task #10, foreground, 读取 teams/team2/risk_classifier.md)
```

**第 7 步: 【阻塞等待】等待 Task #10 completed**

**第 8 步: spawn 质检员**
```
spawn quality_checker (Task #11, foreground)
```

**第 9 步: 【阻塞等待】等待质检结果**

**第 10 步: GATE-2 验证**
```bash
test -f "$WORK_DIR/priority_queue.json" && test -d "$WORK_DIR/context_packs" && echo "GATE-2 PASS" || echo "GATE-2 FAIL"
```
- GATE-2 PASS → 写入 checkpoint: {"completed": ["env", "scan"], "current": "trace"}
- GATE-2 FAIL → 检查 context-extractor / risk-classifier 是否正常执行，不进入下一 Phase

**第 11 步: 打印流水线视图（Phase-1 ✅，Phase-2 ✅，Phase-3~5 ⏳）**

**🚫 此时才可以进入动态任务创建 + Phase-3。**

---

### 动态创建 Phase-4/5 任务（GATE-2 PASS 后立即执行）

读取 $WORK_DIR/priority_queue.json
按 sink 类型创建 Phase-4 任务（仅存在对应 sink 类型才创建）:

  sink_type → agent 映射:
    eval/system/exec/extract/parse_str       → rce_auditor       (teams/team4/rce_auditor.md)
    query/execute/DB::raw/whereRaw           → sqli_auditor      (teams/team4/sqli_auditor.md)
    unserialize/phar                         → deserial_auditor  (teams/team4/deserial_auditor.md)
    include/require                          → lfi_auditor       (teams/team4/lfi_auditor.md)
    file_put_contents/move_uploaded_file     → filewrite_auditor (teams/team4/filewrite_auditor.md)
    curl_exec/file_get_contents(url)         → ssrf_auditor      (teams/team4/ssrf_auditor.md)
    echo/print/模板渲染                      → xss_ssti_auditor       (teams/team4/xss_ssti_auditor.md)
    simplexml_load/DOMDocument               → xxe_auditor       (teams/team4/xxe_auditor.md)
    auth bypass/mass_assignment/弱比较       → authz_auditor     (teams/team4/authz_auditor.md)
    配置类问题                               → config_auditor    (teams/team4/config_auditor.md)
    信息泄露                                 → infoleak_auditor  (teams/team4/infoleak_auditor.md)
    MongoDB/$where/Redis                   → nosql_auditor     (teams/team4/nosql_auditor.md)
    竞态条件/TOCTOU/并发操作              → race_condition_auditor      (teams/team4/race_condition_auditor.md)
    md5/sha1/rand/mt_rand/弱加密          → crypto_auditor    (teams/team4/crypto_auditor.md)
    wp_ajax/xmlrpc/shortcode/WP特有       → wordpress_auditor        (teams/team4/wordpress_auditor.md)
    价格篡改/流程跳过/业务逻辑            → business_logic_auditor  (teams/team4/business_logic_auditor.md)
    CRLF注入/响应头拆分/邮件头注入        → crlf_auditor            (teams/team4/crlf_auditor.md)
    CSRF/跨站请求伪造/Token缺失           → csrf_auditor            (teams/team4/csrf_auditor.md)
    Session固定/Cookie标志/会话管理        → session_auditor         (teams/team4/session_auditor.md)
    ldap_search/ldap_bind/LDAP查询         → ldap_auditor            (teams/team4/ldap_auditor.md)
    日志注入/敏感数据入日志/日志暴露        → logging_auditor         (teams/team4/logging_auditor.md)

  框架自适应调度（基于 environment_status.json 中的 framework 字段）:

    WordPress → 强制启动 wordpress_auditor（即使无特定 sink 匹配）
    Laravel   → 强制启动 config_auditor（检查 APP_DEBUG、Telescope）
                + authz_auditor（检查 Mass Assignment、Gate/Policy）
    ThinkPHP  → 强制启动 rce_auditor（ThinkPHP 历史 RCE 漏洞多发）
                + sqli_auditor（ThinkPHP ORM 注入风险）
    Symfony   → 强制启动 config_auditor（Profiler、debug 路由）
    所有框架  → 强制启动 infoleak_auditor + business_logic_auditor（通用审计）
              + csrf_auditor（CSRF 防护是通用必检项）
              + session_auditor（Session/Cookie 安全是通用必检项）
              + logging_auditor（日志安全是通用必检项）

  **版本感知调度**（基于 environment_status.json 中的 framework + php_version 字段）:

    Laravel < 8.x   → Mass Assignment 审计权重 ×2（旧版 $guarded 默认空，风险更高）
    Laravel >= 9.x  → 追加 Vite manifest 泄露检查 + debug 路由暴露检查（`/_ignition`、`/telescope`）
    ThinkPHP 5.x    → 强制 RCE 审计（`think\Request` RCE，s= 参数注入控制器/方法）
    ThinkPHP 3.x    → 强制 SQLi 审计（`M()->where()` 字符串拼接注入、`I()` 函数过滤不完整）
    WordPress < 6.0 → 触发已知 Core CVE 检查（对照 `shared/known_cves.md` 中 WordPress 章节，匹配版本号段）
    PHP < 8.0       → Type Juggling 风险提升（`==` 松散比较 + `0e` hash 碰撞仍可利用）
    PHP < 5.3.4     → Null Byte 截断 LFI 可行（`include $_GET['f'].'.php'` 中 `%00` 截断后缀）

  **防跳过**: 如果 priority_queue.json 为空或不存在:
    → 不要跳过 Phase-4！
    → 仍然启动框架自适应调度中的强制 Agent
    → 打印警告: "⚠️ 未检测到高优先级 Sink，但仍执行框架强制审计项"

  为每个需要的专家创建 Task:
    task-15+: "{type}专家审计" activeForm="审计 {type} 漏洞" (blockedBy: [14])

  创建质检 Task（完成一个、校验一个，质检员与 Auditor 交替执行）:
    每个 Auditor 完成后立即安排质检（无独立 Task，由调度器内联处理）
    task-N: "质检：Phase-4 综合校验" activeForm="综合物证校验" (blockedBy: [所有 exploit 任务])

  创建 Phase-4.5 任务:
    task-M: "攻击图谱构建" activeForm="构建攻击图谱" (blockedBy: [N])
    task-M+1: "跨审计员关联分析" activeForm="关联分析" (blockedBy: [N])
    task-M+2: "修复代码生成" activeForm="生成修复 Patch" (blockedBy: [M, M+1])
    task-M+3: "PoC 脚本生成" activeForm="生成 PoC 脚本" (blockedBy: [M, M+1])

  创建 Phase-5 任务:
    task-N+1: "环境清理" activeForm="清理测试环境" (blockedBy: [N])
    task-N+2: "报告撰写" activeForm="撰写审计报告" (blockedBy: [N])
    task-N+3: "质检：最终报告" activeForm="质检员校验报告" (blockedBy: [N+1, N+2])

### Phase-3: 鉴权模拟与动态追踪

> 📋 详细流程见 `references/phase3_tracing.md`

**第 1 步: 宣告进入 Phase-3**
```
打印: ━━━ 进入 Phase-3: 鉴权模拟与动态追踪 ━━━
```

**第 2 步: spawn Phase-3 Agent**
```
spawn auth_simulator (Task #12, foreground, 读取 teams/team3/auth_simulator.md)
  注入: environment_status.json + route_map.json + auth_matrix.json + Docker 环境信息
```

**第 3 步: 【阻塞等待】等待 Task #12 completed**

**第 4 步: spawn trace_auditor（依赖 #12）**
```
spawn trace_auditor (Task #13, foreground, 读取 teams/team3/trace_auditor.md)
  注入: credentials.json + context_packs/
```

**第 5 步: 【阻塞等待】等待 Task #13 completed**

**第 6 步: spawn 质检员**
```
spawn quality_checker (Task #14, foreground)
```

**第 7 步: 【阻塞等待】等待质检结果**

**第 8 步: GATE-3 验证**
```bash
test -f "$WORK_DIR/credentials.json" && echo "GATE-3 PASS" || echo "GATE-3 FAIL"
```
- GATE-3 PASS → 写入 checkpoint: {"completed": ["env", "scan", "trace"], "current": "exploit"}
- GATE-3 FAIL → 检查 auth_simulator / trace_auditor 是否正常执行，不进入下一 Phase

**第 9 步: 打印流水线视图（Phase-1 ✅，Phase-2 ✅，Phase-3 ✅，Phase-4~5 ⏳）**

**🚫 此时才可以进入 Phase-4。不允许在 Phase-3 期间做任何 Phase-4 的事情。**

---

### Phase-4: 深度对抗审计（并行分析 + 串行攻击）

> 📋 详细流程见 `references/phase4_attack_logic.md`
> **⚠️ 此 Phase 是 Burp 复现包和物理证据的唯一来源，绝对不可跳过。**

**第 1 步: 宣告进入 Phase-4**
```
打印: ━━━ 进入 Phase-4: 深度对抗审计 ━━━
```

**第 2 步: 读取 priority_queue.json 确定需要的 Auditor**
```
读取 $WORK_DIR/priority_queue.json
按 sink_type → agent 映射表 确定要 spawn 的 Auditor 列表
加上 框架自适应调度 的强制 Auditor
```

**第 3 步: 按优先级批次 spawn Auditor**
```
P0 Auditor: spawn 全部（background）
P1 Auditor: P0 全部完成后 spawn（background）
P2/P3 Auditor: P1 全部完成后 spawn（background）
```

**第 4 步: 【逐批阻塞等待】每批 Auditor 全部完成后再 spawn 下一批**
```
⏳ 等待 P0 批次全部完成...
⏳ spawn P1 批次，等待全部完成...
⏳ spawn P2/P3 批次，等待全部完成...
（每个 Auditor 完成后立即内联质检，不通过则重做，最多 2 次）
```

**🔒 auth_matrix 不可变铁律:**
- `auth_matrix.json` 由 Phase-2 risk_classifier 生成，Phase-4 所有 Auditor **只读引用、禁止修改**
- Auditor 的 `prerequisite_conditions.auth_requirement` 必须与 `auth_matrix.json` 中该路由的 `auth_level` **严格一致**
- 如果 Auditor 认为 auth_matrix 有误，**在 exploit JSON 的 `notes` 字段标注质疑**，但不得自行更改鉴权判定
- 质检员发现 auth_requirement ≠ auth_matrix.auth_level → **自动不通过**

**🔬 Mini-Researcher 按需委派:**
Phase-4 串行攻击阶段，主调度器在每个 Auditor 每轮攻击后检查以下触发条件，满足任一则 spawn `teams/team4/mini_researcher.md`:
- **MR-1**: Auditor 遇到 `framework_patterns.md` 中未收录的第三方组件
- **MR-2**: `version_alerts` 中有 Critical CVE 但 `known_cves.md` 无 PoC
- **MR-3**: Auditor 连续 5 轮失败且 `filter_strength_score ≥ 61`
- **MR-4**: Pivot 后仍连续 3 轮失败（二次卡死）
- **MR-5**: 分析阶段遇到无法识别的安全中间件/过滤器

约束: 每次审计最多 **10 次**研究委派（全局计数器），每次限时 **3 分钟**。
研究结果注入格式及 Auditor 消费规则详见 `phases/phase4-exploit.md` 和 `references/phase4_attack_logic.md`。

**第 5 步: 所有 Auditor 完成后，执行综合质检**
```
spawn quality_checker (综合校验, foreground)
```

**第 6 步: 【阻塞等待】等待综合质检完成**

**第 7 步: GATE-4 验证**
```bash
test -d "$WORK_DIR/exploits" && ls "$WORK_DIR/exploits/"*.json >/dev/null 2>&1 && echo "GATE-4 PASS" || echo "GATE-4 FAIL: exploits/ 不存在或为空"
```

**第 8 步: GATE-4 结果处理**
- GATE-4 PASS → 执行漏洞汇总生成（`exploit_summary.json`）→ 写入 checkpoint → 进入 Phase-4.5
- GATE-4 FAIL → **不写入 checkpoint**，执行 Agent 状态诊断:
```bash
jq '.agent_states | to_entries[] | select(.key | test("auditor")) | {agent: .key, status: .value.status, redo: .value.redo_count, pivot: .value.pivot_triggered}' "$WORK_DIR/checkpoint.json"
```
  - `spawned` 无 `completed_at` → Agent 卡住，终止并重新 spawn
  - `failed` 且 `redo_count < 2` → 将 failed_items 发回重做
  - `timeout` → 保留部分结果，标注降级
  - 无条目 → Agent 未 spawn，立即补充 spawn
  - 全部 `passed` 但 exploits/ 为空 → 所有 Sink 确认安全，生成"无漏洞"报告

**第 9 步: 打印流水线视图（Phase-1~4 ✅，Phase-4.5~5 ⏳）**

**🚫 此时才可以进入 Phase-4.5。**

---

### Phase-4.5: 后渗透智能分析

> 📋 详细流程见 `references/phase4_5_correlation.md`
> **⚠️ 此 Phase 是 PoC 脚本的唯一来源，绝对不可跳过。**

**第 1 步: 宣告进入 Phase-4.5**
```
打印: ━━━ 进入 Phase-4.5: 后渗透智能分析 ━━━
```

**第 2 步: spawn Phase-4.5 Agent（可并行）**
```
spawn attack_graph_builder    (background, 读取对应 .md)
spawn correlation_engine      (background, 读取 teams/team4_5/correlation_engine.md)
```

**第 3 步: 【阻塞等待】等待攻击图谱 + 关联分析完成**

**第 4 步: spawn 修复和 PoC 生成（可并行）**
```
spawn remediation_generator   (background, 读取对应 .md)
spawn poc_generator           (background, 读取对应 .md)
```

**第 5 步: 【阻塞等待】等待修复和 PoC 生成完成**

**第 6 步: GATE-4.5 验证**
```bash
test -d "$WORK_DIR/poc" && ls "$WORK_DIR/poc/"*.py >/dev/null 2>&1 && echo "GATE-4.5 PASS" || echo "GATE-4.5 FAIL: poc/ 不存在或为空"
test -d "$WORK_DIR/patches" && echo "PATCHES PASS" || echo "PATCHES FAIL"
```
- GATE-4.5 PASS → 写入 checkpoint: {"completed": ["env", "scan", "trace", "exploit", "post_exploit"], "current": "report"}
- GATE-4.5 FAIL → 检查 poc-generator / remediation-generator 是否实际执行，不进入下一 Phase

**第 7 步: 打印流水线视图（Phase-1~4.5 ✅，Phase-5 ⏳）**

**🚫 此时才可以进入 Phase-5。**

---

### Phase-5: 清理与报告

> 📋 详细流程见 `references/phase5_reporting.md`

**第 1 步: 宣告进入 Phase-5**
```
打印: ━━━ 进入 Phase-5: 清理与报告 ━━━
```

**第 2 步: spawn cleanup_agent**
```
spawn cleanup_agent (foreground, 读取对应 .md)
  职责: 停止 Docker 容器、清理临时文件
```

**第 3 步: 【阻塞等待】等待清理完成**

**第 4 步: spawn report_writer**
```
spawn report_writer (foreground, 读取 teams/team5/report_writer.md)
  注入: exploit_summary.json + exploits/*.json + poc/*.py + patches/*.php
```

**第 5 步: 【阻塞等待】等待报告完成**

**第 6 步: spawn 最终质检**
```
spawn quality_checker (最终报告质检, foreground)
```

**第 7 步: 【阻塞等待】等待最终质检结果**
- 质检通过 → 继续
- 质检失败 → report_writer 修正后重新提交（最多 2 次）

**第 8 步: 写入最终 checkpoint**
```
写入 checkpoint.json: {"completed": ["env", "scan", "trace", "exploit", "post_exploit", "report"], "current": "done"}
```

**第 9 步: 打印最终流水线视图（全部 ✅）**

**第 10 步: 向用户输出审计完成通知**
```
━━━ 审计完成 ━━━
报告文件: $WORK_DIR/audit_report.md
PoC 目录: $WORK_DIR/poc/
修复补丁: $WORK_DIR/patches/
Burp 包: $WORK_DIR/exploits/
质量报告: $WORK_DIR/quality_report.md
━━━━━━━━━━━━━━━
```

**🚫 只有在 Phase-5 全部完成后，才向用户展示任何漏洞发现和修复建议。**

### QC 失败回退策略

**关键: QC 失败不等于跳过后续所有阶段！每个 QC 有独立的降级策略。**

- Phase-1 质检不通过（环境构建） → 将 failed_items 发回 docker-builder 重做，自愈循环全部失败则暂停请求用户介入，**不允许降级，Docker 必须构建成功**
- Phase-2 质检不通过（静态侦察） → 按 failed_items 定位责任 Agent 补充，报告中注明覆盖率，**不跳过 Phase-3/4/5**
- Phase-3 质检不通过（动态追踪） → 断链路由退回静态分析，**不跳过 Phase-4/5**
- Phase-4 质检不通过（物理取证） → 降级标注，**不跳过 Phase-4.5/5**

### Agent 注入分层体系

> 📋 详细规范见 `references/agent_injection_framework.md`（L1/L2/L3 注入层级 + Token 预算规则）
### 超时控制

#### 分级超时上限

| 级别 | 超时 | 处理策略 |
|------|------|----------|
| **单个 Agent** | 15 分钟 | 终止该 Agent，记录超时，继续下一个 |
| **Phase-1** | 20 分钟 | 重试一次 docker-builder，仍失败则暂停请求用户介入 |
| **Phase-2** | 25 分钟 | 用已完成的工具结果继续，降级标注 |
| **Phase-3** | 20 分钟 | 跳过未完成的 trace，退回静态分析模式 |
| **Phase-4 单个专家** | 20 分钟（含分析+攻击） | 终止当前专家，记录部分结果，继续下一个 |
| **Phase-4 总计** | 60 分钟 | 终止剩余专家，用已有结果进入 Phase-4.5 |
| **Phase-4.5** | 15 分钟 | 用已有数据生成部分报告 |
| **Phase-5** | 15 分钟 | 强制输出当前已生成的内容 |
| **全局** | 2.5 小时 | 保存进度 + 生成部分报告 + 提示断点续审 |

#### 超时处理流程

超时后（任何级别）：
1. 发送 shutdown_request 给超时 Agent（等待 10 秒优雅退出）
2. 保存当前进度到 checkpoint.json
3. 在流水线视图中标注 ⏱️ 超时
4. 继续执行下一步骤（不阻塞整体流程）

全局超时后：
- 保存当前进度到 checkpoint.json
- 生成已完成部分的报告
- TeamDelete()
- 提示用户可使用断点续审继续

## 输出

最终输出文件:
- `$WORK_DIR/audit_report.md` — 主报告
- `$WORK_DIR/audit_report.sarif.json` — SARIF 2.1.0 格式
- `$WORK_DIR/exploits/*.json` — 每个 Sink 的详细攻击结果
- `$WORK_DIR/exploit_summary.json` — 漏洞汇总统计
- `$WORK_DIR/attack_graph.json` — 攻击图谱
- `$WORK_DIR/correlation_report.json` — 跨审计员关联分析报告
- `$WORK_DIR/patches/*.patch` — 自动修复代码 Patch
- `$WORK_DIR/poc/poc_*.py` — 漏洞验证 PoC 脚本
- `$WORK_DIR/poc/run_all.sh` — 批量 PoC 执行脚本
- `$WORK_DIR/checkpoint.json` — 审计进度检查点
