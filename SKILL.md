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
WORK_DIR="/tmp/${PROJECT_NAME}/${TIMESTAMP}"
mkdir -p "$WORK_DIR"
```

checkpoint.json 完整格式:
```json
{
  "project_name": "string",
  "target_path": "string",
  "work_dir": "string",
  "git_commit_hash": "string|null (目标项目的 Git HEAD hash)",
  "incremental_mode": "boolean",
  "changed_files": ["string (增量模式下的变更文件列表)"],
  "completed": ["string (已完成的 Phase: env/scan/trace/exploit/report)"],
  "current": "string (当前 Phase)",
  "mode": "string (full/degraded/static-only)",
  "started_at": "string (ISO 8601)",
  "updated_at": "string (ISO 8601)",
  "phase_timings": {
    "env": "number (秒)",
    "scan": "number (秒)",
    "trace": "number (秒)",
    "exploit": "number (秒)",
    "report": "number (秒)"
  },
  "framework": "string (检测到的框架)",
  "total_sinks": "number",
  "confirmed_vulns": "number",
  "suspected_vulns": "number"
}
```

### Step 4: 断点续审检测

检查 `/tmp/${PROJECT_NAME}/` 下最近的目录是否存在 `checkpoint.json`:

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
  1. 查找最近的 `/tmp/${PROJECT_NAME}/*/checkpoint.json` 且 `current=done`
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

读取以下共享资源文件内容（路径前缀: `${SKILL_DIR}/`），后续注入到每个 Agent 的 prompt 中:

- `shared/anti_hallucination.md` — 反幻觉规则（所有 Agent 必须遵守）
- `shared/sink_definitions.md` — Sink 函数定义（所有 Agent 共用）
- `shared/data_contracts.md` — JSON Schema 数据合约（Agent 间通信格式）
- `shared/env_selfheal.md` — 兼容性自愈策略映射表（@docker-builder 专用）
- `shared/docker_snapshot.md` — Docker 快照管理指令（Phase-4 专家 Agent 专用）
- `shared/realtime_sharing.md` — 实时发现共享协议（Phase-4 专家 Agent 专用）
- `shared/second_order.md` — 二阶漏洞追踪规范（Phase-4 专家 Agent 专用）
- `shared/false_positive_patterns.md` — 误报模式库（QC-3 + 关联引擎专用）
- `shared/payload_templates.md` — 分类攻击 Payload 模板（Phase-4 专家 Agent 专用）
- `shared/waf_bypass.md` — WAF 绕过策略字典（Phase-4 专家 Agent 专用）
- `shared/framework_patterns.md` — 框架安全/不安全模式速查（Phase-2 context-extractor/risk-classifier + Phase-4 专家 + Phase-4.5 remediation-generator）
- `shared/php_specific_patterns.md` — PHP 特有攻击模式（所有 Phase-4 专家 + Phase-2 context-extractor）
- `shared/attack_chains.md` — 攻击链模式（Phase-4.5 attack-graph-builder + correlation-engine）
- `shared/lessons_learned.md` — 实战经验库（可选加载，L3 按需引用）
- `shared/known_cves.md` — PHP 生态 CVE 速查（Phase-2 dep_scanner + Phase-4 专家）

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
  task-4: "QC-0 环境验证"               activeForm="验证环境完整性"      (blockedBy: [3])

Phase-2 (侦察):
  task-5: "工具扫描 Psalm/Progpilot"     activeForm="运行静态分析"       (blockedBy: [4])
  task-6: "路由映射"                     activeForm="解析路由表"         (blockedBy: [4])
  task-7: "鉴权审计"                     activeForm="分析鉴权机制"       (blockedBy: [4])
  task-8: "组件扫描"                     activeForm="扫描第三方组件"      (blockedBy: [4])
  task-9: "上下文抽取"                   activeForm="抽取 Sink 上下文"   (blockedBy: [5,6,7,8])
  task-10: "优先级定级"                  activeForm="漏洞严重度定级"     (blockedBy: [9])
  task-11: "QC-1 侦察完整性"             activeForm="验证侦察完整性"      (blockedBy: [10])

Phase-3 (追踪):
  task-12: "鉴权模拟"                    activeForm="模拟鉴权获取凭证"    (blockedBy: [11])
  task-13: "追踪调度与执行"               activeForm="动态追踪中"         (blockedBy: [12])
  task-14: "QC-2 调用链验证"             activeForm="验证调用链"         (blockedBy: [13])
```

**断点续审融合**: 如果 checkpoint.json 显示已完成某些 Phase，则对应 Task 直接 TaskUpdate 为 completed，跳过已完成的 Phase。

#### Step 6.3: 扁平调度 — 直接 spawn 叶子 Agent

**核心原则**:
1. 每个 Phase 完成后，打印**累积更新**的流水线视图（参考 `references/pipeline_view.md`）
2. **直接读取 `teams/**/*.md` 文件作为 Agent prompt**，不使用中间调度 skill
3. 每个 Agent 的 prompt = 叶子 Agent .md 内容 + 共享资源 + TASK_ID + TARGET_PATH + WORK_DIR
4. 并行 Agent 用 `background` 模式 spawn，串行 Agent 用 `foreground` 模式
5. **Phase 间部分并行**: Phase-2 的 tool-runner/route-mapper/auth-auditor/dep-scanner 完成后，
   若 Docker 环境已就绪（QC-0 通过），可立即启动 Phase-3 的 auth-simulator，
   与 Phase-2 的 context-extractor/risk-classifier 并行执行。
   条件: auth-simulator 不依赖 context_packs（它只需要 route_map + auth_matrix + Docker 环境）。

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

#### Phase Gate Protocol（Phase 间产物验证 — 强制执行）

**⚠️ 此规则优先级最高，违反将导致报告缺失 Burp 复现包和 PoC。**

在将任何 Phase 标记为 completed 写入 checkpoint.json **之前**，必须执行 bash 验证该 Phase 的产物文件确实存在于磁盘:

```bash
# Phase-1 gate
test -f "$WORK_DIR/environment_status.json" && echo "GATE-1 PASS" || echo "GATE-1 FAIL: environment_status.json missing"

# Phase-2 gate
test -f "$WORK_DIR/priority_queue.json" && test -d "$WORK_DIR/context_packs" && echo "GATE-2 PASS" || echo "GATE-2 FAIL"

# Phase-3 gate（static-only 模式豁免）
test -f "$WORK_DIR/credentials.json" && echo "GATE-3 PASS" || echo "GATE-3 FAIL"

# Phase-4 gate ← 关键！缺失此产物 = 报告无 Burp 包
test -d "$WORK_DIR/exploits" && ls "$WORK_DIR/exploits/"*.json >/dev/null 2>&1 && echo "GATE-4 PASS" || echo "GATE-4 FAIL: exploits/ 不存在或为空"

# Phase-4.5 gate ← 关键！缺失此产物 = 报告无 PoC
test -d "$WORK_DIR/poc" && ls "$WORK_DIR/poc/"*.py >/dev/null 2>&1 && echo "GATE-4.5 PASS" || echo "GATE-4.5 FAIL: poc/ 不存在或为空"
```

**GATE FAIL 时的处理**: 不要写入 checkpoint.json 完成标记。检查该 Phase 的 Agent 是否实际被 spawn 并返回了结果。如果 Agent 未被 spawn，立即 spawn 执行。如果 Agent 返回为空，记录降级警告后继续。

**⚠️ 绝对禁止**: 在未实际 spawn Phase-4/4.5 Agent 的情况下，将 exploit/post_exploit 写入 checkpoint.completed。这会导致 report-writer 无法生成 Burp 复现包和 PoC 脚本。

---

### Phase-1: 环境智能识别与构建

── 并行 step ──

读取 teams/team1/env_detective.md + 共享资源
读取 teams/team1/schema_reconstructor.md + 共享资源

同时 spawn 两个 Agent（background 模式）:

  Agent(name="env-detective", team_name="php-audit", run_in_background=true, mode="bypassPermissions", subagent_type="general-purpose")
    → prompt: Task #1 指令 + teams/team1/env_detective.md + 共享资源 + TARGET_PATH + WORK_DIR

  Agent(name="schema-reconstructor", team_name="php-audit", run_in_background=true, mode="bypassPermissions", subagent_type="general-purpose")
    → prompt: Task #2 指令 + teams/team1/schema_reconstructor.md + 共享资源 + TARGET_PATH + WORK_DIR

等待两者全部完成
── 串行 step ──

  Agent(name="docker-builder", team_name="php-audit", foreground, mode="bypassPermissions", subagent_type="general-purpose")
    → prompt: Task #3 指令 + teams/team1/docker_builder.md + shared/env_selfheal.md + 共享资源
            + @env-detective 的返回结果 + TARGET_PATH + WORK_DIR

完成
  Agent(name="qc0", team_name="php-audit", foreground, mode="bypassPermissions", subagent_type="general-purpose")
    → prompt: Task #4 指令 + teams/team1/qc0.md + 共享资源 + WORK_DIR

完成
**QC-0 结果处理（防跳过逻辑）**:
```
解析 QC-0 返回结果:
  - 通过 → MODE="full"，继续正常流程
  - 失败 → MODE="static-only"
    → 打印警告: "⚠️ Docker 环境构建失败，将以纯静态模式继续（Phase-3 动态追踪将跳过）"
    → 不要直接跳过后续 Phase！仍然执行 Phase-2 全部步骤
    → 仅在进入 Phase-3 时检查 MODE 决定是否跳过
```

写入 checkpoint.json: {"completed": ["env"], "current": "scan"}
打印流水线视图

### Phase-2: 静态资产侦察

── 并行 step ──

同时 spawn 四个 Agent（background 模式）:

  Agent(name="tool-runner", team_name="php-audit", run_in_background=true, mode="bypassPermissions", subagent_type="general-purpose")
    → prompt: Task #5 指令 + teams/team2/tool_runner.md + 共享资源
            + tools/sink_finder.php（告知路径和用法）+ TARGET_PATH + WORK_DIR

  Agent(name="route-mapper", team_name="php-audit", run_in_background=true, mode="bypassPermissions", subagent_type="general-purpose")
    → prompt: Task #6 指令 + teams/team2/route_mapper.md + 共享资源 + TARGET_PATH + WORK_DIR

  Agent(name="auth-auditor", team_name="php-audit", run_in_background=true, mode="bypassPermissions", subagent_type="general-purpose")
    → prompt: Task #7 指令 + teams/team2/auth_auditor.md + 共享资源 + TARGET_PATH + WORK_DIR

  Agent(name="dep-scanner", team_name="php-audit", run_in_background=true, mode="bypassPermissions", subagent_type="general-purpose")
    → prompt: Task #8 指令 + teams/team2/dep_scanner.md + shared/known_cves.md
            + 共享资源 + TARGET_PATH + WORK_DIR

等待四者全部完成
── 串行 step ──

  Agent(name="context-extractor", team_name="php-audit", foreground, mode="bypassPermissions", subagent_type="general-purpose")
    → prompt: Task #9 指令 + teams/team2/context_extractor.md + shared/framework_patterns.md
            + shared/php_specific_patterns.md + 共享资源 + TARGET_PATH + WORK_DIR

完成
  Agent(name="risk-classifier", team_name="php-audit", foreground, mode="bypassPermissions", subagent_type="general-purpose")
    → prompt: Task #10 指令 + teams/team2/risk_classifier.md + shared/framework_patterns.md
            + 共享资源 + TARGET_PATH + WORK_DIR

完成
  Agent(name="qc1", team_name="php-audit", foreground, mode="bypassPermissions", subagent_type="general-purpose")
    → prompt: Task #11 指令 + teams/team2/qc1.md + 共享资源 + WORK_DIR

完成解析 QC-1 结果（失败不阻塞，标注覆盖率继续）

**Phase-2 Gate 验证**（必须执行）:
```bash
test -f "$WORK_DIR/priority_queue.json" && test -d "$WORK_DIR/context_packs" && echo "GATE-2 PASS" || echo "GATE-2 FAIL"
```
GATE-2 PASS → 写入 checkpoint.json: {"completed": ["env", "scan"], "current": "trace"}
GATE-2 FAIL → 不写入 checkpoint，检查 context-extractor / risk-classifier 是否正常执行

打印流水线视图

### 动态创建 Phase-4/5 任务

读取 $WORK_DIR/priority_queue.json
按 sink 类型创建 Phase-4 任务（仅存在对应 sink 类型才创建）:

  sink_type → agent 映射:
    eval/system/exec/extract/parse_str       → rce-auditor       (teams/team4/rce_auditor.md)
    query/execute/DB::raw/whereRaw           → sqli-auditor      (teams/team4/sqli_auditor.md)
    unserialize/phar                         → deserial-auditor  (teams/team4/deserial_auditor.md)
    include/require                          → lfi-auditor       (teams/team4/lfi_auditor.md)
    file_put_contents/move_uploaded_file     → filewrite-auditor (teams/team4/filewrite_auditor.md)
    curl_exec/file_get_contents(url)         → ssrf-auditor      (teams/team4/ssrf_auditor.md)
    echo/print/模板渲染                      → xss-auditor       (teams/team4/xss_ssti_auditor.md)
    simplexml_load/DOMDocument               → xxe-auditor       (teams/team4/xxe_auditor.md)
    auth bypass/mass_assignment/弱比较       → authz-auditor     (teams/team4/authz_auditor.md)
    配置类问题                               → config-auditor    (teams/team4/config_auditor.md)
    信息泄露                                 → infoleak-auditor  (teams/team4/infoleak_auditor.md)
    MongoDB/$where/Redis                   → nosql-auditor     (teams/team4/nosql_auditor.md)
    竞态条件/TOCTOU/并发操作              → race-auditor      (teams/team4/race_condition_auditor.md)
    md5/sha1/rand/mt_rand/弱加密          → crypto-auditor    (teams/team4/crypto_auditor.md)
    wp_ajax/xmlrpc/shortcode/WP特有       → wp-auditor        (teams/team4/wordpress_auditor.md)
    价格篡改/流程跳过/业务逻辑            → bizlogic-auditor  (teams/team4/business_logic_auditor.md)

  框架自适应调度（基于 environment_status.json 中的 framework 字段）:

    WordPress → 强制启动 wp-auditor（即使无特定 sink 匹配）
    Laravel   → 强制启动 config-auditor（检查 APP_DEBUG、Telescope）
                + authz-auditor（检查 Mass Assignment、Gate/Policy）
    ThinkPHP  → 强制启动 rce-auditor（ThinkPHP 历史 RCE 漏洞多发）
                + sqli-auditor（ThinkPHP ORM 注入风险）
    Symfony   → 强制启动 config-auditor（Profiler、debug 路由）
    所有框架  → 强制启动 infoleak-auditor + bizlogic-auditor（通用审计）

  **版本感知调度**（基于 environment_status.json 中的 framework + php_version 字段）:

    Laravel < 8.x   → Mass Assignment 审计权重 ×2（旧版 $guarded 默认空，风险更高）
    Laravel >= 9.x  → 追加 Vite manifest 泄露检查 + debug 路由暴露检查（`/_ignition`、`/telescope`）
    ThinkPHP 5.x    → 强制 RCE 审计（`think\Request` RCE，s= 参数注入控制器/方法）
    ThinkPHP 3.x    → 强制 SQLi 审计（`M()->where()` 字符串拼接注入、`I()` 函数过滤不完整）
    WordPress < 6.0 → 触发已知 Core CVE 检查（对照 `shared/wp_core_cve.json`，匹配版本号段）
    PHP < 8.0       → Type Juggling 风险提升（`==` 松散比较 + `0e` hash 碰撞仍可利用）
    PHP < 5.3.4     → Null Byte 截断 LFI 可行（`include $_GET['f'].'.php'` 中 `%00` 截断后缀）

  **防跳过**: 如果 priority_queue.json 为空或不存在:
    → 不要跳过 Phase-4！
    → 仍然启动框架自适应调度中的强制 Agent
    → 打印警告: "⚠️ 未检测到高优先级 Sink，但仍执行框架强制审计项"

  为每个需要的专家创建 Task:
    task-15+: "{type}专家审计" activeForm="审计 {type} 漏洞" (blockedBy: [14])

  创建 QC-3 Task:
    task-N: "QC-3 物理取证验证" activeForm="取证验证" (blockedBy: [所有 exploit 任务])

  创建 Phase-4.5 任务:
    task-M: "攻击图谱构建" activeForm="构建攻击图谱" (blockedBy: [N])
    task-M+1: "跨审计员关联分析" activeForm="关联分析" (blockedBy: [N])
    task-M+2: "修复代码生成" activeForm="生成修复 Patch" (blockedBy: [M, M+1])
    task-M+3: "PoC 脚本生成" activeForm="生成 PoC 脚本" (blockedBy: [M, M+1])

  创建 Phase-5 任务:
    task-N+1: "环境清理" activeForm="清理测试环境" (blockedBy: [N])
    task-N+2: "报告撰写" activeForm="撰写审计报告" (blockedBy: [N])
    task-N+3: "QC-Final" activeForm="验证报告完整性" (blockedBy: [N+1, N+2])

### Phase-3: 鉴权模拟与动态追踪

**防跳过检查**:
```
如果 MODE="static-only":
  → 打印: "⚠️ Phase-3 因 Docker 环境不可用而跳过（纯静态模式）"
  → 将 task-12~14 标记 completed（description 注明"降级跳过"）
  → 直接进入 Phase-4
  → 但不要跳过 Phase-4 和 Phase-5！

如果 MODE="full":
  → 正常执行以下步骤
```

── 串行 step ──

  Agent(name="auth-simulator", team_name="php-audit", foreground, mode="bypassPermissions", subagent_type="general-purpose")
    → prompt: Task #12 指令 + teams/team3/auth_simulator.md + 共享资源 + TARGET_PATH + WORK_DIR

完成
  Agent(name="trace-dispatcher", team_name="php-audit", foreground, mode="bypassPermissions", subagent_type="general-purpose")
    → prompt: Task #13 指令 + teams/team3/trace_dispatcher.md + 共享资源
            + teams/team3/trace_worker.md（注入 worker prompt 供其内部 spawn）
            + tools/trace_filter.php（告知路径和用法）
            + TARGET_PATH + WORK_DIR
    → 内部并行 spawn 最多 2 个 trace-worker

完成
  Agent(name="qc2", team_name="php-audit", foreground, mode="bypassPermissions", subagent_type="general-purpose")
    → prompt: Task #14 指令 + teams/team3/qc2.md + 共享资源 + WORK_DIR

完成解析 QC-2 结果（失败 → 断链路由退回静态分析，不阻塞）

**Phase-3 Gate 验证**（MODE=full 时必须执行，static-only 豁免）:
```bash
if [ "$MODE" = "full" ]; then
  test -f "$WORK_DIR/credentials.json" && echo "GATE-3 PASS" || echo "GATE-3 FAIL"
fi
```
写入 checkpoint.json: {"completed": ["env", "scan", "trace"], "current": "exploit"}
打印流水线视图

### Phase-4: 深度对抗审计（并行分析 + 串行攻击）

**⚠️ 此 Phase 是 Burp 复现包和物理证据的唯一来源，绝对不可跳过。**

**防跳过**: 即使 Phase-3 被跳过（static-only 模式），Phase-4 仍然必须执行。
静态模式下，专家 Agent 仅执行阶段 1（静态分析），跳过阶段 2（动态攻击）。

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

在两个阶段中，发现关键信息时追加写入 $WORK_DIR/shared_findings.jsonl（参考 shared/realtime_sharing.md）。
攻击阶段开始前先读取 shared_findings.jsonl 获取其他审计员的发现。
记录存入点和使用点到 $WORK_DIR/second_order/（参考 shared/second_order.md）。

当你收到 "START_ATTACK" 信号时才进入阶段 2。在此之前只做阶段 1。
```

── Step 1: 并行分析（所有专家同时工作，不碰容器）──

同时 spawn 所有专家 Agent（background 模式）:

  例如（按需 spawn，无对应 sink 则不启动，但框架强制项必须启动）:

  Agent(name="rce-auditor", team_name="php-audit", run_in_background=true, mode="bypassPermissions", subagent_type="general-purpose")
    → prompt: Task #{id} 指令（阶段1模式）+ teams/team4/rce_auditor.md + shared/docker_snapshot.md
            + shared/payload_templates.md + shared/waf_bypass.md + shared/framework_patterns.md
            + 共享资源 + 对应 sink 的 context_packs + traces + credentials
            + tools/payload_encoder.php（告知路径和用法）+ tools/waf_detector.php（告知路径和用法）
            + TARGET_PATH + WORK_DIR

  Agent(name="sqli-auditor", ...) 等其他专家...（所有专家均使用 mode="bypassPermissions"）
  （所有 Phase-4 专家 Agent 均需注入: shared/payload_templates.md + shared/waf_bypass.md
    + shared/framework_patterns.md + shared/php_specific_patterns.md + shared/known_cves.md
    + tools/payload_encoder.php + tools/waf_detector.php）

等待全部分析完成
── Step 2: 串行攻击（逐个专家独占容器执行）──

**防跳过**: 如果 MODE="static-only"，跳过 Step 2（所有专家仅有阶段 1 分析结果），
但仍然执行 QC-3 验证阶段 1 的静态分析结果。

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

── Step 3: Pivot When Stuck（卡住时自动转向）──

当某个专家 Agent 在阶段 2 攻击中持续失败，触发以下 pivot 规则自动切换审计策略:

| 触发条件 (Trigger) | 切换目标 (Switch To) | 额外资源 (Additional Resources) |
|---|---|---|
| **sqli-auditor 连续 8 轮 Payload 全部失败**（无报错差异、无时间差异、无回显差异） | 切换到 **二阶 SQLi 审计**: 让 context-extractor 追踪数据从 DB 取出后的使用点（存储→读取→拼接 SQL），重新构造 payload 打存入点 | `shared/second_order.md` + context-extractor 的 data-flow 输出; 需要回溯 INSERT/UPDATE 语句对应的 SELECT 消费路径 |
| **xss-auditor 被 WAF/htmlspecialchars 完全阻断**（所有 XSS vector 均被过滤，无法绕过） | 自动尝试 **SSTI 审计**: 同一注入点可能是模板引擎渲染入口（Twig/Blade/Smarty），用 `{{7*7}}` / `${7*7}` 探测 | `teams/team4/xss_ssti_auditor.md` 中 SSTI 部分; 需要 `shared/framework_patterns.md` 确认模板引擎类型 |
| **lfi-auditor 路径遍历被过滤**（`../` 被 replace、realpath 限制、open_basedir 阻断） | pivot 到 **php://filter chain** 攻击: 不使用文件系统路径，通过 `php://filter/convert.base64-encode/resource=` 或 filter chain RCE 绕过 | `shared/payload_templates.md` 中 LFI filter chain 模板; 需要确认 `allow_url_include` 状态 |
| **rce-auditor 危险函数被 disable_functions 禁用**（system/exec/passthru/shell_exec 全部在 disabled list） | pivot 到 **反序列化 RCE**: 寻找 `unserialize()` 入口，通过 POP chain 触发 `__destruct`/`__wakeup` 实现代码执行 | `teams/team4/deserial_auditor.md` + `shared/payload_templates.md` 反序列化部分; 需要 Composer 依赖列表构造 gadget chain |
| **ssrf-auditor 内网地址不可达**（目标服务器网络隔离，127.0.0.1/内网段被过滤或无法回连） | pivot 到 **DNS Rebinding**: 使用可控 DNS 记录（TTL=0）让目标先解析到外部 IP 通过校验，再 rebind 到内网地址 | 需要 DNS rebinding 服务（如 rbndr.us 或自建）; `shared/payload_templates.md` 中 SSRF DNS rebinding 模板 |

**pivot 执行流程**:
1. 专家 Agent 在攻击日志中标记 `pivot_triggered: true` + 原因
2. 主调度器检测到 pivot 标记后，spawn 对应的新专家（或复用同一专家的不同模式）
3. 新专家继承原专家的 context_packs 和已收集的信息，避免重复侦察
4. pivot 结果写入 `$WORK_DIR/exploits/{sink_id}_pivot.json`，与原结果合并

── 串行 step ──

  Agent(name="qc3", team_name="php-audit", foreground, mode="bypassPermissions", subagent_type="general-purpose")
    → prompt: Task #N 指令 + teams/team4/qc3.md + 共享资源 + WORK_DIR

完成解析 QC-3 结果（失败 → 降级标注，不阻塞报告）

**Phase-4 Gate 验证**（必须执行）:
```bash
test -d "$WORK_DIR/exploits" && ls "$WORK_DIR/exploits/"*.json >/dev/null 2>&1 && echo "GATE-4 PASS" || echo "GATE-4 FAIL: exploits/ 不存在或为空，report-writer 将无法生成 Burp 复现包"
```
GATE-4 PASS → 写入 checkpoint.json: {"completed": ["env", "scan", "trace", "exploit"], "current": "report"}
GATE-4 FAIL → **不写入 checkpoint**。检查 Phase-4 专家 Agent 是否实际被 spawn。如果未 spawn，立即回到 Phase-4 Step 1 执行。

打印流水线视图

### Phase-4.5: 后渗透智能分析

**⚠️ 此 Phase 是 PoC 脚本的唯一来源，绝对不可跳过。**

── 并行 step ──

同时 spawn 两个 Agent（background 模式）:

  Agent(name="attack-graph-builder", team_name="php-audit", run_in_background=true, mode="bypassPermissions", subagent_type="general-purpose")
    → prompt: Task #M 指令 + teams/team4.5/attack_graph_builder.md
            + shared/attack_chains.md + 共享资源 + WORK_DIR

  Agent(name="correlation-engine", team_name="php-audit", run_in_background=true, mode="bypassPermissions", subagent_type="general-purpose")
    → prompt: Task #M+1 指令 + teams/team4.5/correlation_engine.md
            + shared/false_positive_patterns.md + shared/second_order.md
            + shared/attack_chains.md + 共享资源 + WORK_DIR

等待两者完成
── 并行 step ──

同时 spawn 两个 Agent（background 模式）:

  Agent(name="remediation-generator", team_name="php-audit", run_in_background=true, mode="bypassPermissions", subagent_type="general-purpose")
    → prompt: Task #M+2 指令 + teams/team4.5/remediation_generator.md
            + shared/framework_patterns.md + 共享资源 + TARGET_PATH + WORK_DIR

  Agent(name="poc-generator", team_name="php-audit", run_in_background=true, mode="bypassPermissions", subagent_type="general-purpose")
    → prompt: Task #M+3 指令 + teams/team4.5/poc_generator.md
            + shared/payload_templates.md + shared/waf_bypass.md + 共享资源 + WORK_DIR

等待两者完成

**Phase-4.5 Gate 验证**（必须执行）:
```bash
test -d "$WORK_DIR/poc" && ls "$WORK_DIR/poc/"*.py >/dev/null 2>&1 && echo "GATE-4.5 PASS" || echo "GATE-4.5 FAIL: poc/ 不存在或为空"
test -d "$WORK_DIR/patches" && echo "PATCHES PASS" || echo "PATCHES FAIL"
```
GATE-4.5 PASS → 写入 checkpoint.json: {"completed": ["env", "scan", "trace", "exploit", "post_exploit"], "current": "report"}
GATE-4.5 FAIL → 检查 poc-generator / remediation-generator 是否实际执行并返回结果

打印流水线视图

### Phase-5: 清理与报告

── 并行 step ──

同时 spawn 三个 Agent（background 模式）:

  Agent(name="env-cleaner", team_name="php-audit", run_in_background=true, mode="bypassPermissions", subagent_type="general-purpose")
    → prompt: Task #N+1 指令 + teams/team5/env_cleaner.md + 共享资源 + WORK_DIR

  Agent(name="report-writer", team_name="php-audit", run_in_background=true, mode="bypassPermissions", subagent_type="general-purpose")
    → prompt: Task #N+2 指令 + teams/team5/report_writer.md + 共享资源 + TARGET_PATH + WORK_DIR

  Agent(name="sarif-exporter", team_name="php-audit", run_in_background=true, mode="bypassPermissions", subagent_type="general-purpose")
    → prompt: "将 $WORK_DIR/exploits/*.json 转换为 SARIF 2.1.0 格式。
              每个 confirmed/suspected 漏洞映射为一条 SARIF result。
              severity 映射: confirmed→error, suspected→warning, potential→note。
              包含 physicalLocation（文件+行号）和 message（漏洞描述）。
              输出: $WORK_DIR/audit_report.sarif.json"

等待三者全部完成
── 串行 step ──

  Agent(name="qc-final", team_name="php-audit", foreground, mode="bypassPermissions", subagent_type="general-purpose")
    → prompt: Task #N+3 指令 + teams/team5/qc_final.md + 共享资源 + WORK_DIR

完成
写入 checkpoint.json: {"completed": ["env", "scan", "trace", "exploit", "report"], "current": "done"}
打印最终流水线视图

#### Step 6.4: 累积流水线视图

每个 Phase 完成后打印完整流水线视图，详见 `references/pipeline_view.md`。

状态标记: ✅=完成 | ⚠️=降级 | ❌=失败 | ⏳=等待 | 🔄=跳过

#### Step 6.5: Agent 生命周期管理与团队清理

**Agent 关闭协议**: 每个 Agent 通过 QC 校验后，主调度器发送 shutdown_request 优雅关闭:

```
对于每个已完成的 Agent（按 Phase 顺序）:
  SendMessage(to="{agent-name}", message={type: "shutdown_request", reason: "任务完成，QC 已通过"})
  等待 shutdown_response（最多 30 秒）
  若超时未响应 → 记录警告并继续（不阻塞后续流程）
```

**关闭顺序**:
- 每个 Phase 的 QC Agent 通过后，关闭该 Phase 的所有 Agent
- 最终 QC-Final 通过后，关闭剩余所有 Agent
- 最后执行 TeamDelete()

```
遍历所有仍活跃的 teammate，逐个发送 shutdown_request
等待所有 shutdown_response 或超时
TeamDelete()
```

**tmux 清理（保底逻辑）**: 框架应自动回收 Agent pane，但实践中 idle Agent 进程可能未退出导致 pane 残留。TeamDelete 后执行以下保底清理:

```bash
# 查找并关闭所有 Claude Code Agent Teams 创建的残留 pane
# 仅保留当前主 pane（pane index 0）
CURRENT_PANE=$(tmux display-message -p '#{pane_id}' 2>/dev/null)
if [ -n "$CURRENT_PANE" ]; then
  tmux list-panes -F '#{pane_id}' 2>/dev/null | while read pane; do
    [ "$pane" != "$CURRENT_PANE" ] && tmux kill-pane -t "$pane" 2>/dev/null
  done
  echo "tmux 残留 pane 已清理"
fi
```

```
告知用户: "审计完成！报告文件: $WORK_DIR/audit_report.md"
```

### QC 失败回退策略

**关键: QC 失败不等于跳过后续所有阶段！每个 QC 有独立的降级策略。**

- QC-0 失败（环境构建） → MODE="static-only"，Phase-2 正常执行，Phase-3 跳过，Phase-4 仅做静态分析
- QC-1 失败（侦察完整性） → 用已有部分继续，报告中注明覆盖率，**不跳过 Phase-3/4/5**
- QC-2 失败（调用链验证） → 断链路由退回静态分析，**不跳过 Phase-4/5**
- QC-3 失败（物理取证） → 降级标注，**不跳过 Phase-4.5/5**

### Section 12: Agent 注入分层体系

为控制每个 Agent 的 prompt token 用量，共享资源按注入优先级分为三个层级:

#### 注入层级定义

| 层级 | 名称 | 策略 | 说明 |
|------|------|------|------|
| **L1** | 必注入 (All Agents) | 全文注入到所有 Agent prompt | 核心规则，缺失会导致幻觉或格式错误 |
| **L2** | 按角色注入 (Role-based) | 仅注入给需要该资源的 Agent | 领域知识，按 Agent 职责选择性注入 |
| **L3** | 按需引用 (On-demand) | 仅注入文件路径 + 单行摘要，Agent 需要时自行 Read | 大型参考库，全文注入会超出 token 预算 |

#### L1 必注入资源（所有 Agent）

- `shared/anti_hallucination.md` — 反幻觉规则
- `shared/sink_definitions.md` — Sink 函数定义
- `shared/data_contracts.md` — JSON Schema 数据合约

#### L2 按角色注入资源

| 资源文件 | 注入目标 Agent |
|----------|----------------|
| `shared/php_specific_patterns.md` | 所有 Phase-4 专家 + Phase-2 context-extractor |
| `shared/attack_chains.md` | Phase-4.5 attack-graph-builder + correlation-engine |
| `shared/known_cves.md` | Phase-2 dep-scanner + 所有 Phase-4 专家 |
| `shared/payload_templates.md` | 所有 Phase-4 专家 |
| `shared/waf_bypass.md` | 所有 Phase-4 专家 |
| `shared/framework_patterns.md` | Phase-2 context-extractor/risk-classifier + Phase-4 专家 + Phase-4.5 remediation-generator |
| `shared/docker_snapshot.md` | Phase-4 专家（阶段 2 攻击时） |
| `shared/realtime_sharing.md` | Phase-4 专家 |
| `shared/second_order.md` | Phase-4 专家 + Phase-4.5 correlation-engine |
| `shared/false_positive_patterns.md` | QC-3 + Phase-4.5 correlation-engine |
| `shared/env_selfheal.md` | Phase-1 docker-builder |

#### L3 按需引用资源

以下资源**不全文注入**，仅在 Agent prompt 中注入路径和摘要。Agent 在需要时使用 Read 工具自行读取:

- `shared/lessons_learned.md` — 实战经验库（历史审计踩坑记录与解决方案）

**L3 注入模板**（写入 Agent prompt 的格式）:
```
--- 按需引用资源（L3）---
以下资源未全文注入，需要时使用 Read 工具读取:

- ${SKILL_DIR}/shared/lessons_learned.md
  摘要: 历史审计实战经验库，包含常见踩坑场景、误报/漏报案例、环境兼容性问题的解决方案。
  使用场景: 当你遇到异常行为、不确定的 Sink 判定、或攻击连续失败时，建议先查阅此文件获取参考。
```

#### Token 预算规则

每个 Agent 的 L1 + L2 注入内容（不含任务指令文件本身）须遵守以下行数上限:

| Agent 类型 | L1 + L2 行数上限 |
|------------|-------------------|
| Phase-4 专家 Agent | **<= 1500 行** |
| Phase-4.5 Agent | **<= 800 行** |
| Phase-2 Agent | **<= 500 行** |

**超预算自动降级规则**: 构建 Agent prompt 时，主调度器应在注入前统计 L1 + L2 总行数:
- 若超出该 Agent 类型的行数上限 → 打印警告:
  `"⚠️ Agent {name} 的 L1+L2 注入内容为 {actual} 行，超出预算 {limit} 行。自动将最大的 L2 资源降级为 L3（仅注入路径+摘要）。"`
- 降级顺序: 按文件行数从大到小，逐个将 L2 资源降级为 L3，直到总行数 <= 上限
- 降级后的资源按 L3 模板格式注入路径和摘要

### 超时控制

总计审计时间上限 2.5 小时。超时后：
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
