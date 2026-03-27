<div align="center">

# 🛡️ PHP_AUDIT_SKILLS

**全链路 PHP 代码安全审计 AI Agent 系统**

![Version](https://img.shields.io/badge/version-2.0.0-blue)
![Skills](https://img.shields.io/badge/skills-145+-green)
![Skill Files](https://img.shields.io/badge/skill_files-121-brightgreen)
![Auditors](https://img.shields.io/badge/auditors-21_types_×_2_stages-red)
![Schemas](https://img.shields.io/badge/schemas-30-orange)
![Phase](https://img.shields.io/badge/phases-6-purple)

基于 Claude Code Agent Teams 的多智能体协作安全审计框架，覆盖环境构建、静态侦察、动态追踪、深度对抗利用、后渗透关联分析、报告收口全链路，支持 **21 种漏洞类型** 专家级审计。

[功能特性](#功能特性) · [快速开始](#安装与使用) · [架构设计](#架构设计) · [团队编制](#agent-teams-编制) · [输出产物](#输出产物)

</div>

---

## 功能特性

### 🔄 全链路自动化
- **6 阶段流水线**：Phase 1~5 + Phase 4.5 自动编排，覆盖侦察→追踪→利用→后渗透→报告
- **断点续审**：通过 `checkpoint.json` 记录阶段状态，支持中断恢复与增量审计
- **错误自恢复**：DB 损坏、Agent 崩溃、Token 溢出、磁盘不足等 5 种异常场景自动恢复

### 🎯 21 种漏洞类型覆盖
RCE · SQLi · 反序列化 · LFI · 文件写入 · SSRF · XSS/SSTI · XXE · CSRF · CRLF · 越权/IDOR · Session · 弱加密 · 竞态条件 · NoSQL · LDAP · 信息泄露 · 日志注入 · 配置缺陷 · WordPress 专有 · 业务逻辑

### 🧠 智能攻击记忆系统
- **扁平记忆**：`attack_memory` 表 — 按 sink_type + framework + PHP版本 + WAF 指纹匹配历史攻击经验
- **关系型图记忆**：`memory_nodes` + `memory_edges` 表 — 7 种实体关系类型，支持攻击链自动发现
- **跨项目学习**：历史审计经验自动积累，新项目审计自动匹配相似模式

### 🔬 Mini-Researcher 智能研究员
- 未知组件、无 PoC 的 Critical CVE、连续 5 轮攻击失败等 **5 种条件自动触发**
- 本地知识库 → NVD/GitHub Advisory 外部情报 → 结构化输出
- 3 级置信度消费：高→立即使用、中→追加计划、低→仅参考

### ⚡ 混合调度 + 对抗循环
- **并行分析 + 串行攻击**：先并行静态分析，再逐个独占容器执行攻击
- **8 轮对抗循环**：每轮前 Docker 快照，失败自动回滚，Pivot When Stuck 自动转向
- **框架感知调度**：Laravel / ThinkPHP / Symfony / WordPress 等框架特征识别与强制审计项
- **版本感知调度**：PHP < 8.0 → Type Juggling, ThinkPHP 5.x → RCE 等

### 🔒 质量保障体系
- **Gate 门禁**：每阶段结束强制校验产物存在性（GATE-1 ~ GATE-4.5）
- **独立 QC 池**：按需 spawn 质检员，"完成一个、校验一个"，含图记忆 + 研究员专项检查
- **30 个 JSON Schema**：所有 Agent 间数据交换严格校验格式
- **Auditor 自检**：每个审计员内置 `auditor_self_check.md` 自我校验清单

---

## 架构设计

### 阶段功能总览

| 阶段 | Agent 数 | 核心功能 | 关键产物 |
|------|---------|---------|---------|
| **Phase 1: 环境构建** | 3 | 框架识别、Schema 重建、Docker 构建 + 自愈 | `environment_status.json` |
| **Phase 2: 静态侦察** | 12 | 工具扫描（7 种）、路由映射、鉴权矩阵、依赖扫描、上下文抽取、风险定级 | `priority_queue.json`、`context_packs/` |
| **Phase 3: 动态追踪** | 3+N | 鉴权模拟、Xdebug 追踪、调用链校验 | `traces/*.json`、`credentials.json` |
| **Phase 4: 深度利用** | 21+1 | 21 类漏洞专家审计 + Mini-Researcher | `exploits/*.json`、`research/*.json` |
| **Phase 4.5: 后渗透** | 4 | 攻击图谱、关联分析、Patch 生成、PoC 生成 | `attack_graph.json`、`PoC脚本/*.py` |
| **Phase 5: 报告收口** | 3 | 报告生成、SARIF 导出、环境清理 | `报告/审计报告.md`、`.sarif.json` |
| **QC: 质检** | 2 | 独立质检员池、贯穿全流程 | QC 记录写入 `audit_session.db` |

### Architecture Overview

**145+ skills** organized in **10 subdirectories** under `skills/`, using a **2-stage auditor pattern** (21 auditor types → 42 files: `_analyze` + `_attack`) and a standardized **fill-in template format**.

#### Skills Directory Structure

```
skills/
├── auditors/       — 42 files (21 analyze + 21 attack) + index
├── auth/           — 9 sub-skills + index
├── correlation/    — 5 correlation rules + index
├── infrastructure/ — 4 system skills + index
├── qc/             — 6 phase QC checkers + index
├── report/         — 7 chapter writers + index
├── routes/         — 8 route sub-skills + index
├── scanners/       — 7 scanner wrappers + index
├── shared/         — 9 cross-cutting protocols + index
└── trace/          — 14 trace sub-skills + index
```

**Total**: 111 skill files + 10 index files = **121 files in `skills/`**

#### Fill-in Template Standard

Every skill follows the fill-in template format:

`Identity → Input Contract → 🚨 CRITICAL Rules → Fill-in Procedure (tables) → Output Contract → ✅/❌ Examples → Error Handling`

This minimizes model dependency: the model fills predefined fields rather than generating free-form content.

---

### Design Philosophy

- **Fill-in templates > free generation** — structured fields reduce hallucination
- **Positive/negative examples > abstract rules** — concrete examples anchor behavior
- **Multi-agent single-responsibility > monolithic** — each agent owns one task
- **Independent QC agents for each phase** — quality verification is never self-assessed
- **AI instructions in English, output in Chinese** — precision for the model, readability for the user

---

### 攻击循环流程

```
Phase-4 攻击循环（每个 Sink，最多 8 轮）：

  ┌─ 查询攻击记忆（扁平 + 图记忆）
  │    ↓
  │  制定攻击计划 → exploit_plan.json
  │    ↓
  │  ┌─────────────────────────────────────┐
  │  │  Round 1~8 循环                      │
  │  │  ① Docker 快照                       │
  │  │  ② 发送 Payload                      │
  │  │  ③ 采集物理证据（HTTP 响应/命令输出） │
  │  │  ④ 成功 → 写入 exploit + 记忆        │
  │  │  ⑤ 失败 → WAF 分析 → 调整策略        │
  │  │  ⑥ 连续失败 → Pivot 转向             │
  │  │  ⑦ 触发条件 → Mini-Researcher 委派   │
  │  └─────────────────────────────────────┘
  │    ↓
  │  写入攻击记忆（供后续 Sink 和未来项目复用）
  │    ↓
  └─ QC 质检 → 下一个 Sink
```

### Pivot 自动转向策略

| 原始攻击 | 转向目标 |
|----------|---------|
| SQLi 8 轮全败 | 二阶 SQLi（存储→读取→拼接） |
| XSS 被完全过滤 | SSTI（`{{7*7}}` 探测） |
| LFI 路径过滤 | `php://filter` chain RCE |
| RCE disable_functions | 反序列化 POP chain |
| SSRF 内网不可达 | DNS Rebinding |

---

## Agent Teams 编制

### Team 1 — 环境构建（3 Agents）

| Agent | 职责 |
|-------|------|
| `env_detective` | 框架指纹、PHP 版本、DB 类型识别 |
| `schema_reconstructor` | 从 ORM 模型重建数据库表结构 |
| `docker_builder` | Docker 环境构建 + `env_selfheal` 自愈循环 |

### Team 2 — 静态侦察（12 Agents）

| Agent | 职责 |
|-------|------|
| `psalm_scanner` | Psalm taint analysis |
| `progpilot_scanner` | Progpilot vulnerability scan |
| `ast_scanner` | AST sink detection via `sink_finder.php` |
| `phpstan_scanner` | PHPStan static analysis |
| `semgrep_scanner` | Semgrep pattern matching |
| `composer_audit_scanner` | Composer dependency audit |
| `codeql_scanner` | CodeQL analysis (optional) |
| `route_mapper` | 路由表解析与映射 |
| `auth_auditor` | 鉴权机制分析 |
| `dep_scanner` | 第三方组件 CVE 检测 + `known_cves` |
| `context_extractor` | Sink 上下文抽取 + 数据流分析 |
| `risk_classifier` | 风险优先级定级 P0/P1/P2/P3 |

### Team 3 — 动态追踪（3 + N Agents）

| Agent | 职责 |
|-------|------|
| `auth_simulator` | 模拟多角色登录获取凭证 |
| `trace_dispatcher` | 读取高危 Sink 分批创建追踪任务 |
| `trace_worker` ×N | Xdebug 追踪执行（动态创建） |

### Team 4 — 漏洞审计（21 + 1 Agents）

<details>
<summary>展开 21 种专家审计员</summary>

| # | Agent | 覆盖类型 |
|---|-------|---------|
| 1 | `rce_auditor` | 命令/代码执行 |
| 2 | `sqli_auditor` | SQL 注入（一阶 + 二阶） |
| 3 | `xss_ssti_auditor` | XSS + SSTI |
| 4 | `lfi_auditor` | 本地/远程文件包含 |
| 5 | `filewrite_auditor` | 文件上传/写入 |
| 6 | `ssrf_auditor` | SSRF + DNS Rebinding |
| 7 | `xxe_auditor` | XML 外部实体 |
| 8 | `deserial_auditor` | 反序列化 + POP chain |
| 9 | `crlf_auditor` | CRLF 注入 |
| 10 | `csrf_auditor` | 跨站请求伪造 |
| 11 | `authz_auditor` | 越权 + IDOR |
| 12 | `session_auditor` | Session 管理缺陷 |
| 13 | `crypto_auditor` | 弱加密/密钥泄露 |
| 14 | `race_condition_auditor` | 竞态条件 |
| 15 | `nosql_auditor` | MongoDB/Redis 注入 |
| 16 | `ldap_auditor` | LDAP 注入 |
| 17 | `infoleak_auditor` | 信息泄露 |
| 18 | `logging_auditor` | 日志注入/敏感日志 |
| 19 | `config_auditor` | 配置缺陷 |
| 20 | `wordpress_auditor` | WordPress 专有漏洞 |
| 21 | `business_logic_auditor` | 业务逻辑缺陷 |
| — | `mini_researcher` | 智能研究员（按需委派） |

</details>

### Team 4.5 — 后渗透分析（4 Agents）

| Agent | 职责 |
|-------|------|
| `attack_graph_builder` | 构建攻击图谱 + 链式利用路径 |
| `correlation_engine` | 跨审计员关联 + 图记忆消费 + 误报消除 |
| `poc_generator` | 可执行 PoC 脚本生成 |
| `remediation_generator` | 修复 Patch 生成（框架适配） |

### Team 5 — 报告收口（3 Agents）

| Agent | 职责 |
|-------|------|
| `report_writer` | 主审计报告生成（含 Burp 复现包） |
| `sarif_exporter` | SARIF 2.1.0 标准导出 |
| `env_cleaner` | Xdebug 清理 + 代码/数据库还原 |

### QC — 独立质检（2 Agents）

| Agent | 职责 |
|-------|------|
| `qc_dispatcher` | 质检任务分发 |
| `quality_checker` | 质量校验（含 Mini-Researcher + 图记忆专项） |

---

## 前置要求

- **Docker** + **Docker Compose**（必需）
- **Claude Code**（建议开启 Agent Teams 实验特性）
- **tmux**（可选，分屏查看并行 Agent）

> **Agent Teams 配置：** 在 `~/.claude/settings.json` 中添加：
>
> ```json
> {
>   "env": {
>     "CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS": "1"
>   }
> }
> ```

---

## 安装与使用

### 1. 准备环境

```bash
docker --version
docker compose version
```

### 2. 配置 Skill

将本仓库整体放入 Claude Code 的 skills 目录，或作为项目级 `.github/skills/php-audit/` 使用。

### 3. 一键启动审计

```text
/php-audit /path/to/php-project
```

系统将自动执行 6 阶段全链路审计，最终输出完整报告和 PoC。

---

## 目录结构

```text
PHP_AUDIT_SKILLS/
│
├── SKILL.md                          # 主调度器（Skill 入口）
├── README.md                         # 本文档
├── 全链路详细流程.md                    # 完整执行流程图（文字版）
│
├── phases/                           # 阶段执行模板（7 个）
│   ├── phase1-env.md                 #   环境智能识别与构建
│   ├── phase2-recon.md               #   静态资产侦察
│   ├── phase2-tasks-dynamic.md       #   动态侦察任务创建
│   ├── phase3-trace.md               #   鉴权模拟与动态追踪
│   ├── phase4-exploit.md             #   深度对抗审计
│   ├── phase45-post.md               #   后渗透智能分析
│   └── phase5-report.md              #   清理与报告收口
│
├── teams/                            # Agent 指令文件（40+ Agents）
│   ├── team1/                        #   环境构建（3）
│   │   ├── docker_builder.md
│   │   ├── env_detective.md
│   │   └── schema_reconstructor.md
│   ├── team2/                        #   静态侦察（5 dispatchers; scanners in skills/scanners/）
│   │   ├── route_mapper.md
│   │   ├── auth_auditor.md
│   │   ├── dep_scanner.md
│   │   ├── context_extractor.md
│   │   └── risk_classifier.md
│   ├── team3/                        #   动态追踪（3+N）
│   │   ├── auth_simulator.md
│   │   ├── trace_dispatcher.md
│   │   └── trace_worker.md
│   ├── team4/                        #   漏洞审计（21+1）
│   │   ├── rce_auditor.md
│   │   ├── sqli_auditor.md
│   │   ├── xss_ssti_auditor.md
│   │   ├── lfi_auditor.md
│   │   ├── filewrite_auditor.md
│   │   ├── ssrf_auditor.md
│   │   ├── xxe_auditor.md
│   │   ├── deserial_auditor.md
│   │   ├── crlf_auditor.md
│   │   ├── csrf_auditor.md
│   │   ├── authz_auditor.md
│   │   ├── session_auditor.md
│   │   ├── crypto_auditor.md
│   │   ├── race_condition_auditor.md
│   │   ├── nosql_auditor.md
│   │   ├── ldap_auditor.md
│   │   ├── infoleak_auditor.md
│   │   ├── logging_auditor.md
│   │   ├── config_auditor.md
│   │   ├── wordpress_auditor.md
│   │   ├── business_logic_auditor.md
│   │   └── mini_researcher.md
│   ├── team4.5/                      #   后渗透分析（4）
│   │   ├── attack_graph_builder.md
│   │   ├── correlation_engine.md
│   │   ├── poc_generator.md
│   │   └── remediation_generator.md
│   ├── team5/                        #   报告收口（3）
│   │   ├── report_writer.md
│   │   ├── sarif_exporter.md
│   │   └── env_cleaner.md
│   └── qc/                           #   质检（2）
│       ├── qc_dispatcher.md
│       └── quality_checker.md
│
├── shared/                           # 共享知识库（25 个）
│   ├── anti_hallucination.md         #   反幻觉规则
│   ├── attack_chains.md              #   攻击链模式
│   ├── attack_memory.md              #   攻击记忆系统（扁平 + 关系型）
│   ├── attack_memory_graph.md        #   关系型图记忆模型
│   ├── auditor_self_check.md         #   审计员自检清单
│   ├── context_compression.md        #   上下文压缩策略
│   ├── data_contracts.md             #   数据合约（引用 schemas/）
│   ├── docker_snapshot.md            #   Docker 快照管理
│   ├── env_selfheal.md               #   环境自愈策略
│   ├── error_recovery.md             #   错误恢复指南（5 种场景）
│   ├── evidence_contract.md          #   证据采集标准
│   ├── false_positive_patterns.md    #   误报模式库
│   ├── framework_patterns.md         #   PHP 框架特征模式
│   ├── known_cves.md                 #   PHP 生态 CVE 速查
│   ├── lessons_learned.md            #   实战经验库
│   ├── output_standard.md            #   输出标准规范
│   ├── OUTPUT_TEMPLATE.md            #   标准输出模板
│   ├── payload_templates.md          #   常用 Payload 模板
│   ├── php_specific_patterns.md      #   PHP 特有攻击模式
│   ├── pivot_strategy.md             #   Pivot 转向策略
│   ├── realtime_sharing.md           #   实时数据共享 + 图节点桥接
│   ├── second_order.md               #   二阶漏洞模式
│   ├── severity_rating.md            #   严重程度评级体系
│   ├── sink_definitions.md           #   Sink 函数定义
│   └── waf_bypass.md                 #   WAF 检测与绕过
│
├── schemas/                          # JSON Schema（30 个）
│   ├── attack_graph.schema.json
│   ├── attack_memory_entry.schema.json
│   ├── auth_credentials.schema.json
│   ├── auth_gap_report.schema.json
│   ├── auth_matrix.schema.json
│   ├── business_logic_result.schema.json
│   ├── context_pack.schema.json
│   ├── correlation_report.schema.json
│   ├── credentials.schema.json
│   ├── crypto_audit_result.schema.json
│   ├── dep_risk.schema.json
│   ├── environment_status.schema.json
│   ├── exploit_plan.schema.json
│   ├── exploit_result.schema.json
│   ├── nosql_result.schema.json
│   ├── poc_summary.schema.json
│   ├── priority_queue.schema.json
│   ├── race_condition_result.schema.json
│   ├── remediation_summary.schema.json
│   ├── research_result.schema.json
│   ├── route_map.schema.json
│   ├── shared_findings.schema.json
│   ├── team4_progress.schema.json
│   ├── trace_record.schema.json
│   └── wordpress_result.schema.json
│
├── references/                       # 参考文档（9 个）
│   ├── agent_injection_framework.md  #   Agent 注入框架（L1/L2/L3）
│   ├── phase1_environment.md
│   ├── phase2_recon.md
│   ├── phase3_tracing.md
│   ├── phase4_attack_logic.md        #   攻击逻辑 + Mini-Researcher 委派
│   ├── phase4_5_correlation.md
│   ├── phase5_reporting.md
│   ├── pipeline_view.md              #   端到端流水线视图
│   └── quality_check_templates.md    #   QC 模板（含图记忆 + 研究员检查）
│
├── tools/                            # 辅助工具（12 个）
│   ├── audit_db.sh                   #   数据库操作（889 行，含图记忆命令）
│   ├── audit_monitor.sh              #   审计监控
│   ├── sink_finder.php               #   AST Sink 扫描器
│   ├── trace_filter.php              #   Xdebug Trace 过滤器
│   ├── payload_encoder.php           #   Payload 编码器
│   ├── waf_detector.php              #   WAF 指纹识别
│   ├── jwt_tester.php                #   JWT 安全测试
│   ├── type_juggling_tester.php      #   PHP 类型混淆测试
│   ├── redirect_checker.php          #   开放重定向检测
│   ├── validate_shared.php           #   shared/ 目录校验
│   ├── vuln_intel.sh                 #   漏洞情报收集
│   └── quality_report_gen.sh         #   QC 报告生成
│
├── templates/                        # 环境模板
│   ├── .env.template
│   ├── Dockerfile.template
│   ├── docker-compose.template.yml
│   ├── xdebug.ini.template
│   └── nginx/                        #   Nginx 框架适配配置
│       ├── default.conf
│       ├── laravel.conf
│       ├── symfony.conf
│       ├── thinkphp.conf
│       ├── wordpress.conf
│       └── yii2.conf
│
├── assets/                           # 可视化资源
│   ├── PHP_AUDIT_SKILLS-pipeline.png
│   ├── php-audit-workflow.png
│   ├── php-audit-workflow.svg
│   └── workflow.mmd
│
├── agent-flow.mmd                    # Agent 执行流程图（Mermaid）
└── audit-flow.mmd                    # 审计流程图（Mermaid）
```

---

## 辅助工具详解

| 工具 | 用途 | 用法 | 使用阶段 |
|------|------|------|----------|
| `audit_db.sh` | SQLite 数据库操作（攻击记忆/发现/质检/图记忆） | `bash audit_db.sh <command> [args]` | 全阶段 |
| `sink_finder.php` | AST Sink 扫描器 | `php sink_finder.php <目标目录>` | Phase-2 |
| `trace_filter.php` | Xdebug Trace 精简过滤器 | `php trace_filter.php <trace_file> [sinks]` | Phase-3 |
| `payload_encoder.php` | Payload 编码（URL/Base64/Hex/双重等） | `php payload_encoder.php <payload> <type>` | Phase-4 |
| `waf_detector.php` | WAF/过滤器指纹识别 | `php waf_detector.php <base_url> [cookie]` | Phase-4 |
| `jwt_tester.php` | JWT 安全测试 | `php jwt_tester.php <token> [pubkey]` | Phase-4 |
| `type_juggling_tester.php` | PHP 类型混淆松散比较测试 | `php type_juggling_tester.php <url> [param]` | Phase-4 |
| `redirect_checker.php` | 开放重定向检测 | `php redirect_checker.php <url> [param]` | Phase-4 |
| `vuln_intel.sh` | 漏洞情报收集（NVD/GitHub Advisory） | `bash vuln_intel.sh <component> <version>` | Phase-4 |
| `audit_monitor.sh` | 审计进度实时监控 | `bash audit_monitor.sh <WORK_DIR>` | 全阶段 |
| `quality_report_gen.sh` | QC 报告汇总生成 | `bash quality_report_gen.sh <WORK_DIR>` | Phase-5 |
| `validate_shared.php` | shared/ 目录完整性校验 | `php validate_shared.php [shared_dir]` | 开发/维护 |

### audit_db.sh 命令速查

```bash
# 攻击记忆
bash audit_db.sh init-memory                     # 初始化（自动含图记忆）
bash audit_db.sh memory-write '<json>'            # 写入攻击经验
bash audit_db.sh memory-query '<json>'            # 查询匹配经验
bash audit_db.sh memory-stats                     # 记忆库统计
bash audit_db.sh memory-maintain                  # 清理过期记忆

# 图记忆
bash audit_db.sh graph-node-write '<json>'        # 写入图节点
bash audit_db.sh graph-edge-write '<json>'        # 写入图边
bash audit_db.sh graph-neighbors <node_id>        # 查询邻居节点
bash audit_db.sh graph-by-data-object <obj>       # 按数据对象查询
bash audit_db.sh graph-export <WORK_DIR>          # 导出完整图数据

# 发现管理
bash audit_db.sh finding-write '<json>'           # 写入发现
bash audit_db.sh finding-read [sink_id]           # 读取发现
bash audit_db.sh finding-consume <sink_id>        # 消费发现

# 质检
bash audit_db.sh qc-write '<json>'                # 写入质检记录
bash audit_db.sh qc-read [phase]                  # 读取质检记录
```

---

## 输出产物

审计完成后，`$WORK_DIR/` 目录结构：

```
$WORK_DIR/
├── 报告/
│   ├── 审计报告.md              ← 全中文主报告（含 Burp 模板、攻击链、AI验证标记）
│   └── audit_report.sarif.json  ← SARIF 2.1.0（可导入 GitHub/VS Code）
├── PoC脚本/
│   ├── poc_{sink_id}.py         ← 每个漏洞的 PoC
│   └── 一键运行.sh              ← 批量执行
├── 修复补丁/
│   └── {finding_id}.patch       ← 框架适配修复
├── 经验沉淀/
│   ├── 经验总结.md              ← 绕过技巧/失败教训/新模式
│   └── 共享文件更新建议.md
├── 质量报告/
│   └── 质量报告.md
└── 原始数据/                    ← 中间产物归档
    ├── exploits/, traces/, context_packs/
    ├── attack_graph.json, correlation_report.json
    └── checkpoint.json
```

---

## Gate 门禁与 QC 策略

### Gate 强制验收

| Gate | 校验条件 |
|------|---------|
| GATE-1 | `environment_status.json` 存在 |
| GATE-2 | `priority_queue.json` + `context_packs/` 存在 |
| GATE-3 | `credentials.json` 存在 |
| GATE-4 | `exploits/*.json` 存在 |
| GATE-4.5 | `PoC脚本/*.py` 存在 |

### QC 降级策略

| 阶段 | 质检不通过处理 |
|------|-------------|
| Phase-1 | 发回重做（最多 3 次），自愈循环/用户介入 |
| Phase-2 | 定位责任 Agent 补充，标注覆盖率继续 |
| Phase-3 | 断链路由退回静态分析，不阻塞 |
| Phase-4 | 降级标注，不阻塞报告 |

---

## 演示效果

![PHP_AUDIT_SKILLS Pipeline](assets/PHP_AUDIT_SKILLS-pipeline.png)

<details>
<summary>📋 点击展开完整执行流程图（文字版）</summary>

> 完整流程详见 `全链路详细流程.md`

```
输入: /php-audit <目标路径>
  ↓
前置检查: Docker → 路径验证 → WORK_DIR → 断点续审 → 增量审计
  ↓
Phase 1: env-detective ∥ schema-reconstructor → docker-builder → QC
  ↓
Phase 2: scanners ×7 ∥ route-mapper ∥ auth-auditor ∥ dep-scanner
         → context-extractor → risk-classifier → QC → 动态创建 Phase-4 任务
  ↓
Phase 3: auth-simulator → trace-dispatcher → trace-worker×N → QC
  ↓
Phase 4: Step1 并行分析（21 专家） → Step2 串行攻击（8 轮循环 + Pivot）
         → 攻击记忆写入 → QC（完成一个校验一个）
  ↓
Phase 4.5: attack-graph-builder ∥ correlation-engine
           → poc-generator ∥ remediation-generator
  ↓
Phase 5: env-cleaner ∥ report-writer ∥ sarif-exporter → 最终 QC
  ↓
输出: 报告/审计报告.md + 报告/audit_report.sarif.json + PoC脚本/ + 修复补丁/ + 经验沉淀/ + 质量报告/
```

</details>

---

## 知识注入架构（Agent Injection Framework）

Agent 启动时按层级注入共享知识：

| 层级 | 注入时机 | 内容 |
|------|---------|------|
| **L1（强制）** | 所有 Agent 启动 | `anti_hallucination.md`、`evidence_contract.md`、`data_contracts.md`、`output_standard.md` |
| **L2（角色相关）** | Phase-4 专家启动 | `sink_definitions.md`、`payload_templates.md`、`attack_memory.md`、`attack_memory_graph.md`、`waf_bypass.md` 等 16 个 |
| **L3（按需）** | 运行时触发条件 | `lessons_learned.md`、`mini_researcher.md` |

---

## 最佳实践

1. **完整源码审计** — 提供完整项目源码目录，减少漏报
2. **保留 Docker 环境** — 便于复现验证与物理证据采集
3. **Gate + Schema 校验** — 交付前确认产物完整性
4. **分级修复** — `confirmed` 优先修复，`suspected` 人工复核
5. **攻击记忆复用** — 保留 `/tmp/<项目名>/attack_memory.db`，积累跨项目经验

---

## 项目统计

| 类别 | 数量 |
|------|------|
| Skill 文件（`skills/`） | 121（111 skill + 10 index） |
| 漏洞审计员（2-Stage） | 21 types × 2 = 42 files |
| Skills 子目录 | 10 |
| JSON Schema | 25 个 |
| 共享知识库（`shared/`） | 25 个 |
| 阶段定义 | 7 个 |
| 参考文档 | 9 个 |
| 辅助工具 | 12 个 |
| 环境模板 | 10 个 |
| Markdown 文件总计 | 145+ 个 |

---

## 许可证

本项目仅供安全研究和学习使用。请在授权范围内对目标系统进行审计。
