---
name: php-audit-skills
description: PHP 审计多 Agent Team 全链路技能（Docker-only）：阶段0~7门禁执行，静态+动态绑定，输出中文主报告与技术附录。
---

# PHP_AUDIT_SKILLS（多 Agent Team 全链路）

## 目标
使用多 Agent Team 模式执行 PHP 安全审计全链路：
`预检编排 -> 信息收集 -> 调用链追踪 -> 交叉分析 -> 静态漏洞分析 -> 动态验证 -> AI深入审计 -> 中文报告交付`

默认执行策略：
- Docker-only
- Deep Verify 开启
- 严格门禁开启
- AI 强尝试开启
- 目标优先追到 `confirmed`
- 先识别“无框架 / 有框架（含版本）”再分流执行
- 目标读者优先：网络安全人员
- Agent 自动关闭与资源回收开启

## 输入参数
- `project_path`（必填）：待审计项目目录（绝对路径）。
- `output_base_dir`（可选）：输出根目录，默认 `/tmp`。
- `threads`（可选）：并发线程，默认 `1`。
- `ai_model`（可选）：默认 `sonnet`（或继承环境变量）。
- `ai_rounds`（可选）：默认 `2`。
- `ai_candidates_per_round`（可选）：默认 `5`。
- `ai_timeout`（可选）：默认 `30` 秒。

输出目录固定格式：
- `project_name = basename(project_path)`
- `timestamp = YYYYmmdd_HHMMSS`
- `out_dir = {output_base_dir}/{project_name}/{timestamp}`

## 强制约束
1. 只允许通过 Docker 入口运行：
   - `skills/docker/run_audit.sh`
   - `skills/docker/run_debug.sh`
   - 兼容回退：`docker/run_audit.sh`、`docker/run_debug.sh`
2. 禁止宿主机直接执行核心 Python 入口：
   - `skills/_scripts/audit_cli.py`
   - `skills/_scripts/debug_runner.py`
3. 动态验证必须为容器内真实 `curl` 请求，不允许纯静态复述。
4. 默认严格参数：
   - `--deep-verify`
   - `--strict-deep-verify`
   - `--ai-realtime`
   - `--ai-force-all`
   - `--until-confirmed`
   - `--trace-verbose`
5. 动态阶段硬规则：
   - `debug_verify` 与 `ai_deep_audit` 默认禁止缓存跳过，必须真实执行。
   - 必须落地本次运行证据：`_meta/run_context.json`、`debug_verify/动态运行元信息.md`、`ai_deep_audit/AI深入审计阶段报告.md`。
6. 仅在用户明确要求时可放宽：
   - `--allow-conditional-stop`
   - `--disable-strict-deep-verify`
   - `--disable-ai-realtime`
7. Agent 资源回收硬规则（默认开启）：
   - 每个 Agent 任务完成后必须立即关闭并释放资源，不允许长期挂起。
   - 每个阶段 `Verifier Gate` 写入前，必须执行一次回收检查并确保无残留运行中 Agent。
   - 全流程结束后（成功/失败）都必须执行最终回收，并输出 `归档/质量门禁/资源回收报告.md`。
   - 回收运行台账必须落地：`_meta/agent_runtime.json`、`_meta/agent_reaper_events.jsonl`。
8. Agent 回收环境变量（默认值）：
   - `AGENT_AUTOCLOSE=1`
   - `AGENT_IDLE_TIMEOUT_SEC=120`
   - `AGENT_HEARTBEAT_SEC=5`
   - `AGENT_HARD_TIMEOUT_SEC=1800`

## 项目识别与执行分流（硬规则）
1. 进入动态阶段前，必须先做项目形态识别：
   - 识别是否为 PHP 框架项目（`composer.json` / `composer.lock` / 框架特征目录）。
   - 常见框架识别目标：`laravel`、`symfony`、`thinkphp`、`yii`、`codeigniter`、`slim`、`cakephp`、`hyperf`、`lumen`。
2. 若识别为“无框架项目”，必须执行“片段验证路径”：
   - 从高危 case 抽取最小可执行片段（source -> sink 上下文代码）。
   - AI 基于 `slice_file + slice_code + 注入位` 生成 PoC。
   - 在 Docker 内使用 `PHP片段 + curl` 做真实请求验证（禁止静态复述代替）。
3. 若识别为“框架项目”，必须执行“框架启动路径”：
   - 先识别框架类型与版本（优先 `composer.lock`，次选 `composer.json`）。
   - 选择对应 Docker 运行方式启动项目，并做健康检查确认启动成功。
   - 仅在“启动成功”后，进入 AI 深入审计与严格动态验证。
4. 严格验证收敛规则：
   - 默认启用 `--until-confirmed`，目标是“漏洞已确认（confirmed）”。
   - 若受客观条件阻断（环境/鉴权/依赖缺失），必须输出客观状态与阻断原因（`conditional/rejected/skipped`）。
5. Agent Team 要求：
   - 分流决策由独立 Agent 输出，禁止人工口头跳过识别步骤。
   - 框架启动与健康检查必须由独立 Agent 执行并留痕到阶段门禁文件。

## 多 Agent Team 编排规则
1. 必须采用 Team 模式，不允许单 Agent 串行冒充多角色。
2. 每个阶段必须分配独立 Agent，并由同一个 `agent-verifier` 做阶段门禁。
3. 按 case 拆分任务，尽量“一任务一 Agent”。
4. 失败优先局部重试（失败 case/失败阶段），避免全量重跑。
5. 产物路径、状态统计、门禁结果由 `Coordinator Agent` 统一汇总。
6. 必须使用 tmux 多窗口模式；每个窗口仅运行一个 Agent 命令，不得在同一窗口串行多个 Agent。
7. 主窗口只允许执行两类动作：汇总状态、写入门禁结论（`phase_gate_*.md` / `审计流水线状态.md`）。
8. 若环境不支持 tmux，多窗口要求降级为“后台并发任务”，但输出必须标记为 `fallback:no_tmux`。

## 单一质检Agent规则（强制）
1. 全流程只使用一个质检角色：`agent-verifier`。
2. 每个阶段结束后必须立刻执行一次 `agent-verifier` 验收。
3. 验收结果只有两种：`PASS` 或 `BLOCK`。
4. `BLOCK` 必须立即阻断后续阶段，只允许重跑当前失败阶段。
5. 每次验收必须生成独立报告：`归档/质量门禁/步骤门禁/phase_{id}_verifier.md`。
6. 流水线状态面板必须显示 `agent-verifier` 当前状态（待执行/执行中/已通过/已阻断）。

## tmux 执行约束（强制）
1. 窗口命名固定：`main`、`agent-route`、`agent-auth`、`agent-dep`、`agent-trace`、`agent-vuln-*`、`agent-debug`、`agent-report`。
2. `main` 窗口禁止直接跑审计模块脚本，只能做：
   - 轮询子窗口状态
   - 写门禁与流水线状态文件
   - 触发下一阶段窗口
3. 每个 `agent-*` 窗口只执行一个模块命令，命令结束后退出或进入只读等待。
4. 每个窗口必须落日志到 `{out_dir}/agent_logs/{window}.log`。
5. 阶段推进条件：当前阶段所有 `agent-*` 窗口成功，`main` 才能开启下一阶段窗口。
6. 阶段门禁前必须再次确认：当前阶段 `agent-*` 窗口均已关闭（不是仅“命令执行完”）。
7. 若发现僵尸窗口/挂起进程，`main` 必须先回收后再写门禁文件。

## Agent 自动关闭与回收（硬规则）
1. `agent-*` 窗口执行完单个命令后必须退出或进入只读状态，禁止进入交互等待。
2. 任一 Agent 在超时窗口内无心跳时，必须被回收并记录为 `reaped`。
3. 若阶段失败，必须立刻回收当前阶段全部 Agent，再输出失败门禁。
4. 若流程成功，必须在最终报告前确认“运行中 Agent 数 = 0”。
5. 回收报告至少包含：
   - Agent 启动次数
   - 已关闭数量
   - 强制回收数量
   - 回收异常数量
6. 若 `AGENT_AUTOCLOSE=0`，必须在门禁中明确标注“手动回收模式”与风险。

## 阶段0~7执行规范（对应 Gate 0~7）
说明：阶段0~7在阶段任务结束后，统一由 `agent-verifier` 执行验收并决定是否放行下一阶段。

### 阶段0：预检与编排（3 Agent）
- `Env Agent`：检查 docker/python3/compose 可用性并记录。
- `Path Agent`：计算输出目录 `{base}/{project}/{timestamp}`。
- `Coordinator Agent`：生成 `agent_task_manifest.md`（任务编排清单）。
- `Verifier Gate 0`：输出 `phase_gate_0.md`。

### 阶段1：信息收集（5 Agent 并行）
- `Route-Discover Agent`：`route_mapper` 全量路由发现。
- `Route-Param Agent`：参数位/请求方法提取（GET/POST/BODY等）。
- `Route-Burp Agent`：Burp 模板索引整理（`route_mapper/burp_templates`）。
- `Auth Agent`：`auth_audit` 鉴权映射。
- `Dependency Agent`：`vuln_scanner/mcp` 组件依赖风险。
- `Verifier Gate 1`：输出 `phase_gate_1.md`。

### 阶段2：调用链追踪（按案例拆分）
- `Trace-Dispatch Agent`：按路由入口分发追踪任务。
- `Trace-Worker-#1..#N Agent`：每条高危路由独立追踪（`route_tracer`）。
- `Trace-Merge Agent`：合并 `trace/sinks/call_graph` 结果。
- `Verifier Gate 2`：输出 `phase_gate_2.md`。

### 阶段3：交叉分析（2 Agent）
- `Risk-Join Agent`：合并 route/auth/vuln 结果，建立入口-鉴权-风险关联。
- `Risk-Priority Agent`：产出 `high_risk_routes` 与 `risk_backlog`（P0->P3）。
- `Verifier Gate 3`：输出 `phase_gate_3.md`。

### 阶段4：静态漏洞分析（命中才启动）
- `SQL Agent`：`sql_audit`
- `RCE Agent`：`rce_audit`
- `File Agent`：`file_audit`
- `SSRF/XXE Agent`：`ssrf_xxe_audit`
- `XSS/SSTI Agent`：`xss_ssti_audit`
- `CSRF Agent`：`csrf_audit`
- `VarOverride Agent`：`var_override_audit`
- `Serialize Agent`：`serialize_audit`
- `agent-verifier`：阶段4静态结果验收（仅静态证据，不做动态验证）
- `Verifier Gate 4`：输出 `phase_gate_4.md`。

### 阶段5：动态验证与漏洞确认（详细过程）
- `Framework-Detect Agent`：识别项目是否为框架、框架类型、框架版本。
- `Framework-Boot Agent`：框架项目 Docker 启动与健康检查（启动成功后才允许继续）。
- `Debug-Case Agent`：生成 `debug_cases`（每 case 动态计划）。
- `Snippet-Extract Agent`：无框架项目抽取最小可执行 PHP 片段。
- `Payload-Dict Agent`：字典优先注入（GET->POST->BODY->COOKIE->HEADER）。
- `Payload-AI Agent`：字典未命中时 AI 实时补全（可开关）。
- `Curl-Exec Agent`：Docker 内真实 `curl` 请求验证。
- `Trace-Evidence Agent`：记录动态过程/结果/函数追踪并生成 `debug_*.md`。
- `Burp-Pack Agent`：汇总 Burp 模版与复现说明。
- `Verifier Gate 5`：输出 `phase_gate_5.md`，强制 high/critical 绑定 `dynamic_status`。

### 阶段6：AI深入审计（严格执行）
- `Deep-Select Agent`：读取已生成漏洞报告与动态结果，默认仅选择 `conditional` 进入深审（可通过 `--target-statuses` 调整）。
- `Deep-AI Agent`：基于源码切片与注入位执行多轮 **AI 绕过**（不走字典 payload）。
- `Deep-Verify Agent`：Docker 内真实 `curl` 深验证，默认 `--until-confirmed`，输出客观状态。
- `Deep-Evidence Agent`：生成 `ai_deep_audit/AI深入审计阶段报告.md` 与 `ai_deep_audit_summary.json`。
- `Verifier Gate 6`：输出 `phase_gate_6.md`，强制校验 `ai_only_bypass=true`、目标状态覆盖、执行覆盖。

### 阶段7：报告汇总与交付（中文）
- `Binding Agent`：静态与动态结果绑定矩阵（`dynamic_status` 对齐）。
- `Main-Report Agent`：生成三主报告（`最终静态审计结果.md`、`动态debug审计报告.md`、`AI深入验证最终报告.md`）。
- `Appendix Agent`：生成归档主报告与技术附录（`归档/结论绑定/总报告.md`、`归档/结论绑定/总报告_技术附录.md`）。
- `KPI Agent`：覆盖率/确认率统计。
- `Evidence Agent`：执行证据门禁，生成 `证据校验.md`。
- `Verifier Gate 7`：输出 `phase_gate_7.md`。

## 切片代码驱动 AI PoC（硬规则）
1. 动态阶段必须先完成“框架识别分流”。
2. 无框架路径必须生成切片代码：`debug_verify/slices/*.php`。
3. AI 上下文必须至少包含：
   - `slice_file`
   - `slice_code`
   - `request_candidates`
   - 注入桶与参数位
4. 框架路径必须先通过健康检查，再执行 AI 产出 PoC + Docker 内真实 `curl` 验证。
5. AI 产出的候选请求必须经过 Docker 内真实 `curl` 验证。
6. 结果必须明确为：
   - `confirmed`
   - `conditional`
   - `rejected`
   - `skipped`
7. `skipped` 必须写入 `skip_reason`，枚举为：
   - `precheck_skip`
   - `runtime_skip`
   - `timeout`
   - `auth_required`
   且跳过率质量指标仅统计 `runtime_skip`。
8. 不允许把静态结论直接当动态结论。

## 标准执行命令（默认严格）
```bash
REPO_ROOT="/Users/dream/vscode_code/php_skills"
PROJECT_PATH="/path/to/project"
OUTPUT_BASE_DIR="/tmp"
THREADS="1"
AI_MODEL="sonnet"
AI_ROUNDS="2"
AI_CANDIDATES_PER_ROUND="5"
AI_TIMEOUT="30"

PROJECT_NAME="$(basename "${PROJECT_PATH%/}")"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
OUT_DIR="${OUTPUT_BASE_DIR}/${PROJECT_NAME}/${TIMESTAMP}"

"${REPO_ROOT}/skills/docker/run_audit.sh" "${PROJECT_PATH}" "${OUT_DIR}" \
  --deep-verify \
  --strict-deep-verify \
  --ai-realtime \
  --ai-force-all \
  --until-confirmed \
  --ai-model "${AI_MODEL}" \
  --ai-rounds "${AI_ROUNDS}" \
  --ai-candidates-per-round "${AI_CANDIDATES_PER_ROUND}" \
  --ai-timeout "${AI_TIMEOUT}" \
  --threads "${THREADS}" \
  --trace-verbose \
  --no-progress
```

> 默认等价环境变量（建议在 Team 会话中显式设置）：
```bash
export AGENT_AUTOCLOSE=1
export AGENT_IDLE_TIMEOUT_SEC=120
export AGENT_HEARTBEAT_SEC=5
export AGENT_HARD_TIMEOUT_SEC=1800
```

## 放宽模式（可选）
仅在用户明确要求时追加任一参数：
- `--allow-conditional-stop`
- `--disable-strict-deep-verify`
- `--disable-ai-realtime`
- `--debug-skipped-ratio-max 0.60`（调整动态跳过比例预警阈值）

## 交付产物（目录契约）
最终输出目录（用户自定义 `output_base_dir`）：

```text
{output_base_dir}/{project_name}/{timestamp}/
├── 最终静态审计结果.md
├── 动态debug审计报告.md
├── AI深入验证最终报告.md
├── route_mapper/
├── auth_audit/
├── vuln_report/
├── route_tracer/
├── sql_audit/
├── rce_audit/
├── file_audit/
├── ssrf_xxe_audit/
├── xss_ssti_audit/
├── csrf_audit/
├── var_override_audit/
├── serialize_audit/
├── debug_verify/
├── ai_deep_audit/
├── _meta/
├── 报告汇总/
└── 归档/
    ├── 阶段报告/
    ├── 调试证据/
    ├── Burp模板/
    ├── 质量门禁/
    └── 结论绑定/
```

### AI深入验证最终报告（硬约束）
1. 固定章节：
   - `一、验证结果`
   - `二、验证过程`
   - `三、结论对照（静态 / 动态 / AI）`
   - `四、证据索引`
2. 状态必须全中文：
   - `已确认`
   - `有条件成立`
   - `已排除`
   - `已跳过`
3. `二、验证过程` 仅展示 `已确认/有条件成立` 的 case 明细；`已排除/已跳过` 仅做汇总不展开。
4. 禁止出现：
   - “最终判定”章节
   - “请求样例”小节
5. 每条验证过程必须包含 Burp 复现模版代码块（```http）。

## 输出规范（对外回复）
1. 只输出 `.md` 报告绝对路径。
2. 一行一个路径。
3. 外层三主报告路径必须优先输出：
   - `最终静态审计结果.md`
   - `动态debug审计报告.md`
   - `AI深入验证最终报告.md`
4. 归档关键报告路径随后输出（至少包含 `归档/质量门禁/证据校验.md` 与 `归档/结论绑定/总报告.md`）。
5. 必须输出 `归档/质量门禁/资源回收报告.md` 绝对路径。
6. 最后一行必须是 `AI深入验证最终报告.md` 的绝对路径。
7. 如存在未确认漏洞，附最多 30 条：`case_id + result + stop_reason + ai_status`。

## 失败处理（必须）
失败时必须输出：
- 失败阶段（0~7）
- 失败命令
- 关键 stderr
- 已生成 `.md` 报告绝对路径
- 可直接复跑的修复命令
