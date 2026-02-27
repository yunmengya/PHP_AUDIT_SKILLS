# PHP_AUDIT_SKILLS

PHP 安全审计技能集合，覆盖路由映射、调用链追踪、漏洞模块分析、证据校验与报告汇总。

## Overview

- 审计模式：静态证据链为主，动态验证为辅
- 输出目标：可复核、可追踪、可复现
- 默认输出目录：`/tmp/{project_name}/{timestamp}`

## Modules

- `route_mapper`：路由提取与参数建模
- `route_tracer`：调用链追踪与 Sink 识别
- `sql_audit`：SQL 注入审计
- `auth_audit`：鉴权/越权审计
- `file_audit`：文件相关风险审计
- `rce_audit`：命令执行/代码执行审计
- `ssrf_xxe_audit`：SSRF/XXE 审计
- `xss_ssti_audit`：XSS/SSTI 审计
- `csrf_audit`：CSRF 审计
- `var_override_audit`：变量覆盖审计
- `serialize_audit`：反序列化/Phar/POP 审计
- `vuln_scanner`：依赖漏洞检测
- `final_report`：最终报告生成
- `evidence_check`：证据完整性校验

## Structure

```text
skills/
├── docker/
│   ├── Dockerfile
│   ├── docker-compose.yml
│   ├── run_audit.sh
│   └── run_debug.sh
├── _scripts/
│   ├── audit_cli.py
│   ├── run_samples.py
│   └── *_audit.py
├── _samples/
├── php-*-audit/
├── semgrep-mcp/
├── composer-audit-mcp/
└── report-writer-mcp/
```

## Requirements

- Docker
- Docker Compose
- Git
- Python 3

## Quick Start

### 1. Clone and enter

```bash
git clone https://github.com/<org>/<repo>.git
cd <repo>/skills
```

### 2. Run full audit

```bash
./docker/run_audit.sh <target-project-path>
```

示例：

```bash
./docker/run_audit.sh ../demo_php_app
```

### 3. Run with custom output

```bash
./docker/run_audit.sh <target-project-path> <output-path>
```

### 4. Run selected modules

```bash
./docker/run_audit.sh <target-project-path> \
  --skip-mcp \
  --no-cache \
  --modules route_mapper,route_tracer,sql_audit,final_report,evidence_check
```

### 5. Run debug verification

```bash
./docker/run_debug.sh <target-project-path>
```

## Common Options

`run_audit.sh`:

- `--modules <m1,m2,...>`
- `--skip-mcp`
- `--no-cache`
- `--config <path>`

`run_debug.sh`:

- `--ai-realtime` / `--disable-ai-realtime`
- `--ai-model <model>`
- `--ai-rounds <n>`
- `--ai-candidates-per-round <n>`
- `--ai-timeout <sec>`
- `--trace-verbose`

## Output Artifacts

典型输出：

- `{out}/route_mapper/`
- `{out}/route_tracer/`
- `{out}/sql_audit/`、`{out}/auth_audit/` 等模块目录
- `{out}/_meta/`（Phase 1~5）
- `{out}/debug_verify/debug_evidence.json`
- `{out}/final_report.json`
- `{out}/evidence_check.json`

## Regression

运行样例回归：

```bash
python3 _scripts/run_samples.py
```

该脚本会调用 `./docker/run_audit.sh` 并校验样例输出。

## Commit Convention

建议采用 Conventional Commits：

```text
<type>(<scope>): <summary>
```

示例：

```text
feat(sql_audit): add sink controllability evidence in markdown report
fix(route_tracer): correct taint propagation across nested calls
docs(readme): add skills-level github documentation
```

## Agent Team Prompt

```text
你是技能：PHP_AUDIT_SKILLS 的执行编排器。
目标：对指定 PHP 项目执行完整安全审计流程，必须使用多 agent team 模式，覆盖“路由发现 -> 污点追踪 -> 各漏洞模块分 agent -> 动态 debug 验证（含过程记录）-> 报告汇总”。

【输入参数】
- project_path: 待审计项目绝对路径（必填）
- output_base_dir: 用户指定输出根目录（必填；例如 /tmp）
- run_mode: full（默认）
- threads: 默认 1

【硬性约束】
1. 必须使用 agent team 模式，且至少包含以下角色：
- Coordinator（总控）
- Route Agent（路由发现）
- Taint Agent（污点追踪/调用链）
- Vuln Agents（漏洞模块并行：SQL/Auth/File/RCE/SSRF_XXE/XSS_SSTI/CSRF/VarOverride/Serialize）
- Debug Agent（动态验证与过程记录）
- Report Agent（报告汇总与验收）

2. 必须通过 Docker 入口执行，不允许宿主机直接跑核心 Python 入口：
- /Users/dream/vscode_code/php_skills/skills/docker/run_audit.sh
- /Users/dream/vscode_code/php_skills/skills/docker/run_debug.sh

3. 输出目录必须为：
- {output_base_dir}/{project_name}/{timestamp}
- timestamp 格式：YYYYmmdd_HHMMSS

4. 运行完成后，必须打印全部报告文件“绝对路径”，并且“总报告路径放在最后一行”。

【执行流程】
1. 计算输出目录：
- project_name = basename(project_path)
- timestamp = 当前时间（YYYYmmdd_HHMMSS）
- out_dir = output_base_dir/project_name/timestamp

2. 在仓库目录执行：
- 工作目录：/Users/dream/vscode_code/php_skills

3. 执行完整审计（静态 + 动态 + 汇总）：
/Users/dream/vscode_code/php_skills/skills/docker/run_audit.sh \
  "{project_path}" "{out_dir}" \
  --skip-mcp \
  --no-cache \
  --threads {threads} \
  --no-progress \
  --modules route_mapper,route_tracer,sql_audit,auth_audit,file_audit,rce_audit,ssrf_xxe_audit,xss_ssti_audit,csrf_audit,var_override_audit,serialize_audit,severity_enrich,debug_verify,report_refresh,phase_attack_chain,phase_report_index,final_report,evidence_check

4. Agent 分工要求：
- Route Agent: 校验 route_mapper/route_tracer 产物存在性与条目数
- Taint Agent: 读取 trace/sinks，确认高危路径是否可达
- Vuln Agents: 分别汇总各模块 findings（数量、严重度、入口、位置）
- Debug Agent: 汇总 debug_evidence/debug_process/debug_poc/debug_func_trace，并标注 confirmed/conditional/rejected/skipped
- Report Agent: 汇总主报告+附录+中文报告，输出最终路径清单

5. 严格验收（全部满足）：
- 命令退出码为 0
- 以下文件存在：
  - {out_dir}/final_report.md
  - {out_dir}/final_report_appendix.md
  - {out_dir}/final_report.json
  - {out_dir}/总报告.md
  - {out_dir}/总报告_技术附录.md
  - {out_dir}/总报告.json
  - {out_dir}/debug_verify/debug_evidence.json
  - {out_dir}/debug_verify/debug_process.json
  - {out_dir}/debug_verify/debug_poc.json
  - {out_dir}/debug_verify/debug_func_trace.json
- 输出必须包含所有报告绝对路径，且最后一行是总报告（总报告.md）的绝对路径

【输出格式】
按以下顺序输出：
1. 执行摘要（成功/失败、总耗时、模块覆盖）
2. 动态验证摘要（confirmed/conditional/rejected/skipped 计数）
3. 报告路径清单（绝对路径，一行一个）
4. 最后一行仅输出：总报告.md 的绝对路径

【失败处理】
- 若任一步骤失败，不要中断整体输出。
- 必须给出：失败阶段、失败命令、stderr 关键行、已生成文件清单、下一步修复建议。
```
