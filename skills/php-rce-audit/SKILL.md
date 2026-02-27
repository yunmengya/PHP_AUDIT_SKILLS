---
name: php-rce-audit
description: Audit PHP command/code execution risks and output evidence-based findings.
---

# php-rce-audit

## 用途
覆盖命令执行与代码执行相关风险。

## 输入
- 项目根目录
- 可选：route_mapper/routes.json
- 可选：route_tracer 输出

## 输出
- {project}_audit/rce_audit/findings.json
- {project}_audit/rce_audit/findings.md
- {project}_audit/rce_audit/{project}_rce_audit_{timestamp}.md

## 工作流
1. 定位命令执行/代码执行危险函数与调用点。
2. 追踪可控输入到危险点的证据链。
3. 识别过滤/白名单/禁用函数等防护。
4. 输出 findings.json 与 findings.md。
5. 对命中危险函数输出替代建议（recommendation）。

## 输出要求
- findings.json 中可选字段：
  - dangerous_function: 命中函数名
  - recommendation: 替代建议列表

## Debug 验证（Docker）
- 必须输出 debug_evidence.json/.md（统一字段）
- 记录入口 → 中间处理 → sink 的证据链
- 判定规则：命令/代码执行以“输入是否被限制”为主
- change_type：no_change → 成立；weak_change → 条件成立；strong_change → 不成立

## 方法论对齐（Phase 1~5）
- Phase 1：先完成 `_meta/phase1_map.md`，确认攻击面与优先级。
- Phase 2：并行扫描，填写 `_meta/phase2_risk_map.md` 风险地图。
- Phase 3：深度追踪证据链，记录 `_meta/phase3_trace_log.md`。
- Phase 4：验证与攻击链构建，记录 `_meta/phase4_attack_chain.md`。
- Phase 5：报告输出与终止判断，填写 `_meta/phase5_report_index.md`。
- 终止判断必须回答 Q1/Q2/Q3。

## 参考
- ../_shared/METHODOLOGY.md
- ../_shared/SEVERITY_MODEL.md
- ../_shared/TEMPLATE_PHASE_LOG.md
- ../_shared/AGENT_MAP_PHP.md
- ../_shared/OUTPUT_STANDARD.md
- ../_shared/MCP_WORKFLOW.md
- ../_shared/MCP_TEMPLATE.md
- ../_shared/TEMPLATE_GENERIC_AUDIT.md
- ../php-audit-common/references/sources.yml
- ../php-audit-common/references/sinks.yml
- ../php-audit-common/references/sanitizers.yml
- ../php-audit-common/references/report_template.md
- ../基础_txt/命令执行.txt
- ../基础_txt/代码执行.txt
