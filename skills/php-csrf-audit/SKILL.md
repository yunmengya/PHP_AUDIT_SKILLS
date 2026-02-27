---
name: php-csrf-audit
description: Audit CSRF protections in PHP routes and output evidence-based findings.
---

# php-csrf-audit

## 用途
覆盖 CSRF 风险与防护缺失。

## 输入
- 项目根目录
- 可选：route_mapper/routes.json

## 输出
- {project}_audit/csrf_audit/findings.json
- {project}_audit/csrf_audit/findings.md
- {project}_audit/csrf_audit/{project}_csrf_audit_{timestamp}.md

## 工作流
1. 识别会改变状态的接口（POST/PUT/DELETE 等）。
2. 检查 CSRF token/Referer/Origin 验证逻辑。
3. 记录缺失或弱校验路径。
4. 输出 findings.json 与 findings.md。

## Debug 验证（Docker）
- 必须输出 debug_evidence.json/.md（统一字段）
- 记录入口 → 中间处理 → sink 的证据链
- 判定规则：CSRF 重点看 token/来源校验是否生效
- change_type：no_change → 成立；weak_change → 条件成立；strong_change → 不成立

## 方法论对齐（Phase 1~5）
- Phase 1：先完成 `_meta/phase1_map.md`，确认攻击面与优先级。
- Phase 2：并行扫描，填写 `_meta/phase2_risk_map.md` 风险地图。
- Phase 3：深度追踪证据链，记录 `_meta/phase3_trace_log.md`。
- Phase 4：验证与攻击链构建，记录 `_meta/phase4_attack_chain.md`。
- Phase 5：报告输出与终止判断，填写 `_meta/phase5_report_index.md`。
- 终止判断必须回答 Q1/Q2/Q3。

## 参考
- ../php-audit-common/references/auth_rules.yml
- ../php-audit-common/references/framework_rules.yml
- ../_shared/METHODOLOGY.md
- ../_shared/SEVERITY_MODEL.md
- ../_shared/TEMPLATE_PHASE_LOG.md
- ../_shared/AGENT_MAP_PHP.md
- ../_shared/OUTPUT_STANDARD.md
- ../_shared/MCP_WORKFLOW.md
- ../_shared/MCP_TEMPLATE.md
- ../_shared/TEMPLATE_GENERIC_AUDIT.md
- ../php-audit-common/references/report_template.md
- ../基础_txt/CSRF.txt
