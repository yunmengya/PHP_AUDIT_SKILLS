---
name: php-sql-audit
description: Perform PHP SQL injection audit using evidence chains and output standardized findings.
---

# php-sql-audit

## 用途
基于证据链完成 SQL 注入审计，输出标准化报告。

## 输入
- 项目根目录
- 必选：route_mapper/routes.json
- 必选：route_tracer 输出（必须包含 controllability 字段）

## 输出
- {project}_audit/sql_audit/findings.json
- {project}_audit/sql_audit/findings.md
- {project}_audit/sql_audit/{project}_sql_audit_{timestamp}.md

## 工作流
1. 读取路由与 trace（若有），聚焦入口与数据流。
2. 通过 semgrep 定位 SQL 相关风险点。
3. 用 ripgrep 补强上下文，确认 source → sink 证据链。
4. 识别过滤/转义/预编译的有效性。
5. 生成 findings.json 与 findings.md。
6. 生成综合报告 {project}_sql_audit_{timestamp}.md（包含映射表/风险详情/PoC/修复建议）。

## 证据链要求
- 必须包含 source、taint、sink、validation、controllability、PoC 模板。

## 强制规则
- 若无 route_tracer 输出或缺少 controllability 字段，结论只能标记为 “conditional”。
- 综合报告必须包含 SQL 操作映射表、风险详情、PoC 模板、修复建议。
- 结论区必须引用 route_tracer 的 controllability 证据。

## Debug 验证（Docker）
- 必须输出 debug_evidence.json/.md（统一字段）
- 记录入口 → 中间处理 → sink 的证据链
- 判定规则：SQL/命令/文件类以“输入是否被限制”为主
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
- ../_shared/TEMPLATE_SQL_AUDIT.md
- ../php-audit-common/references/sources.yml
- ../php-audit-common/references/sinks.yml
- ../php-audit-common/references/sanitizers.yml
- ../php-audit-common/references/report_template.md
- ../基础_txt/SQL注入.txt
