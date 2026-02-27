---
name: php-auth-audit
description: Audit authentication and authorization logic for PHP routes, output three-file report.
---

# php-auth-audit

## 用途
鉴权/越权审计，输出三文件结构化报告。

## 输入
- 项目根目录
- 可选：route_mapper/routes.json
- 可选：route_tracer 输出

## 输出
- {project}_audit/auth_audit/auth_routes.md
- {project}_audit/auth_audit/auth_findings.md
- {project}_audit/auth_audit/auth_evidence.json
- {project}_audit/auth_audit/{project}_auth_audit_{timestamp}.md
- {project}_audit/auth_audit/{project}_auth_mapping_{timestamp}.md
- {project}_audit/auth_audit/{project}_auth_README_{timestamp}.md

## 工作流
1. 枚举所有路由与入口，识别鉴权入口（middleware/guard/session/token）。
2. 检查控制器/服务层的资源归属校验（user_id/tenant_id/role）。
3. 标记缺失鉴权或越权风险路径。
4. 输出三文件，auth_evidence.json 使用统一证据链字段。

## 输出要求
- auth_routes.md：路由 → 鉴权机制 → 关键判断点
- auth_findings.md：缺失鉴权/越权风险摘要
- auth_evidence.json：结构化证据链
- ownership_checks：资源归属判定证据（若命中）

## 职责分离（强制）
- 主报告 {project}_auth_audit_{timestamp}.md：仅漏洞分析与风险摘要
- 映射表 {project}_auth_mapping_{timestamp}.md：仅路由→鉴权机制映射
- README {project}_auth_README_{timestamp}.md：仅说明结构与使用方法
- 主报告不得重复完整路由清单；映射表不得包含漏洞分析或 PoC

## 完整性校验（强制）
- 三文件必须存在且互相引用正确
- 若发现职责重复，必须拆分调整

## Debug 验证（Docker）
- 必须输出 debug_evidence.json/.md（统一字段）
- 记录入口 → 中间处理 → sink 的证据链
- 判定规则：鉴权重点看权限/资源归属校验是否生效
- change_type：no_change → 条件成立；weak_change → 条件成立；strong_change → 不成立

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
- ../php-audit-common/references/sources.yml
- ../php-audit-common/references/sinks.yml
- ../php-audit-common/references/sanitizers.yml
- ../php-audit-common/references/report_template.md
