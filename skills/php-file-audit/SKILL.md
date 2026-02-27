---
name: php-file-audit
description: Audit file upload/read/write/delete/include/unzip risks in PHP and output evidence-based findings.
---

# php-file-audit

## 用途
覆盖文件上传、读取、写入、删除、包含、解压相关风险。

## 输入
- 项目根目录
- 可选：route_mapper/routes.json
- 可选：route_tracer 输出

## 输出
- {project}_audit/file_audit/findings.json
- {project}_audit/file_audit/findings.md
- {project}_audit/file_audit/{project}_file_audit_{timestamp}.md

## 工作流
1. 识别文件相关入口（上传参数、路径参数、文件名拼接）。
2. 关注文件类危险函数与操作链：上传/读取/写入/删除/包含/解压。
3. 追踪 source → sink，记录路径拼接/过滤逻辑（realpath/basename/allowlist）。
4. 输出证据链与 PoC 模板。

## Debug 验证（Docker）
- 必须输出 debug_evidence.json/.md（统一字段）
- 记录入口 → 中间处理 → sink 的证据链
- 判定规则：文件类以“输入是否被限制”为主
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
- ../基础_txt/任意文件上传.txt
- ../基础_txt/任意文件读取.txt
- ../基础_txt/文件包含.txt
