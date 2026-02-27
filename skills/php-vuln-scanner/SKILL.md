---
name: php-vuln-scanner
description: Scan PHP dependencies via composer.lock and output vulnerability report.
---

# php-vuln-scanner

## 用途
基于 composer.lock 的依赖漏洞扫描。

## 输入
- 项目根目录（包含 composer.lock）

## 输出
- {project}_audit/vuln_report/composer_audit.json
- {project}_audit/vuln_report/composer_audit.md

## 工作流
1. 检查 composer.lock 是否存在并可读取。
2. 调用 composer-audit-mcp 生成依赖漏洞结果。
3. 输出 json 与 markdown 摘要。
4. 在 markdown 末尾追加“触发点分析”段落（项目环境/入口/组件触发点）。

## 约束
- 仅静态报告，不执行更新或修复。

## Debug 验证（Docker）
- 必须输出 debug_evidence.json/.md（统一字段）
- 依赖漏洞通常无法直接动态验证，可标记为 conditional 或 skipped
- 需在 notes 中写明 skip_reason 或触发点假设

## 参考
- ../_shared/OUTPUT_STANDARD.md
- ../_shared/MCP_WORKFLOW.md
- ../_shared/MCP_TEMPLATE.md
- ../_shared/TEMPLATE_VULN_TRIGGER.md
- ../php-audit-common/references/report_template.md
