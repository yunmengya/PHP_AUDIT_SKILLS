---
name: composer-audit-mcp
description: Use Composer audit to scan PHP dependencies for known vulnerabilities and output normalized results.
---

# composer-audit-mcp

## 用途
基于 `composer.lock` 进行依赖漏洞扫描，输出标准化 MCP 结果与报告。

## 输入
- PHP 项目根目录（必须包含 composer.lock）

## 输出
- {project}_audit/mcp_raw/composer-audit-mcp.json
- {project}_audit/mcp_parsed/composer-audit-mcp.json
- {project}_audit/vuln_report/composer_audit.json
- {project}_audit/vuln_report/composer_audit.md

## 脚本
- 执行：`scripts/composer_audit_mcp.py`
- 本地 composer：`assets/composer.phar`

## 使用方式
```
python3 /Users/dream/vscode_code/php_skills/skills/composer-audit-mcp/scripts/composer_audit_mcp.py \
  --project /path/to/php_project
```

## 说明
- 优先使用技能内的 `composer.phar`，无则使用系统 `composer`。
- 若项目无 composer.lock，则标记为 missing。
