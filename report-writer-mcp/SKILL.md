---
name: report-writer-mcp
description: Aggregate audit findings into a unified summary report.
---

# report-writer-mcp

## 用途
聚合各模块的 findings 输出，生成统一摘要报告。

## 输入
- {out} 目录（包含 findings.json / auth_evidence.json）

## 输出
- {out}/report_summary.json
- {out}/report_summary.md

## 脚本
- 执行：`scripts/report_writer_mcp.py`

## 使用方式
```
python3 /Users/dream/vscode_code/php_skills/skills/report-writer-mcp/scripts/report_writer_mcp.py \
  --project /path/to/php_project
```
