---
name: semgrep-mcp
description: Use official Semgrep CLI to scan PHP code with registry rules (e.g., r/all) and output normalized results.
---

# semgrep-mcp

## 用途
使用官方 Semgrep CLI 执行规则扫描，输出标准化 MCP 结果。

## 默认策略
- 默认规则集：`r/all`（Semgrep Registry 公共规则全集）
- 追加规则：`p/trailofbits` + 本地规则仓库 + PHP taint rules（见下方同步脚本）

## 输入
- PHP 项目根目录

## 输出
- {project}_audit/mcp_raw/semgrep-mcp.json
- {project}_audit/mcp_parsed/semgrep-mcp.json

## 脚本
- 执行：`scripts/semgrep_mcp.py`
- 规则配置：`assets/rulesets.json`
- 规则同步：`scripts/sync_rules.sh`
- 本地 CLI：`/Users/dream/vscode_code/php_skills/skills/semgrep-mcp/.venv/bin/semgrep`
- PHP taint 规则：`assets/php_taint_rules/`

## 使用方式
```
python3 /Users/dream/vscode_code/php_skills/skills/semgrep-mcp/scripts/semgrep_mcp.py \
  --project /path/to/php_project \
  --ruleset /Users/dream/vscode_code/php_skills/skills/semgrep-mcp/assets/rulesets.json
```

## 规则扩展
- 先执行规则同步脚本：`/Users/dream/vscode_code/php_skills/skills/semgrep-mcp/scripts/sync_rules.sh`
- 在 `assets/rulesets.json` 里追加 Semgrep Registry 规则包或本地规则路径。
- 若有 Fortify/RIPS/Seay 规则，需先转换为 Semgrep YAML 并放入本地路径，再加入 rulesets.json。
