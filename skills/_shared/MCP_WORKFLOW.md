# MCP 工作流约定

## 工具角色
- semgrep-mcp：规则补充与交叉验证
- ripgrep-mcp：定位上下文与证据链补强
- composer-audit-mcp：依赖漏洞
- report-writer-mcp：统一报告输出

## 统一输入（建议）
- project_root：项目根目录
- route_map：可选，来自 route_mapper 的 routes.json
- trace_root：可选，来自 route_tracer 的目录

## 统一输出（建议）
- 各模块输出遵循 OUTPUT_STANDARD.md 的 findings.json
- 若工具输出为非结构化文本，应二次解析并补齐字段

## 约束与降级
- semgrep 结果必须用 ripgrep 复核关键路径
- 任一工具缺失时，仍输出 findings.json，但 confidence 下调
- mcp_adapter 统一输出：status + confidence 字段；失败/缺失标记 degraded=true，并写入 mcp_parsed/summary.json 的 degraded_tools
- 动态验证由 debug_verify 输出 debug_evidence.json/.md；不做真实渗透测试

## 适配层（脚本）
- mcp 适配执行：/Users/dream/vscode_code/php_skills/skills/_scripts/mcp_adapter.py
- semgrep-mcp：/Users/dream/vscode_code/php_skills/skills/semgrep-mcp/scripts/semgrep_mcp.py
- semgrep 规则同步：/Users/dream/vscode_code/php_skills/skills/semgrep-mcp/scripts/sync_rules.sh
- ripgrep-mcp：/Users/dream/vscode_code/php_skills/skills/_scripts/ripgrep_mcp.py
- composer-audit-mcp：/Users/dream/vscode_code/php_skills/skills/composer-audit-mcp/scripts/composer_audit_mcp.py
- report-writer-mcp：/Users/dream/vscode_code/php_skills/skills/report-writer-mcp/scripts/report_writer_mcp.py
- semgrep->findings：/Users/dream/vscode_code/php_skills/skills/_scripts/semgrep_to_findings.py
- 汇总输出：/Users/dream/vscode_code/php_skills/skills/_scripts/report_writer.py
- 配置示例：/Users/dream/vscode_code/php_skills/skills/_scripts/mcp_config.example.json
