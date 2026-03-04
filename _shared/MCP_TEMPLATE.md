# MCP 调度模板

## 标准调用
- semgrep-mcp：执行静态规则扫描（含 taint rules）
- ripgrep-mcp：抽取上下文证据链
- composer-audit-mcp：依赖漏洞扫描
- report-writer-mcp：汇总输出报告

## 标准输出
- {project}_audit/mcp_raw/
- {project}_audit/mcp_parsed/

## 使用说明
- 在具体 SKILL 中引用本模板，避免手工复制错误。
- 若缺失某 MCP，需在报告中降低 confidence。
