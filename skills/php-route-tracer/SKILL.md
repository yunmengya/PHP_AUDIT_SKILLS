---
name: php-route-tracer
description: Trace call chains and parameter flows for PHP routes, identify sinks, and output evidence per route.
---

# php-route-tracer

## 用途
基于路由入口追踪调用链、参数流向与 sink，输出可复核证据链。

## 输入
- 项目根目录
- 可选：{project}_audit/route_mapper/routes.json

## 输出
- {project}_audit/route_tracer/call_graph.json
- {project}_audit/route_tracer/call_graph.md
- {project}_audit/route_tracer/{route_name}/trace.json
- {project}_audit/route_tracer/{route_name}/trace.md
- {project}_audit/route_tracer/{route_name}/sinks.json

## 工作流
0. 先运行 call_graph.py 生成全量调用图（call_graph.json）。
1. 以 routes.json 为入口定位 controller/action。
2. 构建方法调用链，记录跨文件/跨类调用。
3. 追踪参数流向（source → 变量传播 → sink）。
4. 标注过滤/校验逻辑，并记录断链点。
5. 每条路由输出 trace.json 与 trace.md。

## 输出要求
- trace.json 至少包含 source、taint、sink、validation、controllability。
- 若断链，controllability 为 conditional 并说明断链点。

## 参考
- ../_shared/OUTPUT_STANDARD.md
- ../_shared/MCP_WORKFLOW.md
- ../_shared/MCP_TEMPLATE.md
- ../php-audit-common/references/sources.yml
- ../php-audit-common/references/sinks.yml
- ../php-audit-common/references/sanitizers.yml
