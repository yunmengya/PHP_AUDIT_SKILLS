---
name: php-route-mapper
description: Extract PHP routes, parameter shapes, and Burp request templates. Outputs to {project}_audit/route_mapper/.
---

# php-route-mapper

## 用途
从 PHP 项目中提取路由、参数结构，并生成 Burp 请求模板。

## 输入
- 项目根目录

## 输出
- {project}_audit/route_mapper/routes.json
- {project}_audit/route_mapper/routes.md
- {project}_audit/route_mapper/burp_templates/

## 工作流
1. 判断框架类型与路由来源（参考 ../_shared/FRAMEWORK_ROUTING.md）。
2. 解析路由定义，提取 method/path/controller/action/middleware。
3. 定位控制器方法，提取参数来源（GET/POST/JSON/HEADER/COOKIE）。
4. 生成每条路由的 Burp 请求模板（占位参数即可）。
5. 输出 routes.json 与 routes.md（摘要表格）。
6. 若未命中框架路由：尝试通用 Router 规则与 REQUEST_URI 手写路由兜底。
7. 若仍为空：回退到入口文件（public/index.php 等）作为单一路由。

## 输出要求
- 路由必须包含 method、path、controller、action、params。
- params 需标明来源与默认值（如有）。

## 参考
- ../_shared/OUTPUT_STANDARD.md
- ../_shared/FRAMEWORK_ROUTING.md
- ../_shared/MCP_TEMPLATE.md
- ../php-audit-common/references/frameworks/thinkphp.yml
- ../php-audit-common/references/frameworks/laravel.yml
- ../php-audit-common/references/frameworks/symfony.yml
- ../php-audit-common/references/frameworks/yii.yml
- ../php-audit-common/references/frameworks/codeigniter.yml
