# {project_name} - SQL 注入审计报告

生成时间：{timestamp}
审计路径：{project_path}

## 一、SQL 操作映射表
| 序号 | 位置(文件:行) | 方法/函数 | 框架 | 参数化状态 | 可控性 | 独立等级 | 组合等级 |
|---|---|---|---|---|---|---|---|
| 1 | {file}:{line} | {function} | {framework} | {param_status} | {controllability} | {independent_severity} | {combined_severity} |

## 二、风险详情
### {id} {title}
- 独立等级：{independent_severity}
- 组合等级：{combined_severity}
- 置信度：{confidence}
- 路由/入口：{route}
- Sink：{sink}
- 过滤/校验：{validation}
- 可控性：{controllability}
- 证据来源：{evidence_source}

**证据链**
- Source：{source}
- Taint：{taint}
- Sink：{sink}

**PoC 模板（不执行）**
```
{poc}
```

**修复建议**
- 使用预编译/参数绑定
- 对 ORDER BY / 列名 / 表名采用白名单
- 统一输入校验与类型约束

## 三、结论
- 高危数量：{high_count}
- 中危数量：{medium_count}
- 低危数量：{low_count}
- 可控性统计：fully={fully_count}, conditional={conditional_count}, none={none_count}

> 说明：若缺少 route_tracer 的 controllability 字段，结论默认标记为 conditional。
