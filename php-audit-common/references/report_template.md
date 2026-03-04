# 漏洞审计报告模板（通用）

## 基本信息
- 项目名称：
- 审计时间：
- 审计范围：
- 审计版本：

## 漏洞条目
### 标题：{title}
- 独立等级：{independent_severity}
- 组合等级：{combined_severity}
- 置信度：{confidence}
- 路由/入口：{route}

#### 证据链
- Source：{source}
- Taint 传播：{taint}
- Sink：{sink}
- 过滤/校验：{validation}
- 可控性结论：{controllability}

#### PoC 模板（不执行）
{poc}

#### Debug 动态验证证据
- 输入值：{input}
- 最终值：{final_value}
- 变化类型：{change_type}
- 判定结果：{result}
- debug_evidence：{debug_evidence_path}

#### 影响与建议
- 影响：
- 修复建议：

## 汇总
- 高危数量：
- 中危数量：
- 低危数量：
- 其他：

## 说明
- 对于专项模块（SQL/Auth/Vuln）请使用对应模板
- 其他漏洞模块可使用 TEMPLATE_GENERIC_AUDIT.md
