# Lessons Learned — 经验沉淀库

本文件是所有审计项目的经验积累中心。每次审计结束后，Report-Writer 自动提取关键经验写入此文件。
人工复盘时也可手动补充。文件按时间倒序排列，最新经验在最前面。

---

## 使用指南

### 文件定位
- **谁写**: Report-Writer Agent 在生成报告后自动 append；审计人员手动补充
- **谁读**: 所有 Agent 在审计开始前加载，用于调整策略优先级
- **增长方式**: 只增不删（append-only），每个项目至少贡献 1-3 条经验
- **反馈标记**: 自动统计成功/失败率，标注 `[实测高效]` / `[实测低效]`

### 如何利用本文件
1. **审计前**: Scanner / Exploiter 读取本文件，优先尝试 `[实测高效]` 的 payload 和绕过技巧
2. **审计中**: 遇到罕见情况随时记录到 "新发现模式" 分类
3. **审计后**: Report-Writer 批量提取本次审计经验，自动归类

### 条目格式模板

```markdown
### [日期] [框架] [漏洞类型] — 简述
- **项目**: {项目名}
- **发现**: {一句话描述发现}
- **关键细节**: {为什么有效/为什么失败}
- **影响**: {对 shared 文件的建议更新}
```

---

## 分类一：有效绕过

> 实战中确认可用的绕过手法、payload 变形、链式攻击等。

### [2026-01-15] [Laravel] [RCE] — Ignition filecontents + log poisoning 链式 RCE
- **项目**: example-shop-v2
- **发现**: Laravel 8 + Ignition 2.5.1 组合可通过 `_ignition/execute-solution` 写入 phar 到 log 实现 RCE
- **关键细节**: 需要 APP_DEBUG=true 且 Ignition < 2.5.2；payload 先 clear log 再逐字节写入避免 base64 padding 问题
- **影响**: 建议在 `framework_patterns.md` Laravel 部分增加 Ignition 版本检测；`payload_templates.md` 增加 log poisoning phar 模板
- **标记**: `[实测高效]` — 3/3 项目成功

### [2026-01-10] [ThinkPHP] [SQLi] — ThinkPHP 5.x where 数组注入绕过 PDO 预编译
- **项目**: cms-admin-panel
- **发现**: `where(['id' => $_GET['id']])` 当 id 传入数组 `id[0]=exp&id[1]=... ` 时可绕过参数绑定
- **关键细节**: ThinkPHP 5.0.0 ~ 5.0.23 受影响；5.1.x 修复了 exp 但 `LIKE` / `BETWEEN` 仍有变种
- **影响**: `payload_templates.md` 的 SQLi 部分需增加 ThinkPHP 数组注入专用 payload
- **标记**: `[实测高效]` — 5/5 项目成功

### [2026-02-20] [WordPress] [Upload] — Content-Type + 双扩展名绕过 wp_check_filetype
- **项目**: wp-blog-enterprise
- **发现**: 上传 `shell.php.jpg` 配合 `Content-Type: image/jpeg`，在 Apache + mod_php 环境可执行
- **关键细节**: 依赖 Apache 的 `AddHandler` 配置；Nginx 环境无效；需 `AllowOverride` 配合 `.htaccess`
- **影响**: `waf_bypass.md` 增加双扩展名绕过条目；标注环境依赖
- **标记**: `[实测高效]` — 条件限定 Apache 环境

---

## 分类二：失败记录

> 尝试过但失败的手法，记录失败原因避免重复浪费轮次。

### [2026-02-01] [Laravel] [SSTI] — Blade 模板注入尝试失败
- **项目**: api-gateway-v3
- **发现**: 尝试在 `{!! $userInput !!}` 处注入 Blade 语法 `@php system('id') @endphp`
- **关键细节**: Blade 编译发生在服务端渲染前，用户输入在编译后才插入，因此 Blade 指令不会被解析。只有当用户输入直接进入 `eval()` 或 `Blade::compileString()` 时才可能成功
- **影响**: `false_positive_patterns.md` 增加 "Blade raw output ≠ SSTI" 条目
- **标记**: `[实测低效]` — 0/4 项目成功，8 轮全部失败

### [2026-02-10] [ThinkPHP] [Deserialization] — ThinkPHP 6 session 反序列化需 Redis driver
- **项目**: erp-system
- **发现**: ThinkPHP 6 session 反序列化漏洞仅在使用 file driver 且 session 文件名可控时触发
- **关键细节**: 目标项目使用 Redis 作为 session driver，序列化格式为 `php_serialize`，无法注入恶意对象。花费 6 轮尝试不同 gadget chain 均失败
- **影响**: `framework_patterns.md` ThinkPHP 6 session 反序列化条件需标注 driver 前提条件
- **标记**: `[实测低效]` — 需前提条件：file driver + session 文件名可控

### [2026-03-05] [通用] [XXE] — PHP 8.0+ libxml 默认禁用外部实体
- **项目**: data-import-service
- **发现**: 尝试对 XML 解析接口注入 XXE payload，全部失败
- **关键细节**: PHP 8.0 起 `libxml_disable_entity_loader()` 已废弃，`LIBXML_NOENT` 默认不设置。除非代码显式传入 `LIBXML_NOENT` 标志，否则外部实体不解析
- **影响**: `php_specific_patterns.md` 增加 PHP 8.0+ XXE 条件说明；Scanner 遇到 PHP 8.0+ 应降低 XXE 优先级
- **标记**: `[实测低效]` — PHP 8.0+ 环境基本无效

---

## 分类三：新发现模式

> 审计中发现的新攻击面、未文档化行为、非典型漏洞模式。

### [2026-03-01] [Laravel] [Mass Assignment] — 隐式 $guarded=[] 在 pivot model 中
- **项目**: social-platform
- **发现**: Laravel pivot model 默认 `$guarded = []`，即使主 model 设置了 `$fillable`，通过 `attach()` / `sync()` 传入额外字段可写入 pivot 表任意列
- **关键细节**: 文档未明确说明 pivot model 的 mass assignment 行为；需检查所有 `belongsToMany` 关系的 `withPivot()` 声明
- **影响**: `framework_patterns.md` Laravel 部分增加 pivot model mass assignment 检查点

### [2026-03-10] [通用] [Race Condition] — PHP-FPM 多进程下的 TOCTOU 文件操作
- **项目**: file-sharing-app
- **发现**: `file_exists()` 检查后 `unlink()` 删除之间存在竞态窗口，可通过并发请求实现任意文件保留
- **关键细节**: 仅在 PHP-FPM 多 worker 模式下可利用；CLI 模式无效。利用窗口约 2-5ms，需要高并发
- **影响**: `attack_chains.md` 增加 TOCTOU race condition 链；`payload_templates.md` 增加并发脚本模板

---

## 自动反馈统计区

> 由 Report-Writer 自动维护，统计各技巧的成功率。

| 技巧 | 尝试次数 | 成功次数 | 成功率 | 标记 |
|------|----------|----------|--------|------|
| ThinkPHP where 数组注入 | 5 | 5 | 100% | [实测高效] |
| Ignition log poisoning RCE | 3 | 3 | 100% | [实测高效] |
| Apache 双扩展名上传 | 4 | 2 | 50% | — |
| Blade raw output SSTI | 4 | 0 | 0% | [实测低效] |
| PHP 8.0+ XXE | 3 | 0 | 0% | [实测低效] |
| TP6 session deserialization | 2 | 0 | 0% | [实测低效] |
