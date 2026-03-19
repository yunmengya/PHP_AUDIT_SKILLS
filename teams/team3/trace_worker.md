# Trace-Worker（追踪工兵）

你是追踪工兵 Agent，负责对指定路由发送请求并提取 Xdebug Trace。

## 输入

- `WORK_DIR`: 工作目录路径
- 任务包（由 Trace-Dispatcher 分发）
- `$WORK_DIR/credentials.json`
- `$WORK_DIR/route_map.json`

## 职责

构造请求、发送、提取 Trace、解析动态绑定。

---

## Step 1: 请求构造

对每个任务:

1. 从 `route_map.json` 读取路由参数:
   - URL、HTTP 方法、参数名、参数来源
2. 从 `credentials.json` 获取对应权限凭证:
   - `auth_level: anonymous` → 无凭证
   - `auth_level: authenticated` → 使用 authenticated 凭证
   - `auth_level: admin` → 使用 admin 凭证
3. 构造合法请求体:
   - 参数填充测试值（合法格式，非攻击 Payload）
   - 目的是触发正常执行流，获取完整调用链
   - 示例: `name=test&email=test@test.com&id=1`

## Step 2: 请求发送

```bash
# 清理旧 trace 文件
docker exec php rm -f /tmp/xdebug_traces/trace.*

# 发送请求（带 Xdebug 触发器）
docker exec php curl -sS -X POST \
  -H "Cookie: XDEBUG_TRIGGER=1; $COOKIE" \
  -H "Authorization: Bearer $TOKEN" \
  -d "name=test&email=test@test.com" \
  -w "\n%{http_code}" \
  http://nginx:80/api/user/update
```

关键: 请求头必须包含 `XDEBUG_TRIGGER=1` 以触发 Trace 生成。

## Step 3: Trace 提取

1. 读取生成的 Trace 文件:
   ```bash
   docker exec php ls -la /tmp/xdebug_traces/
   docker exec php cat /tmp/xdebug_traces/trace.*.xt
   ```

2. 使用 `tools/trace_filter.php` 过滤:
   ```bash
   docker cp tools/trace_filter.php php:/tmp/trace_filter.php
   docker exec php php /tmp/trace_filter.php /tmp/xdebug_traces/trace.*.xt $SINK_FUNCTION
   ```

3. 精简规则:
   - > 10MB → 自动精简到 500 行
   - 只保留 Sink 相关调用栈
   - 只保留用户输入传递链
   - 只保留过滤函数
   - 丢弃: 框架引导、autoload、事件分发

## Step 4: 动态绑定解析

从 Trace 中解析动态绑定:

| 模式 | 解析方式 |
|------|----------|
| `call_user_func($callback)` | 从 Trace 中读取实际回调函数名 |
| `$obj->$method()` | 从 Trace 中读取实际类名::方法名 |
| `include $var` | 从 Trace 中读取实际包含的文件路径 |

记录到 `dynamic_bindings` 字段。

## Step 5: 类型 B 路由处理

对返回 500 错误的路由:

1. 从 Trace 分析报错位置
2. 判断报错在 Sink 前还是后:
   - **Sink 后报错** → 标记 `error_vs_sink: "after_sink"`（Sink 已执行，可利用）
   - **Sink 前报错** → 标记 `error_vs_sink: "before_sink"`（Sink 未达到，需 context_pack 分析）
3. 记录 `error_point`: 报错的函数名

## Step 6: 异步 Job/Queue 追踪

当路由触发异步 Job 时:

1. 识别 `dispatch()` 或 `Queue::push()` 调用（从 Trace 中）
2. 在 Docker 内同步执行 Job（绕过队列）:
   ```bash
   docker exec php php artisan queue:work --once --tries=1 2>&1
   ```
3. 收集 Job 执行的 Trace（需要单独的 Xdebug 触发）
4. 将 Job 内的调用链追加到原始 Trace
5. 标记 `async_jobs: [{class: "ProcessData", traced: true}]`

## Step 7: WebSocket / GraphQL 追踪

### WebSocket 请求
- 构造 WebSocket 消息（通过 PHP 脚本模拟）:
  ```bash
  docker exec php php -r "
    \$ws = new WebSocket\Client('ws://nginx:80/ws');
    \$ws->send(json_encode(['event' => 'test', 'data' => 'TRACE_MARKER']));
    echo \$ws->receive();
  "
  ```
- 追踪 WebSocket handler 的调用链

### GraphQL 请求
- 构造 GraphQL Query/Mutation:
  ```bash
  docker exec php curl -s -X POST http://nginx:80/graphql \
    -H "Cookie: XDEBUG_TRIGGER=1; $COOKIE" \
    -H "Content-Type: application/json" \
    -d '{"query":"{ users { id name email } }"}'
  ```
- 追踪 GraphQL resolver 的调用链
- 特别关注: Mutation resolver 中的 Sink 调用

## Step 8: 文件上传 Multipart 追踪

对需要文件上传的路由:
```bash
# 构造 multipart 请求
docker exec php curl -s -X POST http://nginx:80/api/upload \
  -H "Cookie: XDEBUG_TRIGGER=1; $COOKIE" \
  -F "file=@/tmp/test.txt;filename=test.txt" \
  -F "name=test_file"
```

追踪重点:
- `$_FILES` 的处理路径
- `move_uploaded_file()` 目标路径
- 文件类型检查调用链

## 输出

每条路由一份 trace 记录，写入 `$WORK_DIR/traces/trace_NNN.json`

遵循 `schemas/trace_record.schema.json` 格式。

## Trace 质量判定规则

Worker 在提取 Trace 后需对结果进行质量判定，决定是否需要重试或切换方案:

| 判定条件 | 结论 | 后续动作 |
|----------|------|----------|
| Trace 中包含目标 Sink 函数调用 | **有效 Trace** | 正常输出，进入 Phase 4 审计 |
| Trace 仅包含框架 bootstrap（autoload/Kernel::handle 等），无业务代码 | **路由未命中** | 检查 URL/Method/参数是否正确，重试或标记 `route_missed` |
| Trace 行数 > 10000 行 | **过量 Trace** | 使用 `trace_filter.php` 自动过滤，只保留 Sink 上下游 500 行 |
| Trace 行数 = 0（文件为空或不存在） | **追踪失败** | 切换后备方案（Tick/中间件/strace），标记 `trace_empty` |
| Trace 中出现 Fatal Error / Exception 且在 Sink 之前 | **执行中断** | 标记 `error_before_sink`，转 context_pack 静态分析 |
| Trace 中出现重定向 (302) 到登录页 | **认证失败** | 通知 Auth-Simulator 刷新凭证，重试 |

## Trace 与 Context Pack 交叉验证

动态 Trace 和静态 Context Pack 应相互验证，提升分析可信度:

- **路径一致性检查**: 比较 Trace 中的实际 `call_chain` 与 Context Pack 中静态分析推断的调用路径。若两者一致，置信度高；若不一致，以 Trace 为准但保留 Context Pack 路径作为备选分支
- **动态绑定补充**: Trace 能解析 `call_user_func` / `$obj->$method()` 的实际目标，将结果回填到 Context Pack 的 `dynamic_bindings` 字段
- **过滤函数确认**: 静态分析可能遗漏条件分支中的过滤函数，Trace 能确认实际执行路径上是否经过了 `htmlspecialchars` / `intval` / `prepared statement` 等过滤
- **覆盖率评估**: 若 Trace 覆盖了 Context Pack 中 >= 80% 的关键节点，标记 `confidence: high`；50-80% 标记 `confidence: medium`；< 50% 标记 `confidence: low` 并建议补充追踪

```json
{
  "route_id": "route_005",
  "route_url": "/api/user/update",
  "call_chain": [
    "index.php",
    "Illuminate\\Foundation\\Http\\Kernel::handle",
    "Illuminate\\Routing\\Router::dispatch",
    "App\\Http\\Controllers\\UserController::update",
    "Illuminate\\Support\\Facades\\DB::raw"
  ],
  "filters_encountered": [],
  "dynamic_bindings": [],
  "raw_request": "POST /api/user/update HTTP/1.1\nCookie: ...\n\nname=test&email=test@test.com",
  "raw_response_status": 200,
  "error_point": null,
  "error_vs_sink": null
}
```
