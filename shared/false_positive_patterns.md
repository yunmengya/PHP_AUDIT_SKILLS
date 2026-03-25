# 已知误报模式库（False Positive Patterns）

本文件定义各漏洞类型的已知误报模式。所有审计员在最终定论前必须比对此列表，避免将框架内置防护或安全设计误判为漏洞。

---

## 通用误报模式

### FP-001: 全局中间件已防护

**模式**: 发现 Sink 函数接受用户输入，但全局中间件已拦截恶意输入。
**检查**: 确认中间件确实覆盖了目标路由（检查 `$middleware` 和 `$middlewareGroups`，注意 `$except` 排除列表）。
**常见场景**:
- Laravel `VerifyCsrfToken` 中间件 — 但 `$except` 中排除的路由仍然脆弱
- ThinkPHP 输入过滤 `default_filter` — 但 `input()` 的 filter 参数可覆盖
- Symfony 请求验证 — 但 `$request->query->get()` 不经过验证

### FP-002: 框架自动转义

**模式**: 模板输出用户数据，但框架默认自动转义。
**检查**: 确认使用的是转义语法而非原始输出语法。
**常见场景**:
- Blade `{{ $var }}` 自动 htmlspecialchars — **非误报**: `{!! $var !!}` 不转义
- Twig `{{ var }}` 自动转义 — **非误报**: `{{ var|raw }}` 不转义
- Smarty `{$var}` 依赖配置 — 检查 `$smarty->escape_html`

### FP-003: 参数类型已约束

**模式**: 路由参数被注入，但路由定义了类型约束。
**检查**: 确认框架路由的参数约束是否在到达 Sink 前生效。
**常见场景**:
- Laravel `Route::get('/user/{id}', ...)->where('id', '[0-9]+')` — 非数字直接 404
- Symfony `@Route("/user/{id}", requirements={"id"="\d+"})` — 类型不匹配直接拒绝
- **注意**: 约束仅限路由参数，Query String 参数不受此限制

## SQL 注入误报

### FP-SQL-001: ORM 参数绑定

**模式**: 代码中出现 `DB::` 或 `$db->` 调用，但使用了参数绑定。
**误报条件**: `DB::select('SELECT * FROM users WHERE id = ?', [$id])` — 参数绑定安全
**非误报条件**: `DB::select("SELECT * FROM users WHERE id = $id")` — 字符串拼接不安全

### FP-SQL-002: Laravel Eloquent 安全方法

**安全方法（误报）**:
- `User::find($id)` — 自动参数绑定
- `User::where('id', $id)->first()` — 自动参数绑定
- `User::where('status', $request->status)->get()` — 自动参数绑定

**不安全方法（非误报）**:
- `User::whereRaw("name LIKE '%{$input}%'")` — 原始 SQL
- `DB::raw("COUNT(*) as count WHERE status = '{$status}'")` — 原始表达式
- `User::select(DB::raw($userInput))` — 用户输入进入 raw

### FP-SQL-003: 整数类型转换

**模式**: `$id = (int) $request->input('id'); DB::select("... WHERE id = $id")`
**分析**: 强制类型转换为整数，SQL 注入不可能。但仅限**直接转换后使用**，中间有其他操作则不确定。

## XSS 误报

### FP-XSS-001: Content-Type 非 HTML

**模式**: 端点返回 JSON/XML/CSV，不渲染为 HTML。
**误报条件**: `Content-Type: application/json` + `X-Content-Type-Options: nosniff`
**非误报条件**: 缺少 `nosniff` 头时浏览器可能 MIME 嗅探

### FP-XSS-002: HttpOnly Cookie

**模式**: XSS 存在但 Cookie 设置了 HttpOnly。
**分析**: HttpOnly 阻止 JS 读取 Cookie，但 XSS 仍可:
- 发起 AJAX 请求（CSRF）
- 修改页面内容（钓鱼）
- 记录键盘输入
- **结论**: 仍是漏洞，仅影响降低，不是误报

### FP-XSS-003: CSP 阻止执行

**模式**: XSS Payload 注入成功但 CSP 阻止执行。
**分析**: 严格 CSP（无 `unsafe-inline`）可阻止大多数 XSS，但:
- `<base>` 标签劫持可绕过
- CSS 注入不受 `script-src` 限制
- 数据外泄通过 `<img src=attacker>` 不受限
- **结论**: 降级为 Medium，非完全误报

## RCE 误报

### FP-RCE-001: disable_functions 生效

**模式**: `system()`, `exec()` 等在 `disable_functions` 中。
**检查**: 通过 `phpinfo()` 或 `ini_get('disable_functions')` 确认。
**注意**: `disable_functions` 可被某些方式绕过（LD_PRELOAD, FFI, PHP Bug）

### FP-RCE-002: open_basedir 限制

**模式**: 文件操作 Sink 存在但 `open_basedir` 限制了访问范围。
**检查**: 确认 `open_basedir` 设置且包含目标路径不在允许范围内。
**注意**: `open_basedir` 有已知绕过方式（chdir + ini_set, glob://）

### FP-RCE-003: eval 内容来自安全源

**模式**: `eval()` 调用存在，但输入完全来自代码内部/配置文件。
**误报条件**: `eval('return ' . $config['formula'] . ';')` 其中 `$config` 从受保护配置文件读取
**非误报条件**: 配置文件可被用户修改（如通过管理面板）

## SSRF 误报

### FP-SSRF-001: URL 白名单生效

**模式**: URL 用户可控但有白名单校验。
**误报条件**: 严格域名白名单 + 无重定向跟随
**非误报条件**: 白名单使用 `strpos` 而非严格匹配（`evil.com.trusted.com` 绕过）

### FP-SSRF-002: 仅限 HTTP(S) 协议

**模式**: cURL 设置了 `CURLOPT_PROTOCOLS` 仅允许 HTTP/HTTPS。
**分析**: 阻止了 `file://`, `gopher://` 等协议，但 HTTP SSRF 仍可达内网。

## 越权误报

### FP-AUTHZ-001: 公开设计的端点

**模式**: 无鉴权端点返回数据。
**误报条件**: 端点设计为公开（如商品列表、公开用户资料）
**检查**: 返回的字段是否包含敏感信息（密码哈希、私有邮箱等）

### FP-AUTHZ-002: IDOR 但无敏感数据

**模式**: `GET /api/posts/123` 可访问其他人的帖子。
**误报条件**: 帖子本身是公开的，`is_public=true`
**非误报条件**: 帖子包含私有内容或可执行修改操作

## 配置误报

### FP-CONFIG-001: .env.example 而非 .env

**模式**: `/.env` 返回内容。
**检查**: 是否返回的是 `.env.example`（含占位符值如 `DB_PASSWORD=secret`）
**判断**: 占位符值（`secret`, `password`, `your-key-here`）= 非泄露; 具体值 = 泄露

### FP-CONFIG-002: phpinfo 在受保护路径

**模式**: phpinfo.php 存在。
**误报条件**: 在认证保护的管理路径下且需要管理员权限
**非误报条件**: 公开可访问

## 密码学误报

### FP-CRYPTO-001: MD5 非安全用途

**模式**: 代码中使用 `md5()`。
**误报条件**: 用于缓存键 `md5($url)`、文件名 `md5($filename)`、ETag 生成
**非误报条件**: 用于密码哈希 `md5($password)`、Token 生成、签名验证

### FP-CRYPTO-002: rand() 非安全用途

**模式**: 代码中使用 `rand()` 或 `mt_rand()`。
**误报条件**: 用于分页随机化、UI 展示随机、测试数据生成
**非误报条件**: 用于 Token/验证码/密码重置链接/Session ID 生成

## Type Juggling 误报模式

### FP-JUGGLE-001: `==` 用于非安全场景（字符串格式检查）

**模式**: 代码中使用 `==` 进行比较，但比较目的不涉及安全决策。
**代码示例**:
```php
// 检查用户输入的日期格式
if ($dateFormat == 'Y-m-d') {
    $formatter = new DateFormatter($dateFormat);
}

// 检查分页参数
if ($request->input('sort') == 'asc') {
    $query->orderBy('created_at', 'asc');
}
```
**为何是误报**: `==` 的 type juggling 只在安全相关比较（如密码验证、Token 比对、身份校验）中构成威胁。上述场景即使发生类型混淆，也不会导致越权或认证绕过。
**如何区分**: 确认比较结果是否影响 authentication/authorization 逻辑。若仅影响展示/格式/排序等非安全行为 → 误报。

### FP-JUGGLE-002: `in_array` 用于白名单检查（strict=true 隐式保障）

**模式**: `in_array` 检查用户输入是否在允许列表内，未显式传入第三个参数 `true`。
**代码示例**:
```php
$allowedStatuses = ['active', 'inactive', 'pending'];
if (in_array($request->input('status'), $allowedStatuses)) {
    $user->status = $request->input('status');
}

// 白名单值全部为字符串且输入也是字符串
$allowedColumns = ['name', 'email', 'created_at'];
if (in_array($sortBy, $allowedColumns)) {
    $query->orderBy($sortBy);
}
```
**为何是误报**: 当白名单值全部为**同类型字符串**，且输入也是字符串（如来自 `$_GET`、`$request->input()`），松散比较 `in_array` 不会产生 type juggling 问题。字符串之间的 `==` 比较与 `===` 行为一致。
**如何区分**: 检查白名单数组元素类型是否一致。若白名单包含 `0`、`false`、`null` 等混合类型 → 非误报，存在绕过风险。

### FP-JUGGLE-003: `==` 用于同类型变量比较（int==int）

**模式**: 两侧变量均为相同类型（如 int==int），type juggling 不会改变比较结果。
**代码示例**:
```php
// $userId 来自数据库（int），$routeId 经过 (int) 转换
$userId = Auth::user()->id;       // int from DB
$routeId = (int) $request->route('id');  // explicitly cast to int
if ($userId == $routeId) {
    // 授权通过
}

// 两个整型常量比较
if ($retryCount == 3) {
    throw new TooManyAttemptsException();
}
```
**为何是误报**: 同类型变量之间 `==` 与 `===` 语义一致，不存在 type juggling 风险。`int == int` 不会产生 `"0e12345" == "0"` 这类经典绕过。
**如何区分**: 确认两侧变量的类型来源。若一侧来自用户输入且未做类型转换 → 非误报。若两侧均为已知同类型 → 低风险/误报。

---

## JWT 误报模式

### FP-JWT-001: JWT 用于非敏感场景

**模式**: JWT 用于存储用户偏好设置等非安全相关数据，signature 验证不严格。
**代码示例**:
```php
// JWT 存储用户界面偏好（语言、主题、布局）
$payload = JWT::decode($token, new Key($key, 'HS256'));
$theme = $payload->theme ?? 'default';
$locale = $payload->locale ?? 'en';

// JWT 用于追踪匿名用户行为（无敏感数据）
$trackingToken = JWT::encode(['session_start' => time(), 'ab_group' => 'B'], $key, 'HS256');
```
**为何是误报**: JWT 签名弱点只在 Token 携带身份认证/授权信息时构成安全威胁。偏好设置即使被篡改，也不影响系统安全。
**如何区分**: 检查 JWT payload 中是否包含 `user_id`、`role`、`permissions` 等身份/权限字段。若仅包含非敏感配置数据 → 低严重度，可降级。

### FP-JWT-002: HS256 弱密钥但过期时间极短

**模式**: JWT 使用 HS256 + 较弱密钥，但 Token 过期时间设置很短（如几分钟）。
**代码示例**:
```php
$payload = [
    'user_id' => $user->id,
    'exp' => time() + 300,  // 5分钟过期
    'iat' => time(),
];
$token = JWT::encode($payload, config('app.key'), 'HS256');

// 验证时严格检查过期
try {
    $decoded = JWT::decode($token, new Key(config('app.key'), 'HS256'));
} catch (ExpiredException $e) {
    return response()->json(['error' => 'Token expired'], 401);
}
```
**为何是误报（降级）**: 即使攻击者能暴力破解 HS256 密钥，短过期时间大幅缩小攻击窗口。破解耗时通常远超 Token 有效期。
**如何区分**: 检查 `exp` claim 的时间窗口。若 > 1小时 → 不宜降级。若 <= 5分钟 + 有 refresh 机制 → 可降级为 Low。仍建议使用强密钥。

### FP-JWT-003: JWT 结合服务端 Session 验证

**模式**: JWT 用于传递身份信息，但服务端同时维护 Session 状态做二次校验。
**代码示例**:
```php
// JWT 解码后，还需与服务端 Session 比对
$decoded = JWT::decode($token, new Key($secretKey, 'HS256'));
$jwtUserId = $decoded->sub;

// 服务端 Session 二次验证
$sessionUserId = $_SESSION['authenticated_user_id'] ?? null;
if ($jwtUserId !== $sessionUserId) {
    http_response_code(401);
    die('Session mismatch');
}

// 还检查 Token 是否在 blacklist 中（logout 后 revoke）
if (TokenBlacklist::isRevoked($decoded->jti)) {
    http_response_code(401);
    die('Token revoked');
}
```
**为何是误报（降级）**: 即使 JWT 被伪造或篡改，服务端 Session 验证提供了额外防线。攻击者需要同时控制 JWT 和 Session 才能绕过。
**如何区分**: 确认服务端 Session 校验是**强制执行**而非可选。若 Session 校验可被跳过（如仅在某些路由生效）→ 非误报。

---

## CORS 误报模式

### FP-CORS-001: `Access-Control-Allow-Origin: *` 但无 `Allow-Credentials`

**模式**: CORS 配置为 `*` 但未设置 `Access-Control-Allow-Credentials: true`。
**代码示例**:
```php
// 公开 API，不需要 Cookie 认证
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, OPTIONS');
// 注意：没有设置 Access-Control-Allow-Credentials

// Laravel CORS 配置
'allowed_origins' => ['*'],
'supports_credentials' => false,  // 关键：未启用 credentials
```
**为何是误报**: 当 `Allow-Origin: *` 时，浏览器**禁止**跨域请求携带 Cookie（即使前端设置了 `withCredentials: true`）。攻击者无法通过 CORS 窃取用户认证态下的数据。
**如何区分**: 检查是否同时存在 `Access-Control-Allow-Credentials: true`。若存在 → **严重漏洞**（但注意浏览器不允许 `*` 和 `Credentials: true` 同时使用，某些服务端框架会动态替换 `*` 为请求 Origin）。若不存在 → 低严重度。

### FP-CORS-002: CORS 配置在内部/开发环境

**模式**: 宽松 CORS 配置出现在 dev/staging 环境配置中。
**代码示例**:
```php
// config/cors.php
if (app()->environment('local', 'development', 'testing')) {
    $allowedOrigins = ['*'];  // 开发环境允许所有
} else {
    $allowedOrigins = ['https://app.example.com'];
}

// .env.development
CORS_ALLOWED_ORIGINS=*
```
**为何是误报**: 开发/测试环境的 CORS 配置不影响生产安全。
**如何区分**: 确认该配置是否仅在非生产环境生效。若生产环境 `.env` 或部署配置也使用 `*` → 非误报。记录发现但**不告警**，建议在 review 中注明。

### FP-CORS-003: CORS 限制为已知子域名

**模式**: CORS 配置允许来自同组织子域名的请求。
**代码示例**:
```php
$allowedOrigins = [
    'https://app.example.com',
    'https://admin.example.com',
    'https://api.example.com',
];

// 或使用正则匹配子域名
$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
if (preg_match('/^https:\/\/[\w-]+\.example\.com$/', $origin)) {
    header("Access-Control-Allow-Origin: $origin");
    header('Access-Control-Allow-Credentials: true');
}
```
**为何是误报**: 限制为已知受控子域名属于正常安全配置，不构成 CORS 漏洞。
**如何区分**: 检查正则匹配是否严格。`/\.example\.com$/` 可被 `evil-example.com` 绕过 → **非误报**。正确写法需锚定 `://` 或使用精确列表。

---

## php://filter 误报模式

### FP-FILTER-001: `include` 参数来自硬编码白名单

**模式**: 动态 `include` 存在，但文件名来自固定白名单而非用户输入。
**代码示例**:
```php
$allowedPages = [
    'home' => 'pages/home.php',
    'about' => 'pages/about.php',
    'contact' => 'pages/contact.php',
];

$page = $_GET['page'] ?? 'home';
if (isset($allowedPages[$page])) {
    include $allowedPages[$page];  // 安全：只 include 白名单中的文件
} else {
    include 'pages/404.php';
}
```
**为何是误报**: 用户输入仅作为 key 查询白名单映射，实际 include 的文件路径是硬编码的。攻击者无法通过 `php://filter` 或路径遍历控制 include 目标。
**如何区分**: 确认白名单是否**真正硬编码**。若白名单从数据库/配置文件动态加载且可被用户修改 → 非误报。若白名单值直接拼接了用户输入 → 非误报。

### FP-FILTER-002: `include` 在 `switch-case` 中仅接受预定义值

**模式**: `include` 路径通过 `switch-case` 控制，只有预定义的 case 会触发 include。
**代码示例**:
```php
$module = $_GET['module'] ?? 'dashboard';

switch ($module) {
    case 'dashboard':
        include 'modules/dashboard.php';
        break;
    case 'profile':
        include 'modules/profile.php';
        break;
    case 'settings':
        include 'modules/settings.php';
        break;
    default:
        include 'modules/dashboard.php';  // 默认安全回退
        break;
}
```
**为何是误报**: `switch-case` 的每个分支都使用硬编码路径，用户输入无法影响实际 include 的文件。即使传入 `php://filter/convert.base64-encode/resource=index`，也只会命中 `default` 分支。
**如何区分**: 确认 `switch` 中没有类似 `case $userInput:` 的动态 case，且没有 fall-through 到危险分支。若存在 `include "modules/{$module}.php"` 在 default 分支 → **非误报变成真漏洞**。

---

## Open Redirect 误报模式

### FP-REDIR-001: 重定向目标经过域名白名单检查

**模式**: 用户可控的重定向 URL 经过了严格的域名白名单校验。
**代码示例**:
```php
$redirectUrl = $_GET['redirect'] ?? '/';

$allowedHosts = ['example.com', 'app.example.com', 'login.example.com'];
$parsedUrl = parse_url($redirectUrl);

if (isset($parsedUrl['host']) && !in_array($parsedUrl['host'], $allowedHosts)) {
    $redirectUrl = '/';  // 不在白名单则重定向到首页
}

header("Location: $redirectUrl");
exit;
```
**为何是误报**: 域名白名单严格限制了重定向目标，攻击者无法将用户导向恶意站点。
**如何区分**:
- 检查 `parse_url` 是否能被绕过：`http://evil.com\@example.com`、`//evil.com` 等边界情况
- 检查白名单匹配方式：`strpos($url, 'example.com')` 可被 `example.com.evil.com` 绕过 → **非误报**
- 确认 `parse_url` 的结果是否完整验证了 scheme + host → 若仅检查 host 而忽略 `javascript:` scheme → **非误报**

### FP-REDIR-002: 仅重定向到内部路径（`/` 前缀，无 `//`）

**模式**: 重定向仅接受以 `/` 开头的相对路径，且排除了 `//` 协议相对 URL。
**代码示例**:
```php
$returnPath = $_GET['return'] ?? '/dashboard';

// 严格检查：必须以单个 / 开头，不允许 // 或 /\
if (preg_match('#^/[^/\\\\]#', $returnPath) || $returnPath === '/') {
    header("Location: $returnPath");
} else {
    header("Location: /dashboard");
}
exit;

// 另一种安全实现
function safeRedirect(string $path): void {
    // 仅允许内部路径
    $path = '/' . ltrim($path, '/');
    if (str_starts_with($path, '//') || str_contains($path, '://')) {
        $path = '/';
    }
    header("Location: $path");
    exit;
}
```
**为何是误报**: 仅允许 `/path` 格式的相对路径，浏览器会将其解析为当前域名下的路径，无法跳转到外部域。排除 `//` 防止了协议相对 URL（如 `//evil.com`）。
**如何区分**:
- 检查是否过滤了 `//`：若未过滤 → `//evil.com/path` 可导致 Open Redirect → **非误报**
- 检查是否过滤了 `/\`：某些浏览器将 `/\evil.com` 解析为外部域 → **非误报**
- 检查是否存在 CRLF 注入：`/path%0d%0aLocation:%20http://evil.com` → 需额外防护

---

## 使用指南

审计员在将漏洞标记为 `confirmed` 前，逐项比对以下检查:

1. 遍历本文件中对应漏洞类型的误报模式
2. 检查是否匹配任何误报条件
3. 若匹配:
   - 确认"非误报条件"不成立
   - 若仍是误报 → 降级或丢弃
   - 若为边界情况 → 标注 `[需验证]` 并说明
4. 在报告中注明已排除的误报模式

## 更新规则

- 新发现的误报模式经质检员确认后追加到此文件
- 每个模式须包含: 模式名、误报条件、非误报条件
- 框架版本更新可能使某些误报模式失效，需定期复核
