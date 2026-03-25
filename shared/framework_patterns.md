# 框架安全模式速查

各框架的安全/不安全用法速查表，供所有 Agent 参考。

---

## Laravel

### 安全用法 ✓
| 场景 | 安全写法 |
|------|---------|
| SQL 查询 | `DB::table('users')->where('id', $id)->first()` |
| 模板输出 | `{{ $variable }}` (自动 htmlspecialchars) |
| 文件上传 | `$request->file('photo')->store('photos')` |
| 密码哈希 | `Hash::make($password)` |
| CSRF 保护 | `@csrf` 在表单中 |
| 授权 | `$this->authorize('update', $post)` / Gate/Policy |
| 加密 | `Crypt::encryptString($data)` |
| Token 作用域 | `$token = $user->createToken('name', ['read']);` (Sanctum 限定 scope) |
| Queue Job | 使用 `ShouldBeEncrypted` 接口保护序列化 payload |

### 不安全用法 ✗
| 场景 | 不安全写法 | 漏洞类型 |
|------|-----------|---------|
| SQL 注入 | `DB::raw("WHERE id=$input")` | SQLi |
| SQL 注入 | `->whereRaw("status = '$input'")` | SQLi |
| XSS | `{!! $userInput !!}` | XSS |
| 批量赋值 | `$guarded = []` + `Model::create($request->all())` | Mass Assignment |
| 反序列化 | `unserialize($cookie)` | RCE |
| 命令注入 | `exec("convert $filename")` | RCE |
| SSRF | `file_get_contents($userUrl)` | SSRF |
| 弱比较 | `if ($token == $stored)` | AuthZ Bypass |
| Token 无过期 | `'expiration' => null` in sanctum config | Token 滥用 |
| Debugbar 泄露 | 生产环境启用 `barryvdh/laravel-debugbar` | 信息泄露 |

### 常见陷阱
- `APP_DEBUG=true` 在生产环境 → 堆栈跟踪泄露
- `APP_KEY` 泄露 → Cookie 伪造 / 反序列化 RCE
- Telescope/Horizon 未设鉴权 → 信息泄露
- `VerifyCsrfToken::$except` 过多 → CSRF

### Telescope / Horizon 未鉴权访问检测

Telescope 和 Horizon 默认在 `local` 环境可访问，但很多开发者部署到生产时忘记配置 Gate：

```php
// 危险: TelescopeServiceProvider 中未限制访问
Gate::define('viewTelescope', function ($user) {
    return true;  // 任何已登录用户均可访问
});
```

**检测要点**:
- 检查 `TelescopeServiceProvider::gate()` 是否存在且限制了邮箱/角色
- 检查 `HorizonServiceProvider::gate()` 同理
- 搜索路由 `/telescope`、`/horizon` 是否可公开访问（无中间件）
- 如果 `APP_ENV=production` 但 Telescope/Horizon 注册在 `AppServiceProvider` 而非仅 `local` → 高危

```php
// 安全: 限制到特定管理员邮箱
Gate::define('viewTelescope', function ($user) {
    return in_array($user->email, [
        'admin@example.com',
    ]);
});
```

### Sanctum / Passport Token 安全审计

**Token 过期**:
- Sanctum 默认 Token **永不过期**，必须在 `config/sanctum.php` 设置 `'expiration' => 60 * 24`
- Passport 的 `tokensExpireIn()` / `refreshTokensExpireIn()` 需在 `AuthServiceProvider` 中显式配置
- 搜索 `createToken(` 调用，确认是否传入了 scope 参数

**Token Scope 审计**:
```php
// 危险: 无 scope 限制，获得全部权限
$token = $user->createToken('api-token');

// 安全: 最小权限原则
$token = $user->createToken('api-token', ['read', 'orders:view']);
```

**Token 吊销**:
- 检查是否有 Token 吊销逻辑 (`$user->tokens()->delete()`, `$token->revoke()`)
- 用户修改密码后是否清除旧 Token
- 搜索 `personalAccessTokens` 是否有未清理的过期 Token

### Queue Worker 反序列化风险 (SerializesModels)

Laravel Queue Job 使用 `SerializesModels` trait 时，对象会被序列化存入 Redis/DB：

```php
// 潜在风险: Job payload 中包含序列化的 Eloquent Model
class ProcessOrder implements ShouldQueue
{
    use SerializesModels;
    public $order; // 序列化存储 → 若 Redis 被攻击者控制可注入恶意 payload
}
```

**检测要点**:
- Redis 是否暴露在公网且无密码 (`redis://0.0.0.0:6379`)
- Queue driver 为 `database` 时，`jobs` 表中的 `payload` 字段是否可被篡改
- 搜索 `unserialize(` 与 `Queue::` 的组合使用
- 建议使用 `ShouldBeEncrypted` 接口加密 Job payload (Laravel 8+)

### Livewire 组件注入

Livewire 组件的公有属性可被前端篡改：

```php
// 危险: 公有属性直接绑定到敏感字段
class EditProfile extends Component
{
    public $userId;   // 攻击者可通过 wire:model 篡改 userId
    public $role;     // 攻击者可提升角色

    public function save()
    {
        User::find($this->userId)->update(['role' => $this->role]);
    }
}
```

**安全做法**: 使用 `#[Locked]` 属性 (Livewire v3) 或在 `save()` 中强制使用 `auth()->id()`

### Laravel Debugbar 生产环境泄露

`barryvdh/laravel-debugbar` 在生产环境启用会泄露：
- 所有 SQL 查询及绑定参数（含密码等敏感数据）
- Session 内容、Request 参数
- 环境变量 (可能包含 API Key)
- 路由列表和中间件配置

**检测**: 搜索 `composer.json` 中 `require`（非 `require-dev`）是否包含 `debugbar`；检查 `DEBUGBAR_ENABLED` 环境变量

---

## ThinkPHP

### 安全用法 ✓
| 场景 | 安全写法 |
|------|---------|
| SQL 查询 | `Db::name('user')->where('id', $id)->find()` |
| 参数获取 | `input('get.id/d')` (带类型过滤) |
| 模板输出 | `{$var|htmlspecialchars}` |
| 路由定义 | 显式注册路由，关闭自动路由 |

### 不安全用法 ✗
| 场景 | 不安全写法 | 漏洞类型 |
|------|-----------|---------|
| SQL 注入 | `Db::query("SELECT * FROM user WHERE id=$id")` | SQLi |
| SQL 注入 | `->where('id', 'exp', $input)` | SQLi (exp 表达式) |
| 变量覆盖 | `extract($_GET)` | 变量覆盖 |
| RCE | `think\App::invokeMethod()` 路由控制 | RCE |
| 路由暴露 | `'url_route_must' => false` (允许自动路由) | 未授权访问 |

### 历史高危漏洞

- ThinkPHP 5.0.x RCE (invokeFunction)
- ThinkPHP 5.1.x SQL 注入 (where/exp)
- ThinkPHP 6.x Session 反序列化

### 版本特定 RCE 检测指纹

#### ThinkPHP 5.0.x — invokeFunction RCE

漏洞原理: 控制器/方法未过滤，可直接调用任意函数。

```
# 攻击 payload 指纹（在日志或 WAF 中检测）:
/index.php?s=/index/\think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=whoami
/index.php?s=index/think\app/invokefunction&function=call_user_func_array
```

**代码检测**: 搜索 `thinkphp` 版本号 `5.0.0` ~ `5.0.23`，检查 `App::invokeFunction` 是否被 patch。

#### ThinkPHP 5.1.x — where('exp') SQL 注入

```php
// 危险: exp 表达式允许原始 SQL
$result = Db::name('user')->where('id', 'exp', $userInput)->find();
// 攻击者传入: "= 1 UNION SELECT password FROM admin--"
```

**检测**: 全局搜索 `'exp'` 作为 `where()` 第二参数；检查 ThinkPHP 版本是否 < 5.1.23。

#### ThinkPHP 6.x — Session 反序列化

当 Session 驱动为文件存储且 Session ID 可控时，攻击者可写入恶意序列化数据：

**检测要点**:
- `session.type` 配置是否为 `file`
- Session ID 是否从用户输入获取且未校验格式
- 搜索 `session(` 函数调用，检查是否存储了用户可控对象

### 路由安全: 自动路由模式暴露

ThinkPHP 的自动路由 (auto-route) 模式会将所有 Controller 的 public 方法自动映射为 URL：

```php
// config/route.php 或 config/app.php
'url_route_must' => false,  // 危险: 允许通过 URL 直接访问任意控制器方法
```

**风险**:
- 内部管理方法（如 `AdminController::resetPassword()`）可被直接访问
- 测试方法、调试方法意外暴露
- 绕过中间件和路由级权限检查

**检测**: 搜索 `url_route_must` 配置项；如果为 `false` 或未设置，标记为高危。

**安全做法**: 设置 `'url_route_must' => true`，强制所有访问通过显式定义的路由。

---

## Yii2

### 安全用法 ✓
| 场景 | 安全写法 |
|------|---------|
| SQL 查询 | `User::find()->where(['id' => $id])->one()` |
| XSS 防护 | `Html::encode($text)` |
| CSRF | `\yii\filters\Csrf` 行为 |
| RBAC | `Yii::$app->user->can('updatePost')` |

### 不安全用法 ✗
| 场景 | 不安全写法 | 漏洞类型 |
|------|-----------|---------|
| SQL 注入 | `Model::findBySql("SELECT * WHERE id=$id")` | SQLi |
| SQL 注入 | `->orderBy($userInput)` | SQLi |
| XSS | `<?= $userInput ?>` 无 encode | XSS |

---

## WordPress

### 安全用法 ✓
| 场景 | 安全写法 |
|------|---------|
| SQL 查询 | `$wpdb->prepare("SELECT * FROM %s WHERE id = %d", $table, $id)` |
| 输出转义 | `esc_html($text)`, `esc_attr($attr)`, `esc_url($url)` |
| Nonce 验证 | `wp_verify_nonce($_POST['_wpnonce'], 'action')` |
| 权限检查 | `current_user_can('manage_options')` |
| 数据清理 | `sanitize_text_field($input)`, `absint($id)` |
| REST API 权限 | `'permission_callback' => function() { return current_user_can('edit_posts'); }` |
| 安全数据库操作 | `$wpdb->insert($table, $data, $format)` / `$wpdb->update(...)` |

### 不安全用法 ✗
| 场景 | 不安全写法 | 漏洞类型 |
|------|-----------|---------|
| SQL 注入 | `$wpdb->query("SELECT * WHERE id=$input")` | SQLi |
| SQL 注入 | `$wpdb->query("DELETE FROM $table WHERE id=" . $_GET['id'])` | SQLi |
| XSS | `echo $_GET['param']` | XSS |
| 权限误用 | `if (is_admin()) { /* 敏感操作 */ }` | 权限绕过 |
| CSRF | 缺少 `wp_verify_nonce()` | CSRF |
| 文件上传 | 未检查 MIME + 扩展名 | 文件上传 |
| REST 无权限 | `register_rest_route` 无 `permission_callback` | 未授权访问 |
| Hook 注入 | `do_action($_GET['hook_name'])` | 任意代码执行 |

### 关键函数
- `is_admin()` — 仅检查是否在后台页面，**不是**权限检查
- `current_user_can()` — **真正的**权限检查
- `wp_nonce_field()` / `wp_verify_nonce()` — CSRF 保护
- `esc_sql()` — 仅转义引号，不如 `$wpdb->prepare()` 安全

### REST API permission_callback 缺失检测

WordPress 5.5+ 要求 `register_rest_route` 必须包含 `permission_callback`，否则会触发 `_doing_it_wrong` 警告。但旧插件/主题可能缺失：

```php
// 危险: 任何人（包括未登录用户）均可访问
register_rest_route('myplugin/v1', '/users', [
    'methods'  => 'GET',
    'callback' => 'get_all_users',
    // 缺少 permission_callback → 默认允许所有人访问
]);

// 危险: 显式设为公开但开发者可能未意识到
register_rest_route('myplugin/v1', '/delete-user', [
    'methods'  => 'DELETE',
    'callback' => 'delete_user_handler',
    'permission_callback' => '__return_true',  // 危险写法！破坏性操作无权限校验
]);
```

**检测**: 全局搜索 `register_rest_route`，逐一检查是否包含 `permission_callback`，以及 callback 内容是否为 `__return_true`（对敏感操作不安全）。

### Action / Filter Hook 注入

WordPress 的 Hook 系统（`do_action` / `apply_filters`）若 hook 名称或参数来自用户输入，可能导致意外行为：

```php
// 危险: hook 名称来自用户输入
$action = $_GET['action_type'];
do_action("process_{$action}");
// 攻击者传入 action_type=admin_init → 触发管理员初始化流程

// 危险: 用户输入直接传入 hook 参数
do_action('user_profile_update', $_POST['data']);
// 所有挂载该 hook 的回调都会收到未过滤的数据
```

**检测要点**:
- 搜索 `do_action(` 和 `apply_filters(`，检查参数是否包含 `$_GET`、`$_POST`、`$_REQUEST`
- 检查 hook 名称是否由变量拼接且变量来源为用户输入
- 特别注意 `wp_ajax_nopriv_` 前缀的 hook（对未登录用户开放）

### wpdb 用法审计: query() 直拼 vs prepare()

`$wpdb->query()` 接受原始 SQL，是 WordPress 中 SQL 注入的首要来源：

```php
// 危险: 直接字符串拼接
$wpdb->query("UPDATE wp_users SET status='active' WHERE id=" . $_GET['uid']);
$wpdb->query("SELECT * FROM wp_posts WHERE post_title LIKE '%" . $_POST['search'] . "%'");

// 安全: 使用 prepare() 参数绑定
$wpdb->query($wpdb->prepare(
    "UPDATE wp_users SET status='active' WHERE id = %d", absint($_GET['uid'])
));
$wpdb->query($wpdb->prepare(
    "SELECT * FROM wp_posts WHERE post_title LIKE %s", '%' . $wpdb->esc_like($_POST['search']) . '%'
));
```

**审计规则**: 搜索 `$wpdb->query(` 后面直接跟引号（而非 `$wpdb->prepare`）的用法，全部标记为疑似 SQLi。同样检查 `$wpdb->get_results(`、`$wpdb->get_var(`、`$wpdb->get_row(` 的参数。

### XML-RPC 攻击面

`xmlrpc.php` 是 WordPress 的远程调用接口，常被利用进行暴力破解和 DDoS：

**攻击方式**:
- `system.multicall` — 单个请求中封装数百次 `wp.getUsersBlogs` 调用，进行批量密码暴力破解
- `pingback.ping` — 利用 WordPress 作为 SSRF 跳板或 DDoS 反射器
- 用户枚举 — 通过 `wp.getAuthors` 获取用户名列表

**检测要点**:
- 检查 `xmlrpc.php` 是否可访问（未被 Web Server 屏蔽）
- 搜索是否有 `add_filter('xmlrpc_enabled', '__return_false')` 来禁用
- 检查 `.htaccess` 或 Nginx 配置是否屏蔽了 `xmlrpc.php`
- 如果必须保留 XML-RPC，检查是否禁用了 `system.multicall`

```php
// 推荐: 完全禁用 XML-RPC
add_filter('xmlrpc_enabled', '__return_false');

// 或仅禁用 system.multicall
add_filter('xmlrpc_methods', function($methods) {
    unset($methods['system.multicall']);
    return $methods;
});
```

---

## Symfony

### 安全用法 ✓
| 场景 | 安全写法 |
|------|---------|
| SQL 查询 | `$qb->setParameter('id', $id)` (QueryBuilder 参数绑定) |
| 模板输出 | `{{ variable }}` (Twig 自动转义) |
| 表单验证 | `$form->isValid()` + Validator 约束 |
| 授权 | `#[IsGranted('ROLE_ADMIN')]` |
| CSRF | `csrf_token('authenticate')` |

### 不安全用法 ✗
| 场景 | 不安全写法 | 漏洞类型 |
|------|-----------|---------|
| SQL 注入 | `$conn->query("SELECT * WHERE id=$id")` | SQLi |
| SSTI | `$twig->createTemplate($userInput)->render()` | SSTI/RCE |
| XSS | `{{ variable|raw }}` | XSS |
| 反序列化 | `unserialize($request->get('data'))` | RCE |

---

## CodeIgniter

CodeIgniter 分为 CI3 (3.x) 和 CI4 (4.x) 两个大版本，安全模型差异较大。

### 安全用法 ✓
| 场景 | 安全写法 | 适用版本 |
|------|---------|---------|
| SQL 查询 | `$this->db->where('id', $id)->get('users')` | CI3 |
| SQL 查询 | `$builder->where('id', $id)->get()` | CI4 |
| 参数绑定 | `$this->db->query("SELECT * FROM users WHERE id = ?", [$id])` | CI3/CI4 |
| XSS 过滤 | `$this->security->xss_clean($input)` | CI3 |
| XSS 转义 | `esc($text)` | CI4 |
| CSRF | `$this->security->csrf_verify()` / 表单 hidden token | CI3 |
| CSRF | `csrf_field()` 在表单中 + `CSRFFilter` | CI4 |
| 输出转义 | `<?= esc($variable) ?>` | CI4 |

### 不安全用法 ✗
| 场景 | 不安全写法 | 漏洞类型 |
|------|-----------|---------|
| SQL 注入 | `$this->db->query("SELECT * FROM users WHERE id=$id")` | SQLi |
| SQL 注入 | `$this->db->where("id = $id")->get('users')` | SQLi |
| XSS | `echo $this->input->get('name')` (CI3 无自动 XSS 过滤) | XSS |
| XSS | `<?= $userInput ?>` 无 `esc()` | XSS |
| 文件包含 | `$this->load->view($_GET['page'])` | LFI |

### 常见陷阱

**CI3 `$this->input->get()` 无自动 XSS 过滤**:
CI3 的 `$this->input->get()` 和 `$this->input->post()` 默认**不做** XSS 过滤（除非全局配置 `$config['global_xss_filtering'] = TRUE`，但此配置已被官方废弃）。必须手动调用 `$this->security->xss_clean()` 或在输出时转义。

```php
// 危险: 直接输出用户输入
echo $this->input->get('search');

// 安全: 输出时转义
echo htmlspecialchars($this->input->get('search'), ENT_QUOTES, 'UTF-8');
```

**Query Builder 绕过**:
CI3 的 Query Builder 在某些方法中仍然允许原始 SQL 片段：
```php
// 看起来安全但实际危险
$this->db->where("status = 'active' AND role = " . $input)->get('users');
// where() 接受完整字符串时不会参数化
```

**CI4 环境配置泄露**:
- `.env` 文件放在 web root 且未被 server 屏蔽
- `CI_ENVIRONMENT = development` 在生产环境 → 详细错误输出

---

## CakePHP

CakePHP 提供了较完善的 ORM 和安全组件，但误用仍可导致漏洞。

### 安全用法 ✓
| 场景 | 安全写法 |
|------|---------|
| SQL 查询 | `$query->where(['id' => $id])` (ORM 自动参数绑定) |
| SQL 查询 | `$query->where(['status' => $status, 'role' => $role])` |
| XSS 防护 | `h($text)` (等同于 `htmlspecialchars`) |
| XSS (模板) | `<?= h($variable) ?>` |
| CSRF | `$this->loadComponent('Csrf')` 或中间件 `CsrfProtectionMiddleware` |
| 表单防篡改 | `$this->loadComponent('Security')` (Form Tampering 保护) |
| 密码哈希 | `(new DefaultPasswordHasher())->hash($password)` |
| 输入验证 | `$validator->requirePresence('email')->add('email', 'validFormat', [...])` |

### 不安全用法 ✗
| 场景 | 不安全写法 | 漏洞类型 |
|------|-----------|---------|
| SQL 注入 | `$query->where("id = $id")` | SQLi |
| SQL 注入 | `$conn->execute("SELECT * FROM users WHERE name='$name'")` | SQLi |
| XSS | `echo $variable` 无 `h()` 调用 | XSS |
| XSS | `<?= $this->request->getQuery('q') ?>` 直接输出 | XSS |
| 批量赋值 | `$entity = $table->patchEntity($entity, $this->request->getData())` 无 `$fields` 限制 | Mass Assignment |

### 常见陷阱

**`h()` helper 遗漏**:
CakePHP 模板 (`.ctp` / `.php`) 不像 Twig/Blade 那样自动转义，所有用户数据输出必须手动用 `h()` 包裹：
```php
// 危险
<td><?= $user->name ?></td>

// 安全
<td><?= h($user->name) ?></td>
```

**patchEntity 批量赋值**:
```php
// 危险: 允许所有字段被修改（包括 role, is_admin 等）
$entity = $table->patchEntity($entity, $this->request->getData());

// 安全: 白名单限制可赋值字段
$entity = $table->patchEntity($entity, $this->request->getData(), [
    'fields' => ['name', 'email', 'bio']
]);
```

**调试模式**: `config/app.php` 中 `'debug' => true` 在生产环境 → 泄露完整堆栈和查询

---

## Slim Framework

Slim 是 PHP 微框架，**不内置 ORM、模板引擎、CSRF 保护**，安全性完全依赖开发者选用的第三方库。

### 安全用法 ✓
| 场景 | 安全写法 |
|------|---------|
| SQL 查询 | 配合 Eloquent/Doctrine: `$db->prepare("SELECT * FROM users WHERE id = ?")` |
| 模板输出 | 配合 Twig: `{{ variable }}` (自动转义) |
| CSRF | 使用 `slim/csrf` 中间件 |
| 输入获取 | `$params = $request->getQueryParams()` + 手动验证/过滤 |
| 路由中间件 | 在路由组上添加认证中间件 |

### 不安全用法 ✗
| 场景 | 不安全写法 | 漏洞类型 |
|------|-----------|---------|
| SQL 注入 | `$db->query("SELECT * FROM users WHERE id=" . $args['id'])` | SQLi |
| XSS | `$response->getBody()->write("Hello " . $request->getQueryParams()['name'])` | XSS |
| 无 CSRF | 未引入 `slim/csrf` 中间件 | CSRF |
| 无认证 | 路由未添加 Auth 中间件 | 未授权访问 |
| 反序列化 | `unserialize($request->getParsedBody()['data'])` | RCE |

### 常见陷阱

**`getQueryParams()` 和 `getParsedBody()` 返回原始数据**:
Slim 的 PSR-7 Request 对象不做任何过滤或验证，所有参数均为原始用户输入：
```php
// 危险: 直接使用，无任何过滤
$app->get('/search', function ($request, $response) {
    $q = $request->getQueryParams()['q'];
    $response->getBody()->write("<p>Results for: $q</p>");  // XSS
    return $response;
});
```

**缺乏默认安全组件**:
- 无内置 ORM → 开发者可能直接拼接 SQL
- 无内置模板引擎 → 可能直接 `echo`/`write` 用户输入
- 无内置 CSRF → 如果忘记引入 `slim/csrf`，表单完全不受保护
- 无内置验证器 → 输入验证依赖 `respect/validation` 等第三方库

**审计重点**: 检查 `composer.json`，确认是否引入了:
- ORM 库 (Eloquent / Doctrine)
- 模板引擎 (Twig / Plates)
- CSRF 中间件 (`slim/csrf`)
- 验证库

若缺少以上任意组件，对应安全风险极高。

---

## Native PHP (无框架)

**风险等级: 极高** — Native PHP 项目没有框架提供的安全抽象层，Sink 密度在所有 PHP 项目中最高。

### 安全用法 ✓
| 场景 | 安全写法 |
|------|---------|
| SQL 查询 | `$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?"); $stmt->execute([$id]);` |
| XSS 防护 | `echo htmlspecialchars($input, ENT_QUOTES, 'UTF-8')` |
| 密码哈希 | `password_hash($password, PASSWORD_DEFAULT)` |
| 密码验证 | `password_verify($input, $hash)` |
| Session 安全 | `session_regenerate_id(true)` 在登录后 |
| CSRF | 手动生成 `bin2hex(random_bytes(32))` 存入 Session 并在表单中校验 |
| 文件上传 | 白名单扩展名 + `finfo_file()` 检查 MIME + 重命名 + 存储到 web root 外 |

### 不安全用法 ✗ (高危模式)
| 场景 | 不安全写法 | 漏洞类型 |
|------|-----------|---------|
| 变量覆盖 | `extract($_GET)` / `extract($_POST)` | Variable Overwrite |
| 变量覆盖 | `foreach($_GET as $key => $val) { $$key = $val; }` | Variable Overwrite |
| 文件包含 | `include $_GET['page']` / `include $_GET['page'] . '.php'` | LFI / RFI |
| SQL 注入 | `mysql_query("SELECT * FROM users WHERE id='$_GET[id]'")` | SQLi |
| SQL 注入 | `mysqli_query($conn, "SELECT * WHERE name='" . $_POST['name'] . "'")` | SQLi |
| XSS | `echo $_GET['search']` / `echo $username` (未转义) | XSS |
| 命令注入 | `system("ping " . $_GET['host'])` | RCE |
| 命令注入 | `exec("convert " . $_FILES['img']['name'] . " output.png")` | RCE |
| 反序列化 | `unserialize($_COOKIE['data'])` | RCE |
| SSRF | `file_get_contents($_GET['url'])` | SSRF |
| 路径遍历 | `file_get_contents("uploads/" . $_GET['file'])` | Path Traversal |

### 常见陷阱 (>= 7 种高危模式详解)

#### 1. `extract($_GET)` / `$$key` 变量覆盖

```php
// 危险: 用户可覆盖任意变量，包括 $is_admin, $user_id 等
extract($_GET);
// 攻击者访问: ?is_admin=1&user_id=999

// 同样危险:
foreach ($_REQUEST as $key => $value) {
    $$key = $value;  // 动态变量名 → 覆盖已有变量
}
```

#### 2. `include $_GET['page']` 文件包含

```php
// 危险: LFI (Local File Inclusion)
include $_GET['page'];
// 攻击: ?page=../../etc/passwd
// 攻击: ?page=php://filter/convert.base64-encode/resource=config.php

// 带后缀也不安全 (PHP < 5.3.4 可用 %00 截断)
include $_GET['page'] . '.php';
// 攻击: ?page=../../etc/passwd%00   (null byte 截断)
```

#### 3. `mysql_query()` 直接拼接 SQL

```php
// 极危险: 古老 API + 无参数绑定
$result = mysql_query("SELECT * FROM users WHERE id='" . $_GET['id'] . "'");
// mysql_* 函数在 PHP 7.0 已移除，但仍存在于遗留项目

// 即使用 mysqli，直接拼接仍然危险
$result = mysqli_query($conn, "SELECT * FROM users WHERE email='" . $_POST['email'] . "'");
```

#### 4. 无 CSRF 保护

```php
// 危险: 表单无 Token 验证
if ($_POST['action'] === 'delete') {
    delete_user($_POST['user_id']);  // 攻击者构造恶意页面即可触发
}
```

Native PHP 没有框架自动的 CSRF 中间件，开发者必须手动实现 Token 机制。

#### 5. 无输出转义

```php
// 危险: 数据库读取后直接输出
$user = $pdo->query("SELECT * FROM users WHERE id=1")->fetch();
echo "<p>Welcome, " . $user['name'] . "</p>";
// 若 name 字段含 <script>，即为 Stored XSS
```

#### 6. 不安全的 Session 处理

```php
// 危险: 登录成功后未重新生成 Session ID → Session Fixation
session_start();
if (check_password($user, $pass)) {
    $_SESSION['logged_in'] = true;
    // 缺少 session_regenerate_id(true);
}

// 危险: Session 存储路径权限不当 → 其他用户可读取 Session 文件
// 危险: Session Cookie 未设置 HttpOnly / Secure / SameSite
```

#### 7. 不安全的文件上传

```php
// 危险: 仅检查扩展名，未检查实际内容
$ext = pathinfo($_FILES['file']['name'], PATHINFO_EXTENSION);
if ($ext === 'jpg') {
    move_uploaded_file($_FILES['file']['tmp_name'], "uploads/" . $_FILES['file']['name']);
    // 问题1: 文件名未重命名，可能被目录遍历攻击 (../../shell.php)
    // 问题2: 上传目录在 web root 下，可直接访问执行
    // 问题3: 未检查文件实际 MIME 类型
}
```

### Native PHP 审计优先级

由于 Native PHP 缺乏安全抽象，审计时应按以下优先级排查:

1. **SQL 注入** — 搜索所有 `mysql_query`、`mysqli_query`、`pg_query`、`$pdo->query(`（非 prepare）
2. **文件包含** — 搜索 `include`/`require` 后跟变量的用法
3. **命令注入** — 搜索 `system()`、`exec()`、`passthru()`、`shell_exec()`、反引号
4. **XSS** — 搜索 `echo`/`print` 后跟 `$_GET`/`$_POST`/`$_REQUEST` 或未转义的数据库字段
5. **变量覆盖** — 搜索 `extract(` 和 `$$`
6. **反序列化** — 搜索 `unserialize(`
7. **SSRF** — 搜索 `file_get_contents(`、`curl_exec(` 后跟用户输入的 URL
