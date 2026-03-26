# Framework Security Pattern Quick Reference

Quick reference table of secure/insecure usage patterns for each framework, for all Agents to reference.

---

## Laravel

### Secure Usage ✓
| Scenario | Secure Pattern |
|------|---------|
| SQL query | `DB::table('users')->where('id', $id)->first()` |
| Template output | `{{ $variable }}` (automatic htmlspecialchars) |
| File upload | `$request->file('photo')->store('photos')` |
| Password hashing | `Hash::make($password)` |
| CSRF protection | `@csrf` in forms |
| Authorization | `$this->authorize('update', $post)` / Gate/Policy |
| Encryption | `Crypt::encryptString($data)` |
| Token scoping | `$token = $user->createToken('name', ['read']);` (Sanctum scoped) |
| Queue Job | Use `ShouldBeEncrypted` interface to protect serialized payload |

### Insecure Usage ✗
| Scenario | Insecure Pattern | Vulnerability Type |
|------|-----------|---------|
| SQL injection | `DB::raw("WHERE id=$input")` | SQLi |
| SQL injection | `->whereRaw("status = '$input'")` | SQLi |
| XSS | `{!! $userInput !!}` | XSS |
| Mass assignment | `$guarded = []` + `Model::create($request->all())` | Mass Assignment |
| Deserialization | `unserialize($cookie)` | RCE |
| Command injection | `exec("convert $filename")` | RCE |
| SSRF | `file_get_contents($userUrl)` | SSRF |
| Weak comparison | `if ($token == $stored)` | AuthZ Bypass |
| Token no expiry | `'expiration' => null` in sanctum config | Token abuse |
| Debugbar leak | `barryvdh/laravel-debugbar` enabled in production | Information leak |

### Common Pitfalls
- `APP_DEBUG=true` in production → stack trace leak
- `APP_KEY` leak → Cookie forgery / deserialization RCE
- Telescope/Horizon without auth → information leak
- `VerifyCsrfToken::$except` with too many entries → CSRF

### Telescope / Horizon Unauthenticated Access Detection

Telescope and Horizon are accessible by default in `local` environment, but many developers forget to configure the Gate when deploying to production:

```php
// DANGEROUS: No access restriction in TelescopeServiceProvider
Gate::define('viewTelescope', function ($user) {
    return true;  // Any logged-in user can access
});
```

**Detection points**:
- Check whether `TelescopeServiceProvider::gate()` exists and restricts by email/role
- Check `HorizonServiceProvider::gate()` similarly
- Search for routes `/telescope`, `/horizon` that are publicly accessible (no middleware)
- If `APP_ENV=production` but Telescope/Horizon is registered in `AppServiceProvider` rather than `local` only → high risk

```php
// SECURE: Restricted to specific admin emails
Gate::define('viewTelescope', function ($user) {
    return in_array($user->email, [
        'admin@example.com',
    ]);
});
```

### Sanctum / Passport Token Security Audit

**Token expiration**:
- Sanctum tokens **never expire** by default; `'expiration' => 60 * 24` MUST be set in `config/sanctum.php`
- Passport's `tokensExpireIn()` / `refreshTokensExpireIn()` MUST be explicitly configured in `AuthServiceProvider`
- Search for `createToken(` calls and verify whether scope parameter is passed

**Token Scope audit**:
```php
// DANGEROUS: No scope restriction, gets full permissions
$token = $user->createToken('api-token');

// SECURE: Least privilege principle
$token = $user->createToken('api-token', ['read', 'orders:view']);
```

**Token revocation**:
- Check whether token revocation logic exists (`$user->tokens()->delete()`, `$token->revoke()`)
- Check whether old tokens are cleared after password change
- Search `personalAccessTokens` for uncleaned expired tokens

### Queue Worker Deserialization Risk (SerializesModels)

When Laravel Queue Job uses the `SerializesModels` trait, objects are serialized into Redis/DB:

```php
// Potential risk: Job payload contains serialized Eloquent Model
class ProcessOrder implements ShouldQueue
{
    use SerializesModels;
    public $order; // Serialized for storage → if Redis is attacker-controlled, malicious payload can be injected
}
```

**Detection points**:
- Whether Redis is exposed publicly without a password (`redis://0.0.0.0:6379`)
- When Queue driver is `database`, whether the `payload` field in `jobs` table can be tampered with
- Search for combined usage of `unserialize(` and `Queue::`
- Recommend using `ShouldBeEncrypted` interface to encrypt Job payload (Laravel 8+)

### Livewire Component Injection

Livewire component public properties can be tampered with from the frontend:

```php
// DANGEROUS: Public properties directly bound to sensitive fields
class EditProfile extends Component
{
    public $userId;   // Attacker can tamper userId via wire:model
    public $role;     // Attacker can escalate role

    public function save()
    {
        User::find($this->userId)->update(['role' => $this->role]);
    }
}
```

**Secure approach**: Use `#[Locked]` attribute (Livewire v3) or force `auth()->id()` in `save()`

### Laravel Debugbar Production Leak

`barryvdh/laravel-debugbar` enabled in production leaks:
- All SQL queries and binding parameters (including sensitive data like passwords)
- Session contents, Request parameters
- Environment variables (may include API Keys)
- Route list and middleware configuration

**Detection**: Search `composer.json` for `require` (not `require-dev`) containing `debugbar`; check `DEBUGBAR_ENABLED` environment variable

---

## ThinkPHP

### Secure Usage ✓
| Scenario | Secure Pattern |
|------|---------|
| SQL query | `Db::name('user')->where('id', $id)->find()` |
| Parameter retrieval | `input('get.id/d')` (with type filtering) |
| Template output | `{$var|htmlspecialchars}` |
| Route definition | Explicitly register routes, disable auto-routing |

### Insecure Usage ✗
| Scenario | Insecure Pattern | Vulnerability Type |
|------|-----------|---------|
| SQL injection | `Db::query("SELECT * FROM user WHERE id=$id")` | SQLi |
| SQL injection | `->where('id', 'exp', $input)` | SQLi (exp expression) |
| Variable overwrite | `extract($_GET)` | Variable Overwrite |
| RCE | `think\App::invokeMethod()` route control | RCE |
| Route exposure | `'url_route_must' => false` (allows auto-routing) | Unauthorized access |

### Historical High-Risk Vulnerabilities

- ThinkPHP 5.0.x RCE (invokeFunction)
- ThinkPHP 5.1.x SQL injection (where/exp)
- ThinkPHP 6.x Session deserialization

### Version-Specific RCE Detection Signatures

#### ThinkPHP 5.0.x — invokeFunction RCE

Vulnerability principle: Controller/method not filtered, allows direct invocation of arbitrary functions.

```
# Attack payload signatures (detect in logs or WAF):
/index.php?s=/index/\think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=whoami
/index.php?s=index/think\app/invokefunction&function=call_user_func_array
```

**Code detection**: Search for `thinkphp` version `5.0.0` ~ `5.0.23`; check whether `App::invokeFunction` has been patched.

#### ThinkPHP 5.1.x — where('exp') SQL Injection

```php
// DANGEROUS: exp expression allows raw SQL
$result = Db::name('user')->where('id', 'exp', $userInput)->find();
// Attacker passes: "= 1 UNION SELECT password FROM admin--"
```

**Detection**: Global search for `'exp'` as the second argument to `where()`; check whether ThinkPHP version is < 5.1.23.

#### ThinkPHP 6.x — Session Deserialization

When the Session driver uses file storage and the Session ID is controllable, an attacker can write malicious serialized data:

**Detection points**:
- Whether `session.type` config is `file`
- Whether Session ID is obtained from user input without format validation
- Search for `session(` function calls; check whether user-controllable objects are stored

### Route Security: Auto-Route Mode Exposure

ThinkPHP's auto-route mode automatically maps all Controller public methods to URLs:

```php
// config/route.php or config/app.php
'url_route_must' => false,  // DANGEROUS: Allows direct URL access to any controller method
```

**Risks**:
- Internal management methods (e.g., `AdminController::resetPassword()`) become directly accessible
- Test methods, debug methods accidentally exposed
- Bypasses middleware and route-level permission checks

**Detection**: Search for `url_route_must` config item; if `false` or unset, flag as high risk.

**Secure approach**: Set `'url_route_must' => true` to force all access through explicitly defined routes.

---

## Yii2

### Secure Usage ✓
| Scenario | Secure Pattern |
|------|---------|
| SQL query | `User::find()->where(['id' => $id])->one()` |
| XSS protection | `Html::encode($text)` |
| CSRF | `\yii\filters\Csrf` behavior |
| RBAC | `Yii::$app->user->can('updatePost')` |

### Insecure Usage ✗
| Scenario | Insecure Pattern | Vulnerability Type |
|------|-----------|---------|
| SQL injection | `Model::findBySql("SELECT * WHERE id=$id")` | SQLi |
| SQL injection | `->orderBy($userInput)` | SQLi |
| XSS | `<?= $userInput ?>` without encode | XSS |

---

## WordPress

### Secure Usage ✓
| Scenario | Secure Pattern |
|------|---------|
| SQL query | `$wpdb->prepare("SELECT * FROM %s WHERE id = %d", $table, $id)` |
| Output escaping | `esc_html($text)`, `esc_attr($attr)`, `esc_url($url)` |
| Nonce verification | `wp_verify_nonce($_POST['_wpnonce'], 'action')` |
| Permission check | `current_user_can('manage_options')` |
| Data sanitization | `sanitize_text_field($input)`, `absint($id)` |
| REST API permission | `'permission_callback' => function() { return current_user_can('edit_posts'); }` |
| Secure DB operation | `$wpdb->insert($table, $data, $format)` / `$wpdb->update(...)` |

### Insecure Usage ✗
| Scenario | Insecure Pattern | Vulnerability Type |
|------|-----------|---------|
| SQL injection | `$wpdb->query("SELECT * WHERE id=$input")` | SQLi |
| SQL injection | `$wpdb->query("DELETE FROM $table WHERE id=" . $_GET['id'])` | SQLi |
| XSS | `echo $_GET['param']` | XSS |
| Permission misuse | `if (is_admin()) { /* sensitive operation */ }` | AuthZ Bypass |
| CSRF | Missing `wp_verify_nonce()` | CSRF |
| File upload | No MIME + extension check | File upload |
| REST no permission | `register_rest_route` without `permission_callback` | Unauthorized access |
| Hook injection | `do_action($_GET['hook_name'])` | Arbitrary code execution |

### Key Functions
- `is_admin()` — Only checks whether on admin page, is **NOT** a permission check
- `current_user_can()` — The **actual** permission check
- `wp_nonce_field()` / `wp_verify_nonce()` — CSRF protection
- `esc_sql()` — Only escapes quotes, less secure than `$wpdb->prepare()`

### REST API permission_callback Missing Detection

WordPress 5.5+ requires `register_rest_route` to include `permission_callback`, otherwise a `_doing_it_wrong` warning is triggered. But older plugins/themes may be missing it:

```php
// DANGEROUS: Anyone (including unauthenticated users) can access
register_rest_route('myplugin/v1', '/users', [
    'methods'  => 'GET',
    'callback' => 'get_all_users',
    // Missing permission_callback → defaults to allowing everyone
]);

// DANGEROUS: Explicitly set to public but developer may not realize
register_rest_route('myplugin/v1', '/delete-user', [
    'methods'  => 'DELETE',
    'callback' => 'delete_user_handler',
    'permission_callback' => '__return_true',  // DANGEROUS! Destructive operation without permission check
]);
```

**Detection**: Global search for `register_rest_route`, check each one for `permission_callback`, and whether the callback content is `__return_true` (unsafe for sensitive operations).

### Action / Filter Hook Injection

WordPress's Hook system (`do_action` / `apply_filters`) can cause unexpected behavior if hook names or arguments come from user input:

```php
// DANGEROUS: Hook name comes from user input
$action = $_GET['action_type'];
do_action("process_{$action}");
// Attacker passes action_type=admin_init → triggers admin initialization flow

// DANGEROUS: User input passed directly as hook argument
do_action('user_profile_update', $_POST['data']);
// All callbacks hooked to this action receive unfiltered data
```

**Detection points**:
- Search for `do_action(` and `apply_filters(`, check whether arguments contain `$_GET`, `$_POST`, `$_REQUEST`
- Check whether hook names are constructed from variables sourced from user input
- Pay special attention to `wp_ajax_nopriv_` prefixed hooks (open to unauthenticated users)

### wpdb Usage Audit: query() Direct Concatenation vs prepare()

`$wpdb->query()` accepts raw SQL and is the primary source of SQL injection in WordPress:

```php
// DANGEROUS: Direct string concatenation
$wpdb->query("UPDATE wp_users SET status='active' WHERE id=" . $_GET['uid']);
$wpdb->query("SELECT * FROM wp_posts WHERE post_title LIKE '%" . $_POST['search'] . "%'");

// SECURE: Using prepare() parameter binding
$wpdb->query($wpdb->prepare(
    "UPDATE wp_users SET status='active' WHERE id = %d", absint($_GET['uid'])
));
$wpdb->query($wpdb->prepare(
    "SELECT * FROM wp_posts WHERE post_title LIKE %s", '%' . $wpdb->esc_like($_POST['search']) . '%'
));
```

**Audit rule**: Search for `$wpdb->query(` followed directly by a quote (rather than `$wpdb->prepare`); flag all as suspected SQLi. Also check arguments of `$wpdb->get_results(`, `$wpdb->get_var(`, `$wpdb->get_row(`.

### XML-RPC Attack Surface

`xmlrpc.php` is WordPress's remote call interface, commonly exploited for brute force attacks and DDoS:

**Attack methods**:
- `system.multicall` — Encapsulates hundreds of `wp.getUsersBlogs` calls in a single request for bulk password brute forcing
- `pingback.ping` — Uses WordPress as SSRF proxy or DDoS reflector
- User enumeration — Retrieves username list via `wp.getAuthors`

**Detection points**:
- Check whether `xmlrpc.php` is accessible (not blocked by web server)
- Search for `add_filter('xmlrpc_enabled', '__return_false')` to disable it
- Check `.htaccess` or Nginx config for blocking of `xmlrpc.php`
- If XML-RPC must be retained, check whether `system.multicall` is disabled

```php
// Recommended: Completely disable XML-RPC
add_filter('xmlrpc_enabled', '__return_false');

// Or disable only system.multicall
add_filter('xmlrpc_methods', function($methods) {
    unset($methods['system.multicall']);
    return $methods;
});
```

---

## Symfony

### Secure Usage ✓
| Scenario | Secure Pattern |
|------|---------|
| SQL query | `$qb->setParameter('id', $id)` (QueryBuilder parameter binding) |
| Template output | `{{ variable }}` (Twig auto-escaping) |
| Form validation | `$form->isValid()` + Validator constraints |
| Authorization | `#[IsGranted('ROLE_ADMIN')]` |
| CSRF | `csrf_token('authenticate')` |

### Insecure Usage ✗
| Scenario | Insecure Pattern | Vulnerability Type |
|------|-----------|---------|
| SQL injection | `$conn->query("SELECT * WHERE id=$id")` | SQLi |
| SSTI | `$twig->createTemplate($userInput)->render()` | SSTI/RCE |
| XSS | `{{ variable|raw }}` | XSS |
| Deserialization | `unserialize($request->get('data'))` | RCE |

---

## CodeIgniter

CodeIgniter is split into CI3 (3.x) and CI4 (4.x) as two major versions with significantly different security models.

### Secure Usage ✓
| Scenario | Secure Pattern | Applicable Version |
|------|---------|---------|
| SQL query | `$this->db->where('id', $id)->get('users')` | CI3 |
| SQL query | `$builder->where('id', $id)->get()` | CI4 |
| Parameter binding | `$this->db->query("SELECT * FROM users WHERE id = ?", [$id])` | CI3/CI4 |
| XSS filtering | `$this->security->xss_clean($input)` | CI3 |
| XSS escaping | `esc($text)` | CI4 |
| CSRF | `$this->security->csrf_verify()` / form hidden token | CI3 |
| CSRF | `csrf_field()` in forms + `CSRFFilter` | CI4 |
| Output escaping | `<?= esc($variable) ?>` | CI4 |

### Insecure Usage ✗
| Scenario | Insecure Pattern | Vulnerability Type |
|------|-----------|---------|
| SQL injection | `$this->db->query("SELECT * FROM users WHERE id=$id")` | SQLi |
| SQL injection | `$this->db->where("id = $id")->get('users')` | SQLi |
| XSS | `echo $this->input->get('name')` (CI3 has no auto XSS filtering) | XSS |
| XSS | `<?= $userInput ?>` without `esc()` | XSS |
| File inclusion | `$this->load->view($_GET['page'])` | LFI |

### Common Pitfalls

**CI3 `$this->input->get()` has no automatic XSS filtering**:
CI3's `$this->input->get()` and `$this->input->post()` do **NOT** perform XSS filtering by default (unless global config `$config['global_xss_filtering'] = TRUE` is set, but this config has been officially deprecated). You MUST manually call `$this->security->xss_clean()` or escape on output.

```php
// DANGEROUS: Direct output of user input
echo $this->input->get('search');

// SECURE: Escape on output
echo htmlspecialchars($this->input->get('search'), ENT_QUOTES, 'UTF-8');
```

**Query Builder bypass**:
CI3's Query Builder still allows raw SQL fragments in certain methods:
```php
// Appears safe but is actually dangerous
$this->db->where("status = 'active' AND role = " . $input)->get('users');
// where() does not parameterize when accepting a full string
```

**CI4 environment config leak**:
- `.env` file placed in web root and not blocked by server
- `CI_ENVIRONMENT = development` in production → verbose error output

---

## CakePHP

CakePHP provides a fairly comprehensive ORM and security components, but misuse can still lead to vulnerabilities.

### Secure Usage ✓
| Scenario | Secure Pattern |
|------|---------|
| SQL query | `$query->where(['id' => $id])` (ORM automatic parameter binding) |
| SQL query | `$query->where(['status' => $status, 'role' => $role])` |
| XSS protection | `h($text)` (equivalent to `htmlspecialchars`) |
| XSS (template) | `<?= h($variable) ?>` |
| CSRF | `$this->loadComponent('Csrf')` or middleware `CsrfProtectionMiddleware` |
| Form tampering protection | `$this->loadComponent('Security')` (Form Tampering protection) |
| Password hashing | `(new DefaultPasswordHasher())->hash($password)` |
| Input validation | `$validator->requirePresence('email')->add('email', 'validFormat', [...])` |

### Insecure Usage ✗
| Scenario | Insecure Pattern | Vulnerability Type |
|------|-----------|---------|
| SQL injection | `$query->where("id = $id")` | SQLi |
| SQL injection | `$conn->execute("SELECT * FROM users WHERE name='$name'")` | SQLi |
| XSS | `echo $variable` without `h()` call | XSS |
| XSS | `<?= $this->request->getQuery('q') ?>` direct output | XSS |
| Mass assignment | `$entity = $table->patchEntity($entity, $this->request->getData())` without `$fields` restriction | Mass Assignment |

### Common Pitfalls

**`h()` helper omission**:
CakePHP templates (`.ctp` / `.php`) do not auto-escape like Twig/Blade; all user data output MUST be manually wrapped with `h()`:
```php
// DANGEROUS
<td><?= $user->name ?></td>

// SECURE
<td><?= h($user->name) ?></td>
```

**patchEntity mass assignment**:
```php
// DANGEROUS: Allows all fields to be modified (including role, is_admin etc.)
$entity = $table->patchEntity($entity, $this->request->getData());

// SECURE: Whitelist restricts assignable fields
$entity = $table->patchEntity($entity, $this->request->getData(), [
    'fields' => ['name', 'email', 'bio']
]);
```

**Debug mode**: `'debug' => true` in `config/app.php` in production → leaks full stack traces and queries

---

## Slim Framework

Slim is a PHP micro-framework that **does not include built-in ORM, template engine, or CSRF protection**; security relies entirely on third-party libraries chosen by the developer.

### Secure Usage ✓
| Scenario | Secure Pattern |
|------|---------|
| SQL query | With Eloquent/Doctrine: `$db->prepare("SELECT * FROM users WHERE id = ?")` |
| Template output | With Twig: `{{ variable }}` (auto-escaping) |
| CSRF | Use `slim/csrf` middleware |
| Input retrieval | `$params = $request->getQueryParams()` + manual validation/filtering |
| Route middleware | Add auth middleware to route groups |

### Insecure Usage ✗
| Scenario | Insecure Pattern | Vulnerability Type |
|------|-----------|---------|
| SQL injection | `$db->query("SELECT * FROM users WHERE id=" . $args['id'])` | SQLi |
| XSS | `$response->getBody()->write("Hello " . $request->getQueryParams()['name'])` | XSS |
| No CSRF | `slim/csrf` middleware not included | CSRF |
| No auth | Route has no Auth middleware | Unauthorized access |
| Deserialization | `unserialize($request->getParsedBody()['data'])` | RCE |

### Common Pitfalls

**`getQueryParams()` and `getParsedBody()` return raw data**:
Slim's PSR-7 Request object does not perform any filtering or validation; all parameters are raw user input:
```php
// DANGEROUS: Direct use, no filtering
$app->get('/search', function ($request, $response) {
    $q = $request->getQueryParams()['q'];
    $response->getBody()->write("<p>Results for: $q</p>");  // XSS
    return $response;
});
```

**Lack of default security components**:
- No built-in ORM → developers may directly concatenate SQL
- No built-in template engine → may directly `echo`/`write` user input
- No built-in CSRF → if `slim/csrf` is forgotten, forms are completely unprotected
- No built-in validator → input validation depends on `respect/validation` or other third-party libraries

**Audit focus**: Check `composer.json` to confirm whether the following are included:
- ORM library (Eloquent / Doctrine)
- Template engine (Twig / Plates)
- CSRF middleware (`slim/csrf`)
- Validation library

If any of the above components are missing, the corresponding security risk is extremely high.

---

## Native PHP (No Framework)

**Risk level: Extremely High** — Native PHP projects lack the security abstraction layer provided by frameworks; Sink density is the highest among all PHP project types.

### Secure Usage ✓
| Scenario | Secure Pattern |
|------|---------|
| SQL query | `$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?"); $stmt->execute([$id]);` |
| XSS protection | `echo htmlspecialchars($input, ENT_QUOTES, 'UTF-8')` |
| Password hashing | `password_hash($password, PASSWORD_DEFAULT)` |
| Password verification | `password_verify($input, $hash)` |
| Session security | `session_regenerate_id(true)` after login |
| CSRF | Manually generate `bin2hex(random_bytes(32))`, store in Session and validate in forms |
| File upload | Extension whitelist + `finfo_file()` MIME check + rename + store outside web root |

### Insecure Usage ✗ (High-Risk Patterns)
| Scenario | Insecure Pattern | Vulnerability Type |
|------|-----------|---------|
| Variable overwrite | `extract($_GET)` / `extract($_POST)` | Variable Overwrite |
| Variable overwrite | `foreach($_GET as $key => $val) { $$key = $val; }` | Variable Overwrite |
| File inclusion | `include $_GET['page']` / `include $_GET['page'] . '.php'` | LFI / RFI |
| SQL injection | `mysql_query("SELECT * FROM users WHERE id='$_GET[id]'")` | SQLi |
| SQL injection | `mysqli_query($conn, "SELECT * WHERE name='" . $_POST['name'] . "'")` | SQLi |
| XSS | `echo $_GET['search']` / `echo $username` (unescaped) | XSS |
| Command injection | `system("ping " . $_GET['host'])` | RCE |
| Command injection | `exec("convert " . $_FILES['img']['name'] . " output.png")` | RCE |
| Deserialization | `unserialize($_COOKIE['data'])` | RCE |
| SSRF | `file_get_contents($_GET['url'])` | SSRF |
| Path traversal | `file_get_contents("uploads/" . $_GET['file'])` | Path Traversal |

### Common Pitfalls (>= 7 High-Risk Patterns Detailed)

#### 1. `extract($_GET)` / `$$key` Variable Overwrite

```php
// DANGEROUS: User can overwrite any variable, including $is_admin, $user_id etc.
extract($_GET);
// Attacker visits: ?is_admin=1&user_id=999

// Equally dangerous:
foreach ($_REQUEST as $key => $value) {
    $$key = $value;  // Dynamic variable name → overwrites existing variables
}
```

#### 2. `include $_GET['page']` File Inclusion

```php
// DANGEROUS: LFI (Local File Inclusion)
include $_GET['page'];
// Attack: ?page=../../etc/passwd
// Attack: ?page=php://filter/convert.base64-encode/resource=config.php

// With suffix is also unsafe (PHP < 5.3.4 allows %00 truncation)
include $_GET['page'] . '.php';
// Attack: ?page=../../etc/passwd%00   (null byte truncation)
```

#### 3. `mysql_query()` Direct SQL Concatenation

```php
// Extremely dangerous: Legacy API + no parameter binding
$result = mysql_query("SELECT * FROM users WHERE id='" . $_GET['id'] . "'");
// mysql_* functions were removed in PHP 7.0 but still exist in legacy projects

// Even with mysqli, direct concatenation is still dangerous
$result = mysqli_query($conn, "SELECT * FROM users WHERE email='" . $_POST['email'] . "'");
```

#### 4. No CSRF Protection

```php
// DANGEROUS: Form has no Token validation
if ($_POST['action'] === 'delete') {
    delete_user($_POST['user_id']);  // Attacker crafts a malicious page to trigger this
}
```

Native PHP has no framework automatic CSRF middleware; developers MUST manually implement a Token mechanism.

#### 5. No Output Escaping

```php
// DANGEROUS: Direct output after database read
$user = $pdo->query("SELECT * FROM users WHERE id=1")->fetch();
echo "<p>Welcome, " . $user['name'] . "</p>";
// If name field contains <script>, this is Stored XSS
```

#### 6. Insecure Session Handling

```php
// DANGEROUS: Session ID not regenerated after successful login → Session Fixation
session_start();
if (check_password($user, $pass)) {
    $_SESSION['logged_in'] = true;
    // Missing session_regenerate_id(true);
}

// DANGEROUS: Session storage path has improper permissions → other users can read Session files
// DANGEROUS: Session Cookie not set with HttpOnly / Secure / SameSite
```

#### 7. Insecure File Upload

```php
// DANGEROUS: Only checks extension, not actual content
$ext = pathinfo($_FILES['file']['name'], PATHINFO_EXTENSION);
if ($ext === 'jpg') {
    move_uploaded_file($_FILES['file']['tmp_name'], "uploads/" . $_FILES['file']['name']);
    // Problem 1: Filename not renamed, vulnerable to directory traversal (../../shell.php)
    // Problem 2: Upload directory under web root, directly accessible for execution
    // Problem 3: Actual file MIME type not checked
}
```

### Native PHP Audit Priority

Since Native PHP lacks security abstractions, auditing SHOULD follow this priority order:

1. **SQL injection** — Search for all `mysql_query`, `mysqli_query`, `pg_query`, `$pdo->query(` (non-prepare)
2. **File inclusion** — Search for `include`/`require` followed by variables
3. **Command injection** — Search for `system()`, `exec()`, `passthru()`, `shell_exec()`, backticks
4. **XSS** — Search for `echo`/`print` followed by `$_GET`/`$_POST`/`$_REQUEST` or unescaped database fields
5. **Variable overwrite** — Search for `extract(` and `$$`
6. **Deserialization** — Search for `unserialize(`
7. **SSRF** — Search for `file_get_contents(`, `curl_exec(` followed by user input URLs
