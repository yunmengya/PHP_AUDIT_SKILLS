# Known CVEs — PHP 生态高频 CVE 速查库

审计时快速比对目标组件版本，判断是否存在已知漏洞。按组件分类，每条包含完整利用前提。

---

## Laravel

### CVE-2021-3129 — Ignition RCE (Log Poisoning + Phar)
- **影响版本**: Ignition < 2.5.2 (Laravel 6.x / 7.x / 8.x with debug mode)
- **漏洞类型**: RCE (Remote Code Execution)
- **检测方法**: 访问 `/_ignition/execute-solution`，返回非 404 即存在；检查 `composer.lock` 中 `facade/ignition` 版本
- **利用前提**: `APP_DEBUG=true`；Ignition 组件存在且可访问；可写 storage/logs
- **利用链**: 通过 `_ignition/execute-solution` 清空日志 → 逐字节写入 phar payload → `phar://` 触发反序列化

### CVE-2018-15133 — APP_KEY Deserialization RCE
- **影响版本**: Laravel 5.5.x ~ 5.6.29
- **漏洞类型**: RCE (Deserialization)
- **检测方法**: 发送恶意 cookie，观察 500 错误堆栈是否暴露反序列化相关类；需已知 APP_KEY
- **利用前提**: 必须获得 `APP_KEY`（通过 `.env` 泄露、debug 页面、git 泄露等）
- **利用链**: 利用 APP_KEY 加密恶意序列化对象 → 放入 laravel_session cookie → 服务端解密触发 `unserialize()`

### CVE-2021-21263 — Query Binding Bypass (SQLi)
- **影响版本**: Laravel < 8.22.1
- **漏洞类型**: SQL Injection
- **检测方法**: 检查 `composer.lock` 版本；搜索使用 `whereIn` / `whereNotIn` 配合用户输入的代码
- **利用前提**: 应用使用 PostgreSQL；用户输入进入 query binding 且未额外验证类型
- **利用链**: 传入特殊构造的数组参数 → 绕过 PDO 参数绑定 → 注入 SQL 片段

### CVE-2024-13918 / CVE-2024-13919 — Laravel Reflected XSS
- **影响版本**: Laravel 11.9.0 ~ 11.35.1, 12.0.0 ~ 12.1.1
- **漏洞类型**: Reflected XSS
- **检测方法**: 检查 `composer.lock` 版本；测试错误页面中路由参数是否被反射
- **利用前提**: `APP_DEBUG=true` 或自定义错误页面渲染用户输入
- **利用链**: 构造含 XSS payload 的 URL 路由参数 → 触发 404/500 → 错误页面未转义输出

---

## ThinkPHP

### ThinkPHP 5.0 RCE — invokefunction 远程代码执行
- **CVE**: 无正式编号 (CNVD-2018-24942)
- **影响版本**: ThinkPHP 5.0.0 ~ 5.0.23
- **漏洞类型**: RCE
- **检测方法**: 发送 `?s=index/think\app/invokefunction&function=phpinfo&vars[0]=1`，返回 phpinfo 即存在
- **利用前提**: 默认路由开启 (通常默认开启)；无 WAF 拦截
- **利用链**: 控制器/方法路由解析缺陷 → 可调用任意类的任意方法 → `call_user_func_array()` 执行任意函数

### ThinkPHP 5.1 SQLi — Builder 组件 SQL 注入
- **CVE**: 无正式编号
- **影响版本**: ThinkPHP 5.1.0 ~ 5.1.25
- **漏洞类型**: SQL Injection
- **检测方法**: 搜索使用 `order()` / `where()` 且参数来自用户输入的代码；检查框架版本
- **利用前提**: 用户输入直接进入 `order()` / `where()` 等 query builder 方法
- **利用链**: `order` 参数传入 `updatexml` 等报错注入函数 → 拼接进 SQL → 数据库执行报错带出数据

### ThinkPHP 6 Session 反序列化
- **CVE**: 无正式编号
- **影响版本**: ThinkPHP 6.0.0 ~ 6.0.1
- **漏洞类型**: Deserialization RCE
- **检测方法**: 检查 session 配置是否使用 file driver；session ID 是否来自未过滤的用户输入
- **利用前提**: session driver 为 file (非 Redis/Memcache)；session 文件路径可控（session ID 未严格过滤）
- **利用链**: 控制 session ID → 写入含恶意序列化数据的 session 文件 → 任意文件创建 + 反序列化

### ThinkPHP 多语言 RCE — lang 参数包含
- **CVE**: 无正式编号 (2022年公开)
- **影响版本**: ThinkPHP 5.x / 6.x 开启多语言功能
- **漏洞类型**: RCE (File Inclusion)
- **检测方法**: 发送 `?lang=../../../../usr/local/lib/php/pearcmd`，观察响应；检查中间件是否加载 `LoadLangPack`
- **利用前提**: 开启多语言中间件；PHP 安装了 pearcmd.php (默认安装通常存在)
- **利用链**: `lang` 参数控制语言文件路径 → 文件包含 → 利用 `pearcmd.php` 实现文件写入 → Webshell

---

## WordPress

### CVE-2022-21661 — WP_Query SQL Injection
- **影响版本**: WordPress < 5.8.3
- **漏洞类型**: SQL Injection
- **检测方法**: 检查 WordPress 版本；搜索使用 `WP_Query` 且 `tax_query` 参数来自用户输入的代码
- **利用前提**: 存在允许用户控制 `WP_Query` 参数的功能（如自定义 REST endpoint、AJAX handler）
- **利用链**: 构造恶意 `tax_query` 参数 → `WP_Tax_Query::clean_query()` 处理不当 → 注入 SQL

### CVE-2019-8942 — WordPress Image RCE (Crop 功能)
- **影响版本**: WordPress < 5.0.1 / < 4.9.9
- **漏洞类型**: RCE (via Post Meta Overwrite + Path Traversal)
- **检测方法**: 检查 WP 版本；需要至少 Author 权限
- **利用前提**: 攻击者拥有 Author 或以上角色；服务器使用 GD/Imagick 库
- **利用链**: 上传含恶意 EXIF 的图片 → 利用 `wp_crop_image()` 的路径穿越覆写 → 修改 post meta 指向恶意文件 → 包含执行

### WordPress REST API 权限绕过 (CVE-2017-1001000)
- **影响版本**: WordPress 4.7.0 ~ 4.7.1
- **漏洞类型**: Authorization Bypass → Content Injection
- **检测方法**: 发送 `POST /wp-json/wp/v2/posts/1?id=1abc`，若可修改内容则存在
- **利用前提**: REST API 启用（WordPress 4.7+ 默认启用）；目标有 Posts
- **利用链**: 利用类型转换缺陷在 URL 中传入非整型 ID → 绕过权限检查 → 未认证修改任意文章

### CVE-2023-2745 — WordPress Directory Traversal
- **影响版本**: WordPress < 6.2.1
- **漏洞类型**: Directory Traversal → 信息泄露
- **检测方法**: 检查 WP 版本；尝试 `wp-login.php?wp_lang=../../../etc/passwd%00`
- **利用前提**: 攻击者可访问 `wp-login.php`
- **利用链**: `wp_lang` 参数路径穿越 → 包含任意 `.mo` 文件 → 信息泄露 / 配合文件上传实现 RCE

---

## 常用组件 (Common Components)

### PHPUnit RCE — eval-stdin.php 远程代码执行
- **CVE**: CVE-2017-9841
- **影响版本**: PHPUnit 4.8.19 ~ 4.8.27, 5.x ~ 5.6.2
- **漏洞类型**: RCE
- **检测方法**: 访问 `vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php`，返回非 404 即存在
- **利用前提**: `vendor/` 目录可通过 Web 访问（生产环境未删除开发依赖或 Web 根目录配置不当）
- **利用链**: POST 请求发送 PHP 代码到 `eval-stdin.php` → 直接 `eval()` 执行

### PHPMailer RCE — CVE-2016-10033 / CVE-2016-10045
- **影响版本**: PHPMailer < 5.2.18 (10033), < 5.2.20 (10045 绕过补丁)
- **漏洞类型**: RCE (mail() 参数注入)
- **检测方法**: 检查 `composer.lock` 中 phpmailer 版本；搜索 `Sender` / `setFrom()` 是否接受用户输入
- **利用前提**: 应用使用 `mail()` 作为传输方式（非 SMTP）；用户可控 sender/from 地址
- **利用链**: 在 email 地址中注入 `-X` / `-OQueueDirectory` 参数 → Sendmail 写文件到 Web 目录 → Webshell

### Guzzle SSRF — CVE-2022-29248 / CVE-2022-31042 / CVE-2022-31043
- **影响版本**: Guzzle < 7.4.4 (cookie / header 跨域泄露), 全版本 (SSRF 取决于使用方式)
- **漏洞类型**: SSRF / Credential Leakage
- **检测方法**: 搜索 `GuzzleHttp\Client` 使用场景，检查 URL 是否来自用户输入；检查版本
- **利用前提**: 用户可控请求目标 URL 或部分 URL（host/path/query）
- **利用链**: 传入内网 URL → Guzzle 发起服务端请求 → 访问云元数据 / 内网服务 → 信息泄露或进一步攻击

### Monolog RCE — 反序列化 Gadget Chain
- **CVE**: 无正式 CVE (POP chain component)
- **影响版本**: Monolog 1.x ~ 3.x (作为反序列化链的一部分)
- **漏洞类型**: Deserialization → RCE (POP Gadget)
- **检测方法**: 确认存在反序列化入口点；`composer.lock` 中存在 monolog
- **利用前提**: 应用存在可触发的 `unserialize()` 入口点；Monolog 在 autoload 范围内
- **利用链**: 构造 `Monolog\Handler\BufferHandler` → 嵌套 `SyslogUdpHandler` → `__destruct()` 触发 → 写文件 / 命令执行

### Symfony Debug RCE — CVE-2021-21381
- **影响版本**: Symfony 3.4.x ~ 5.x (HttpKernel debug mode)
- **漏洞类型**: RCE (via _fragment route)
- **检测方法**: 访问 `/_fragment`，返回 500 而非 404 说明路由存在；需获取 APP_SECRET
- **利用前提**: debug 模式或 `_fragment` 路由启用；已知 `APP_SECRET`（可通过 `/_profiler` 泄露）
- **利用链**: 利用 APP_SECRET 签名 `_fragment` URL → `HttpKernel::handleSubRequest()` → 执行任意 controller

### Twig SSTI — Server-Side Template Injection
- **CVE**: 无固定 CVE (代码使用不当)
- **影响版本**: Twig 全版本 (取决于使用方式)
- **漏洞类型**: SSTI → RCE
- **检测方法**: 输入 `{{7*7}}`，返回 49 即存在；检查是否使用 `Twig\Environment::createTemplate()`
- **利用前提**: 用户输入被作为模板字符串传入 Twig（非模板变量）
- **利用链**: `{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("id")}}` → RCE

---

## PHP Runtime 安全修复

### PHP 8.x 关键安全变更

| PHP 版本 | 安全修复 | 影响 |
|-----------|----------|------|
| PHP 8.0.0 | `libxml_disable_entity_loader()` 废弃，外部实体默认禁用 | XXE 在 PHP 8.0+ 基本无效（除非显式启用 `LIBXML_NOENT`） |
| PHP 8.0.0 | `assert()` 不再执行字符串代码 | `assert($userInput)` 不再可作为 RCE 向量 |
| PHP 8.1.0 | `$GLOBALS` 变为只读副本 | 通过 `$GLOBALS` 覆盖变量的技巧失效 |
| PHP 8.1.0 | Fibers 引入 | 新的异步代码可能引入竞态条件 |
| PHP 8.2.0 | 动态属性废弃 | 部分反序列化 gadget chain 可能需要调整 |
| PHP 8.3.0 | `json_validate()` 新增 | 不影响安全，但可检测应用是否运行 8.3+ |

### PHP 7.x 遗留安全问题

| PHP 版本 | CVE / 问题 | 类型 |
|-----------|------------|------|
| PHP 7.0 ~ 7.4 | CVE-2019-11043 | Nginx + php-fpm 路径处理 RCE |
| PHP 7.0 ~ 7.2 | `mt_rand()` 种子可预测 | 加密安全缺陷 |
| PHP < 7.4.21 | CVE-2021-21705 | `filter_var()` SSRF / URL 验证绕过 |
| PHP < 7.3.29 | CVE-2021-21702 | SOAP 客户端空指针 DoS |

### CVE-2019-11043 — PHP-FPM + Nginx RCE
- **影响版本**: PHP 7.1.x ~ 7.3.x (特定版本), PHP-FPM
- **漏洞类型**: RCE (Buffer Underflow)
- **检测方法**: 使用 `phuip-fpizdam` 工具扫描；检查 Nginx 配置中 `fastcgi_split_path_info` 正则
- **利用前提**: Nginx 配置使用特定 `fastcgi_split_path_info` 正则且带 `PATH_INFO`；PHP-FPM
- **利用链**: 发送特殊构造的 URL 含 `%0a` → `fastcgi_split_path_info` 正则匹配异常 → env 变量下溢 → 覆写 PHP-FPM worker 配置 → RCE

### CVE-2024-4577 — PHP CGI Argument Injection (Windows)
- **影响版本**: PHP 8.1 < 8.1.29, 8.2 < 8.2.20, 8.3 < 8.3.8 (Windows only)
- **漏洞类型**: RCE (CGI Argument Injection)
- **检测方法**: Windows + PHP CGI 模式；发送 `?%ADd+allow_url_include%3D1+%ADd+auto_prepend_file%3Dphp://input`
- **利用前提**: Windows 系统；PHP 运行在 CGI 模式（非 PHP-FPM/Apache mod_php）
- **利用链**: Windows Best-Fit 字符映射将 `%AD` (soft hyphen) 转为 `-` → 注入 PHP CLI 参数 → `-d` 修改配置 → `auto_prepend_file=php://input` → RCE

---

## 速查：按漏洞类型索引

| 漏洞类型 | 相关 CVE |
|----------|----------|
| RCE | CVE-2021-3129, CVE-2018-15133, ThinkPHP 5.0, CVE-2017-9841, CVE-2016-10033, CVE-2019-11043, CVE-2019-8942, CVE-2024-4577 |
| SQLi | CVE-2021-21263, ThinkPHP 5.1, CVE-2022-21661 |
| Deserialization | CVE-2018-15133, ThinkPHP 6 Session, Monolog chain |
| SSRF | Guzzle CVE-2022-29248 |
| SSTI | Twig (usage-dependent) |
| Auth Bypass | CVE-2017-1001000 (WordPress REST API) |
| XSS | CVE-2024-13918, CVE-2024-13919 |
| File Inclusion | ThinkPHP 多语言, CVE-2023-2745 |
