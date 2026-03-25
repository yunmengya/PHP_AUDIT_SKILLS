# Sink 函数定义（完整列表）

本文件定义所有需要检测的 Sink 函数，按漏洞类型分类。所有 Agent 共用此列表。

---

## 1. RCE Sink（远程代码/命令执行）

### 代码执行
| 函数 | 危险等级 | 说明 |
|------|----------|------|
| `eval($code)` | 极高 | 直接执行 PHP 代码 |
| `assert($code)` | 极高 | PHP 7 前可执行代码字符串 |
| `preg_replace('/e', $replacement)` | 极高 | /e 修饰符执行替换为代码（PHP 7 移除） |
| `create_function($args, $code)` | 极高 | 内部使用 eval（PHP 7.2 废弃） |

### 命令执行
| 函数 | 危险等级 | 说明 |
|------|----------|------|
| `system($cmd)` | 极高 | 执行命令并输出结果 |
| `exec($cmd)` | 极高 | 执行命令返回最后一行 |
| `passthru($cmd)` | 极高 | 执行命令并直接输出原始数据 |
| `shell_exec($cmd)` | 极高 | 等同于反引号 \`$cmd\` |
| `popen($cmd, $mode)` | 极高 | 打开进程管道 |
| `proc_open($cmd, ...)` | 极高 | 高级进程控制 |
| `pcntl_exec($path)` | 极高 | 替换当前进程为新程序 |

### 回调执行
| 函数 | 危险等级 | 说明 |
|------|----------|------|
| `call_user_func($callback, ...)` | 高 | 动态调用函数 |
| `call_user_func_array($callback, $args)` | 高 | 动态调用函数（数组参数） |
| `array_map($callback, $array)` | 中 | 回调可被控制时危险 |
| `array_filter($array, $callback)` | 中 | 回调可被控制时危险 |
| `usort($array, $callback)` | 中 | 回调可被控制时危险 |
| `array_walk($array, $callback)` | 中 | 回调可被控制时危险 |

### 动态调用
| 模式 | 危险等级 | 说明 |
|------|----------|------|
| `$func()` | 高 | 变量函数调用 |
| `$$var` | 高 | 可变变量 |
| `${$var}` | 高 | 可变变量（花括号语法） |

### 变量覆盖
| 函数 | 危险等级 | 说明 |
|------|----------|------|
| `extract($array)` | 高 | 将数组导入当前符号表 |
| `parse_str($string)` | 高 | 无第二参数时导入变量到当前作用域 |
| `mb_parse_str($string)` | 高 | 同 parse_str |

---

## 2. SQL Sink（SQL 注入）

### 原生 PHP
| 函数 | 危险等级 | 说明 |
|------|----------|------|
| `$pdo->query($sql)` | 高 | 直接执行 SQL |
| `$pdo->exec($sql)` | 高 | 执行无结果集 SQL |
| `$mysqli->query($sql)` | 高 | MySQLi 查询 |
| `$mysqli->multi_query($sql)` | 极高 | 支持堆叠查询 |
| `mysql_query($sql)` | 高 | 已废弃的 MySQL 函数 |
| `pg_query($conn, $sql)` | 高 | PostgreSQL 查询 |

### Laravel
| 函数 | 危险等级 | 说明 |
|------|----------|------|
| `DB::raw($sql)` | 高 | 原始 SQL 表达式 |
| `DB::select($sql)` | 高 | 原始 SQL 查询（非参数化时） |
| `->whereRaw($sql)` | 高 | 原始 WHERE 条件 |
| `->havingRaw($sql)` | 高 | 原始 HAVING 条件 |
| `->orderByRaw($sql)` | 高 | 原始 ORDER BY |
| `->selectRaw($sql)` | 高 | 原始 SELECT 列 |
| `->groupByRaw($sql)` | 高 | 原始 GROUP BY |

### ThinkPHP
| 函数 | 危险等级 | 说明 |
|------|----------|------|
| `Db::query($sql)` | 高 | 原始 SQL 查询 |
| `Db::execute($sql)` | 高 | 原始 SQL 执行 |
| `->where(字符串拼接)` | 高 | 非数组/闭包形式的 where |

### Yii2
| 函数 | 危险等级 | 说明 |
|------|----------|------|
| `Model::findBySql($sql)` | 高 | 原始 SQL 查询 |
| `createCommand()->rawSql` | 高 | 原始 SQL 命令 |

---

## 3. 文件包含 Sink（LFI/RFI）

| 函数 | 危险等级 | 说明 |
|------|----------|------|
| `include $path` | 极高 | 包含并执行文件 |
| `include_once $path` | 极高 | 同上，仅一次 |
| `require $path` | 极高 | 包含并执行文件（失败致命） |
| `require_once $path` | 极高 | 同上，仅一次 |
| `highlight_file($path)` | 高 | 显示文件源码 |
| `show_source($path)` | 高 | highlight_file 别名 |
| `file_get_contents($path)` | 高 | 读取文件内容 |
| `readfile($path)` | 高 | 输出文件内容 |
| `fread($handle, $length)` | 中 | 读取打开的文件 |
| `file($path)` | 高 | 读取文件到数组 |
| `fpassthru($handle)` | 中 | 输出文件剩余内容 |

---

## 4. 文件写入 Sink

| 函数 | 危险等级 | 说明 |
|------|----------|------|
| `file_put_contents($path, $data)` | 极高 | 写入文件（可写 WebShell） |
| `fwrite($handle, $data)` | 高 | 写入已打开的文件 |
| `fputs($handle, $data)` | 高 | fwrite 别名 |
| `move_uploaded_file($tmp, $dest)` | 极高 | 移动上传文件（文件上传漏洞） |
| `copy($src, $dest)` | 高 | 复制文件 |
| `rename($old, $new)` | 中 | 重命名/移动文件 |
| `mkdir($path)` | 低 | 创建目录 |
| `tempnam($dir, $prefix)` | 低 | 创建临时文件 |
| `ZipArchive::extractTo($dest)` | 高 | 解压到指定目录（路径穿越） |

---

## 5. 反序列化 Sink

| 函数/模式 | 危险等级 | 说明 |
|-----------|----------|------|
| `unserialize($data)` | 极高 | 反序列化对象（触发魔术方法） |
| `phar://` 流协议 | 极高 | 触发 phar 元数据反序列化 |
| Memcached/Redis 对象取出 | 高 | 缓存中存储的序列化对象 |
| `json_decode()` + 魔术方法 | 中 | 需配合特定代码模式 |

### 关联魔术方法（Gadget 入口）
| 方法 | 说明 |
|------|------|
| `__destruct()` | 对象销毁时触发 |
| `__wakeup()` | 反序列化时触发 |
| `__toString()` | 对象转字符串时触发 |
| `__call()` | 调用不存在的方法时触发 |
| `__get()` | 访问不存在的属性时触发 |

---

## 6. SSRF Sink（服务端请求伪造）

| 函数 | 危险等级 | 说明 |
|------|----------|------|
| `curl_init()` + `curl_exec()` | 极高 | cURL 请求 |
| `curl_multi_exec()` | 极高 | 并发 cURL 请求 |
| `file_get_contents($url)` | 高 | 当参数为 URL 时 |
| `fopen($url, $mode)` | 高 | 当参数为 URL 时 |
| `SoapClient($wsdl)` | 高 | SOAP 请求 |
| `SimpleXMLElement($url)` | 高 | 加载远程 XML |
| `get_headers($url)` | 高 | 获取 HTTP 头 |
| `getimagesize($url)` | 中 | 获取远程图片信息 |

---

## 7. XSS/SSTI Sink（跨站脚本/模板注入）

### XSS 输出函数
| 函数/模式 | 危险等级 | 说明 |
|-----------|----------|------|
| `echo $var` | 高 | 直接输出（无转义） |
| `print $var` | 高 | 直接输出 |
| `printf($format, ...)` | 中 | 格式化输出 |
| `sprintf($format, ...)` | 中 | 格式化字符串 |
| `vprintf($format, $args)` | 中 | 数组参数格式化输出 |

### 模板引擎（未转义输出）
| 模式 | 框架 | 危险等级 | 说明 |
|------|------|----------|------|
| `{!! $var !!}` | Laravel Blade | 高 | 未转义输出 |
| `{:$var}` | ThinkPHP | 高 | 未转义输出 |
| `<?= $var ?>` | 原生 PHP | 高 | 短标签输出 |

### SSTI 模板注入
| 模式 | 引擎 | 危险等级 | 说明 |
|------|------|----------|------|
| `{{ user_input }}` | Twig | 极高 | 用户输入进入模板表达式 |
| `{$user_input}` | Smarty | 极高 | 用户输入作为模板变量 |
| `{php}` | Smarty | 极高 | Smarty PHP 标签 |
| 用户输入进入 `render()`/`compile()` | 通用 | 极高 | 模板字符串可控 |

---

## 8. XXE Sink（XML 外部实体注入）

| 函数 | 危险等级 | 说明 |
|------|----------|------|
| `simplexml_load_string($xml)` | 极高 | 解析 XML 字符串 |
| `simplexml_load_file($file)` | 极高 | 解析 XML 文件 |
| `DOMDocument::loadXML($xml)` | 极高 | DOM 解析 XML |
| `DOMDocument::load($file)` | 极高 | DOM 加载 XML 文件 |
| `XMLReader::xml($xml)` | 高 | XMLReader 解析 |
| `XMLReader::open($file)` | 高 | XMLReader 打开文件 |
| `libxml_disable_entity_loader(false)` | 极高 | 显式启用外部实体加载 |

---

## 9. Mass Assignment Sink（批量赋值）

| 模式 | 框架 | 危险等级 | 说明 |
|------|------|----------|------|
| `Model::create($request->all())` | Laravel | 高 | 全部请求参数创建模型 |
| `$model->fill($request->all())` | Laravel | 高 | 全部请求参数填充模型 |
| `$model->update($request->all())` | Laravel | 高 | 全部请求参数更新模型 |
| `$guarded = []` | Laravel | 极高 | 无保护字段，全部可赋值 |
| `$fillable` 包含敏感字段 | Laravel | 中 | role/is_admin/status 等 |

---

## 10. NoSQL Injection Sink

### MongoDB（PHP Driver）
| 函数/模式 | 危险等级 | 说明 |
|-----------|----------|------|
| `$collection->find($filter)` | 高 | 当 $filter 包含用户输入时 |
| `$collection->findOne($filter)` | 高 | 同上 |
| `$collection->aggregate($pipeline)` | 高 | 聚合管道可注入 |
| `$collection->updateOne($filter, $update)` | 高 | $update 中 `$set` 可控 |
| `$collection->deleteMany($filter)` | 极高 | 过滤条件可控导致批量删除 |
| MongoDB `$where` 操作符 | 极高 | 执行 JavaScript 表达式 |
| MongoDB `$regex` 操作符 | 中 | ReDoS 或信息泄露 |
| MongoDB `$gt/$lt/$ne/$in` 操作符 | 高 | 操作符注入绕过认证 |

### Laravel MongoDB（jenssegers）
| 函数/模式 | 危险等级 | 说明 |
|-----------|----------|------|
| `Model::whereRaw($rawQuery)` | 高 | 原始 MongoDB 查询 |
| `Model::where($field, $operator, $value)` | 中 | $operator 可控时 |

### Redis
| 函数/模式 | 危险等级 | 说明 |
|-----------|----------|------|
| `$redis->eval($script)` | 极高 | 执行 Lua 脚本 |
| `$redis->rawCommand($cmd)` | 极高 | 原始命令注入 |

---

## 11. GraphQL Sink

| 模式 | 危险等级 | 说明 |
|------|----------|------|
| 无深度限制的 GraphQL 查询 | 高 | 嵌套查询 DoS |
| 无授权的 Mutation | 极高 | 未鉴权的写操作 |
| `__schema` 内省未禁用 | 中 | Schema 信息泄露 |
| 用户输入直接拼入 GraphQL 查询 | 高 | GraphQL 注入 |
| 无速率限制的批量查询 | 中 | 枚举攻击 |
| Subscription 无鉴权 | 高 | WebSocket 未授权访问 |

---

## 12. 竞态条件 Sink

| 模式 | 危险等级 | 说明 |
|------|----------|------|
| 检查-然后-使用（TOCTOU） | 高 | 文件存在检查和操作之间的竞态 |
| 余额检查后扣款 | 极高 | 双重支付/透支 |
| 限流计数器非原子操作 | 高 | 并发绕过限流 |
| Token 一次性使用非原子验证 | 高 | Token 重放 |
| `file_exists()` + `include()` | 高 | 竞态文件包含 |
| `move_uploaded_file()` + 验证 + 删除 | 高 | 竞态文件上传 |
| `flock()` 缺失的文件操作 | 中 | 并发写入竞态 |

---

## 13. 缓存投毒 Sink

| 模式 | 危险等级 | 说明 |
|------|----------|------|
| `Cache::put($key, $userInput)` | 高 | 缓存内容可控 |
| `Cache::remember($key, $ttl, $callback)` | 中 | 缓存键可控导致投毒 |
| HTTP 缓存头不当 | 中 | `Cache-Control`/`Vary` 错误导致跨用户缓存 |
| CDN/反向代理缓存 | 高 | Web 缓存投毒（参数、Header） |
| Session 存储于共享缓存 | 中 | Session 混淆 |
| 模板缓存写入 | 高 | 模板缓存注入持久 XSS/RCE |

---

## 14. 密码学 Sink

| 函数/模式 | 危险等级 | 说明 |
|-----------|----------|------|
| `md5($password)` / `sha1($password)` | 高 | 不安全的密码哈希（无盐、快速哈希） |
| `rand()` / `mt_rand()` | 高 | 不安全的随机数生成（可预测） |
| `openssl_encrypt` 使用 ECB 模式 | 高 | ECB 模式泄露数据模式 |
| 硬编码 IV / 零 IV | 高 | 初始化向量不随机 |
| `mcrypt_*` | 高 | 已废弃的加密库 |
| `base64_encode` 作为"加密" | 极高 | 编码非加密 |
| `crc32` / `adler32` 用于完整性校验 | 中 | 碰撞容易 |
| `password_hash` 使用 `PASSWORD_DEFAULT` | 低 | 安全但需确认 cost 参数 |
| JWT 使用 HS256 + 弱密钥 | 高 | 密钥可暴力破解 |

---

## 15. WordPress 特定 Sink

| 函数/模式 | 危险等级 | 说明 |
|-----------|----------|------|
| `$wpdb->query($sql)` | 极高 | 原始 SQL（非 prepare） |
| `$wpdb->get_results($sql)` | 高 | 同上 |
| `update_option($key, $value)` | 高 | 覆盖任意配置 |
| `update_user_meta($id, $key, $value)` | 高 | 修改用户元数据 |
| `wp_set_auth_cookie($user_id)` | 极高 | 直接设置认证 Cookie |
| `do_shortcode($content)` | 高 | 短代码注入 |
| `call_user_func` 在 Hook 中 | 高 | 回调控制 |
| `wp_remote_get($url)` | 高 | SSRF |
| `wp_mail` 第5参数 | 高 | 邮件头注入 |
| `sanitize_text_field` 误用 | 中 | 不适合 SQL/HTML 上下文 |
| `wp_kses_post` 不当使用 | 中 | 允许部分 HTML |
| `is_admin()` 用于授权检查 | 极高 | 仅检查是否在后台页面，非权限检查 |

---

## 各类 Sink 漏洞模式识别补充说明

> 以下为对上述已有 Sink 分类的 **漏洞模式识别 (Vulnerability Pattern Recognition)** 补充笔记。
> 重点不仅在函数名本身，而在于 **上下文模式** 和 **直接调用 vs 间接调用** 的区分。

### RCE Sink 漏洞模式识别
- **直接调用 (Direct Call)**：`eval($_GET['code'])` — 参数直接来源于用户输入，无任何过滤。
- **间接调用 (Indirect Call)**：用户输入存入数据库/缓存，后续被 `eval()` 或 `create_function()` 读取并执行（二次注入模式）。
- **上下文模式**：参数来自 `$_GET` / `$_POST` / `$_REQUEST` 且未经 `escapeshellarg()` / `escapeshellcmd()` 包裹直接传入 `system()` / `exec()`。
- **变量函数模式**：`$func = $_GET['action']; $func();` — 函数名可控即为 RCE。
- **回调滥用模式**：`array_map($_GET['func'], $data)` — 回调参数可控时等同代码执行。

### SQL Sink 漏洞模式识别
- **直接调用 (Direct Call)**：`$pdo->query("SELECT * FROM users WHERE id=" . $_GET['id'])` — 字符串拼接 SQL。
- **间接调用 (Indirect Call)**：ORM 的 `whereRaw($userInput)` vs 安全的 `where('id', $userInput)` — 前者危险，后者参数化。
- **上下文模式**：参数来自 `$_GET` 且未经 `intval()` / `(int)` 强制转换直接拼入数字型 SQL 字段。
- **框架陷阱**：Laravel `DB::raw()` 嵌套在 `->where()` 内时容易被忽略：`->where(DB::raw("id = $input"))`。
- **ORDER BY 注入**：`->orderByRaw($_GET['sort'])` — ORDER BY 无法使用参数绑定，常被遗漏。

### 文件包含 Sink 漏洞模式识别
- **直接调用**：`include $_GET['page'] . '.php'` — 路径可控，即使拼接后缀也可用 `%00` (PHP < 5.3.4) 或长路径截断绕过。
- **间接调用**：配置文件中 `$template = $config['theme'];` 后 `include $template` — 配置可被用户修改时形成间接包含。
- **上下文模式**：`file_get_contents($_GET['url'])` 同时作为 SSRF + 文件读取 Sink，需注意协议包装器如 `php://filter`。

### 文件写入 Sink 漏洞模式识别
- **直接调用**：`file_put_contents($_GET['file'], $_POST['data'])` — 文件名和内容均可控。
- **间接调用**：上传文件名未做随机化，`move_uploaded_file($tmp, 'uploads/' . $_FILES['f']['name'])` — 可写入 `.php` 后缀。
- **上下文模式**：解压缩操作 `ZipArchive::extractTo()` 未校验压缩包内文件路径，导致 `../` 路径穿越写入任意位置。

### 反序列化 Sink 漏洞模式识别
- **直接调用**：`unserialize($_COOKIE['data'])` — 反序列化来源于客户端可控数据。
- **间接调用**：`phar://` 协议触发 — `file_exists('phar://user_upload.jpg')` 可触发 phar 元数据反序列化。
- **上下文模式**：`unserialize()` 的第二参数 `allowed_classes` 未设置或设为 `true`，允许任意类实例化。

### SSRF Sink 漏洞模式识别
- **直接调用**：`curl_setopt($ch, CURLOPT_URL, $_GET['url']); curl_exec($ch);` — URL 直接可控。
- **间接调用**：`file_get_contents($config['webhook_url'])` — webhook 地址在管理后台配置，管理员账户被攻破后形成 SSRF。
- **上下文模式**：仅检查 `http://` / `https://` 前缀但未验证目标 IP（可用 DNS Rebinding 绕过）。内网地址 `127.0.0.1` / `169.254.169.254` / `10.x.x.x` 应在黑名单中。

### XSS/SSTI Sink 漏洞模式识别
- **直接调用**：`echo $_GET['name']` — 输入直接输出无 `htmlspecialchars()` 转义。
- **间接调用**：数据库存储后在页面渲染 — `echo $article->content` — 存储型 XSS。
- **上下文模式**：区分 HTML 上下文、JavaScript 上下文、URL 上下文 — `htmlspecialchars()` 在 JS 上下文中不够用，需 `json_encode()` + `JSON_HEX_TAG`。
- **模板引擎**：Blade `{!! $var !!}` vs `{{ $var }}` — 前者未转义，后者自动转义。

### XXE Sink 漏洞模式识别
- **直接调用**：`simplexml_load_string($_POST['xml'])` — 未调用 `libxml_disable_entity_loader(true)` 或未设置 `LIBXML_NOENT` 标志。
- **上下文模式**：PHP 8.0+ 中 `libxml_disable_entity_loader()` 已废弃，需使用 `LIBXML_NOENT` 标志位。旧代码迁移时容易遗漏。

### Mass Assignment Sink 漏洞模式识别
- **直接调用**：`User::create($request->all())` 且 `$fillable` 包含 `role` / `is_admin`。
- **间接调用**：`$model->forceFill($request->all())` — 绕过 `$fillable` 保护。
- **上下文模式**：检查 `$guarded = []`（空数组）意味着所有字段均可赋值，极其危险。

---

## 16. JWT 相关 Sink

> JWT (JSON Web Token) 在 PHP 中的常见安全陷阱，涵盖 token 解析、签名验证、算法混淆等场景。

| 函数/模式 | 危险等级 | 上下文模式说明 |
|-----------|----------|----------------|
| `JWT::decode($token, $key, [])` — 算法数组为空 | 极高 | `firebase/php-jwt` 库中 `JWT::decode()` 第三参数未指定允许的算法列表，攻击者可将 header 中 `alg` 设为 `none` 绕过签名验证。**正确做法**：指定 `['HS256']` 或使用 `Key` 对象明确算法。 |
| `JWT::decode($token, $key)` — 未区分 HS256 / RS256 | 极高 | 算法混淆攻击 (Algorithm Confusion)：当服务端使用 RSA 公钥验证时，攻击者将 `alg` 改为 `HS256` 并用公钥作为 HMAC 密钥签名，导致验证通过。**上下文模式**：检查 decode 时是否用 `new Key($publicKey, 'RS256')` 明确绑定算法。 |
| 手动 `base64_decode()` + `json_decode()` 解析 JWT | 高 | 手动拆分 JWT (`explode('.', $token)`) 然后 `base64_decode` + `json_decode` 读取 payload，但 **跳过了签名验证步骤**。攻击者可任意篡改 payload 内容（如 `user_id`、`role`）。 |
| `openssl_verify()` 返回值使用 `==` 而非 `===` | 高 | `openssl_verify()` 返回 `1`（成功）、`0`（失败）、`-1`（错误）。使用 `if(openssl_verify(...) == true)` 时，`-1` 也会被视为 `true`（PHP 类型转换），导致错误时仍然通过验证。**必须** `=== 1` 严格比较。 |
| JWT `exp` / `nbf` 声明未校验 | 中 | 解码 JWT 后未检查 `exp`（过期时间）或 `nbf`（生效时间），导致过期 token 永久有效。部分库需要显式开启 `leeway` 配置。 |
| JWT Secret 硬编码或弱密钥 | 高 | `JWT::encode($payload, 'secret123', 'HS256')` — 使用短/可预测密钥，攻击者可暴力破解。**上下文模式**：检查密钥是否来自 `env()` 或配置文件，长度是否 >= 256 bit。 |
| `kid` Header 参数注入 | 极高 | JWT header 中 `kid` (Key ID) 字段如果直接拼入文件路径或 SQL 查询（如 `file_get_contents("/keys/" . $header->kid)`），可导致目录穿越或 SQL 注入获取任意密钥。 |

---

## 17. Open Redirect Sink（开放重定向）

> 开放重定向漏洞允许攻击者构造合法域名 URL 将用户重定向到恶意网站，常用于钓鱼攻击。

| 函数/模式 | 危险等级 | 上下文模式说明 |
|-----------|----------|----------------|
| `header("Location: " . $userInput)` | 极高 | 用户输入直接拼入 `Location` 响应头。**上下文模式**：参数来自 `$_GET['redirect']` / `$_GET['url']` / `$_GET['next']` / `$_GET['return_to']` 等常见参数名且未做白名单校验。攻击者可设置为 `https://evil.com`。 |
| `header("Location: " . $url)` 仅检查前缀 | 高 | 使用 `strpos($url, 'https://example.com') === 0` 做校验，但可被 `https://example.com.evil.com` 绕过。**正确做法**：使用 `parse_url()` 提取 host 后与白名单严格比较。 |
| Laravel `redirect($userInput)` / `Redirect::to($userInput)` | 高 | 框架 `redirect()` 辅助函数接受完整 URL（含外部域名）。**上下文模式**：检查传入 `redirect()` 的参数是否来自用户输入且未经 `url()->isValidUrl()` 或域名白名单验证。 |
| ThinkPHP `$this->redirect($url)` | 高 | ThinkPHP 控制器 `redirect()` 方法同样接受外部 URL。**上下文模式**：参数来自 `input('get.url')` 或 `$request->param('url')` 未经验证。 |
| `<meta http-equiv="refresh" content="0;url=$userInput">` | 高 | HTML meta 标签重定向，用户输入嵌入 `url=` 后。常见于前端模板中 `<meta ... content="0;url=<?= $redirect ?>">`。即使 `header()` 做了防护，HTML 层面的重定向也需检查。 |
| JavaScript `window.location = phpVar` | 中 | PHP 将用户输入赋值给 JavaScript 变量后用于重定向：`<script>window.location = '<?= $url ?>';</script>`。需同时防范 XSS 和 Open Redirect。 |
| `wp_redirect($url)` 未设 `$safe` 参数 | 高 | WordPress 的 `wp_redirect()` 默认不限制目标域名。应使用 `wp_safe_redirect()` 代替，后者仅允许重定向到白名单域名。 |

---

## 18. CORS 配置 Sink（跨域资源共享配置不当）

> CORS 配置错误可导致跨域数据窃取，尤其在使用 `Access-Control-Allow-Credentials: true` 时。

| 函数/模式 | 危险等级 | 上下文模式说明 |
|-----------|----------|----------------|
| `header("Access-Control-Allow-Origin: " . $_SERVER['HTTP_ORIGIN'])` | 极高 | 将请求中的 `Origin` 头直接回显为 `Access-Control-Allow-Origin`，等同于允许任意域访问。**上下文模式**：检查是否存在 `$_SERVER['HTTP_ORIGIN']` 直接拼入响应头且无白名单校验。 |
| `Access-Control-Allow-Credentials: true` + 动态 Origin 回显 | 极高 | 当同时设置 `Access-Control-Allow-Credentials: true` 和动态回显 Origin 时，攻击者可从恶意站点读取已认证用户的敏感数据（Cookie 会被发送）。**这是 CORS 配置中最危险的组合。** |
| `Access-Control-Allow-Origin: *` + 敏感 API | 高 | 虽然 `*` 不允许携带 Credentials，但对无需认证的敏感数据（如内网 API、用户公开信息）仍然危险。**上下文模式**：检查使用 `*` 的 API 是否返回任何不应公开的信息。 |
| Origin 白名单校验使用 `strpos()` / `preg_match()` 不当 | 高 | `if(strpos($origin, 'example.com') !== false)` 可被 `evil-example.com` 或 `example.com.evil.com` 绕过。**正确做法**：完整域名匹配 `in_array($origin, $allowedOrigins)`。 |
| `Access-Control-Allow-Headers` 包含 `Authorization` 但 Origin 未限制 | 高 | 允许跨域发送 `Authorization` 头（如 Bearer Token），但 Origin 未做白名单，导致任意站点可携带 token 请求 API。**上下文模式**：检查 preflight 响应中 `Allow-Headers` 包含敏感头时 Origin 是否受限。 |
| Laravel `cors.php` 配置 `'allowed_origins' => ['*']` | 中 | Laravel 框架 `config/cors.php` 中 `allowed_origins` 设为通配符。需结合 `supports_credentials` 字段判断：若 `supports_credentials = true` 则为极高危险。 |
| Nginx/Apache 层 CORS 配置覆盖应用层 | 中 | Web 服务器层面配置 `add_header Access-Control-Allow-Origin *` 会覆盖 PHP 应用层的精细 CORS 策略，导致应用层白名单失效。**上下文模式**：需同时审查 `.htaccess` / Nginx conf 和 PHP 代码。 |

---

## 19. HTTP Method 检查缺失 Sink（HTTP 方法限制不当）

> HTTP 方法未正确限制可导致 CSRF 绕过、信息泄露、非预期操作等安全问题。

| 模式 | 危险等级 | 上下文模式说明 |
|------|----------|----------------|
| 路由仅注册 GET/POST 但未限制 TRACE/OPTIONS 等方法 | 高 | Web 服务器默认启用 TRACE 方法可导致 Cross-Site Tracing (XST) 攻击，泄露 `HttpOnly` Cookie。**上下文模式**：检查 Apache 是否配置 `TraceEnable Off`，Nginx 默认不支持 TRACE 但自定义配置可能启用。 |
| `Route::any($uri, $handler)` 注册路由 | 高 | Laravel `Route::any()` / ThinkPHP `Route::rule($uri, $handler)` 默认匹配所有 HTTP 方法。**上下文模式**：敏感操作（如删除、修改密码）使用 `any()` 注册时，可被 GET 请求触发（CSRF via `<img src>`），绕过 CSRF Token 保护（因 GET 通常不检查 token）。 |
| Middleware 仅拦截特定方法，遗漏其他方法 | 高 | CSRF Middleware 通常排除 GET/HEAD/OPTIONS，但如果路由同时接受 PUT/PATCH/DELETE 且 Middleware 未覆盖这些方法，则可被绕过。**上下文模式**：检查 `VerifyCsrfToken` Middleware 的 `$except` 列表和方法过滤逻辑。 |
| REST API 未限制 DELETE/PUT 方法 | 极高 | API 路由未对 DELETE/PUT 方法做额外权限校验。**上下文模式**：`Route::resource()` 自动注册包含 `destroy` (DELETE) 和 `update` (PUT) 方法，若 Controller 中这些 Action 缺少独立权限检查（仅依赖统一 `auth` Middleware），普通用户可能删除/修改他人资源。 |
| `$_SERVER['REQUEST_METHOD']` 检查可被覆盖 | 高 | Laravel 等框架支持 `_method` 参数覆盖 HTTP 方法：`<input type="hidden" name="_method" value="DELETE">`。**上下文模式**：检查是否存在方法覆盖 (Method Spoofing) 且无 CSRF 保护的表单，攻击者可利用此机制发送 DELETE/PUT 请求。 |
| HEAD 方法泄露信息 | 中 | HEAD 请求通常返回与 GET 相同的响应头但无 body。某些 API 在响应头中泄露敏感信息（如 `X-Total-Count`、自定义调试头）。**上下文模式**：检查是否有仅在 GET 上做权限检查但 HEAD 方法未覆盖的情况。 |
| WebDAV 方法未禁用 | 高 | PROPFIND、MKCOL、COPY、MOVE 等 WebDAV 方法若未在 Web 服务器层禁用，可导致目录遍历、文件操作等。**上下文模式**：检查 Apache 是否加载 `mod_dav`，Nginx 是否配置了 dav 模块。 |

## 20. CRLF Injection Sink（CRLF 注入 / HTTP 响应拆分）

> CRLF 注入通过在 HTTP 头部注入 `\r\n` 换行符，可导致响应拆分、XSS、缓存投毒、Session Fixation。

| 模式 | 危险等级 | 上下文模式说明 |
|------|----------|----------------|
| `header("Location: " . $userInput)` | 极高 | 用户输入直接拼接到 Location 头，若未过滤 `\r\n`/`%0d%0a` 可注入任意头部。PHP ≥7.0 会检查多行头但框架封装可能绕过。 |
| `header("X-Custom: " . $value)` | 高 | 自定义头部值包含用户输入。攻击者注入 `\r\nSet-Cookie: session=evil` 实现 Session Fixation。 |
| `setcookie($name, $value)` 中 `$name`/`$value` 来自用户输入 | 高 | cookie name/value 中的 `\r\n` 可注入额外 Set-Cookie 头。PHP 7.0+ 对 `$name` 有限制但 `$value` 仍需检查。 |
| `mail($to, $subject, $body, $additionalHeaders)` | 极高 | `$additionalHeaders` 包含用户输入时，可注入 CC/BCC/Content-Type 等邮件头，实现邮件劫持或钓鱼。 |
| `$response->header($key, $value)` 框架响应头设置 | 高 | Laravel/Symfony 的 Response 对象设置头部，若 `$value` 未过滤换行符，可绕过 PHP 原生 `header()` 的检查。 |
| `header("Content-Disposition: attachment; filename=\"$filename\"")` | 高 | 文件名包含 `\r\n` 可注入额外头部，结合 `Content-Type` 注入实现 XSS。 |

## 21. CSRF Sink（跨站请求伪造）

> CSRF 利用浏览器自动携带 Cookie 的特性，诱导已认证用户执行非预期操作。

| 模式 | 危险等级 | 上下文模式说明 |
|------|----------|----------------|
| POST 表单无 `csrf_token`/`_token` 隐藏字段 | 极高 | 状态变更表单缺少 CSRF Token。检查 `<form method="POST">` 是否包含 `@csrf`(Laravel)/`csrf_token()`(Symfony)/`__token__`(ThinkPHP)。 |
| `VerifyCsrfToken::$except` 排除列表过宽 | 高 | Laravel CSRF 中间件的 `$except` 数组包含通配符（如 `api/*`、`webhook/*`），可能暴露敏感操作。 |
| AJAX 请求未设置 `X-CSRF-TOKEN` 头 | 高 | 前端 AJAX 调用 POST/PUT/DELETE 接口时未从 `<meta name="csrf-token">` 或 cookie 读取 Token 并附加到请求头。 |
| `Route::any()` / `Route::match(['get','post'])` | 高 | 状态变更操作同时接受 GET 请求，绕过 CSRF 保护（GET 通常不检查 Token）。 |
| API 路由使用 Session 认证但无 CSRF 保护 | 极高 | `api.php` 路由使用 `web` 中间件组（含 Session），但 API 通常不检查 CSRF Token。 |
| 自定义 CSRF 实现验证不严格 | 高 | 自行实现的 Token 验证逻辑存在缺陷：空值通过、Token 不轮换、可预测的 Token 生成算法。 |
| `session.cookie_samesite` 未设置或为 `None` | 高 | php.ini 或 `session_set_cookie_params()` 中 SameSite 未配置，浏览器默认行为因版本而异。 |

## 22. Session/Cookie Security Sink（Session 与 Cookie 安全）

> Session 管理缺陷可导致 Session Fixation、Session Hijacking、敏感数据泄露等。

| 模式 | 危险等级 | 上下文模式说明 |
|------|----------|----------------|
| `session_start()` 后认证成功但未调用 `session_regenerate_id(true)` | 极高 | Session Fixation 核心缺陷：攻击者预设 Session ID，受害者登录后 ID 未更换，攻击者直接复用。 |
| `session.cookie_httponly = 0` 或 `setcookie()` 无 HttpOnly | 极高 | Session Cookie 可被 JavaScript 读取（`document.cookie`），XSS → Session Hijacking 链路完整。 |
| `session.cookie_secure = 0` 且站点有 HTTPS | 高 | Session Cookie 在 HTTP 明文传输中泄露。MITM 可截获 Session ID。 |
| `session.use_strict_mode = 0` | 高 | PHP 接受客户端提交的未初始化 Session ID，是 Session Fixation 的前提条件。 |
| `session.use_only_cookies = 0` | 高 | 允许通过 URL 参数传递 Session ID（`?PHPSESSID=xxx`），Referer 泄露 + 日志记录风险。 |
| 登出流程未完整销毁 Session | 高 | 仅调用 `session_destroy()` 但未清除 Cookie 和 `$_SESSION`，或未使旧 ID 失效。 |
| `/tmp/sess_*` 文件权限 0644（共享主机） | 高 | 共享主机环境下其他用户可读取 Session 文件，泄露 Session 数据。 |
| `session.serialize_handler` 不一致 | 极高 | 不同代码路径使用不同的序列化处理器（php/php_serialize），可导致 Session 反序列化注入。 |

## 23. LDAP Injection Sink（LDAP 注入）

> LDAP 注入通过在 LDAP 查询过滤器或 DN 中注入特殊字符，可导致认证绕过、数据泄露、权限提升。

| 模式 | 危险等级 | 上下文模式说明 |
|------|----------|----------------|
| `ldap_search($conn, $dn, "(uid=" . $userInput . ")")` | 极高 | 用户输入直接拼接到 LDAP 过滤器。攻击者注入 `*)(uid=*))(|(uid=*` 可遍历所有用户。 |
| `ldap_bind($conn, $userDN, $password)` 中 `$password` 为空字符串 | 极高 | LDAP 匿名绑定或空密码绑定，某些 LDAP 服务器接受空密码作为认证通过。 |
| `ldap_search($conn, $baseDN, $filter)` 中 `$filter` 来自表单 | 高 | 搜索过滤器包含用户输入，可注入 OR/AND 逻辑操作符改变查询语义。 |
| Symfony `LdapAdapter` / `adldap2` 的查询构造 | 高 | 框架 LDAP 包的查询构造器若使用字符串拼接而非参数化，同样存在注入风险。 |
| `ldap_add()`/`ldap_modify()` 中属性值来自用户输入 | 高 | 写入操作中注入额外属性（如 `userPassword`）可导致权限提升。 |
| LDAP DN 拼接: `"cn=" . $username . ",ou=users,dc=example"` | 高 | DN 组件注入可导致访问不同 OU 下的资源。特殊字符 `,`, `+`, `"`, `\`, `<`, `>`, `;` 需转义。 |

## 24. Logging Security Sink（日志安全）

> 日志安全缺陷可导致日志注入（伪造条目）、敏感数据泄露、日志文件 Web 暴露、日志包含 RCE。

| 模式 | 危险等级 | 上下文模式说明 |
|------|----------|----------------|
| `error_log($userInput)` / `Log::info($userInput)` | 高 | 用户输入直接写入日志。注入 `\n[2024-01-01] CRITICAL:` 可伪造日志条目，干扰安全监控。 |
| `Log::info("Login: " . $username . " password: " . $password)` | 极高 | 密码/Token/API Key 等敏感数据明文记录到日志文件。违反合规要求（PCI-DSS, GDPR）。 |
| 日志文件存储在 `public/` 或 `storage/logs/` 且 Web 可访问 | 极高 | `storage/logs/laravel.log` 若未被 `.htaccess`/nginx 规则阻止访问，可直接下载泄露全部日志。 |
| `ini_set('display_errors', '1')` 在生产环境 | 高 | 错误信息（含文件路径、SQL 语句、堆栈）直接显示给用户。 |
| 日志文件 include: `include($logPath)` | 极高 | 若攻击者可控日志内容（注入 `<?php system($cmd); ?>`）且日志文件被包含，实现 RCE。 |
| 无关键安全事件审计 | 高 | 登录失败、权限变更、密码重置等安全事件未记录，影响事后取证和实时告警。 |
