# PHP 攻击面 → Agent 切分参考

## 切分原则
- 由攻击面推导，不套固定模板。
- 搜索模式不重叠，避免重复扫描。
- Agent 之间可完全并行。

## 攻击面映射
- 认证与授权链 → `php-auth-audit`
- SQL 读写路径 → `php-sql-audit`
- 文件上传/下载/包含 → `php-file-audit`
- 命令/代码执行 → `php-rce-audit`
- 出站请求/解析器 → `php-ssrf-xxe-audit`
- 模板渲染/输出 → `php-xss-ssti-audit`
- 反序列化/Phar → `php-serialize-audit`
- 变量覆盖/动态变量 → `php-var-override-audit`
- CSRF 防护 → `php-csrf-audit`

## 搜索模式不重叠示例
- Auth Agent：JWT/Token/Session/Middleware/Policy
- SQL Agent：query/prepare/execute/拼接 SQL
- File Agent：upload/include/readfile/file_get_contents
- SSRF Agent：curl/file_get_contents/http client
- XSS Agent：echo/print/template render

## Agent 数量建议
- 小型项目（<10K LOC）：2-3 个
- 中型项目（10K-50K LOC）：3-5 个
- 大型项目（50K-200K LOC）：5-9 个
- 超大型（>200K LOC）：6-10 个
