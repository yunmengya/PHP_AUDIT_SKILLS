# Debug Evidence

| case_id | vuln_type | entry | change_type | result | source_path | notes |
| --- | --- | --- | --- | --- | --- | --- |
| SQLI-001 | sql_injection | GET /user?id= | no_change | confirmed | app/Repo.php:88 | 变量未过滤，1:1 拼接成立 |
