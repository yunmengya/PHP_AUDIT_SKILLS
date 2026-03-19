# 动态任务创建（Phase 2 完成后执行）

读取 $WORK_DIR/priority_queue.json，按 sink 类型创建 Phase-4 专家任务。

## Sink 类型 → Agent 映射表

| sink_type | agent_name | agent_md 文件 |
|-----------|-----------|--------------|
| eval/system/exec/extract/parse_str | rce-auditor | teams/team4/rce_auditor.md |
| query/execute/DB::raw/whereRaw | sqli-auditor | teams/team4/sqli_auditor.md |
| unserialize/phar | deserial-auditor | teams/team4/deserial_auditor.md |
| include/require | lfi-auditor | teams/team4/lfi_auditor.md |
| file_put_contents/move_uploaded_file | filewrite-auditor | teams/team4/filewrite_auditor.md |
| curl_exec/file_get_contents(url) | ssrf-auditor | teams/team4/ssrf_auditor.md |
| echo/print/模板渲染 | xss-auditor | teams/team4/xss_ssti_auditor.md |
| simplexml_load/DOMDocument | xxe-auditor | teams/team4/xxe_auditor.md |
| auth bypass/mass_assignment/弱比较 | authz-auditor | teams/team4/authz_auditor.md |
| 配置类问题 | config-auditor | teams/team4/config_auditor.md |
| 信息泄露 | infoleak-auditor | teams/team4/infoleak_auditor.md |
| MongoDB/$where/Redis | nosql-auditor | teams/team4/nosql_auditor.md |
| 竞态条件/TOCTOU/并发 | race-auditor | teams/team4/race_condition_auditor.md |
| md5/sha1/rand/弱加密 | crypto-auditor | teams/team4/crypto_auditor.md |
| wp_ajax/xmlrpc/shortcode | wp-auditor | teams/team4/wordpress_auditor.md |
| 价格篡改/流程跳过/业务逻辑 | bizlogic-auditor | teams/team4/business_logic_auditor.md |

## 框架自适应调度

读取 $WORK_DIR/environment_status.json 中的 framework 字段:

- **WordPress** → 强制启动 wp-auditor
- **Laravel** → 强制启动 config-auditor + authz-auditor
- **ThinkPHP** → 强制启动 rce-auditor + sqli-auditor
- **Symfony** → 强制启动 config-auditor
- **所有框架** → 强制启动 infoleak-auditor + bizlogic-auditor

## 创建任务

仅为存在对应 sink 类型（或框架强制启动）的专家创建 Task:

```
task-15: "{type}专家审计"  activeForm="审计 {type} 漏洞"  (blockedBy: [14])
task-16: ...（每种 sink 类型一个）
```

创建 QC-3 Task:
```
task-N: "QC-3 物理取证验证"  activeForm="取证验证"  (blockedBy: [所有 exploit 任务])
```

创建 Phase-4.5 任务:
```
task-M:   "攻击图谱构建"    activeForm="构建攻击图谱"    (blockedBy: [N])
task-M+1: "跨审计员关联分析"  activeForm="关联分析"       (blockedBy: [N])
task-M+2: "修复代码生成"     activeForm="生成修复 Patch"  (blockedBy: [M, M+1])
task-M+3: "PoC 脚本生成"    activeForm="生成 PoC 脚本"   (blockedBy: [M, M+1])
```

创建 Phase-5 任务:
```
task-N+1: "环境清理"    activeForm="清理测试环境"    (blockedBy: [N])
task-N+2: "报告撰写"    activeForm="撰写审计报告"    (blockedBy: [N])
task-N+3: "QC-Final"   activeForm="验证报告完整性"   (blockedBy: [N+1, N+2])
```

**记录所有动态 TASK_ID 映射，供后续 Phase 使用。**
