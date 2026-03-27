#!/usr/bin/env bash
# ============================================================
# audit_db.sh — PHP 审计 SQLite 数据库工具
# ============================================================
# 替代 JSONL 文件，提供 ACID 事务、索引查询、并发安全
#
# 两个数据库:
#   1. 全局记忆库: ~/.php_audit/attack_memory.db  (跨审计持久化)
#   2. 审计会话库: $WORK_DIR/audit_session.db      (单次审计)
#
# 用法:
#   audit_db.sh init-memory              初始化全局记忆库
#   audit_db.sh init-session <WORK_DIR>  初始化审计会话库
#
#   # 攻击记忆 (全局)
#   audit_db.sh memory-write  <json>     写入一条攻击记忆
#   audit_db.sh memory-query  <条件>     查询匹配记忆
#   audit_db.sh memory-stats             统计记忆库
#   audit_db.sh memory-maintain          容量维护
#
#   # 共享发现 (会话)
#   audit_db.sh finding-write <WORK_DIR> <json>                写入发现
#   audit_db.sh finding-read  <WORK_DIR> [finding_type] [agent] 读取发现
#   audit_db.sh finding-consume <WORK_DIR> <id> <agent>        标记已消费
#   audit_db.sh finding-stats <WORK_DIR>                       统计发现
#
#   # 迁移工具
#   audit_db.sh migrate-memory [jsonl_path]   从 JSONL 迁移记忆
#   audit_db.sh migrate-findings <WORK_DIR>   从 JSONL 迁移发现
#
#   # 质检记录 (会话)
#   audit_db.sh qc-write <WORK_DIR> <json>   写入质检记录
#   audit_db.sh qc-read  <WORK_DIR> [phase]  读取质检记录
#   audit_db.sh qc-stats <WORK_DIR>          质检统计汇总
#
#   # 关系型记忆图 (全局)
#   audit_db.sh init-graph                    初始化图表
#   audit_db.sh graph-node-write <json>       写入漏洞节点
#   audit_db.sh graph-edge-write <json>       写入关系边
#   audit_db.sh graph-neighbors  <node_id>    查询节点关联
#   audit_db.sh graph-by-data-object <obj>    按数据对象查询
#   audit_db.sh graph-export <WORK_DIR>       导出完整图结构
# ============================================================
set -euo pipefail

MEMORY_DIR="${HOME}/.php_audit"
MEMORY_DB="${MEMORY_DIR}/attack_memory.db"

# ── SQLite 配置：WAL 模式 + 合理超时 ──
sql() {
    local db="$1"; shift
    sqlite3 -batch -json "$db" ".timeout 5000" "$@" 2>>"${WORK_DIR:-.}/.audit_state/error.log"
}

sql_exec() {
    local db="$1"; shift
    sqlite3 -batch "$db" ".timeout 5000" "$@" 2>>"${WORK_DIR:-.}/.audit_state/error.log"
}

sql_raw() {
    local db="$1"; shift
    sqlite3 -batch "$db" "$@" 2>>"${WORK_DIR:-.}/.audit_state/error.log"
}

escape_sql() {
    printf '%s' "${1//\'/\'\'}"
}

# ===========================================================
# 初始化：全局攻击记忆库
# ===========================================================
init_memory() {
    mkdir -p "$MEMORY_DIR"
    sql_raw "$MEMORY_DB" <<'SQL'
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS attack_memory (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    sink_type       TEXT NOT NULL,
    sink_function   TEXT,
    framework       TEXT NOT NULL,
    framework_version TEXT,
    php_version     TEXT NOT NULL,
    waf_type        TEXT DEFAULT 'none',
    status          TEXT NOT NULL CHECK(status IN ('confirmed','failed','partial')),
    rounds_used     INTEGER NOT NULL,
    max_rounds      INTEGER,
    successful_round INTEGER,
    successful_payload_type TEXT,
    successful_payload_summary TEXT,
    bypass_technique TEXT,
    eliminated_strategies TEXT,  -- JSON array as text
    failure_reason  TEXT,
    environment_factors TEXT,    -- JSON object as text
    project_hash    TEXT,
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);

-- 高频查询索引
CREATE INDEX IF NOT EXISTS idx_memory_lookup
    ON attack_memory(sink_type, framework, status);
CREATE INDEX IF NOT EXISTS idx_memory_php
    ON attack_memory(sink_type, php_version);
CREATE INDEX IF NOT EXISTS idx_memory_status
    ON attack_memory(status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_memory_project
    ON attack_memory(project_hash);
SQL
    echo "✅ 全局记忆库就绪: $MEMORY_DB"

    # 自动初始化关系型图表（同一 DB 文件）
    init_graph
}

# ===========================================================
# 初始化：审计会话库
# ===========================================================
init_session() {
    local work_dir="${1:?用法: audit_db.sh init-session <WORK_DIR>}"
    local session_db="${work_dir}/audit_session.db"

    sql_raw "$session_db" <<'SQL'
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS shared_findings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    source_agent    TEXT NOT NULL,
    finding_type    TEXT NOT NULL CHECK(finding_type IN (
        'credential','internal_url','secret_key','endpoint','bypass_method','config_value'
    )),
    priority        TEXT NOT NULL CHECK(priority IN ('critical','high','medium')),
    data_key        TEXT NOT NULL,
    data_value      TEXT NOT NULL,
    data_context    TEXT,
    source_location TEXT,
    target_agents   TEXT,  -- JSON array as text
    consumed_by     TEXT DEFAULT '[]'  -- JSON array as text
);

-- 高频查询索引
CREATE INDEX IF NOT EXISTS idx_findings_type
    ON shared_findings(finding_type, priority);
CREATE INDEX IF NOT EXISTS idx_findings_agent
    ON shared_findings(source_agent);
CREATE INDEX IF NOT EXISTS idx_findings_key
    ON shared_findings(data_key);
CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_dedup
    ON shared_findings(source_agent, finding_type, data_key, data_value);

-- 漏洞情报缓存表（vuln_intel.sh 查询结果）
CREATE TABLE IF NOT EXISTS vuln_intel (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    source          TEXT NOT NULL,
    package         TEXT NOT NULL,
    vuln_id         TEXT NOT NULL,
    aliases         TEXT,  -- JSON array
    summary         TEXT,
    severity        TEXT,
    cvss_score      REAL,
    affected_ranges TEXT,
    references_     TEXT,  -- JSON array (references is reserved word)
    published       TEXT,
    fetched_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_vuln_dedup
    ON vuln_intel(vuln_id, package);
CREATE INDEX IF NOT EXISTS idx_vuln_severity
    ON vuln_intel(severity, package);

-- 质检记录表（quality-checker 写入）
CREATE TABLE IF NOT EXISTS qc_records (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    qc_id           TEXT NOT NULL,
    phase           TEXT NOT NULL,
    target_agent    TEXT NOT NULL,
    verdict         TEXT NOT NULL CHECK(verdict IN ('pass','fail')),
    pass_count      INTEGER NOT NULL DEFAULT 0,
    total_count     INTEGER NOT NULL DEFAULT 0,
    failed_items    TEXT,           -- JSON array of failed item numbers
    warn_items      TEXT,           -- JSON array of warn item numbers
    metrics         TEXT,           -- JSON object with coverage metrics
    redo_count      INTEGER NOT NULL DEFAULT 0,
    timestamp       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);

CREATE INDEX IF NOT EXISTS idx_qc_phase
    ON qc_records(phase, target_agent);
CREATE UNIQUE INDEX IF NOT EXISTS idx_qc_dedup
    ON qc_records(qc_id);
SQL
    echo "✅ 会话库就绪: $session_db"
}

# ===========================================================
# 攻击记忆：写入
# ===========================================================
memory_write() {
    local json="${1:?用法: audit_db.sh memory-write '<json>'}"

    # 从 JSON 提取字段并插入
    local stmt
    stmt=$(echo "$json" | jq -r '
        "INSERT INTO attack_memory (sink_type, sink_function, framework, framework_version, php_version, waf_type, status, rounds_used, max_rounds, successful_round, successful_payload_type, successful_payload_summary, bypass_technique, eliminated_strategies, failure_reason, environment_factors, project_hash) VALUES ("
        + ([
            .sink_type, .sink_function, .framework, .framework_version,
            .php_version, (.waf_type // "none"), .status,
            (.rounds_used | tostring), (.max_rounds // null | tostring),
            (.successful_round // null | tostring),
            .successful_payload_type, .successful_payload_summary,
            .bypass_technique,
            (.eliminated_strategies // [] | tojson),
            .failure_reason,
            (.environment_factors // {} | tojson),
            .project_hash
        ] | map(
            if . == null or . == "null" then "NULL"
            elif test("^[0-9]+$") then .
            else "\u0027" + gsub("\u0027"; "\u0027\u0027") + "\u0027"
            end
        ) | join(","))
        + ");"
    ')

    sql_exec "$MEMORY_DB" "$stmt"
    echo "✅ 记忆已写入"
}

# ===========================================================
# 攻击记忆：查询
# ===========================================================
memory_query() {
    local sink_type="${1:?用法: audit_db.sh memory-query <sink_type> [framework] [php_major] [waf_type]}"
    local framework="${2:-}"
    local php_major="${3:-}"
    local waf_type="${4:-}"

    local where="sink_type = '$(escape_sql "$sink_type")'"
    [ -n "$framework" ] && where="${where} AND framework = '$(escape_sql "$framework")'"
    [ -n "$php_major" ] && where="${where} AND php_version LIKE '$(escape_sql "$php_major").%'"
    [ -n "$waf_type" ]  && where="${where} AND waf_type = '$(escape_sql "$waf_type")'"

    sql "$MEMORY_DB" "
        SELECT sink_type, sink_function, framework, php_version, waf_type,
               status, rounds_used, successful_round,
               successful_payload_type, bypass_technique,
               eliminated_strategies, failure_reason, created_at
        FROM attack_memory
        WHERE ${where}
        ORDER BY
            CASE status WHEN 'confirmed' THEN 0 WHEN 'partial' THEN 1 ELSE 2 END,
            created_at DESC
        LIMIT 20;
    "
}

# ===========================================================
# 攻击记忆：统计
# ===========================================================
memory_stats() {
    echo "=== 攻击记忆统计 ==="
    sql_exec "$MEMORY_DB" "
        SELECT '总记录: ' || COUNT(*) FROM attack_memory;
        SELECT '  confirmed: ' || COUNT(*) FROM attack_memory WHERE status='confirmed';
        SELECT '  failed: ' || COUNT(*) FROM attack_memory WHERE status='failed';
        SELECT '  partial: ' || COUNT(*) FROM attack_memory WHERE status='partial';
        SELECT '---';
        SELECT '按 sink_type 分布:';
        SELECT '  ' || sink_type || ': ' || COUNT(*) || ' (' || SUM(CASE WHEN status='confirmed' THEN 1 ELSE 0 END) || ' confirmed)'
        FROM attack_memory GROUP BY sink_type ORDER BY COUNT(*) DESC LIMIT 10;
        SELECT '---';
        SELECT '按 framework 分布:';
        SELECT '  ' || framework || ': ' || COUNT(*)
        FROM attack_memory GROUP BY framework ORDER BY COUNT(*) DESC LIMIT 5;
    "
}

# ===========================================================
# 攻击记忆：容量维护
# ===========================================================
memory_maintain() {
    local total
    total=$(sql_exec "$MEMORY_DB" "SELECT COUNT(*) FROM attack_memory;")

    if [ "$total" -le 1000 ]; then
        echo "记忆库 ${total} 条，无需维护（阈值 1000）"
        return 0
    fi

    echo "记忆库 ${total} 条，执行维护 ..."

    # 保留所有 confirmed + 最近 500 条（取并集）
    sql_exec "$MEMORY_DB" "
        DELETE FROM attack_memory
        WHERE id NOT IN (
            SELECT id FROM attack_memory WHERE status = 'confirmed'
            UNION
            SELECT id FROM attack_memory ORDER BY created_at DESC LIMIT 500
        );
    "

    local after
    after=$(sql_exec "$MEMORY_DB" "SELECT COUNT(*) FROM attack_memory;")
    echo "✅ 维护完成: ${total} → ${after} 条"

    # 关系型图表维护: 节点超过 5000 条时清理最老的 speculative 节点
    local node_count
    node_count=$(sql_exec "$MEMORY_DB" "SELECT COUNT(*) FROM memory_nodes;" 2>/dev/null || echo "0")
    if [ "$node_count" -gt 5000 ]; then
        echo "图节点 ${node_count} 条，清理 speculative 节点 ..."
        sql_exec "$MEMORY_DB" "
            DELETE FROM memory_edges
            WHERE source_node IN (
                SELECT node_id FROM memory_nodes
                WHERE status = 'speculative'
                ORDER BY created_at ASC
                LIMIT $((node_count - 4500))
            ) OR target_node IN (
                SELECT node_id FROM memory_nodes
                WHERE status = 'speculative'
                ORDER BY created_at ASC
                LIMIT $((node_count - 4500))
            );
            DELETE FROM memory_nodes
            WHERE node_id IN (
                SELECT node_id FROM memory_nodes
                WHERE status = 'speculative'
                ORDER BY created_at ASC
                LIMIT $((node_count - 4500))
            );
        "
        local after_nodes
        after_nodes=$(sql_exec "$MEMORY_DB" "SELECT COUNT(*) FROM memory_nodes;")
        echo "✅ 图节点维护: ${node_count} → ${after_nodes} 条"
    fi

    # 回收空间
    sql_exec "$MEMORY_DB" "VACUUM;"
}

# ===========================================================
# 共享发现：写入
# ===========================================================
finding_write() {
    local work_dir="${1:?用法: audit_db.sh finding-write <WORK_DIR> '<json>'}"
    local json="${2:?缺少 JSON 参数}"
    local session_db="${work_dir}/audit_session.db"

    local stmt
    stmt=$(echo "$json" | jq -r '
        "INSERT OR IGNORE INTO shared_findings (source_agent, finding_type, priority, data_key, data_value, data_context, source_location, target_agents) VALUES ("
        + ([
            .source_agent,
            .finding_type,
            .priority,
            .data.key,
            .data.value,
            (.data.context // null),
            (.data.source_location // null),
            (.target_agents // [] | tojson)
        ] | map(
            if . == null then "NULL"
            else "\u0027" + gsub("\u0027"; "\u0027\u0027") + "\u0027"
            end
        ) | join(","))
        + ");"
    ')

    sql_exec "$session_db" "$stmt"
    echo "✅ 发现已写入"
}

# ===========================================================
# 共享发现：读取
# ===========================================================
finding_read() {
    local work_dir="${1:?用法: audit_db.sh finding-read <WORK_DIR> [type] [not_consumed_by]}"
    local finding_type="${2:-}"
    local not_consumed_by="${3:-}"
    local session_db="${work_dir}/audit_session.db"

    local where="1=1"
    [ -n "$finding_type" ] && where="${where} AND finding_type = '$(escape_sql "$finding_type")'"
    [ -n "$not_consumed_by" ] && where="${where} AND consumed_by NOT LIKE '%\"$(escape_sql "$not_consumed_by")\"%'"

    sql "$session_db" "
        SELECT id, timestamp, source_agent, finding_type, priority,
               data_key, data_value, data_context, source_location,
               target_agents, consumed_by
        FROM shared_findings
        WHERE ${where}
        ORDER BY
            CASE priority WHEN 'critical' THEN 0 WHEN 'high' THEN 1 ELSE 2 END,
            timestamp DESC;
    "
}

# ===========================================================
# 共享发现：标记已消费
# ===========================================================
finding_consume() {
    local work_dir="${1:?}"
    local finding_id="${2:?}"
    local agent_name="${3:?}"
    local session_db="${work_dir}/audit_session.db"

    sql_exec "$session_db" "
        UPDATE shared_findings
        SET consumed_by = json_insert(consumed_by, '\$[#]', '$(escape_sql "$agent_name")')
        WHERE id = ${finding_id}
        AND consumed_by NOT LIKE '%\"$(escape_sql "$agent_name")\"%';
    "
    echo "✅ 已标记消费: finding #${finding_id} by ${agent_name}"
}

# ===========================================================
# 共享发现：统计
# ===========================================================
finding_stats() {
    local work_dir="${1:?}"
    local session_db="${work_dir}/audit_session.db"

    echo "=== 共享发现统计 ==="
    sql_exec "$session_db" "
        SELECT '总发现: ' || COUNT(*) FROM shared_findings;
        SELECT '  critical: ' || COUNT(*) FROM shared_findings WHERE priority='critical';
        SELECT '  high: ' || COUNT(*) FROM shared_findings WHERE priority='high';
        SELECT '  medium: ' || COUNT(*) FROM shared_findings WHERE priority='medium';
        SELECT '---';
        SELECT '按类型:';
        SELECT '  ' || finding_type || ': ' || COUNT(*)
        FROM shared_findings GROUP BY finding_type ORDER BY COUNT(*) DESC;
        SELECT '---';
        SELECT '按来源:';
        SELECT '  ' || source_agent || ': ' || COUNT(*)
        FROM shared_findings GROUP BY source_agent ORDER BY COUNT(*) DESC;
        SELECT '---';
        SELECT '未消费: ' || COUNT(*) FROM shared_findings WHERE consumed_by = '[]';
    "
}

# ===========================================================
# 迁移：JSONL → SQLite（攻击记忆）
# ===========================================================
migrate_memory() {
    local jsonl="${1:-${MEMORY_DIR}/attack_memory.jsonl}"
    if [ ! -f "$jsonl" ]; then
        echo "无 JSONL 文件可迁移: $jsonl"
        return 0
    fi

    init_memory

    local count=0
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        memory_write "$line" >/dev/null 2>&1 && count=$((count + 1))
    done < "$jsonl"

    echo "✅ 迁移完成: ${count} 条记忆从 JSONL → SQLite"
    echo "   原始文件已保留: $jsonl"
    echo "   建议验证后删除: rm $jsonl"
}

# ===========================================================
# 迁移：JSONL → SQLite（共享发现）
# ===========================================================
migrate_findings() {
    local work_dir="${1:?}"
    local jsonl="${work_dir}/shared_findings.jsonl"
    if [ ! -f "$jsonl" ]; then
        echo "无 JSONL 文件可迁移: $jsonl"
        return 0
    fi

    init_session "$work_dir" >/dev/null

    local count=0
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        finding_write "$work_dir" "$line" >/dev/null 2>&1 && count=$((count + 1))
    done < "$jsonl"

    echo "✅ 迁移完成: ${count} 条发现从 JSONL → SQLite"
}

# ===========================================================
# 质检记录：写入
# ===========================================================
qc_write() {
    local work_dir="${1:?用法: audit_db.sh qc-write <WORK_DIR> '<json>'}"
    local json="${2:?用法: audit_db.sh qc-write <WORK_DIR> '<json>'}"
    local session_db="${work_dir}/audit_session.db"

    # 确保 qc_records 表存在
    [ -f "$session_db" ] || init_session "$work_dir" >/dev/null

    # 提取字段
    local qc_id phase agent verdict pass_count total_count failed warn metrics redo
    qc_id=$(echo "$json" | jq -r '.qc_id // "qc-unknown"')
    phase=$(echo "$json" | jq -r '.phase // "unknown"')
    agent=$(echo "$json" | jq -r '.agent // .target_agent // "unknown"')
    verdict=$(echo "$json" | jq -r '.verdict // "fail"')
    pass_count=$(echo "$json" | jq -r '.pass_count // 0')
    total_count=$(echo "$json" | jq -r '.total_count // 0')
    failed=$(echo "$json" | jq -c '.failed_items // []')
    warn=$(echo "$json" | jq -c '.warn_items // []')
    metrics=$(echo "$json" | jq -c '.metrics // {}')
    redo=$(echo "$json" | jq -r '.redo_count // 0')

    sql_exec "$session_db" \
        "INSERT OR REPLACE INTO qc_records (qc_id, phase, target_agent, verdict, pass_count, total_count, failed_items, warn_items, metrics, redo_count) VALUES ('$(escape_sql "$qc_id")','$(escape_sql "$phase")','$(escape_sql "$agent")','$(escape_sql "$verdict")',${pass_count},${total_count},'$(escape_sql "$failed")','$(escape_sql "$warn")','$(escape_sql "$metrics")',${redo})"
    echo "✅ 质检记录已写入: phase=${phase} agent=${agent} verdict=${verdict}"
}

# ===========================================================
# 质检记录：读取
# ===========================================================
qc_read() {
    local work_dir="${1:?用法: audit_db.sh qc-read <WORK_DIR> [phase]}"
    local session_db="${work_dir}/audit_session.db"
    local phase="${2:-}"

    [ -f "$session_db" ] || { echo "[]"; return 0; }

    if [ -n "$phase" ]; then
        sql "$session_db" "SELECT * FROM qc_records WHERE phase='$(escape_sql "$phase")' ORDER BY timestamp"
    else
        sql "$session_db" "SELECT * FROM qc_records ORDER BY phase, timestamp"
    fi
}

# ===========================================================
# 质检记录：汇总统计
# ===========================================================
qc_stats() {
    local work_dir="${1:?用法: audit_db.sh qc-stats <WORK_DIR>}"
    local session_db="${work_dir}/audit_session.db"

    [ -f "$session_db" ] || { echo "无质检记录"; return 0; }

    sql_exec "$session_db" "
        SELECT
            phase,
            COUNT(*) as total_checks,
            SUM(CASE WHEN verdict='pass' THEN 1 ELSE 0 END) as passed,
            SUM(CASE WHEN verdict='fail' THEN 1 ELSE 0 END) as failed,
            SUM(redo_count) as total_redos,
            ROUND(AVG(pass_count * 100.0 / NULLIF(total_count, 0)), 1) as avg_pass_rate
        FROM qc_records
        GROUP BY phase
        ORDER BY phase;
    "
}

# ===========================================================
# 初始化：关系型记忆图表
# ===========================================================
init_graph() {
    mkdir -p "$MEMORY_DIR"
    sql_raw "$MEMORY_DB" <<'SQL'
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS memory_nodes (
    node_id     TEXT PRIMARY KEY,
    vuln_type   TEXT NOT NULL,
    sink_id     TEXT NOT NULL,
    route       TEXT,
    severity    TEXT,
    status      TEXT,
    framework   TEXT,
    data_object TEXT,
    summary     TEXT,
    created_at  TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);
CREATE INDEX IF NOT EXISTS idx_nodes_type ON memory_nodes(vuln_type);
CREATE INDEX IF NOT EXISTS idx_nodes_data ON memory_nodes(data_object);
CREATE INDEX IF NOT EXISTS idx_nodes_status ON memory_nodes(status);

CREATE TABLE IF NOT EXISTS memory_edges (
    edge_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    source_node TEXT NOT NULL REFERENCES memory_nodes(node_id),
    target_node TEXT NOT NULL REFERENCES memory_nodes(node_id),
    relation    TEXT NOT NULL,
    direction   TEXT DEFAULT 'forward',
    confidence  TEXT DEFAULT 'probable',
    evidence    TEXT,
    combined_severity TEXT,
    created_at  TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    UNIQUE(source_node, target_node, relation)
);
CREATE INDEX IF NOT EXISTS idx_edges_relation ON memory_edges(relation);
CREATE INDEX IF NOT EXISTS idx_edges_source ON memory_edges(source_node);
CREATE INDEX IF NOT EXISTS idx_edges_target ON memory_edges(target_node);
SQL
    echo "✅ 关系型记忆图表就绪: $MEMORY_DB"
}

# ===========================================================
# 图记忆：写入节点
# ===========================================================
graph_node_write() {
    local json="${1:?用法: audit_db.sh graph-node-write '<json>'}"

    # 解析 JSON 字段
    local node_id vuln_type sink_id route severity status framework data_object summary
    node_id=$(echo "$json" | jq -r '.node_id // empty')
    vuln_type=$(echo "$json" | jq -r '.vuln_type // empty')
    sink_id=$(echo "$json" | jq -r '.sink_id // empty')
    route=$(echo "$json" | jq -r '.route // ""')
    severity=$(echo "$json" | jq -r '.severity // ""')
    status=$(echo "$json" | jq -r '.status // ""')
    framework=$(echo "$json" | jq -r '.framework // ""')
    data_object=$(echo "$json" | jq -r '.data_object // ""')
    summary=$(echo "$json" | jq -r '.summary // ""')

    [ -n "$node_id" ] && [ -n "$vuln_type" ] && [ -n "$sink_id" ] || {
        echo "❌ 必填字段: node_id, vuln_type, sink_id" >&2; return 1
    }

    sql_exec "$MEMORY_DB" "
        INSERT OR REPLACE INTO memory_nodes
            (node_id, vuln_type, sink_id, route, severity, status, framework, data_object, summary)
        VALUES
            ('$(escape_sql "$node_id")',
             '$(escape_sql "$vuln_type")',
             '$(escape_sql "$sink_id")',
             '$(escape_sql "$route")',
             '$(escape_sql "$severity")',
             '$(escape_sql "$status")',
             '$(escape_sql "$framework")',
             '$(escape_sql "$data_object")',
             '$(escape_sql "$summary")');
    "
    echo "✅ 节点写入: $node_id ($vuln_type)"
}

# ===========================================================
# 图记忆：写入边
# ===========================================================
graph_edge_write() {
    local json="${1:?用法: audit_db.sh graph-edge-write '<json>'}"

    local source_node target_node relation direction confidence evidence combined_severity
    source_node=$(echo "$json" | jq -r '.source_node // empty')
    target_node=$(echo "$json" | jq -r '.target_node // empty')
    relation=$(echo "$json" | jq -r '.relation // empty')
    direction=$(echo "$json" | jq -r '.direction // "forward"')
    confidence=$(echo "$json" | jq -r '.confidence // "probable"')
    evidence=$(echo "$json" | jq -r '.evidence // ""')
    combined_severity=$(echo "$json" | jq -r '.combined_severity // ""')

    [ -n "$source_node" ] && [ -n "$target_node" ] && [ -n "$relation" ] || {
        echo "❌ 必填字段: source_node, target_node, relation" >&2; return 1
    }

    # 验证关系类型
    case "$relation" in
        data_flows_to|enables|escalates_to|shares_data_object|same_entry_point|auth_chain|pivot_from) ;;
        *) echo "❌ 无效关系类型: $relation (允许: data_flows_to|enables|escalates_to|shares_data_object|same_entry_point|auth_chain|pivot_from)" >&2; return 1 ;;
    esac

    sql_exec "$MEMORY_DB" "
        INSERT OR REPLACE INTO memory_edges
            (source_node, target_node, relation, direction, confidence, evidence, combined_severity)
        VALUES
            ('$(escape_sql "$source_node")',
             '$(escape_sql "$target_node")',
             '$(escape_sql "$relation")',
             '$(escape_sql "$direction")',
             '$(escape_sql "$confidence")',
             '$(escape_sql "$evidence")',
             '$(escape_sql "$combined_severity")');
    "
    echo "✅ 边写入: $source_node --[$relation]--> $target_node"
}

# ===========================================================
# 图记忆：查询节点邻居
# ===========================================================
graph_neighbors() {
    local node_id="${1:?用法: audit_db.sh graph-neighbors <node_id>}"

    [ -f "$MEMORY_DB" ] || { echo "[]"; return 0; }

    sql "$MEMORY_DB" "
        SELECT json_object(
            'direction', 'outgoing',
            'relation', e.relation,
            'confidence', e.confidence,
            'evidence', e.evidence,
            'combined_severity', e.combined_severity,
            'neighbor', json_object(
                'node_id', n.node_id,
                'vuln_type', n.vuln_type,
                'sink_id', n.sink_id,
                'route', n.route,
                'severity', n.severity,
                'status', n.status,
                'summary', n.summary
            )
        )
        FROM memory_edges e
        JOIN memory_nodes n ON e.target_node = n.node_id
        WHERE e.source_node = '$(escape_sql "$node_id")'
        UNION ALL
        SELECT json_object(
            'direction', 'incoming',
            'relation', e.relation,
            'confidence', e.confidence,
            'evidence', e.evidence,
            'combined_severity', e.combined_severity,
            'neighbor', json_object(
                'node_id', n.node_id,
                'vuln_type', n.vuln_type,
                'sink_id', n.sink_id,
                'route', n.route,
                'severity', n.severity,
                'status', n.status,
                'summary', n.summary
            )
        )
        FROM memory_edges e
        JOIN memory_nodes n ON e.source_node = n.node_id
        WHERE e.target_node = '$(escape_sql "$node_id")'
        ORDER BY 1;
    "
}

# ===========================================================
# 图记忆：按数据对象查询
# ===========================================================
graph_by_data_object() {
    local data_object="${1:?用法: audit_db.sh graph-by-data-object <data_object>}"

    [ -f "$MEMORY_DB" ] || { echo '{"nodes":[],"edges":[]}'; return 0; }

    local nodes edges
    nodes=$(sql "$MEMORY_DB" "
        SELECT json_object(
            'node_id', node_id,
            'vuln_type', vuln_type,
            'sink_id', sink_id,
            'route', route,
            'severity', severity,
            'status', status,
            'framework', framework,
            'summary', summary
        )
        FROM memory_nodes
        WHERE data_object = '$(escape_sql "$data_object")'
        ORDER BY created_at DESC;
    ")

    # 获取这些节点之间的边
    edges=$(sql "$MEMORY_DB" "
        SELECT json_object(
            'source_node', e.source_node,
            'target_node', e.target_node,
            'relation', e.relation,
            'confidence', e.confidence,
            'evidence', e.evidence,
            'combined_severity', e.combined_severity
        )
        FROM memory_edges e
        WHERE e.source_node IN (SELECT node_id FROM memory_nodes WHERE data_object = '$(escape_sql "$data_object")')
           OR e.target_node IN (SELECT node_id FROM memory_nodes WHERE data_object = '$(escape_sql "$data_object")')
        ORDER BY e.created_at DESC;
    ")

    # 组合输出
    echo "{\"nodes\":${nodes:-[]},\"edges\":${edges:-[]}}"
}

# ===========================================================
# 图记忆：导出完整图结构
# ===========================================================
graph_export() {
    local work_dir="${1:?用法: audit_db.sh graph-export <WORK_DIR>}"

    [ -f "$MEMORY_DB" ] || { echo '{"nodes":[],"edges":[],"stats":{}}'; return 0; }

    local nodes edges node_count edge_count
    nodes=$(sql "$MEMORY_DB" "
        SELECT json_object(
            'node_id', node_id,
            'vuln_type', vuln_type,
            'sink_id', sink_id,
            'route', route,
            'severity', severity,
            'status', status,
            'framework', framework,
            'data_object', data_object,
            'summary', summary,
            'created_at', created_at
        )
        FROM memory_nodes
        ORDER BY created_at DESC;
    ")

    edges=$(sql "$MEMORY_DB" "
        SELECT json_object(
            'edge_id', edge_id,
            'source_node', source_node,
            'target_node', target_node,
            'relation', relation,
            'direction', direction,
            'confidence', confidence,
            'evidence', evidence,
            'combined_severity', combined_severity,
            'created_at', created_at
        )
        FROM memory_edges
        ORDER BY created_at DESC;
    ")

    node_count=$(sql_exec "$MEMORY_DB" "SELECT COUNT(*) FROM memory_nodes;" 2>/dev/null || echo "0")
    edge_count=$(sql_exec "$MEMORY_DB" "SELECT COUNT(*) FROM memory_edges;" 2>/dev/null || echo "0")

    local output="{\"nodes\":${nodes:-[]},\"edges\":${edges:-[]},\"stats\":{\"node_count\":${node_count},\"edge_count\":${edge_count}}}"

    # 同时写入文件供 report_writer 使用
    mkdir -p "$work_dir"
    echo "$output" > "$work_dir/attack_graph_data.json"
    echo "✅ 图数据已导出: $work_dir/attack_graph_data.json (${node_count} 节点, ${edge_count} 边)"
}

# ===========================================================
# 主入口
# ===========================================================
case "${1:-help}" in
    init-memory)     init_memory ;;
    init-graph)      init_graph ;;
    init-session)    shift; init_session "$@" ;;
    memory-write)    shift; memory_write "$@" ;;
    memory-query)    shift; memory_query "$@" ;;
    memory-stats)    memory_stats ;;
    memory-maintain) memory_maintain ;;
    finding-write)   shift; finding_write "$@" ;;
    finding-read)    shift; finding_read "$@" ;;
    finding-consume) shift; finding_consume "$@" ;;
    finding-stats)   shift; finding_stats "$@" ;;
    migrate-memory)  shift; migrate_memory "$@" ;;
    migrate-findings) shift; migrate_findings "$@" ;;
    qc-write)        shift; qc_write "$@" ;;
    qc-read)         shift; qc_read "$@" ;;
    qc-stats)        shift; qc_stats "$@" ;;
    graph-node-write)  shift; graph_node_write "$@" ;;
    graph-edge-write)  shift; graph_edge_write "$@" ;;
    graph-neighbors)   shift; graph_neighbors "$@" ;;
    graph-by-data-object) shift; graph_by_data_object "$@" ;;
    graph-export)      shift; graph_export "$@" ;;
    help|*)
        echo "用法: audit_db.sh <命令> [参数...]"
        echo ""
        echo "初始化:"
        echo "  init-memory                  初始化全局记忆库"
        echo "  init-session <WORK_DIR>      初始化审计会话库"
        echo ""
        echo "攻击记忆 (全局 ~/.php_audit/attack_memory.db):"
        echo "  memory-write  '<json>'       写入攻击记忆"
        echo "  memory-query  <sink_type> [framework] [php_major] [waf_type]"
        echo "  memory-stats                 统计记忆库"
        echo "  memory-maintain              容量维护（>1000条时清理）"
        echo ""
        echo "共享发现 (会话 WORK_DIR/audit_session.db):"
        echo "  finding-write  <WORK_DIR> '<json>'      写入发现"
        echo "  finding-read   <WORK_DIR> [type] [agent] 读取发现"
        echo "  finding-consume <WORK_DIR> <id> <agent>  标记已消费"
        echo "  finding-stats  <WORK_DIR>               统计发现"
        echo ""
        echo "迁移:"
        echo "  migrate-memory  [jsonl_path]   从 JSONL 迁移记忆"
        echo "  migrate-findings <WORK_DIR>    从 JSONL 迁移发现"
        echo ""
        echo "质检记录 (会话 WORK_DIR/audit_session.db):"
        echo "  qc-write  <WORK_DIR> '<json>'  写入质检记录"
        echo "  qc-read   <WORK_DIR> [phase]   读取质检记录"
        echo "  qc-stats  <WORK_DIR>           质检统计汇总"
        echo ""
        echo "关系型记忆图 (全局 ~/.php_audit/attack_memory.db):"
        echo "  init-graph                      初始化图表（memory_nodes + memory_edges）"
        echo "  graph-node-write '<json>'       写入漏洞节点"
        echo "  graph-edge-write '<json>'       写入关系边"
        echo "  graph-neighbors  <node_id>      查询节点的所有关联"
        echo "  graph-by-data-object <object>   按数据对象查询攻击面"
        echo "  graph-export <WORK_DIR>         导出完整图结构到 JSON"
        ;;
esac
