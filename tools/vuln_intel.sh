#!/usr/bin/env bash
# ============================================================
# vuln_intel.sh — 外部漏洞情报查询（免 API Key）
# ============================================================
# 用法: vuln_intel.sh <composer.lock 路径> [输出目录]
#
# 数据源（均免费、无需认证）:
#   1. OSV.dev API       — Google 维护，支持 Packagist 生态
#   2. cve.circl.lu API  — CIRCL 维护，CPE 精确匹配
#   3. FriendsOfPHP      — 社区 YAML advisory，容器内已可用
#
# 输出: <输出目录>/vuln_intel.json
# ============================================================
set -euo pipefail

COMPOSER_LOCK="${1:?用法: vuln_intel.sh <composer.lock> [输出目录]}"
OUTPUT_DIR="${2:-.}"
OUTPUT_FILE="${OUTPUT_DIR}/vuln_intel.json"
TIMEOUT=10  # 每个 API 请求超时秒数

# ── 颜色输出 ──
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; }

# ── 前置检查 ──
if [ ! -f "$COMPOSER_LOCK" ]; then
    error "找不到 composer.lock: $COMPOSER_LOCK"
    exit 1
fi

for cmd in jq curl; do
    if ! command -v "$cmd" &>/dev/null; then
        error "缺少依赖: $cmd"
        exit 1
    fi
done

mkdir -p "$OUTPUT_DIR"

# ── 解析 composer.lock，提取包名+版本 ──
info "解析 composer.lock ..."
PACKAGES=$(jq -r '
  [(.packages // [])[], (.["packages-dev"] // [])[]]
  | {name: .name, version: (.version | ltrimstr("v")), is_dev: false}
' "$COMPOSER_LOCK")

TOTAL=$(echo "$PACKAGES" | jq -s 'length')
info "发现 ${TOTAL} 个依赖包"

# ── 初始化结果文件 ──
echo '[]' > "$OUTPUT_FILE"

# ===========================================================
# 数据源 1: OSV.dev（批量查询）
# https://osv.dev/docs/#tag/api/operation/OSV_QueryAffectedBatch
# ===========================================================
query_osv() {
    info "查询 OSV.dev (Packagist) ..."

    # 构建批量查询 payload（每批最多 1000 个）
    local batch_payload
    batch_payload=$(echo "$PACKAGES" | jq -s '[.[] | {
        package: {
            name: .name,
            ecosystem: "Packagist"
        },
        version: .version
    }]' | jq '{queries: .}')

    local response
    response=$(curl -s --max-time 30 \
        -X POST "https://api.osv.dev/v1/querybatch" \
        -H "Content-Type: application/json" \
        -d "$batch_payload" 2>/dev/null) || {
        warn "OSV.dev 请求失败（网络不可用或超时）"
        return 0
    }

    # 解析响应：results 数组与 queries 数组一一对应
    local count
    count=$(echo "$response" | jq '[.results[]? | select(.vulns != null and (.vulns | length) > 0)] | length' 2>/dev/null || echo 0)

    if [ "$count" -gt 0 ]; then
        # 将 OSV 结果转换为统一格式
        local pkg_names
        pkg_names=$(echo "$PACKAGES" | jq -s '[.[].name]')

        echo "$response" | jq --argjson names "$pkg_names" '
            [.results | to_entries[] | select(.value.vulns != null) |
             .key as $i | .value.vulns[] |
             {
                 source: "osv.dev",
                 package: $names[$i],
                 vuln_id: (.id // "unknown"),
                 aliases: ([.aliases[]?] // []),
                 summary: (.summary // .details // "N/A" | .[0:200]),
                 severity: (
                     if .database_specific.severity then .database_specific.severity
                     elif (.severity[]?.score // 0) >= 9 then "CRITICAL"
                     elif (.severity[]?.score // 0) >= 7 then "HIGH"
                     elif (.severity[]?.score // 0) >= 4 then "MEDIUM"
                     else "LOW"
                     end
                 ),
                 affected_ranges: [.affected[]?.ranges[]?.events[]? | objects | to_entries[] | "\(.key):\(.value)"] ,
                 references: [.references[]?.url // empty] | .[0:3],
                 published: (.published // "unknown")
             }
            ]
        ' 2>/dev/null > "${OUTPUT_DIR}/.osv_results.json" || true

        local osv_count
        osv_count=$(jq 'length' "${OUTPUT_DIR}/.osv_results.json" 2>/dev/null || echo 0)
        info "OSV.dev: 发现 ${osv_count} 条漏洞"

        # 合并到主结果
        jq -s '.[0] + .[1]' "$OUTPUT_FILE" "${OUTPUT_DIR}/.osv_results.json" > "${OUTPUT_FILE}.tmp" \
            && mv "${OUTPUT_FILE}.tmp" "$OUTPUT_FILE"
        rm -f "${OUTPUT_DIR}/.osv_results.json"
    else
        info "OSV.dev: 未发现已知漏洞"
    fi
}

# ===========================================================
# 数据源 2: cve.circl.lu（逐包查询高危包）
# https://cve.circl.lu/api/
# ===========================================================
query_circl() {
    info "查询 cve.circl.lu (高危包) ..."

    # 仅对已知高危生态的包查询（避免过多请求）
    local high_risk_vendors=("laravel" "symfony" "guzzlehttp" "monolog" "dompdf" "phpunit" "twig" "doctrine" "league" "swiftmailer" "phpmailer")

    local circl_results="[]"
    local queried=0

    echo "$PACKAGES" | jq -r -c '.name' | while IFS= read -r pkg; do
        local vendor
        vendor=$(echo "$pkg" | cut -d'/' -f1)

        # 仅查询高危 vendor
        local is_high_risk=false
        for v in "${high_risk_vendors[@]}"; do
            if [ "$vendor" = "$v" ]; then
                is_high_risk=true
                break
            fi
        done
        [ "$is_high_risk" = false ] && continue

        # CPE 格式: cpe:2.3:a:vendor:product
        local product
        product=$(echo "$pkg" | cut -d'/' -f2)

        local response
        response=$(curl -s --max-time "$TIMEOUT" \
            "https://cve.circl.lu/api/search/${vendor}/${product}" 2>/dev/null) || continue

        # 提取匹配的 CVE
        local matches
        matches=$(echo "$response" | jq --arg pkg "$pkg" '[
            .[]? | select(.id != null) | {
                source: "cve.circl.lu",
                package: $pkg,
                vuln_id: .id,
                aliases: [],
                summary: (.summary // "N/A" | .[0:200]),
                severity: (
                    if (.cvss // 0) >= 9 then "CRITICAL"
                    elif (.cvss // 0) >= 7 then "HIGH"
                    elif (.cvss // 0) >= 4 then "MEDIUM"
                    else "LOW"
                    end
                ),
                cvss_score: (.cvss // null),
                references: [.references[]? // empty] | .[0:3],
                published: (.Published // "unknown")
            }
        ] | .[0:10]' 2>/dev/null) || continue

        local cnt
        cnt=$(echo "$matches" | jq 'length' 2>/dev/null || echo 0)
        if [ "$cnt" -gt 0 ]; then
            queried=$((queried + cnt))
            echo "$matches" >> "${OUTPUT_DIR}/.circl_batch.json"
        fi

        sleep 0.5  # 礼貌限速
    done

    # 合并 circl 结果
    if [ -f "${OUTPUT_DIR}/.circl_batch.json" ]; then
        jq -s 'flatten' "${OUTPUT_DIR}/.circl_batch.json" > "${OUTPUT_DIR}/.circl_results.json" 2>/dev/null || true
        local circl_count
        circl_count=$(jq 'length' "${OUTPUT_DIR}/.circl_results.json" 2>/dev/null || echo 0)
        info "cve.circl.lu: 发现 ${circl_count} 条漏洞"

        jq -s '.[0] + .[1]' "$OUTPUT_FILE" "${OUTPUT_DIR}/.circl_results.json" > "${OUTPUT_FILE}.tmp" \
            && mv "${OUTPUT_FILE}.tmp" "$OUTPUT_FILE"
        rm -f "${OUTPUT_DIR}/.circl_results.json" "${OUTPUT_DIR}/.circl_batch.json"
    else
        info "cve.circl.lu: 未发现额外漏洞"
    fi
}

# ===========================================================
# 去重 + 排序 + 统计
# ===========================================================
finalize() {
    info "去重与排序 ..."

    # 按 vuln_id + package 去重，按 severity 排序
    jq '
        group_by(.vuln_id + "|" + .package)
        | map(
            reduce .[] as $item (.[0];
                .aliases += ($item.aliases // [])
                | .references += ($item.references // [])
                | if $item.source != .source then .source = .source + "+" + $item.source else . end
            )
            | .aliases |= unique
            | .references |= unique | .references |= .[0:5]
        )
        | sort_by(
            if .severity == "CRITICAL" then 0
            elif .severity == "HIGH" then 1
            elif .severity == "MEDIUM" then 2
            else 3 end
        )
    ' "$OUTPUT_FILE" > "${OUTPUT_FILE}.tmp" && mv "${OUTPUT_FILE}.tmp" "$OUTPUT_FILE"

    # 统计
    local total critical high medium low
    total=$(jq 'length' "$OUTPUT_FILE")
    critical=$(jq '[.[] | select(.severity == "CRITICAL")] | length' "$OUTPUT_FILE")
    high=$(jq '[.[] | select(.severity == "HIGH")] | length' "$OUTPUT_FILE")
    medium=$(jq '[.[] | select(.severity == "MEDIUM")] | length' "$OUTPUT_FILE")
    low=$(jq '[.[] | select(.severity == "LOW")] | length' "$OUTPUT_FILE")

    echo ""
    info "═══════════════════════════════════════"
    info "  外部情报汇总: ${total} 条漏洞"
    info "  CRITICAL: ${critical}  HIGH: ${high}  MEDIUM: ${medium}  LOW: ${low}"
    info "  输出: ${OUTPUT_FILE}"
    info "═══════════════════════════════════════"
}

# ── 主流程 ──
query_osv
query_circl
finalize
