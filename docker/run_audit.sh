#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
COMPOSE_FILE="${SCRIPT_DIR}/docker-compose.yml"

usage() {
  cat <<'USAGE'
Usage:
  skills/docker/run_audit.sh <project> [out] [audit options...]

Deep verify options:
  --deep-verify                           Run strict AI+Docker deep verification after audit (default)
  --disable-deep-verify                   Skip deep verification stage
  --strict-deep-verify                    Enforce strict gate for deep verification
  --disable-strict-deep-verify            Do not fail on deep verification gate violations
  --ai-realtime                           Enable realtime AI supplement (default)
  --disable-ai-realtime                   Disable realtime AI supplement
  --ai-model <model>                      Override model
  --ai-rounds <n>                         AI rounds (default: 2)
  --ai-candidates-per-round <n>           AI candidates per round (default: 5)
  --ai-timeout <sec>                      AI timeout seconds (default: 30)
  --ai-force-all                          Force AI attempts for every case (default)
  --disable-ai-force-all                  Disable force-AI mode
  --until-confirmed                       Keep trying until confirmed
  --allow-conditional-stop                Allow conditional as stop target
  --debug-skipped-ratio-max <0~1>         Max skipped ratio threshold (default: 0.40)
  --trace-verbose                         Write per-case trace JSON (default)
  --disable-trace-verbose                 Disable per-case trace JSON

Default out:
  If [out] is omitted, output path is /tmp/{project_name}/{timestamp}.
USAGE
}

abs_path() {
  local input="$1"
  if [[ "${input}" == /* ]]; then
    printf '%s\n' "${input}"
  else
    printf '%s\n' "$(pwd)/${input}"
  fi
}

default_tmp_out_dir() {
  local project_host="$1"
  local base_tmp="${SKILLS_TMP_DIR:-/tmp}"
  local project_name
  local timestamp
  local out_dir
  local suffix=0
  project_name="$(basename "${project_host%/}")"
  project_name="$(printf '%s' "${project_name}" | tr -cs 'A-Za-z0-9._-' '_')"
  timestamp="$(date +%Y%m%d_%H%M%S)"
  out_dir="${base_tmp}/${project_name}/${timestamp}"
  while [[ -e "${out_dir}" ]]; do
    suffix=$((suffix + 1))
    out_dir="${base_tmp}/${project_name}/${timestamp}_${suffix}"
  done
  mkdir -p "${out_dir}"
  printf '%s\n' "${out_dir}"
}

docker_daemon_ready() {
  docker info >/dev/null 2>&1
}

start_docker_desktop_best_effort() {
  if [[ "$(uname -s)" != "Darwin" ]]; then
    return 0
  fi
  if command -v open >/dev/null 2>&1; then
    if [[ -d "/Applications/Docker.app" ]]; then
      open -ga Docker >/dev/null 2>&1 || open -a Docker >/dev/null 2>&1 || true
    fi
  fi
}

ensure_docker_daemon() {
  if docker_daemon_ready; then
    return
  fi
  echo "[INFO] Docker daemon is not ready; trying to start Docker..." >&2
  start_docker_desktop_best_effort

  local timeout_sec="${DOCKER_START_TIMEOUT_SEC:-120}"
  local waited=0
  while (( waited < timeout_sec )); do
    if docker_daemon_ready; then
      echo "[INFO] Docker daemon is ready." >&2
      return
    fi
    sleep 2
    waited=$((waited + 2))
  done

  echo "Error: Docker daemon not ready after ${timeout_sec}s." >&2
  echo "Hint: start Docker Desktop manually, then rerun skills/docker/run_audit.sh." >&2
  exit 1
}

ensure_readable_dir() {
  local dir="$1"
  local label="$2"
  if [[ ! -e "${dir}" ]]; then
    echo "Error: ${label} does not exist: ${dir}" >&2
    exit 1
  fi
  if [[ ! -d "${dir}" ]]; then
    echo "Error: ${label} must be a directory: ${dir}" >&2
    exit 1
  fi
  if [[ ! -r "${dir}" ]]; then
    echo "Error: ${label} is not readable: ${dir}" >&2
    exit 1
  fi
}

ensure_writable_dir() {
  local dir="$1"
  mkdir -p "${dir}" || {
    echo "Error: failed to create output directory: ${dir}" >&2
    exit 1
  }
  if [[ ! -d "${dir}" ]]; then
    echo "Error: output path is not a directory: ${dir}" >&2
    exit 1
  fi
  local probe="${dir}/.write_probe_$$"
  if ! : > "${probe}" 2>/dev/null; then
    echo "Error: output directory is not writable: ${dir}" >&2
    exit 1
  fi
  rm -f "${probe}"
}

dir_has_entries() {
  local dir="$1"
  find "${dir}" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null | grep -q .
}

ensure_out_dir_available() {
  local dir="$1"
  local explicit_out="$2"
  local allow_reuse="${SKILLS_ALLOW_REUSE_OUT:-0}"
  local lock_file="${dir}/_meta/run.lock"
  if [[ -f "${lock_file}" ]]; then
    echo "Error: output directory appears to be in use (lock exists): ${lock_file}" >&2
    echo "Hint: use a new output path, or wait for the previous run to finish." >&2
    exit 1
  fi
  if [[ "${explicit_out}" == "1" && "${allow_reuse}" != "1" ]]; then
    if dir_has_entries "${dir}"; then
      echo "Error: output directory is not empty: ${dir}" >&2
      echo "Hint: use a fresh output directory, or set SKILLS_ALLOW_REUSE_OUT=1 to override." >&2
      exit 1
    fi
  fi
}

mount_config_file() {
  local host_path="$1"
  local idx="$2"
  if [[ ! -e "${host_path}" ]]; then
    echo "Error: config does not exist: ${host_path}" >&2
    exit 1
  fi
  if [[ ! -f "${host_path}" ]]; then
    echo "Error: config must be a file: ${host_path}" >&2
    exit 1
  fi
  if [[ ! -r "${host_path}" ]]; then
    echo "Error: config is not readable: ${host_path}" >&2
    exit 1
  fi
  printf '/work/config/config_%s_%s\n' "${idx}" "$(basename "${host_path}")"
}

resolve_ai_model() {
  if [[ -n "${AI_MODEL}" ]]; then
    return
  fi
  if [[ -n "${AI_CONFIRM_MODEL:-}" ]]; then
    AI_MODEL="${AI_CONFIRM_MODEL}"
  elif [[ -n "${AI_AUDIT_MODEL:-}" ]]; then
    AI_MODEL="${AI_AUDIT_MODEL}"
  else
    AI_MODEL="sonnet"
  fi
}

ensure_uint() {
  local value="$1"
  local label="$2"
  if [[ ! "${value}" =~ ^[0-9]+$ ]]; then
    echo "Error: ${label} must be a non-negative integer, got: ${value}" >&2
    exit 1
  fi
}

ensure_ratio() {
  local value="$1"
  local label="$2"
  if [[ ! "${value}" =~ ^([0-9]+([.][0-9]+)?|[.][0-9]+)$ ]]; then
    echo "Error: ${label} must be a number between 0 and 1, got: ${value}" >&2
    exit 1
  fi
  if ! awk -v v="${value}" 'BEGIN{exit !(v >= 0 && v <= 1)}'; then
    echo "Error: ${label} must be between 0 and 1, got: ${value}" >&2
    exit 1
  fi
}

if [[ $# -lt 1 ]]; then
  usage
  exit 1
fi

PROJECT_INPUT="$1"
shift

OUT_INPUT=""
if [[ $# -gt 0 && "$1" != --* ]]; then
  OUT_INPUT="$1"
  shift
fi

PROJECT_HOST="$(abs_path "${PROJECT_INPUT}")"
ensure_readable_dir "${PROJECT_HOST}" "project"

if [[ -n "${OUT_INPUT}" ]]; then
  OUT_HOST="$(abs_path "${OUT_INPUT}")"
  OUT_EXPLICIT=1
else
  OUT_HOST="$(default_tmp_out_dir "${PROJECT_HOST}")"
  OUT_EXPLICIT=0
fi
ensure_writable_dir "${OUT_HOST}"
ensure_out_dir_available "${OUT_HOST}" "${OUT_EXPLICIT}"
ensure_docker_daemon

DEEP_VERIFY=1
STRICT_DEEP_VERIFY=0
AI_REALTIME=1
AI_MODEL=""
AI_ROUNDS=2
AI_CANDIDATES_PER_ROUND=5
AI_TIMEOUT=30
AI_FORCE_ALL=1
UNTIL_CONFIRMED=0
TRACE_VERBOSE=1
DEBUG_SKIPPED_RATIO_MAX="${DEBUG_SKIPPED_RATIO_MAX:-0.40}"

MOUNTS=(
  -v "${PROJECT_HOST}:/work/project:ro"
  -v "${OUT_HOST}:/work/out:rw"
)
EXTRA_ARGS=()
CONFIG_COUNT=0

while [[ $# -gt 0 ]]; do
  token="$1"
  case "${token}" in
    --project|--out)
      echo "Error: use positional <project> [out], do not pass ${token}." >&2
      exit 1
      ;;
    --project=*|--out=*)
      echo "Error: use positional <project> [out], do not pass ${token}." >&2
      exit 1
      ;;

    --deep-verify)
      DEEP_VERIFY=1
      shift
      ;;
    --disable-deep-verify)
      DEEP_VERIFY=0
      shift
      ;;
    --strict-deep-verify)
      STRICT_DEEP_VERIFY=1
      shift
      ;;
    --disable-strict-deep-verify)
      STRICT_DEEP_VERIFY=0
      shift
      ;;

    --ai-realtime)
      AI_REALTIME=1
      shift
      ;;
    --disable-ai-realtime)
      AI_REALTIME=0
      shift
      ;;
    --ai-model)
      if [[ $# -lt 2 ]]; then
        echo "Error: --ai-model requires a value" >&2
        exit 1
      fi
      AI_MODEL="$2"
      shift 2
      ;;
    --ai-model=*)
      AI_MODEL="${token#--ai-model=}"
      shift
      ;;
    --ai-rounds)
      if [[ $# -lt 2 ]]; then
        echo "Error: --ai-rounds requires a value" >&2
        exit 1
      fi
      AI_ROUNDS="$2"
      shift 2
      ;;
    --ai-rounds=*)
      AI_ROUNDS="${token#--ai-rounds=}"
      shift
      ;;
    --ai-candidates-per-round)
      if [[ $# -lt 2 ]]; then
        echo "Error: --ai-candidates-per-round requires a value" >&2
        exit 1
      fi
      AI_CANDIDATES_PER_ROUND="$2"
      shift 2
      ;;
    --ai-candidates-per-round=*)
      AI_CANDIDATES_PER_ROUND="${token#--ai-candidates-per-round=}"
      shift
      ;;
    --ai-timeout)
      if [[ $# -lt 2 ]]; then
        echo "Error: --ai-timeout requires a value" >&2
        exit 1
      fi
      AI_TIMEOUT="$2"
      shift 2
      ;;
    --ai-timeout=*)
      AI_TIMEOUT="${token#--ai-timeout=}"
      shift
      ;;
    --ai-force-all)
      AI_FORCE_ALL=1
      shift
      ;;
    --disable-ai-force-all)
      AI_FORCE_ALL=0
      shift
      ;;
    --until-confirmed)
      UNTIL_CONFIRMED=1
      shift
      ;;
    --allow-conditional-stop)
      UNTIL_CONFIRMED=0
      shift
      ;;
    --trace-verbose)
      TRACE_VERBOSE=1
      shift
      ;;
    --disable-trace-verbose)
      TRACE_VERBOSE=0
      shift
      ;;
    --debug-skipped-ratio-max)
      if [[ $# -lt 2 ]]; then
        echo "Error: --debug-skipped-ratio-max requires a value" >&2
        exit 1
      fi
      DEBUG_SKIPPED_RATIO_MAX="$2"
      shift 2
      ;;
    --debug-skipped-ratio-max=*)
      DEBUG_SKIPPED_RATIO_MAX="${token#--debug-skipped-ratio-max=}"
      shift
      ;;

    --config)
      if [[ $# -lt 2 ]]; then
        echo "Error: --config requires a path" >&2
        exit 1
      fi
      config_host="$(abs_path "$2")"
      CONFIG_COUNT=$((CONFIG_COUNT + 1))
      config_container="$(mount_config_file "${config_host}" "${CONFIG_COUNT}")"
      MOUNTS+=( -v "${config_host}:${config_container}:ro" )
      EXTRA_ARGS+=( --config "${config_container}" )
      shift 2
      ;;
    --config=*)
      config_value="${token#--config=}"
      config_host="$(abs_path "${config_value}")"
      CONFIG_COUNT=$((CONFIG_COUNT + 1))
      config_container="$(mount_config_file "${config_host}" "${CONFIG_COUNT}")"
      MOUNTS+=( -v "${config_host}:${config_container}:ro" )
      EXTRA_ARGS+=( "--config=${config_container}" )
      shift
      ;;
    *)
      EXTRA_ARGS+=( "${token}" )
      shift
      ;;
  esac
done

ensure_uint "${AI_ROUNDS}" "AI rounds"
ensure_uint "${AI_CANDIDATES_PER_ROUND}" "AI candidates per round"
ensure_uint "${AI_TIMEOUT}" "AI timeout"
ensure_ratio "${DEBUG_SKIPPED_RATIO_MAX}" "Debug skipped ratio max"
resolve_ai_model
if [[ -z "${AUDIT_RUN_ID:-}" ]]; then
  AUDIT_RUN_ID="$(date +%Y%m%d_%H%M%S)_$$"
fi

run_container() {
  local -a inner=("$@")
  local -a cmd=(
    docker compose -f "${COMPOSE_FILE}" run --rm
    -e "SKILLS_HOST_OUT=${OUT_HOST}"
    -e "AUDIT_RUN_ID=${AUDIT_RUN_ID}"
    -e "AI_DEEP_MODEL=${AI_MODEL}"
    -e "AI_CONFIRM_MODEL=${AI_MODEL}"
    -e "AI_AUDIT_MODEL=${AI_MODEL}"
    -e "DEBUG_SKIPPED_RATIO_MAX=${DEBUG_SKIPPED_RATIO_MAX}"
    -e "STRICT_BLOCK_DEBUG_SKIPPED_RATIO=0"
    "${MOUNTS[@]}"
    debug
    "${inner[@]}"
  )
  "${cmd[@]}"
}

run_strict_evidence_check() {
  local -a strict_env=(
    -e "STRICT_DYNAMIC_VERIFY_ALL=1"
    -e "STRICT_AI_REALTIME=$([[ ${AI_REALTIME} -eq 1 ]] && echo 1 || echo 0)"
    -e "STRICT_AI_REQUIRE_ATTEMPT=$([[ ${AI_REALTIME} -eq 1 && ${AI_FORCE_ALL} -eq 1 ]] && echo 1 || echo 0)"
    -e "STRICT_REQUIRE_CONFIRMED=$([[ ${UNTIL_CONFIRMED} -eq 1 ]] && echo 1 || echo 0)"
    -e "STRICT_BLOCK_DEBUG_SKIPPED_RATIO=1"
    -e "DEBUG_SKIPPED_RATIO_MAX=${DEBUG_SKIPPED_RATIO_MAX}"
  )
  local -a cmd=(
    docker compose -f "${COMPOSE_FILE}" run --rm
    -e "SKILLS_HOST_OUT=${OUT_HOST}"
    -e "AUDIT_RUN_ID=${AUDIT_RUN_ID}"
    "${strict_env[@]}"
    "${MOUNTS[@]}"
    debug
    python3 /app/skills/_scripts/evidence_check.py
    --project /work/project
    --out /work/out
    --strict
  )
  "${cmd[@]}"
}

echo "[INFO] Project: ${PROJECT_HOST}" >&2
echo "[INFO] Output: ${OUT_HOST}" >&2
echo "[INFO] Run ID: ${AUDIT_RUN_ID}" >&2

AUDIT_CMD=(
  python3 /app/skills/_scripts/audit_cli.py
  --project /work/project
  --out /work/out
)
if [[ ${#EXTRA_ARGS[@]} -gt 0 ]]; then
  AUDIT_CMD+=( "${EXTRA_ARGS[@]}" )
fi

echo "[INFO] Running audit pipeline in docker..." >&2
run_container "${AUDIT_CMD[@]}"

if [[ ${DEEP_VERIFY} -eq 0 ]]; then
  echo "[INFO] Deep verification disabled; audit completed." >&2
  exit 0
fi

echo "[INFO] Deep verification: preparing AI context..." >&2
run_container \
  python3 /app/skills/_scripts/debug_runner.py \
  --project /work/project \
  --out /work/out \
  --prepare-ai-context-only

AI_STATUS="disabled"
SUGGESTIONS_HOST="${OUT_HOST}/mcp_raw/ai-confirm-mcp-debug.json"
if [[ ${AI_REALTIME} -eq 1 ]]; then
  export AI_CONFIRM_MODEL="${AI_MODEL}"
  export AI_DEBUG_ROUNDS="${AI_ROUNDS}"
  export AI_DEBUG_CANDIDATES_PER_ROUND="${AI_CANDIDATES_PER_ROUND}"
  export AI_DEBUG_TIMEOUT="${AI_TIMEOUT}"
  MCP_CONFIG="${REPO_ROOT}/skills/_scripts/mcp_config.debug.json"

  echo "[INFO] Deep verification: host-side realtime AI suggestions..." >&2
  set +e
  python3 "${REPO_ROOT}/skills/_scripts/mcp_adapter.py" \
    --project "${PROJECT_HOST}" \
    --out "${OUT_HOST}" \
    --tool ai-confirm-debug-mcp \
    --config "${MCP_CONFIG}"
  MCP_RC=$?
  set -e

  if [[ ${MCP_RC} -eq 0 && -f "${SUGGESTIONS_HOST}" ]]; then
    AI_STATUS="ok"
  else
    AI_STATUS="failed"
    if [[ ${STRICT_DEEP_VERIFY} -eq 1 ]]; then
      echo "Error: strict deep verification requires realtime AI suggestions, but acquisition failed." >&2
      exit 1
    fi
    echo "[WARN] Realtime AI suggestions unavailable; continuing with current strict setting disabled." >&2
  fi
fi

DEBUG_CMD=(
  python3 /app/skills/_scripts/debug_runner.py
  --project /work/project
  --out /work/out
  --ai-model "${AI_MODEL}"
  --ai-rounds "${AI_ROUNDS}"
  --ai-candidates-per-round "${AI_CANDIDATES_PER_ROUND}"
  --ai-timeout "${AI_TIMEOUT}"
)
if [[ ${TRACE_VERBOSE} -eq 1 ]]; then
  DEBUG_CMD+=( --trace-verbose )
fi
if [[ ${AI_FORCE_ALL} -eq 1 ]]; then
  DEBUG_CMD+=( --ai-force-all )
fi
if [[ ${UNTIL_CONFIRMED} -eq 1 ]]; then
  DEBUG_CMD+=( --until-confirmed )
else
  DEBUG_CMD+=( --allow-conditional-stop )
fi
if [[ ${AI_REALTIME} -eq 1 ]]; then
  DEBUG_CMD+=( --ai-realtime --ai-runtime-status "${AI_STATUS}" )
  if [[ -f "${SUGGESTIONS_HOST}" ]]; then
    DEBUG_CMD+=( --ai-suggestions /work/out/mcp_raw/ai-confirm-mcp-debug.json )
  fi
else
  DEBUG_CMD+=( --disable-ai-realtime --ai-runtime-status "disabled" )
fi

echo "[INFO] Deep verification: running docker debug verification..." >&2
run_container "${DEBUG_CMD[@]}"

echo "[INFO] Deep verification: refreshing reports..." >&2
run_container python3 /app/skills/_scripts/report_refresh.py --project /work/project --out /work/out
run_container python3 /app/skills/_scripts/phase_attack_chain.py --project /work/project --out /work/out
run_container python3 /app/skills/_scripts/phase_report_index.py --project /work/project --out /work/out
run_container python3 /app/skills/_scripts/final_report.py --project /work/project --out /work/out

if [[ ${STRICT_DEEP_VERIFY} -eq 1 ]]; then
  echo "[INFO] Deep verification: running strict evidence gate..." >&2
  run_strict_evidence_check
else
  run_container python3 /app/skills/_scripts/evidence_check.py --project /work/project --out /work/out
fi

echo "[INFO] Audit + deep verification completed." >&2
