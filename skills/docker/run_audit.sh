#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="${SCRIPT_DIR}/docker-compose.yml"

usage() {
  cat <<'EOF'
Usage:
  skills/docker/run_audit.sh <project> [out] [audit options...]

Default out:
  If [out] is omitted, output path is /tmp/{project_name}/{timestamp}.
EOF
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
else
  OUT_HOST="$(default_tmp_out_dir "${PROJECT_HOST}")"
fi
ensure_writable_dir "${OUT_HOST}"
ensure_docker_daemon

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

CMD=(
  docker compose -f "${COMPOSE_FILE}" run --rm
  -e "SKILLS_HOST_OUT=${OUT_HOST}"
  "${MOUNTS[@]}"
  debug
  python3 /app/skills/_scripts/audit_cli.py
  --project /work/project
  --out /work/out
)
if [[ ${#EXTRA_ARGS[@]} -gt 0 ]]; then
  CMD+=( "${EXTRA_ARGS[@]}" )
fi

echo "[INFO] Project: ${PROJECT_HOST}" >&2
echo "[INFO] Output: ${OUT_HOST}" >&2
exec "${CMD[@]}"
