#!/usr/bin/env bash
set -uo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly WORKSPACE_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd -P)"
readonly DOCKER_SOCKET="/var/run/docker.sock"

failures=0
warnings=0

pass() {
  printf '[PASS] %s\n' "$*"
}

note() {
  printf '[INFO] %s\n' "$*"
}

warn() {
  warnings=$((warnings + 1))
  printf '[WARN] %s\n' "$*" >&2
}

fail() {
  failures=$((failures + 1))
  printf '[FAIL] %s\n' "$*" >&2
}

print_output() {
  local output=$1
  local line

  [[ -n "${output}" ]] || return 0
  while IFS= read -r line; do
    printf '       %s\n' "${line}"
  done <<< "${output}"
}

record_issue() {
  local severity=$1
  shift

  if [[ "${severity}" == "required" ]]; then
    fail "$*"
  else
    warn "$*"
  fi
}

run_check() {
  local severity=$1
  local label=$2
  local display=$3
  shift 3

  local output
  local status
  output="$("$@" 2>&1)"
  status=$?

  if ((status == 0)); then
    pass "${label}"
    if [[ "${display}" == "show" ]]; then
      print_output "${output}"
    fi
    return 0
  fi

  record_issue "${severity}" "${label} (exit ${status})"
  print_output "${output}"
  return "${status}"
}

run_bounded_check() {
  local severity=$1
  local label=$2
  local display=$3
  local duration=$4
  shift 4

  if command -v timeout >/dev/null 2>&1; then
    run_check "${severity}" "${label}" "${display}" timeout "${duration}" "$@"
  else
    run_check "${severity}" "${label}" "${display}" "$@"
  fi
}

tool_available() {
  command -v "$1" >/dev/null 2>&1
}

check_tool() {
  local tool=$1
  local path

  path="$(command -v "${tool}" 2>/dev/null || true)"
  if [[ -n "${path}" ]]; then
    pass "${tool} is available at ${path}"
    return 0
  fi

  fail "${tool} is not available on PATH"
  return 1
}

check_readable_file() {
  local severity=$1
  local label=$2
  local path=$3

  if [[ -z "${path}" ]]; then
    record_issue "${severity}" "${label} path is empty"
    return 1
  fi
  if [[ ! -e "${path}" ]]; then
    record_issue "${severity}" "${label} is missing: ${path}"
    return 1
  fi
  if [[ ! -f "${path}" ]]; then
    record_issue "${severity}" "${label} is not a regular file: ${path}"
    return 1
  fi
  if [[ ! -r "${path}" ]]; then
    record_issue "${severity}" "${label} is not readable: ${path}"
    return 1
  fi
  if [[ ! -s "${path}" ]]; then
    record_issue "${severity}" "${label} is empty: ${path}"
    return 1
  fi

  pass "${label} is readable: ${path}"
  return 0
}

prepare_mise_path() {
  local mise_shims=""

  if [[ -n "${HOME:-}" ]]; then
    export PATH="${HOME}/.local/bin:${PATH}"
  fi

  if [[ -n "${MISE_DATA_DIR:-}" ]]; then
    mise_shims="${MISE_DATA_DIR}/shims"
  elif [[ -n "${XDG_DATA_HOME:-}" ]]; then
    mise_shims="${XDG_DATA_HOME}/mise/shims"
  elif [[ -n "${HOME:-}" ]]; then
    mise_shims="${HOME}/.local/share/mise/shims"
  fi

  if [[ -n "${mise_shims}" && -d "${mise_shims}" ]]; then
    export PATH="${mise_shims}:${PATH}"
  fi
}

find_kubeconfig() {
  local severity=$1
  local kubeconfig_value="${KUBECONFIG:-}"
  local path
  local selected=""
  local -a paths=()
  local -a candidates=()
  local -a generated_candidates=()

  KUBECONFIG_READY=0
  RESOLVED_KUBECONFIG=""

  if [[ -n "${kubeconfig_value}" ]]; then
    IFS=':' read -r -a paths <<< "${kubeconfig_value}"
    if ((${#paths[@]} == 0)); then
      record_issue "${severity}" "KUBECONFIG does not contain a path"
      return 1
    fi

    KUBECONFIG_READY=1
    for path in "${paths[@]}"; do
      [[ -n "${path}" ]] || continue
      if ! check_readable_file "${severity}" "Kubeconfig" "${path}"; then
        KUBECONFIG_READY=0
      fi
    done
    RESOLVED_KUBECONFIG="${kubeconfig_value}"
    ((KUBECONFIG_READY == 1))
    return
  fi

  if [[ -n "${HOME:-}" ]]; then
    candidates+=("${HOME}/.kube/config")
  fi
  candidates+=(
    "${WORKSPACE_DIR}/clusters/main/kubeconfig"
    "${WORKSPACE_DIR}/clusters/main/talos/generated/kubeconfig"
    "${WORKSPACE_DIR}/kubeconfig"
  )

  shopt -s nullglob
  generated_candidates=(
    "${WORKSPACE_DIR}"/clusters/main/*kubeconfig*.yaml
    "${WORKSPACE_DIR}"/clusters/main/talos/generated/*kubeconfig*
  )
  shopt -u nullglob
  candidates+=("${generated_candidates[@]}")

  for path in "${candidates[@]}"; do
    if [[ -e "${path}" ]]; then
      selected="${path}"
      break
    fi
  done

  if [[ -z "${selected}" ]]; then
    record_issue "${severity}" "Kubeconfig was not found; set KUBECONFIG or generate one with clustertool"
    return 1
  fi

  if check_readable_file "${severity}" "Kubeconfig" "${selected}"; then
    KUBECONFIG_READY=1
    RESOLVED_KUBECONFIG="${selected}"
    return 0
  fi

  return 1
}

main() {
  local cluster_file_severity="optional"
  local talos_config
  local age_key
  local talos_ready=0
  local tool

  KUBECONFIG_READY=0
  RESOLVED_KUBECONFIG=""

  printf '==> Devcontainer environment validation\n'
  printf '    workspace: %s\n' "${WORKSPACE_DIR}"

  prepare_mise_path
  if ! cd "${WORKSPACE_DIR}"; then
    fail "Cannot access workspace: ${WORKSPACE_DIR}"
    exit 1
  fi

  if [[ "${DEVCONTAINER_REQUIRE_CLUSTER_CONFIG:-0}" == "1" ]]; then
    cluster_file_severity="required"
  fi

  for tool in git mise talosctl clustertool kubectl kubecolor docker; do
    check_tool "${tool}"
  done

  if tool_available git; then
    run_check required "Git safe-directory configuration" hide \
      git config --global --replace-all safe.directory "${WORKSPACE_DIR}"
  fi

  if tool_available mise; then
    run_check required "mise responds" show mise --version
  fi
  if tool_available talosctl; then
    run_check required "talosctl client responds" show talosctl version --client
  fi
  if tool_available clustertool; then
    run_bounded_check required "clustertool info succeeds" hide 15s clustertool info
  fi
  if tool_available kubectl; then
    run_check required "kubectl client responds" show kubectl version --client=true
  fi
  if tool_available kubecolor; then
    run_check required "kubecolor responds" show kubecolor --kubecolor-version
  fi

  if tool_available docker; then
    run_check required "Docker CLI responds" show docker --version
    run_check required "Docker Compose plugin responds" show docker compose version
    run_check required "Docker Buildx plugin responds" show docker buildx version
  fi

  if [[ -S "${DOCKER_SOCKET}" ]]; then
    pass "Docker socket exists: ${DOCKER_SOCKET}"
  else
    fail "Docker socket is missing or is not a socket: ${DOCKER_SOCKET}"
  fi

  if [[ -r "${DOCKER_SOCKET}" && -w "${DOCKER_SOCKET}" ]]; then
    pass "Docker socket is readable and writable"
  else
    fail "Docker socket is not readable and writable by the current user"
  fi

  if tool_available docker && [[ -S "${DOCKER_SOCKET}" ]]; then
    run_bounded_check required "Docker host daemon is reachable" show 10s \
      docker --host "unix://${DOCKER_SOCKET}" info --format 'Docker server {{.ServerVersion}}'
  fi

  talos_config="${TALOSCONFIG:-${WORKSPACE_DIR}/clusters/main/talos/generated/talosconfig}"
  if check_readable_file "${cluster_file_severity}" "Talos config" "${talos_config}"; then
    talos_ready=1
    if tool_available talosctl &&
      ! run_check "${cluster_file_severity}" "Talos config parses" hide \
        env "TALOSCONFIG=${talos_config}" talosctl config info; then
      talos_ready=0
    fi
  fi

  age_key="${SOPS_AGE_KEY_FILE:-${WORKSPACE_DIR}/age.agekey}"
  check_readable_file optional "SOPS age key" "${age_key}"

  find_kubeconfig "${cluster_file_severity}"
  if ((KUBECONFIG_READY == 1)) && tool_available kubectl; then
    run_check "${cluster_file_severity}" "kubectl can load the current context" show \
      env "KUBECONFIG=${RESOLVED_KUBECONFIG}" kubectl config current-context
  fi

  if [[ "${DEVCONTAINER_LIVE_CHECKS:-0}" == "1" ]]; then
    if ((KUBECONFIG_READY == 1)) && tool_available kubectl; then
      run_bounded_check optional "Kubernetes API is reachable" hide 12s \
        env "KUBECONFIG=${RESOLVED_KUBECONFIG}" \
        kubectl --request-timeout=8s cluster-info
    fi
    if ((talos_ready == 1)) && tool_available talosctl; then
      run_bounded_check optional "Talos API is reachable" hide 12s \
        env "TALOSCONFIG=${talos_config}" talosctl version
    fi
  else
    note "Live Kubernetes/Talos checks skipped (set DEVCONTAINER_LIVE_CHECKS=1 to enable)"
  fi

  printf '\nValidation summary: %s failure(s), %s warning(s)\n' \
    "${failures}" "${warnings}"

  if ((failures > 0)); then
    return 1
  fi

  return 0
}

main "$@"
