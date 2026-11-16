#!/usr/bin/env bash
set -Eeuo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly WORKSPACE_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd -P)"
readonly USER_CONFIG_DIR="${XDG_CONFIG_HOME:-${HOME:?HOME is not set}/.config}"
readonly FISH_CONFIG_DIR="${USER_CONFIG_DIR}/fish"
readonly USER_MISE_BIN="${HOME}/.local/bin/mise"

MISE_EXECUTABLE=""

log() {
  printf '==> %s\n' "$*"
}

warn() {
  printf 'WARNING: %s\n' "$*" >&2
}

handle_error() {
  local exit_code=$?
  printf 'ERROR: post-create failed on line %s (exit %s)\n' "${BASH_LINENO[0]}" "${exit_code}" >&2
  exit "${exit_code}"
}

trap handle_error ERR

install_mise() {
  local mise_bin
  mise_bin="$(command -v mise 2>/dev/null || true)"

  if [[ -z "${mise_bin}" && -x "${USER_MISE_BIN}" ]]; then
    mise_bin="${USER_MISE_BIN}"
  fi

  if [[ -z "${mise_bin}" ]]; then
    command -v curl >/dev/null 2>&1 || {
      printf 'ERROR: curl is required to install mise\n' >&2
      return 1
    }

    log "Installing mise"
    mkdir -p "$(dirname -- "${USER_MISE_BIN}")"
    curl -fsSL https://mise.run | MISE_INSTALL_PATH="${USER_MISE_BIN}" sh
    mise_bin="${USER_MISE_BIN}"
  else
    log "mise is already installed at ${mise_bin}"
  fi

  if [[ ! -x "${mise_bin}" ]]; then
    printf 'ERROR: mise is not executable at %s\n' "${mise_bin}" >&2
    return 1
  fi

  MISE_EXECUTABLE="${mise_bin}"
}

configure_shells() {
  local mise_bin=$1
  local bashrc="${HOME}/.bashrc"
  local bash_activation
  local fish_activation="${FISH_CONFIG_DIR}/conf.d/mise.fish"
  local legacy_fish_config

  log "Configuring Bash and Fish activation"
  mkdir -p "${FISH_CONFIG_DIR}/conf.d"
  touch "${bashrc}"

  printf -v bash_activation 'eval "$("%s" activate bash)"' "${mise_bin}"
  if ! grep -Fqx -- "${bash_activation}" "${bashrc}"; then
    printf '\n%s\n' "${bash_activation}" >> "${bashrc}"
  fi

  cat > "${fish_activation}" <<EOF
# Managed by .devcontainer/postCreateCommand.sh
if test -x "${mise_bin}"
    "${mise_bin}" activate fish | source
end
EOF

  # Repair only the exact file written by the old bootstrap. Preserve every
  # other Fish configuration, including user customizations.
  legacy_fish_config=$'# Devcontainer fish config (clean baseline)\nif status is-interactive\n    # interactive shell only\n    source ~/.config/fish/config.fish\nend'
  if [[ -f "${FISH_CONFIG_DIR}/config.fish" ]] &&
    [[ "$(< "${FISH_CONFIG_DIR}/config.fish")" == "${legacy_fish_config}" ]]; then
    cat > "${FISH_CONFIG_DIR}/config.fish" <<'EOF'
if status is-interactive
    # Commands to run in interactive sessions can go here
end
EOF
  fi
}

install_fish_plugins() {
  if ! command -v fish >/dev/null 2>&1; then
    warn "fish is not installed; skipping Fisher plugins"
    return 0
  fi

  log "Installing Fisher plugins"
  if ! fish -c '
    if not functions -q fisher
        curl -fsSL https://raw.githubusercontent.com/jorgebucaran/fisher/main/functions/fisher.fish | source
        and fisher install jorgebucaran/fisher
    end

    fisher install \
        decors/fish-colored-man \
        edc/bass \
        jorgebucaran/autopair.fish \
        nickeb96/puffer-fish \
        PatrickF1/fzf.fish
  '; then
    warn "one or more optional Fisher plugins could not be installed"
  fi
}

install_project_tools() {
  local mise_bin=$1

  log "Trusting mise.toml and installing project tools"
  (
    cd "${WORKSPACE_DIR}"
    "${mise_bin}" trust "${WORKSPACE_DIR}/mise.toml"
    MISE_YES=1 "${mise_bin}" install
  )
}

main() {
  local mise_bin

  log "Devcontainer bootstrap starting"
  printf '    workspace: %s\n' "${WORKSPACE_DIR}"
  printf '    home:      %s\n' "${HOME}"

  install_mise
  mise_bin="${MISE_EXECUTABLE}"
  configure_shells "${mise_bin}"
  install_fish_plugins
  install_project_tools "${mise_bin}"

  log "Devcontainer bootstrap complete"
}

main "$@"
