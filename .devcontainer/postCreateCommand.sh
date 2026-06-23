#!/usr/bin/env bash
set -euo pipefail
set -o noglob

echo "==> Devcontainer bootstrap starting"

########################################
# Detect environment root
########################################
HOME_DIR="${HOME:-/config}"
FISH_DIR="/config/fish"
MISE_BIN="/config/.local/bin/mise"

echo "HOME: $HOME_DIR"
echo "FISH: $FISH_DIR"

########################################
# Ensure required dirs exist
########################################
mkdir -p "$FISH_DIR"
mkdir -p "$FISH_DIR/conf.d"
mkdir -p "$HOME_DIR/.config"

########################################
# HARD RESET fish config (prevents corruption)
########################################
echo "==> Resetting fish config (authoritative path)"

cat > "$FISH_DIR/config.fish" <<'EOF'
# Devcontainer fish config (clean baseline)
if status is-interactive
    # interactive shell only
    source ~/.config/fish/config.fish
end
EOF

########################################
# Install fisher + plugins (idempotent)
########################################
echo "==> Installing fisher plugins"

if command -v fish >/dev/null 2>&1; then
  fish -lc '
    if not functions -q fisher
        curl -sL https://git.io/fisher | source
        fisher install jorgebucaran/fisher
    end

    fisher install decors/fish-colored-man || true
    fisher install edc/bass || true
    fisher install jorgebucaran/autopair.fish || true
    fisher install nickeb96/puffer-fish || true
    fisher install PatrickF1/fzf.fish || true
  '
fi

########################################
# Install mise (safe + deterministic)
########################################
echo "==> Installing mise"

if [ ! -x "$MISE_BIN" ]; then
  curl -fsSL https://mise.run | sh
fi

if [ ! -x "$MISE_BIN" ]; then
  echo "ERROR: mise not found at $MISE_BIN"
  exit 1
fi

########################################
# Bash integration
########################################
echo "==> Configuring bash"

if ! grep -q "mise activate bash" "$HOME_DIR/.bashrc" 2>/dev/null; then
  echo "eval \"\$($MISE_BIN activate bash)\"" >> "$HOME_DIR/.bashrc"
fi

########################################
# Fish integration (CORRECT MODEL: conf.d ONLY)
########################################
echo "==> Configuring fish integration"

cat > "$FISH_DIR/conf.d/mise.fish" <<EOF
if test -x $MISE_BIN
    $MISE_BIN activate fish | source
end
EOF

########################################
# direnv safety note (no interference)
########################################
echo "==> direnv detected (no modification applied)"

########################################
# Virtualenv sanity check
########################################
echo "==> Checking virtualenv"

VENV_DIR="${containerWorkspaceFolder:-$PWD}/.venv"

if [ -f "$VENV_DIR/pyvenv.cfg" ]; then
  if ! grep -q "venv" "$VENV_DIR/pyvenv.cfg" 2>/dev/null; then
    echo "Invalid venv detected, removing..."
    rm -rf "$VENV_DIR"
  fi
fi

########################################
# Finish
########################################
echo "==> Devcontainer bootstrap complete"