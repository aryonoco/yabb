#!/bin/env bash
# SPDX-License-Identifier: 0BSD
# Copyright (c) 2023-2026 Aryan Ameri
#
set -e

echo "========================================"
echo "YABB Development Environment Setup"
echo "========================================"

# Navigate to workspace
cd /workspaces/yabb

# Powerlevel10k configuration
cp .devcontainer/p10k.zsh ~/.p10k.zsh
echo '[[ ! -f ~/.p10k.zsh ]] || source ~/.p10k.zsh' >> ~/.zshrc

# Oh-my-zsh plugins
PLUGINS="git docker"
sed -i "s/^plugins=.*/plugins=($PLUGINS)/" ~/.zshrc

# Shell aliases - ALL using just commands
cat >> ~/.zshrc << 'EOF'

# Add workspace bin to PATH for running built binaries directly
export PATH="/workspaces/yabb/bin:$PATH"

# =============================================================================
# YABB Development Aliases (all via just)
# =============================================================================

# Primary commands (just shortcuts)
alias j='just'
alias jls='just --list'
alias jv='just versions'

# Build shortcuts (via just)
alias jb='just build'
alias jbr='just release'

# Cross-compilation shortcuts (via just)
alias jra='just release-all'
alias jbarm='just build-arm64'
alias jbarmhf='just build-armhf'
alias jbrv='just build-riscv64'
alias jbppc='just build-ppc64el'
alias jbloong='just build-loong64'

# Test shortcuts (via just)
alias jt='just test'
alias jtv='just test-verbose'
alias jtr='just test-report'

# Code quality shortcuts (via just)
alias jf='just fmt'
alias jfc='just fmt-check'
alias jfd='just fmt-diff'
alias jln='just lint'
alias jc='just check'

# CI shortcuts (via just)
alias jci='just ci'
alias jreuse='just reuse'

# Development shortcuts (via just)
alias jr='just run'
alias jw='just watch'
alias jwt='just watch-test'

# Cleanup shortcuts (via just)
alias jcl='just clean'
alias jca='just clean-all'

# Documentation shortcuts (via just)
alias jd='just docs'
alias jdo='just docs-open'

# Release shortcut (via just)
alias jrel='just release'

# Help function
yabbhelp() {
  echo "YABB Development Commands (via just)"
  echo "====================================="
  echo ""
  echo "Primary:"
  echo "  j           - just (task runner)"
  echo "  jls         - just --list (show all commands)"
  echo "  jv          - just versions (show tool versions)"
  echo ""
  echo "Build:"
  echo "  jb          - just build (debug)"
  echo "  jbr         - just release (optimised static)"
  echo ""
  echo "Cross-compilation:"
  echo "  jra         - just release-all (all 8 architectures)"
  echo "  jbarm       - just build-arm64"
  echo "  jbarmhf     - just build-armhf"
  echo "  jbrv        - just build-riscv64"
  echo "  jbppc       - just build-ppc64el"
  echo "  jbloong     - just build-loong64"
  echo ""
  echo "Test:"
  echo "  jt          - just test"
  echo "  jtv         - just test-verbose"
  echo "  jtr         - just test-report (HTML)"
  echo ""
  echo "Code Quality:"
  echo "  jf          - just fmt (format with nph)"
  echo "  jfc         - just fmt-check (CI-friendly)"
  echo "  jc          - just check (fmt-check + lint)"
  echo "  jreuse      - just reuse (REUSE compliance)"
  echo "  jci         - just ci (full pipeline)"
  echo ""
  echo "Development:"
  echo "  jr          - just run (build & run --help)"
  echo "  jw          - just watch (rebuild on change)"
  echo "  jwt         - just watch-test (test on change)"
  echo ""
  echo "Other:"
  echo "  jcl         - just clean"
  echo "  jd          - just docs"
  echo ""
  echo "Run 'just --list' for all available commands"
}
EOF

# uv shell completions (zsh)
echo 'eval "$(uv generate-shell-completion zsh)"' >> ~/.zshrc
echo 'eval "$(uvx --generate-shell-completion zsh)"' >> ~/.zshrc

# Aliases for Debian package naming quirks
echo "alias fd='fdfind'" >> ~/.zshrc
echo "alias bat='batcat'" >> ~/.zshrc

# fzf key bindings and completion (zsh)
echo 'source /usr/share/doc/fzf/examples/key-bindings.zsh' >> ~/.zshrc
echo 'source /usr/share/doc/fzf/examples/completion.zsh' >> ~/.zshrc

# Install Python tools via uv
echo ""
echo "Installing Python tools via uv..."
uv tool install reuse

# Run setup via just (installs tools + dependencies)
echo ""
echo "Running just setup..."
just setup

# Generate nimble.lock if not present (reproducible builds)
if [ ! -f nimble.lock ]; then
  echo "Generating nimble.lock for reproducible builds..."
  just lock
fi

# =============================================================================
# Version Validation - ensures devcontainer matches versions.env
# =============================================================================
echo ""
echo "Validating version configuration..."
if [ -f versions.env ]; then
  source versions.env
  MISMATCH=0

  # Validate Nim
  INSTALLED_NIM=$(nim --version 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' || echo "unknown")
  echo "Checking Nim: expected=$NIM_VERSION, installed=$INSTALLED_NIM"
  if [ "$NIM_VERSION" != "$INSTALLED_NIM" ]; then
    echo "  WARNING: Nim version mismatch!"
    MISMATCH=1
  fi

  # Validate Zig
  INSTALLED_ZIG=$(zig version 2>/dev/null || echo "unknown")
  echo "Checking Zig: expected=$ZIG_VERSION, installed=$INSTALLED_ZIG"
  if [ "$ZIG_VERSION" != "$INSTALLED_ZIG" ]; then
    echo "  WARNING: Zig version mismatch!"
    MISMATCH=1
  fi

  # Validate zigcc is installed
  if ! command -v zigcc &> /dev/null; then
    echo "  WARNING: zigcc not found! Run 'nimble install -y zigcc'"
    MISMATCH=1
  else
    echo "Checking zigcc: installed"
  fi

  # Validate RISCstar RISC-V64 toolchain
  if command -v riscv64-none-linux-musl-gcc &> /dev/null; then
    INSTALLED_RISCSTAR=$(riscv64-none-linux-musl-gcc --version 2>/dev/null | head -1 || echo "unknown")
    echo "Checking RISCstar RISC-V64: installed ($INSTALLED_RISCSTAR)"
  else
    echo "  WARNING: RISCstar RISC-V64 toolchain not found!"
    MISMATCH=1
  fi

  # Validate uv
  INSTALLED_UV=$(uv --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' || echo "unknown")
  echo "Checking uv: expected=$UV_VERSION, installed=$INSTALLED_UV"
  if [ "$UV_VERSION" != "$INSTALLED_UV" ]; then
    echo "  WARNING: uv version mismatch!"
    MISMATCH=1
  fi

  # Validate reuse (installed via uv tool)
  if command -v reuse &> /dev/null; then
    INSTALLED_REUSE=$(reuse --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' || echo "unknown")
    echo "Checking reuse: installed ($INSTALLED_REUSE)"
  else
    echo "  WARNING: reuse not found! Run 'uv tool install reuse'"
    MISMATCH=1
  fi

  if [ "$MISMATCH" -eq 1 ]; then
    echo ""
    echo "========================================"
    echo "WARNING: Version mismatch detected!"
    echo "========================================"
    echo "To fix: Update .devcontainer/devcontainer.json"
    echo "  - build.args (NIM_VERSION, ZIG_VERSION, UV_VERSION)"
    echo "  - containerEnv (NIM_VERSION, ZIG_VERSION, UV_VERSION)"
    echo "Then rebuild the container."
    echo "========================================"
  else
    echo "OK: All versions match versions.env"
  fi
else
  echo "WARNING: versions.env not found"
fi

# Show versions via just
echo ""
just versions

echo ""
echo "========================================"
echo "YABB Development Environment Ready!"
echo "========================================"
echo ""
echo "Quick start:"
echo "  just            - Show all available commands"
echo "  just build      - Build debug binary"
echo "  just release    - Build optimised static binary"
echo "  just release-all - Cross-compile all architectures"
echo "  just test       - Run tests"
echo "  just ci         - Run full CI pipeline"
echo "  yabbhelp        - Show alias shortcuts"
echo ""
