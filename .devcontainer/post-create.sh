#!/bin/bash
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

# =============================================================================
# YABB Development Aliases (all via just)
# =============================================================================

# Primary commands (just shortcuts)
alias j='just'
alias jls='just --list'
alias jv='just versions'

# Build shortcuts (via just)
alias jb='just build'
alias jbr='just build-release'
alias jbs='just build-static'
alias jbd='just build-debug'

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
  echo "  jbr         - just build-release (optimised)"
  echo "  jbs         - just build-static (musl)"
  echo "  jbd         - just build-debug (with LLDB symbols)"
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
  echo "  jrel        - just release (full release)"
  echo ""
  echo "Run 'just --list' for all available commands"
}
EOF

# Run setup via just (installs tools + dependencies)
echo ""
echo "Running just setup..."
just setup

# Generate nimble.lock if not present (reproducible builds)
if [ ! -f nimble.lock ]; then
  echo "Generating nimble.lock for reproducible builds..."
  just lock
fi

# Validate versions.env matches installed Nim version
echo ""
echo "Validating version configuration..."
if [ -f versions.env ]; then
  source versions.env
  INSTALLED_NIM=$(nim --version 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' || echo "unknown")
  if [ "$NIM_VERSION" != "$INSTALLED_NIM" ]; then
    echo ""
    echo "========================================"
    echo "WARNING: Version mismatch detected!"
    echo "========================================"
    echo "  versions.env:    NIM_VERSION=$NIM_VERSION"
    echo "  Installed Nim:   $INSTALLED_NIM"
    echo ""
    echo "To fix: Update .devcontainer/devcontainer.json"
    echo "  - build.args.NIM_VERSION"
    echo "  - containerEnv.NIM_VERSION"
    echo "Then rebuild the container."
    echo "========================================"
    echo ""
  else
    echo "OK: Nim version matches versions.env ($NIM_VERSION)"
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
echo "  just         - Show all available commands"
echo "  just build   - Build debug binary"
echo "  just test    - Run tests"
echo "  just ci      - Run full CI pipeline"
echo "  yabbhelp     - Show alias shortcuts"
echo ""
