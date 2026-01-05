# =============================================================================
# YABB - Yet Another BTRFS Backup
# Task runner with version management
# =============================================================================

# Shell configuration for reliable pipe/redirect handling
set shell := ["bash", "-euo", "pipefail", "-c"]

# Load environment variables from versions.env (single source of truth)
set dotenv-load
set dotenv-filename := "versions.env"

# =============================================================================
# VERSION MANAGEMENT
# =============================================================================

# Tool versions loaded from versions.env
# NIM_VERSION and CHOOSENIM_VERSION are set in versions.env
# These fallbacks are only used if versions.env is missing
NIM_VERSION := env_var_or_default("NIM_VERSION", "2.2.6")
CHOOSENIM_VERSION := env_var_or_default("CHOOSENIM_VERSION", "0.8.16")
NPH_VERSION := env_var_or_default("NPH_VERSION", "0.6.2")
NIMLANGSERVER_VERSION := "latest"

# Extract current installed versions
_nim-version:
    @nim --version 2>/dev/null | head -1 | cut -d' ' -f4 || echo "not installed"

_nimble-version:
    @nimble --version 2>/dev/null | head -1 | cut -d' ' -f2 || echo "not installed"

_nph-version:
    @nph --version 2>/dev/null | head -1 || echo "not installed"

_nimlangserver-version:
    @nimlangserver --version 2>/dev/null | head -1 || echo "not installed"

# =============================================================================
# DEFAULT & HELP
# =============================================================================

# Show available commands
default:
    @just --list

# Show version information for all tools
versions:
    @echo "YABB Development Environment Versions:"
    @echo "======================================="
    @echo "  Nim:           $(just _nim-version)"
    @echo "  Nimble:        $(just _nimble-version)"
    @echo "  nph:           $(just _nph-version)"
    @echo "  nimlangserver: $(just _nimlangserver-version)"
    @echo "  just:          $(just --version)"
    @echo ""
    @echo "Target versions (from versions.env):"
    @echo "  NIM_VERSION:       {{NIM_VERSION}}"
    @echo "  CHOOSENIM_VERSION: {{CHOOSENIM_VERSION}}"
    @echo "  NPH_VERSION:       {{NPH_VERSION}}"

# =============================================================================
# SETUP & INSTALLATION
# =============================================================================

# Full environment setup (run after devcontainer creation)
setup: _install-nim-tools install
    @echo "Setup complete! Run 'just versions' to verify."

# Install Nim development tools
_install-nim-tools:
    @echo "Installing Nim development tools..."
    # Install nimlangserver via nimble (works fine)
    nimble install -y nimlangserver
    # Build nph from source to avoid nimble's broken nim package resolution
    @if ! command -v nph &> /dev/null || [ "$(nph --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')" != "{{NPH_VERSION}}" ]; then \
        echo "Installing nph v{{NPH_VERSION}} from source..."; \
        rm -rf /tmp/nph; \
        git clone --depth 1 --branch "v{{NPH_VERSION}}" https://github.com/arnetheduck/nph.git /tmp/nph; \
        cd /tmp/nph && nimble setup && nim c -d:release -o:$HOME/.nimble/bin/nph src/nph.nim; \
        rm -rf /tmp/nph; \
    else \
        echo "nph v{{NPH_VERSION}} already installed"; \
    fi
    @echo "Nim tools installed"

# Install project dependencies
install:
    @echo "Installing project dependencies..."
    nimble refresh
    nimble install -d --accept
    @echo "Dependencies installed"

# Update all dependencies
update:
    nimble refresh
    nimble install -d --accept
    @echo "Dependencies updated"

# Generate nimble.lock for reproducible builds
lock:
    nimble lock
    @echo "nimble.lock generated"

# =============================================================================
# BUILDING
# =============================================================================

# Build debug binary (default for development)
build:
    @echo "Building debug binary..."
    nimble build
    @echo "Debug build: bin/yabb (glibc, debug symbols, assertions, checks)"

# Build release binary (production deployment)
release: && _clean-cache
    @echo "Building release binary..."
    nimble release
    @echo "Release build: bin/yabb (musl static, optimised, stripped)"

# Rebuild debug from scratch
rebuild: clean build
    @echo "Rebuild complete"

# =============================================================================
# TESTING
# =============================================================================

# Run all tests
test:
    @echo "Running tests..."
    nimble test
    @echo "All tests passed"

# Run tests with verbose output
test-verbose:
    @echo "Running tests (verbose)..."
    testament --verbose all
    @echo "All tests passed"

# Run specific test file
test-file file:
    @echo "Running test: {{file}}"
    testament {{file}}

# Run tests and generate HTML report
test-report:
    @echo "Running tests with report..."
    testament all
    testament html
    @echo "Test report: testresults.html"

# =============================================================================
# CODE QUALITY
# =============================================================================

# Format all source files with nph
fmt:
    @echo "Formatting source files..."
    nph src/ tests/
    @echo "Formatting complete"

# Check formatting without modifying (CI-friendly)
fmt-check:
    @echo "Checking formatting..."
    nph --check src/ tests/
    @echo "Formatting check passed"

# Show diff of formatting changes
fmt-diff:
    @echo "Showing formatting diff..."
    nph --diff src/ tests/

# Lint source files (Nim compile-time checks)
lint:
    @echo "Running lint checks..."
    nim check src/yabb.nim
    @echo "Lint checks passed"

# Run all code quality checks
check: fmt-check lint
    @echo "All quality checks passed"

# =============================================================================
# CI PIPELINE
# =============================================================================

# Run full CI pipeline locally
ci: fmt-check lint test
    @echo ""
    @echo "============================================"
    @echo "All CI checks passed!"
    @echo "============================================"

# CI with verbose output
ci-verbose: fmt-check lint test-verbose
    @echo ""
    @echo "============================================"
    @echo "All CI checks passed!"
    @echo "============================================"

# =============================================================================
# DOCUMENTATION
# =============================================================================

# Generate HTML documentation
docs:
    @echo "Generating documentation..."
    nim doc --project --index:on --outdir:htmldocs src/yabb.nim
    @echo "Documentation generated: htmldocs/"

# Open documentation in browser (if available)
docs-open: docs
    @if command -v xdg-open &> /dev/null; then \
        xdg-open htmldocs/theindex.html; \
    elif command -v open &> /dev/null; then \
        open htmldocs/theindex.html; \
    else \
        echo "Open htmldocs/theindex.html in your browser"; \
    fi

# =============================================================================
# CLEANUP
# =============================================================================

# Clean intermediate build cache (preserves binaries)
_clean-cache:
    @rm -rf nimcache/
    @rm -f testresults.html
    @rm -f outputGotten.txt
    @rm -f tests/megatest tests/megatest.nim

# Clean all build artifacts including binaries
clean:
    @echo "Cleaning build artifacts..."
    rm -rf bin/yabb bin/*.exe
    rm -rf nimcache/
    rm -rf htmldocs/
    rm -f testresults.html
    rm -f outputGotten.txt
    rm -f tests/megatest tests/megatest.nim
    @echo "Clean complete"

# Deep clean (includes nimble cache)
clean-all: clean
    @echo "Deep cleaning..."
    rm -rf nimblecache/
    rm -rf nimbledeps/
    @echo "Deep clean complete"

# =============================================================================
# DEBUGGING
# =============================================================================

# Show debug configuration info
debug-info:
    @echo "Nim Debug Configuration:"
    @echo "========================"
    @echo "Nim version:     $(nim --version | head -1)"
    @echo "Pretty-printer:  ~/.choosenim/toolchains/nim-{{NIM_VERSION}}/tools/debug/nimlldb.py"
    @echo ""
    @if [ -f ~/.choosenim/toolchains/nim-{{NIM_VERSION}}/tools/debug/nimlldb.py ]; then \
        echo "LLDB pretty-printer found"; \
    else \
        echo "LLDB pretty-printer NOT found"; \
    fi
    @if [ -f ~/.choosenim/toolchains/nim-{{NIM_VERSION}}/tools/debug/nim-gdb.py ]; then \
        echo "GDB pretty-printer found"; \
    else \
        echo "GDB pretty-printer NOT found"; \
    fi

# =============================================================================
# DEVELOPMENT HELPERS
# =============================================================================

# Quick build and run with --help
run: build
    @echo ""
    ./bin/yabb --help

# Quick build and run with custom args
run-args *ARGS: build
    @echo ""
    ./bin/yabb {{ARGS}}

# Watch for changes and rebuild (requires entr)
watch:
    @echo "Watching for changes... (Ctrl+C to stop)"
    @find src/ -name '*.nim' | entr -c just build

# Watch and run tests on change
watch-test:
    @echo "Watching for changes... (Ctrl+C to stop)"
    @find src/ tests/ -name '*.nim' | entr -c just test

# =============================================================================
# BINARY INFO
# =============================================================================

# Show binary info
binary-info:
    @echo "Binary information:"
    @file bin/yabb 2>/dev/null || echo "Binary not found - run 'just build' first"
    @ls -lh bin/yabb 2>/dev/null || true
    @ldd bin/yabb 2>/dev/null || echo "(static binary - no dynamic dependencies)"
