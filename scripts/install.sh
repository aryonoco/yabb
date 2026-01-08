#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
#===============================================================================
# install.sh - YABB binary installer
#
# DESCRIPTION:
#   Download and install YABB (Yet Another BTRFS Backup) from GitHub releases.
#
# REQUIREMENTS:
#   Bash 5.2+
#   Linux (x86_64, aarch64, riscv64, ppc64le, or loongarch64)
#   curl, tar, zstd, sha256sum
#
# USAGE:
#   curl -fsSL https://raw.githubusercontent.com/aryonoco/yabb/main/scripts/install.sh | sudo bash
#   sudo ./install.sh
#   sudo ./install.sh --dir /usr/local/bin --version v0.4.3
#   sudo ./install.sh --remove
#
# INSTALLATION OPTIONS:
#   -d, --dir PATH       Install directory (default: /opt/yabb)
#   -v, --version VER    Install specific version (default: latest)
#   --no-config          Skip config file installation
#   --no-completions     Skip shell completion installation
#
# REMOVAL OPTIONS:
#   --remove             Remove YABB installation
#   --purge              Also remove config files
#   -f, --force          Skip confirmation prompts
#
# GENERAL OPTIONS:
#   --dry-run            Show what would be done without making changes
#   --verbose            Enable verbose output
#   --help, -h           Show this help message
#
# ENVIRONMENT:
#   TRACE=1              Enable bash debug tracing
#
# LICENSE:               MPL-2.0
#===============================================================================

# shellcheck enable=check-set-e-suppressed
# shellcheck enable=check-extra-masked-returns

# Intentional patterns that shellcheck flags at info level:
# - SC2310: Functions in conditionals (has_command, confirm_action) are intentional control flow
# - SC2016: Single-quoted $PATH is intentional (user should see literal $PATH to copy)
# - SC2312: ls -A in subshell for empty dir check is intentional (we check output, not exit code)

#-------------------------------------------------------------------------------
# Bash Version Check
#-------------------------------------------------------------------------------
if ((BASH_VERSINFO[0] < 5 || (BASH_VERSINFO[0] == 5 && BASH_VERSINFO[1] < 2))); then
  printf 'Error: This script requires Bash 5.2+. Current: %s\n' "${BASH_VERSION}" >&2
  exit 1
fi

#-------------------------------------------------------------------------------
# Strict Mode & Safety Settings
#-------------------------------------------------------------------------------
set -o errexit
set -o errtrace
set -o nounset
set -o pipefail
shopt -s extglob
shopt -s globskipdots
shopt -s inherit_errexit
shopt -s assoc_expand_once

# Debug tracing
[[ ${TRACE:-0} == 1 ]] && set -o xtrace

#-------------------------------------------------------------------------------
# Constants
#-------------------------------------------------------------------------------
declare -r SCRIPT_NAME="${0##*/}"
declare -r SCRIPT_VERSION="1.0.0"

# GitHub configuration
declare -r GITHUB_REPO="aryonoco/yabb"
declare -r GITHUB_API="https://api.github.com/repos/${GITHUB_REPO}/releases"
declare -r GITHUB_DOWNLOAD="https://github.com/${GITHUB_REPO}/releases/download"

# Default paths
declare -r DEFAULT_INSTALL_DIR="/opt/yabb"
declare -r SYSTEM_CONFIG_PATH="/etc/yabb.toml"

# Security: Domain allowlist for downloads
declare -ra ALLOWED_DOWNLOAD_DOMAINS=(
  github.com
  api.github.com
  objects.githubusercontent.com
)

# Network configuration
declare -ri MAX_RETRIES=5
declare -ri RETRY_DELAY_BASE=2
declare -ri DOWNLOAD_TIMEOUT=60
declare -ri MAX_DOWNLOAD_SIZE=52428800

# Exit codes
declare -ri EXIT_SUCCESS=0
declare -ri EXIT_GENERAL_ERROR=1
declare -ri EXIT_INVALID_ARGS=2
declare -ri EXIT_ROOT_REQUIRED=3
declare -ri EXIT_UNSUPPORTED_ARCH=4
declare -ri EXIT_NETWORK_ERROR=5
declare -ri EXIT_CHECKSUM_FAILED=6
declare -ri EXIT_INSTALL_FAILED=7

# Required commands
declare -ra REQUIRED_COMMANDS=(
  curl tar zstd sha256sum grep uname mkdir rm mv cp chmod mktemp cut
)

# Architecture mapping (uname -m -> release archive suffix)
declare -rA ARCH_MAP=(
  [x86_64]="amd64"
  [aarch64]="arm64"
  [riscv64]="riscv64"
  [ppc64le]="ppc64le"
  [loongarch64]="loong64"
)

#-------------------------------------------------------------------------------
# Global State Variables
#-------------------------------------------------------------------------------
declare INSTALL_DIR="${DEFAULT_INSTALL_DIR}"
declare YABB_VERSION="latest"
declare DRY_RUN=false
declare VERBOSE=false
declare INSTALL_CONFIG=true
declare INSTALL_COMPLETIONS=true
declare SHOW_HELP=false

# Removal mode state
declare REMOVE_MODE=false
declare PURGE_CONFIG=false
declare FORCE_REMOVE=false

# Detected values
declare ARCH=""
declare RESOLVED_VERSION=""

# Cleanup state tracking
declare -i CLEANUP_IN_PROGRESS=0
declare -i SIGNAL_RECEIVED=0
declare RECEIVED_SIGNAL=""
declare -a CLEANUP_ACTIONS=()
declare -A CREATED_FILES=()
declare TEMP_DIR=""

#-------------------------------------------------------------------------------
# Terminal Colors
#-------------------------------------------------------------------------------
declare -A COLORS
if [[ -t 1 && ${TERM:-dumb} != dumb ]]; then
  COLORS=(
    [red]='\033[0;31m'
    [green]='\033[0;32m'
    [yellow]='\033[0;33m'
    [blue]='\033[0;34m'
    [cyan]='\033[0;36m'
    [bold]='\033[1m'
    [reset]='\033[0m'
  )
else
  COLORS=([red]='' [green]='' [yellow]='' [blue]='' [cyan]='' [bold]='' [reset]='')
fi

#-------------------------------------------------------------------------------
# Logging Functions
#-------------------------------------------------------------------------------
_log() {
  local -r level="$1" color="$2" msg="$3"
  local timestamp
  printf -v timestamp '%(%Y-%m-%d %H:%M:%S)T' "${EPOCHSECONDS}"
  printf '%b[%s]%b %s - %s\n' "${COLORS[${color}]}" "${level}" "${COLORS[reset]}" "${timestamp}" "${msg}"
}

log_info() { _log "INFO " "blue" "$1"; }
log_success() { _log "OK   " "green" "$1"; }
log_warn() { _log "WARN " "yellow" "$1" >&2; }
log_error() { _log "ERROR" "red" "$1" >&2; }
log_debug() {
  if [[ ${VERBOSE} == true ]]; then
    _log "DEBUG" "cyan" "$1"
  fi
}

log_step() {
  local -r step="$1" desc="$2"
  printf '\n%b%b[Step %s]%b %s\n' "${COLORS[bold]}" "${COLORS[blue]}" "${step}" "${COLORS[reset]}" "${desc}"
  printf '%s\n' "$(printf -- '-%.0s' {1..60})"
}

#-------------------------------------------------------------------------------
# Utility Functions
#-------------------------------------------------------------------------------
die() {
  log_error "$1"
  exit "${2:-${EXIT_GENERAL_ERROR}}"
}

has_command() {
  command -v "$1" &> /dev/null
}

# Dry-run aware execution
execute() {
  if [[ ${DRY_RUN} == true ]]; then
    log_info "[DRY-RUN] Would execute: ${*@Q}"
    return 0
  fi
  log_debug "Executing: ${*@Q}"
  "$@"
}

# Confirmation prompt (respects --force and --dry-run)
confirm_action() {
  local -r prompt="$1"

  # Force mode bypasses confirmation
  [[ ${FORCE_REMOVE} == true ]] && return 0

  # Dry-run mode assumes yes for preview
  if [[ ${DRY_RUN} == true ]]; then
    log_info "[DRY-RUN] Would prompt: ${prompt}"
    return 0
  fi

  # Non-interactive mode: decline by default
  if [[ ! -t 0 ]]; then
    log_warn "Non-interactive mode - use --force to proceed"
    return 1
  fi

  # Interactive prompt
  printf '%b%s [y/N]: %b' "${COLORS[yellow]}" "${prompt}" "${COLORS[reset]}"
  local response
  read -r response
  [[ ${response,,} =~ ^(y|yes)$ ]]
}

#-------------------------------------------------------------------------------
# Download
#-------------------------------------------------------------------------------
validate_url() {
  local -r url="$1"
  local -r pattern='^https://[a-zA-Z0-9][-a-zA-Z0-9]*(\.[a-zA-Z0-9][-a-zA-Z0-9]*)+(/[-a-zA-Z0-9_.~%/]*)?$'

  # Validate URL format
  if [[ ! ${url} =~ ${pattern} ]]; then
    die "Invalid URL format: ${url}" "${EXIT_NETWORK_ERROR}"
  fi

  # Extract domain from URL
  local domain="${url#https://}"
  domain="${domain%%/*}"

  # Validate against allowed domains
  local allowed=false d
  for d in "${ALLOWED_DOWNLOAD_DOMAINS[@]}"; do
    if [[ ${domain} == "${d}" || ${domain} == *".${d}" ]]; then
      allowed=true
      break
    fi
  done

  if [[ ${allowed} != true ]]; then
    die "URL domain not in allowlist: ${domain}" "${EXIT_NETWORK_ERROR}"
  fi
}

secure_download() {
  local -r url="$1" output="$2"
  local -ri max_size="${3:-${MAX_DOWNLOAD_SIZE}}"

  validate_url "${url}"

  curl -fsSL \
    --proto '=https' \
    --tlsv1.2 \
    --connect-timeout 10 \
    --max-time "${DOWNLOAD_TIMEOUT}" \
    --retry 3 \
    --retry-connrefused \
    --max-filesize "${max_size}" \
    -o "${output}" \
    "${url}"
}

secure_fetch() {
  local -r url="$1"

  validate_url "${url}"

  curl -fsSL \
    --proto '=https' \
    --tlsv1.2 \
    --connect-timeout 10 \
    --max-time "${DOWNLOAD_TIMEOUT}" \
    --retry 3 \
    --retry-connrefused \
    "${url}"
}

#-------------------------------------------------------------------------------
# Retry with Exponential Backoff
#-------------------------------------------------------------------------------
retry_with_backoff() {
  local -ri max_attempts="$1"
  local -i delay="$2"
  shift 2
  local -a cmd=("$@")
  local -i attempt=1
  local output
  local -i exit_code

  while ((attempt <= max_attempts)); do
    if output=$("${cmd[@]}" 2>&1); then
      printf '%s' "${output}"
      return 0
    fi
    exit_code=$?

    if ((attempt == max_attempts)); then
      log_error "Command failed after ${max_attempts} attempts: ${cmd[*]@Q}"
      log_error "Last output: ${output}"
      return 1
    fi

    # Check for rate limiting or server errors
    if [[ ${output} =~ (429|503|rate.limit|"Too Many Requests") ]]; then
      log_warn "Rate limited (attempt ${attempt}/${max_attempts}). Waiting ${delay}s..."
      ((delay *= 3))
    else
      log_warn "Attempt ${attempt}/${max_attempts} failed (exit: ${exit_code}). Retrying in ${delay}s..."
      ((delay *= 2))
    fi

    # Cap maximum delay
    ((delay > 60)) && delay=60

    sleep "${delay}"
    ((attempt++))
  done
}

#-------------------------------------------------------------------------------
# Signal & Cleanup
#-------------------------------------------------------------------------------
declare -rA SIGNAL_INFO=(
  [HUP]="1:Hangup:graceful"
  [INT]="2:Interrupt:graceful"
  [QUIT]="3:Quit:graceful"
  [TERM]="15:Terminated:graceful"
)

signal_handler() {
  local -r sig_name="${1:-UNKNOWN}"
  local sig_num=1

  # Prevent re-entrant signal handling
  ((SIGNAL_RECEIVED)) && return
  SIGNAL_RECEIVED=1
  RECEIVED_SIGNAL="${sig_name}"

  # Parse signal info
  if [[ -v SIGNAL_INFO[${sig_name}] ]]; then
    IFS=':' read -r sig_num _ _ <<< "${SIGNAL_INFO[${sig_name}]}"
  fi

  log_warn "Received SIG${sig_name} - initiating cleanup..."
  exit $((128 + sig_num))
}

error_handler() {
  local -ri exit_code=$?
  local -r failed_cmd="${BASH_COMMAND}"
  local -r line="${BASH_LINENO[0]}"
  local -r func="${FUNCNAME[1]:-main}"

  # Don't trigger for intentional failures
  ((exit_code == 0)) && return 0

  log_error "Command failed with exit code ${exit_code}"
  log_error "  Location: ${func}() at line ${line}"
  log_error "  Command:  ${failed_cmd}"

  # Show stack trace in verbose mode
  if [[ ${VERBOSE} == true ]]; then
    log_debug "Stack trace:"
    local -i i
    for ((i = 1; i < ${#FUNCNAME[@]}; i++)); do
      log_debug "  [${i}] ${FUNCNAME[i]}() at ${BASH_SOURCE[i]:-unknown}:${BASH_LINENO[i - 1]}"
    done
  fi
}

register_cleanup() {
  local -r action="$1"
  CLEANUP_ACTIONS+=("${action}")
  log_debug "Registered cleanup action: ${action}"
}

register_created_file() {
  local -r file="$1"
  CREATED_FILES["${file}"]=1
  log_debug "Tracking created file: ${file}"
}

cleanup() {
  local -ri original_exit_code=$?
  local -i exit_code=${original_exit_code}

  # Prevent recursive cleanup
  ((CLEANUP_IN_PROGRESS)) && return
  CLEANUP_IN_PROGRESS=1

  # Disable all signal traps during cleanup
  trap '' INT TERM HUP QUIT

  log_debug "Cleanup triggered (exit_code=${exit_code}, signal=${RECEIVED_SIGNAL:-none})"

  # Execute registered cleanup actions in reverse order (LIFO)
  local -i i
  for ((i = ${#CLEANUP_ACTIONS[@]} - 1; i >= 0; i--)); do
    local action="${CLEANUP_ACTIONS[i]}"
    log_debug "Executing cleanup action: ${action}"
    if declare -F "${action}" &> /dev/null; then
      "${action}" 2> /dev/null || true
    fi
  done

  # Rollback: Remove files we created (if exit was not successful)
  if ((exit_code != 0)); then
    log_info "Rolling back changes..."
    for file in "${!CREATED_FILES[@]}"; do
      if [[ -e ${file} ]]; then
        log_debug "Removing created file: ${file}"
        rm -rf "${file}" 2> /dev/null || true
      fi
    done
  fi

  # Final status
  if ((exit_code != 0)); then
    log_error "Script failed with exit code: ${exit_code}"
    [[ -n ${RECEIVED_SIGNAL:-} ]] && log_error "Terminated by: SIG${RECEIVED_SIGNAL}"
  fi

  exit "${exit_code}"
}

setup_signal_handlers() {
  # EXIT trap - always runs, handles all cleanup
  trap cleanup EXIT

  # ERR trap - provides error context
  trap error_handler ERR

  # Graceful termination signals
  trap 'signal_handler HUP' HUP
  trap 'signal_handler INT' INT
  trap 'signal_handler QUIT' QUIT
  trap 'signal_handler TERM' TERM

  log_debug "Signal handlers installed"
}

#-------------------------------------------------------------------------------
# Temp Directory Management
#-------------------------------------------------------------------------------
create_temp_dir() {
  TEMP_DIR=$(mktemp -d -t yabb-install.XXXXXX) || die "Failed to create temp directory" "${EXIT_GENERAL_ERROR}"
  chmod 700 "${TEMP_DIR}"
  register_cleanup "cleanup_temp_dir"
  log_debug "Created temp directory: ${TEMP_DIR}"
}

cleanup_temp_dir() {
  if [[ -n ${TEMP_DIR} && -d ${TEMP_DIR} ]]; then
    rm -rf "${TEMP_DIR}"
    log_debug "Removed temp directory: ${TEMP_DIR}"
  fi
}

#-------------------------------------------------------------------------------
# Validation Functions
#-------------------------------------------------------------------------------
check_root() {
  if ((EUID != 0)); then
    die "This script must be run as root. Use: sudo ${SCRIPT_NAME}" "${EXIT_ROOT_REQUIRED}"
  fi
}

validate_required_commands() {
  log_info "Validating required commands..."

  local -a missing=()
  local cmd

  for cmd in "${REQUIRED_COMMANDS[@]}"; do
    # shellcheck disable=SC2310  # Intentional: check command existence
    if ! has_command "${cmd}"; then
      missing+=("${cmd}")
    fi
  done

  if ((${#missing[@]} > 0)); then
    log_error "Missing required command(s): ${missing[*]}"
    die "Install missing commands and try again" "${EXIT_GENERAL_ERROR}"
  fi

  log_success "All required commands available"
}

#-------------------------------------------------------------------------------
# ISA Detection
#-------------------------------------------------------------------------------
detect_architecture() {
  log_info "Detecting system architecture..."

  local machine
  machine="$(uname -m)" || die "Failed to detect architecture" "${EXIT_GENERAL_ERROR}"

  if [[ -v ARCH_MAP[${machine}] ]]; then
    ARCH="${ARCH_MAP[${machine}]}"
    log_success "Architecture: ${machine} -> ${ARCH}"
  else
    die "Unsupported architecture: ${machine}. Supported: ${!ARCH_MAP[*]}" "${EXIT_UNSUPPORTED_ARCH}"
  fi
}

#-------------------------------------------------------------------------------
# Version Resolution
#-------------------------------------------------------------------------------
resolve_version() {
  log_info "Resolving version..."

  if [[ ${YABB_VERSION} == "latest" ]]; then
    log_debug "Fetching latest release from GitHub API..."

    local response
    # shellcheck disable=SC2310  # Intentional: error handling with || die
    response=$(retry_with_backoff "${MAX_RETRIES}" "${RETRY_DELAY_BASE}" \
      secure_fetch "${GITHUB_API}/latest") || die "Failed to fetch latest version" "${EXIT_NETWORK_ERROR}"

    # Parse tag_name from JSON response
    RESOLVED_VERSION=$(printf '%s' "${response}" | grep -oE '"tag_name"[[:space:]]*:[[:space:]]*"[^"]+"' | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | head -1)

    if [[ -z ${RESOLVED_VERSION} ]]; then
      die "Failed to parse version from API response" "${EXIT_NETWORK_ERROR}"
    fi
  else
    RESOLVED_VERSION="${YABB_VERSION}"

    # Validate version format
    if [[ ! ${RESOLVED_VERSION} =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?$ ]]; then
      die "Invalid version format: ${RESOLVED_VERSION} (expected: vX.Y.Z or vX.Y.Z-suffix)" "${EXIT_INVALID_ARGS}"
    fi
  fi

  log_success "Version: ${RESOLVED_VERSION}"
}

#-------------------------------------------------------------------------------
# Verification
#-------------------------------------------------------------------------------
download_and_verify() {
  log_step "3/4" "Downloading and verifying release"

  local -r version_num="${RESOLVED_VERSION#v}"
  local -r archive_name="yabb-${version_num}-linux-${ARCH}.tar.zst"
  local -r archive_url="${GITHUB_DOWNLOAD}/${RESOLVED_VERSION}/${archive_name}"
  local -r checksum_url="${GITHUB_DOWNLOAD}/${RESOLVED_VERSION}/SHA256SUMS"

  local -r archive_path="${TEMP_DIR}/${archive_name}"
  local -r checksum_path="${TEMP_DIR}/SHA256SUMS"

  # Download checksum file first
  log_info "Downloading checksums..."
  if [[ ${DRY_RUN} == true ]]; then
    log_info "[DRY-RUN] Would download: ${checksum_url}"
  else
    # shellcheck disable=SC2310  # Intentional: error handling with || die
    secure_download "${checksum_url}" "${checksum_path}" \
      || die "Failed to download checksums from ${checksum_url}" "${EXIT_NETWORK_ERROR}"
  fi

  # Download archive
  log_info "Downloading ${archive_name}..."
  if [[ ${DRY_RUN} == true ]]; then
    log_info "[DRY-RUN] Would download: ${archive_url}"
  else
    # shellcheck disable=SC2310  # Intentional: error handling with || die
    secure_download "${archive_url}" "${archive_path}" \
      || die "Failed to download archive from ${archive_url}" "${EXIT_NETWORK_ERROR}"
  fi

  # Verify checksum
  if [[ ${DRY_RUN} == true ]]; then
    log_info "[DRY-RUN] Would verify SHA256 checksum"
  else
    log_info "Verifying SHA256 checksum..."

    local expected_checksum
    expected_checksum=$(grep "${archive_name}" "${checksum_path}" | cut -d' ' -f1)

    if [[ -z ${expected_checksum} ]]; then
      die "Checksum not found for ${archive_name} in SHA256SUMS" "${EXIT_CHECKSUM_FAILED}"
    fi

    local actual_checksum
    actual_checksum=$(sha256sum "${archive_path}" | cut -d' ' -f1)

    if [[ ${expected_checksum} != "${actual_checksum}" ]]; then
      log_error "Checksum mismatch!"
      log_error "Expected: ${expected_checksum}"
      log_error "Got:      ${actual_checksum}"
      die "Security verification failed - archive may be corrupted or tampered" "${EXIT_CHECKSUM_FAILED}"
    fi

    log_success "Checksum verified"
  fi

  # Extract archive (zstd compressed)
  log_info "Extracting archive..."
  if [[ ${DRY_RUN} == true ]]; then
    log_info "[DRY-RUN] Would extract: ${archive_path}"
  else
    zstd -d -c "${archive_path}" | tar -xf - -C "${TEMP_DIR}" \
      || die "Failed to extract archive" "${EXIT_INSTALL_FAILED}"
    log_success "Archive extracted"
  fi
}

#-------------------------------------------------------------------------------
# File Installation
#-------------------------------------------------------------------------------
install_files() {
  log_step "4/4" "Installing files"

  local -r version_num="${RESOLVED_VERSION#v}"
  local -r extract_dir="${TEMP_DIR}/yabb-${version_num}-linux-${ARCH}"

  # Create install directory
  if [[ ! -d ${INSTALL_DIR} ]]; then
    log_info "Creating directory: ${INSTALL_DIR}"
    execute mkdir -p "${INSTALL_DIR}"
    register_created_file "${INSTALL_DIR}"
  fi

  # Install binary
  log_info "Installing binary..."
  if [[ ${DRY_RUN} == true ]]; then
    log_info "[DRY-RUN] Would install: ${INSTALL_DIR}/yabb"
  else
    cp "${extract_dir}/yabb" "${INSTALL_DIR}/yabb"
    chmod 755 "${INSTALL_DIR}/yabb"
    register_created_file "${INSTALL_DIR}/yabb"
  fi
  log_success "Installed: ${INSTALL_DIR}/yabb"

  # Install shell completions
  if [[ ${INSTALL_COMPLETIONS} == true ]]; then
    log_info "Installing shell completions..."
    local comp
    local -i installed=0
    for comp in yabb.bash yabb.fish yabb.zsh; do
      if [[ ${DRY_RUN} == true ]]; then
        log_info "[DRY-RUN] Would install: ${INSTALL_DIR}/${comp}"
        installed+=1
      elif [[ -f ${extract_dir}/shell_completions/${comp} ]]; then
        cp "${extract_dir}/shell_completions/${comp}" "${INSTALL_DIR}/"
        register_created_file "${INSTALL_DIR}/${comp}"
        installed+=1
      fi
    done
    log_success "Installed ${installed} completion file(s) to ${INSTALL_DIR}/"
  fi

  # Install systemd service files
  log_info "Installing systemd service files..."
  local -a systemd_files=(
    "yabb.service"
    "yabb.timer"
    "yabb-update.service"
    "yabb-update.timer"
    "yabb-update.conf"
  )
  local sfile
  for sfile in "${systemd_files[@]}"; do
    if [[ ${DRY_RUN} == true ]]; then
      log_info "[DRY-RUN] Would install: ${INSTALL_DIR}/${sfile}"
    elif [[ -f ${extract_dir}/scripts/${sfile} ]]; then
      cp "${extract_dir}/scripts/${sfile}" "${INSTALL_DIR}/"
      register_created_file "${INSTALL_DIR}/${sfile}"
    fi
  done
  log_success "Installed systemd files to ${INSTALL_DIR}/"

  # Install install.sh itself for future updates
  if [[ ${DRY_RUN} == true ]]; then
    log_info "[DRY-RUN] Would install: ${INSTALL_DIR}/install.sh"
  elif [[ -f ${extract_dir}/scripts/install.sh ]]; then
    cp "${extract_dir}/scripts/install.sh" "${INSTALL_DIR}/"
    chmod +x "${INSTALL_DIR}/install.sh"
    register_created_file "${INSTALL_DIR}/install.sh"
    log_success "Installed: ${INSTALL_DIR}/install.sh"
  fi

  # Handle configuration
  if [[ ${INSTALL_CONFIG} == true ]]; then
    # Always copy sample config to install dir as reference
    if [[ ${DRY_RUN} == true ]]; then
      log_info "[DRY-RUN] Would copy sample config to: ${INSTALL_DIR}/yabb.conf"
    else
      cp "${extract_dir}/yabb.conf" "${INSTALL_DIR}/yabb.conf"
      register_created_file "${INSTALL_DIR}/yabb.conf"
    fi

    # Handle system config
    if [[ -f ${SYSTEM_CONFIG_PATH} ]]; then
      log_info "Existing config found: ${SYSTEM_CONFIG_PATH}"
      log_info "Sample config available at: ${INSTALL_DIR}/yabb.conf"
    else
      log_info "Installing config to ${SYSTEM_CONFIG_PATH}..."
      if [[ ${DRY_RUN} == true ]]; then
        log_info "[DRY-RUN] Would install config to: ${SYSTEM_CONFIG_PATH}"
      else
        cp "${extract_dir}/yabb.conf" "${SYSTEM_CONFIG_PATH}"
        register_created_file "${SYSTEM_CONFIG_PATH}"
      fi
      log_success "Config installed (edit before first use)"
    fi
  fi
}

#-------------------------------------------------------------------------------
# Post Install Summary
#-------------------------------------------------------------------------------
print_summary() {
  printf '\n%b%b' "${COLORS[bold]}" "${COLORS[green]}"
  printf '================================================================================\n'
  printf 'Installation Complete!\n'
  printf '================================================================================\n'
  printf '%b' "${COLORS[reset]}"

  printf '\nInstalled version: %s\n' "${RESOLVED_VERSION}"
  printf 'Binary:            %s/yabb\n' "${INSTALL_DIR}"

  if [[ -f ${SYSTEM_CONFIG_PATH} ]]; then
    printf 'Config:            %s\n' "${SYSTEM_CONFIG_PATH}"
  else
    printf 'Sample config:     %s/yabb.conf\n' "${INSTALL_DIR}"
  fi

  printf '\nNext steps:\n'
  local -i step=1
  if [[ ! -f ${SYSTEM_CONFIG_PATH} ]]; then
    printf '  %d. Create config:  sudo cp %s/yabb.conf %s\n' "${step}" "${INSTALL_DIR}" "${SYSTEM_CONFIG_PATH}"
    ((step++)) || true
  fi
  printf '  %d. Edit config:    sudo nano %s\n' "${step}" "${SYSTEM_CONFIG_PATH}"
  ((step++)) || true
  # shellcheck disable=SC2016  # Intentional: show literal $PATH for user to copy
  printf '  %d. Add to PATH:    export PATH="%s:$PATH"\n' "${step}" "${INSTALL_DIR}"
  ((step++)) || true
  printf '  %d. Verify:         %s/yabb --help\n' "${step}" "${INSTALL_DIR}"
  ((step++)) || true
  printf '  %d. Validate:       sudo %s/yabb validate\n' "${step}" "${INSTALL_DIR}"
  printf '\n'
}

#-------------------------------------------------------------------------------
# Removal Functions
#-------------------------------------------------------------------------------
run_removal() {
  log_info "YABB Removal Mode"

  # Confirm unless --force
  # shellcheck disable=SC2310  # Intentional: confirm_action returns status for branching
  if ! confirm_action "Remove YABB from ${INSTALL_DIR}?"; then
    log_info "Removal cancelled"
    exit "${EXIT_SUCCESS}"
  fi

  remove_step_binary
  remove_step_completions

  if [[ ${PURGE_CONFIG} == true ]]; then
    remove_step_config
  fi

  printf '\n%b%b' "${COLORS[bold]}" "${COLORS[green]}"
  printf '================================================================================\n'
  printf 'Removal Complete!\n'
  printf '================================================================================\n'
  printf '%b\n' "${COLORS[reset]}"
}

remove_step_binary() {
  log_step "1/3" "Removing binary"

  if [[ -f "${INSTALL_DIR}/yabb" ]]; then
    execute rm -f "${INSTALL_DIR}/yabb"
    log_success "Removed: ${INSTALL_DIR}/yabb"
  else
    log_warn "Binary not found: ${INSTALL_DIR}/yabb"
  fi
}

remove_step_completions() {
  log_step "2/3" "Removing shell completions, systemd files, and sample config"

  local -a files_to_remove=(
    "${INSTALL_DIR}/yabb.bash"
    "${INSTALL_DIR}/yabb.fish"
    "${INSTALL_DIR}/yabb.zsh"
    "${INSTALL_DIR}/yabb.conf"
    "${INSTALL_DIR}/yabb.service"
    "${INSTALL_DIR}/yabb.timer"
    "${INSTALL_DIR}/yabb-update.service"
    "${INSTALL_DIR}/yabb-update.timer"
    "${INSTALL_DIR}/yabb-update.conf"
    "${INSTALL_DIR}/install.sh"
  )

  local file
  local -i removed=0
  for file in "${files_to_remove[@]}"; do
    if [[ -f ${file} ]]; then
      execute rm -f "${file}"
      removed+=1
    fi
  done

  if ((removed > 0)); then
    log_success "Removed ${removed} file(s)"
  else
    log_info "No additional files found"
  fi

  # Remove install directory if empty
  if [[ -d ${INSTALL_DIR} ]]; then
    # shellcheck disable=SC2312  # Intentional: checking if output is empty, not exit code
    if [[ -z $(ls -A "${INSTALL_DIR}" 2> /dev/null) ]]; then
      execute rmdir "${INSTALL_DIR}"
      log_success "Removed empty directory: ${INSTALL_DIR}"
    else
      log_info "Directory not empty, keeping: ${INSTALL_DIR}"
    fi
  fi
}

remove_step_config() {
  log_step "3/3" "Removing configuration"

  # System config
  if [[ -f ${SYSTEM_CONFIG_PATH} ]]; then
    # shellcheck disable=SC2310  # Intentional: confirm_action returns status for branching
    if confirm_action "Remove system config ${SYSTEM_CONFIG_PATH}?"; then
      execute rm -f "${SYSTEM_CONFIG_PATH}"
      log_success "Removed: ${SYSTEM_CONFIG_PATH}"
    else
      log_info "Keeping: ${SYSTEM_CONFIG_PATH}"
    fi
  else
    log_info "System config not found: ${SYSTEM_CONFIG_PATH}"
  fi

  # User config (XDG location)
  local -r user_config_dir="${HOME}/.config/yabb"
  local -r user_config="${user_config_dir}/yabb.toml"

  if [[ -f ${user_config} ]]; then
    # shellcheck disable=SC2310  # Intentional: confirm_action returns status for branching
    if confirm_action "Remove user config ${user_config}?"; then
      execute rm -f "${user_config}"
      # shellcheck disable=SC2312  # Intentional: checking if output is empty, not exit code
      if [[ -d ${user_config_dir} && -z $(ls -A "${user_config_dir}" 2> /dev/null) ]]; then
        rmdir "${user_config_dir}" 2> /dev/null || true
      fi
      log_success "Removed: ${user_config}"
    else
      log_info "Keeping: ${user_config}"
    fi
  fi
}

#-------------------------------------------------------------------------------
# Help
#-------------------------------------------------------------------------------
show_help() {
  cat << EOF
${SCRIPT_NAME} v${SCRIPT_VERSION} - YABB Binary Installer

USAGE:
  ${SCRIPT_NAME} [OPTIONS]

DESCRIPTION:
  Download and install YABB (Yet Another BTRFS Backup) from GitHub releases.
  Automatically detects architecture (x86_64/aarch64/riscv64/ppc64le/loongarch64) and verifies checksums.

INSTALLATION OPTIONS:
  -d, --dir PATH       Install directory (default: ${DEFAULT_INSTALL_DIR})
  -v, --version VER    Install specific version (default: latest)
                       Example: --version v0.4.3
  --no-config          Skip config file installation
  --no-completions     Skip shell completion installation

REMOVAL OPTIONS:
  --remove             Remove YABB binary and completions
  --purge              Also remove config files (/etc/yabb.toml and user config)
  -f, --force          Skip confirmation prompts

GENERAL OPTIONS:
  --dry-run            Show what would be done without making changes
  --verbose            Enable verbose/debug output
  -h, --help           Show this help message

ENVIRONMENT:
  TRACE=1              Enable bash debug tracing (set -x)

EXAMPLES:
  # Install latest version
  sudo ${SCRIPT_NAME}

  # Install specific version
  sudo ${SCRIPT_NAME} --version v0.4.3

  # Install to custom directory
  sudo ${SCRIPT_NAME} --dir /usr/local/bin

  # Preview installation (dry-run)
  sudo ${SCRIPT_NAME} --dry-run --verbose

  # Remove installation
  sudo ${SCRIPT_NAME} --remove

  # Remove including config files
  sudo ${SCRIPT_NAME} --remove --purge --force

  # Pipe installation (curl | bash)
  curl -fsSL https://raw.githubusercontent.com/aryonoco/yabb/main/scripts/install.sh | sudo bash

EOF
}

#-------------------------------------------------------------------------------
# Argument Parsing
#-------------------------------------------------------------------------------
parse_args() {
  while (($# > 0)); do
    case "$1" in
      -d | --dir)
        [[ -n ${2:-} ]] || die "Option $1 requires an argument" "${EXIT_INVALID_ARGS}"
        INSTALL_DIR="$2"
        shift 2
        ;;
      -v | --version)
        [[ -n ${2:-} ]] || die "Option $1 requires an argument" "${EXIT_INVALID_ARGS}"
        YABB_VERSION="$2"
        shift 2
        ;;
      --no-config)
        INSTALL_CONFIG=false
        shift
        ;;
      --no-completions)
        INSTALL_COMPLETIONS=false
        shift
        ;;
      --remove)
        REMOVE_MODE=true
        shift
        ;;
      --purge)
        PURGE_CONFIG=true
        shift
        ;;
      -f | --force)
        FORCE_REMOVE=true
        shift
        ;;
      --dry-run)
        DRY_RUN=true
        shift
        ;;
      --verbose)
        VERBOSE=true
        shift
        ;;
      -h | --help)
        SHOW_HELP=true
        shift
        ;;
      -*)
        die "Unknown option: $1. Use --help for usage." "${EXIT_INVALID_ARGS}"
        ;;
      *)
        die "Unexpected argument: $1. Use --help for usage." "${EXIT_INVALID_ARGS}"
        ;;
    esac
  done
}

#-------------------------------------------------------------------------------
# Main Entry Points
#-------------------------------------------------------------------------------
run_installation() {
  log_info "YABB Installer v${SCRIPT_VERSION}"

  if [[ ${DRY_RUN} == true ]]; then
    log_warn "DRY-RUN MODE - No changes will be made"
  fi

  create_temp_dir

  log_step "1/4" "Detecting system"
  detect_architecture

  log_step "2/4" "Resolving version"
  resolve_version

  download_and_verify

  install_files

  print_summary
}

main() {
  setup_signal_handlers
  parse_args "$@"

  if [[ ${SHOW_HELP} == true ]]; then
    show_help
    exit "${EXIT_SUCCESS}"
  fi

  check_root

  validate_required_commands

  # Install or Remove
  if [[ ${REMOVE_MODE} == true ]]; then
    run_removal
  else
    run_installation
  fi
}

main "$@"
