#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2023-2026 Aryan Ameri
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#
#===============================================================================
# setup-yabb.sh - YABB binary installer
#
# DESCRIPTION:
#   Download and install YABB (Yet Another BTRFS Backup) from GitHub releases.
#
# REQUIREMENTS:
#   Bash 5.2+
#   Linux (x86_64, aarch64, riscv64, ppc64le, or loongarch64)
#   curl, tar, zstd, sha256sum, flock
#
# USAGE (please manually verify content first!):
#   curl -fsSL --proto '=https' --tlsv1.2 https://raw.githubusercontent.com/aryonoco/yabb/main/scripts/setup-yabb.sh | sudo bash
#   sudo ./setup-yabb.sh
#   sudo ./setup-yabb.sh --dir /opt/yabb --version v0.4.3
#   sudo ./setup-yabb.sh --remove
#   sudo ./setup-yabb.sh --remove --purge --force
#
# INSTALLATION OPTIONS:
#   -d, --dir PATH       Install directory (default: /opt/yabb)
#   -v, --version VER    Install specific version (default: latest)
#   -f, --force          Force installation even if same version
#   --no-config          Skip config file installation
#   --no-completions     Skip shell completion installation
#   --no-systemd         Skip systemd unit installation
#
# REMOVAL OPTIONS:
#   --remove             Remove YABB installation
#   --purge              Also remove config files
#   --force, -f          Skip confirmation prompts
#
# GENERAL OPTIONS:
#   --dry-run            Show what would be done without making changes
#   --verbose            Enable verbose output
#   --trace-commands     Enable command-level tracing (DEBUG trap)
#   --syslog             Also log to syslog (for enterprise environments)
#   --help, -h           Show this help message
#
# ENVIRONMENT:
#   TRACE=1              Enable bash debug tracing (set -x)
#
# LICENSE:               MPL-2.0
#===============================================================================

# shellcheck enable=check-set-e-suppressed
# shellcheck enable=check-extra-masked-returns

# Intentional patterns that shellcheck flags at info level:
# - SC2310: Functions in conditionals (has_command, etc.) are intentional control flow
# - SC2312: Command substitutions in local declarations are intentional (simple helpers)
# - SC2015: A && B || true pattern is intentional for optional increment/continue on error
# - SC2016: Single-quoted $PATH is intentional (user should see literal $PATH to copy)

#-------------------------------------------------------------------------------
# Bash Version Check - MUST BE FIRST EXECUTABLE CODE
#-------------------------------------------------------------------------------
if ((BASH_VERSINFO[0] < 5 || (BASH_VERSINFO[0] == 5 && BASH_VERSINFO[1] < 2))); then
  printf 'FATAL: Bash 5.2+ required. Current: %s\n' "${BASH_VERSION}" >&2
  exit 1
fi

#-------------------------------------------------------------------------------
# Strict Mode & Safety Settings
#-------------------------------------------------------------------------------
set -o errexit             # Exit on any command failure
set -o errtrace            # ERR trap inherited by functions/subshells
set -o nounset             # Exit on undefined variable
set -o pipefail            # Catch errors in pipelines
shopt -s extglob           # Extended pattern matching
shopt -s globskipdots      # Never match . or .. in globs (Bash 5.2+)
shopt -s inherit_errexit   # Command substitutions inherit errexit (Bash 4.4+)
shopt -s assoc_expand_once # Prevent double array subscript evaluation (Bash 5.0+)

# Enable debug tracing if TRACE=1
[[ ${TRACE:-0} == 1 ]] && set -o xtrace

# Command-level tracing
declare TRACE_COMMANDS=false

#-------------------------------------------------------------------------------
# Constants - Script Metadata
#-------------------------------------------------------------------------------
declare -r SCRIPT_NAME="${0##*/}"
declare -r SCRIPT_VERSION="2.0.0"
declare -r LOG_FILE="/var/log/yabb-install.log"
declare -r LOCK_FILE="/var/lock/yabb-install.lock"

#-------------------------------------------------------------------------------
# Constants - GitHub Configuration
#-------------------------------------------------------------------------------
declare -r GITHUB_REPO="aryonoco/yabb"
declare -r GITHUB_API="https://api.github.com/repos/${GITHUB_REPO}/releases"
declare -r GITHUB_DOWNLOAD="https://github.com/${GITHUB_REPO}/releases/download"

#-------------------------------------------------------------------------------
# Constants - Installation Paths
#-------------------------------------------------------------------------------
declare -r DEFAULT_INSTALL_DIR="/opt/yabb"
declare -r SYSTEM_CONFIG_PATH="/etc/yabb.toml"
declare -r SYSTEM_CONFIG_DIR="/etc/yabb"
declare -r SYSTEMD_UNIT_DIR="/etc/systemd/system"
declare -r BASH_COMPLETION_DIR="/etc/bash_completion.d"
declare -r ZSH_COMPLETION_DIR="/usr/local/share/zsh/site-functions"
declare -r FISH_COMPLETION_DIR="/usr/share/fish/vendor_completions.d"
declare -r STEP_MARKER_DIR="/var/lib/yabb-install"

#-------------------------------------------------------------------------------
# Constants - Security
#-------------------------------------------------------------------------------
# Allowed domains for downloads
declare -ra ALLOWED_DOWNLOAD_DOMAINS=(
  github.com
  api.github.com
  objects.githubusercontent.com
)

#-------------------------------------------------------------------------------
# Constants - Network Configuration
#-------------------------------------------------------------------------------
declare -ri MAX_RETRIES=5
declare -ri RETRY_DELAY_BASE=2
declare -ri DOWNLOAD_TIMEOUT=60
declare -ri MAX_DOWNLOAD_SIZE=52428800 # 50MB
declare -ri LOCK_TIMEOUT=300           # 5 minutes

#-------------------------------------------------------------------------------
# Constants - Disk Space
#-------------------------------------------------------------------------------
declare -ri REQUIRED_DISK_SPACE_MB=100 # Archive + extracted + staging + margin

#-------------------------------------------------------------------------------
# Constants - Exit Codes
#-------------------------------------------------------------------------------
declare -ri EXIT_SUCCESS=0
declare -ri EXIT_GENERAL_ERROR=1
declare -ri EXIT_LOCK_FAILED=2
declare -ri EXIT_INVALID_ARGS=3
declare -ri EXIT_ROOT_REQUIRED=4
declare -ri EXIT_UNSUPPORTED_ARCH=5
declare -ri EXIT_NETWORK_ERROR=6
declare -ri EXIT_CHECKSUM_FAILED=7
declare -ri EXIT_INSTALL_FAILED=8
declare -ri EXIT_DISK_SPACE=9
# shellcheck disable=SC2034  # Reserved for future use in confirm_action
declare -ri EXIT_USER_CANCELLED=10

#-------------------------------------------------------------------------------
# Constants - Required Commands
#-------------------------------------------------------------------------------
declare -ra REQUIRED_COMMANDS=(
  curl tar zstd sha256sum grep uname mkdir rm mv cp chmod
  mktemp cut flock stat realpath file sort
)

#-------------------------------------------------------------------------------
# Constants - ISA Mapping
#-------------------------------------------------------------------------------
declare -rA ARCH_MAP=(
  [x86_64]="amd64"
  [aarch64]="arm64"
  [riscv64]="riscv64"
  [ppc64le]="ppc64le"
  [loongarch64]="loong64"
)

#-------------------------------------------------------------------------------
# Constants - Systemd Files
#-------------------------------------------------------------------------------
declare -ra SYSTEMD_FILES=(
  "yabb.service"
  "yabb.timer"
)

#-------------------------------------------------------------------------------
# Global State Variables - Installation Options
#-------------------------------------------------------------------------------
declare INSTALL_DIR="${DEFAULT_INSTALL_DIR}"
declare YABB_VERSION="latest"
declare FORCE_INSTALL=false
declare INSTALL_CONFIG=true
declare INSTALL_COMPLETIONS=true
declare INSTALL_SYSTEMD=true

#-------------------------------------------------------------------------------
# Global State Variables - General Options
#-------------------------------------------------------------------------------
declare DRY_RUN=false
declare VERBOSE=false
declare SYSLOG=false
declare TRACE_COMMANDS=false

#-------------------------------------------------------------------------------
# Global State Variables - Removal Mode
#-------------------------------------------------------------------------------
declare REMOVE_MODE=false
declare PURGE_CONFIG=false
declare FORCE_REMOVE=false

#-------------------------------------------------------------------------------
# Global State Variables - Detected Values
#-------------------------------------------------------------------------------
declare ARCH=""
declare RESOLVED_VERSION=""
declare TEMP_DIR=""

#-------------------------------------------------------------------------------
# Global State Variables - Cleanup Tracking
#-------------------------------------------------------------------------------
declare -i CLEANUP_IN_PROGRESS=0
declare -i SIGNAL_RECEIVED=0
declare RECEIVED_SIGNAL=""
declare -a CLEANUP_ACTIONS=()
declare -A CREATED_FILES=()
declare -A MODIFIED_FILES=()

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
  printf '%b[%s]%b %s - %s\n' "${COLORS[${color}]}" "${level}" "${COLORS[reset]}" "${timestamp}" "${msg}" | tee -a "${LOG_FILE}"
  _syslog "${level}" "${msg}"
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

# Send to syslog if enabled
_syslog() {
  local -r level="$1" msg="$2"
  if [[ ${SYSLOG} == true ]]; then
    # shellcheck disable=SC2310
    if has_command logger; then
      logger -t "${SCRIPT_NAME}" -p "user.${level,,}" "${msg}" 2> /dev/null || true
    fi
  fi
}

log_step() {
  local -r step="$1" desc="$2"
  printf '\n%b%b[Step %s]%b %s\n' "${COLORS[bold]}" "${COLORS[blue]}" "${step}" "${COLORS[reset]}" "${desc}" | tee -a "${LOG_FILE}"
  printf '%s\n' "$(printf -- '-%.0s' {1..60})" | tee -a "${LOG_FILE}"
}

#-------------------------------------------------------------------------------
# Core Utilities
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

#-------------------------------------------------------------------------------
# Confirmation Prompt
#-------------------------------------------------------------------------------
confirm_action() {
  local -r prompt="$1"

  # Force mode bypasses confirmation
  [[ ${FORCE_REMOVE} == true || ${FORCE_INSTALL} == true ]] && return 0

  # Dry-run mode assumes yes for preview
  if [[ ${DRY_RUN} == true ]]; then
    log_info "[DRY-RUN] Would prompt: ${prompt}"
    return 0
  fi

  # Non-interactive mode: use safe default (decline)
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
    if [[ ${output} =~ (429|503|"Too Many Requests"|"Service Unavailable"|rate.limit) ]]; then
      log_warn "Server rate-limited or unavailable (attempt ${attempt}/${max_attempts})"
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
# Atomic File Write
#-------------------------------------------------------------------------------
atomic_write() {
  local -r target="$1"
  local -r content="$2"
  local temp

  temp=$(mktemp "${target}.tmp.XXXXXX") || die "Failed to create temp file for ${target}" "${EXIT_GENERAL_ERROR}"
  trap 'rm -f "${temp}" 2>/dev/null; trap - RETURN' RETURN
  printf '%s\n' "${content}" > "${temp}"
  mv -f "${temp}" "${target}"

  # Clear trap and register for rollback
  trap - RETURN
  register_created_file "${target}"
}

#-------------------------------------------------------------------------------
# File Backup
#-------------------------------------------------------------------------------
backup_file() {
  local -r file="$1"
  if [[ -f ${file} ]]; then
    local -r backup="${file}.bak.${SRANDOM}"
    cp -a "${file}" "${backup}" 2> /dev/null || true
    register_modified_file "${file}" "${backup}"
    echo "${backup}"
  fi
}

#-------------------------------------------------------------------------------
# Lock Management
#-------------------------------------------------------------------------------
declare LOCK_FD=""

acquire_lock() {
  log_debug "Acquiring lock: ${LOCK_FILE}"

  local -r lock_dir="${LOCK_FILE%/*}"
  if [[ ! -d ${lock_dir} ]]; then
    mkdir -p "${lock_dir}" || die "Cannot create lock directory: ${lock_dir}" "${EXIT_LOCK_FAILED}"
  fi

  exec {LOCK_FD}> "${LOCK_FILE}" || die "Cannot open lock file: ${LOCK_FILE}" "${EXIT_LOCK_FAILED}"

  if ! flock -w "${LOCK_TIMEOUT}" "${LOCK_FD}"; then
    die "Could not acquire lock within ${LOCK_TIMEOUT}s. Another instance may be running." "${EXIT_LOCK_FAILED}"
  fi

  printf '%d\n' $$ >&"${LOCK_FD}"
  log_debug "Lock acquired (PID: $$)"

  # Register lock release as cleanup action
  register_cleanup "release_lock"
}

release_lock() {
  if [[ -n ${LOCK_FD} ]]; then
    exec {LOCK_FD}>&- 2> /dev/null || true
    log_debug "Lock released"
  fi
}

#-------------------------------------------------------------------------------
# Cleanup Action Registry
#-------------------------------------------------------------------------------
register_cleanup() {
  local -r action="$1"
  CLEANUP_ACTIONS+=("${action}")
  log_debug "Registered cleanup action: ${action}"
}

register_created_file() {
  local -r file="$1"
  CREATED_FILES["${file}"]=1
  log_debug "Registered created file: ${file}"
}

register_modified_file() {
  local -r file="$1" backup="$2"
  MODIFIED_FILES["${file}"]="${backup}"
  log_debug "Registered modified file: ${file} (backup: ${backup})"
}

#-------------------------------------------------------------------------------
# Child Process Cleanup
#-------------------------------------------------------------------------------
cleanup_processes() {
  local -a child_pids
  mapfile -t child_pids < <(pgrep -P $$ 2> /dev/null || true)

  if ((${#child_pids[@]} > 0)); then
    log_debug "Terminating ${#child_pids[@]} child process(es)"
    for pid in "${child_pids[@]}"; do
      kill -TERM "${pid}" 2> /dev/null || true
    done
    sleep 0.5
    for pid in "${child_pids[@]}"; do
      kill -KILL "${pid}" 2> /dev/null || true
    done
  fi
}

#-------------------------------------------------------------------------------
# Temp Directory Cleanup
#-------------------------------------------------------------------------------
cleanup_temp_dir() {
  if [[ -n ${TEMP_DIR:-} && -d ${TEMP_DIR} ]]; then
    rm -rf "${TEMP_DIR}"
    log_debug "Cleaned up temp directory"
  fi
}

#-------------------------------------------------------------------------------
# Main Cleanup Handler (EXIT trap)
#-------------------------------------------------------------------------------
cleanup() {
  local -ri original_exit_code=$?
  local -i exit_code=${original_exit_code}

  # Prevent recursive cleanup
  ((CLEANUP_IN_PROGRESS)) && return
  CLEANUP_IN_PROGRESS=1

  # Disable all signal traps during cleanup
  trap '' INT TERM HUP QUIT

  log_debug "Cleanup triggered (exit_code=${exit_code}, signal=${RECEIVED_SIGNAL:-none})"

  # Terminate child processes first
  cleanup_processes

  # If we received a signal, log it
  if [[ -n ${RECEIVED_SIGNAL:-} ]]; then
    log_info "Cleaning up after SIG${RECEIVED_SIGNAL}..."
  fi

  # Execute registered cleanup actions in reverse order (LIFO)
  local -i i
  for ((i = ${#CLEANUP_ACTIONS[@]} - 1; i >= 0; i--)); do
    local action="${CLEANUP_ACTIONS[i]}"
    log_debug "Executing cleanup action: ${action}"
    if declare -F "${action}" &> /dev/null; then
      "${action}" 2> /dev/null || true
    fi
  done

  # Rollback on failure: Remove files we created
  if ((exit_code != 0)); then
    log_info "Rolling back changes..."

    for file in "${!CREATED_FILES[@]}"; do
      if [[ -f ${file} || -d ${file} ]]; then
        log_debug "Removing created: ${file}"
        rm -rf "${file}" 2> /dev/null || true
      fi
    done

    # Restore modified files from backups
    for file in "${!MODIFIED_FILES[@]}"; do
      local backup="${MODIFIED_FILES[${file}]}"
      if [[ -f ${backup} ]]; then
        log_debug "Restoring ${file} from ${backup}"
        mv -f "${backup}" "${file}" 2> /dev/null || true
      fi
    done

    # Attempt atomic rollback if staging/rollback dirs exist
    rollback_atomic_installation
  else
    # Success: remove backup files
    for file in "${!MODIFIED_FILES[@]}"; do
      local backup="${MODIFIED_FILES[${file}]}"
      rm -f "${backup}" 2> /dev/null || true
    done
  fi

  # Final status
  if ((exit_code != 0)); then
    log_error "Script failed with exit code: ${exit_code}"
    [[ -n ${RECEIVED_SIGNAL:-} ]] && log_error "Terminated by: SIG${RECEIVED_SIGNAL}"
    log_info "Log file: ${LOG_FILE}"
  fi

  exit "${exit_code}"
}

#-------------------------------------------------------------------------------
# Installation Rollback
#-------------------------------------------------------------------------------
rollback_atomic_installation() {
  local -r staging="${INSTALL_DIR}.staging"
  local -r rollback="${INSTALL_DIR}.rollback"

  # Clean partial staging
  if [[ -d ${staging} ]]; then
    log_debug "Removing partial staging directory"
    rm -rf "${staging}" 2> /dev/null || true
  fi

  # Restore from rollback if available
  if [[ -d ${rollback} ]]; then
    if [[ ! -d ${INSTALL_DIR} ]] || [[ ! -x ${INSTALL_DIR}/yabb ]]; then
      log_info "Restoring previous installation from rollback"
      rm -rf "${INSTALL_DIR}" 2> /dev/null || true
      if mv "${rollback}" "${INSTALL_DIR}" 2> /dev/null; then
        log_success "Previous installation restored"
      else
        log_error "Rollback failed - manual intervention may be required"
      fi
    fi
  fi
}

#-------------------------------------------------------------------------------
# Signal Definitions
#-------------------------------------------------------------------------------
declare -rA SIGNAL_INFO=(
  # Graceful termination signals
  [HUP]="1:Hangup:graceful"
  [INT]="2:Interrupt:graceful"
  [QUIT]="3:Quit:graceful"
  [TERM]="15:Terminated:graceful"

  # Program error signals (fatal - attempt cleanup)
  [ILL]="4:Illegal instruction:fatal"
  [TRAP]="5:Trace/breakpoint trap:fatal"
  [ABRT]="6:Aborted:fatal"
  [BUS]="7:Bus error:fatal"
  [FPE]="8:Floating point exception:fatal"
  [SEGV]="11:Segmentation fault:fatal"
  [SYS]="31:Bad system call:fatal"
)

#-------------------------------------------------------------------------------
# Signal Handler
#-------------------------------------------------------------------------------
signal_handler() {
  local -r sig_name="${1:-UNKNOWN}"
  local sig_num=1 sig_desc="Unknown signal" sig_type="fatal"

  # Prevent re-entrant signal handling
  ((SIGNAL_RECEIVED)) && return
  SIGNAL_RECEIVED=1
  RECEIVED_SIGNAL="${sig_name}"

  if [[ -v SIGNAL_INFO[${sig_name}] ]]; then
    IFS=':' read -r sig_num sig_desc sig_type <<< "${SIGNAL_INFO[${sig_name}]}"
  fi

  local -ri exit_code=$((128 + sig_num))

  case "${sig_type}" in
    graceful)
      log_warn "Received SIG${sig_name} (${sig_desc}) - initiating graceful shutdown..."
      ;;
    fatal)
      log_error "FATAL: Received SIG${sig_name} (${sig_desc}) - attempting emergency cleanup..."
      ;;
    *)
      log_error "Received unknown signal type: SIG${sig_name}"
      ;;
  esac

  exit "${exit_code}"
}

#-------------------------------------------------------------------------------
# Error Handler
#-------------------------------------------------------------------------------
error_handler() {
  local -ri exit_code=$?
  local -r failed_cmd="${BASH_COMMAND}"
  local -r line="${BASH_LINENO[0]}"
  local -r func="${FUNCNAME[1]:-main}"
  local -r src="${BASH_SOURCE[1]:-${SCRIPT_NAME}}"

  ((exit_code == 0)) && return 0

  log_error "Command failed with exit code ${exit_code}"
  log_error "  Location: ${func}() at ${src}:${line}"
  log_error "  Command:  ${failed_cmd}"

  if [[ ${VERBOSE} == true ]]; then
    log_debug "Stack trace:"
    local -i i
    for ((i = 1; i < ${#FUNCNAME[@]}; i++)); do
      log_debug "  [${i}] ${FUNCNAME[i]}() at ${BASH_SOURCE[i]:-unknown}:${BASH_LINENO[i - 1]}"
    done

    log_debug "Variable state:"
    log_debug "  DRY_RUN=${DRY_RUN:-unset}"
    log_debug "  INSTALL_DIR=${INSTALL_DIR:-unset}"
    log_debug "  ARCH=${ARCH:-unset}"
    log_debug "  RESOLVED_VERSION=${RESOLVED_VERSION:-unset}"
  fi
}

#-------------------------------------------------------------------------------
# Setup Signal Handlers
#-------------------------------------------------------------------------------
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

  # Program error signals (fatal - attempt cleanup)
  trap 'signal_handler ILL' ILL
  trap 'signal_handler TRAP' TRAP
  trap 'signal_handler ABRT' ABRT
  trap 'signal_handler BUS' BUS
  trap 'signal_handler FPE' FPE
  trap 'signal_handler SEGV' SEGV
  trap 'signal_handler SYS' SYS 2> /dev/null || true

  log_debug "Signal handlers installed"
}

#-------------------------------------------------------------------------------
# Debug Tracing
#-------------------------------------------------------------------------------
setup_debug_tracing() {
  if [[ ${TRACE_COMMANDS} == true ]]; then
    trap '_trace_command "${BASH_COMMAND}" "${LINENO}" "${FUNCNAME[0]:-main}"' DEBUG
    log_debug "Command tracing enabled"
  fi
}

_trace_command() {
  local -r trace_cmd="$1" trace_line="$2" trace_func="$3"
  # Skip internal tracing functions
  [[ ${trace_cmd} == _trace_command* || ${trace_cmd} == log_* ]] && return
  log_debug "[${trace_func}:${trace_line}] ${trace_cmd}"
}

#-------------------------------------------------------------------------------
# Step Markers for Idempotency
#-------------------------------------------------------------------------------

# Check if a step was previously completed
step_completed() {
  local -r step_name="$1"
  [[ -f "${STEP_MARKER_DIR}/.step_${step_name}" ]]
}

# Mark a step as completed
mark_step_complete() {
  local -r step_name="$1"
  if [[ ${DRY_RUN} != true ]]; then
    mkdir -p "${STEP_MARKER_DIR}"
    printf '%s\n' "$(printf '%(%FT%T)T' "${EPOCHSECONDS}")" > "${STEP_MARKER_DIR}/.step_${step_name}"
  fi
  log_debug "Step '${step_name}' marked complete"
}

# Clear all step markers (for fresh install with --force)
clear_step_markers() {
  if [[ -d ${STEP_MARKER_DIR} ]]; then
    rm -f "${STEP_MARKER_DIR}"/.step_* 2> /dev/null || true
    log_debug "Step markers cleared"
  fi
}

#-------------------------------------------------------------------------------
# Root Check
#-------------------------------------------------------------------------------
check_root() {
  ((EUID == 0)) || die "This script must be run as root. Use: sudo ${SCRIPT_NAME}" "${EXIT_ROOT_REQUIRED}"
}

#-------------------------------------------------------------------------------
# Required Commands Validation
#-------------------------------------------------------------------------------
validate_required_commands() {
  log_info "Validating required commands..."

  local -a missing=()
  local cmd

  for cmd in "${REQUIRED_COMMANDS[@]}"; do
    # shellcheck disable=SC2310
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
# Network Connectivity Check
#-------------------------------------------------------------------------------
check_network() {
  log_info "Checking network connectivity..."

  local -ra test_endpoints=(
    "https://api.github.com"
    "https://github.com"
  )

  local endpoint
  for endpoint in "${test_endpoints[@]}"; do
    if curl -fsSL \
      --proto '=https' \
      --tlsv1.2 \
      --connect-timeout 5 \
      --max-time 10 \
      -o /dev/null \
      "${endpoint}" 2> /dev/null; then
      log_success "Network connectivity confirmed"
      return 0
    fi
  done

  die "No network connectivity. Please check your internet connection." "${EXIT_NETWORK_ERROR}"
}

#-------------------------------------------------------------------------------
# DNS Resolution Check
#-------------------------------------------------------------------------------
check_dns() {
  log_info "Checking DNS resolution..."

  if ! getent hosts github.com &> /dev/null; then
    die "DNS resolution failed for github.com. Check your DNS settings." "${EXIT_NETWORK_ERROR}"
  fi

  log_success "DNS resolution OK"
}

#-------------------------------------------------------------------------------
# Disk Space Check
#-------------------------------------------------------------------------------
check_disk_space() {
  log_info "Checking available disk space..."

  local -i available_mb
  available_mb=$(df -BM /opt 2> /dev/null | awk 'NR==2 {print int($4)}') || available_mb=0

  if ((available_mb < REQUIRED_DISK_SPACE_MB)); then
    die "Insufficient disk space: ${available_mb}MB available, ${REQUIRED_DISK_SPACE_MB}MB required" "${EXIT_DISK_SPACE}"
  fi

  log_success "Disk space OK: ${available_mb}MB available"
}

#-------------------------------------------------------------------------------
# File Descriptor Limits Check
#-------------------------------------------------------------------------------
check_file_descriptors() {
  log_info "Checking file descriptor limits..."
  local -ri required_fds=256
  local -i max_fds
  max_fds=$(ulimit -n 2> /dev/null) || max_fds=0

  if ((max_fds > 0 && max_fds < required_fds)); then
    log_warn "Low file descriptor limit: ${max_fds} (recommended: ${required_fds}+)"
  else
    log_debug "File descriptor limit: ${max_fds}"
  fi
}

#-------------------------------------------------------------------------------
# Path Validation
#-------------------------------------------------------------------------------
validate_path_safe() {
  local -r path="$1"

  # Must be absolute path
  if [[ ${path} != /* ]]; then
    die "Path must be absolute: ${path}" "${EXIT_INVALID_ARGS}"
  fi

  # Check for path traversal attempts
  if [[ ${path} == *..* ]]; then
    die "Path contains traversal sequence: ${path}" "${EXIT_INVALID_ARGS}"
  fi

  # Resolve and verify - realpath -m doesn't require path to exist
  local resolved
  if ! resolved=$(realpath -m "${path}" 2> /dev/null); then
    die "Invalid path: ${path}" "${EXIT_INVALID_ARGS}"
  fi

  # Verify resolved path is sensible (not empty, absolute)
  if [[ -z ${resolved} || ${resolved} != /* ]]; then
    die "Path resolution failed: ${path}" "${EXIT_INVALID_ARGS}"
  fi
}

#-------------------------------------------------------------------------------
# URL Validation
#-------------------------------------------------------------------------------
validate_url() {
  local -r url="$1"
  local -r pattern='^https://[a-zA-Z0-9][-a-zA-Z0-9]*(\.[a-zA-Z0-9][-a-zA-Z0-9]*)+(/[-a-zA-Z0-9_.~%/]*)?$'

  # Must be HTTPS
  if [[ ${url} != https://* ]]; then
    die "Security: Only HTTPS URLs allowed: ${url}" "${EXIT_NETWORK_ERROR}"
  fi

  # Validate URL format
  if [[ ! ${url} =~ ${pattern} ]]; then
    die "Invalid URL format: ${url}" "${EXIT_NETWORK_ERROR}"
  fi

  # Extract and validate domain
  local domain="${url#https://}"
  domain="${domain%%/*}"

  local allowed=false
  local d
  for d in "${ALLOWED_DOWNLOAD_DOMAINS[@]}"; do
    if [[ ${domain} == "${d}" || ${domain} == *".${d}" ]]; then
      allowed=true
      break
    fi
  done

  if [[ ${allowed} != true ]]; then
    die "Security: Domain not in allowlist: ${domain}" "${EXIT_NETWORK_ERROR}"
  fi
}

#-------------------------------------------------------------------------------
# Download
#-------------------------------------------------------------------------------
secure_download() {
  local -r url="$1"
  local -r output="$2"
  local -ri max_size="${3:-${MAX_DOWNLOAD_SIZE}}"

  validate_url "${url}"

  log_debug "Downloading: ${url}"

  curl -fsSL \
    --proto '=https' \
    --tlsv1.2 \
    --connect-timeout 10 \
    --max-time "${DOWNLOAD_TIMEOUT}" \
    --retry 3 \
    --retry-connrefused \
    --max-filesize "${max_size}" \
    -o "${output}" \
    "${url}" || die "Download failed: ${url}" "${EXIT_NETWORK_ERROR}"

  if [[ ! -s ${output} ]]; then
    die "Downloaded file is empty: ${output}" "${EXIT_NETWORK_ERROR}"
  fi

  log_debug "Downloaded successfully: ${output}"
}

#-------------------------------------------------------------------------------
# Fetch
#-------------------------------------------------------------------------------
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
# Checksum Verification
#-------------------------------------------------------------------------------
verify_checksum() {
  local -r file="$1"
  local -r expected="$2"

  local actual
  actual=$(sha256sum "${file}" | cut -d' ' -f1)

  if [[ ${actual} != "${expected}" ]]; then
    log_error "SECURITY: Checksum verification failed!"
    log_error "  Expected: ${expected}"
    log_error "  Actual:   ${actual}"
    die "File may be corrupted or tampered with" "${EXIT_CHECKSUM_FAILED}"
  fi

  log_success "Checksum verified"
}

#-------------------------------------------------------------------------------
# Get Installed Version
#-------------------------------------------------------------------------------
get_installed_version() {
  local -r binary="${INSTALL_DIR}/yabb"

  # Not installed
  if [[ ! -f ${binary} ]]; then
    echo ""
    return 0
  fi

  # Not executable
  if [[ ! -x ${binary} ]]; then
    echo "unknown"
    return 0
  fi

  # Try to get version
  local output
  if output=$("${binary}" --version 2> /dev/null); then
    local version
    version=$(echo "${output}" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    if [[ -n ${version} ]]; then
      echo "${version}"
      return 0
    fi
  fi

  echo "unknown"
}

#-------------------------------------------------------------------------------
# Compare Versions
#-------------------------------------------------------------------------------
compare_versions() {
  local v1="${1#v}"
  local v2="${2#v}"

  if [[ "${v1}" == "${v2}" ]]; then
    echo "same"
    return 0
  fi

  local sorted_first
  sorted_first=$(printf '%s\n%s' "${v1}" "${v2}" | sort -V | head -1)

  if [[ "${sorted_first}" == "${v1}" ]]; then
    echo "older" # v1 < v2
  else
    echo "newer" # v1 > v2
  fi
}

#-------------------------------------------------------------------------------
# Check If Update Should Proceed
#-------------------------------------------------------------------------------
check_should_update() {
  local -r current="$1"
  local -r target="${2#v}"

  # Force flag bypasses all checks
  if [[ ${FORCE_INSTALL} == true ]]; then
    log_info "Force flag set - proceeding with installation"
    return 1 # Don't skip
  fi

  # No current version = fresh install
  if [[ -z ${current} ]]; then
    log_info "No existing installation - proceeding with fresh install"
    return 1 # Don't skip
  fi

  # Unknown version = possibly corrupted, try to fix
  if [[ ${current} == "unknown" ]]; then
    log_warn "Cannot determine installed version - proceeding with installation"
    return 1 # Don't skip
  fi

  # Compare versions
  local cmp
  cmp=$(compare_versions "${current}" "${target}")

  case "${cmp}" in
    same)
      log_success "Already at version ${target} - nothing to do"
      log_info "Use --force to reinstall"
      return 0 # Skip
      ;;
    newer)
      log_info "Installed version ${current} is newer than ${target}"
      log_info "Use --force to downgrade"
      return 0 # Skip
      ;;
    older)
      log_info "Upgrade available: ${current} -> ${target}"
      return 1 # Don't skip
      ;;
    *)
      log_warn "Unexpected version comparison result: ${cmp} - proceeding with installation"
      return 1 # Don't skip, be safe and try to install
      ;;
  esac
}

#-------------------------------------------------------------------------------
# Resolve Target Version from GitHub
#-------------------------------------------------------------------------------
resolve_target_version() {
  log_info "Resolving version..."

  if [[ ${YABB_VERSION} == "latest" ]]; then
    log_debug "Fetching latest release from GitHub API..."

    local response
    # shellcheck disable=SC2310
    response=$(retry_with_backoff "${MAX_RETRIES}" "${RETRY_DELAY_BASE}" \
      secure_fetch "${GITHUB_API}/latest") || die "Failed to fetch latest version" "${EXIT_NETWORK_ERROR}"

    RESOLVED_VERSION=$(printf '%s' "${response}" | grep -oE '"tag_name"[[:space:]]*:[[:space:]]*"[^"]+"' | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | head -1)

    if [[ -z ${RESOLVED_VERSION} ]]; then
      die "Failed to parse version from API response" "${EXIT_NETWORK_ERROR}"
    fi
  else
    RESOLVED_VERSION="${YABB_VERSION}"

    if [[ ! ${RESOLVED_VERSION} =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?$ ]]; then
      die "Invalid version format: ${RESOLVED_VERSION} (expected: vX.Y.Z)" "${EXIT_INVALID_ARGS}"
    fi
  fi

  log_success "Version: ${RESOLVED_VERSION}"
}

#-------------------------------------------------------------------------------
# Staging Directory Helpers
#-------------------------------------------------------------------------------
staging_dir() { echo "${INSTALL_DIR}.staging"; }
rollback_dir() { echo "${INSTALL_DIR}.rollback"; }

#-------------------------------------------------------------------------------
# Create Secure Temp Directory
#-------------------------------------------------------------------------------
create_secure_temp_dir() {
  TEMP_DIR=$(mktemp -d -t "yabb-install.XXXXXXXXXX") \
    || die "Failed to create secure temp directory" "${EXIT_GENERAL_ERROR}"

  chmod 700 "${TEMP_DIR}"

  # Verify ownership
  local owner_uid
  owner_uid=$(stat -c %u "${TEMP_DIR}") || {
    rm -rf "${TEMP_DIR}"
    die "Failed to stat temp directory" "${EXIT_GENERAL_ERROR}"
  }
  if [[ ${owner_uid} != "${EUID}" ]]; then
    rm -rf "${TEMP_DIR}"
    die "Temp directory ownership verification failed" "${EXIT_GENERAL_ERROR}"
  fi

  register_cleanup cleanup_temp_dir
  log_debug "Created secure temp directory: ${TEMP_DIR}"
}

#-------------------------------------------------------------------------------
# Clean Stale Artifacts from Interrupted Installations
#-------------------------------------------------------------------------------
clean_stale_artifacts() {
  local staging rollback
  staging="$(staging_dir)"
  rollback="$(rollback_dir)"
  readonly staging rollback

  # Clean stale staging
  if [[ -d ${staging} ]]; then
    log_warn "Removing stale staging directory from previous interrupted install"
    rm -rf "${staging}" || die "Cannot clean staging directory" "${EXIT_INSTALL_FAILED}"
  fi

  # Handle stale rollback
  if [[ -d ${rollback} ]]; then
    if [[ ! -d ${INSTALL_DIR} ]]; then
      # Previous swap failed - restore
      log_warn "Detected interrupted installation - restoring from rollback"
      mv "${rollback}" "${INSTALL_DIR}" \
        || die "Cannot restore from rollback" "${EXIT_INSTALL_FAILED}"
      log_success "Restored previous installation from rollback"
    else
      # Previous cleanup failed - remove rollback
      log_warn "Removing stale rollback directory"
      rm -rf "${rollback}" || log_warn "Could not remove stale rollback"
    fi
  fi
}

#-------------------------------------------------------------------------------
# Verify Staging Contents
#-------------------------------------------------------------------------------
verify_staging_contents() {
  local staging
  staging="$(staging_dir)"
  readonly staging

  # Binary must exist and be executable
  if [[ ! -x ${staging}/yabb ]]; then
    die "Staging verification failed: yabb binary not executable" "${EXIT_INSTALL_FAILED}"
  fi

  if ! file "${staging}/yabb" 2> /dev/null | grep -q 'ELF'; then
    die "Staging verification failed: yabb is not a valid ELF binary" "${EXIT_INSTALL_FAILED}"
  fi

  log_debug "Staging verification passed"
}

#-------------------------------------------------------------------------------
# Prepare Staging Area
#-------------------------------------------------------------------------------
prepare_staging_area() {
  local -r extract_dir="$1"
  local staging
  staging="$(staging_dir)"
  readonly staging

  log_info "Preparing staging area..."

  if [[ ${DRY_RUN} == true ]]; then
    log_info "[DRY-RUN] Would create staging at: ${staging}"
    return 0
  fi

  rm -rf "${staging}"
  mkdir -p "${staging}" || die "Cannot create staging directory" "${EXIT_INSTALL_FAILED}"

  cp -a "${extract_dir}/." "${staging}/" || {
    rm -rf "${staging}"
    die "Failed to copy files to staging" "${EXIT_INSTALL_FAILED}"
  }

  chmod 755 "${staging}/yabb"
  [[ -f ${staging}/scripts/setup-yabb.sh ]] && chmod 755 "${staging}/scripts/setup-yabb.sh"

  verify_staging_contents

  log_success "Staging area prepared"
}

#-------------------------------------------------------------------------------
# Atomic Swap Installation
#-------------------------------------------------------------------------------
atomic_swap_installation() {
  local staging rollback
  staging="$(staging_dir)"
  rollback="$(rollback_dir)"
  readonly staging rollback

  log_info "Performing atomic installation swap..."

  if [[ ${DRY_RUN} == true ]]; then
    log_info "[DRY-RUN] Would atomically swap ${staging} -> ${INSTALL_DIR}"
    return 0
  fi

  # Ensure no stale rollback
  rm -rf "${rollback}" 2> /dev/null || true

  # CRITICAL SECTION START

  # Step 1: Move existing to rollback (if exists)
  if [[ -d ${INSTALL_DIR} ]]; then
    log_debug "Moving existing installation to rollback"
    if ! mv "${INSTALL_DIR}" "${rollback}"; then
      rm -rf "${staging}"
      die "Failed to prepare rollback - installation aborted (no changes made)" "${EXIT_INSTALL_FAILED}"
    fi
  fi

  # Step 2: Move staging to final location (ATOMIC)
  if ! mv "${staging}" "${INSTALL_DIR}"; then
    log_error "CRITICAL: Atomic swap failed - initiating rollback"

    if [[ -d ${rollback} ]]; then
      if mv "${rollback}" "${INSTALL_DIR}"; then
        log_warn "Rollback successful - previous installation restored"
        die "Installation failed but previous version restored" "${EXIT_INSTALL_FAILED}"
      else
        die "CRITICAL: Rollback failed! Manual intervention required. Backup at: ${rollback}" "${EXIT_INSTALL_FAILED}"
      fi
    else
      die "Installation failed (fresh install, no rollback available)" "${EXIT_INSTALL_FAILED}"
    fi
  fi

  # CRITICAL SECTION END
  log_success "Atomic swap completed successfully"
}

#-------------------------------------------------------------------------------
# Cleanup Rollback Directory After Success
#-------------------------------------------------------------------------------
cleanup_rollback() {
  local rollback
  rollback="$(rollback_dir)"
  readonly rollback

  if [[ -d ${rollback} ]]; then
    log_debug "Removing rollback directory"
    rm -rf "${rollback}" || log_warn "Could not remove rollback directory"
  fi
}

#-------------------------------------------------------------------------------
# Install System Config (NEVER overwrites existing)
#-------------------------------------------------------------------------------
install_system_config() {
  if [[ ${INSTALL_CONFIG} != true ]]; then
    log_debug "Config installation skipped (--no-config)"
    return 0
  fi

  local -r src="${INSTALL_DIR}/yabb.conf"
  local -r dest="${SYSTEM_CONFIG_PATH}"

  if [[ ! -f ${src} ]]; then
    log_warn "Source config not found: ${src}"
    return 0
  fi

  if [[ -f ${dest} ]]; then
    log_info "Existing config preserved: ${dest}"
    return 0
  fi

  if [[ ${DRY_RUN} == true ]]; then
    log_info "[DRY-RUN] Would install config: ${dest}"
    return 0
  fi

  cp "${src}" "${dest}"
  chmod 644 "${dest}"
  register_created_file "${dest}"
  log_success "Installed config: ${dest}"
}

#-------------------------------------------------------------------------------
# Install Shell Completions (ALWAYS overwrites)
#-------------------------------------------------------------------------------
install_shell_completions() {
  if [[ ${INSTALL_COMPLETIONS} != true ]]; then
    log_debug "Completions installation skipped (--no-completions)"
    return 0
  fi

  local -r src_dir="${INSTALL_DIR}/shell_completions"
  local -i installed=0

  # Bash
  # shellcheck disable=SC2310
  if has_command bash && [[ -f ${src_dir}/yabb.bash ]]; then
    if install_file_overwrite "${src_dir}/yabb.bash" "${BASH_COMPLETION_DIR}/yabb"; then
      ((installed++))
    fi
  fi

  # Zsh
  # shellcheck disable=SC2310
  if has_command zsh && [[ -f ${src_dir}/yabb.zsh ]]; then
    if install_file_overwrite "${src_dir}/yabb.zsh" "${ZSH_COMPLETION_DIR}/_yabb"; then
      ((installed++))
    fi
  fi

  # Fish
  # shellcheck disable=SC2310
  if has_command fish && [[ -f ${src_dir}/yabb.fish ]]; then
    if install_file_overwrite "${src_dir}/yabb.fish" "${FISH_COMPLETION_DIR}/yabb.fish"; then
      ((installed++))
    fi
  fi

  log_success "Installed ${installed} shell completion(s)"
}

#-------------------------------------------------------------------------------
# Install Systemd Files (ALWAYS overwrites)
#-------------------------------------------------------------------------------
install_systemd_files() {
  if [[ ${INSTALL_SYSTEMD} != true ]]; then
    log_debug "Systemd installation skipped (--no-systemd)"
    return 0
  fi

  local -r src_dir="${INSTALL_DIR}/scripts"
  local -i installed=0

  for sfile in "${SYSTEMD_FILES[@]}"; do
    if [[ -f ${src_dir}/${sfile} ]]; then
      # shellcheck disable=SC2310  # Intentional: optional install, failures should not exit
      if install_file_overwrite "${src_dir}/${sfile}" "${SYSTEMD_UNIT_DIR}/${sfile}"; then
        ((installed++))
      fi
    fi
  done

  # Daemon reload if any units installed
  if ((installed > 0)) && [[ ${DRY_RUN} != true ]]; then
    # shellcheck disable=SC2310
    if has_command systemctl; then
      systemctl daemon-reload 2> /dev/null || log_warn "Failed to reload systemd"
    fi
  fi

  log_success "Installed ${installed} systemd unit(s)"
}

#-------------------------------------------------------------------------------
# Helper: Install File with Overwrite
#-------------------------------------------------------------------------------
install_file_overwrite() {
  local -r src="$1"
  local -r dest="$2"

  if [[ ${DRY_RUN} == true ]]; then
    log_info "[DRY-RUN] Would install: ${dest}"
    return 0
  fi

  local -r dest_dir="${dest%/*}"
  [[ -d ${dest_dir} ]] || mkdir -p "${dest_dir}"

  # Backup existing file for rollback
  [[ -f ${dest} ]] && backup_file "${dest}"

  cp -f "${src}" "${dest}"
  chmod 644 "${dest}"
  log_debug "Installed: ${dest}"
  return 0
}

#-------------------------------------------------------------------------------
# Verification
#-------------------------------------------------------------------------------
verify_installation() {
  printf '\n%b===============================================================%b\n' "${COLORS[bold]}" "${COLORS[reset]}" | tee -a "${LOG_FILE}"
  printf '%b                    VERIFICATION%b\n' "${COLORS[bold]}" "${COLORS[reset]}" | tee -a "${LOG_FILE}"
  printf '%b===============================================================%b\n' "${COLORS[bold]}" "${COLORS[reset]}" | tee -a "${LOG_FILE}"

  if [[ ${DRY_RUN} == true ]]; then
    log_info "[DRY-RUN] Verification skipped"
    return 0
  fi

  local -i passed=1

  # Binary exists and executable
  if [[ -x ${INSTALL_DIR}/yabb ]]; then
    local ver
    ver=$("${INSTALL_DIR}/yabb" --version 2> /dev/null) || ver="unknown"
    log_success "Binary: ${INSTALL_DIR}/yabb (${ver})"
  else
    log_error "Binary not found or not executable"
    passed=0
  fi

  # Config file
  if [[ -f ${SYSTEM_CONFIG_PATH} ]]; then
    log_success "Config: ${SYSTEM_CONFIG_PATH}"
  else
    log_info "Config: Not installed (sample at ${INSTALL_DIR}/yabb.conf)"
  fi

  # Completions
  [[ -f ${BASH_COMPLETION_DIR}/yabb ]] && log_success "Bash completion: installed"
  [[ -f ${ZSH_COMPLETION_DIR}/_yabb ]] && log_success "Zsh completion: installed"
  [[ -f ${FISH_COMPLETION_DIR}/yabb.fish ]] && log_success "Fish completion: installed"

  # Systemd
  for sfile in "${SYSTEMD_FILES[@]}"; do
    if [[ -f ${SYSTEMD_UNIT_DIR}/${sfile} ]]; then
      log_success "Systemd: ${sfile}"
    fi
  done

  # No rollback artifacts
  local staging rollback
  staging="$(staging_dir)"
  rollback="$(rollback_dir)"
  if [[ -d ${staging} ]] || [[ -d ${rollback} ]]; then
    log_warn "Stale installation artifacts exist"
    passed=0
  fi

  return $((1 - passed))
}

#-------------------------------------------------------------------------------
# Health Check
#-------------------------------------------------------------------------------
health_check() {
  log_info "Running post-installation health check..."

  local -i score=0
  local -ri max_score=4

  # Check binary responds
  if "${INSTALL_DIR}/yabb" --help &> /dev/null; then
    log_debug "Health: Binary responds to --help"
    ((score++))
  fi

  # Check version output
  if "${INSTALL_DIR}/yabb" --version &> /dev/null; then
    log_debug "Health: Version command works"
    ((score++))
  fi

  # Check validate command exists
  if "${INSTALL_DIR}/yabb" validate --help &> /dev/null 2>&1; then
    log_debug "Health: Validate command available"
    ((score++))
  fi

  # Check no stale artifacts
  local staging rollback
  staging="$(staging_dir)"
  rollback="$(rollback_dir)"
  if [[ ! -d ${staging} ]] && [[ ! -d ${rollback} ]]; then
    log_debug "Health: No stale artifacts"
    ((score++))
  fi

  log_info "Health check score: ${score}/${max_score}"

  if ((score < 2)); then
    log_warn "Installation may be incomplete"
    return 1
  fi

  log_success "Health check passed"
  return 0
}

#-------------------------------------------------------------------------------
# Download and Verify
#-------------------------------------------------------------------------------
download_and_verify() {
  log_step "5/7" "Downloading and verifying release"

  local -r version_num="${RESOLVED_VERSION#v}"
  local -r archive_name="yabb-${version_num}-linux-${ARCH}.tar.zst"
  local -r archive_url="${GITHUB_DOWNLOAD}/${RESOLVED_VERSION}/${archive_name}"
  local -r checksum_url="${GITHUB_DOWNLOAD}/${RESOLVED_VERSION}/SHA256SUMS"

  local -r archive_path="${TEMP_DIR}/${archive_name}"
  local -r checksum_path="${TEMP_DIR}/SHA256SUMS"

  # Download checksum file
  log_info "Downloading checksums..."
  if [[ ${DRY_RUN} == true ]]; then
    log_info "[DRY-RUN] Would download: ${checksum_url}"
  else
    secure_download "${checksum_url}" "${checksum_path}"
  fi

  # Download archive
  log_info "Downloading ${archive_name}..."
  if [[ ${DRY_RUN} == true ]]; then
    log_info "[DRY-RUN] Would download: ${archive_url}"
  else
    secure_download "${archive_url}" "${archive_path}"
  fi

  # Verify checksum
  if [[ ${DRY_RUN} == true ]]; then
    log_info "[DRY-RUN] Would verify SHA256 checksum"
  else
    log_info "Verifying SHA256 checksum..."
    local expected_checksum
    expected_checksum=$(grep "${archive_name}" "${checksum_path}" | cut -d' ' -f1)

    if [[ -z ${expected_checksum} ]]; then
      die "Checksum not found for ${archive_name}" "${EXIT_CHECKSUM_FAILED}"
    fi

    verify_checksum "${archive_path}" "${expected_checksum}"
  fi

  # Extract
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
# Print Summary
#-------------------------------------------------------------------------------
print_summary() {
  printf '\n%b===============================================================%b\n' "${COLORS[bold]}" "${COLORS[reset]}" | tee -a "${LOG_FILE}"
  printf '%b                    INSTALLATION COMPLETE%b\n' "${COLORS[bold]}" "${COLORS[reset]}" | tee -a "${LOG_FILE}"
  printf '%b===============================================================%b\n' "${COLORS[bold]}" "${COLORS[reset]}" | tee -a "${LOG_FILE}"

  [[ ${DRY_RUN} == true ]] && log_info "Mode: DRY-RUN (no changes made)"

  log_info ""
  log_info "Version:     ${RESOLVED_VERSION}"
  log_info "Binary:      ${INSTALL_DIR}/yabb"
  log_info "Config:      ${SYSTEM_CONFIG_PATH}"
  log_info "Log file:    ${LOG_FILE}"
  log_info ""
  log_info "Next steps:"
  log_info "  1. Edit config:    sudo nano ${SYSTEM_CONFIG_PATH}"
  # shellcheck disable=SC2016
  log_info '  2. Add to PATH:    export PATH="${INSTALL_DIR}:$PATH"'
  log_info "  3. Enable timer:   sudo systemctl enable --now yabb.timer"
  log_info "  4. Test:           ${INSTALL_DIR}/yabb --help"
  log_info ""
  log_info "To update:   sudo ${INSTALL_DIR}/scripts/setup-yabb.sh"
  log_info "To remove:   sudo ${INSTALL_DIR}/scripts/setup-yabb.sh --remove"
  log_info ""
}

#-------------------------------------------------------------------------------
# Show Help
#-------------------------------------------------------------------------------
show_help() {
  cat << EOF
${SCRIPT_NAME} v${SCRIPT_VERSION} - YABB Enterprise Installer

USAGE:
  ${SCRIPT_NAME} [OPTIONS]

DESCRIPTION:
  Download and install YABB (Yet Another BTRFS Backup) from GitHub releases.
  Non-interactive, idempotent, atomic installation with rollback support.
  Automatically detects architecture and verifies checksums.

  Features:
  - Atomic installation with automatic rollback on failure
  - flock-based locking to prevent concurrent runs
  - SHA256 checksum verification
  - Comprehensive security hardening
  - Syslog support for enterprise environments

INSTALLATION OPTIONS:
  -d, --dir PATH       Install directory (default: ${DEFAULT_INSTALL_DIR})
  -v, --version VER    Install specific version (default: latest)
                       Example: --version v0.4.3
  -f, --force          Force installation even if same version
  --no-config          Skip config file installation
  --no-completions     Skip shell completion installation
  --no-systemd         Skip systemd unit installation

REMOVAL OPTIONS:
  --remove             Remove YABB installation
  --purge              Also remove config files
  --force, -f          Skip confirmation prompts

GENERAL OPTIONS:
  --dry-run            Show what would be done without making changes
  --verbose            Enable verbose output
  --trace-commands     Enable command-level tracing (DEBUG trap)
  --syslog             Also log to syslog (for enterprise environments)
  -h, --help           Show this help message

ENVIRONMENT:
  TRACE=1              Enable bash debug tracing (set -x)

INSTALLATION LOCATIONS:
  Binary & scripts:    ${DEFAULT_INSTALL_DIR}/
  System config:       /etc/yabb.toml
  Bash completion:     /etc/bash_completion.d/yabb
  Zsh completion:      /usr/local/share/zsh/site-functions/_yabb
  Fish completion:     /usr/share/fish/vendor_completions.d/yabb.fish
  Systemd units:       /etc/systemd/system/yabb.{service,timer}
  Log file:            /var/log/yabb-install.log
  Lock file:           /var/lock/yabb-install.lock

EXIT CODES:
  0   Success
  1   General error
  2   Lock acquisition failed
  3   Invalid arguments
  4   Root required
  5   Unsupported architecture
  6   Network error
  7   Checksum verification failed
  8   Installation failed
  9   Insufficient disk space
  10  User cancelled

EXAMPLES:
  # Install latest version
  sudo ${SCRIPT_NAME}

  # Install specific version
  sudo ${SCRIPT_NAME} --version v0.4.3

  # Force reinstall same version
  sudo ${SCRIPT_NAME} --force

  # Preview installation (dry-run)
  sudo ${SCRIPT_NAME} --dry-run --verbose

  # Remove installation
  sudo ${SCRIPT_NAME} --remove

  # Remove including config files
  sudo ${SCRIPT_NAME} --remove --purge --force

  # Pipe installation (please manually verify content first!)
  curl -fsSL --proto '=https' --tlsv1.2 https://raw.githubusercontent.com/aryonoco/yabb/main/scripts/setup-yabb.sh | sudo bash

EOF
}

#-------------------------------------------------------------------------------
# Run Removal
#-------------------------------------------------------------------------------
run_removal() {
  log_info "YABB Removal Mode"
  [[ ${DRY_RUN} == true ]] && log_warn "DRY-RUN MODE: No changes will be made"

  # Confirm unless --force
  # shellcheck disable=SC2310
  if ! confirm_action "Remove YABB from ${INSTALL_DIR} and system locations?"; then
    log_info "Removal cancelled"
    exit "${EXIT_SUCCESS}"
  fi

  # Step 1: Stop and disable systemd units
  log_step "1/4" "Stopping and disabling systemd units"
  # shellcheck disable=SC2310
  if has_command systemctl; then
    for sfile in "${SYSTEMD_FILES[@]}"; do
      local unit="${sfile%.service}"
      unit="${unit%.timer}"
      if systemctl is-active --quiet "${sfile}" 2> /dev/null; then
        execute systemctl stop "${sfile}" || true
        log_info "Stopped: ${sfile}"
      fi
      if systemctl is-enabled --quiet "${sfile}" 2> /dev/null; then
        execute systemctl disable "${sfile}" || true
        log_info "Disabled: ${sfile}"
      fi
    done
  fi

  # Step 2: Remove installation directory
  log_step "2/4" "Removing installation directory"
  if [[ -d ${INSTALL_DIR} ]]; then
    execute rm -rf "${INSTALL_DIR}"
    log_success "Removed: ${INSTALL_DIR}"
  else
    log_warn "Installation directory not found: ${INSTALL_DIR}"
  fi

  # Step 3: Remove shell completions
  log_step "3/4" "Removing shell completions"
  local -a completion_files=(
    "${BASH_COMPLETION_DIR}/yabb"
    "${ZSH_COMPLETION_DIR}/_yabb"
    "${FISH_COMPLETION_DIR}/yabb.fish"
  )

  local -i removed=0
  for file in "${completion_files[@]}"; do
    if [[ -f ${file} ]]; then
      execute rm -f "${file}"
      log_info "Removed: ${file}"
      ((removed++)) || true
    fi
  done

  if ((removed > 0)); then
    log_success "Removed ${removed} shell completion file(s)"
  fi

  # Step 4: Remove systemd files
  for sfile in "${SYSTEMD_FILES[@]}"; do
    if [[ -f ${SYSTEMD_UNIT_DIR}/${sfile} ]]; then
      execute rm -f "${SYSTEMD_UNIT_DIR}/${sfile}"
      log_info "Removed: ${SYSTEMD_UNIT_DIR}/${sfile}"
    fi
  done

  # shellcheck disable=SC2310
  if has_command systemctl && [[ ${DRY_RUN} != true ]]; then
    systemctl daemon-reload 2> /dev/null || true
  fi

  # Step 5: Remove config files if --purge
  if [[ ${PURGE_CONFIG} == true ]]; then
    log_step "4/4" "Removing configuration files"

    if [[ -f ${SYSTEM_CONFIG_PATH} ]]; then
      execute rm -f "${SYSTEM_CONFIG_PATH}"
      log_success "Removed: ${SYSTEM_CONFIG_PATH}"
    fi

    if [[ -d ${SYSTEM_CONFIG_DIR} ]]; then
      execute rm -rf "${SYSTEM_CONFIG_DIR}"
      log_success "Removed: ${SYSTEM_CONFIG_DIR}"
    fi

    # Remove step markers
    if [[ -d ${STEP_MARKER_DIR} ]]; then
      execute rm -rf "${STEP_MARKER_DIR}"
      log_info "Removed: ${STEP_MARKER_DIR}"
    fi
  else
    log_step "4/4" "Preserving configuration files"
    log_info "Config preserved: ${SYSTEM_CONFIG_PATH}"
    log_info "Use --purge to remove config files"
  fi

  printf '\n%b===============================================================%b\n' "${COLORS[bold]}" "${COLORS[reset]}"
  printf '%b                    REMOVAL COMPLETE%b\n' "${COLORS[bold]}" "${COLORS[reset]}"
  printf '%b===============================================================%b\n' "${COLORS[bold]}" "${COLORS[reset]}"
}

#-------------------------------------------------------------------------------
# Main Orchestrator
#-------------------------------------------------------------------------------
run_installation() {
  log_info "YABB Installer v${SCRIPT_VERSION}"
  [[ ${DRY_RUN} == true ]] && log_warn "DRY-RUN MODE: No changes will be made"
  [[ ${TRACE_COMMANDS} == true ]] && log_warn "TRACE MODE: Command tracing enabled"

  # Phase 1: Preparation
  log_step "1/7" "Preparing installation environment"
  create_secure_temp_dir
  clean_stale_artifacts
  [[ ${FORCE_INSTALL} == true ]] && clear_step_markers

  # Phase 2: System Checks
  log_step "2/7" "Validating system requirements"
  check_disk_space
  check_file_descriptors

  # Phase 3: Network Checks
  log_step "3/7" "Checking network connectivity"
  check_dns
  check_network

  # Phase 4: Detection & Resolution
  log_step "4/7" "Detecting system and resolving version"
  detect_architecture
  resolve_target_version

  # Phase 5: Version Check
  local current_version
  current_version=$(get_installed_version)
  # shellcheck disable=SC2310
  if check_should_update "${current_version}" "${RESOLVED_VERSION}"; then
    log_success "Installation complete (already up-to-date)"
    exit "${EXIT_SUCCESS}"
  fi

  # Phase 6: Download, Verify, Install
  download_and_verify
  local -r version_num="${RESOLVED_VERSION#v}"
  local -r extract_dir="${TEMP_DIR}/yabb-${version_num}-linux-${ARCH}"
  prepare_staging_area "${extract_dir}"
  atomic_swap_installation

  # Phase 7: System Files & Cleanup
  log_step "6/7" "Installing system files"
  install_system_config
  install_shell_completions
  install_systemd_files
  cleanup_rollback

  # Verification
  log_step "7/7" "Verifying installation"
  # shellcheck disable=SC2310
  verify_installation || true
  # shellcheck disable=SC2310
  health_check || true

  print_summary
  log_success "Installation completed successfully!"
}

#-------------------------------------------------------------------------------
# Argument Parsing
#-------------------------------------------------------------------------------
parse_arguments() {
  while (($# > 0)); do
    case "$1" in
      -d | --dir)
        [[ -n ${2:-} ]] || die "--dir requires PATH" "${EXIT_INVALID_ARGS}"
        INSTALL_DIR="$2"
        validate_path_safe "${INSTALL_DIR}"
        shift 2
        ;;
      --dir=*)
        INSTALL_DIR="${1#*=}"
        validate_path_safe "${INSTALL_DIR}"
        shift
        ;;
      -v | --version)
        [[ -n ${2:-} ]] || die "--version requires VERSION" "${EXIT_INVALID_ARGS}"
        YABB_VERSION="$2"
        shift 2
        ;;
      --version=*)
        YABB_VERSION="${1#*=}"
        shift
        ;;
      -f | --force)
        FORCE_INSTALL=true
        FORCE_REMOVE=true
        shift
        ;;
      --no-config)
        INSTALL_CONFIG=false
        shift
        ;;
      --no-completions)
        INSTALL_COMPLETIONS=false
        shift
        ;;
      --no-systemd)
        INSTALL_SYSTEMD=false
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
      --dry-run)
        DRY_RUN=true
        shift
        ;;
      --verbose)
        VERBOSE=true
        shift
        ;;
      --trace-commands)
        TRACE_COMMANDS=true
        shift
        ;;
      --syslog)
        SYSLOG=true
        shift
        ;;
      -h | --help)
        show_help
        exit 0
        ;;
      -*)
        die "Unknown option: $1 (use --help)" "${EXIT_INVALID_ARGS}"
        ;;
      *)
        die "Unexpected argument: $1 (use --help)" "${EXIT_INVALID_ARGS}"
        ;;
    esac
  done

  # Validate argument combinations
  if [[ ${REMOVE_MODE} == true && ${YABB_VERSION} != "latest" ]]; then
    die "--remove and --version are mutually exclusive" "${EXIT_INVALID_ARGS}"
  fi

  if [[ ${PURGE_CONFIG} == true && ${REMOVE_MODE} != true ]]; then
    die "--purge requires --remove" "${EXIT_INVALID_ARGS}"
  fi
}

#-------------------------------------------------------------------------------
# Main Entry Point
#-------------------------------------------------------------------------------
main() {
  # Initialize log file
  mkdir -p "${LOG_FILE%/*}"
  : > "${LOG_FILE}"
  chmod 644 "${LOG_FILE}"

  log_info "==============================================================="
  log_info "  YABB Installer v${SCRIPT_VERSION}"
  log_info "  Bash ${BASH_VERSION} | Started: $(printf '%(%F %T)T' "${EPOCHSECONDS}")"
  log_info "==============================================================="

  setup_signal_handlers
  setup_debug_tracing

  # Freeze configuration to prevent modification
  readonly INSTALL_DIR YABB_VERSION FORCE_INSTALL INSTALL_CONFIG INSTALL_COMPLETIONS INSTALL_SYSTEMD
  readonly DRY_RUN VERBOSE SYSLOG TRACE_COMMANDS
  readonly REMOVE_MODE PURGE_CONFIG FORCE_REMOVE

  acquire_lock

  # Validation
  check_root
  validate_required_commands

  # Route to appropriate function
  if [[ ${REMOVE_MODE} == true ]]; then
    run_removal
  else
    run_installation
  fi
}

parse_arguments "$@"
main
