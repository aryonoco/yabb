#!/usr/bin/env bash

# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2023-2026 Aryan Ameri
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#

################################
#          Script Setup         #
################################
# Set locale to ensure consistent behavior
export LC_ALL=C
set -euo pipefail

################################
#     Constants & Variables     #
################################
# Exit codes
declare -r -i EXIT_SUCCESS=0
declare -r -i EXIT_INVALID_ARGUMENT=2
declare -r -i EXIT_CONFIG_MISSING=3
declare -r -i EXIT_MISSING_VAR=4
declare -r -i EXIT_INVALID_VAR=5
declare -r -i EXIT_PREREQ_MISSING=6
declare -r -i EXIT_DIR_INVALID=7
declare -r -i EXIT_NO_CHANGES=1  # Add this with the other EXIT_* constants

# File paths and locks
declare -r LOCK_FILE="/var/run/yabb.lock"
declare -r LAST_SNAPSHOT_FILE="/var/run/yabb_last_snapshot"
declare -r ERROR_COUNT_LOCK="/var/run/yabb_error_count.lock"

# Configuration variables
declare -r -a REQUIRED_VARS=("SRC_DIR" "DST_DIR" "SNAPSHOT_DIR" "COMPRESSION_LEVEL")
declare -r SNAPSHOT_PREFIX="backup."
declare -g -r SNAPSHOT_NAME="${SNAPSHOT_PREFIX}$(date -u '+%Y-%m-%dT%H%M%SZ')"
declare -g -a -r DELETED_SNAPSHOTS=()
declare -g -r CONFIG_FILE="/etc/yabb.conf"

# Ensure PATH includes necessary directories for systemd/cron environments
declare -r PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# Script version and metadata
declare -r SCRIPT_VERSION="1.0"
declare -g -i SCRIPT_STATUS=0
declare -g -A ERROR_COUNTS=([ERROR]=0 [WARNING]=0)

# Retry settings
declare -r -i RETRY_COUNT=3
declare -r -i RETRY_DELAY=5
declare -r -i LOCK_TIMEOUT=300

# Temporary file templates
declare -r TEMP_FILE_PREFIX="yabb"
declare -r TEMP_SNAPSHOT_PREFIX="yabb-snapshot"
declare -r TEMP_SEND_PREFIX="yabb-send"
declare -r TEMP_COMPARE_PREFIX="yabb-compare"
declare -r TEMP_LOCK_PREFIX="yabb-lock"

# Performance and efficiency thresholds
declare -r -i BALANCE_THRESHOLD=75
declare -r -i DEFRAG_THRESHOLD=50
declare -r -i MIN_FREE_SPACE=1024  # Minimum free space in MB
declare -r -i MAX_CHAIN_LENGTH=10  # Maximum snapshot chain length

# Compression settings
declare -r -A SUPPORTED_COMPRESSION=(
    ["zstd"]="ZSTD compression"
    ["zlib"]="ZLIB compression"
    ["lzo"]="LZO compression"
)
declare -r -i DEFAULT_COMPRESSION_LEVEL=3
declare -r DEFAULT_COMPRESSION_ALGO="zstd"

# Snapshot retention defaults (if not set in config)
declare -r -i DEFAULT_RETENTION_HOURLY=24
declare -r -i DEFAULT_RETENTION_DAILY=7
declare -r -i DEFAULT_RETENTION_WEEKLY=4
declare -r -i DEFAULT_RETENTION_MONTHLY=6
declare -r -i DEFAULT_RETENTION_YEARLY=2

# Feature flags and operational modes
declare -g -i BACKUP_DEBUG=0
declare -g -i DRY_RUN=0
declare -g -i FORCE_FULL=0
declare -g -i SNAPSHOT_COMPRESS=1
declare -g -i SNAPSHOT_ENCRYPT=0
declare -g -i MAX_PARALLEL_JOBS=1

# Global associative arrays for state tracking
declare -g -A PROGRESS_FILES=()
declare -g -A KEEP_SNAPSHOTS=()

# Logging categories
declare -r -a LOG_CATEGORIES=(
    "GENERAL" "PREREQ" "CONFIG" "LOCK" "SNAPSHOT" 
    "RETENTION" "COMPRESS" "CLEANUP" "PROGRESS" "ERROR"
)

# Signal handling
declare -r -a HANDLED_SIGNALS=(
    SIGTERM SIGINT SIGHUP SIGQUIT SIGABRT
)

################################
#     Prerequisites Check       #
################################
check_prerequisites() {
    # Correct the declaration of the associative array
    declare -A REQUIRED_COMMANDS=(
        ["btrfs"]="For btrfs operations"
        ["date"]="For timestamp operations"
        ["find"]="For finding snapshots"
        ["grep"]="For text processing"
        ["awk"]="For text processing"
        ["uuidgen"]="For generating unique IDs"
        ["df"]="For disk space checks"
        ["flock"]="For file locking"
        ["mktemp"]="For temporary file creation"
    )
    
    # Create temporary test file with proper cleanup
    declare local temp_test_file
    temp_test_file="$(mktemp -p /tmp -t "${TEMP_FILE_PREFIX}.XXXXXXXXXX")" || {
        handle_error "ERROR" "Failed to create temporary test file" "$EXIT_PREREQ_MISSING" "PREREQ"
        return "$EXIT_PREREQ_MISSING"
    }
    
    # Ensure cleanup of temporary test file
    trap 'rm -f "${temp_test_file}" 2>/dev/null || true; trap - RETURN' RETURN
    
    # Check for required commands using associative array
    declare local cmd
    for cmd in "${!REQUIRED_COMMANDS[@]}"; do
        if ! command -v "${cmd}" >/dev/null 2>&1; then
            handle_error "ERROR" \
                "Required command not found: ${cmd} (${REQUIRED_COMMANDS[${cmd}]})" \
                "$EXIT_PREREQ_MISSING" "PREREQ"
            return "$EXIT_PREREQ_MISSING"
        fi
        debug "Found required command: ${cmd}" "PREREQ"
    done

    # Check if running as root or with sufficient privileges
    if [[ "${EUID}" -ne 0 ]]; then
        handle_error "ERROR" "This script must be run as root" "$EXIT_PREREQ_MISSING" "PREREQ"
        return "$EXIT_PREREQ_MISSING"
    fi

    # Check btrfs tools with retry mechanism
    if ! retry "${RETRY_COUNT}" "${RETRY_DELAY}" btrfs version >/dev/null 2>&1; then
        handle_error "ERROR" "btrfs-progs not working properly" "$EXIT_PREREQ_MISSING" "PREREQ"
        return "$EXIT_PREREQ_MISSING"
    fi

    # Verify btrfs features required for efficient snapshots
    declare -r -a REQUIRED_FEATURES=(
        "Send/receive"
        "Compression"
        "Incremental backup"
    )
    
    if ! (( DRY_RUN )); then
        declare local feature
        for feature in "${REQUIRED_FEATURES[@]}"; do
            # Modify this check to ensure it correctly verifies the feature
            if ! btrfs send --dry-run /path/to/any/btrfs/subvolume >/dev/null 2>&1; then
                handle_error "ERROR" \
                    "Required btrfs feature not available: ${feature}" \
                    "$EXIT_PREREQ_MISSING" "PREREQ"
                return "$EXIT_PREREQ_MISSING"
            fi
            debug "Found required btrfs feature: ${feature}" "PREREQ"
        done
    fi

    # Check for zstd support in kernel with retry
    if ! retry "${RETRY_COUNT}" "${RETRY_DELAY}" \
        grep -q "zstd" /proc/crypto 2>/dev/null; then
        handle_error "ERROR" "Kernel does not support zstd compression" \
            "$EXIT_PREREQ_MISSING" "PREREQ"
        return "$EXIT_PREREQ_MISSING"
    fi

    # Verify write permissions in required directories
    declare -r -a local REQUIRED_DIRS=(
        "/tmp"
        "$(dirname "${LOCK_FILE}")"
        "$(dirname "${LAST_SNAPSHOT_FILE}")"
    )

    if ! (( DRY_RUN )); then
        declare local dir
        for dir in "${REQUIRED_DIRS[@]}"; do
            if ! retry "${RETRY_COUNT}" "${RETRY_DELAY}" \
                mktemp -p "${dir}" -t "${TEMP_FILE_PREFIX}.XXXXXXXXXX" >/dev/null 2>&1; then
                handle_error "ERROR" \
                    "Directory not writable: ${dir}" \
                    "$EXIT_PREREQ_MISSING" "PREREQ"
                return "$EXIT_PREREQ_MISSING"
            fi
            debug "Verified write access to: ${dir}" "PREREQ"
        done
    fi

    # Check systemd-cat availability for logging (optional)
    if command -v systemd-cat >/dev/null 2>&1; then
        debug "systemd-cat found, will use for logging" "PREREQ"
    else
        debug "systemd-cat not found, falling back to standard logging" "PREREQ"
    fi

    debug "All prerequisites checked successfully" "PREREQ"
    return "$EXIT_SUCCESS"
}
################################
#       Logging Functions       #
################################
# Main logging function
log() {
    declare -r local level="${1:-INFO}"
    declare -r local category="${2:-GENERAL}"
    declare -r local message="${3}"
    declare -r local formatted_message="[$(date -u '+%Y-%m-%d %H:%M:%S UTC')] [$level][$category] $message"
    printf "%s\n" "$formatted_message" >&2
    if command -v systemd-cat >/dev/null 2>&1; then
        declare -l local priority
        case "$level" in
            INFO) priority="info" ;;
            ERROR) priority="err" ;;
            WARNING) priority="warning" ;;
            DEBUG) priority="debug" ;;
            *) priority="info" ;;
        esac
        printf "%s\n" "$formatted_message" | systemd-cat -t "yabb" -p "$priority"
    fi
}

# Error logging
error() {
    declare -r local message="$1"
    declare -r -i local exit_code="${2:-$EXIT_INVALID_VAR}"
    declare -r local category="${3:-GENERAL}"
    handle_error "ERROR" "$message" "$exit_code" "$category"
    return "$exit_code"
}

warning() {
    declare -r local message="$1"
    declare -r local category="${2:-GENERAL}"
    handle_error "WARNING" "$message" 0 "$category"
}

debug() { [[ "${BACKUP_DEBUG:-0}" == "1" ]] && log "DEBUG" "${2:-GENERAL}" "$1"; }
info() { log "INFO" "${2:-GENERAL}" "$1"; }

################################
#     Validation Functions      #
################################
# Configuration validation
validate_config() {
    declare -i local status=0
    declare local var dir_var num_var
    declare -r local dir_path

    # Validate required variables
    for var in "${REQUIRED_VARS[@]}"; do
        if [[ -z "${!var:-}" ]]; then
            handle_error "ERROR" "Required variable '$var' is missing in 'yabb.conf'" "$EXIT_MISSING_VAR" "CONFIG"
            return "$EXIT_MISSING_VAR"
        fi
    done

    # Only proceed if required variables are present
    if (( status == 0 )); then
        # Validate optional configuration
        if ! validate_optional_config; then
            status=$?
        fi
    fi

    # Only proceed if optional config is valid
    if (( status == 0 )); then
        # Validate variable dependencies
        if ! validate_variable_dependencies; then
            status=$?
        fi
    fi

    # Only proceed if dependencies are valid
    if (( status == 0 )); then
        # Validate directory paths
        for dir_var in SRC_DIR DST_DIR SNAPSHOT_DIR; do
            dir_path="$(sanitize_path "${!dir_var}")" || {
                status=$?
                break
            }

            if ! validate_path "$dir_path" "directory" "true"; then
                status="$EXIT_DIR_INVALID"
                break
            fi
        done
    fi

    # Only proceed if paths are valid
    if (( status == 0 )); then
        # Validate numeric variables
        for num_var in FORCE_FULL DRY_RUN MIN_FREE_SPACE RETENTION_HOURLY RETENTION_DAILY \
            RETENTION_WEEKLY RETENTION_MONTHLY RETENTION_YEARLY; do
            if [[ -n "${!num_var}" && ! "${!num_var}" =~ ^[0-9]+$ ]]; then
                handle_error "ERROR" "$num_var must be a non-negative integer." "$EXIT_INVALID_VAR" "CONFIG"
                status="$EXIT_INVALID_VAR"
                break
            fi
        done
    fi

    # Only proceed if numeric variables are valid
    if (( status == 0 )); then
        # Validate COMPRESSION_LEVEL format
        if [[ ! "$COMPRESSION_LEVEL" =~ ^zstd:[0-9]+$ ]]; then
            handle_error "ERROR" "COMPRESSION_LEVEL must be in format 'zstd:<level>'." "$EXIT_INVALID_VAR" "CONFIG"
            status="$EXIT_INVALID_VAR"
        fi
    fi

    # Only make variables readonly if all validation passed
    if (( status == 0 )); then
        declare -a -r local readonly_vars=(
            "${REQUIRED_VARS[@]}"
            "SRC_DIR"
            "DST_DIR"
            "SNAPSHOT_DIR"
            "COMPRESSION_LEVEL"
            "FORCE_FULL"
            "DRY_RUN"
            "MIN_FREE_SPACE"
            "RETENTION_HOURLY"
            "RETENTION_DAILY"
            "RETENTION_WEEKLY"
            "RETENTION_MONTHLY"
            "RETENTION_YEARLY"
        )

        for var in "${readonly_vars[@]}"; do
            if ! readonly "$var" 2>/dev/null; then
                handle_error "WARNING" "Failed to make $var readonly" "$EXIT_INVALID_VAR" "CONFIG"
            fi
        done
    fi

    return "$status"
}

validate_optional_config() {
    # Define optional variables with their types and default values
    declare -A -r local OPTIONAL_VARS=(
        ["BACKUP_DEBUG"]="bool:0"
        ["FORCE_FULL"]="bool:0"
        ["DRY_RUN"]="bool:0"
        ["MIN_FREE_SPACE"]="int:1024"
        ["RETENTION_HOURLY"]="int:24"
        ["RETENTION_DAILY"]="int:7"
        ["RETENTION_WEEKLY"]="int:4"
        ["RETENTION_MONTHLY"]="int:6"
        ["RETENTION_YEARLY"]="int:2"
        ["SNAPSHOT_COMPRESS"]="bool:1"
        ["SNAPSHOT_ENCRYPT"]="bool:0"
        ["MAX_PARALLEL_JOBS"]="int:1"
        ["RETRY_ATTEMPTS"]="int:3"
        ["RETRY_DELAY"]="int:5"
    )

    declare local var_name var_spec var_type var_default
    for var_name in "${!OPTIONAL_VARS[@]}"; do
        var_spec="${OPTIONAL_VARS[$var_name]}"
        var_type="${var_spec%%:*}"
        var_default="${var_spec#*:}"

        # If variable is not set, set it to default
        if [[ -z "${!var_name+x}" ]]; then
            debug "Setting $var_name to default value: $var_default"
            declare -g "$var_name=$var_default"
            continue
        fi

        # Validate based on type
        case "$var_type" in
            bool)
                if [[ ! "${!var_name}" =~ ^[0-1]$ ]]; then
                    error "$var_name must be 0 or 1, got: ${!var_name}"
                    return "$EXIT_INVALID_VAR"
                fi
                ;;
            int)
                if ! [[ "${!var_name}" =~ ^[0-9]+$ ]]; then
                    error "$var_name must be a non-negative integer, got: ${!var_name}"
                    return "$EXIT_INVALID_VAR"
                fi
                ;;
            path)
                if ! validate_path "${!var_name}" "any" "false"; then
                    error "$var_name contains invalid path: ${!var_name}"
                    return "$EXIT_INVALID_VAR"
                fi
                ;;
            *)
                error "Unknown variable type $var_type for $var_name"
                return "$EXIT_INVALID_VAR"
                ;;
        esac

        debug "Validated optional variable $var_name=${!var_name}"
    done

    # Additional validation for specific variables
    if (( MIN_FREE_SPACE < 512 )); then
        warning "MIN_FREE_SPACE is set below recommended minimum of 512MB"
    fi

    if (( MAX_PARALLEL_JOBS > 8 )); then
        warning "MAX_PARALLEL_JOBS is set above recommended maximum of 8"
    fi

    # Make validated variables readonly
    for var_name in "${!OPTIONAL_VARS[@]}"; do
        readonly "$var_name"
    done

    return 0
}

validate_variable_dependencies() {
    # Check retention policy consistency
    if (( RETENTION_HOURLY > 0 )); then
        if (( RETENTION_HOURLY < 6 )); then
            warning "RETENTION_HOURLY is set below recommended minimum of 6 hours"
        fi
    fi

    if (( RETENTION_DAILY > 0 && RETENTION_HOURLY == 0 )); then
        warning "RETENTION_DAILY is set but RETENTION_HOURLY is disabled"
    fi

    # Check compression and encryption compatibility
    if (( SNAPSHOT_ENCRYPT == 1 && SNAPSHOT_COMPRESS == 0 )); then
        warning "Encryption without compression may result in suboptimal space usage"
    fi

    # Validate retry settings
    if (( RETRY_ATTEMPTS > 0 && RETRY_DELAY < 1 )); then
        handle_error "ERROR" "RETRY_DELAY must be at least 1 second when RETRY_ATTEMPTS is enabled" "$EXIT_INVALID_VAR" "CONFIG"
        return "$EXIT_INVALID_VAR"
    fi

    return 0
}

validate_retention_settings() {
    declare -a -r local retention_vars=("RETENTION_HOURLY" "RETENTION_DAILY" "RETENTION_WEEKLY" "RETENTION_MONTHLY" "RETENTION_YEARLY")
    for var in "${retention_vars[@]}"; do
        if [[ -n "${!var}" ]]; then
            if ! [[ "${!var}" =~ ^[0-9]+$ ]]; then
                handle_error "ERROR" "$var must be a non-negative integer" "$EXIT_INVALID_VAR" "CONFIG"
                return "$EXIT_INVALID_VAR"
            fi
            debug "Validated $var=${!var}"
        else
            debug "$var is not set"
        fi
    done
    return "$EXIT_SUCCESS"
}

check_filesystem_space() {
    declare -r dir="$1"
    declare -r -i available
    available=$(df -BM "$dir" | awk 'NR==2 {print $4}' | tr -d 'M')
    if (( available < MIN_FREE_SPACE )); then
        handle_error "ERROR" "Insufficient free space in $dir. Available: ${available}M, Required: ${MIN_FREE_SPACE}M" "$EXIT_INVALID_VAR" "SPACE"
        return "$EXIT_INVALID_VAR"
    fi
    return "$EXIT_SUCCESS"
}

################################
#      Utility Functions        #
################################
# Retry mechanism for commands
retry() {
    declare -r -i max_attempts="$1"
    declare -r -i initial_delay="$2"
    shift 2
    declare -r local category="RETRY"
    declare -r local command_string="$*"
    
    # Validate input parameters
    if (( max_attempts < 1 )); then
        handle_error "ERROR" "Invalid retry count: ${max_attempts}" \
            "$EXIT_INVALID_VAR" "${category}"
        return "$EXIT_INVALID_VAR"
    fi
    
    if (( initial_delay < 0 )); then
        handle_error "ERROR" "Invalid retry delay: ${initial_delay}" \
            "$EXIT_INVALID_VAR" "${category}"
        return "$EXIT_INVALID_VAR"
    fi
    
    # Create temporary directory for tracking attempts
    declare local temp_dir
    temp_dir="$(mktemp -d -t "${TEMP_FILE_PREFIX}-retry.XXXXXXXXXX")" || {
        handle_error "ERROR" "Failed to create temporary retry directory" \
            "$EXIT_INVALID_VAR" "${category}"
        return "$EXIT_INVALID_VAR"
    }
    
    # Ensure cleanup of temporary directory
    trap 'rm -rf "${temp_dir}" 2>/dev/null || true; trap - RETURN' RETURN
    
    declare -i local attempt=1
    declare local delay="$initial_delay"
    
    while (( attempt <= max_attempts )); do
        # Execute command and capture exit status atomically
        if ! (( DRY_RUN )); then
            if "${@}"; then
                debug "Command succeeded on attempt ${attempt}: ${command_string}" "${category}"
                return 0
            fi
            
            declare -r -i exit_code=$?
            
            if (( attempt == max_attempts )); then
                handle_error "ERROR" \
                    "Command failed after ${attempt} attempts: ${command_string}" \
                    "$exit_code" "${category}"
                return "$exit_code"
            fi
            
            warning "Command failed: ${command_string}. Attempt ${attempt}/${max_attempts}. Retrying in ${delay} seconds..." "${category}"
            
            # Sleep with interrupt handling
            if ! sleep "$delay"; then
                debug "Sleep interrupted, aborting retry" "${category}"
                return "$exit_code"
            fi
            
            # Exponential backoff with maximum delay cap
            declare -r -i MAX_DELAY=300  # 5 minutes
            delay=$(( delay * 2 < MAX_DELAY ? delay * 2 : MAX_DELAY ))
        else
            debug "DRY_RUN: Would retry command: ${command_string}" "${category}"
            return 0
        fi
        
        (( attempt++ ))
    done
    
    # This should never be reached due to the loop logic
    return "$EXIT_INVALID_VAR"
}

################################
#    Lock File Management       #
################################
# Acquire process lock
acquire_lock() {
    declare -r -i lock_fd=200
    declare -r lock_file="$1"

    # Create temporary lock file in standard temp directory
    declare -r local temp_lock_file
    temp_lock_file="$(mktemp -t "${TEMP_FILE_PREFIX}-lock.XXXXXXXXXX")" || {
        handle_error "ERROR" "Failed to create temporary lock file" "$EXIT_INVALID_VAR" "LOCK"
        return "$EXIT_INVALID_VAR"
    }
    # Link it to the actual lock file location
    ln -sf "$temp_lock_file" "$lock_file" || {
        rm -f "$temp_lock_file"
        handle_error "ERROR" "Failed to create lock file link" "$EXIT_INVALID_VAR" "LOCK"
        return "$EXIT_INVALID_VAR"
    }

    # Open lock file descriptor
    eval "exec $lock_fd>\"$lock_file\"" || {
        handle_error "ERROR" "Failed to open lock file: $lock_file" "$EXIT_INVALID_VAR"
        return "$EXIT_INVALID_VAR"
    }

    # Try to acquire the lock with a 5-minute timeout
    if ! flock -w 300 -n "$lock_fd"; then  # 5-minute timeout
        eval "exec $lock_fd>&-"
        handle_error "ERROR" "Failed to acquire lock after 5 minutes" "$EXIT_INVALID_VAR" "LOCK"
        return "$EXIT_INVALID_VAR"
    fi

    # Write PID to lock file
    printf '%d\n' "$$" > "$lock_file" || {
        warning "Failed to write PID to lock file"
    }

    return 0
}

# Release process lock
release_lock() {
    declare -r -i lock_fd=200
    declare -r lock_file="$1"
    declare temp_lock_file
    
    # Get the actual temp file path
    temp_lock_file="$(readlink "$lock_file" 2>/dev/null)"

    # Release the lock if we hold it
    if [[ -f "$lock_file" ]] && [[ "$(cat "$lock_file" 2>/dev/null)" == "$$" ]]; then
        flock -u "$lock_fd" 2>/dev/null || warning "Failed to release lock"
        rm -f "$lock_file" 2>/dev/null || warning "Failed to remove lock file"
        [[ -n "$temp_lock_file" ]] && rm -f "$temp_lock_file" 2>/dev/null
    fi

    # Close the file descriptor
    eval "exec $lock_fd>&-" 2>/dev/null
}

################################
#     Cleanup Management        #
################################
# Main cleanup function
cleanup() {
    declare -r -i exit_code=$?
    declare -i cleanup_failed=0

    # Release lock first
    release_lock "$LOCK_FILE" || cleanup_failed=1

    # Cleanup resources
    cleanup_resources || cleanup_failed=1

    # Remove error count lock file
    rm -f "$ERROR_COUNT_LOCK" 2>/dev/null

    # Report final status
    if [[ $SCRIPT_STATUS -ne 0 || $exit_code -ne 0 || $cleanup_failed -eq 1 ]]; then
        log "ERROR" "SUMMARY" "Script completed with errors. Status: $SCRIPT_STATUS, Exit: $exit_code, Errors: ${ERROR_COUNTS[ERROR]}, Warnings: ${ERROR_COUNTS[WARNING]}"
        return "$([[ $SCRIPT_STATUS -ne 0 ]] && printf '%d' "$SCRIPT_STATUS" || printf '%d' "$exit_code")"
    fi

    log "INFO" "SUMMARY" "Script completed successfully. Warnings: ${ERROR_COUNTS[WARNING]}"
    return 0
}

# Resource cleanup
cleanup_resources() {
    declare -i local status=0
    
    # Clean up any temporary files
    find /tmp -name "${TEMP_FILE_PREFIX}*" -user "$(id -u)" -type f -mmin +60 -delete 2>/dev/null || status=1
    echo "SNAPSHOT_DIR is set to: ${SNAPSHOT_DIR:-not set}"
    # Clean up any stale snapshot temporary directories
    find "$SNAPSHOT_DIR" -name "${TEMP_SNAPSHOT_PREFIX}*" -type d -mmin +60 -exec btrfs subvolume delete {} \; 2>/dev/null || status=1
    
    return "$status"
}

# Snapshot resource cleanup
cleanup_snapshot_resources() {
    declare -r local temp_snapshot="$1"
    declare -r local tmp_send_file="$2"
    declare -i local status=0

    if [[ -d "$temp_snapshot" ]]; then
        if ! (( DRY_RUN )); then
            debug "Cleaning up temporary snapshot: $temp_snapshot"
            if ! retry "$RETRY_COUNT" "$RETRY_DELAY" btrfs subvolume delete "$temp_snapshot" 2>/dev/null; then
                warning "Failed to cleanup temporary snapshot: $temp_snapshot"
                status=1
            fi
        else
            debug "DRY_RUN: Would delete temporary snapshot: $temp_snapshot" "CLEANUP"
        fi
    fi

    if [[ -f "$tmp_send_file" ]]; then
        debug "Cleaning up temporary send file: $tmp_send_file"
        if ! rm -f "$tmp_send_file" 2>/dev/null; then
            warning "Failed to remove temporary send file: $tmp_send_file"
            status=1
        fi
    fi

    return "$status"
}

################################
#     Storage Management        #
################################
# Storage efficiency check
check_storage_efficiency() {
    declare -r local target_dir="$1"
    declare -i local status=0
    
    debug "Checking storage efficiency for $target_dir" "STORAGE"
    
    # Check space usage
    declare -i local usage_percent
    usage_percent=$(btrfs filesystem usage "$target_dir" | awk '/Data,single/ {gsub(/%/,""); print $6}')
    
    if (( usage_percent > BALANCE_THRESHOLD )); then
        warning "Storage usage ($usage_percent%) exceeds threshold ($BALANCE_THRESHOLD%)"
        status=1
    fi
    
    # Check fragmentation
    declare -i local frag_percent
    frag_percent=$(btrfs filesystem df "$target_dir" | awk '/Data,single/ {print $5}' | tr -d '%')
    
    if (( frag_percent > DEFRAG_THRESHOLD )); then
        warning "Fragmentation ($frag_percent%) exceeds threshold ($DEFRAG_THRESHOLD%)"
        status=1
    fi
    
    return "$status"
}

# Storage optimization
optimize_storage() {
    declare -r local target_dir="$1"
    declare -i local status=0
    
    initialize_progress "Storage Optimization" 4
    
    if ! (( DRY_RUN )); then
        report_progress "Checking storage efficiency" 1
        
        # Check if optimization is needed
        if check_storage_efficiency "$target_dir"; then
            debug "Storage efficiency within acceptable limits" "STORAGE"
            return 0
        fi
        
        report_progress "Running defragmentation" 2
        # Defrag with compression
        if ! retry "$RETRY_COUNT" "$RETRY_DELAY" btrfs filesystem defrag -r -czstd -f "$target_dir"; then
            warning "Defragmentation failed for $target_dir"
            return "$EXIT_INVALID_VAR"
        fi
        
        report_progress "Balancing data blocks" 3
        # Balance with focus on space efficiency
        if ! retry "$RETRY_COUNT" "$RETRY_DELAY" btrfs balance start \
            -dusage=5,limit=2 \
            -musage=5,limit=4 \
            "$target_dir"; then
            warning "Balance failed for $target_dir"
            return "$EXIT_INVALID_VAR"
        fi
        
        report_progress "Scrubbing filesystem" 4
        # Scrub to ensure data integrity
        if ! retry "$RETRY_COUNT" "$RETRY_DELAY" btrfs scrub start -B "$target_dir"; then
            warning "Scrub failed for $target_dir"
            return "$EXIT_INVALID_VAR"
        fi
    else
        report_progress "DRY_RUN: Would optimize storage" 4
    fi
    
    return "$EXIT_SUCCESS"
}

# Storage balancing
balance_storage() {
    declare -r local target_dir="$1"
    
    initialize_progress "Storage Balance" 3
    
    if ! (( DRY_RUN )); then
        report_progress "Starting metadata balance" 1
        
        # First balance metadata for better performance
        if ! retry "$RETRY_COUNT" "$RETRY_DELAY" btrfs balance start -musage=0 "$target_dir"; then
            warning "Metadata balance failed for $target_dir"
            return "$EXIT_INVALID_VAR"
        fi
        
        report_progress "Starting data balance" 2
        
        # Then balance data with focus on space efficiency
        if ! retry "$RETRY_COUNT" "$RETRY_DELAY" btrfs balance start -dusage=0 "$target_dir"; then
            warning "Data balance failed for $target_dir"
            return "$EXIT_INVALID_VAR"
        fi
        
        report_progress "Balance completed" 3
    else
        report_progress "DRY_RUN: Would balance storage" 3
    fi
    
    return "$EXIT_SUCCESS"
}

################################
#     Snapshot Management       #
################################
# Create snapshot
create_snapshot() {
    # Add directory existence check before creating snapshot
    if [[ ! -d "$SNAPSHOT_DIR" ]]; then
        if ! mkdir -p "$SNAPSHOT_DIR"; then
            handle_error "ERROR" "Failed to create snapshot directory" "$EXIT_INVALID_VAR" "SNAPSHOT"
            return "$EXIT_INVALID_VAR"
        fi
    fi

    declare -r local temp_snapshot
    temp_snapshot="$(mktemp -d -p "$SNAPSHOT_DIR" "${TEMP_COMPARE_PREFIX}.XXXXXXXXXX")" || {
        handle_error "ERROR" "Failed to create temporary snapshot directory" "$EXIT_INVALID_VAR" "SNAPSHOT"
        return "$EXIT_INVALID_VAR"
    }
    declare -r local new_snapshot
    new_snapshot="$(join_paths "$SNAPSHOT_DIR" "$SNAPSHOT_NAME")" || return "$?"

    declare local last_snapshot=""
    declare local parent_snapshot=""
    declare -i local do_full_snapshot=1
    declare -i local retry_count=3
    declare -i local retry_delay=5

    # Create temporary file for send/receive operations with proper cleanup
    declare -r local tmp_send_file
    tmp_send_file="$(mktemp -t "${TEMP_SEND_PREFIX}.XXXXXXXXXX")" || {
        handle_error "ERROR" "Failed to create temporary send file" "$EXIT_INVALID_VAR" "SNAPSHOT"
        return "$EXIT_INVALID_VAR"
    }

    # Ensure cleanup of temporary resources
    trap 'cleanup_snapshot_resources "$temp_snapshot" "$tmp_send_file"; trap - RETURN' RETURN

    # Initialize progress tracking with correct step count
    initialize_progress "Snapshot Creation" 12

    # Check for previous snapshot with proper error handling
    report_progress "Checking previous snapshots" 1
    if [[ -f "$LAST_SNAPSHOT_FILE" ]]; then
        last_snapshot="$(cat "$LAST_SNAPSHOT_FILE")" || {
            warning "Failed to read last snapshot file"
            do_full_snapshot=1
        }

        if [[ -n "$last_snapshot" ]] && verify_snapshot "$last_snapshot" 2>/dev/null; then
            report_progress "Checking for changes" 2
            # Find the most appropriate parent snapshot
            parent_snapshot="$(get_latest_snapshot "$SNAPSHOT_DIR")"
            
            if [[ -n "$parent_snapshot" ]] && verify_snapshot "$parent_snapshot" 2>/dev/null; then
                report_progress "Found parent snapshot: $parent_snapshot" 2
                
                # Create temporary snapshot for comparison
                if retry "$retry_count" "$retry_delay" btrfs subvolume snapshot -r "$SRC_DIR" "$temp_snapshot"; then
                    # Check for changes efficiently
                    if ! detect_changes "$parent_snapshot" "$temp_snapshot"; then
                        report_progress "No changes detected, skipping" 10
                        return "$EXIT_SUCCESS"
                    fi
                    do_full_snapshot=0
                    report_progress "Changes detected, creating incremental snapshot" 3
                else
                    warning "Failed to create temporary snapshot for comparison"
                    do_full_snapshot=1
                fi
            else
                report_progress "No valid parent snapshot found, creating full snapshot" 2
                do_full_snapshot=1
            fi
        else
            warning "Last snapshot verification failed. Proceeding with full snapshot." "SNAPSHOT"
            do_full_snapshot=1
        fi
    else
        report_progress "No previous snapshot found" 2
        do_full_snapshot=1
    fi

    # Create the actual snapshot with optimal settings
    report_progress "Creating snapshot with reference to parent" 4
    retry "$retry_count" "$retry_delay" btrfs subvolume snapshot \
        -r \
        -i 32k \
        "$SRC_DIR" "$new_snapshot" || {
        handle_error "ERROR" "Failed to create snapshot: $SNAPSHOT_NAME" "$EXIT_INVALID_VAR" "SNAPSHOT"
        return "$EXIT_INVALID_VAR"
    }

    # Set parent reference in metadata
    if [[ -n "$parent_snapshot" ]] && (( ! do_full_snapshot )); then
        retry "$retry_count" "$retry_delay" btrfs property set "$new_snapshot" user.snapshot.parent "$parent_snapshot" || {
            warning "Failed to set parent snapshot reference"
            return "$EXIT_INVALID_VAR"
        }
    fi

    # Send snapshot with optimal reference handling
    report_progress "Sending snapshot" 5
    if [[ "${FORCE_FULL:-0}" -eq 1 ]] || (( do_full_snapshot )); then
        info "Performing full snapshot send" "SNAPSHOT"
        retry "$RETRY_COUNT" "$RETRY_DELAY" btrfs send \
            --compressed-data \
            --no-data-copy \
            "$new_snapshot" > "$tmp_send_file" || {
            handle_error "ERROR" "Failed to send full snapshot" "$EXIT_INVALID_VAR" "SNAPSHOT"
            return "$EXIT_INVALID_VAR"
        }
    else
        info "Performing incremental snapshot send from parent" "SNAPSHOT"
        retry "$RETRY_COUNT" "$RETRY_DELAY" btrfs send \
            --compressed-data \
            --no-data-copy \
            -c "$parent_snapshot" \
            -p "$parent_snapshot" "$new_snapshot" > "$tmp_send_file" || {
            warning "Incremental send failed, falling back to full send"
            retry "$RETRY_COUNT" "$RETRY_DELAY" btrfs send \
                --compressed-data \
                --no-data-copy \
                "$new_snapshot" > "$tmp_send_file" || {
                handle_error "ERROR" "Failed to send snapshot" "$EXIT_INVALID_VAR" "SNAPSHOT"
                return "$EXIT_INVALID_VAR"
            }
        }
    fi

    # Update snapshot chain metadata
    if ! (( DRY_RUN )); then
        report_progress "Updating snapshot chain metadata" 6
        update_snapshot_chain_metadata "$new_snapshot" "$parent_snapshot" || {
            warning "Failed to update snapshot chain metadata"
            return "$EXIT_INVALID_VAR"
        }
    else
        report_progress "DRY_RUN: Would update snapshot chain metadata" 6
    fi

    # Receive with storage efficiency options
    report_progress "Receiving snapshot" 7
    retry "$RETRY_COUNT" "$RETRY_DELAY" btrfs receive \
        --max-errors 10 \
        -v \
        "$DST_DIR" < "$tmp_send_file" || {
        handle_error "ERROR" "Failed to receive snapshot" "$EXIT_INVALID_VAR" "SNAPSHOT"
        return "$EXIT_INVALID_VAR"
    }

    # Single verification block
    report_progress "Verifying snapshot" 10
    verify_snapshot "$new_snapshot" || {
        handle_error "ERROR" "Verification failed for: $new_snapshot" "$EXIT_INVALID_VAR" "SNAPSHOT"
        return "$EXIT_INVALID_VAR"
    }

    # Add last snapshot file update
    if ! (( DRY_RUN )); then
        report_progress "Updating last snapshot reference" 11
        printf '%s\n' "$new_snapshot" > "$LAST_SNAPSHOT_FILE" || {
            handle_error "ERROR" "Failed to update last snapshot file" "$EXIT_INVALID_VAR" "SNAPSHOT"
            return "$EXIT_INVALID_VAR"
        }
    else
        report_progress "DRY_RUN: Would update last snapshot reference" 11
    fi

    report_progress "Completed successfully" 12
    return "$EXIT_SUCCESS"
}

# Verify snapshot
verify_snapshot() {
    declare -r local snapshot_path="$1"
    declare -r local category="VERIFY"
    declare -i local status="$EXIT_SUCCESS"
    
    # Validate input
    if [[ -z "${snapshot_path}" ]]; then
        handle_error "ERROR" "Empty snapshot path provided" \
            "$EXIT_INVALID_VAR" "${category}"
        return "$EXIT_INVALID_VAR"
    fi

    if ! (( DRY_RUN )); then
        # Create temporary directory with secure permissions
        declare local temp_dir
        temp_dir="$(mktemp -d -t "${TEMP_FILE_PREFIX}-verify.XXXXXXXXXX")" || {
            handle_error "ERROR" "Failed to create temporary verify directory" \
                "$EXIT_INVALID_VAR" "${category}"
            return "$EXIT_INVALID_VAR"
        }

        # Create result file with secure permissions
        declare -r local result_file="${temp_dir}/result"
        if ! mktemp -p "${temp_dir}" -t "result.XXXXXXXXXX" > /dev/null 2>&1; then
            rm -rf "${temp_dir}" 2>/dev/null || true
            handle_error "ERROR" "Failed to create result file" \
                "$EXIT_INVALID_VAR" "${category}"
            return "$EXIT_INVALID_VAR"
        fi

        # Create lock file with secure permissions
        declare -r local lock_file="${temp_dir}/lock"
        if ! mktemp -p "${temp_dir}" -t "lock.XXXXXXXXXX" > /dev/null 2>&1; then
            rm -rf "${temp_dir}" 2>/dev/null || true
            handle_error "ERROR" "Failed to create lock file" \
                "$EXIT_INVALID_VAR" "${category}"
            return "$EXIT_INVALID_VAR"
        fi

        # Enhanced cleanup trap handling all signals
        trap 'err=$?; rm -rf "${temp_dir}" 2>/dev/null || true; 
             if [[ -n "${lock_file}" && -f "${lock_file}" ]]; then
                 flock -u 200 2>/dev/null || true;
                 rm -f "${lock_file}" 2>/dev/null || true;
             fi;
             trap - RETURN SIGTERM SIGINT SIGHUP ERR EXIT;
             exit "$err"' \
            RETURN SIGTERM SIGINT SIGHUP ERR EXIT

        # Perform verifications atomically with retries
        if ! retry "${RETRY_COUNT}" "${RETRY_DELAY}" \
            flock -w "${LOCK_TIMEOUT}" -x "${lock_file}" \
            bash -c '
                set -euo pipefail
                shopt -s inherit_errexit
                
                declare -r snapshot_path="$1"
                declare -r temp_dir="$2"
                declare -r result_file="$3"
                declare -r -A REQUIRED_PROPS=(
                    ["user.snapshot.uuid"]="Unique snapshot identifier"
                    ["user.snapshot.timestamp"]="Snapshot creation time"
                    ["user.snapshot.type"]="Snapshot type (full/incremental)"
                    ["user.snapshot.parent"]="Parent snapshot reference"
                    ["user.snapshot.compression"]="Compression settings"
                )
                
                # Verify directory existence and type
                if [[ ! -d "${snapshot_path}" ]]; then
                    printf "Snapshot path does not exist or is not a directory" > "${result_file}"
                    exit 1
                fi

                # Verify btrfs subvolume with retry
                if ! retry "${RETRY_COUNT}" "${RETRY_DELAY}" \
                    btrfs subvolume show "${snapshot_path}" >/dev/null 2>&1; then
                    printf "Not a valid btrfs subvolume" > "${result_file}"
                    exit 1
                fi

                # Verify read-only status with retry
                if ! retry "${RETRY_COUNT}" "${RETRY_DELAY}" \
                    btrfs property get "${snapshot_path}" ro | grep -q "ro=true"; then
                    printf "Snapshot is not read-only" > "${result_file}"
                    exit 1
                fi

                # Verify required metadata properties with retries
                for prop in "${!REQUIRED_PROPS[@]}"; do
                    if ! retry "${RETRY_COUNT}" "${RETRY_DELAY}" \
                        btrfs property get "${snapshot_path}" "${prop}" >/dev/null 2>&1; then
                        printf "Missing required property (%s): %s" \
                            "${prop}" "${REQUIRED_PROPS[${prop}]}" > "${result_file}"
                        exit 1
                    fi
                done

                # Verify snapshot name format
                declare -r snapshot_name="$(basename "${snapshot_path}")"
                declare -r timestamp_pattern="^${SNAPSHOT_PREFIX}[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{6}Z$"
                if [[ ! "${snapshot_name}" =~ ${timestamp_pattern} ]]; then
                    printf "Invalid snapshot name format" > "${result_file}"
                    exit 1
                fi

                # Verify snapshot timestamp validity with retry
                declare -r timestamp="${snapshot_name#${SNAPSHOT_PREFIX}}"
                if ! retry "${RETRY_COUNT}" "${RETRY_DELAY}" \
                    date -u -d "${timestamp}" >/dev/null 2>&1; then
                    printf "Invalid snapshot timestamp" > "${result_file}"
                    exit 1
                fi

                # Verify parent snapshot if incremental
                declare -r snapshot_type="$(retry "${RETRY_COUNT}" "${RETRY_DELAY}" \
                    btrfs property get "${snapshot_path}" user.snapshot.type)"
                if [[ "${snapshot_type#*=}" == "incremental" ]]; then
                    declare -r parent="$(retry "${RETRY_COUNT}" "${RETRY_DELAY}" \
                        btrfs property get "${snapshot_path}" user.snapshot.parent)"
                    declare -r parent_path="${parent#*=}"
                    if [[ "${parent_path}" != "none" ]] && [[ ! -d "${parent_path}" ]]; then
                        printf "Parent snapshot not found: %s" "${parent_path}" > "${result_file}"
                        exit 1
                    fi
                fi

                exit 0
            ' -- "${snapshot_path}" "${temp_dir}" "${result_file}"; then
            
            # Read error message if available with retry
            declare local error_msg="Snapshot verification failed"
            if [[ -f "${result_file}" ]]; then
                if ! error_msg="$(retry "${RETRY_COUNT}" "${RETRY_DELAY}" cat "${result_file}")"; then
                    error_msg="Failed to read error message"
                fi
            fi
            
            handle_error "ERROR" "${error_msg}: ${snapshot_path}" \
                "$EXIT_INVALID_VAR" "${category}"
            status="$EXIT_INVALID_VAR"
        else
            debug "Snapshot verified successfully: ${snapshot_path}" "${category}"
        fi
    else
        debug "DRY_RUN: Would verify snapshot: ${snapshot_path}" "${category}"
    fi

    return "${status}"
}

################################
#     Chain Management          #
################################
# Optimize snapshot chain
optimize_snapshot_chain() {
    declare -r local snapshot_dir="$1"
    declare -r -i local max_chain_length=10
    declare -i local status=0
    declare -r local category="CHAIN"
    
    initialize_progress "Chain Optimization" 3
    
    report_progress "Checking chain length" 1
    
    if ! (( DRY_RUN )); then
        # Create temporary lock file for chain operations
        declare local chain_lock
        chain_lock="$(mktemp -t "${TEMP_FILE_PREFIX}-chain-lock.XXXXXXXXXX")" || {
            handle_error "ERROR" "Failed to create chain lock" \
                "$EXIT_INVALID_VAR" "${category}"
            return "$EXIT_INVALID_VAR"
        }
        
        # Ensure cleanup of chain lock
        trap 'rm -f "${chain_lock}" 2>/dev/null || true; trap - RETURN' \
            RETURN SIGINT SIGTERM SIGHUP ERR EXIT

        # Get current chain length with atomic operations
        declare -i local chain_length
        if ! chain_length=$(retry "${RETRY_COUNT}" "${RETRY_DELAY}" \
            flock -w "${LOCK_TIMEOUT:-300}" -x "${chain_lock}" \
            btrfs subvolume list -p "${snapshot_dir}" | grep -c "^ID") || \
            (( chain_length < 1 )); then
            warning "Failed to get snapshot chain length, attempting recovery"
            if ! retry "${RETRY_COUNT}" "${RETRY_DELAY}" \
                flock -w "${LOCK_TIMEOUT:-300}" -x "${chain_lock}" \
                recover_snapshot_chain "${snapshot_dir}"; then
                warning "Chain recovery failed"
                return 1
            fi
            # Try again after recovery with atomic operation
            chain_length=$(retry "${RETRY_COUNT}" "${RETRY_DELAY}" \
                flock -w "${LOCK_TIMEOUT:-300}" -x "${chain_lock}" \
                btrfs subvolume list -p "${snapshot_dir}" | grep -c "^ID") || {
                warning "Failed to get snapshot chain length even after recovery"
                return 1
            }
        fi
        
        report_progress "Analyzing chain length ($chain_length)" 2
        
        if (( chain_length > max_chain_length )); then
            report_progress "Creating new full snapshot" 3
            retry "$RETRY_COUNT" "$RETRY_DELAY" btrfs subvolume snapshot -r "$SRC_DIR" "${snapshot_dir}/backup.full.$(date -u '+%Y%m%d')" || {
                warning "Failed to create new full snapshot for chain optimization"
                status=1
            }
        else
            report_progress "Chain length optimal" 3
        fi
    else
        report_progress "DRY_RUN: Would check chain length" 3
    fi
    
    return "$status"
}

# Get latest snapshot
get_latest_snapshot() {
    declare -r local snapshot_dir="$1"
    declare -r local category="SNAPSHOT"
    declare local latest_snapshot=""
    declare -i local latest_time=0
    
    # Validate input
    if [[ ! -d "${snapshot_dir}" ]]; then
        handle_error "ERROR" "Snapshot directory does not exist: ${snapshot_dir}" \
            "$EXIT_INVALID_VAR" "${category}"
        return "$EXIT_INVALID_VAR"
    fi

    if ! (( DRY_RUN )); then
        # Create temporary directory for atomic operations
        declare local temp_dir
        temp_dir="$(mktemp -d -t "${TEMP_FILE_PREFIX}-latest.XXXXXXXXXX")" || {
            handle_error "ERROR" "Failed to create temporary directory" \
                "$EXIT_INVALID_VAR" "${category}"
            return "$EXIT_INVALID_VAR"
        }

        # Ensure cleanup of temporary directory and handle all signals
        trap 'rm -rf "${temp_dir}" 2>/dev/null || true; trap - RETURN' \
            RETURN SIGTERM SIGINT SIGHUP ERR EXIT

        # Create lock file for atomic operations
        declare -r local lock_file="${temp_dir}/lock"
        touch "${lock_file}" || {
            handle_error "ERROR" "Failed to create lock file" \
                "$EXIT_INVALID_VAR" "${category}"
            return "$EXIT_INVALID_VAR"
        }

        # Find latest snapshot atomically
        if ! retry "${RETRY_COUNT}" "${RETRY_DELAY}" \
            flock -w "${LOCK_TIMEOUT}" -x "${lock_file}" \
            bash -c '
                set -euo pipefail
                
                declare -r snapshot_dir="$1"
                declare -r temp_dir="$2"
                declare -r result_file="${temp_dir}/result"
                declare local latest_snapshot=""
                declare -i local latest_time=0
                
                # Process each snapshot
                while IFS= read -r snapshot; do
                    # Skip if not a directory
                    [[ -d "${snapshot}" ]] || continue
                    
                    # Get snapshot timestamp
                    declare -i local snap_time
                    if ! snap_time=$(get_snapshot_timestamp "${snapshot}"); then
                        continue
                    fi
                    
                    # Update latest if this snapshot is newer
                    if (( snap_time > latest_time )); then
                        latest_snapshot="${snapshot}"
                        latest_time="${snap_time}"
                    fi
                done < <(find "${snapshot_dir}" -maxdepth 1 -name "${SNAPSHOT_PREFIX}*" -type d)
                
                # Write result atomically
                printf "%s" "${latest_snapshot}" > "${result_file}.tmp"
                mv -f "${result_file}.tmp" "${result_file}"
            ' -- "${snapshot_dir}" "${temp_dir}"; then
            handle_error "ERROR" "Failed to find latest snapshot" \
                "$EXIT_INVALID_VAR" "${category}"
            return "$EXIT_INVALID_VAR"
        fi

        # Read result atomically
        declare -r local result_file="${temp_dir}/result"
        if [[ -f "${result_file}" ]]; then
            latest_snapshot="$(cat "${result_file}")"
        fi

        if [[ -n "${latest_snapshot}" ]]; then
            # Verify the snapshot integrity
            if ! retry "${RETRY_COUNT}" "${RETRY_DELAY}" verify_snapshot "${latest_snapshot}"; then
                handle_error "ERROR" "Latest snapshot verification failed: ${latest_snapshot}" \
                    "$EXIT_INVALID_VAR" "${category}"
                return "$EXIT_INVALID_VAR"
            fi
            debug "Found latest snapshot: ${latest_snapshot}" "${category}"
        else
            debug "No valid snapshots found in: ${snapshot_dir}" "${category}"
        fi
    else
        debug "DRY_RUN: Would find latest snapshot in: ${snapshot_dir}" "${category}"
    fi

    printf '%s' "${latest_snapshot}"
    return "$EXIT_SUCCESS"
}

# Find parent snapshot
find_parent_snapshot() {
    declare -r local snapshot_dir="$1"
    declare -r local current_time="$2"
    declare -i local recovery_attempted=0
    
    if [[ ! -d "${snapshot_dir}" ]]; then
        warning "Snapshot directory does not exist: ${snapshot_dir}"
        return "$EXIT_INVALID_VAR"
    fi
    
    if [[ -z "${current_time}" ]] || ! [[ "${current_time}" =~ ^[0-9]+$ ]]; then
        warning "Invalid current time provided"
        return "$EXIT_INVALID_VAR"
    fi
    
    while true; do
        declare local parent_snapshot=""
        declare -i local parent_time=0
        
        while IFS= read -r snapshot; do
            if [[ ! -d "${snapshot}" ]] || \
                ! retry "${RETRY_COUNT}" "${RETRY_DELAY}" verify_snapshot "${snapshot}"; then
                debug "Skipping invalid snapshot path: ${snapshot}"
                continue
            fi
            
            declare -i local snap_time
            snap_time=$(get_snapshot_timestamp "${snapshot}") || {
                debug "Failed to get timestamp for snapshot: ${snapshot}"
                continue
            }
            
            if (( snap_time < current_time && snap_time > parent_time )); then
                parent_snapshot="${snapshot}"
                parent_time="${snap_time}"
            fi
        done < <(find "${snapshot_dir}" -maxdepth 1 -name "${SNAPSHOT_PREFIX}*" -type d)
        
        # If no valid parent found and haven't tried recovery yet
        if [[ -z "${parent_snapshot}" && "${recovery_attempted}" -eq 0 ]]; then
            warning "No valid parent snapshot found, attempting recovery"
            if recover_snapshot_chain "${snapshot_dir}"; then
                recovery_attempted=1
                continue  # Try again after recovery
            fi
        fi
        break
    done
    
    printf '%s' "${parent_snapshot}"
    return 0
}

# Update chain metadata
update_snapshot_chain_metadata() {
    declare -r local current_snapshot="$1"
    declare -r local parent_snapshot="$2"
    declare -r local category="METADATA"
    declare -i local status=0

    # Validate input parameters
    if [[ ! -d "${current_snapshot}" ]]; then
        handle_error "ERROR" "Current snapshot does not exist: ${current_snapshot}" \
            "${EXIT_INVALID_VAR}" "${category}"
        return "${EXIT_INVALID_VAR}"
    fi

    # Create temporary directory with secure permissions
    declare local temp_dir
    temp_dir="$(mktemp -d -t "${TEMP_FILE_PREFIX}-metadata.XXXXXXXXXX")" || {
        handle_error "ERROR" "Failed to create temporary metadata directory" \
            "${EXIT_INVALID_VAR}" "${category}"
        return "${EXIT_INVALID_VAR}"
    }

    # Create metadata file with secure permissions
    declare -r local metadata_file="${temp_dir}/metadata"
    if ! mktemp -p "${temp_dir}" -t "metadata.XXXXXXXXXX" > /dev/null 2>&1; then
        rm -rf "${temp_dir}" 2>/dev/null || true
        handle_error "ERROR" "Failed to create metadata file" \
            "${EXIT_INVALID_VAR}" "${category}"
        return "${EXIT_INVALID_VAR}"
    fi

    # Create lock file with secure permissions
    declare -r local lock_file="${temp_dir}/lock"
    if ! mktemp -p "${temp_dir}" -t "lock.XXXXXXXXXX" > /dev/null 2>&1; then
        rm -rf "${temp_dir}" 2>/dev/null || true
        handle_error "ERROR" "Failed to create lock file" \
            "${EXIT_INVALID_VAR}" "${category}"
        return "${EXIT_INVALID_VAR}"
    fi

    # Ensure cleanup of temporary files and handle all signals
    trap 'rm -rf "${temp_dir}" 2>/dev/null || true; trap - RETURN' \
        RETURN SIGTERM SIGINT SIGHUP ERR EXIT

    if ! (( DRY_RUN )); then
        # Verify current snapshot with retry
        if ! retry "${RETRY_COUNT}" "${RETRY_DELAY}" verify_snapshot "${current_snapshot}"; then
            handle_error "ERROR" "Invalid current snapshot: ${current_snapshot}" \
                "${EXIT_INVALID_VAR}" "${category}"
            return "${EXIT_INVALID_VAR}"
        fi

        # Define comprehensive metadata properties
        declare -A -r local metadata=(
            ["user.snapshot.uuid"]="$(uuidgen)"
            ["user.snapshot.timestamp"]="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
            ["user.snapshot.source"]="${SRC_DIR}"
            ["user.snapshot.destination"]="${DST_DIR}"
            ["user.snapshot.compression"]="${COMPRESSION_LEVEL}"
            ["user.snapshot.type"]="$([[ -n "${parent_snapshot}" ]] && printf "incremental" || printf "full")"
            ["user.snapshot.hostname"]="$(hostname -f)"
            ["user.snapshot.kernel"]="$(uname -r)"
            ["user.snapshot.size"]="$(retry "${RETRY_COUNT}" "${RETRY_DELAY}" \
                btrfs filesystem df "${current_snapshot}" | \
                awk '/Data,single/ {print $3}')"
        )

        # Use flock for atomic metadata updates
        if ! retry "${RETRY_COUNT}" "${RETRY_DELAY}" \
            flock -w "${LOCK_TIMEOUT:-300}" -x "${lock_file}" \
            bash -c '
                set -euo pipefail
                shopt -s inherit_errexit
                
                declare -r current_snapshot="$1"
                declare -r parent_snapshot="$2"
                declare -r metadata_file="$3"
                declare -r temp_dir="$4"
                declare -i local status=0
                
                # Set parent reference and chain position atomically
                if [[ -n "${parent_snapshot}" ]] && [[ -d "${parent_snapshot}" ]]; then
                    # Verify parent snapshot with retry
                    if ! retry "${RETRY_COUNT}" "${RETRY_DELAY}" verify_snapshot "${parent_snapshot}"; then
                        return "${EXIT_INVALID_VAR}"
                    fi
                    
                    # Create temporary property file
                    declare -r local temp_prop="${temp_dir}/prop.tmp"
                    
                    # Set parent reference atomically
                    if ! retry "${RETRY_COUNT}" "${RETRY_DELAY}" \
                        btrfs property set "${current_snapshot}" \
                        user.snapshot.parent "${parent_snapshot}"; then
                        return "${EXIT_INVALID_VAR}"
                    fi
                    
                    # Get parent chain position with retry and validation
                    declare -i chain_position=0
                    declare local chain_pos
                    if chain_pos="$(retry "${RETRY_COUNT}" "${RETRY_DELAY}" \
                        btrfs property get "${parent_snapshot}" \
                        user.snapshot.chain.position 2>/dev/null)"; then
                        if [[ "${chain_pos}" =~ ^user\.snapshot\.chain\.position=([0-9]+)$ ]]; then
                            chain_position="${BASH_REMATCH[1]}"
                        fi
                    fi
                    
                    # Increment and set new chain position atomically
                    chain_position=$((chain_position + 1))
                    printf "%d" "${chain_position}" > "${temp_prop}"
                    
                    if ! retry "${RETRY_COUNT}" "${RETRY_DELAY}" \
                        btrfs property set "${current_snapshot}" \
                        user.snapshot.chain.position "$(cat "${temp_prop}")"; then
                        return "${EXIT_INVALID_VAR}"
                    fi
                    
                    # Record chain length for efficiency tracking
                    if ! retry "${RETRY_COUNT}" "${RETRY_DELAY}" \
                        btrfs property set "${current_snapshot}" \
                        user.snapshot.chain.length "${chain_position}"; then
                        status=1
                    fi
                else
                    # Start new chain atomically
                    if ! retry "${RETRY_COUNT}" "${RETRY_DELAY}" \
                        btrfs property set "${current_snapshot}" \
                        user.snapshot.parent "none"; then
                        return "${EXIT_INVALID_VAR}"
                    fi
                    
                    if ! retry "${RETRY_COUNT}" "${RETRY_DELAY}" \
                        btrfs property set "${current_snapshot}" \
                        user.snapshot.chain.position "0"; then
                        return "${EXIT_INVALID_VAR}"
                    fi
                    
                    if ! retry "${RETRY_COUNT}" "${RETRY_DELAY}" \
                        btrfs property set "${current_snapshot}" \
                        user.snapshot.chain.length "0"; then
                        status=1
                    fi
                fi
                
                return "${status}"
            ' -- "${current_snapshot}" "${parent_snapshot}" "${metadata_file}" "${temp_dir}"; then
            status="${EXIT_INVALID_VAR}"
            handle_error "ERROR" "Failed to update chain metadata" \
                "${EXIT_INVALID_VAR}" "${category}"
            return "${status}"
        fi
        
        # Set additional metadata properties atomically with batching
        declare -r -i local BATCH_SIZE=5
        declare -i local count=0
        declare -a local batch=()
        
        for prop in "${!metadata[@]}"; do
            batch+=("${prop}" "${metadata[${prop}]}")
            (( count++ ))
            
            if (( count >= BATCH_SIZE )) || [[ "${prop}" == "${!metadata[@]: -1}" ]]; then
                if ! retry "${RETRY_COUNT}" "${RETRY_DELAY}" \
                    flock -w "${LOCK_TIMEOUT:-300}" -x "${lock_file}" \
                    bash -c '
                        set -euo pipefail
                        declare -r snapshot="$1"
                        shift
                        declare -a props=("$@")
                        
                        for ((i=0; i<${#props[@]}; i+=2)); do
                            if ! retry "${RETRY_COUNT}" "${RETRY_DELAY}" \
                                btrfs property set "${snapshot}" \
                                "${props[i]}" "${props[i+1]}"; then
                                return 1
                            fi
                        done
                        return 0
                    ' -- "${current_snapshot}" "${batch[@]}"; then
                    warning "Failed to set metadata properties batch" "${category}"
                    status=1
                fi
                batch=()
                count=0
            fi
        done
        
        debug "Updated chain metadata for: ${current_snapshot}" "${category}"
    else
        debug "DRY_RUN: Would update chain metadata for: ${current_snapshot}" "${category}"
        debug "DRY_RUN: Parent snapshot: ${parent_snapshot:-none}" "${category}"
    fi
    
    return "${status}"
}

################################
#     Retention Management      #
################################
# Apply retention policies
apply_retention() {
    declare -r local target_dir="$1"
    shift
    declare -a -r local snapshots=("${@}")
    declare -a -r local retention_vars=("hourly" "daily" "weekly" "monthly" "yearly")
    
    # Declare keep_snapshots at this scope since it's shared between subfunctions
    declare -g -A keep_snapshots=()
    
    [[ ${#snapshots[@]} -eq 0 ]] && return "$EXIT_SUCCESS"

    declare -A -r local retention_periods=(
        ["hourly"]="$RETENTION_HOURLY"
        ["daily"]="$RETENTION_DAILY"
        ["weekly"]="$RETENTION_WEEKLY"
        ["monthly"]="$RETENTION_MONTHLY"
        ["yearly"]="$RETENTION_YEARLY"
    )

    # Always keep the most recent snapshot
    keep_snapshots["${snapshots[0]}"]=1
    info "Keeping most recent snapshot: ${snapshots[0]}" "RETENTION"

    # Keep all snapshots in the current partial hour
    keep_current_partial_hour_snapshots "${snapshots[@]}"

    # Iterate over retention periods
    for period in "hourly" "daily" "weekly" "monthly" "yearly"; do
        declare -r -i local count="${retention_periods[$period]}"
        [[ -n "$count" && "$count" -gt 0 ]] || continue
        "apply_${period}_retention" "${snapshots[@]}"
    done

    # Delete snapshots not in keep_snapshots
    delete_non_retained_snapshots "${snapshots[@]}"

    # Log retention summary
    log_retention_summary
}

keep_current_partial_hour_snapshots() {
    declare -a -r local snapshots=("${@}")
    
    # Get current time components
    declare -r local current_time
    current_time=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
    
    # Calculate start of current hour
    declare -r local current_hour_start
    current_hour_start=$(date -u -d "${current_time}" '+%Y-%m-%dT%H:00:00Z')
    
    declare -r -i local current_hour_epoch
    current_hour_epoch=$(date -u -d "${current_hour_start}" '+%s')
    
    # Keep track of how many snapshots we're keeping from current hour
    declare -i local current_hour_count=0
    
    for snapshot in "${snapshots[@]}"; do
        declare -i local snap_time
        snap_time=$(get_snapshot_timestamp "$snapshot") || continue
        
        # If snapshot is from current partial hour, keep it
        if (( snap_time >= current_hour_epoch )); then
            keep_snapshots["$snapshot"]=1
            (( current_hour_count++ ))
            info "Keeping snapshot from current partial hour: $snapshot" "RETENTION"
        fi
    done
    
    debug "Kept ${current_hour_count} snapshots from current partial hour" "RETENTION"
}

apply_hourly_retention() {
    declare -a -r local snapshots=("${@}")
    declare -r -i count="$RETENTION_HOURLY"
    
    # Skip if hourly retention is disabled
    (( count > 0 )) || return 0
    
    # Get current time
    declare -r local current_time
    current_time=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
    
    # Start from previous complete hour
    for ((i=1; i<=count; i++)); do
        # Calculate target hour boundaries
        declare -r local target_hour_start
        target_hour_start=$(date -u -d "${current_time} ${i} hours ago" '+%Y-%m-%dT%H:00:00Z')
        
        declare -r -i period_start
        period_start=$(date -u -d "${target_hour_start}" '+%s')
        
        declare -r -i period_end
        period_end=$((period_start + 3599))  # 59 minutes 59 seconds
        
        # Find newest snapshot in this hour
        declare local latest_snapshot=""
        declare -i local latest_time=0
        
        for snapshot in "${snapshots[@]}"; do
            declare -i local snap_time
            snap_time=$(get_snapshot_timestamp "$snapshot") || continue
            
            if (( snap_time >= period_start && snap_time <= period_end )); then
                if (( snap_time > latest_time )); then
                    latest_snapshot="$snapshot"
                    latest_time="$snap_time"
                fi
            fi
        done
        
        # Keep the newest snapshot from this hour if found
        if [[ -n "$latest_snapshot" && -z "${keep_snapshots[$latest_snapshot]:-}" ]]; then
            keep_snapshots["$latest_snapshot"]=1
            info "Keeping hourly retention snapshot (hour -${i}): $latest_snapshot" "RETENTION"
            debug "Hour period: $(date -u -d @${period_start} '+%Y-%m-%d %H:%M:%S') to $(date -u -d @${period_end} '+%Y-%m-%d %H:%M:%S')" "RETENTION"
        fi
    done
}

apply_daily_retention() {
    declare -a -r local snapshots=("${@}")
    declare -r -i count="$RETENTION_DAILY"
    
    # Skip if daily retention is disabled
    (( count > 0 )) || return 0
    
    # Get current time
    declare -r local current_time
    current_time=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
    
    for ((i=1; i<=count; i++)); do
        # Calculate target day boundaries
        declare -r local target_date
        target_date=$(date -u -d "${current_time} ${i} days ago" '+%Y-%m-%d')
        
        declare -r -i period_start
        period_start=$(date -u -d "${target_date} 00:00:00" '+%s')
        
        declare -r -i period_end
        period_end=$(date -u -d "${target_date} 23:59:59" '+%s')
        
        # Find newest snapshot in this day
        declare local latest_snapshot=""
        declare -i local latest_time=0
        
        for snapshot in "${snapshots[@]}"; do
            declare -i local snap_time
            snap_time=$(get_snapshot_timestamp "$snapshot") || continue
            
            if (( snap_time >= period_start && snap_time <= period_end )); then
                if (( snap_time > latest_time )); then
                    latest_snapshot="$snapshot"
                    latest_time="$snap_time"
                fi
            fi
        done
        
        # Keep the newest snapshot from this day if found
        if [[ -n "$latest_snapshot" && -z "${keep_snapshots[$latest_snapshot]:-}" ]]; then
            keep_snapshots["$latest_snapshot"]=1
            info "Keeping daily retention snapshot (day -${i}): $latest_snapshot" "RETENTION"
            debug "Day period: $(date -u -d @${period_start} '+%Y-%m-%d') to $(date -u -d @${period_end} '+%Y-%m-%d')" "RETENTION"
        fi
    done
}

apply_weekly_retention() {
    declare -a -r local snapshots=("${@}")
    declare -r -i count="$RETENTION_WEEKLY"
    declare -r local category="RETENTION"
    
    # Skip if weekly retention is disabled
    (( count > 0 )) || return 0
    
    # Get current time
    declare -r local current_time
    current_time=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
    
    # Find current week's Monday
    declare -r local current_monday
    current_monday=$(date -u -d "${current_time} -$(date -u -d "${current_time}" '+%u') days" '+%Y-%m-%d')
    
    # Create temporary directory for atomic operations
    declare local temp_dir
    temp_dir="$(mktemp -d -t "${TEMP_FILE_PREFIX}-weekly.XXXXXXXXXX")" || {
        handle_error "ERROR" "Failed to create temporary directory for weekly retention" \
            "$EXIT_INVALID_VAR" "${category}"
        return "$EXIT_INVALID_VAR"
    }
    
    # Ensure cleanup of temporary directory
    trap 'rm -rf "${temp_dir}" 2>/dev/null || true; trap - RETURN' RETURN
    
    for ((i=0; i<count; i++)); do
        # Calculate target week boundaries (Monday 00:00:00 to Sunday 23:59:59)
        declare -r local target_monday
        target_monday=$(date -u -d "${current_monday} -$((i * 7)) days" '+%Y-%m-%d')
        
        declare -r -i period_start
        period_start=$(date -u -d "${target_monday} 00:00:00" '+%s')
        
        declare -r -i period_end
        period_end=$(date -u -d "${target_monday} +6 days 23:59:59" '+%s')
        
        # Find newest snapshot in this week
        declare local latest_snapshot=""
        declare -i local latest_time=0
        
        if ! (( DRY_RUN )); then
            for snapshot in "${snapshots[@]}"; do
                declare -i local snap_time
                if ! snap_time=$(retry "${RETRY_COUNT}" "${RETRY_DELAY}" \
                    get_snapshot_timestamp "${snapshot}"); then
                    debug "Failed to get timestamp for snapshot: ${snapshot}" "${category}"
                    continue
                fi
                
                if (( snap_time >= period_start && snap_time <= period_end )); then
                    if (( snap_time > latest_time )); then
                        latest_snapshot="${snapshot}"
                        latest_time="${snap_time}"
                    fi
                fi
            done
            
            # Keep the newest snapshot from this week if found
            if [[ -n "${latest_snapshot}" && -z "${keep_snapshots[${latest_snapshot}]:-}" ]]; then
                keep_snapshots["${latest_snapshot}"]=1
                info "Keeping weekly retention snapshot (week -${i}): ${latest_snapshot}" "${category}"
                debug "Week period: $(date -u -d @"${period_start}" '+%Y-%m-%d') to $(date -u -d @"${period_end}" '+%Y-%m-%d')" "${category}"
            fi
        else
            debug "DRY_RUN: Would process weekly retention for period: $(date -u -d @"${period_start}" '+%Y-%m-%d') to $(date -u -d @"${period_end}" '+%Y-%m-%d')" "${category}"
        fi
    done
    
    return "$EXIT_SUCCESS"
}

apply_monthly_retention() {
    declare -a -r local snapshots=("${@}")
    declare -r -i count="$RETENTION_MONTHLY"
    declare -r local category="RETENTION"
    
    # Skip if monthly retention is disabled
    (( count > 0 )) || return 0
    
    # Get current time
    declare -r local current_time
    current_time=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
    
    # Create temporary directory for atomic operations
    declare local temp_dir
    temp_dir="$(mktemp -d -t "${TEMP_FILE_PREFIX}-monthly.XXXXXXXXXX")" || {
        handle_error "ERROR" "Failed to create temporary directory for monthly retention" \
            "$EXIT_INVALID_VAR" "${category}"
        return "$EXIT_INVALID_VAR"
    }
    
    # Ensure cleanup of temporary directory
    trap 'rm -rf "${temp_dir}" 2>/dev/null || true; trap - RETURN' RETURN
    
    # Create lock file for atomic operations
    declare -r local lock_file="${temp_dir}/lock"
    
    for ((i=1; i<=count; i++)); do
        # Calculate target month boundaries
        declare -r local target_month_start
        target_month_start=$(date -u -d "${current_time} -${i} months" '+%Y-%m-01')
        
        declare -r -i period_start
        period_start=$(date -u -d "${target_month_start} 00:00:00" '+%s')
        
        # Calculate last day of the month
        declare -r local period_end_date
        period_end_date=$(date -u -d "${target_month_start} +1 month -1 day" '+%Y-%m-%d')
        
        declare -r -i period_end
        period_end=$(date -u -d "${period_end_date} 23:59:59" '+%s')
        
        # Find newest snapshot in this month
        declare local latest_snapshot=""
        declare -i local latest_time=0
        
        if ! (( DRY_RUN )); then
            # Use flock for atomic operations
            if ! retry "${RETRY_COUNT}" "${RETRY_DELAY}" \
                flock -w "${LOCK_TIMEOUT}" -x "${lock_file}" \
                bash -c '
                    declare -a snapshots=("${@}")
                    for snapshot in "${snapshots[@]}"; do
                        declare -i snap_time
                        if ! snap_time=$(retry "${RETRY_COUNT}" "${RETRY_DELAY}" \
                            get_snapshot_timestamp "${snapshot}"); then
                            continue
                        fi
                        
                        if (( snap_time >= period_start && snap_time <= period_end )); then
                            if (( snap_time > latest_time )); then
                                latest_snapshot="${snapshot}"
                                latest_time="${snap_time}"
                            fi
                        fi
                    done
                    printf "%s:%d" "${latest_snapshot}" "${latest_time}"
                ' -- "${snapshots[@]}" > "${temp_dir}/result"; then
                debug "Failed to process snapshots for month ${i}" "${category}"
                continue
            fi
            
            # Read results atomically
            if [[ -f "${temp_dir}/result" ]]; then
                IFS=: read -r latest_snapshot latest_time < "${temp_dir}/result"
            fi
            
            # Keep the newest snapshot from this month if found
            if [[ -n "${latest_snapshot}" && -z "${keep_snapshots[${latest_snapshot}]:-}" ]]; then
                keep_snapshots["${latest_snapshot}"]=1
                info "Keeping monthly retention snapshot (month -${i}): ${latest_snapshot}" "${category}"
                debug "Month period: $(date -u -d @"${period_start}" '+%Y-%m-%d') to $(date -u -d @"${period_end}" '+%Y-%m-%d')" "${category}"
                
                # Verify snapshot integrity
                if ! retry "${RETRY_COUNT}" "${RETRY_DELAY}" verify_snapshot "${latest_snapshot}"; then
                    warning "Monthly snapshot verification failed: ${latest_snapshot}" "${category}"
                    continue
                fi
            fi
        else
            debug "DRY_RUN: Would process monthly retention for period: $(date -u -d @"${period_start}" '+%Y-%m-%d') to $(date -u -d @"${period_end}" '+%Y-%m-%d')" "${category}"
        fi
    done
    
    return "$EXIT_SUCCESS"
}

apply_yearly_retention() {
    declare -a -r local snapshots=("${@}")
    declare -r -i count="$RETENTION_YEARLY"
    declare -r local category="RETENTION"
    
    # Skip if yearly retention is disabled
    (( count > 0 )) || return 0
    
    # Get current time
    declare -r local current_time
    current_time=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
    
    # Create temporary directory for atomic operations
    declare local temp_dir
    temp_dir="$(mktemp -d -t "${TEMP_FILE_PREFIX}-yearly.XXXXXXXXXX")" || {
        handle_error "ERROR" "Failed to create temporary directory for yearly retention" \
            "$EXIT_INVALID_VAR" "${category}"
        return "$EXIT_INVALID_VAR"
    }
    
    # Ensure cleanup of temporary directory
    trap 'rm -rf "${temp_dir}" 2>/dev/null || true; trap - RETURN' RETURN
    
    # Create lock file for atomic operations
    declare -r local lock_file="${temp_dir}/lock"
    
    for ((i=1; i<=count; i++)); do
        # Calculate target year boundaries
        declare -r local target_year
        target_year=$(date -u -d "${current_time} -${i} years" '+%Y')
        
        declare -r -i period_start
        period_start=$(date -u -d "${target_year}-01-01 00:00:00" '+%s')
        
        declare -r -i period_end
        period_end=$(date -u -d "${target_year}-12-31 23:59:59" '+%s')
        
        # Find newest snapshot in this year
        declare local latest_snapshot=""
        declare -i local latest_time=0
        
        if ! (( DRY_RUN )); then
            # Use flock for atomic operations
            if ! retry "${RETRY_COUNT}" "${RETRY_DELAY}" \
                flock -w "${LOCK_TIMEOUT}" -x "${lock_file}" \
                bash -c '
                    declare -a snapshots=("${@}")
                    for snapshot in "${snapshots[@]}"; do
                        declare -i snap_time
                        if ! snap_time=$(retry "${RETRY_COUNT}" "${RETRY_DELAY}" \
                            get_snapshot_timestamp "${snapshot}"); then
                            continue
                        fi
                        
                        if (( snap_time >= period_start && snap_time <= period_end )); then
                            if (( snap_time > latest_time )); then
                                latest_snapshot="${snapshot}"
                                latest_time="${snap_time}"
                            fi
                        fi
                    done
                    printf "%s:%d" "${latest_snapshot}" "${latest_time}"
                ' -- "${snapshots[@]}" > "${temp_dir}/result"; then
                debug "Failed to process snapshots for year ${i}" "${category}"
                continue
            fi
            
            # Read results atomically
            if [[ -f "${temp_dir}/result" ]]; then
                IFS=: read -r latest_snapshot latest_time < "${temp_dir}/result"
            fi
            
            # Keep the newest snapshot from this year if found
            if [[ -n "${latest_snapshot}" && -z "${keep_snapshots[${latest_snapshot}]:-}" ]]; then
                keep_snapshots["${latest_snapshot}"]=1
                info "Keeping yearly retention snapshot (year -${i}): ${latest_snapshot}" "${category}"
                debug "Year period: $(date -u -d @"${period_start}" '+%Y-%m-%d') to $(date -u -d @"${period_end}" '+%Y-%m-%d')" "${category}"
                
                # Verify snapshot integrity
                if ! retry "${RETRY_COUNT}" "${RETRY_DELAY}" verify_snapshot "${latest_snapshot}"; then
                    warning "Yearly snapshot verification failed: ${latest_snapshot}" "${category}"
                    continue
                fi
            fi
        else
            debug "DRY_RUN: Would process yearly retention for period: ${target_year}" "${category}"
        fi
    done
    
    return "$EXIT_SUCCESS"
}

delete_non_retained_snapshots() {
    declare -a -r local snapshots=("${@}")
    declare -a local deleted_list=()

    for snapshot in "${snapshots[@]}"; do
        if [[ -z "${keep_snapshots[$snapshot]:-}" ]]; then
            log "INFO" "DELETION" "Deleting snapshot: $snapshot" "RETENTION"
            if ! (( DRY_RUN )); then
                if retry "$RETRY_COUNT" "$RETRY_DELAY" btrfs subvolume delete "$snapshot"; then
                    deleted_list+=("$snapshot")
                    info "Deleted snapshot: $snapshot" "RETENTION"
                else
                    handle_error "ERROR" "Failed to delete snapshot '$snapshot'" "$EXIT_INVALID_VAR" "DELETION"
                    return "$EXIT_INVALID_VAR"
                fi
            else
                info "DRY_RUN enabled: Skipping deletion of snapshot: $snapshot" "RETENTION"
            fi
        fi
    done

    # Store deleted list for summary logging
    DELETED_SNAPSHOTS=("${deleted_list[@]}")
}

# Log retention summary
log_retention_summary() {
    declare -r -i retained_count=${#keep_snapshots[@]}
    declare -r -i deleted_count=${#DELETED_SNAPSHOTS[@]}
    info "Retention process completed. Snapshots retained: $retained_count. Snapshots deleted: $deleted_count." "RETENTION"

    # Log lists of retained snapshots
    if (( retained_count > 0 )); then
        info "Snapshots retained:" "RETENTION"
        for s in "${!keep_snapshots[@]}"; do
            info "  - $s" "RETENTION"
        done
    fi

    # Log lists of deleted snapshots
    if (( deleted_count > 0 )); then
        info "Snapshots deleted:" "RETENTION"
        for s in "${DELETED_SNAPSHOTS[@]}"; do
            info "  - $s" "RETENTION"
        done
    fi
}

################################
#     Metadata Management       #
################################
# Initialize metadata
initialize_metadata_variables() {
    # Basic metadata
    declare -r local METADATA_VERSION="1.0"

    # Snapshot metadata
    declare -r local snapshot_uuid
    snapshot_uuid=$(uuidgen 2>/dev/null || printf "unknown")
    declare -r local snapshot_timestamp
    snapshot_timestamp=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
    declare -r local snapshot_size
    snapshot_size=$(btrfs filesystem df "$SRC_DIR" 2>/dev/null | awk '/Data,single/ {print $3}' || printf "unknown")

    # System metadata
    declare -r local system_hostname
    system_hostname=$(hostname -f 2>/dev/null || hostname || printf "unknown")
    declare -r local system_kernel
    system_kernel=$(uname -r)
    declare -r local system_platform
    system_platform=$(uname -m)

    # Filesystem metadata
    declare -r local fs_uuid
    fs_uuid=$(btrfs filesystem show "$SRC_DIR" | grep -oP 'uuid: \K[a-f0-9-]+' || printf "unknown")
    declare -r local fs_label
    fs_label=$(btrfs filesystem label "$SRC_DIR" 2>/dev/null || printf "unknown")
    declare -r local fs_type
    fs_type=$(df -T "$SRC_DIR" | awk 'NR==2 {print $2}')

    # Backup metadata
    declare -r -l local backup_type
    backup_type=$([[ "${FORCE_FULL:-0}" -eq 1 ]] && printf "full" || printf "incremental")
    declare -r -l local backup_compression
    backup_compression="${COMPRESSION_LEVEL:-zstd:3}"
    declare -r -l local backup_source_path
    backup_source_path="$SRC_DIR"
    declare -r -l local backup_destination_path
    backup_destination_path="$DST_DIR"

    # Retention metadata
    declare -r -i local retention_policy_hourly
    retention_policy_hourly="${RETENTION_HOURLY:-0}"
    declare -r -i local retention_policy_daily
    retention_policy_daily="${RETENTION_DAILY:-0}"
    declare -r -i local retention_policy_weekly
    retention_policy_weekly="${RETENTION_WEEKLY:-0}"
    declare -r -i local retention_policy_monthly
    retention_policy_monthly="${RETENTION_MONTHLY:-0}"
    declare -r -i local retention_policy_yearly
    retention_policy_yearly="${RETENTION_YEARLY:-0}"

    # Status metadata
    declare -r local status_verified="false"
    declare -r local status_compressed="false"
    declare -r local status_encrypted="false"

    # Error handling metadata
    declare -r local last_error=""
    declare -i -r local error_count=0
    declare -i -r local warning_count=0

    # Make all metadata readonly
    declare -r -l local snapshot_uuid="${snapshot_uuid}"
    declare -r -l local snapshot_timestamp="${snapshot_timestamp}"
    declare -r -l local snapshot_size="${snapshot_size}"
    declare -r -l system_hostname="${system_hostname}"
    declare -r -l system_kernel="${system_kernel}"
    declare -r -l system_platform="${system_platform}"
    declare -r -l fs_uuid="${fs_uuid}"
    declare -r -l fs_label="${fs_label}"
    declare -r -l fs_type="${fs_type}"
    declare -r -l backup_type="${backup_type}"
    declare -r -l backup_compression="${backup_compression}"
    declare -r -l backup_source_path="${backup_source_path}"
    declare -r -l backup_destination_path="${backup_destination_path}"
    declare -r -l retention_policy_hourly="${retention_policy_hourly}"
    declare -r -l retention_policy_daily="${retention_policy_daily}"
    declare -r -l retention_policy_weekly="${retention_policy_weekly}"
    declare -r -l retention_policy_monthly="${retention_policy_monthly}"
    declare -r -l retention_policy_yearly="${retention_policy_yearly}"
}

# Set snapshot properties
set_snapshot_properties() {
    declare -r local snapshot_path="$1"
    declare -r local do_full_snapshot="$2"
    declare -r local last_snapshot="$3"
    
    # Add input validation
    if [[ ! -d "$snapshot_path" ]]; then
        handle_error "ERROR" "Invalid snapshot path: $snapshot_path" "$EXIT_INVALID_VAR" "METADATA"
        return "$EXIT_INVALID_VAR"
    fi
    
    if [[ -n "$last_snapshot" ]] && [[ ! -d "$last_snapshot" ]]; then
        handle_error "ERROR" "Invalid last snapshot path: $last_snapshot" "$EXIT_INVALID_VAR" "METADATA"
        return "$EXIT_INVALID_VAR"
    fi

    if ! (( DRY_RUN )); then
        # Basic properties
        retry "$RETRY_COUNT" "$RETRY_DELAY" btrfs property set "$snapshot_path" ro true || {
            handle_error "ERROR" "Failed to set read-only property" "$EXIT_INVALID_VAR" "METADATA"
            return "$EXIT_INVALID_VAR"
        }

        # Metadata properties with validation
        declare -a local metadata_commands=(
            "user.snapshot.uuid=${snapshot_uuid}"
            "user.snapshot.timestamp=$snapshot_timestamp"
            "user.snapshot.source=$SRC_DIR"
            "user.snapshot.type=$([[ $do_full_snapshot -eq 1 ]] && printf 'full' || printf 'incremental')"
            "user.snapshot.parent=$([[ $do_full_snapshot -eq 0 && -n "$last_snapshot" ]] && printf '%s' "$last_snapshot" || printf 'none')"
            "user.snapshot.compression=$COMPRESSION_LEVEL"
        )

        for cmd in "${metadata_commands[@]}"; do
            declare local prop_name prop_value
            read -r prop_name prop_value <<< "$cmd"
            retry "$RETRY_COUNT" "$RETRY_DELAY" btrfs property set "$snapshot_path" "$prop_name" "$prop_value" || {
                handle_error "WARNING" "Failed to set property $prop_name for: $snapshot_path" 0 "METADATA"
            }
        done
    else
        info "DRY_RUN enabled: Would set properties for snapshot: $snapshot_path" "METADATA"
    fi

    return "$EXIT_SUCCESS"
}

################################
#    Compression Verification   #
################################
verify_compression() {
    declare -r local dir="$1"
    
    # Verify input directory exists
    if [[ ! -d "${dir}" ]]; then
        handle_error "ERROR" "Directory does not exist: ${dir}" \
            "$EXIT_INVALID_VAR" "COMPRESS"
        return "$EXIT_INVALID_VAR"
    fi

    # Define supported compression algorithms
    declare -r -A local SUPPORTED_ALGORITHMS=(
        ["zstd"]="zstd compression"
        ["zlib"]="zlib compression"
        ["lzo"]="lzo compression"
    )

    # Extract algorithm and level from COMPRESSION_LEVEL
    declare local algorithm level
    if [[ "${COMPRESSION_LEVEL}" =~ ^([a-z]+):([0-9]+)$ ]]; then
        algorithm="${BASH_REMATCH[1]}"
        level="${BASH_REMATCH[2]}"
    else
        handle_error "ERROR" \
            "Invalid compression format: ${COMPRESSION_LEVEL}, expected <algorithm>:<level>" \
            "$EXIT_INVALID_VAR" "COMPRESS"
        return "$EXIT_INVALID_VAR"
    fi

    # Verify algorithm is supported
    if [[ -z "${SUPPORTED_ALGORITHMS[${algorithm}]:-}" ]]; then
        handle_error "ERROR" \
            "Unsupported compression algorithm: ${algorithm}. Supported: ${!SUPPORTED_ALGORITHMS[*]}" \
            "$EXIT_INVALID_VAR" "COMPRESS"
        return "$EXIT_INVALID_VAR"
    fi

    # Verify compression level is within valid range
    declare -r -i local min_level=1
    declare -r -i local max_level
    case "${algorithm}" in
        zstd)
            max_level=15
            ;;
        zlib)
            max_level=9
            ;;
        lzo)
            max_level=9
            ;;
    esac

    if (( level < min_level || level > max_level )); then
        handle_error "ERROR" \
            "Invalid compression level for ${algorithm}: ${level}. Valid range: ${min_level}-${max_level}" \
            "$EXIT_INVALID_VAR" "COMPRESS"
        return "$EXIT_INVALID_VAR"
    fi

    # Check if filesystem supports compression
    if ! retry "${RETRY_COUNT}" "${RETRY_DELAY}" \
        btrfs filesystem df "${dir}" | grep -q "Data,single"; then
        handle_error "ERROR" \
            "Filesystem does not support compression: ${dir}" \
            "$EXIT_INVALID_VAR" "COMPRESS"
        return "$EXIT_INVALID_VAR"
    fi

    # Verify kernel support for the chosen algorithm
    if ! retry "${RETRY_COUNT}" "${RETRY_DELAY}" \
        grep -q "${algorithm}" /proc/crypto 2>/dev/null; then
        handle_error "ERROR" \
            "Kernel does not support ${algorithm} compression" \
            "$EXIT_INVALID_VAR" "COMPRESS"
        return "$EXIT_INVALID_VAR"
    fi

    # Create temporary file to test compression
    if ! (( DRY_RUN )); then
        declare local temp_test_file
        temp_test_file="$(mktemp -p "${dir}" -t "${TEMP_FILE_PREFIX}.XXXXXXXXXX")" || {
            handle_error "ERROR" \
                "Failed to create temporary test file in ${dir}" \
                "$EXIT_INVALID_VAR" "COMPRESS"
            return "$EXIT_INVALID_VAR"
        }

        # Ensure cleanup of temporary test file
        trap 'rm -f "${temp_test_file}" 2>/dev/null || true; trap - RETURN' RETURN

        # Test compression by setting attribute
        if ! retry "${RETRY_COUNT}" "${RETRY_DELAY}" \
            btrfs property set "${temp_test_file}" compression "${algorithm}:${level}"; then
            handle_error "ERROR" \
                "Failed to set compression on test file" \
                "$EXIT_INVALID_VAR" "COMPRESS"
            return "$EXIT_INVALID_VAR"
        fi

        debug "Successfully verified compression: ${algorithm}:${level}" "COMPRESS"
    else
        debug "DRY_RUN: Would verify compression: ${algorithm}:${level}" "COMPRESS"
    fi

    return "$EXIT_SUCCESS"
}

################################
#     Argument Parsing          #
################################
parse_arguments() {
    # Declare local variables as readonly where possible
    declare -r -A local VALID_ARGS=(
        ["--config"]="Specify config file path"
        ["--debug"]="Enable debug logging"
        ["--dry-run"]="Show what would be done"
        ["--help"]="Show help message"
        ["--version"]="Show version information"
    )

    # Create temporary array for processed arguments
    declare -a local processed_args=()

    while [[ $# -gt 0 ]]; do
        declare local arg="$1"
        case "${arg}" in
            --config=*)
                declare local config_path
                config_path="${arg#*=}"
                if [[ -z "${config_path}" ]]; then
                    handle_error "ERROR" "Config path cannot be empty" \
                        "$EXIT_INVALID_ARGUMENT" "ARGS"
                    return "$EXIT_INVALID_ARGUMENT"
                fi
                # Store processed config path
                declare -g CONFIG_FILE
                CONFIG_FILE="$(readlink -f "${config_path}")" || {
                    handle_error "ERROR" "Invalid config path: ${config_path}" \
                        "$EXIT_INVALID_ARGUMENT" "ARGS"
                    return "$EXIT_INVALID_ARGUMENT"
                }
                ;;
            --debug)
                declare -g BACKUP_DEBUG=1
                debug "Debug mode enabled" "ARGS"
                ;;
            --dry-run)
                declare -g DRY_RUN=1
                info "Dry run mode enabled" "ARGS"
                ;;
            --help|-h)
                show_help
                return "$EXIT_SUCCESS"
                ;;
            --version|-v)
                printf "yabb version %s\n" "${SCRIPT_VERSION}"
                return "$EXIT_SUCCESS"
                ;;
            *)
                # Check if the argument starts with --
                if [[ "${arg}" == --* ]]; then
                    handle_error "ERROR" "Unknown argument: ${arg}" \
                        "$EXIT_INVALID_ARGUMENT" "ARGS"
                    return "$EXIT_INVALID_ARGUMENT"
                fi
                # Store non-option arguments
                processed_args+=("${arg}")
                ;;
        esac
        shift
    done

    # Verify config file exists and is readable
    if [[ ! -f "${CONFIG_FILE}" ]]; then
        handle_error "ERROR" "Config file not found: ${CONFIG_FILE}" \
            "$EXIT_CONFIG_MISSING" "ARGS"
        return "$EXIT_CONFIG_MISSING"
    fi

    if [[ ! -r "${CONFIG_FILE}" ]]; then
        handle_error "ERROR" "Config file not readable: ${CONFIG_FILE}" \
            "$EXIT_CONFIG_MISSING" "ARGS"
        return "$EXIT_CONFIG_MISSING"
    fi

    # Source config file with retry mechanism
    if ! retry "${RETRY_COUNT}" "${RETRY_DELAY}" source "${CONFIG_FILE}"; then
        handle_error "ERROR" "Failed to source config file: ${CONFIG_FILE}" \
            "$EXIT_CONFIG_MISSING" "ARGS"
        return "$EXIT_CONFIG_MISSING"
    fi

    # Set default values for optional arguments if not set
    declare -g BACKUP_DEBUG="${BACKUP_DEBUG:-0}"
    declare -g DRY_RUN="${DRY_RUN:-0}"

    # Log argument parsing completion in debug mode
    debug "Arguments parsed successfully: CONFIG_FILE=${CONFIG_FILE}, BACKUP_DEBUG=${BACKUP_DEBUG}, DRY_RUN=${DRY_RUN}" "ARGS"
    
    return "$EXIT_SUCCESS"
}

################################
#     Help Text Display         #
################################
show_help() {
    declare -r local category="HELP"
    
    # Create temporary file for help text
    declare local temp_help_file
    temp_help_file="$(mktemp -t "${TEMP_FILE_PREFIX}-help.XXXXXXXXXX")" || {
        handle_error "ERROR" "Failed to create temporary help file" \
            "$EXIT_INVALID_VAR" "${category}"
        return "$EXIT_INVALID_VAR"
    }

    # Ensure cleanup of temporary files
    trap 'rm -f "${temp_help_file}" 2>/dev/null || true; trap - RETURN' \
        RETURN SIGINT SIGTERM SIGHUP ERR EXIT

    # Get script name safely
    declare -r local script_name
    script_name="$(basename "${0}")" || {
        handle_error "ERROR" "Failed to get script name" \
            "$EXIT_INVALID_VAR" "${category}"
        return "$EXIT_INVALID_VAR"
    }

    # Define help sections with associative arrays
    declare -r -A local RETENTION_SETTINGS=(
        ["RETENTION_HOURLY"]="Number of hourly snapshots to keep"
        ["RETENTION_DAILY"]="Number of daily snapshots to keep"
        ["RETENTION_WEEKLY"]="Number of weekly snapshots to keep"
        ["RETENTION_MONTHLY"]="Number of monthly snapshots to keep"
        ["RETENTION_YEARLY"]="Number of yearly snapshots to keep"
    )

    declare -r -A local CONFIG_SETTINGS=(
        ["SRC_DIR"]="Source directory to backup"
        ["DST_DIR"]="Destination directory for backups"
        ["SNAPSHOT_DIR"]="Directory to store snapshots"
        ["COMPRESSION_LEVEL"]="Compression algorithm and level (e.g., zstd:3)"
    )

    declare -r -A local EXIT_CODES=(
        ["0"]="Success"
        ["1"]="No changes detected"  # Add this line
        ["2"]="Invalid argument"
        ["3"]="Configuration missing"
        ["4"]="Missing variable"
        ["5"]="Invalid variable"
        ["6"]="Prerequisites missing"
        ["7"]="Invalid directory"
    )

    # Generate help text atomically
    if ! retry "${RETRY_COUNT}" "${RETRY_DELAY}" \
        printf '%s\n' "Yet Another BTRFS Backup (YABB) - Version ${SCRIPT_VERSION}" > "${temp_help_file}"; then
        handle_error "ERROR" "Failed to write help header" \
            "$EXIT_INVALID_VAR" "${category}"
        return "$EXIT_INVALID_VAR"
    fi

    {
        printf '\nDescription:\n'
        printf '  Efficient BTRFS snapshot management and backup utility with incremental\n'
        printf '  backup support, compression, and retention policy management.\n'

        printf '\nUsage:\n'
        printf '  %s [OPTIONS]\n' "${script_name}"

        printf '\nOptions:\n'
        printf '  --config=PATH    Specify config file path (default: /etc/yabb.conf)\n'
        printf '  --debug          Enable debug logging\n'
        printf '  --dry-run        Show what would be done without making changes\n'
        printf '  --help, -h       Show this help message\n'
        printf '  --version, -v    Show version information\n'

        printf '\nRequirements:\n'
        printf '  - BTRFS filesystem with compression support\n'
        printf '  - Root privileges\n'
        printf '  - btrfs-progs package\n'
        printf '  - Standard Unix utilities (date, find, grep, awk)\n'

        printf '\nConfiguration (yabb.conf):\n'
        for key in "${!CONFIG_SETTINGS[@]}"; do
            printf '  %-16s %s\n' "${key}" "${CONFIG_SETTINGS[${key}]}"
        done

        printf '\nRetention Settings:\n'
        for key in "${!RETENTION_SETTINGS[@]}"; do
            printf '  %-16s %s\n' "${key}" "${RETENTION_SETTINGS[${key}]}"
        done

        printf '\nExit Codes:\n'
        for code in "${!EXIT_CODES[@]}"; do
            printf '  %-2s  %s\n' "${code}" "${EXIT_CODES[${code}]}"
        done

        printf '\nExamples:\n'
        printf '  # Run with default configuration\n'
        printf '  %s\n' "${script_name}"
        printf '\n  # Use custom config file\n'
        printf '  %s --config=/path/to/custom.conf\n' "${script_name}"
        printf '\n  # Dry run to see what would happen\n'
        printf '  %s --dry-run\n' "${script_name}"

        printf '\nLogging:\n'
        printf '  - Uses systemd journal if available\n'
        printf '  - Falls back to standard error output\n'
        printf '  - Debug logging available with --debug\n'

        printf '\nFor detailed documentation, visit:\n'
        printf '  https://github.com/your-repo/yabb/docs\n'
        printf '\nReport bugs to: your-email@example.com\n'
    } >> "${temp_help_file}" || {
        handle_error "ERROR" "Failed to write help content" \
            "$EXIT_INVALID_VAR" "${category}"
        return "$EXIT_INVALID_VAR"
    }

    # Display help text atomically
    if ! (( DRY_RUN )); then
        if ! retry "${RETRY_COUNT}" "${RETRY_DELAY}" cat "${temp_help_file}"; then
            handle_error "ERROR" "Failed to display help text" \
                "$EXIT_INVALID_VAR" "${category}"
            return "$EXIT_INVALID_VAR"
        fi
    else
        debug "DRY_RUN: Would display help text from: ${temp_help_file}" "${category}"
    fi

    return "$EXIT_SUCCESS"
}

################################
#     Change Detection          #
################################
detect_changes() {
    declare -r local parent_snapshot="$1"
    declare -r local current_snapshot="$2"

    # Validate input parameters
    if [[ ! -d "${parent_snapshot}" ]]; then
        handle_error "ERROR" "Parent snapshot does not exist: ${parent_snapshot}" \
            "$EXIT_INVALID_VAR" "CHANGES"
        return "$EXIT_INVALID_VAR"
    fi

    if [[ ! -d "${current_snapshot}" ]]; then
        handle_error "ERROR" "Current snapshot does not exist: ${current_snapshot}" \
            "$EXIT_INVALID_VAR" "CHANGES"
        return "$EXIT_INVALID_VAR"
    fi

    # Create temporary file for btrfs send output
    declare local temp_send_file
    temp_send_file="$(mktemp -t "${TEMP_SEND_PREFIX}.XXXXXXXXXX")" || {
        handle_error "ERROR" "Failed to create temporary send file" \
            "$EXIT_INVALID_VAR" "CHANGES"
        return "$EXIT_INVALID_VAR"
    }

    # Ensure cleanup of temporary files
    trap 'rm -f "${temp_send_file}" 2>/dev/null || true; trap - RETURN' RETURN

    if ! (( DRY_RUN )); then
        debug "Comparing snapshots: ${parent_snapshot} -> ${current_snapshot}" "CHANGES"

        # Try to generate incremental send stream with retry
        if ! retry "${RETRY_COUNT}" "${RETRY_DELAY}" \
            btrfs send --quiet -p "${parent_snapshot}" "${current_snapshot}" \
            > "${temp_send_file}" 2>/dev/null; then
            
            # Check if failure was due to no changes
            if [[ -f "${temp_send_file}" ]] && \
               [[ ! -s "${temp_send_file}" ]]; then
                debug "No changes detected between snapshots" "CHANGES"
                return "$EXIT_NO_CHANGES"
            fi

            # Real error occurred
            handle_error "ERROR" \
                "Failed to compare snapshots: ${parent_snapshot} -> ${current_snapshot}" \
                "$EXIT_INVALID_VAR" "CHANGES"
            return "$EXIT_INVALID_VAR"
        fi

        # Check if send stream contains actual changes
        if [[ ! -s "${temp_send_file}" ]]; then
            debug "No changes detected between snapshots" "CHANGES"
            return "$EXIT_NO_CHANGES"
        fi

        # Verify send stream integrity
        if ! retry "${RETRY_COUNT}" "${RETRY_DELAY}" \
            btrfs receive --quiet --dump "${temp_send_file}" >/dev/null 2>&1; then
            handle_error "ERROR" \
                "Invalid send stream between snapshots" \
                "$EXIT_INVALID_VAR" "CHANGES"
            return "$EXIT_INVALID_VAR"
        fi

        # Calculate and log change statistics if in debug mode
        if [[ "${BACKUP_DEBUG:-0}" == "1" ]]; then
            declare -r -i local stream_size
            stream_size="$(stat -c %s "${temp_send_file}")"
            
            declare -r -i local change_count
            change_count="$(btrfs receive --quiet --dump "${temp_send_file}" 2>/dev/null | \
                grep -c "^[[:space:]]*path" || true)"
            
            debug "Detected ${change_count} changes (${stream_size} bytes)" "CHANGES"
        fi

        info "Changes detected between snapshots" "CHANGES"
        return 0
    else
        debug "DRY_RUN: Would check for changes between: ${parent_snapshot} -> ${current_snapshot}" "CHANGES"
        # Return success in dry-run mode to allow testing
        return 0
    fi
}

################################
#     Error Handling            #
################################
handle_error() {
    declare -r local level="$1"
    declare -r local message="$2"
    declare -r -i local exit_code="${3:-0}"
    declare -r local category="${4:-GENERAL}"

    # Validate input parameters
    if [[ ! "${level}" =~ ^(ERROR|WARNING|INFO|DEBUG)$ ]]; then
        printf "Invalid error level: %s\n" "${level}" >&2
        return "$EXIT_INVALID_VAR"
    fi

    # Create temporary lock file for atomic operations
    declare local temp_lock_file
    temp_lock_file="$(mktemp -t "${TEMP_LOCK_PREFIX}-error.XXXXXXXXXX")" || {
        log "WARNING" "LOCK" "Failed to create temporary error lock file"
        return "$EXIT_INVALID_VAR"
    }

    # Ensure cleanup of temporary files
    trap 'rm -f "${temp_lock_file}" 2>/dev/null || true; trap - RETURN' RETURN

    # Increment error counters atomically using lock file
    if [[ -n "${ERROR_COUNT_LOCK:-}" ]]; then
        # Create lock directory if it doesn't exist
        declare local lock_dir
        lock_dir="$(dirname "${ERROR_COUNT_LOCK}")"
        if ! (( DRY_RUN )); then
            if [[ ! -d "${lock_dir}" ]]; then
                if ! retry "${RETRY_COUNT}" "${RETRY_DELAY}" mkdir -p "${lock_dir}"; then
                    log "WARNING" "LOCK" "Failed to create lock directory: ${lock_dir}"
                fi
            fi

            # Use flock with retry for atomic counter increment
            if ! retry "${RETRY_COUNT}" "${RETRY_DELAY}" \
                flock -w "${LOCK_TIMEOUT:-300}" "${temp_lock_file}" \
                bash -c "
                    declare -A counts=([ERROR]=${ERROR_COUNTS[ERROR]} [WARNING]=${ERROR_COUNTS[WARNING]})
                    case '${level}' in
                        ERROR)   (( counts[ERROR]++ ))   ;;
                        WARNING) (( counts[WARNING]++ )) ;;
                    esac
                    declare -p counts > '${ERROR_COUNT_LOCK}'
                "; then
                log "WARNING" "LOCK" "Failed to update error counts"
            fi
        else
            debug "DRY_RUN: Would increment ${level} counter" "ERROR"
        fi
    fi

    # Log the error using the existing logging facility
    log "${level}" "${category}" "${message}"

    # Handle different error levels
    case "${level}" in
        ERROR)
            if (( exit_code != 0 )); then
                if ! (( DRY_RUN )); then
                    # Attempt to cleanup any temporary resources with retry
                    if ! retry "${RETRY_COUNT}" "${RETRY_DELAY}" cleanup_resources; then
                        log "WARNING" "CLEANUP" "Failed to cleanup resources after error"
                    fi
                else
                    debug "DRY_RUN: Would perform error cleanup" "ERROR"
                fi
            fi
            ;;
        WARNING)
            debug "Warning encountered: ${message}" "ERROR"
            ;;
    esac

    # Special handling for debugging with enhanced stack trace
    if [[ "${BACKUP_DEBUG:-0}" == "1" ]]; then
        declare -r local stack_size="${#FUNCNAME[@]}"
        declare -r local current_func="${FUNCNAME[1]:-main}"
        declare -r local current_line="${BASH_LINENO[0]:-unknown}"
        
        debug "Error occurred in ${current_func}(), line ${current_line}" "ERROR"
        
        if (( stack_size > 2 )); then
            declare -a -r local stack_trace=()
            for ((i=1; i<stack_size-1; i++)); do
                stack_trace+=("  ${FUNCNAME[i]}() called from ${FUNCNAME[i+1]:-main}(), line ${BASH_LINENO[i]:-unknown}")
            done
            
            debug "Call stack:" "ERROR"
            printf '%s\n' "${stack_trace[@]}" | while IFS= read -r line; do
                debug "${line}" "ERROR"
            done
        fi
    fi

    # Enhanced retry handling for transient errors
    if [[ "${level}" == "ERROR" ]] && (( exit_code != 0 )); then
        declare -r -A local RETRYABLE_CATEGORIES=(
            [LOCK]="Lock acquisition failures"
            [IO]="Input/Output operations"
            [NETWORK]="Network operations"
            [BTRFS]="BTRFS filesystem operations"
        )

        if [[ -n "${RETRYABLE_CATEGORIES[${category}]:-}" ]]; then
            debug "Error in retryable category: ${category} (${RETRYABLE_CATEGORIES[${category}]})" "ERROR"
        else
            debug "Error in non-retryable category: ${category}" "ERROR"
        fi
    fi

    # Return appropriate exit code
    if (( exit_code != 0 )); then
        return "$exit_code"
    fi
    return "$EXIT_SUCCESS"
}


################################
#     Path Sanitization         #
################################
sanitize_path() {
    declare -r local input_path="$1"
    declare -r local category="${2:-PATH}"

    # Validate input
    if [[ -z "${input_path}" ]]; then
        handle_error "ERROR" "Empty path provided" \
            "$EXIT_INVALID_VAR" "${category}"
        return "$EXIT_INVALID_VAR"
    fi

    # Create temporary directory for atomic operations
    declare local temp_dir
    temp_dir="$(mktemp -d -t "${TEMP_FILE_PREFIX}-path.XXXXXXXXXX")" || {
        handle_error "ERROR" "Failed to create temporary directory" \
            "$EXIT_INVALID_VAR" "${category}"
        return "$EXIT_INVALID_VAR"
    }

    # Create temporary file within the directory
    declare local temp_path_file
    temp_path_file="${temp_dir}/path" || {
        rm -rf "${temp_dir}" 2>/dev/null || true
        handle_error "ERROR" "Failed to create temporary path file" \
            "$EXIT_INVALID_VAR" "${category}"
        return "$EXIT_INVALID_VAR"
    }

    # Ensure cleanup of temporary files and directory
    trap 'rm -rf "${temp_dir}" 2>/dev/null || true; trap - RETURN' RETURN SIGINT SIGTERM SIGHUP

    # Remove trailing slashes with parameter expansion
    declare local cleaned_path
    cleaned_path="${input_path%/}"

    # Handle special cases with associative array
    declare -r -A local INVALID_PATHS=(
        [""]="Invalid empty path after cleaning"
        ["."]="Invalid relative path: ."
        [".."]="Invalid relative path: .."
    )

    if [[ -n "${INVALID_PATHS[${cleaned_path}]:-}" ]]; then
        handle_error "ERROR" "${INVALID_PATHS[${cleaned_path}]}" \
            "$EXIT_INVALID_VAR" "${category}"
        return "$EXIT_INVALID_VAR"
    fi

    if ! (( DRY_RUN )); then
        # Convert relative paths to absolute with retry
        if [[ "${cleaned_path}" != /* ]]; then
            declare local pwd_path
            if ! pwd_path="$(retry "${RETRY_COUNT}" "${RETRY_DELAY}" pwd)"; then
                handle_error "ERROR" "Failed to get current directory" \
                    "$EXIT_INVALID_VAR" "${category}"
                return "$EXIT_INVALID_VAR"
            fi
            cleaned_path="${pwd_path}/${cleaned_path}"
        fi

        # Resolve symbolic links and normalize path with retry
        declare local resolved_path
        if ! resolved_path="$(retry "${RETRY_COUNT}" "${RETRY_DELAY}" \
            readlink -f "${cleaned_path}" 2>/dev/null)"; then
            handle_error "ERROR" "Failed to resolve path: ${cleaned_path}" \
                "$EXIT_INVALID_VAR" "${category}"
            return "$EXIT_INVALID_VAR"
        fi

        # Define invalid patterns with descriptions
        declare -r -A local INVALID_PATTERNS=(
            ['/\.\.']='Parent directory reference'
            ['/\./']='Current directory reference'
            ['/[^/]*/\.\.']='Parent directory after component'
            ['^[^/]']='Non-absolute path'
            ['//']='Double slash'
        )

        # Check for invalid patterns
        for pattern in "${!INVALID_PATTERNS[@]}"; do
            if [[ "${resolved_path}" =~ ${pattern} ]]; then
                handle_error "ERROR" \
                    "Path contains ${INVALID_PATTERNS[${pattern}]}: ${resolved_path}" \
                    "$EXIT_INVALID_VAR" "${category}"
                return "$EXIT_INVALID_VAR"
            fi
        done

        # Verify path length
        declare -r -i local MAX_PATH_LENGTH=4096
        if (( ${#resolved_path} > MAX_PATH_LENGTH )); then
            handle_error "ERROR" \
                "Path exceeds maximum length (${MAX_PATH_LENGTH}): ${resolved_path}" \
                "$EXIT_INVALID_VAR" "${category}"
            return "$EXIT_INVALID_VAR"
        fi

        # Write resolved path atomically using temporary file
        if ! retry "${RETRY_COUNT}" "${RETRY_DELAY}" \
            printf '%s' "${resolved_path}" > "${temp_path_file}.tmp"; then
            handle_error "ERROR" "Failed to write resolved path" \
                "$EXIT_INVALID_VAR" "${category}"
            return "$EXIT_INVALID_VAR"
        fi

        # Atomic move of temporary file
        if ! retry "${RETRY_COUNT}" "${RETRY_DELAY}" \
            mv -f "${temp_path_file}.tmp" "${temp_path_file}"; then
            handle_error "ERROR" "Failed to move temporary path file" \
                "$EXIT_INVALID_VAR" "${category}"
            return "$EXIT_INVALID_VAR"
        fi

        # Read path atomically with retry
        if ! resolved_path="$(retry "${RETRY_COUNT}" "${RETRY_DELAY}" \
            cat "${temp_path_file}")"; then
            handle_error "ERROR" "Failed to read resolved path" \
                "$EXIT_INVALID_VAR" "${category}"
            return "$EXIT_INVALID_VAR"
        fi

        debug "Sanitized path: ${input_path} -> ${resolved_path}" "${category}"
        printf '%s' "${resolved_path}"
    else
        debug "DRY_RUN: Would sanitize path: ${input_path}" "${category}"
        printf '%s' "${cleaned_path}"
    fi

    return "$EXIT_SUCCESS"
}



################################
#     Path Validation           #
################################
validate_path() {
    declare -r local path="$1"
    declare -r local type="${2:-any}"        # directory, file, or any
    declare -r local must_exist="${3:-true}" # true or false
    declare -r local category="${4:-PATH}"

    # Create temporary directory for atomic operations
    declare local temp_dir
    temp_dir="$(mktemp -d -t "${TEMP_FILE_PREFIX}-validate.XXXXXXXXXX")" || {
        handle_error "ERROR" "Failed to create temporary validation directory" \
            "$EXIT_INVALID_VAR" "${category}"
        return "$EXIT_INVALID_VAR"
    }

    # Ensure cleanup of temporary directory and its contents
    trap 'rm -rf "${temp_dir}" 2>/dev/null || true; trap - RETURN' RETURN SIGINT SIGTERM SIGHUP

    # Validate input parameters using associative array
    declare -r -A local VALID_TYPES=(
        ["directory"]="Directory path"
        ["file"]="File path"
        ["any"]="Path of any type"
    )

    if [[ -z "${VALID_TYPES[${type}]:-}" ]]; then
        handle_error "ERROR" \
            "Invalid path type: ${type}. Valid types: ${!VALID_TYPES[*]}" \
            "$EXIT_INVALID_VAR" "${category}"
        return "$EXIT_INVALID_VAR"
    fi

    # Sanitize the path first using existing function with retry
    declare local sanitized_path
    if ! sanitized_path="$(retry "${RETRY_COUNT}" "${RETRY_DELAY}" \
        sanitize_path "${path}" "${category}")"; then
        return "$EXIT_INVALID_VAR"
    fi

    if ! (( DRY_RUN )); then
        # Create lock file for atomic operations
        declare local lock_file
        lock_file="${temp_dir}/validate.lock"

        # Use flock for atomic operations
        if ! retry "${RETRY_COUNT}" "${RETRY_DELAY}" \
            flock -w "${LOCK_TIMEOUT:-300}" -x "${lock_file}" \
            bash -c '
                path="$1"
                must_exist="$2"
                type="$3"

                # Check path existence if required
                if [[ "${must_exist}" == "true" ]] && ! test -e "${path}"; then
                    exit 1
                fi

                # Verify path type
                case "${type}" in
                    directory)
                        test -d "${path}" || exit 2
                        ;;
                    file)
                        test -f "${path}" || exit 3
                        ;;
                esac

                exit 0
            ' -- "${sanitized_path}" "${must_exist}" "${type}"; then
            
            declare -r -i local status=$?
            case $status in
                1)
                    handle_error "ERROR" \
                        "Path does not exist: ${sanitized_path}" \
                        "$EXIT_INVALID_VAR" "${category}"
                    ;;
                2)
                    handle_error "ERROR" \
                        "Path is not a directory: ${sanitized_path}" \
                        "$EXIT_INVALID_VAR" "${category}"
                    ;;
                3)
                    handle_error "ERROR" \
                        "Path is not a regular file: ${sanitized_path}" \
                        "$EXIT_INVALID_VAR" "${category}"
                    ;;
                *)
                    handle_error "ERROR" \
                        "Failed to validate path: ${sanitized_path}" \
                        "$EXIT_INVALID_VAR" "${category}"
                    ;;
            esac
            return "$EXIT_INVALID_VAR"
        fi

        # Define and check permissions atomically
        declare -r -A local PERMISSION_CHECKS=(
            ["read"]="test -r"
            ["write"]="test -w"
            ["execute"]="test -x"
        )

        # Determine required permissions based on type
        declare -a -r local required_perms
        case "${type}" in
            directory)
                required_perms=("read" "write" "execute")
                ;;
            file)
                required_perms=("read" "write")
                ;;
            *)
                required_perms=("read")
                ;;
        esac

        # Check permissions atomically
        for perm in "${required_perms[@]}"; do
            if ! retry "${RETRY_COUNT}" "${RETRY_DELAY}" \
                flock -w "${LOCK_TIMEOUT:-300}" -x "${lock_file}" \
                bash -c "${PERMISSION_CHECKS[${perm}]} \"${sanitized_path}\""; then
                handle_error "ERROR" \
                    "Path lacks ${perm} permission: ${sanitized_path}" \
                    "$EXIT_INVALID_VAR" "${category}"
                return "$EXIT_INVALID_VAR"
            fi
        done

        # For directories, verify filesystem type atomically
        if [[ "${type}" == "directory" ]]; then
            declare local fs_type
            if ! fs_type="$(retry "${RETRY_COUNT}" "${RETRY_DELAY}" \
                flock -w "${LOCK_TIMEOUT:-300}" -x "${lock_file}" \
                df -PT "${sanitized_path}" | awk 'NR==2 {print $2}')"; then
                handle_error "ERROR" \
                    "Failed to determine filesystem type for: ${sanitized_path}" \
                    "$EXIT_INVALID_VAR" "${category}"
                return "$EXIT_INVALID_VAR"
            fi

            # Verify btrfs for snapshot directories
            if [[ "${category}" == "SNAPSHOT" && "${fs_type}" != "btrfs" ]]; then
                handle_error "ERROR" \
                    "Snapshot directory must be on btrfs filesystem: ${sanitized_path}" \
                    "$EXIT_INVALID_VAR" "${category}"
                return "$EXIT_INVALID_VAR"
            fi

            debug "Filesystem type verified: ${fs_type}" "${category}"
        fi

        debug "Path validated successfully: ${sanitized_path} (${VALID_TYPES[${type}]})" "${category}"
    else
        debug "DRY_RUN: Would validate path: ${sanitized_path} (${VALID_TYPES[${type}]})" "${category}"
    fi

    # Return the sanitized path
    printf '%s' "${sanitized_path}"
    return "$EXIT_SUCCESS"
}

################################
#     Progress Tracking         #
################################
initialize_progress() {
    declare -r local message="$1"
    declare -r -i local total_steps="${2:-0}"
    declare -r local category="${3:-PROGRESS}"

    # Validate input parameters
    if [[ -z "${message}" ]]; then
        handle_error "ERROR" "Empty progress message provided" \
            "$EXIT_INVALID_VAR" "${category}"
        return "$EXIT_INVALID_VAR"
    fi

    if (( total_steps < 1 )); then
        handle_error "ERROR" "Invalid total steps: ${total_steps}" \
            "$EXIT_INVALID_VAR" "${category}"
        return "$EXIT_INVALID_VAR"
    fi

    # Create temporary directory for progress tracking
    declare local temp_dir
    temp_dir="$(mktemp -d -t "${TEMP_FILE_PREFIX}-progress.XXXXXXXXXX")" || {
        handle_error "ERROR" "Failed to create temporary progress directory" \
            "$EXIT_INVALID_VAR" "${category}"
        return "$EXIT_INVALID_VAR"
    }

    # Enhanced cleanup trap with all signals
    trap 'cleanup_progress "${temp_dir}" 2>/dev/null || true; trap - RETURN' \
        RETURN SIGINT SIGTERM SIGHUP ERR EXIT

    # Create progress tracking files with atomic operations
    declare -r local progress_file="${temp_dir}/progress"
    declare -r local message_file="${temp_dir}/message"
    declare -r local total_file="${temp_dir}/total"
    declare -r local lock_file="${temp_dir}/lock"

    if ! (( DRY_RUN )); then
        # Initialize progress tracking atomically with enhanced error handling
        if ! retry "${RETRY_COUNT}" "${RETRY_DELAY}" \
            flock -w "${LOCK_TIMEOUT:-300}" -x "${lock_file}" \
            bash -c '
                set -euo pipefail
                declare -r progress_file="$1"
                declare -r message="$2"
                declare -r message_file="$3"
                declare -r total_steps="$4"
                declare -r total_file="$5"

                printf "%d" "0" > "${progress_file}.tmp"
                printf "%s" "${message}" > "${message_file}.tmp"
                printf "%d" "${total_steps}" > "${total_file}.tmp"

                mv -f "${progress_file}.tmp" "${progress_file}"
                mv -f "${message_file}.tmp" "${message_file}"
                mv -f "${total_file}.tmp" "${total_file}"
            ' -- "${progress_file}" "${message}" "${message_file}" "${total_steps}" "${total_file}"; then
            handle_error "ERROR" "Failed to initialize progress tracking" \
                "$EXIT_INVALID_VAR" "${category}"
            return "$EXIT_INVALID_VAR"
        fi

        # Store progress files in global associative array with readonly
        declare -g -A -r PROGRESS_FILES=(
            [progress]="${progress_file}"
            [message]="${message_file}"
            [total]="${total_file}"
            [lock]="${lock_file}"
            [dir]="${temp_dir}"
        )

        # Initialize global progress variables with readonly where appropriate
        declare -g -r PROGRESS_MESSAGE="${message}"
        declare -g -r -i PROGRESS_TOTAL="${total_steps}"
        declare -g -i PROGRESS_CURRENT=0

        # Log initial progress with enhanced information
        debug "Progress tracking initialized in: ${temp_dir}" "${category}"
        debug "Progress initialized: ${message} (0/${total_steps})" "${category}"

        # Calculate and log initial percentage
        declare -r -i local percentage=0
        info "Progress: ${message} [${percentage}%] (0/${total_steps})" "${category}"
    else
        debug "DRY_RUN: Would initialize progress: ${message} (${total_steps} steps)" "${category}"
    fi

    return "$EXIT_SUCCESS"
}

# Helper function for progress cleanup
cleanup_progress() {
    declare -r local dir="$1"
    
    # Remove all temporary files first
    find "${dir}" -type f -name "${TEMP_FILE_PREFIX}*" -delete 2>/dev/null || true
    
    # Then remove the directory
    rm -rf "${dir}" 2>/dev/null || true
    
    return 0
}

# Report progress of an operation
report_progress() {
    declare -r local message="$1"
    declare -r -i local current_step="${2:-0}"
    declare -r local category="${3:-PROGRESS}"
    declare -r -i local max_retries="${RETRY_COUNT:-3}"
    declare -r -i local retry_delay="${RETRY_DELAY:-5}"

    # Validate input parameters
    if [[ -z "${message}" ]]; then
        handle_error "ERROR" "Empty progress message provided" \
            "$EXIT_INVALID_VAR" "${category}"
        return "$EXIT_INVALID_VAR"
    fi

    # Validate current step value with bounds checking
    if (( current_step < 0 )); then
        handle_error "ERROR" "Invalid current step: ${current_step}" \
            "$EXIT_INVALID_VAR" "${category}"
        return "$EXIT_INVALID_VAR"
    fi

    if ! (( DRY_RUN )); then
        # Verify progress tracking is initialized with retry
        if ! retry "${max_retries}" "${retry_delay}" \
            test -f "${PROGRESS_FILES[lock]:-/nonexistent}"; then
            handle_error "ERROR" "Progress tracking not initialized" \
                "$EXIT_INVALID_VAR" "${category}"
            return "$EXIT_INVALID_VAR"
        fi

        # Create temporary directory for atomic operations
        declare local temp_dir
        temp_dir="$(mktemp -d -t "${TEMP_FILE_PREFIX}-progress-update.XXXXXXXXXX")" || {
            handle_error "ERROR" "Failed to create temporary progress update directory" \
                "$EXIT_INVALID_VAR" "${category}"
            return "$EXIT_INVALID_VAR"
        }

        # Enhanced cleanup trap with all signals and error handling
        trap 'err=$?; cleanup_progress "${temp_dir}" 2>/dev/null || true; trap - RETURN; exit "$err"' \
            RETURN SIGINT SIGTERM SIGHUP ERR EXIT

        # Create atomic operation lock file
        declare -r local atomic_lock="${temp_dir}/atomic.lock"
        touch "${atomic_lock}" || {
            handle_error "ERROR" "Failed to create atomic lock file" \
                "$EXIT_INVALID_VAR" "${category}"
            return "$EXIT_INVALID_VAR"
        }

        # Update progress with atomic operations and enhanced error handling
        if ! retry "${max_retries}" "${retry_delay}" \
            flock -w "${LOCK_TIMEOUT:-300}" -x "${atomic_lock}" \
            bash -c '
                set -euo pipefail
                shopt -s inherit_errexit

                # Declare readonly variables
                declare -r progress_file="$1"
                declare -r current_step="$2"
                declare -r message="$3"
                declare -r message_file="$4"
                declare -r temp_dir="$5"
                declare -r total_file="$6"

                # Create temporary files in temp directory
                declare -r temp_progress="${temp_dir}/progress.tmp"
                declare -r temp_message="${temp_dir}/message.tmp"

                # Write to temporary files first
                printf "%d" "${current_step}" > "${temp_progress}"
                printf "%s" "${message}" > "${temp_message}"

                # Verify total steps before proceeding
                declare -r -i total_steps="$(cat "${total_file}")"
                if (( current_step > total_steps )); then
                    printf "Warning: Current step %d exceeds total steps %d\n" \
                        "${current_step}" "${total_steps}" >&2
                fi

                # Atomic moves with verification
                mv -f "${temp_progress}" "${progress_file}"
                mv -f "${temp_message}" "${message_file}"

                # Verify files were written correctly
                [[ "$(cat "${progress_file}")" == "${current_step}" ]] || exit 1
                [[ "$(cat "${message_file}")" == "${message}" ]] || exit 1
            ' -- \
                "${PROGRESS_FILES[progress]}" \
                "${current_step}" \
                "${message}" \
                "${PROGRESS_FILES[message]}" \
                "${temp_dir}" \
                "${PROGRESS_FILES[total]}"; then
            handle_error "ERROR" "Failed to update progress atomically" \
                "$EXIT_INVALID_VAR" "${category}"
            return "$EXIT_INVALID_VAR"
        fi

        # Update global variables with validation and readonly protection
        if [[ "${PROGRESS_MESSAGE}" != "${message}" ]]; then
            PROGRESS_MESSAGE="${message}"
        fi

        if (( PROGRESS_CURRENT != current_step )); then
            PROGRESS_CURRENT="${current_step}"
        fi

        # Calculate percentage with enhanced bounds checking
        declare -r -i local percentage
        if (( PROGRESS_TOTAL > 0 )); then
            if (( current_step <= PROGRESS_TOTAL )); then
                percentage=$(( current_step * 100 / PROGRESS_TOTAL ))
            else
                percentage=100
                debug "Current step (${current_step}) exceeds total steps (${PROGRESS_TOTAL})" "${category}"
            fi
        else
            percentage=0
            debug "Invalid total steps: ${PROGRESS_TOTAL}" "${category}"
        fi

        # Enhanced progress logging with completion detection
        debug "Progress updated: ${message} (${current_step}/${PROGRESS_TOTAL})" "${category}"
        if (( percentage == 100 )); then
            info "Progress complete: ${message} [${percentage}%] (${current_step}/${PROGRESS_TOTAL})" "${category}"
        else
            info "Progress: ${message} [${percentage}%] (${current_step}/${PROGRESS_TOTAL})" "${category}"
        fi
    else
        debug "DRY_RUN: Would update progress: ${message} (step ${current_step})" "${category}"
    fi

    return "$EXIT_SUCCESS"
}

################################
#     Chain Recovery            #
################################
recover_snapshot_chain() {
    declare -r local snapshot_dir="$1"
    declare -r local category="RECOVERY"
    declare -i local status=0

    # Initialize progress tracking
    initialize_progress "Snapshot Chain Recovery" 5

    # Create temporary directory for recovery operations
    declare local temp_dir
    temp_dir="$(mktemp -d -t "${TEMP_FILE_PREFIX}-recovery.XXXXXXXXXX")" || {
        handle_error "ERROR" "Failed to create temporary recovery directory" \
            "$EXIT_INVALID_VAR" "${category}"
        return "$EXIT_INVALID_VAR"
    }

    # Ensure cleanup of temporary directory
    trap 'rm -rf "${temp_dir}" 2>/dev/null || true; trap - RETURN' \
        RETURN SIGINT SIGTERM SIGHUP ERR EXIT

    if ! (( DRY_RUN )); then
        report_progress "Scanning for incomplete snapshots" 1

        # Find all snapshots and verify their integrity
        declare -a local incomplete_snapshots=()
        while IFS= read -r snapshot; do
            # Skip if not a directory
            [[ -d "${snapshot}" ]] || continue

            # Check if snapshot is incomplete
            if ! retry "${RETRY_COUNT}" "${RETRY_DELAY}" \
                btrfs subvolume show "${snapshot}" >/dev/null 2>&1 || \
                ! retry "${RETRY_COUNT}" "${RETRY_DELAY}" \
                btrfs property get "${snapshot}" ro | grep -q "ro=true"; then
                incomplete_snapshots+=("${snapshot}")
                warning "Found incomplete snapshot: ${snapshot}"
            fi
        done < <(find "${snapshot_dir}" -maxdepth 1 -name "${SNAPSHOT_PREFIX}*")

        report_progress "Cleaning up incomplete snapshots" 2

        # Clean up incomplete snapshots
        for snapshot in "${incomplete_snapshots[@]}"; do
            debug "Removing incomplete snapshot: ${snapshot}" "${category}"
            if ! retry "${RETRY_COUNT}" "${RETRY_DELAY}" \
                btrfs subvolume delete "${snapshot}"; then
                warning "Failed to remove incomplete snapshot: ${snapshot}"
                status=1
            fi
        done

        report_progress "Verifying snapshot chain integrity" 3

        # Verify snapshot chain integrity
        declare -A local snapshot_parents=()
        declare -A local snapshot_children=()
        declare local latest_snapshot
        latest_snapshot="$(get_latest_snapshot "${snapshot_dir}")" || {
            handle_error "ERROR" "Failed to get latest snapshot" \
                "$EXIT_INVALID_VAR" "${category}"
            return "$EXIT_INVALID_VAR"
        }

        # Build snapshot relationship maps
        while IFS= read -r snapshot; do
            [[ -d "${snapshot}" ]] || continue

            # Get parent reference
            declare local parent
            parent="$(retry "${RETRY_COUNT}" "${RETRY_DELAY}" \
                btrfs property get "${snapshot}" user.snapshot.parent 2>/dev/null)" || continue
            parent="${parent#user.snapshot.parent=}"

            if [[ "${parent}" != "none" && -d "${parent}" ]]; then
                snapshot_parents["${snapshot}"]="${parent}"
                snapshot_children["${parent}"]+=" ${snapshot}"
            fi
        done < <(find "${snapshot_dir}" -maxdepth 1 -name "${SNAPSHOT_PREFIX}*")

        report_progress "Checking for chain breaks" 4

        # Check for broken chains
        declare -a local broken_chains=()
        declare local current="${latest_snapshot}"
        while [[ -n "${current}" ]]; do
            declare local parent="${snapshot_parents[${current}]:-}"
            if [[ -n "${parent}" && ! -d "${parent}" ]]; then
                broken_chains+=("${current}")
                warning "Found broken chain at: ${current} (missing parent: ${parent})"
            fi
            current="${parent}"
        done

        report_progress "Rebuilding broken chains" 5

        # Rebuild broken chains
        if (( ${#broken_chains[@]} > 0 )); then
            warning "Found ${#broken_chains[@]} broken chains, attempting repair"

            for snapshot in "${broken_chains[@]}"; do
                # Find closest valid ancestor
                declare local valid_parent=""
                declare local current_parent="${snapshot_parents[${snapshot}]}"
                
                while [[ -n "${current_parent}" ]]; do
                    if [[ -d "${current_parent}" ]] && \
                        retry "${RETRY_COUNT}" "${RETRY_DELAY}" \
                        verify_snapshot "${current_parent}"; then
                        valid_parent="${current_parent}"
                        break
                    fi
                    current_parent="${snapshot_parents[${current_parent}]:-}"
                done

                # Update parent reference
                if [[ -n "${valid_parent}" ]]; then
                    debug "Updating parent reference for ${snapshot} to ${valid_parent}" "${category}"
                    if ! retry "${RETRY_COUNT}" "${RETRY_DELAY}" \
                        btrfs property set "${snapshot}" \
                        user.snapshot.parent "${valid_parent}"; then
                        warning "Failed to update parent reference for: ${snapshot}"
                        status=1
                    fi
                else
                    # No valid parent found, mark as full snapshot
                    debug "Converting ${snapshot} to full snapshot" "${category}"
                    if ! retry "${RETRY_COUNT}" "${RETRY_DELAY}" \
                        btrfs property set "${snapshot}" \
                        user.snapshot.parent "none"; then
                        warning "Failed to convert to full snapshot: ${snapshot}"
                        status=1
                    fi
                fi
            done

            # Optimize chain after repairs
            if ! optimize_snapshot_chain "${snapshot_dir}"; then
                warning "Failed to optimize snapshot chain after repairs"
                status=1
            fi
        fi
    else
        debug "DRY_RUN: Would perform snapshot chain recovery in: ${snapshot_dir}" "${category}"
    fi

    return "${status}"
}

join_paths() {
    declare -r local base_path="$1"
    declare -r local sub_path="$2"
    declare -r local category="PATH"
    declare -i local status=0
    
    # Validate input parameters
    if [[ -z "${base_path}" || -z "${sub_path}" ]]; then
        handle_error "ERROR" "Empty path component provided" \
            "${EXIT_INVALID_VAR}" "${category}"
        return "${EXIT_INVALID_VAR}"
    fi
    
    # Create temporary directory with secure permissions
    declare local temp_dir
    temp_dir="$(mktemp -d -t "${TEMP_FILE_PREFIX}-join.XXXXXXXXXX")" || {
        handle_error "ERROR" "Failed to create temporary join directory" \
            "${EXIT_INVALID_VAR}" "${category}"
        return "${EXIT_INVALID_VAR}"
    }
    
    # Create result file with secure permissions
    declare -r local result_file="${temp_dir}/result"
    if ! mktemp -p "${temp_dir}" -t "result.XXXXXXXXXX" > /dev/null 2>&1; then
        rm -rf "${temp_dir}" 2>/dev/null || true
        handle_error "ERROR" "Failed to create result file" \
            "${EXIT_INVALID_VAR}" "${category}"
        return "${EXIT_INVALID_VAR}"
    fi
    
    # Create lock file with secure permissions
    declare -r local lock_file="${temp_dir}/lock"
    if ! mktemp -p "${temp_dir}" -t "lock.XXXXXXXXXX" > /dev/null 2>&1; then
        rm -rf "${temp_dir}" 2>/dev/null || true
        handle_error "ERROR" "Failed to create lock file" \
            "${EXIT_INVALID_VAR}" "${category}"
        return "${EXIT_INVALID_VAR}"
    fi
    
    # Ensure cleanup of temporary files and handle all signals
    trap 'rm -rf "${temp_dir}" 2>/dev/null || true; trap - RETURN' \
        RETURN SIGTERM SIGINT SIGHUP ERR EXIT
    
    if ! (( DRY_RUN )); then
        # Use flock with retry for atomic path joining operations
        if ! retry "${RETRY_COUNT}" "${RETRY_DELAY}" \
            flock -w "${LOCK_TIMEOUT:-300}" -x "${lock_file}" \
            bash -c '
                set -euo pipefail
                shopt -s inherit_errexit
                
                declare -r base_path="$1"
                declare -r sub_path="$2"
                declare -r result_file="$3"
                declare -r temp_result="${result_file}.tmp"
                
                # Sanitize paths using existing function with retry
                declare local clean_base clean_sub
                if ! clean_base="$(retry 3 5 sanitize_path "${base_path}")"; then
                    return "${EXIT_INVALID_VAR}"
                fi
                if ! clean_sub="$(retry 3 5 sanitize_path "${sub_path}")"; then
                    return "${EXIT_INVALID_VAR}"
                fi
                
                # Remove trailing slash from base and leading slash from sub
                clean_base="${clean_base%/}"
                clean_sub="${clean_sub#/}"
                
                # Join and normalize paths atomically
                declare local joined_path
                if ! joined_path="$(retry 3 5 sanitize_path "${clean_base}/${clean_sub}")"; then
                    return "${EXIT_INVALID_VAR}"
                fi
                
                # Write result atomically
                printf "%s" "${joined_path}" > "${temp_result}"
                mv -f "${temp_result}" "${result_file}"
                
                return 0
            ' -- "${base_path}" "${sub_path}" "${result_file}"; then
            status="${EXIT_INVALID_VAR}"
            handle_error "ERROR" "Failed to join paths atomically" \
                "${EXIT_INVALID_VAR}" "${category}"
            return "${status}"
        fi
        
        # Read result atomically with retry
        declare local result
        if ! result="$(retry "${RETRY_COUNT}" "${RETRY_DELAY}" cat "${result_file}")"; then
            status="${EXIT_INVALID_VAR}"
            handle_error "ERROR" "Failed to read joined path result" \
                "${EXIT_INVALID_VAR}" "${category}"
            return "${status}"
        fi
        
        debug "Joined paths: ${base_path} + ${sub_path} -> ${result}" "${category}"
        printf '%s' "${result}"
    else
        debug "DRY_RUN: Would join paths: ${base_path} + ${sub_path}" "${category}"
        # Even in DRY_RUN, sanitize the output format
        declare local safe_base safe_sub
        safe_base="${base_path%/}"
        safe_sub="${sub_path#/}"
        printf '%s/%s' "${safe_base}" "${safe_sub}"
    fi
    
    return "${EXIT_SUCCESS}"
}

# Get snapshot timestamp
get_snapshot_timestamp() {
    declare -r local snapshot_path="$1"
    declare -r local category="TIMESTAMP"
    declare -i local status="$EXIT_SUCCESS"
    
    # Validate input using existing validate_path function with retry
    if ! retry "${RETRY_COUNT}" "${RETRY_DELAY}" \
        validate_path "${snapshot_path}" "directory" "true" "${category}"; then
        return "$EXIT_INVALID_VAR"
    fi

    # Create temporary directory with secure permissions
    declare local temp_dir
    temp_dir="$(mktemp -d -t "${TEMP_FILE_PREFIX}-timestamp.XXXXXXXXXX")" || {
        handle_error "ERROR" "Failed to create temporary timestamp directory" \
            "$EXIT_INVALID_VAR" "${category}"
        return "$EXIT_INVALID_VAR"
    }

    # Create result file with secure permissions
    declare -r local result_file="${temp_dir}/result"
    if ! mktemp -p "${temp_dir}" -t "result.XXXXXXXXXX" > /dev/null 2>&1; then
        rm -rf "${temp_dir}" 2>/dev/null || true
        handle_error "ERROR" "Failed to create result file" \
            "$EXIT_INVALID_VAR" "${category}"
        return "$EXIT_INVALID_VAR"
    fi

    # Create lock file with secure permissions
    declare -r local lock_file="${temp_dir}/lock"
    if ! mktemp -p "${temp_dir}" -t "lock.XXXXXXXXXX" > /dev/null 2>&1; then
        rm -rf "${temp_dir}" 2>/dev/null || true
        handle_error "ERROR" "Failed to create lock file" \
            "$EXIT_INVALID_VAR" "${category}"
        return "$EXIT_INVALID_VAR"
    fi

    # Enhanced cleanup trap handling all signals
    trap 'err=$?; 
         if [[ -n "${lock_file}" && -f "${lock_file}" ]]; then
             flock -u 200 2>/dev/null || true;
             rm -f "${lock_file}" 2>/dev/null || true;
         fi;
         if [[ -n "${result_file}" && -f "${result_file}" ]]; then
             rm -f "${result_file}" 2>/dev/null || true;
         fi;
         if [[ -n "${temp_dir}" && -d "${temp_dir}" ]]; then
             rm -rf "${temp_dir}" 2>/dev/null || true;
         fi;
         trap - RETURN SIGTERM SIGINT SIGHUP ERR EXIT;
         return $err' \
        RETURN SIGTERM SIGINT SIGHUP ERR EXIT

    if ! (( DRY_RUN )); then
        # Use flock for atomic operations with retry
        if ! retry "${RETRY_COUNT}" "${RETRY_DELAY}" \
            flock -w "${LOCK_TIMEOUT:-300}" -x "${lock_file}" \
            bash -c '
                set -euo pipefail
                shopt -s inherit_errexit
                
                declare -r snapshot_path="$1"
                declare -r temp_dir="$2"
                declare -r result_file="$3"
                declare -r SNAPSHOT_PREFIX="$4"
                
                # Extract timestamp from snapshot name
                declare local timestamp_str
                if ! timestamp_str="$(basename "${snapshot_path}" | grep -oP "${SNAPSHOT_PREFIX}\K[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{6}Z")"; then
                    return 1
                fi

                # Convert timestamp to epoch
                declare -i local epoch_time
                if ! epoch_time="$(date -u -d "${timestamp_str}" "+%s" 2>/dev/null)"; then
                    return 2
                fi

                # Write result atomically using mktemp
                declare local temp_result
                temp_result="$(mktemp -p "${temp_dir}" -t result.XXXXXXXXXX)" || return 3
                printf "%d" "${epoch_time}" > "${temp_result}"
                mv -f "${temp_result}" "${result_file}"
                return 0
            ' -- "${snapshot_path}" "${temp_dir}" "${result_file}" "${SNAPSHOT_PREFIX}"; then
            
            declare -r -i local exit_code=$?
            case "${exit_code}" in
                1)
                    handle_error "ERROR" \
                        "Failed to extract timestamp from snapshot name: ${snapshot_path}" \
                        "$EXIT_INVALID_VAR" "${category}"
                    ;;
                2)
                    handle_error "ERROR" \
                        "Failed to convert timestamp to epoch: ${snapshot_path}" \
                        "$EXIT_INVALID_VAR" "${category}"
                    ;;
                3)
                    handle_error "ERROR" \
                        "Failed to create temporary result file: ${snapshot_path}" \
                        "$EXIT_INVALID_VAR" "${category}"
                    ;;
                *)
                    handle_error "ERROR" \
                        "Failed to process timestamp for: ${snapshot_path}" \
                        "$EXIT_INVALID_VAR" "${category}"
                    ;;
            esac
            return "$EXIT_INVALID_VAR"
        fi

        # Read result atomically with retry
        declare -i local epoch_time
        if ! epoch_time="$(retry "${RETRY_COUNT}" "${RETRY_DELAY}" \
            cat "${result_file}")"; then
            handle_error "ERROR" "Failed to read timestamp result" \
                "$EXIT_INVALID_VAR" "${category}"
            return "$EXIT_INVALID_VAR"
        fi

        debug "Got snapshot timestamp: ${snapshot_path} -> ${epoch_time}" "${category}"
        printf '%d' "${epoch_time}"
    else
        debug "DRY_RUN: Would get timestamp for: ${snapshot_path}" "${category}"
        # Return current time in dry run mode
        declare -i local current_time
        current_time="$(date -u '+%s')"
        printf '%d' "${current_time}"
    fi

    return "${status}"
}


################################
#        Signal Handling        #
################################
# Set up signal traps
trap cleanup EXIT SIGTERM SIGINT SIGHUP

################################
#     Main Program Logic       #
################################
# Main function
main() {
    # Check prerequisites first
    check_prerequisites || return $?

    # Initialize error tracking and temporary files
    declare -g -i SCRIPT_STATUS=0
    declare -g -A -r ERROR_COUNTS=([ERROR]=0 [WARNING]=0)
    declare local temp_snapshot=""
    declare local tmp_send_file=""
    declare -r local tmp_file
    
    # Create temporary file with cleanup trap
    tmp_file="$(mktemp -t "${TEMP_FILE_PREFIX}.XXXXXXXXXX")" || {
        handle_error "ERROR" "Failed to create temporary file" "$EXIT_INVALID_VAR" "MAIN"
        return "$EXIT_INVALID_VAR"
    }
    
    # Add cleanup for temporary files
    trap 'rm -f "$tmp_file" 2>/dev/null || true; trap - EXIT' EXIT

    # Try to acquire lock with enhanced error handling
    case $(acquire_lock "$LOCK_FILE") in
        0) 
            debug "Lock acquired successfully"
            ;;
        2) 
            log "INFO" "LOCK" "Another instance running"
            return "$EXIT_SUCCESS"
            ;;
        *)
            handle_error "ERROR" "Lock acquisition failed" "$EXIT_INVALID_VAR" "LOCK"
            return "$EXIT_INVALID_VAR"
            ;;
    esac

    # Execute main logic with error propagation and cleanup
    {
        parse_arguments "$@" &&
        initialize_metadata_variables &&
        validate_config &&
        validate_retention_settings &&
        check_filesystem_space "$SRC_DIR" &&
        check_filesystem_space "$DST_DIR" &&
        verify_compression "$SRC_DIR" &&
        create_snapshot
    } || {
        declare -i local exit_status=$?
        cleanup_snapshot_resources "$temp_snapshot" "$tmp_send_file" || true
        return "$exit_status"
    }

    return "$EXIT_SUCCESS"
}

################################
#       Script Entry Point      #
################################
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
    exit $?
fi
