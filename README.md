# YABB - Yet Another BTRFS Backup

A BTRFS snapshot/backup utility, cause none of the existing ones worked exactly the way I wanted.

## Features

### Core Backup Functionality
- **Incremental and Full Backups**: Determines whether to perform incremental or full backups based on available parent snapshots
- **Progress Monitoring**: Transfer progress visualisation using pipe viewer (pv)
- **Atomic Operations**: Snapshots are created atomically with automatic cleanup on failure
- **Space Management**: Pre-flight checks to ensure sufficient destination space before initiating transfers

### Data Integrity
- **Multi-layer Verification**: Combines UUID verification, scrub operations, and checksum sampling
- **Device Error Detection**: Monitors BTRFS device statistics before and after operations
- **Automatic Scrubbing**: Configurable periodic filesystem scrubbing with optional rate limiting
- **Checksum Verification**: Samples configurable percentage of files for integrity validation

### Retention and Lifecycle
- **Time based Retention**: Configurable retention period with automatic pruning of expired snapshots
- **Minimum Snapshot Guarantee**: Maintains specified minimum number of snapshots regardless of age
- **Dual location Pruning**: Manages snapshot lifecycle on both source and destination volumes

### Emergency Recovery
- **Point-in-time Restore**: Restore specific snapshots or latest available backup
- **Pre-restore Verification**: Validates backup integrity before initiating recovery
- **Flexible Restore Paths**: Support for custom restore locations or default adjacent recovery points

## Configuration

All configuration options are set using environment variables.

| Variable | Default | Description |
|----------|---------|-------------|
| `YABB_SOURCE_VOL` | `/data` | Source BTRFS subvolume to backup |
| `YABB_DEST_MOUNT` | `/mnt/external` | Destination BTRFS filesystem mount point |
| `YABB_MIN_FREE_GB` | `1` | Minimum free space (GB) to maintain on destination |
| `YABB_LOCK_FILE` | `/var/lock/yabb.lock` | Lock file path for preventing concurrent operations |
| `YABB_RETENTION_DAYS` | `90` | Days to retain snapshots (0 to disable pruning) |
| `YABB_KEEP_MINIMUM` | `5` | Minimum number of snapshots to retain |
| `YABB_VERIFY_SAMPLE_PERCENT` | `5` | Percentage of files to sample for checksum verification (0 to disable) |
| `YABB_MINIMUM_DAYS_BETWEEN_SCRUBS` | `30` | Days between automatic scrub operations (0 to disable) |
| `YABB_SCRUB_RATE_LIMIT` | _(empty)_ | Scrub I/O rate limit (e.g., `100M`, `1G`) |

## Requirements

### Required Dependencies
- Linux operating system with BTRFS filesystem support
- BTRFS tools (`btrfs-progs`) - Core BTRFS operations
- Pipe Viewer (`pv`) - Progress monitoring during transfers
- BC calculator (`bc`) - Mathematical calculations for size conversions

### Optional Dependencies
YABB will use the following utilities if available but has fallbacks if unavailable:

| Utility | Purpose | Fallback|
|---------|---------|-------------------|
| `perl` | Accurate incremental backup size estimation | Falls back to conservative 10% estimate |
| `realpath` | Path canonicalization and validation | May affect path validation in edge cases |
| `flock` | Process locking for concurrent operation prevention | Built into most systems |
| `mountpoint` | Mount point verification | Falls back to mount attempt |
| `mktemp` | Secure temporary file creation | Built into most systems |
| `stat` | Filesystem type detection | Falls back to `df` command |
| `df` | Backup filesystem type detection | Required if `stat` unavailable |
| `du` | Directory size calculations | Required for space estimation |

### Filesystem Requirements
- Source volume must be a BTRFS subvolume
- Destination must be a BTRFS filesystem
- Sufficient permissions for snapshot operations
- Write access to lock file location (default: `/var/lock/`)

## Installation

1. Download the script:
```bash
wget https://github.com/yourusername/yabb/raw/main/yabb.sh
chmod +x yabb.sh
```

2. Install required dependencies:
```bash
# Debian/Ubuntu
sudo apt install btrfs-progs pv bc

# RHEL/Fedora
sudo dnf install btrfs-progs pv bc

# Arch Linux
sudo pacman -S btrfs-progs pv bc

# Alpine Linux
apk add btrfs-progs pv bc
```

3. Install optional dependencies for enhanced functionality:

```bash
# Debian/Ubuntu
sudo apt install perl coreutils util-linux

# RHEL/Fedora
sudo dnf install perl coreutils util-linux

# Arch Linux
sudo pacman -S perl coreutils util-linux

# Alpine Linux
apk add perl coreutils util-linux
```

## Usage

### Basic Backup Operation

Execute backup with default configuration:
```bash
./yabb.sh
```

### Custom Configuration

Override configuration for specific execution:
```bash
YABB_SOURCE_VOL=/home YABB_DEST_MOUNT=/backup ./yabb.sh
```

### Restore Operations

Restore latest snapshot:
```bash
./yabb.sh --restore latest
```

Restore specific snapshot:
```bash
./yabb.sh --restore data.2024-01-15T10:30:00Z
```

Restore to custom location:
```bash
./yabb.sh --restore data.2024-01-15T10:30:00Z /mnt/recovery/data
```

### Command Line Options

| Option | Description |
|--------|-------------|
| `--help`, `-h` | Display help message with current configuration |
| `--version`, `-v` | Show version information |
| `--restore NAME [PATH]` | Restore snapshot (NAME: snapshot name or 'latest', PATH: optional custom location) |

## Exit Codes

| Code | Description |
|------|-------------|
| `0` | Success |
| `1` | Operation failed |
| `2` | Backup succeeded with verification warnings |
| `3` | Restore succeeded with verification warnings |

## Operational Details

### Snapshot Naming Convention
Snapshots follow the format: `{SOURCE_BASE}.{UTC_TIMESTAMP}`
- Example: `data.2025-01-15T10:30:00Z`

### Directory Structure
```
Source Volume:
├── .yabb_snapshots/
│   ├── data.2024-01-15T10:30:00Z
│   ├── data.2024-01-15T11:30:00Z
│   └── ...

Destination Mount:
├── .yabb_snapshots/
│   ├── data.2024-01-15T10:30:00Z
│   ├── data.2024-01-15T11:30:00Z
│   └── ...
```

## Scheduling

### Cron

Daily backup at 2 AM:
```bash
0 2 * * * /usr/local/bin/yabb.sh >> /var/log/yabb.log 2>&1
```

Hourly incremental backups:
```bash
0 * * * * YABB_RETENTION_DAYS=7 /usr/local/bin/yabb.sh >> /var/log/yabb.log 2>&1
```

### Systemd Timer

Create `/etc/systemd/system/yabb.service`:
```ini
[Unit]
Description=YABB Backup Service
After=multi-user.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/yabb.sh
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

Create `/etc/systemd/system/yabb.timer`:
```ini
[Unit]
Description=YABB Backup Timer
Requires=yabb.service

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
```

Enable timer:
```bash
sudo systemctl enable --now yabb.timer
```

## Error Handling

### Automatic Recovery
- Partial snapshots are automatically detected and removed
- Failed operations trigger comprehensive cleanup
- Lock files are released on both normal and abnormal termination

### Manual Intervention
If automatic cleanup fails, manually remove:
- Lock file: `/var/lock/yabb.lock`
- Partial snapshots in `.yabb_snapshots` directories

## Performance Tuning

### I/O Rate Limiting
Configure scrub rate limiting to minimize impact on system performance:
```bash
YABB_SCRUB_RATE_LIMIT=100M ./yabb.sh
```

### Verification Sampling
Adjust checksum verification percentage based on dataset size and performance requirements:
```bash
# Disable verification for maximum speed
YABB_VERIFY_SAMPLE_PERCENT=0 ./yabb.sh

# Comprehensive verification
YABB_VERIFY_SAMPLE_PERCENT=100 ./yabb.sh
```

## Troubleshooting

### Common Issues

**Insufficient Space**
- Increase `YABB_MIN_FREE_GB` buffer
- Reduce `YABB_RETENTION_DAYS`
- Manually prune old snapshots

**Lock File Conflicts**
```bash
# Check for stale locks
cat /var/lock/yabb.lock
# Remove if process no longer exists
rm -f /var/lock/yabb.lock
```

**Device Errors**
```bash
# Check device statistics
btrfs device stats /mnt/destination
# Clear error counters after resolution
btrfs device stats -z /mnt/destination
```

## Licence

GPL-3.0-only - See LICENSE for full text.

## Author

Copyright (C) 2025-present Aryan Ameri <info@ameri.coffee>
