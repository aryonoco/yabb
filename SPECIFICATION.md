# YABB — Functional Specification

Version 0.5.5 | Specification Date: 2026-03-22

This document is the sole specification for reimplementing YABB (Yet Another BTRFS Backup). It describes **what** the programme does and **how it should behave**, without prescribing implementation structure, module layout, or language-specific patterns. The implementing agent should make idiomatic choices for the target language.

---

## Table of Contents

1. [Programme Overview](#1-programme-overview)
2. [External Dependencies and System Requirements](#2-external-dependencies-and-system-requirements)
3. [Domain Model](#3-domain-model)
4. [Error Model](#4-error-model)
5. [Configuration](#5-configuration)
6. [Retention Policy Engine](#6-retention-policy-engine)
7. [Snapshot Naming and Metadata](#7-snapshot-naming-and-metadata)
8. [BTRFS Operations Abstraction Layer](#8-btrfs-operations-abstraction-layer)
9. [Backup Workflow](#9-backup-workflow)
10. [Chain Management](#10-chain-management)
11. [Chain Recovery](#11-chain-recovery)
12. [Storage Optimisation](#12-storage-optimisation)
13. [Infrastructure Utilities](#13-infrastructure-utilities)
14. [CLI Interface and Output](#14-cli-interface-and-output)
15. [systemd Integration](#15-systemd-integration)
16. [Exit Codes and Process Model](#16-exit-codes-and-process-model)
17. [Acceptance Criteria](#17-acceptance-criteria)
- [Appendix A: Reference Configuration File](#appendix-a-reference-configuration-file)
- [Appendix B: systemd Service Unit](#appendix-b-systemd-service-unit)
- [Appendix C: systemd Timer Unit](#appendix-c-systemd-timer-unit)

---

## 1. Programme Overview

YABB is a Linux CLI tool that creates incremental BTRFS backups with retention policies. It operates on local BTRFS filesystems, creating read-only snapshots, sending them to a backup destination via `btrfs send | btrfs receive`, and deleting old snapshots according to configurable retention rules.

### Operational Model

- **Single static binary** — no runtime dependencies beyond system tools
- **Requires root** — BTRFS operations need `CAP_SYS_ADMIN`
- **Local only** — source and destination must be locally mounted BTRFS filesystems
- **Single instance** — file locking prevents concurrent execution
- **Configuration via TOML** — `/etc/yabb.toml` or `~/.config/yabb/yabb.toml`

### Five Subcommands

| Command | Purpose |
|---------|---------|
| `run` | Execute a backup (create snapshot, send to destination, apply retention) |
| `validate` | Check configuration validity and system prerequisites without running a backup |
| `status` | Display current snapshot count and disk usage |
| `optimize` | Manually run storage maintenance (defrag, balance, scrub) |
| `health` | Diagnose snapshot chain integrity, optionally repair |

### Design Principles

- **Errors are values** — all fallible operations return `Result<T, Error>`. The programme never raises exceptions for control flow.
- **Immutable data** — configuration and state objects are never mutated; operations return new values.
- **Graceful degradation** — non-critical failures (cleanup, optimisation) log warnings and continue; critical failures abort with specific exit codes.

---

## 2. External Dependencies and System Requirements

### System Requirements

- Linux kernel with BTRFS support
- Root access (EUID 0)
- `btrfs-progs` version 5.14 or later (required for `--compressed-data` flag on `btrfs send`)

### Required External Commands

**Checked during prerequisite verification** (Section 13.5) — the programme verifies these exist before running:

| Command | Purpose |
|---------|---------|
| `btrfs` | All BTRFS subvolume, filesystem, property, send/receive operations |
| `pv` | Progress display during send/receive streaming |
| `setfattr` | Writing extended attributes (`user.yabb.*` namespace) |
| `getfattr` | Reading extended attributes |
| `df` | Disk space checks |
| `uuidgen` | Generating unique snapshot identifiers |
| `flock` | File locking (prerequisite check only; actual locking uses `fcntl`) |
| `mktemp` | Temporary file creation |
| `date` | Timestamp operations |
| `find` | Finding snapshots |
| `grep` | Text processing |
| `awk` | Text processing |

**Used but not explicitly checked** (assumed available on all Linux systems):

| Command | Purpose |
|---------|---------|
| `stat` | Filesystem type detection (`stat -f -c %T`) |
| `uname` | Kernel version (`uname -r`) and platform detection (`uname -m`) |
| `head` | Stream truncation for change detection |
| `wc` | Byte counting for change detection |
| `which` | Checking command existence during prerequisite verification |

### BTRFS Commands Used

Full list of `btrfs` subcommands and arguments — see Section 8 for details on each:

- `btrfs version`
- `btrfs subvolume create|delete|show|snapshot`
- `btrfs property get|set`
- `btrfs filesystem usage|defragment|label`
- `btrfs balance start|status`
- `btrfs scrub start|status`
- `btrfs device stats`
- `btrfs send` (with `--compressed-data`, `--quiet`, `-c`, `-p`)
- `btrfs receive`

---

## 3. Domain Model

This section defines every data structure. Use the host language's type system to enforce constraints at construction time. Field tables use language-neutral notation.

### 3.1 Exit Codes

An enumeration with 12 members. Each member has a fixed integer value used as the process exit code.

| Name | Value | Meaning |
|------|-------|---------|
| Success | 0 | Operation completed successfully |
| NoChanges | 1 | No changes detected since last snapshot (not an error) |
| InvalidArgument | 2 | Bad CLI arguments |
| ConfigMissing | 3 | Configuration file not found |
| MissingVar | 4 | Required configuration variable missing |
| InvalidVar | 5 | Configuration variable has invalid value |
| PrereqMissing | 6 | Required tool or capability missing |
| DirInvalid | 7 | Directory does not exist or is not on BTRFS |
| LockHeld | 8 | Lock held by another instance (informational — see Section 16) |
| LockError | 9 | Lock file I/O error |
| DeviceErrors | 10 | BTRFS device has errors |
| Shutdown | 11 | Clean shutdown via signal |

### 3.2 Compression

**CompressionAlgo** — three variants:

| Variant | Serialised as | Level range |
|---------|---------------|-------------|
| Zstd | `"zstd"` | 1–15 |
| Zlib | `"zlib"` | 1–9 |
| Lzo | `"lzo"` | 1–9 |

**CompressionLevel** — a pair of algorithm and level:

| Field | Type | Constraint |
|-------|------|------------|
| algo | CompressionAlgo | |
| level | Integer | Must be within the algorithm's valid range |

Compression levels are serialised as `"algo:level"` (e.g., `"zstd:3"`).

### 3.3 Snapshot Type

Two variants, serialised as lowercase strings:

| Variant | Serialised as |
|---------|---------------|
| Full | `"full"` |
| Incremental | `"incremental"` |

### 3.4 Snapshot

Represents a discovered snapshot on the filesystem.

| Field | Type | Notes |
|-------|------|-------|
| path | String | Absolute path to the snapshot directory |
| name | String | Directory name only (e.g., `backup.2024-01-15T143045Z`) |
| timestamp | DateTime (UTC) | Parsed from the snapshot name |
| snapshotType | SnapshotType | Full or Incremental |
| parent | Optional String | Path to parent snapshot, if incremental |
| uuid | String | Unique identifier |
| verified | Boolean | Whether verification checks have passed |

### 3.5 Retention Policy

| Field | Type | Default | Constraint |
|-------|------|---------|------------|
| hourly | Natural | 24 | >= 0 |
| daily | Natural | 7 | >= 0 |
| weekly | Natural | 4 | >= 0 |
| monthly | Natural | 6 | >= 0 |
| yearly | Natural | 2 | >= 0 |

A value of 0 disables that retention tier.

### 3.6 Optimisation Config

| Field | Type | Default | Constraint |
|-------|------|---------|------------|
| enabled | Boolean | true | |
| balanceThreshold | Percentage | 75 | 0–100, clamped on load |
| defragThreshold | Percentage | 50 | 0–100, clamped on load |

### 3.7 Chain Config

| Field | Type | Default | Constraint |
|-------|------|---------|------------|
| maxLength | Natural | 10 | Must be >= 1 |

### 3.8 YabbConfig

The complete configuration record, constructed from TOML file plus CLI overrides.

| Field | Type | Notes |
|-------|------|-------|
| srcDir | SourcePath | Distinct from DestPath and SnapshotDirPath |
| dstDir | DestPath | |
| snapshotDir | SnapshotDirPath | |
| compression | CompressionLevel | |
| compress | Boolean | Whether to pass `--compressed-data` to `btrfs send` (default: true) |
| retention | RetentionPolicy | |
| optimization | OptimisationConfig | |
| chain | ChainConfig | |
| debug | Boolean | CLI flag |
| dryRun | Boolean | CLI flag |
| forceFull | Boolean | CLI flag |
| minFreeSpace | Natural | In megabytes (default: 1024) |
| maxParallelJobs | Positive | Reserved for future use (default: 1) |
| retryCount | Positive | Number of retry attempts (default: 3) |
| retryDelay | Natural | Seconds between retries (default: 5) |

**Distinct path types**: SourcePath, DestPath, and SnapshotDirPath should be distinct types (newtypes wrapping strings) to prevent accidentally passing a source path where a destination path is expected.

### 3.9 Snapshot Metadata

The full record stored in extended attributes on each snapshot. See Section 7 for the xattr key names.

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| uuid | String | Yes | Unique identifier |
| timestamp | DateTime (UTC) | Yes | Snapshot creation time |
| snapshotType | SnapshotType | Yes | |
| parent | Optional String | Yes | Path or absent; serialised as `"none"` when absent |
| chainPosition | Natural | Yes | 0-indexed position in chain |
| chainLength | Natural | Yes | Total chain length |
| compression | String | Yes | Format: `"algo:level"` |
| source | Optional String | No | Source directory path |
| hostname | Optional String | No | System hostname |
| kernel | Optional String | No | Kernel version (`uname -r`) |
| fsUuid | Optional String | No | BTRFS filesystem UUID |
| fsLabel | Optional String | No | BTRFS filesystem label |
| platform | Optional String | No | Architecture (`uname -m`) |
| destination | Optional String | No | Destination directory path |
| sizeBytes | Int64 | No | Snapshot size (default: 0) |

### 3.10 Execution Statistics

Immutable statistics tracking, updated functionally (each update returns a new record).

| Field | Type | Notes |
|-------|------|-------|
| errors | Integer | Count of errors encountered |
| warnings | Integer | Count of warnings |
| snapshotsCreated | Integer | Number of snapshots created |
| snapshotsDeleted | Integer | Number of snapshots deleted |
| startTime | Float | Unix epoch timestamp when execution started |
| operations | List of String | Names of operations performed |

Operations that produce new stats records: `withError`, `withWarning`, `withSnapshotCreated`, `withSnapshotsDeleted(count)`, `withOperation(name)`, `combine(other)`.

### 3.11 Config Validation

**ConfigWarning** — a field name and a message string.

**ConfigValidationResult** — a list of ConfigWarning values. Supports functional accumulation via `withWarning(field, message)` and `combine(other)`.

### 3.12 Parent Validation State

A sum type with five variants, used for pattern matching during chain validation:

| Variant | Meaning |
|---------|---------|
| NoParentRef | Incremental snapshot has no parent reference in metadata |
| MissingParentPath | Parent is referenced but the path does not exist on the filesystem |
| ValidParent | Parent exists and is accessible |
| FullSnapshot | Snapshot is full — no parent needed |
| MetadataError | Could not read the snapshot's metadata |

### 3.13 Chain Info

| Field | Type | Notes |
|-------|------|-------|
| snapshots | List of Snapshot | All snapshots in the chain, sorted by timestamp |
| fullSnapshotCount | Integer | |
| incrementalCount | Integer | |
| totalSize | Int64 | Placeholder (currently 0) |
| chainLength | Integer | Total number of snapshots |
| isValid | Boolean | True if fullSnapshotCount > 0 or no snapshots exist |

### 3.14 Chain Diagnostics

**ChainIssue** — an enumeration of diagnostic categories:

| Variant | Display text |
|---------|-------------|
| MissingParent | `"Missing parent snapshot"` |
| MissingMetadata | `"Missing required metadata"` |
| InvalidChainPos | `"Invalid chain position"` |
| BrokenChain | `"Broken chain linkage"` |
| NotReadonly | `"Snapshot is not read-only"` |
| InvalidSubvolume | `"Not a valid btrfs subvolume"` |

**ChainDiagnostic** — a record with `path` (string), `issue` (ChainIssue), and `details` (string).

### 3.15 Constrained Ranges

The following constrained range types are defined for validation purposes. `Percentage` is used directly as a field type in `OptimisationConfig`. The remaining types are defined but used only for range-checking during parsing and validation — they are **not** used as struct field types. The corresponding struct fields use `Natural`, `Positive`, or `range[1..15]` instead (see Sections 3.7 and 3.8).

| Type name | Range | Used for | Used as field type? |
|-----------|-------|----------|---------------------|
| Percentage | 0–100 | Optimisation thresholds | Yes (`OptimisationConfig.balanceThreshold`, `.defragThreshold`) |
| ChainLength | 1–1000 | Chain max length validation | No (field uses `Natural`) |
| ChainPosition | 0–999 | Position within chain validation | No (field uses `Natural`) |
| RetryCount | 1–100 | Retry attempt validation | No (field uses `Positive`) |
| RetryDelaySeconds | 0–3600 | Retry delay validation | No (field uses `Natural`) |
| ZstdLevel | 1–15 | zstd compression level validation | No (`CompressionLevel.level` uses `range[1..15]`) |
| ZlibLevel | 1–9 | zlib compression level validation | No (validated via range check at parse time) |
| LzoLevel | 1–9 | lzo compression level validation | No (validated via range check at parse time) |

---

## 4. Error Model

### 4.1 Error Structure

Every error in the system is a value with three fields:

| Field | Type | Purpose |
|-------|------|---------|
| code | ExitCode | Maps to the process exit code |
| category | String | Short tag for log filtering |
| msg | String | Human-readable error description |

### 4.2 Error Categories

Each error category maps to a specific exit code:

| Category | Exit Code | Used for |
|----------|-----------|----------|
| `CONFIG` | ConfigMissing (3) | Config file not found or unparseable |
| `VALIDATION` | InvalidVar (5) | Config value out of range, invalid format |
| `PREREQ` | PrereqMissing (6) or DeviceErrors (10) | Missing tool, insufficient btrfs version, or BTRFS device errors |
| `BTRFS` | InvalidVar (5) | BTRFS operation failures |
| `CHANGES` | NoChanges (1) | No changes detected between snapshots |
| `DIR` | DirInvalid (7) | Directory missing, wrong permissions, not BTRFS |
| `ARG` | InvalidArgument (2) | Bad CLI arguments |
| `LOCK` | LockHeld (8) or LockError (9) | Lock contention or I/O error |
| `SHUTDOWN` | Shutdown (11) | Graceful termination via signal |
| `PROCESS` | InvalidVar (5) | External command execution failures |
| `PATH` | InvalidVar (5) or DirInvalid (7) | Path sanitisation failures (format/resolution errors use InvalidVar; existence/permission errors use DirInvalid) |

### 4.3 Execution Summary

At the end of the `run` command, log a summary containing:
- Status code
- Runtime (formatted as `Xs` or `Xm Ys`)
- Snapshots created and deleted counts
- Error and warning counts
- List of operations performed (joined with `, `)

The log level depends on outcome: error level if status != 0 or errors > 0; warning level if warnings > 0; info level otherwise.

---

## 5. Configuration

*This section is pure logic except for filesystem checks during validation.*

### 5.1 TOML Schema

```toml
[paths]
src_dir = "/data"           # Source directory to back up (must be on BTRFS)
dst_dir = "/backup"         # Destination for received snapshots (must be on BTRFS)
snapshot_dir = "/snapshots" # Local snapshot storage (must be on BTRFS)

[compression]
algorithm = "zstd"          # "zstd", "zlib", or "lzo"
level = 3                   # Algorithm-specific (see Section 3.2)
enabled = true              # Pass --compressed-data to btrfs send

[retention]
hourly = 24
daily = 7
weekly = 4
monthly = 6
yearly = 2

[options]
min_free_space = 1024       # Megabytes
max_parallel_jobs = 1       # Reserved for future use
retry_count = 3
retry_delay = 5             # Seconds

[optimization]
enabled = true
balance_threshold = 75      # Percentage (0–100)
defrag_threshold = 50       # Percentage (0–100)

[chain]
max_length = 10
```

### 5.2 Defaults

| Key | Default value |
|-----|---------------|
| `compression.algorithm` | `"zstd"` |
| `compression.level` | `3` |
| `compression.enabled` | `true` |
| `retention.hourly` | `24` |
| `retention.daily` | `7` |
| `retention.weekly` | `4` |
| `retention.monthly` | `6` |
| `retention.yearly` | `2` |
| `options.min_free_space` | `1024` |
| `options.max_parallel_jobs` | `1` |
| `options.retry_count` | `3` |
| `options.retry_delay` | `5` |
| `optimization.enabled` | `true` |
| `optimization.balance_threshold` | `75` |
| `optimization.defrag_threshold` | `50` |
| `chain.max_length` | `10` |

### 5.3 Config File Resolution Order

1. If the user specifies a non-default path via `--configPath`, use it directly
2. Otherwise, try `/etc/yabb.toml`
3. If not found, try `~/.config/yabb/yabb.toml` (XDG user config)
4. If neither exists, return an error listing both paths tried

### 5.4 Compression Level Parsing

Format: `"algo:level"` (e.g., `"zstd:3"`)

Parsing rules:
1. Split on `:`; must produce exactly 2 parts
2. First part must be `"zstd"`, `"zlib"`, or `"lzo"` (case-insensitive)
3. Second part must be a valid integer
4. Integer must be within the algorithm's range (Section 3.2)

### 5.5 Dependency Validation Warnings

After loading, check these rules. Violations produce **warnings** (logged but do not prevent operation):

1. `daily > 0` but `hourly == 0` — daily retention is set but hourly is disabled
2. `weekly > 0` but `daily == 0` — weekly set but daily disabled
3. `monthly > 0` but `weekly == 0` — monthly set but weekly disabled
4. `yearly > 0` but `monthly == 0` — yearly set but monthly disabled
5. `retryCount > 1` and `retryDelay < 1` — retries enabled but delay too short
6. `hourly > 0` and `hourly < 6` — hourly below recommended minimum of 6
7. `chain.maxLength > 50` — long chains may impact restore performance

### 5.6 Config Validation

After loading and warning checks, validate:

1. All three directories (srcDir, dstDir, snapshotDir) must exist
2. Source directory requires read + execute permissions
3. Destination and snapshot directories require read + write + execute permissions
4. All three directories must be on BTRFS filesystems (checked via `stat -f -c %T path`)
5. `chain.maxLength` must be >= 1

### 5.7 CLI Override Merging

The `debug`, `dryRun`, and `forceFull` flags from the CLI are merged onto the loaded config to produce a new config value (the original is not mutated).

> **Invariants:**
> - The `[paths]` section is mandatory. All three path keys are required.
> - Optimisation thresholds are clamped to 0–100 during loading (out-of-range values in TOML are silently clamped, not rejected).
> - The TOML key names use `snake_case` (e.g., `src_dir`, `max_length`, `retry_count`).

---

## 6. Retention Policy Engine

*This section is pure logic — no side effects, no filesystem access. It should be comprehensively unit-tested.*

### 6.1 Retention Periods

Five period types, in order of granularity:

| Period | Abbreviation |
|--------|-------------|
| Hourly | rpHourly |
| Daily | rpDaily |
| Weekly | rpWeekly |
| Monthly | rpMonthly |
| Yearly | rpYearly |

### 6.2 Period Boundary Calculation

Given a period type, a 0-indexed offset `index`, and a reference time (UTC), calculate the start and stop times of that period.

**Hourly:**
```
hourStart = referenceTime - (index + 1) hours
start = hourStart truncated to the top of the hour (minutes=0, seconds=0)
stop  = start + 1 hour - 1 second
```
Index 0 = the most recent complete hour.

**Daily:**
```
dayStart = referenceTime - (index + 1) days
start = dayStart at 00:00:00
stop  = start + 1 day - 1 second (i.e., 23:59:59 same day)
```
Index 0 = yesterday.

**Weekly:**
Weeks start on Monday (ISO 8601).
```
currentWeekday = referenceTime.dayOfWeek  (Monday=0, Tuesday=1, ..., Sunday=6)
mondayOffset   = currentWeekday
targetMonday   = referenceTime - (mondayOffset + 7 * index) days
start = targetMonday at 00:00:00
stop  = start + 7 days - 1 second
```
Index 0 = the Monday of the current week (which may be a partial week).

**Monthly:**
```
totalMonths = referenceTime.year * 12 + (referenceTime.month - 1) - index - 1
year  = totalMonths / 12            (integer division)
month = (totalMonths mod 12) + 1
start = first day of (year, month) at 00:00:00
stop  = first day of next month - 1 second
```
Index 0 = the previous calendar month. Handles year boundaries and varying month lengths (including leap year February).

**Yearly:**
```
targetYear = referenceTime.year - index - 1
start = January 1 of targetYear at 00:00:00
stop  = December 31 of targetYear at 23:59:59
```
Index 0 = the previous calendar year.

All times are UTC.

### 6.3 Period Key

Each period has a unique string key derived from a timestamp. **Note:** This function is defined but not called by the retention selection algorithm, which uses `getPeriodBoundaries()` and `isInPeriod()` directly instead. The keys are provided for potential future use or external tooling.

| Period | Key format | Example |
|--------|-----------|---------|
| Hourly | `"yyyy-MM-dd-HH"` | `"2024-01-15-14"` |
| Daily | `"yyyy-MM-dd"` | `"2024-01-15"` |
| Weekly | `"yyyy-WNN"` | `"2024-W03"` (week number = yearday / 7 + 1; this is **not** ISO 8601 week numbering) |
| Monthly | `"yyyy-MM"` | `"2024-01"` |
| Yearly | `"yyyy"` | `"2024"` |

### 6.4 Snapshot Selection Algorithm

Given a list of snapshots, a retention policy, and a reference time:

1. If the snapshot list is empty, return an empty keep set.
2. Sort snapshots by timestamp descending (newest first).
3. **Always keep the most recent snapshot** — add it to the keep set.
4. **Keep all snapshots in the current partial hour** — find the top of the current hour (referenceTime with minutes=0, seconds=0) and keep all snapshots with timestamps >= that boundary.
5. **For each retention tier**, in order (hourly, then daily, then weekly, then monthly, then yearly):
   - For each period index from 0 to (count - 1):
     - Calculate the period boundaries (Section 6.2)
     - Find all snapshots whose timestamps fall within [start, stop] inclusive
     - Among those, select the one with the latest timestamp
     - If that snapshot is not already in the keep set, add it
6. Return the keep set.

### 6.5 Full Snapshot Protection

After the selection algorithm (Section 6.4), apply this additional rule:

1. Find all snapshots whose `user.yabb.type` extended attribute equals `"full"` (read from the filesystem)
2. If at least one full snapshot exists AND none of them are in the keep set, add the **oldest** full snapshot to the keep set

This prevents total data loss by ensuring at least one complete base snapshot survives retention.

### 6.6 Deletion

After computing the keep set:

1. All snapshots **not** in the keep set are candidates for deletion
2. Delete each candidate via `btrfs subvolume delete`
3. In dry-run mode, log what would be deleted without actually deleting
4. Count and return the number of kept and deleted snapshots
5. Failed deletions are logged as warnings; they do not abort the process

### 6.7 Worked Example 1 — Basic Retention

```
Reference time: 2024-01-15T14:30:00Z
Policy: hourly=3, daily=2, weekly=0, monthly=0, yearly=0

Snapshots (newest first):
  S1: /snap/backup.2024-01-15T140000Z   (14:00 today)
  S2: /snap/backup.2024-01-15T133000Z   (13:30 today)
  S3: /snap/backup.2024-01-15T123000Z   (12:30 today)
  S4: /snap/backup.2024-01-15T113000Z   (11:30 today)
  S5: /snap/backup.2024-01-15T103000Z   (10:30 today)
  S6: /snap/backup.2024-01-14T200000Z   (20:00 yesterday)
  S7: /snap/backup.2024-01-14T100000Z   (10:00 yesterday)
  S8: /snap/backup.2024-01-13T150000Z   (15:00 two days ago)
```

Step-by-step:

| Step | Rule | Action | Keep set |
|------|------|--------|----------|
| 1 | Most recent | Keep S1 | {S1} |
| 2 | Current partial hour (14:00–14:30) | S1 already kept | {S1} |
| 3 | Hourly index 0 (13:00–13:59) | S2 at 13:30 is latest in range → keep | {S1, S2} |
| 4 | Hourly index 1 (12:00–12:59) | S3 at 12:30 is latest in range → keep | {S1, S2, S3} |
| 5 | Hourly index 2 (11:00–11:59) | S4 at 11:30 is latest in range → keep | {S1, S2, S3, S4} |
| 6 | Daily index 0 (2024-01-14 full day) | S6 at 20:00 and S7 at 10:00 in range; S6 is latest → keep | {S1, S2, S3, S4, S6} |
| 7 | Daily index 1 (2024-01-13 full day) | S8 at 15:00 in range → keep | {S1, S2, S3, S4, S6, S8} |

**Result:** Keep {S1, S2, S3, S4, S6, S8}. **Delete** {S5, S7}.

S5 (10:30 today) is not in any hourly period (10:00–10:59 is 4 hours back from 14:30, index 3, but hourly count is only 3). S7 (10:00 yesterday) loses to S6 (20:00 yesterday) as S6 is more recent within the same daily period.

### 6.8 Worked Example 2 — Month and Year Boundary

```
Reference time: 2024-02-01T10:00:00Z
Policy: hourly=0, daily=0, weekly=0, monthly=2, yearly=1

Snapshots:
  S1: /snap/backup.2024-02-01T080000Z   (today)
  S2: /snap/backup.2024-01-15T120000Z   (mid-January)
  S3: /snap/backup.2024-01-02T120000Z   (early January)
  S4: /snap/backup.2023-12-20T120000Z   (December 2023)
  S5: /snap/backup.2023-11-15T120000Z   (November 2023)
  S6: /snap/backup.2023-10-10T120000Z   (October 2023)
```

Monthly boundary calculation:
- Index 0: totalMonths = 2024×12 + (2−1) − 0 − 1 = 24288 → year=2024, month=1 → **January 2024** (Jan 1 to Jan 31)
- Index 1: totalMonths = 24287 → year=2023, month=12 → **December 2023** (Dec 1 to Dec 31)

Yearly boundary calculation:
- Index 0: targetYear = 2024 − 0 − 1 = 2023 → **2023** (Jan 1 to Dec 31)

| Step | Rule | Action | Keep set |
|------|------|--------|----------|
| 1 | Most recent | Keep S1 | {S1} |
| 2 | Current partial hour (10:00) | S1 already kept | {S1} |
| 3 | Monthly index 0 (Jan 2024) | S2 (Jan 15) and S3 (Jan 2) in range; S2 is latest → keep | {S1, S2} |
| 4 | Monthly index 1 (Dec 2023) | S4 (Dec 20) in range → keep | {S1, S2, S4} |
| 5 | Yearly index 0 (2023) | S4, S5, S6 in range; S4 is latest, already in keep set | {S1, S2, S4} |

**Result:** Keep {S1, S2, S4}. **Delete** {S3, S5, S6}.

S3 loses to S2 (both in January, S2 is more recent). S5 and S6 lose to S4 (all in 2023, S4 is most recent).

> **Invariants:**
> - The most recent snapshot is **always** kept, even if all retention counts are 0.
> - At least one full snapshot must survive retention (Section 6.5).
> - The selection algorithm is deterministic given the same inputs.
> - All times are UTC. The programme does not consider local time zones.

---

## 7. Snapshot Naming and Metadata

### 7.1 Naming Convention

Format: `backup.YYYY-MM-DDTHHMMSSZ`

- Prefix: `backup.` (literal, including the dot)
- Timestamp: UTC, no colons in time portion, literal `T` separator and `Z` suffix
- Example: `backup.2024-01-15T143045Z`
- Total timestamp portion length: 18 characters

Character-by-character validation of the timestamp portion (after stripping the `backup.` prefix):

| Positions | Content |
|-----------|---------|
| 0–3 | Digits (year) |
| 4 | Literal `-` |
| 5–6 | Digits (month) |
| 7 | Literal `-` |
| 8–9 | Digits (day) |
| 10 | Literal `T` |
| 11–12 | Digits (hour) |
| 13–14 | Digits (minute) |
| 15–16 | Digits (second) |
| 17 | Literal `Z` |

Timestamp parsing format string: `yyyy-MM-dd'T'HHmmss'Z'`

### 7.2 Extended Attribute Properties

All metadata is stored in the `user.yabb.*` extended attribute namespace using `setfattr` / `getfattr`.

**Required properties (7):**

| Attribute key | Format | Example value |
|---------------|--------|---------------|
| `user.yabb.uuid` | UUID string | `"550e8400-e29b-41d4-a716-446655440000"` |
| `user.yabb.timestamp` | `yyyy-MM-dd'T'HH:mm:ss'Z'` | `"2024-01-15T14:30:45Z"` |
| `user.yabb.type` | `"full"` or `"incremental"` | `"incremental"` |
| `user.yabb.parent` | Absolute path or `"none"` | `"/snapshots/backup.2024-01-14T120000Z"` |
| `user.yabb.chain.pos` | Integer string (0-indexed) | `"3"` |
| `user.yabb.chain.len` | Integer string | `"4"` |
| `user.yabb.compression` | `"algo:level"` | `"zstd:3"` |

**Note:** The timestamp format in metadata (`HH:mm:ss` with colons) differs from the snapshot name format (`HHmmss` without colons).

**The parent sentinel:** When a snapshot has no parent (i.e., it is a full snapshot), the `user.yabb.parent` property is set to the literal string `"none"`. When reading, treat `"none"` or empty string as absent.

**Optional properties (8):**

| Attribute key | Content |
|---------------|---------|
| `user.yabb.source` | Source directory path |
| `user.yabb.hostname` | System hostname (from `/etc/hostname`) |
| `user.yabb.kernel` | Kernel version (`uname -r` output) |
| `user.yabb.fs.uuid` | BTRFS filesystem UUID (from `btrfs filesystem show`) |
| `user.yabb.fs.label` | BTRFS filesystem label (from `btrfs filesystem label`) |
| `user.yabb.platform` | Architecture (`uname -m` output) |
| `user.yabb.destination` | Destination directory path |
| `user.yabb.size` | Size in bytes (integer string) |

**Write behaviour:** All 7 required properties must be set successfully or the operation fails. Optional properties are best-effort — log a warning on failure but do not abort.

**Read behaviour:** All 7 required properties must be readable or return an error. Optional properties default to absent/0 if unreadable.

### 7.3 Snapshot Verification

A snapshot passes verification if all 7 checks pass, in order:

1. The directory exists on the filesystem
2. It is a valid BTRFS subvolume (`btrfs subvolume show` succeeds)
3. It is read-only (`btrfs property get <path> ro` contains `"ro=true"`)
4. All 7 required extended attribute properties can be read
5. The directory name matches the naming convention (Section 7.1)
6. The timestamp in the name is parseable
7. If the snapshot is incremental (type = `"incremental"`), the parent path exists on the filesystem

Each check uses the retry mechanism (Section 13.2). In dry-run mode, verification always succeeds.

### 7.4 Listing Snapshots

To list snapshots in a directory:
1. Walk the directory entries
2. Filter to directories only
3. Filter to entries whose name starts with `"backup."`
4. Parse the timestamp from each name
5. Skip entries that fail to parse (log at debug level)
6. Return the valid snapshots (in directory listing order, not sorted)

**Note on snapshot type:** Listed snapshots have their `snapshotType` field set to `Full` as a default. The listing operation does not read extended attributes to determine the actual type. Code that needs the true snapshot type (e.g., retention full-snapshot protection, chain management) reads the `user.yabb.type` xattr directly via `getProperty()` or `getSnapshotMetadata()`.

> **Known bug:** The `status --json` output includes a `"type"` field for each snapshot (Section 14.4) that is populated from this default value, meaning it always reports `"full"` regardless of actual snapshot type. The internal chain and retention logic is unaffected because it reads xattrs independently.

### 7.5 Last Snapshot Tracking

The path of the most recently created snapshot is stored in `/var/run/yabb_last_snapshot`. This is used to quickly find the parent for incremental backups without scanning the directory.

- **Write:** Atomic — write to a `.tmp` file first, then rename (POSIX rename is atomic on the same filesystem)
- **Read:** Read the file, strip whitespace, verify the path exists on disk
- If the file is missing or the referenced path doesn't exist, fall back to directory scanning (Section 9)

---

## 8. BTRFS Operations Abstraction Layer

*This section is impure — every operation shells out to external commands.*

### 8.1 Command Execution

All external commands executed via `runCommand()`:
- Merge stderr into stdout for unified output capture
- Have a configurable timeout (default: 120 seconds). Long-running operations (balance, scrub, auto-optimisation defrag) pass an explicit ~1-week timeout.
- In dry-run mode, log the command that would have been executed and return success without running it
- Return a result containing the exit code and captured output

**Exception:** `runBtrfsSendReceive()` uses the system `execShellCmd()` function (required for shell pipe support) which has **no timeout mechanism**. The send/receive streaming pipe runs until completion or until an external signal terminates the process. See Section 8.2 for details.

### 8.2 Operations Reference

**Filesystem detection:**
- `isBtrfsFilesystem(path)` → `stat -f -c %T <path>`
  - Result: output equals `"btrfs"` (boolean)

**Filesystem usage:**
- `getFilesystemUsage(path)` → `btrfs filesystem usage -b <path>`
  - Parse output line by line. Lines of interest:
    - `"Device size: <N>"` → total bytes
    - `"Used: <N>"` → used bytes
    - `"Device unallocated: <N>"` → unallocated bytes
    - `"Free (estimated): <N>"` → available bytes
  - Return `(usedBytes, availableBytes)` tuple

**Subvolume operations:**
- `createSubvolume(path)` → `btrfs subvolume create <path>`
- `deleteSubvolume(path)` → `btrfs subvolume delete <path>`
- `createSnapshot(source, dest, readonly)` → `btrfs subvolume snapshot [-r] <source> <dest>`
  - The `-r` flag is added only if `readonly` is true
- `isSubvolume(path)` → `btrfs subvolume show <path>` — success if exit code is 0
- `isReadonly(path)` → `btrfs property get <path> ro` — check output contains `"ro=true"`
- `setReadonly(path, value)` → `btrfs property set <path> ro <true|false>`

**Property operations:**
- `setProperty(path, name, value)`:
  - If name starts with `"user."`: `setfattr -n <name> -v <value> <path>`
  - Otherwise: `btrfs property set <path> <name> <value>`
- `getProperty(path, name)`:
  - If name starts with `"user."`: `getfattr --only-values -n <name> <path>`
  - Otherwise: `btrfs property get <path> <name>` — parse output format `"name=value"`, split on `=`, return value portion

**Received UUID detection:**
- `getReceivedUuid(path)` → `btrfs subvolume show <path>`
  - Parse output for line starting with `"Received UUID:"`
  - Extract the UUID portion
  - Return absent if UUID is `"-"` or empty
- `isOrphanedDestSnapshot(path)` → true if `isSubvolume(path)` AND `getReceivedUuid(path)` returns absent

**Change detection (streaming):**
- `checkSendStreamHasContent(parent, current)` → shell command:
  ```
  btrfs send --quiet -p <parent> <current> 2>/dev/null | head -c 512 | wc -c
  ```
  - Parse the byte count from `wc -c` output
  - If byte count >= 300: changes exist (return true)
  - If byte count < 300: no changes (return false)
  - The `head -c 512` causes SIGPIPE to terminate `btrfs send` early — this is O(1) regardless of data size

**Send/receive (streaming):**
- `runBtrfsSendReceive(sendArgs, destDir)` → shell pipe:
  ```
  btrfs send <sendArgs...> | pv -pterb | btrfs receive <destDir>
  ```
  - `pv` flags: `-p` (progress), `-t` (timer), `-e` (ETA), `-r` (rate), `-b` (bytes transferred)
  - Executed via `execShellCmd()` (required for shell pipe syntax). **No timeout is enforced** — the pipe runs until completion. Graceful termination relies on the signal handling mechanism (Section 13.3), though note that signals may not propagate to the child shell process.
  - No temporary files — true streaming

**Space checking:**
- `checkFilesystemSpace(path, minFreeSpaceMB)` → `df -BM --output=avail <path>`
  - Parse the second line of output, remove all occurrences of `"M"` (via string replacement), convert to integer
  - Return error if available MB < minFreeSpaceMB

### 8.3 Chain Length Update

After creating a snapshot, update the `user.yabb.chain.len` property on **all** snapshots in the snapshot directory:
1. Walk the snapshot directory
2. Filter to directories starting with `"backup."`
3. Set `user.yabb.chain.len` to the new total count on each

---

## 9. Backup Workflow

*The `run` subcommand. This is impure — the main orchestration shell.*

### 9.1 Nine-Step Sequence

The backup workflow proceeds through 9 steps, with shutdown checks between major steps. If a shutdown signal is received, the workflow exits cleanly with exit code 11.

**Step 0 — Load config:**
Load and parse the TOML configuration file (Section 5). Apply CLI flag overrides.

**Step 1 — Check prerequisites:**
Verify root access, required commands, BTRFS features, `--compressed-data` support, device error pre-flight check. See Section 13.5.

**Step 2 — Acquire lock:**
Acquire an exclusive file lock on `/var/run/yabb.lock` with a 5-minute timeout. If the lock is held by another instance, **exit with code 0** (this is informational, not an error). If there is a real lock I/O error, exit with code 9.

*Shutdown check*

**Step 3 — Validate config:**
Verify directories exist, have correct permissions, and are on BTRFS. See Section 5.6.

**Step 4 — Check space:**
Check both source and destination have at least `minFreeSpace` MB available. Also verify kernel/filesystem supports the configured compression algorithm.

Check chain length: if the current chain length >= `chain.maxLength`, override `forceFull` to true.

*Shutdown check*

**Step 5 — Cleanup:**
Two cleanup operations (both non-fatal — log warnings and continue on failure):

1. **Incomplete snapshots:** Find and delete snapshots in the snapshot directory that are not read-only or are not valid subvolumes (Section 11.3)
2. **Orphaned destination snapshots:** Find and delete snapshots in the destination directory that have the `"backup."` prefix but no Received UUID (Section 11.4)

*Shutdown check*

**Step 6 — Create snapshot:**
Execute the snapshot decision and creation logic (Section 9.2 and 9.3). If the result is NoChanges (exit code 1), finish successfully.

*Shutdown check*

**Step 7 — Apply retention:**
Run the retention algorithm (Section 6) on the snapshot directory.

**Step 8 — Finalise:**
If auto-optimisation is enabled and the retention step deleted any snapshots, run storage optimisation (Section 12). This is non-fatal.

Release the lock. Clean up temporary files. Log the execution summary.

### 9.2 Snapshot Decision Logic

This determines whether to create a full or incremental snapshot.

1. If `forceFull` is true: **full snapshot** — skip all change detection.
2. Otherwise, find a parent snapshot candidate:
   a. Read `/var/run/yabb_last_snapshot` (the tracking file)
   b. If the tracking file is missing or the referenced path doesn't exist, scan the snapshot directory for the most recent snapshot that has all 7 required metadata properties
   c. If no candidate found: **full snapshot**
3. Verify the candidate snapshot (Section 7.3, 7 checks)
4. If verification fails:
   a. Scan the snapshot directory for an alternative valid snapshot
   b. If found and verified: use that as the parent
   c. If not found: **full snapshot**
5. Create a temporary read-only snapshot of the source for change detection
6. Run stream-based change detection between the parent and the temporary snapshot
7. Based on result:
   - No changes detected: return NoChanges (exit code 1) — **do not create a snapshot**
   - Changes detected: **incremental snapshot** using the verified parent
   - Detection failed: **full snapshot** (log warning)
8. Clean up the temporary snapshot (always, even on failure)

### 9.3 Snapshot Creation

Once the decision is made (full or incremental, with or without parent):

1. **Create writable snapshot** of the source directory (not read-only, because extended attributes cannot be set on read-only subvolumes)
2. **Generate UUID** for the snapshot (fallback to `"unknown-<unix_timestamp>"` if UUID generation fails)
3. **Set all metadata properties** (Section 7.2) — required properties must succeed
4. **Make the snapshot read-only** via `btrfs property set <path> ro true`
5. **Build send arguments:**
   - For full: `[--compressed-data] <snapshotPath>`
   - For incremental: `[--compressed-data] -c <parent> -p <parent> <snapshotPath>`
   - `--compressed-data` is included only if `config.compress` is true
6. **Stream send/receive:** `btrfs send <args> | pv -pterb | btrfs receive <destDir>`
   - Before retrying, check if a partial destination snapshot exists and clean it up
7. **On send failure:**
   - Delete the source snapshot to prevent chain corruption
   - **Never silently fall back** from incremental to full — return an error telling the user to use `--forceFull`
8. **Update chain length** on all snapshots in the directory (Section 8.3)
9. **Verify** both the source and destination snapshots (Section 7.3)
10. **Update the tracking file** (`/var/run/yabb_last_snapshot`) with the new snapshot path

> **Invariants:**
> - The programme never silently falls back from incremental to full on send failure. It fails with an error message recommending `--forceFull`.
> - Metadata must be set before the snapshot is made read-only (xattrs cannot be written to read-only subvolumes).
> - The temporary comparison snapshot is always cleaned up, even on failure (use a defer/finally/dispose pattern).
> - Cleanup failures during Step 5 are non-fatal — they do not abort the backup.

---

## 10. Chain Management

### 10.1 Chain Structure

A snapshot chain starts with a full snapshot and is followed by zero or more incremental snapshots, each referencing its parent via the `user.yabb.parent` extended attribute.

### 10.2 Chain Info

To get chain info for a snapshot directory:
1. List all valid snapshots (Section 7.4)
2. Sort by timestamp ascending (oldest first)
3. Count full vs incremental snapshots (by reading `user.yabb.type` from each)
4. Chain is valid if `fullSnapshotCount > 0` OR there are no snapshots at all

### 10.3 Chain Verification

To verify a chain:
1. Must have at least one full snapshot (error otherwise)
2. For each snapshot, determine its parent validation state (Section 3.12):
   - Metadata read failure → skip (debug log)
   - Full snapshot → valid (no parent needed)
   - Valid parent (path exists) → valid
   - No parent reference (incremental with no parent) → **invalid**
   - Missing parent path (path doesn't exist) → **invalid**
3. If any snapshot is invalid, log the specific issue
4. Additionally, verify chain depth consistency:
   - For each snapshot, traverse its parent chain to calculate actual depth
   - Compare to the stored `user.yabb.chain.pos` value
   - Log warnings for mismatches but do not fail

### 10.4 Chain Depth

To calculate the depth of a snapshot:
1. Start at the snapshot with depth 0
2. Read its metadata
3. If it's a full snapshot or has no parent: return current depth
4. Otherwise: recurse to the parent, incrementing depth
5. Safety limit: stop at depth 1000

### 10.5 Max Chain Length Enforcement

Before creating a snapshot, check if the current chain length >= `chain.maxLength`. If so, force a full snapshot regardless of the `forceFull` CLI flag. This prevents unbounded incremental chains.

---

## 11. Chain Recovery

### 11.1 Chain Diagnostics

For each snapshot in the directory, check (in this order — stop at first issue found per snapshot):

1. **Is it a valid BTRFS subvolume?** (`btrfs subvolume show`) — if not: `InvalidSubvolume`
2. **Is it read-only?** — if not: `NotReadonly` (indicates interrupted creation)
3. **Does it have all 7 required metadata properties?** — if not: `MissingMetadata`
4. **If incremental, does the parent reference exist?**
   - No parent defined: `MissingParent`
   - Parent path doesn't exist: `MissingParent`
   - Full snapshot or valid parent: no issue

Return the list of all diagnostics across all snapshots.

### 11.2 Recovery Process (4 steps)

**Step 1 — Find recovery point:**
Find the most recent full snapshot. If none, find the most recent snapshot with a recoverable parent chain (an ancestor that is a full snapshot exists).

**Step 2 — Rebuild from full snapshot (if found):**
- Keep the full snapshot and all snapshots newer than it
- Delete all snapshots older than the full snapshot
- Delete all snapshots without metadata

**Step 3 — Clean up incomplete snapshots:**
Find all snapshots diagnosed with `NotReadonly` or `InvalidSubvolume` and delete them.

**Step 4 — Repair chain metadata:**
Update the `user.yabb.chain.len` property on all remaining valid snapshots to reflect the actual count.

Return counts: incompletes cleaned, orphans removed, metadata repaired.

### 11.3 Incomplete Snapshot Cleanup

Used both in recovery and during the regular backup workflow (Step 5):
1. Run chain diagnostics (Section 11.1)
2. Filter to issues of type `NotReadonly` or `InvalidSubvolume`
3. Delete each via `btrfs subvolume delete`
4. Return (cleaned count, failed count)

### 11.4 Orphaned Destination Snapshot Cleanup

Used during the regular backup workflow (Step 5):
1. Walk the destination directory
2. Filter to directories starting with `"backup."`
3. For each, check if it's an orphaned destination snapshot (subvolume with no Received UUID)
4. Delete orphans via `btrfs subvolume delete`
5. Return (cleaned count, failed count)

---

## 12. Storage Optimisation

### 12.1 Operations

**Defragmentation:**
- Standalone (via `optimize` subcommand): `btrfs filesystem defragment -r <path>`
  - Uses the default command timeout (120 seconds). **Known bug:** large filesystems may cause this operation to be killed before completion.
- Auto-optimisation (after retention): `btrfs filesystem defragment -r -czstd <path>` (adds zstd compression during defrag)
  - Uses the long operation timeout (~1 week).

**Balance:**
```
btrfs balance start -dusage=5,limit=2 -musage=5,limit=4 <path>
```
- `-dusage=5,limit=2`: process data chunks with <= 5% utilisation, max 2 chunks
- `-musage=5,limit=4`: process metadata chunks with <= 5% utilisation, max 4 chunks
- This is a targeted, lightweight balance — not a full rebalance
- Uses the long operation timeout (~1 week).

**Scrub:**
```
btrfs scrub start -B <path>
```
- `-B`: blocking mode (waits for completion)
- Uses the long operation timeout (~1 week).

### 12.2 Compression Verification

Before creating a snapshot, verify the configured compression algorithm is supported:
1. Check for `/sys/fs/btrfs/features/compress_<algo>` (e.g., `compress_zstd`)
2. Fallback: read `/proc/crypto` and check if the algorithm name appears (case-insensitive)

### 12.3 Storage Efficiency

Parse `btrfs filesystem usage -b <path>` to calculate:
- `usagePercent = min(100, (usedBytes * 100) / totalBytes)`
- `fragPercent = max(0, min(100, 100 - ((usedBytes * 100) / (totalBytes - unallocatedBytes))))`

### 12.4 Auto-Optimisation

During the backup workflow (Step 8), if `optimization.enabled` is true and retention deleted at least one snapshot:
1. Calculate storage efficiency
2. If `fragPercent > defragThreshold`: run defrag with compression
3. If `usagePercent > balanceThreshold`: run balance
4. Both are non-fatal — log warnings on failure

### 12.5 The `optimize` Subcommand

Runs defrag, balance, and/or scrub individually based on CLI flags:
- `--defrag` (default: true)
- `--balance` (default: true)
- `--scrub` (default: false)

Reports the number of operations completed and failed.

### 12.6 Device Error Detection

```
btrfs device stats <path>
```
Parse each output line. If any line contains `"errors"` (case-insensitive) and the last token (the count) is > 0, device errors are present.

---

## 13. Infrastructure Utilities

### 13.1 File Locking

**Lock file path:** `/var/run/yabb.lock`

**Mechanism:** POSIX `fcntl` advisory file locking (exclusive write lock on the entire file).

**Acquisition:**
1. Open (or create) the lock file with read-write permissions (mode 0644)
2. Attempt a non-blocking lock (`F_SETLK`)
3. If it fails (lock held by another process), poll with 100ms sleep intervals
4. On success, write the current PID to the lock file
5. If the timeout expires (default: 300 seconds / 5 minutes), return a `LockHeld` error

**Release:**
1. Apply an unlock operation via `fcntl`
2. Close the file descriptor
3. Remove the lock file from the filesystem

**Two distinct error conditions:**
- **Lock held** (exit code 8): another YABB instance is running. The `run` command treats this as informational and exits with code **0** (not 8).
- **Lock I/O error** (exit code 9): permission denied, filesystem error, etc. This is a real error.

### 13.2 Retry with Exponential Backoff

A generic retry mechanism for any fallible operation.

**Parameters:**
- `maxAttempts`: maximum number of tries (1–100)
- `initialDelay`: seconds to wait before the first retry
- `operation`: the fallible function to retry
- `description`: label for log messages

**Behaviour:**
1. Execute the operation
2. If it succeeds, return the result
3. If it fails and attempts remain:
   a. Check shutdown flag — if set, abort immediately
   b. Sleep for `delay` seconds
   c. Check shutdown flag again after sleeping
   d. Double the delay: `nextDelay = min(delay * 2, 300)` (cap at 5 minutes)
   e. Retry from step 1

### 13.3 Signal Handling

**Handled signals** (all set a single atomic boolean shutdown flag):

| Signal | Trigger |
|--------|---------|
| SIGTERM | Standard termination (systemd stop) |
| SIGINT | Ctrl+C |
| SIGHUP | Terminal hangup |
| SIGQUIT | Ctrl+\\ (handled gracefully, no core dump) |
| SIGABRT | abort() cleanup |

**Ignored signals:**
- SIGPIPE — ignored so that broken pipes return EPIPE errors instead of crashing the process

**Shutdown check:** A function that reads the atomic flag and returns a Result — `Ok(())` if not shutdown, `Error(Shutdown)` if shutdown was requested. This is called between major workflow steps (Section 9.1).

The shutdown flag is the **only** mutable state in the system.

### 13.4 Path Sanitisation

All user-supplied paths are sanitised before use:

1. Strip leading/trailing whitespace
2. Strip trailing slashes
3. Reject empty string, `"."`, and `".."`
4. Convert to absolute path
5. Resolve symlinks (follow them to their real path)
6. Check length <= 4096 characters
7. Post-resolution security check: reject if path contains `"/../"`, `"/./`", or `"//"`

**Permission checking:** Use POSIX `access()` to verify read/write/execute permissions on the real user ID.

**Subpath detection:** Check if one path is a component-wise subpath of another (not just string prefix — `/var/logfiles` is NOT a subpath of `/var/log`).

### 13.5 Prerequisite Checking

The full prerequisite check sequence (Section 9, Step 1):

1. Verify running as root (EUID 0)
2. Check that all 12 prerequisite-checked commands exist (via `which`): `btrfs`, `pv`, `setfattr`, `getfattr`, `date`, `find`, `grep`, `awk`, `uuidgen`, `df`, `flock`, `mktemp`
3. Check `btrfs` tools work (`btrfs version`)
4. Check `btrfs send` supports `--compressed-data` (search `btrfs send --help` output)
5. Check BTRFS device for errors (`btrfs device stats`) — abort if errors found
6. Verify write access to: `/tmp`, parent directory of lock file, parent directory of last-snapshot tracking file

### 13.6 Temporary File Cleanup

During the finalisation step of the backup workflow:

1. Walk `/tmp` for files starting with `"yabb"` that are older than 1 hour — delete them
2. Walk the snapshot directory for directories starting with `"yabb-"` that are older than 1 hour — delete them as subvolumes

Skip in dry-run mode.

---

## 14. CLI Interface and Output

### 14.1 Subcommands and Flags

**`run`** — Execute backup

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--configPath` | | String | `/etc/yabb.toml` | Config file path |
| `--debug` | `-d` | Boolean | false | Enable debug logging |
| `--dryRun` | `-n` | Boolean | false | Show what would happen without changes |
| `--forceFull` | `-f` | Boolean | false | Force full snapshot |
| `--json` | `-j` | Boolean | false | JSON output format |

**`validate`** — Check configuration and prerequisites

Performs three checks in sequence:
1. Load and parse the TOML configuration file
2. Validate configuration (directories exist, correct permissions, on BTRFS, chain length valid — see Section 5.6)
3. Run the full prerequisite check (root access, required commands, BTRFS features, `--compressed-data` support, device errors — see Section 13.5)

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--configPath` | | String | `/etc/yabb.toml` | Config file path |
| `--json` | `-j` | Boolean | false | JSON output format |

**`status`** — Show snapshot status

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--configPath` | | String | `/etc/yabb.toml` | Config file path |
| `--json` | `-j` | Boolean | false | JSON output format |

**`optimize`** — Storage maintenance

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--configPath` | | String | `/etc/yabb.toml` | Config file path |
| `--dryRun` | `-n` | Boolean | false | Dry run |
| `--defrag` | | Boolean | true | Run defragmentation |
| `--balance` | | Boolean | true | Run balance |
| `--scrub` | | Boolean | false | Run scrub |
| `--json` | `-j` | Boolean | false | JSON output format |

**`health`** — Chain integrity

| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--configPath` | | String | `/etc/yabb.toml` | Config file path |
| `--repair` | `-r` | Boolean | false | Attempt to repair issues |
| `--json` | `-j` | Boolean | false | JSON output format |

### 14.2 Version

The programme supports `--version` to display the version string.

### 14.3 Text Output Mode (default)

When stdout is a TTY:
- **Success messages:** Green `✓` prefix
- **Info messages:** Cyan `ℹ` prefix
- **Error messages:** Red `✗` prefix (written to stderr)
- **Progress:** `[3/9] Creating backup snapshot...` step indicators
- **Spinners:** Braille animation during individual operations
- **Tables:** Aligned key-value pairs with dimmed keys

When stdout is NOT a TTY:
- Plain text without colour codes
- Unicode symbols (`✓`, `ℹ`, `✗`) are still used for user-facing messages (the `useUnicode` flag defaults to true and is not toggled by TTY detection)
- Spinner/operation completion indicators fall back to `[OK]`/`[FAILED]`
- No spinners or cursor manipulation
- Structured log messages instead of progress indicators

### 14.4 JSON Output Mode

When `--json` is passed, all output is structured JSON. No progress indicators, no colour codes.

**Generic messages:**
```json
{"status": "success", "message": "..."}
{"status": "error", "message": "..."}
{"status": "info", "message": "..."}
```

**`validate` success:**
```json
{
  "status": "valid",
  "config": {
    "srcDir": "/data",
    "dstDir": "/backup",
    "snapshotDir": "/snapshots",
    "compression": {"algorithm": "zstd", "level": 3},
    "retention": {"hourly": 24, "daily": 7, "weekly": 4, "monthly": 6, "yearly": 2}
  }
}
```

**`status`:**
```json
{
  "snapshotCount": 5,
  "snapshots": [
    {"name": "backup.2024-01-15T143045Z", "path": "/snap/...", "timestamp": "...", "type": "full"}
  ],
  "sourceUsage": {"usedBytes": 1073741824, "availableBytes": 5368709120},
  "destUsage": {"usedBytes": 2147483648, "availableBytes": 3221225472}
}
```
The `sourceUsage` and `destUsage` fields are only present if the usage query succeeds.

**`optimize`:**
```json
{
  "status": "success",
  "operationsCompleted": 2,
  "errors": 0,
  "dryRun": false
}
```
Status is `"success"` if all operations passed, `"partial"` if any failed.

**`health`:**
```json
{
  "status": "healthy",
  "chainLength": 5,
  "fullSnapshots": 1,
  "incrementalSnapshots": 4,
  "isValid": true,
  "deviceErrors": false,
  "issues": [],
  "issueCount": 0
}
```
Status is `"healthy"` if no issues and no device errors, `"issues"` otherwise.

If `--repair` was used and repair was performed:
```json
{
  "incompletesCleaned": 1,
  "orphansRemoved": 0,
  "metadataRepaired": 3
}
```

### 14.5 Status Display (text mode)

The `status` subcommand shows:
- Snapshot directory path
- Total snapshot count
- Source and destination disk usage (in MB)
- Up to 5 snapshots (in directory listing order, not sorted by timestamp) with name and formatted timestamp (`yyyy-MM-dd HH:mm`)

### 14.6 Health Display (text mode)

The `health` subcommand shows:
- Snapshot directory path
- Chain length, full count, incremental count
- Chain validity (Yes/No)
- Device errors (Yes/No)
- Each issue with path and description
- If repair was performed: counts of cleaned, orphaned, and repaired snapshots

---

## 15. systemd Integration

### 15.1 Service Unit

- Type: `oneshot` (runs once and exits)
- ExecStart: `/opt/yabb/yabb run`
- Timeouts: 3600s start, 120s stop
- Resource priority: Nice=19, idle I/O scheduling, idle CPU scheduling
- Security hardening: capability bounding set (CAP_SYS_ADMIN and related), syscall filter, private network, memory protection
- Logging: stdout and stderr to journald, syslog identifier `"yabb"`

Condition checks: only runs if `/opt/yabb/yabb` and `/etc/yabb.toml` both exist.

See Appendix B for the full unit file.

### 15.2 Timer Unit

- Schedule: daily at 00:00
- `Persistent=true` — runs missed backups after boot
- `RandomizedDelaySec=1800` — spreads load across 30 minutes
- `DeferReactivation=yes` — won't re-trigger if the service is still running

See Appendix C for the full timer file.

### 15.3 journald Logging

When systemd journal integration is available (detected at startup), the programme forwards summary messages to journald with appropriate priority levels:
- `info` for successful completion
- `warning` for completion with warnings
- `err` for completion with errors

---

## 16. Exit Codes and Process Model

| Exit Code | Name | Semantics |
|-----------|------|-----------|
| 0 | Success | Operation completed successfully |
| 1 | NoChanges | No changes detected since last snapshot — this is not an error |
| 2 | InvalidArgument | Bad CLI arguments |
| 3 | ConfigMissing | Configuration file not found |
| 4 | MissingVar | Required configuration variable missing |
| 5 | InvalidVar | Invalid configuration or BTRFS operation error |
| 6 | PrereqMissing | Required tool or capability missing |
| 7 | DirInvalid | Directory does not exist, wrong permissions, or not on BTRFS |
| 8 | LockHeld | Lock held by another instance |
| 9 | LockError | Lock file I/O error |
| 10 | DeviceErrors | BTRFS device has errors |
| 11 | Shutdown | Clean shutdown via signal |

### Special Cases

- **Exit code 1 (NoChanges):** Returned by `run` when `btrfs send` detects no changes between the parent and current snapshots. This is success — no snapshot is created, and the process exits cleanly.
- **Exit code 8 (LockHeld):** The internal error code is 8, but the `run` command maps this to **process exit code 0** because another instance running is an informational condition, not a failure.
- **Exit code 11 (Shutdown):** Returned when a signal (SIGTERM, SIGINT, etc.) is received during operation. The programme cleans up (releases lock, removes temp files) before exiting.

---

## 17. Acceptance Criteria

### 17.1 Retention Period Boundaries

Test these with `referenceTime = 2024-01-15T14:30:00Z`:

| Period | Index | Expected start | Expected stop |
|--------|-------|---------------|---------------|
| Hourly | 0 | 2024-01-15 13:00:00 | 2024-01-15 13:59:59 |
| Hourly | 1 | 2024-01-15 12:00:00 | 2024-01-15 12:59:59 |
| Daily | 0 | 2024-01-14 00:00:00 | 2024-01-14 23:59:59 |
| Monthly (ref: 2024-02-15) | 0 | 2024-01-01 00:00:00 | 2024-01-31 23:59:59 |
| Monthly (ref: 2024-03-15) | 0 | 2024-02-01 00:00:00 | 2024-02-29 23:59:59 (leap year) |
| Monthly (ref: 2024-01-15) | 0 | 2023-12-01 00:00:00 | 2023-12-31 23:59:59 (year boundary) |
| Yearly (ref: 2024-06-15) | 0 | 2023-01-01 00:00:00 | 2023-12-31 23:59:59 |

### 17.2 Period Key Generation

With timestamp `2024-01-15T14:30:00Z`:

| Period | Expected key |
|--------|-------------|
| Hourly | `"2024-01-15-14"` |
| Daily | `"2024-01-15"` |
| Monthly | `"2024-01"` |
| Yearly | `"2024"` |

### 17.3 isInPeriod

Period: 2024-01-01 00:00:00 to 2024-01-31 23:59:59

| Timestamp | Expected |
|-----------|----------|
| 2024-01-15 12:00:00 | true |
| 2023-12-31 23:59:59 | false |
| 2024-02-01 00:00:00 | false |
| 2024-01-01 00:00:00 (start boundary) | true |
| 2024-01-31 23:59:59 (end boundary) | true |

### 17.4 Snapshot Selection

**Empty list:** returns empty set.

**Single snapshot with all-zero policy:** The single snapshot is still kept (most recent is always kept).

**Two snapshots with all-zero policy:** Only the newest is kept.

### 17.5 Compression Level Parsing

| Input | Expected result |
|-------|----------------|
| `"zstd:3"` | Ok(Zstd, 3) |
| `"zlib:6"` | Ok(Zlib, 6) |
| `"lzo:1"` | Ok(Lzo, 1) |
| `"zstd:15"` | Ok(Zstd, 15) — max zstd level |
| `"zstd:16"` | Error — out of range |
| `"zlib:10"` | Error — out of range (max 9) |
| `"zstd"` | Error — no colon |
| `"zstd:"` | Error — empty level |
| `":3"` | Error — no algorithm |
| `""` | Error — empty string |
| `"gzip:5"` | Error — unknown algorithm |
| `"zstd:abc"` | Error — non-numeric level |

### 17.6 Exit Code Values

Verify that each exit code enum member has the correct integer value (0 through 11 as listed in Section 3.1).

### 17.7 Path Sanitisation

| Input | Expected |
|-------|----------|
| `""` | Error |
| `"   "` | Error |
| `"."` | Error |
| `".."` | Error |
| `"/"` | Error |
| `"/var"` (if exists) | Ok(`"/var"`) |
| Non-existent path | Error |

### 17.8 Integration Tests

The following require a real BTRFS filesystem and root access — separate from pure unit tests:

- Creating and deleting subvolumes
- Creating read-only snapshots
- Setting and reading extended attributes
- `btrfs send | btrfs receive` pipeline
- File locking between processes
- Signal handling and graceful shutdown

---

## Appendix A: Reference Configuration File

```toml
# YABB - Yet Another BTRFS Backup
# Example configuration file
# Copy to /etc/yabb.toml and customize

[paths]
# Source directory to backup (must be on btrfs)
src_dir = "/data"

# Destination for received snapshots (must be on btrfs)
dst_dir = "/backup"

# Directory to store local snapshots (must be on btrfs)
snapshot_dir = "/snapshots"

[compression]
# Compression algorithm: zstd, zlib, or lzo
algorithm = "zstd"

# Compression level (1-15 for zstd, 1-9 for zlib/lzo)
level = 3

# Pass --compressed-data to btrfs send
enabled = true

[retention]
# Number of snapshots to keep per time period
hourly = 24    # Keep 24 hourly snapshots
daily = 7      # Keep 7 daily snapshots
weekly = 4     # Keep 4 weekly snapshots
monthly = 6    # Keep 6 monthly snapshots
yearly = 2     # Keep 2 yearly snapshots

[options]
# Minimum free space required (MB)
min_free_space = 1024

# Maximum parallel operations (reserved for future use)
max_parallel_jobs = 1

# Retry attempts for failed operations
retry_count = 3

# Delay between retries (seconds)
retry_delay = 5

[optimization]
# Enable auto-optimization after retention
enabled = true

# Usage percentage threshold for balance operation (0-100)
balance_threshold = 75

# Fragmentation percentage threshold for defragmentation (0-100)
defrag_threshold = 50

[chain]
# Maximum incremental chain length before forcing a full snapshot
max_length = 10
```

---

## Appendix B: systemd Service Unit

```ini
[Unit]
Description=YABB BTRFS Backup
Documentation=https://github.com/aryonoco/yabb
After=local-fs.target

# Only run if binary and config exist
ConditionPathExists=/opt/yabb/yabb
ConditionPathExists=/etc/yabb.toml


[Service]
Type=oneshot
RemainAfterExit=no

# Run the backup
ExecStart=/opt/yabb/yabb run

# Timeouts (allow long backups)
TimeoutStartSec=3600
TimeoutStopSec=120

# Resource Priority (low impact on system)
Nice=19
IOSchedulingClass=idle
IOSchedulingPriority=7
CPUSchedulingPolicy=idle

# Filesystem & Mount Isolation
PrivateTmp=yes
PrivateMounts=yes
ProtectHome=yes
ProtectProc=invisible
ProcSubset=pid

# Kernel Protection
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectClock=yes
ProtectHostname=yes

# Privilege Restriction
LockPersonality=yes
RestrictSUIDSGID=yes

# Capabilities for complete BTRFS backup/restore
CapabilityBoundingSet=CAP_SYS_ADMIN CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH CAP_FOWNER CAP_FSETID CAP_CHOWN CAP_MKNOD CAP_SETFCAP CAP_LINUX_IMMUTABLE CAP_MAC_ADMIN
AmbientCapabilities=CAP_SYS_ADMIN CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH CAP_FOWNER CAP_FSETID CAP_CHOWN CAP_SETFCAP CAP_LINUX_IMMUTABLE CAP_MAC_ADMIN

# System Call Filtering
SystemCallArchitectures=native
SystemCallFilter=@system-service @mount
SystemCallFilter=~@clock @cpu-emulation @debug @obsolete @reboot @swap
SystemCallErrorNumber=EPERM

# Network (not needed for local backup)
PrivateNetwork=yes
IPAddressDeny=any
RestrictAddressFamilies=AF_UNIX

# Namespace Isolation
RestrictNamespaces=~user pid net uts
KeyringMode=private

# Memory Protection
MemoryDenyWriteExecute=yes
RestrictRealtime=yes

# Resource Limits
LimitNOFILE=65535
LimitNPROC=512
TasksMax=64
MemoryMax=2G

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=yabb
LogLevelMax=info


[Install]
WantedBy=multi-user.target
```

---

## Appendix C: systemd Timer Unit

```ini
[Unit]
Description=Daily YABB Backup
Documentation=https://github.com/aryonoco/yabb


[Timer]
# Run daily (00:00)
OnCalendar=daily

# Run missed backups after boot
Persistent=true

# Spread load: randomise start within 30 minutes
RandomizedDelaySec=1800

# Don't re-trigger if service still running
DeferReactivation=yes


[Install]
WantedBy=timers.target
```
