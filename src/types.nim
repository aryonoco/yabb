# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2023-2026 Aryan Ameri
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#

## Core domain types for YABB
## Uses Result[T, E] from nim-results for explicit error handling

# Pure module - enable maximum strict modes
{.experimental: "strictFuncs".}
{.experimental: "strictCaseObjects".}

import std/[times, strutils]
import results
export results # Re-export for Opt[T] usage

type
  # =============================================================================
  # Range types for compile-time validation
  # =============================================================================
  Percentage* = range[0 .. 100] ## Constrained percentage value (0-100)

  # Chain constraints
  ChainLength* = range[1 .. 1000] ## Maximum snapshots in a chain
  ChainPosition* = range[0 .. 999] ## Position within a chain (0-indexed)

  # Retry constraints
  RetryCount* = range[1 .. 100] ## Number of retry attempts
  RetryDelaySeconds* = range[0 .. 3600] ## Delay between retries in seconds

  # =============================================================================
  # Distinct types for type safety (newtype pattern)
  # =============================================================================

  # File system paths - prevent mixing source/dest/config paths
  SourcePath* = distinct string ## Source directory path for backups
  DestPath* = distinct string ## Destination directory path for backups
  SnapshotDirPath* = distinct string ## Snapshot directory within dest

# =============================================================================
# Borrowing for string-based distinct types
# =============================================================================
template borrowStringOps(T: typedesc) =
  proc `$`*(x: T): string {.borrow.}
  proc `==`*(a, b: T): bool {.borrow.}
  proc len*(x: T): int {.borrow.}

borrowStringOps(SourcePath)
borrowStringOps(DestPath)
borrowStringOps(SnapshotDirPath)

type
  ExitCode* = enum
    ecSuccess = 0
    ecNoChanges = 1
    ecInvalidArgument = 2
    ecConfigMissing = 3
    ecMissingVar = 4
    ecInvalidVar = 5
    ecPrereqMissing = 6
    ecDirInvalid = 7
    ecLockHeld = 8 # Lock held by another instance (not an error, exit 0 in CLI)
    ecLockError = 9 # Lock file I/O error (permission denied, etc.)
    ecDeviceErrors = 10 # BTRFS device has errors
    ecShutdown = 11 # Clean shutdown via signal (SIGTERM, SIGINT, etc.)

  CompressionAlgo* = enum
    caZstd = "zstd"
    caZlib = "zlib"
    caLzo = "lzo"

  # Algorithm-specific level ranges (compile-time safety)
  ZstdLevel* = range[1 .. 15] ## zstd compression level (1-15)
  ZlibLevel* = range[1 .. 9] ## zlib compression level (1-9)
  LzoLevel* = range[1 .. 9] ## lzo compression level (1-9)

  # Legacy type alias for compatibility
  CompressionLevel* = object
    algo*: CompressionAlgo
    level*: range[1 .. 15]

  SnapshotType* = enum
    stFull = "full"
    stIncremental = "incremental"

  Snapshot* = object
    path*: string
    name*: string
    timestamp*: DateTime
    snapshotType*: SnapshotType
    parent*: Opt[string] # Use Opt[T] from nim-results for consistency
    uuid*: string
    verified*: bool

  RetentionPolicy* = object
    hourly*: Natural
    daily*: Natural
    weekly*: Natural
    monthly*: Natural
    yearly*: Natural

  OptimizationConfig* = object
    enabled*: bool ## Enable auto-optimization after retention
    balanceThreshold*: Percentage ## Usage percent threshold for balance
    defragThreshold*: Percentage ## Fragmentation percent threshold

  ChainConfig* = object
    maxLength*: Natural # Maximum chain length before forcing full snapshot

  YabbConfig* = object
    srcDir*: SourcePath
    dstDir*: DestPath
    snapshotDir*: SnapshotDirPath
    compression*: CompressionLevel
    compress*: bool # Whether to use --compressed-data on btrfs send (default: true)
    retention*: RetentionPolicy
    optimization*: OptimizationConfig
    chain*: ChainConfig
    debug*: bool
    dryRun*: bool
    forceFull*: bool
    minFreeSpace*: Natural # MB
    maxParallelJobs*: Positive
    retryCount*: Positive
    retryDelay*: Natural # seconds

  YabbError* = object
    ## Error type for YABB operations - used with Result[T, YabbError]
    ## Not an exception - errors are returned via Result, not raised
    code*: ExitCode
    category*: string
    msg*: string

  YabbResult*[T] = Result[T, YabbError]

  # Execution statistics for tracking errors/warnings without global state
  ExecutionStats* = object
    errors*: int
    warnings*: int
    snapshotsCreated*: int
    snapshotsDeleted*: int
    startTime*: float ## Unix epoch timestamp when execution started
    operations*: seq[string] ## List of operations performed

  # Configuration validation types - pure functional approach
  ConfigWarning* = object ## Immutable warning from config validation
    field*: string
    message*: string

  ConfigValidationResult* = object ## Immutable result of config dependency validation
    warnings*: seq[ConfigWarning]

  # =============================================================================
  # Object Variants for Pattern Matching (ADTs / Sum Types)
  # =============================================================================
  ParentValidationState* = enum
    ## Represents the validation state of a snapshot's parent reference.
    ## Used with fusion/matching for exhaustive pattern matching.
    pvsNoParentRef ## Incremental has no parent defined
    pvsMissingParentPath ## Parent defined but path doesn't exist
    pvsValidParent ## Parent exists and is accessible
    pvsFullSnapshot ## Full snapshot, no parent needed
    pvsMetadataError ## Could not read metadata

  ParsedUsageLineKind* = enum
    ## Kind of btrfs filesystem usage output line
    pulDeviceSize
    pulUsed
    pulDeviceUnallocated
    pulFreeEstimated
    pulUnknown

  ParsedUsageLine* = object
    ## Parsed btrfs filesystem usage line for pattern matching.
    ## Each variant holds the extracted value from that line type.
    case kind*: ParsedUsageLineKind
    of pulDeviceSize, pulDeviceUnallocated, pulFreeEstimated:
      bytes*: int64
    of pulUsed:
      usedBytes*: int64
    of pulUnknown:
      discard

{.push raises: [].}

# ExecutionStats functional operations
func initStats*(startTime: float = 0.0): ExecutionStats =
  ExecutionStats(
    errors: 0,
    warnings: 0,
    snapshotsCreated: 0,
    snapshotsDeleted: 0,
    startTime: startTime,
    operations: @[],
  )

func withError*(s: ExecutionStats): ExecutionStats =
  ExecutionStats(
    errors: s.errors + 1,
    warnings: s.warnings,
    snapshotsCreated: s.snapshotsCreated,
    snapshotsDeleted: s.snapshotsDeleted,
    startTime: s.startTime,
    operations: s.operations,
  )

func withWarning*(s: ExecutionStats): ExecutionStats =
  ExecutionStats(
    errors: s.errors,
    warnings: s.warnings + 1,
    snapshotsCreated: s.snapshotsCreated,
    snapshotsDeleted: s.snapshotsDeleted,
    startTime: s.startTime,
    operations: s.operations,
  )

func withSnapshotCreated*(s: ExecutionStats): ExecutionStats =
  ExecutionStats(
    errors: s.errors,
    warnings: s.warnings,
    snapshotsCreated: s.snapshotsCreated + 1,
    snapshotsDeleted: s.snapshotsDeleted,
    startTime: s.startTime,
    operations: s.operations,
  )

func withSnapshotsDeleted*(s: ExecutionStats, count: int): ExecutionStats =
  ExecutionStats(
    errors: s.errors,
    warnings: s.warnings,
    snapshotsCreated: s.snapshotsCreated,
    snapshotsDeleted: s.snapshotsDeleted + count,
    startTime: s.startTime,
    operations: s.operations,
  )

func withOperation*(s: ExecutionStats, op: string): ExecutionStats =
  ExecutionStats(
    errors: s.errors,
    warnings: s.warnings,
    snapshotsCreated: s.snapshotsCreated,
    snapshotsDeleted: s.snapshotsDeleted,
    startTime: s.startTime,
    operations: s.operations & @[op],
  )

func combine*(a, b: ExecutionStats): ExecutionStats =
  ExecutionStats(
    errors: a.errors + b.errors,
    warnings: a.warnings + b.warnings,
    snapshotsCreated: a.snapshotsCreated + b.snapshotsCreated,
    snapshotsDeleted: a.snapshotsDeleted + b.snapshotsDeleted,
    startTime: a.startTime,
    operations: a.operations & b.operations,
  )

# ConfigValidationResult functional operations
func initValidationResult*(): ConfigValidationResult =
  ConfigValidationResult(warnings: @[])

func withWarning*(
    r: ConfigValidationResult, field, message: string
): ConfigValidationResult =
  ConfigValidationResult(
    warnings: r.warnings & @[ConfigWarning(field: field, message: message)]
  )

func hasWarnings*(r: ConfigValidationResult): bool =
  r.warnings.len > 0

func combine*(a, b: ConfigValidationResult): ConfigValidationResult =
  ConfigValidationResult(warnings: a.warnings & b.warnings)

# =============================================================================
# ParsedUsageLine helpers
# =============================================================================

func parseBtrfsUsageLine*(line: string): ParsedUsageLine =
  ## Parse a single line from btrfs filesystem usage output.
  ## Returns a typed ParsedUsageLine for pattern matching.
  let trimmed = line.strip()
  let parts = trimmed.split()

  if trimmed.startsWith("Device size:") and parts.len >= 3:
    ParsedUsageLine(
      kind: pulDeviceSize,
      bytes: (
        try:
          parseBiggestInt(parts[2])
        except ValueError:
          0'i64
      ),
    )
  elif trimmed.startsWith("Used:") and parts.len >= 2:
    ParsedUsageLine(
      kind: pulUsed,
      usedBytes: (
        try:
          parseBiggestInt(parts[1])
        except ValueError:
          0'i64
      ),
    )
  elif trimmed.startsWith("Device unallocated:") and parts.len >= 3:
    ParsedUsageLine(
      kind: pulDeviceUnallocated,
      bytes: (
        try:
          parseBiggestInt(parts[2])
        except ValueError:
          0'i64
      ),
    )
  elif trimmed.startsWith("Free (estimated):") and parts.len >= 3:
    ParsedUsageLine(
      kind: pulFreeEstimated,
      bytes: (
        try:
          parseBiggestInt(parts[2])
        except ValueError:
          0'i64
      ),
    )
  else:
    ParsedUsageLine(kind: pulUnknown)

# Constants
const
  DefaultConfigPath* = "/etc/yabb.toml"
  UserConfigPath* = "~/.config/yabb/yabb.toml" ## XDG-compliant user config location
  LockFile* = "/var/run/yabb.lock"
  LastSnapshotFile* = "/var/run/yabb_last_snapshot"
  TempSendPrefix* = "yabb-send"
  TempComparePrefix* = "yabb-compare"
  SnapshotPrefix* = "backup."

  # Optimization defaults
  DefaultAutoOptimize* = true
  DefaultBalanceThreshold*: Percentage = 75 ## Percent usage
  DefaultDefragThreshold*: Percentage = 50 ## Percent fragmentation

  # Chain defaults
  DefaultMaxChainLength* = 10

{.pop.}
