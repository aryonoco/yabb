## Core domain types for YABB
## Uses Result[T, E] from nim-results for explicit error handling

# Pure module - enable maximum strict modes
{.experimental: "strictFuncs".}
{.experimental: "strictCaseObjects".}

import std/[times, strutils]
import results
export results  # Re-export for Opt[T] usage

type
  # =============================================================================
  # Range types for compile-time validation
  # =============================================================================
  Percentage* = range[0..100]  ## Constrained percentage value (0-100)

  # Chain constraints
  ChainLength* = range[1..1000]     ## Maximum snapshots in a chain
  ChainPosition* = range[0..999]    ## Position within a chain (0-indexed)

  # Retry constraints
  RetryCount* = range[1..100]       ## Number of retry attempts
  RetryDelaySeconds* = range[0..3600] ## Delay between retries in seconds

  # =============================================================================
  # Distinct types for type safety (newtype pattern)
  # =============================================================================

  # File system paths - prevent mixing source/dest/config paths
  SourcePath* = distinct string       ## Source directory path for backups
  DestPath* = distinct string         ## Destination directory path for backups
  ConfigPath* = distinct string       ## Configuration file path
  SnapshotDirPath* = distinct string  ## Snapshot directory within dest

  # Legacy path types (keep for compatibility)
  SnapshotPath* = distinct string     ## Path to a snapshot directory
  SnapshotName* = distinct string     ## Name of a snapshot (without path)

  # Identifiers
  Uuid* = distinct string             ## UUID string value

  # Time types
  UnixTimestamp* = distinct int64     ## Unix timestamp in seconds

  # Size types (prevent mixing bytes/megabytes)
  Bytes* = distinct int64             ## Size in bytes
  Megabytes* = distinct Natural       ## Size in megabytes

# =============================================================================
# Borrowing for string-based distinct types
# =============================================================================
template borrowStringOps(T: typedesc) =
  proc `$`*(x: T): string {.borrow.}
  proc `==`*(a, b: T): bool {.borrow.}
  proc len*(x: T): int {.borrow.}

borrowStringOps(SourcePath)
borrowStringOps(DestPath)
borrowStringOps(ConfigPath)
borrowStringOps(SnapshotDirPath)
borrowStringOps(SnapshotPath)
borrowStringOps(SnapshotName)
borrowStringOps(Uuid)

# =============================================================================
# Borrowing for numeric distinct types
# =============================================================================
proc `$`*(x: UnixTimestamp): string {.borrow.}
proc `==`*(a, b: UnixTimestamp): bool {.borrow.}
proc `<`*(a, b: UnixTimestamp): bool {.borrow.}
proc `<=`*(a, b: UnixTimestamp): bool {.borrow.}

proc `$`*(x: Bytes): string {.borrow.}
proc `==`*(a, b: Bytes): bool {.borrow.}
proc `<`*(a, b: Bytes): bool {.borrow.}
proc `<=`*(a, b: Bytes): bool {.borrow.}
proc `+`*(a, b: Bytes): Bytes {.borrow.}
proc `-`*(a, b: Bytes): Bytes {.borrow.}

proc `$`*(x: Megabytes): string {.borrow.}
proc `==`*(a, b: Megabytes): bool {.borrow.}
proc `<`*(a, b: Megabytes): bool {.borrow.}
proc `<=`*(a, b: Megabytes): bool {.borrow.}

# =============================================================================
# Conversion functions (explicit only - no implicit conversions!)
# =============================================================================
func toBytes*(mb: Megabytes): Bytes =
  ## Convert megabytes to bytes (explicit conversion required)
  Bytes(mb.int64 * 1024 * 1024)

func toMegabytes*(b: Bytes): Megabytes =
  ## Convert bytes to megabytes (explicit conversion required)
  Megabytes(b.int64 div (1024 * 1024))

func toUnix*(ts: UnixTimestamp): int64 =
  ## Extract raw unix timestamp value
  int64(ts)

func fromUnix*(ts: int64): UnixTimestamp =
  ## Create UnixTimestamp from raw value
  UnixTimestamp(ts)

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
    ecLockHeld = 8      # Lock held by another instance (not an error, exit 0 in CLI)
    ecLockError = 9     # Lock file I/O error (permission denied, etc.)
    ecDeviceErrors = 10 # BTRFS device has errors

  CompressionAlgo* = enum
    caZstd = "zstd"
    caZlib = "zlib"
    caLzo = "lzo"

  # Algorithm-specific level ranges (compile-time safety)
  ZstdLevel* = range[1..15]   ## zstd compression level (1-15)
  ZlibLevel* = range[1..9]    ## zlib compression level (1-9)
  LzoLevel* = range[1..9]     ## lzo compression level (1-9)

  # Legacy type alias for compatibility
  CompressionLevel* = object
    algo*: CompressionAlgo
    level*: range[1..15]

  # New case object with algorithm-specific level validation
  CompressionConfig* = object
    ## Compression configuration with compile-time level range validation.
    ## Each algorithm has its own valid level range enforced at compile-time.
    case algo*: CompressionAlgo
    of caZstd:
      zstdLevel*: ZstdLevel
    of caZlib:
      zlibLevel*: ZlibLevel
    of caLzo:
      lzoLevel*: LzoLevel

  SnapshotType* = enum
    stFull = "full"
    stIncremental = "incremental"

  Snapshot* = object
    path*: string
    name*: string
    timestamp*: DateTime
    snapshotType*: SnapshotType
    parent*: Opt[string]  # Use Opt[T] from nim-results for consistency
    uuid*: string
    verified*: bool

  RetentionPolicy* = object
    hourly*: Natural
    daily*: Natural
    weekly*: Natural
    monthly*: Natural
    yearly*: Natural

  OptimizationConfig* = object
    enabled*: bool              ## Enable auto-optimization after retention
    balanceThreshold*: Percentage  ## Usage percent threshold for balance
    defragThreshold*: Percentage   ## Fragmentation percent threshold

  ChainConfig* = object
    maxLength*: Natural     # Maximum chain length before forcing full snapshot

  YabbConfig* = object
    srcDir*: string
    dstDir*: string
    snapshotDir*: string
    compression*: CompressionLevel  # Simple object (CompressionConfig for validation)
    retention*: RetentionPolicy
    optimization*: OptimizationConfig
    chain*: ChainConfig
    debug*: bool
    dryRun*: bool
    forceFull*: bool
    minFreeSpace*: Natural  # MB
    maxParallelJobs*: Positive
    retryCount*: Positive
    retryDelay*: Natural    # seconds

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

  # =============================================================================
  # Object Variants for Pattern Matching (ADTs / Sum Types)
  # =============================================================================

  ParentValidationState* = enum
    ## Represents the validation state of a snapshot's parent reference.
    ## Used with fusion/matching for exhaustive pattern matching.
    pvsNoParentRef       ## Incremental has no parent defined
    pvsMissingParentPath ## Parent defined but path doesn't exist
    pvsValidParent       ## Parent exists and is accessible
    pvsFullSnapshot      ## Full snapshot, no parent needed
    pvsMetadataError     ## Could not read metadata

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
func initStats*(): ExecutionStats =
  ExecutionStats(errors: 0, warnings: 0)

func withError*(s: ExecutionStats): ExecutionStats =
  ExecutionStats(errors: s.errors + 1, warnings: s.warnings)

func withWarning*(s: ExecutionStats): ExecutionStats =
  ExecutionStats(errors: s.errors, warnings: s.warnings + 1)

func combine*(a, b: ExecutionStats): ExecutionStats =
  ExecutionStats(errors: a.errors + b.errors, warnings: a.warnings + b.warnings)

# =============================================================================
# CompressionConfig helpers
# =============================================================================

func level*(c: CompressionConfig): int =
  ## Get compression level as int (for serialization/logging)
  case c.algo
  of caZstd: c.zstdLevel.int
  of caZlib: c.zlibLevel.int
  of caLzo: c.lzoLevel.int

func zstdConfig*(level: ZstdLevel): CompressionConfig =
  ## Create zstd compression config with compile-time level validation
  CompressionConfig(algo: caZstd, zstdLevel: level)

func zlibConfig*(level: ZlibLevel): CompressionConfig =
  ## Create zlib compression config with compile-time level validation
  CompressionConfig(algo: caZlib, zlibLevel: level)

func lzoConfig*(level: LzoLevel): CompressionConfig =
  ## Create lzo compression config with compile-time level validation
  CompressionConfig(algo: caLzo, lzoLevel: level)

func toCompressionConfig*(cl: CompressionLevel): CompressionConfig =
  ## Convert legacy CompressionLevel to new CompressionConfig
  ## Used for migration from old config format
  case cl.algo
  of caZstd: zstdConfig(ZstdLevel(cl.level))
  of caZlib: zlibConfig(ZlibLevel(min(9, cl.level)))
  of caLzo: lzoConfig(LzoLevel(min(9, cl.level)))

func toCompressionLevel*(cc: CompressionConfig): CompressionLevel =
  ## Convert CompressionConfig back to legacy CompressionLevel
  ## Used for backward compatibility
  CompressionLevel(algo: cc.algo, level: cc.level)

# =============================================================================
# ParsedUsageLine helpers
# =============================================================================

func parseBtrfsUsageLine*(line: string): ParsedUsageLine =
  ## Parse a single line from btrfs filesystem usage output.
  ## Returns a typed ParsedUsageLine for pattern matching.
  let trimmed = line.strip()
  let parts = trimmed.split()

  if trimmed.startsWith("Device size:") and parts.len >= 3:
    ParsedUsageLine(kind: pulDeviceSize, bytes: (try: parseBiggestInt(parts[2]) except ValueError: 0'i64))
  elif trimmed.startsWith("Used:") and parts.len >= 2:
    ParsedUsageLine(kind: pulUsed, usedBytes: (try: parseBiggestInt(parts[1]) except ValueError: 0'i64))
  elif trimmed.startsWith("Device unallocated:") and parts.len >= 3:
    ParsedUsageLine(kind: pulDeviceUnallocated, bytes: (try: parseBiggestInt(parts[2]) except ValueError: 0'i64))
  elif trimmed.startsWith("Free (estimated):") and parts.len >= 3:
    ParsedUsageLine(kind: pulFreeEstimated, bytes: (try: parseBiggestInt(parts[2]) except ValueError: 0'i64))
  else:
    ParsedUsageLine(kind: pulUnknown)

# Constants
const
  DefaultConfigPath* = "/etc/yabb.toml"
  LockFile* = "/var/run/yabb.lock"
  LastSnapshotFile* = "/var/run/yabb_last_snapshot"
  TempSendPrefix* = "yabb-send"
  TempComparePrefix* = "yabb-compare"
  SnapshotPrefix* = "backup."

  # Optimization defaults
  DefaultAutoOptimize* = true
  DefaultBalanceThreshold*: Percentage = 75  ## Percent usage
  DefaultDefragThreshold*: Percentage = 50   ## Percent fragmentation

  # Chain defaults
  DefaultMaxChainLength* = 10

{.pop.}
