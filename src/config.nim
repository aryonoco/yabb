## Configuration loading from TOML

import std/[os, strutils]
import parsetoml
import types
import errors
import btrfs/operations  # isBtrfsFilesystem

const
  DefaultRetentionHourly* = 24
  DefaultRetentionDaily* = 7
  DefaultRetentionWeekly* = 4
  DefaultRetentionMonthly* = 6
  DefaultRetentionYearly* = 2
  DefaultMinFreeSpace* = 1024  # MB
  DefaultRetryCount* = 3
  DefaultRetryDelay* = 5

{.push raises: [].}

proc parseCompressionLevel*(s: string): YabbResult[CompressionLevel] =
  ## Parse compression string (algo:level) into CompressionLevel.
  ## Uses algorithm-specific range types internally for validation.
  let parts = s.split(':')
  if parts.len != 2:
    return err(validationError("Invalid compression format, expected algo:level"))

  let algo = case parts[0].toLowerAscii
    of "zstd": caZstd
    of "zlib": caZlib
    of "lzo": caLzo
    else: return err(validationError("Unsupported compression: " & parts[0]))

  let level = try: parseInt(parts[1])
              except ValueError: return err(validationError("Invalid level: " & parts[1]))

  # Validate using algorithm-specific ranges (ZstdLevel, ZlibLevel, LzoLevel)
  case algo
  of caZstd:
    if level < ZstdLevel.low or level > ZstdLevel.high:
      return err(validationError("zstd level must be 1-15, got: " & $level))
  of caZlib:
    if level < ZlibLevel.low or level > ZlibLevel.high:
      return err(validationError("zlib level must be 1-9, got: " & $level))
  of caLzo:
    if level < LzoLevel.low or level > LzoLevel.high:
      return err(validationError("lzo level must be 1-9, got: " & $level))

  ok(CompressionLevel(algo: algo, level: level))

proc loadConfig*(path: string = DefaultConfigPath): YabbResult[YabbConfig] =
  if not fileExists(path):
    return err(configError("Config file not found: " & path))

  let toml = try: parsetoml.parseFile(path)
             except Exception as e: return err(configError(e.msg))

  if not toml.hasKey("paths"):
    return err(configError("Missing [paths] section"))

  let paths = try: toml["paths"]
              except KeyError: return err(configError("Missing [paths] section"))
  let srcDir = paths.getOrDefault("src_dir").getStr("")
  let dstDir = paths.getOrDefault("dst_dir").getStr("")
  let snapshotDir = paths.getOrDefault("snapshot_dir").getStr("")

  if srcDir.len == 0 or dstDir.len == 0 or snapshotDir.len == 0:
    return err(configError("Missing required paths"))

  let comp = toml.getOrDefault("compression")
  let algo = comp.getOrDefault("algorithm").getStr("zstd")
  let level = comp.getOrDefault("level").getInt(3)
  let compression = parseCompressionLevel(algo & ":" & $level).valueOr:
    return err(error)

  let ret = toml.getOrDefault("retention")
  let opts = toml.getOrDefault("options")
  let optim = toml.getOrDefault("optimization")
  let chainCfg = toml.getOrDefault("chain")

  ok(YabbConfig(
    srcDir: srcDir,
    dstDir: dstDir,
    snapshotDir: snapshotDir,
    compression: compression,
    retention: RetentionPolicy(
      hourly: ret.getOrDefault("hourly").getInt(DefaultRetentionHourly),
      daily: ret.getOrDefault("daily").getInt(DefaultRetentionDaily),
      weekly: ret.getOrDefault("weekly").getInt(DefaultRetentionWeekly),
      monthly: ret.getOrDefault("monthly").getInt(DefaultRetentionMonthly),
      yearly: ret.getOrDefault("yearly").getInt(DefaultRetentionYearly)
    ),
    optimization: OptimizationConfig(
      enabled: optim.getOrDefault("enabled").getBool(DefaultAutoOptimize),
      # Clamp to Percentage range (0-100) to handle out-of-range config values gracefully
      balanceThreshold: Percentage(min(100, max(0, optim.getOrDefault("balance_threshold").getInt(DefaultBalanceThreshold.int)))),
      defragThreshold: Percentage(min(100, max(0, optim.getOrDefault("defrag_threshold").getInt(DefaultDefragThreshold.int))))
    ),
    chain: ChainConfig(
      maxLength: chainCfg.getOrDefault("max_length").getInt(DefaultMaxChainLength)
    ),
    debug: false,
    dryRun: false,
    forceFull: false,
    minFreeSpace: opts.getOrDefault("min_free_space").getInt(DefaultMinFreeSpace),
    maxParallelJobs: opts.getOrDefault("max_parallel_jobs").getInt(1),
    retryCount: opts.getOrDefault("retry_count").getInt(DefaultRetryCount),
    retryDelay: opts.getOrDefault("retry_delay").getInt(DefaultRetryDelay)
  ))

func withOverrides*(cfg: YabbConfig, debug, dryRun, forceFull: bool): YabbConfig =
  ## Pure function: creates new config with CLI overrides applied
  ## Does not mutate the input config
  YabbConfig(
    srcDir: cfg.srcDir,
    dstDir: cfg.dstDir,
    snapshotDir: cfg.snapshotDir,
    compression: cfg.compression,
    retention: cfg.retention,
    optimization: cfg.optimization,
    chain: cfg.chain,
    debug: debug,
    dryRun: dryRun,
    forceFull: forceFull,
    minFreeSpace: cfg.minFreeSpace,
    maxParallelJobs: cfg.maxParallelJobs,
    retryCount: cfg.retryCount,
    retryDelay: cfg.retryDelay
  )

proc validateConfig*(config: YabbConfig): YabbResult[void] =
  ## Validate configuration: directories exist and are on btrfs filesystem
  # Check directories exist
  if not dirExists(config.srcDir):
    return err(dirError("Source directory does not exist: " & config.srcDir))
  if not dirExists(config.dstDir):
    return err(dirError("Destination directory does not exist: " & config.dstDir))
  if not dirExists(config.snapshotDir):
    return err(dirError("Snapshot directory does not exist: " & config.snapshotDir))

  # Note: Optimization thresholds are now enforced at compile-time via Percentage type (0-100)
  # Config loading clamps out-of-range values automatically

  # Validate chain settings
  if config.chain.maxLength < 1:
    return err(validationError("chain.max_length must be at least 1, got: " &
      $config.chain.maxLength))

  # Verify btrfs filesystem (plan requirement)
  let srcBtrfs = isBtrfsFilesystem(config.srcDir)
  if srcBtrfs.isErr:
    return err(dirError("Cannot check filesystem type for source: " & srcBtrfs.error.msg))
  if not srcBtrfs.value:
    return err(dirError("Source directory is not on btrfs: " & config.srcDir))

  let dstBtrfs = isBtrfsFilesystem(config.dstDir)
  if dstBtrfs.isErr:
    return err(dirError("Cannot check filesystem type for destination: " & dstBtrfs.error.msg))
  if not dstBtrfs.value:
    return err(dirError("Destination directory is not on btrfs: " & config.dstDir))

  let snapBtrfs = isBtrfsFilesystem(config.snapshotDir)
  if snapBtrfs.isErr:
    return err(dirError("Cannot check filesystem type for snapshot dir: " & snapBtrfs.error.msg))
  if not snapBtrfs.value:
    return err(dirError("Snapshot directory is not on btrfs: " & config.snapshotDir))

  ok()

{.pop.}
