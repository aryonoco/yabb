# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2023-2026 Aryan Ameri
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#

## Configuration loading from TOML

import std/[os, strutils]
import parsetoml
import types
import errors
import wrappers/log # warn for config warnings
import btrfs/operations # isBtrfsFilesystem
import utils/paths # sanitizePath, checkPathPermissions

const
  DefaultRetentionHourly* = 24
  DefaultRetentionDaily* = 7
  DefaultRetentionWeekly* = 4
  DefaultRetentionMonthly* = 6
  DefaultRetentionYearly* = 2
  DefaultMinFreeSpace* = 1024 # MB
  DefaultRetryCount* = 3
  DefaultRetryDelay* = 5

{.push raises: [].}

func validateDependencies*(cfg: YabbConfig): ConfigValidationResult =
  ## Pure function: validate inter-variable dependencies
  ## Returns warnings as immutable data, not side effects
  result = initValidationResult()

  # Retention dependency check - daily requires hourly to be meaningful
  if cfg.retention.daily > 0 and cfg.retention.hourly == 0:
    result = result.withWarning(
      "retention", "RETENTION_DAILY is set but RETENTION_HOURLY is disabled"
    )

  # Weekly requires daily
  if cfg.retention.weekly > 0 and cfg.retention.daily == 0:
    result = result.withWarning(
      "retention", "RETENTION_WEEKLY is set but RETENTION_DAILY is disabled"
    )

  # Monthly requires weekly
  if cfg.retention.monthly > 0 and cfg.retention.weekly == 0:
    result = result.withWarning(
      "retention", "RETENTION_MONTHLY is set but RETENTION_WEEKLY is disabled"
    )

  # Yearly requires monthly
  if cfg.retention.yearly > 0 and cfg.retention.monthly == 0:
    result = result.withWarning(
      "retention", "RETENTION_YEARLY is set but RETENTION_MONTHLY is disabled"
    )

  # Retry delay check
  if cfg.retryCount > 1 and cfg.retryDelay < 1:
    result = result.withWarning(
      "retry", "RETRY_DELAY should be at least 1 second when retries enabled"
    )

  # Hourly minimum recommendation
  if cfg.retention.hourly > 0 and cfg.retention.hourly < 6:
    result = result.withWarning(
      "retention.hourly", "RETENTION_HOURLY below recommended minimum of 6 hours"
    )

  # Chain length sanity check
  if cfg.chain.maxLength > 50:
    result = result.withWarning(
      "chain.max_length", "Long snapshot chains (>50) may impact restore performance"
    )

proc parseCompressionLevel*(s: string): YabbResult[CompressionLevel] =
  ## Parse compression string (algo:level) into CompressionLevel.
  ## Uses algorithm-specific range types internally for validation.
  let parts = s.split(':')
  if parts.len != 2:
    return err(validationError("Invalid compression format, expected algo:level"))

  let algo =
    case parts[0].toLowerAscii
    of "zstd":
      caZstd
    of "zlib":
      caZlib
    of "lzo":
      caLzo
    else:
      return err(validationError("Unsupported compression: " & parts[0]))

  let level =
    try:
      parseInt(parts[1])
    except ValueError:
      return err(validationError("Invalid level: " & parts[1]))

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

proc resolveConfigPath*(path: string = DefaultConfigPath): string =
  ## Resolve config path with XDG fallback support.
  ## Priority: explicit path > /etc/yabb.toml > ~/.config/yabb/yabb.toml
  ## Returns the path to use (may not exist - caller should check).

  # If user specified a non-default path, use it directly
  if path != DefaultConfigPath:
    return path

  # Try system-wide config first
  if fileExists(DefaultConfigPath):
    return DefaultConfigPath

  # Try XDG user config as fallback
  let userPath = expandTilde(UserConfigPath)
  if fileExists(userPath):
    return userPath

  # Return default path for error reporting (will fail in loadConfig)
  DefaultConfigPath

proc loadConfig*(path: string = DefaultConfigPath): YabbResult[YabbConfig] =
  let resolvedPath = resolveConfigPath(path)

  if not fileExists(resolvedPath):
    # Provide helpful error message based on what was tried
    if path == DefaultConfigPath:
      return err(
        configError(
          "Config file not found. Tried: " & DefaultConfigPath & " and " &
            expandTilde(UserConfigPath)
        )
      )
    else:
      return err(configError("Config file not found: " & resolvedPath))

  let toml =
    try:
      parsetoml.parseFile(resolvedPath)
    except Exception as e:
      return err(configError(e.msg))

  if not toml.hasKey("paths"):
    return err(configError("Missing [paths] section"))

  let paths =
    try:
      toml["paths"]
    except KeyError:
      return err(configError("Missing [paths] section"))

  # Extract raw paths from TOML
  let srcDirRaw = paths.getOrDefault("src_dir").getStr("")
  let dstDirRaw = paths.getOrDefault("dst_dir").getStr("")
  let snapshotDirRaw = paths.getOrDefault("snapshot_dir").getStr("")

  if srcDirRaw.len == 0 or dstDirRaw.len == 0 or snapshotDirRaw.len == 0:
    return err(configError("Missing required paths"))

  # Sanitize paths early - validates format, resolves symlinks, checks for traversal
  let srcDir = sanitizePath(srcDirRaw).valueOr:
    return err(configError("Invalid source directory: " & error.msg))
  let dstDir = sanitizePath(dstDirRaw).valueOr:
    return err(configError("Invalid destination directory: " & error.msg))
  let snapshotDir = sanitizePath(snapshotDirRaw).valueOr:
    return err(configError("Invalid snapshot directory: " & error.msg))

  let comp = toml.getOrDefault("compression")
  let algo = comp.getOrDefault("algorithm").getStr("zstd")
  let level = comp.getOrDefault("level").getInt(3)
  let compress = comp.getOrDefault("enabled").getBool(true)
    # Default: use --compressed-data
  let compression = parseCompressionLevel(algo & ":" & $level).valueOr:
    return err(error)

  let ret = toml.getOrDefault("retention")
  let opts = toml.getOrDefault("options")
  let optim = toml.getOrDefault("optimization")
  let chainCfg = toml.getOrDefault("chain")

  let cfg = YabbConfig(
    srcDir: SourcePath(srcDir),
    dstDir: DestPath(dstDir),
    snapshotDir: SnapshotDirPath(snapshotDir),
    compression: compression,
    compress: compress,
    retention: RetentionPolicy(
      hourly: ret.getOrDefault("hourly").getInt(DefaultRetentionHourly),
      daily: ret.getOrDefault("daily").getInt(DefaultRetentionDaily),
      weekly: ret.getOrDefault("weekly").getInt(DefaultRetentionWeekly),
      monthly: ret.getOrDefault("monthly").getInt(DefaultRetentionMonthly),
      yearly: ret.getOrDefault("yearly").getInt(DefaultRetentionYearly),
    ),
    optimization: OptimizationConfig(
      enabled: optim.getOrDefault("enabled").getBool(DefaultAutoOptimize),
      # Clamp to Percentage range (0-100) to handle out-of-range config values gracefully
      balanceThreshold: Percentage(
        min(
          100,
          max(
            0,
            optim.getOrDefault("balance_threshold").getInt(DefaultBalanceThreshold.int),
          ),
        )
      ),
      defragThreshold: Percentage(
        min(
          100,
          max(
            0, optim.getOrDefault("defrag_threshold").getInt(DefaultDefragThreshold.int)
          ),
        )
      ),
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
    retryDelay: opts.getOrDefault("retry_delay").getInt(DefaultRetryDelay),
  )

  # Validate config dependencies and log any warnings
  let validation = validateDependencies(cfg)
  for w in validation.warnings:
    warn "Config warning", field = w.field, message = w.message

  ok(cfg)

func withOverrides*(cfg: YabbConfig, debug, dryRun, forceFull: bool): YabbConfig =
  ## Pure function: creates new config with CLI overrides applied
  ## Does not mutate the input config
  YabbConfig(
    srcDir: cfg.srcDir,
    dstDir: cfg.dstDir,
    snapshotDir: cfg.snapshotDir,
    compression: cfg.compression,
    compress: cfg.compress,
    retention: cfg.retention,
    optimization: cfg.optimization,
    chain: cfg.chain,
    debug: debug,
    dryRun: dryRun,
    forceFull: forceFull,
    minFreeSpace: cfg.minFreeSpace,
    maxParallelJobs: cfg.maxParallelJobs,
    retryCount: cfg.retryCount,
    retryDelay: cfg.retryDelay,
  )

proc validateConfig*(config: YabbConfig): YabbResult[void] =
  ## Validate configuration: directories exist and are on btrfs filesystem
  # Check directories exist
  if not dirExists($config.srcDir):
    return err(dirError("Source directory does not exist: " & $config.srcDir))
  if not dirExists($config.dstDir):
    return err(dirError("Destination directory does not exist: " & $config.dstDir))
  if not dirExists($config.snapshotDir):
    return err(dirError("Snapshot directory does not exist: " & $config.snapshotDir))

  # Check permissions - source needs read+execute, dest/snapshot need read+write+execute
  checkPathPermissions($config.srcDir, {ppRead, ppExecute}).isOkOr:
    return err(dirError("Source directory: " & error.msg))
  checkPathPermissions($config.dstDir, {ppRead, ppWrite, ppExecute}).isOkOr:
    return err(dirError("Destination directory: " & error.msg))
  checkPathPermissions($config.snapshotDir, {ppRead, ppWrite, ppExecute}).isOkOr:
    return err(dirError("Snapshot directory: " & error.msg))

  # Note: Optimization thresholds are enforced at compile time via Percentage type (0-100)
  # Config loading clamps out-of-range values automatically

  # Validate chain settings
  if config.chain.maxLength < 1:
    return err(
      validationError(
        "chain.max_length must be at least 1, got: " & $config.chain.maxLength
      )
    )

  # Verify btrfs filesystem 
  let srcBtrfs = isBtrfsFilesystem($config.srcDir)
  if srcBtrfs.isErr:
    return
      err(dirError("Cannot check filesystem type for source: " & srcBtrfs.error.msg))
  if not srcBtrfs.value:
    return err(dirError("Source directory is not on btrfs: " & $config.srcDir))

  let dstBtrfs = isBtrfsFilesystem($config.dstDir)
  if dstBtrfs.isErr:
    return err(
      dirError("Cannot check filesystem type for destination: " & dstBtrfs.error.msg)
    )
  if not dstBtrfs.value:
    return err(dirError("Destination directory is not on btrfs: " & $config.dstDir))

  let snapBtrfs = isBtrfsFilesystem($config.snapshotDir)
  if snapBtrfs.isErr:
    return err(
      dirError("Cannot check filesystem type for snapshot dir: " & snapBtrfs.error.msg)
    )
  if not snapBtrfs.value:
    return err(dirError("Snapshot directory is not on btrfs: " & $config.snapshotDir))

  ok()

{.pop.}
