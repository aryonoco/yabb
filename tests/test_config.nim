## Tests for configuration loading and validation

import unittest
import std/[os, tempfiles, strutils]

import ../src/types
import ../src/config
import ../src/errors
import ../src/btrfs/operations  # isBtrfsFilesystem

suite "Configuration loading":
  test "missing config file returns error":
    let result = loadConfig("/nonexistent/path/yabb.toml")
    check result.isErr
    check result.error.code == ecConfigMissing

  test "valid config loads correctly":
    # Create a temporary config file
    let (file, path) = createTempFile("yabb_test_", ".toml")
    defer:
      file.close()
      removeFile(path)

    file.write("""
[paths]
src_dir = "/data"
dst_dir = "/backup"
snapshot_dir = "/snapshots"

[compression]
algorithm = "zstd"
level = 3

[retention]
hourly = 24
daily = 7
weekly = 4
monthly = 6
yearly = 2

[options]
min_free_space = 1024
retry_count = 3
retry_delay = 5
""")
    file.flushFile()

    let result = loadConfig(path)
    check result.isOk

    let cfg = result.value
    check cfg.srcDir == "/data"
    check cfg.dstDir == "/backup"
    check cfg.snapshotDir == "/snapshots"
    check cfg.compression.algo == caZstd
    check cfg.compression.level == 3
    check cfg.retention.hourly == 24
    check cfg.retention.daily == 7
    check cfg.retention.weekly == 4
    check cfg.retention.monthly == 6
    check cfg.retention.yearly == 2
    check cfg.minFreeSpace == 1024
    check cfg.retryCount == 3
    check cfg.retryDelay == 5

  test "config with defaults":
    let (file, path) = createTempFile("yabb_test_", ".toml")
    defer:
      file.close()
      removeFile(path)

    # Minimal config - only required paths
    file.write("""
[paths]
src_dir = "/data"
dst_dir = "/backup"
snapshot_dir = "/snapshots"
""")
    file.flushFile()

    let result = loadConfig(path)
    check result.isOk

    let cfg = result.value
    # Check defaults are applied
    check cfg.compression.algo == caZstd
    check cfg.compression.level == 3
    check cfg.retention.hourly == DefaultRetentionHourly
    check cfg.retention.daily == DefaultRetentionDaily
    check cfg.retention.weekly == DefaultRetentionWeekly
    check cfg.retention.monthly == DefaultRetentionMonthly
    check cfg.retention.yearly == DefaultRetentionYearly
    check cfg.minFreeSpace == DefaultMinFreeSpace
    check cfg.retryCount == DefaultRetryCount
    check cfg.retryDelay == DefaultRetryDelay

  test "config missing paths section fails":
    let (file, path) = createTempFile("yabb_test_", ".toml")
    defer:
      file.close()
      removeFile(path)

    file.write("""
[compression]
algorithm = "zstd"
level = 3
""")
    file.flushFile()

    let result = loadConfig(path)
    check result.isErr

  test "config missing required path fails":
    let (file, path) = createTempFile("yabb_test_", ".toml")
    defer:
      file.close()
      removeFile(path)

    file.write("""
[paths]
src_dir = "/data"
# Missing dst_dir and snapshot_dir
""")
    file.flushFile()

    let result = loadConfig(path)
    check result.isErr

  test "config with invalid compression fails":
    let (file, path) = createTempFile("yabb_test_", ".toml")
    defer:
      file.close()
      removeFile(path)

    file.write("""
[paths]
src_dir = "/data"
dst_dir = "/backup"
snapshot_dir = "/snapshots"

[compression]
algorithm = "invalid"
level = 3
""")
    file.flushFile()

    let result = loadConfig(path)
    check result.isErr

suite "Configuration validation":
  test "validateConfig returns error for non-existent source":
    let cfg = YabbConfig(
      srcDir: "/nonexistent/source",
      dstDir: "/tmp",  # This exists
      snapshotDir: "/tmp",
      compression: CompressionLevel(algo: caZstd, level: 3),
      retention: RetentionPolicy(hourly: 24, daily: 7, weekly: 4, monthly: 6, yearly: 2),
      optimization: OptimizationConfig(enabled: true, balanceThreshold: 75, defragThreshold: 50),
      chain: ChainConfig(maxLength: 10),
      debug: false,
      dryRun: false,
      forceFull: false,
      minFreeSpace: 1024,
      maxParallelJobs: 1,
      retryCount: 3,
      retryDelay: 5
    )

    let result = validateConfig(cfg)
    check result.isErr
    check result.error.code == ecDirInvalid

  test "validateConfig returns error for non-existent destination":
    let cfg = YabbConfig(
      srcDir: "/tmp",  # This exists
      dstDir: "/nonexistent/destination",
      snapshotDir: "/tmp",
      compression: CompressionLevel(algo: caZstd, level: 3),
      retention: RetentionPolicy(hourly: 24, daily: 7, weekly: 4, monthly: 6, yearly: 2),
      optimization: OptimizationConfig(enabled: true, balanceThreshold: 75, defragThreshold: 50),
      chain: ChainConfig(maxLength: 10),
      debug: false,
      dryRun: false,
      forceFull: false,
      minFreeSpace: 1024,
      maxParallelJobs: 1,
      retryCount: 3,
      retryDelay: 5
    )

    let result = validateConfig(cfg)
    check result.isErr

  test "validateConfig succeeds for valid paths on btrfs":
    # This test requires btrfs - skip on non-btrfs systems
    let btrfsCheck = isBtrfsFilesystem("/tmp")
    if btrfsCheck.isErr or not btrfsCheck.value:
      skip()  # Skip test on non-btrfs systems
    else:
      let cfg = YabbConfig(
        srcDir: "/tmp",
        dstDir: "/tmp",
        snapshotDir: "/tmp",
        compression: CompressionLevel(algo: caZstd, level: 3),
        retention: RetentionPolicy(hourly: 24, daily: 7, weekly: 4, monthly: 6, yearly: 2),
        optimization: OptimizationConfig(enabled: true, balanceThreshold: 75, defragThreshold: 50),
        chain: ChainConfig(maxLength: 10),
        debug: false,
        dryRun: false,
        forceFull: false,
        minFreeSpace: 1024,
        maxParallelJobs: 1,
        retryCount: 3,
        retryDelay: 5
      )
      let result = validateConfig(cfg)
      check result.isOk

  test "validateConfig rejects non-btrfs paths":
    # This test requires non-btrfs filesystem
    let btrfsCheck = isBtrfsFilesystem("/tmp")
    if btrfsCheck.isErr or btrfsCheck.value:
      skip()  # Skip test on btrfs systems
    else:
      let cfg = YabbConfig(
        srcDir: "/tmp",
        dstDir: "/tmp",
        snapshotDir: "/tmp",
        compression: CompressionLevel(algo: caZstd, level: 3),
        retention: RetentionPolicy(hourly: 24, daily: 7, weekly: 4, monthly: 6, yearly: 2),
        optimization: OptimizationConfig(enabled: true, balanceThreshold: 75, defragThreshold: 50),
        chain: ChainConfig(maxLength: 10),
        debug: false,
        dryRun: false,
        forceFull: false,
        minFreeSpace: 1024,
        maxParallelJobs: 1,
        retryCount: 3,
        retryDelay: 5
      )
      let result = validateConfig(cfg)
      check result.isErr
      check "not on btrfs" in result.error.msg
