# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2023-2026 Aryan Ameri
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#

## Tests for core types
## Tests type conversions, enums, and basic type operations

import unittest
import std/[times]

# Add src directory to path
import ../src/types
import ../src/config

suite "ExitCode enum":
  test "exit codes have correct values":
    check ecSuccess.ord == 0
    check ecNoChanges.ord == 1
    check ecInvalidArgument.ord == 2
    check ecConfigMissing.ord == 3
    check ecMissingVar.ord == 4
    check ecInvalidVar.ord == 5
    check ecPrereqMissing.ord == 6
    check ecDirInvalid.ord == 7

suite "CompressionAlgo enum":
  test "compression algorithms have correct string values":
    check $caZstd == "zstd"
    check $caZlib == "zlib"
    check $caLzo == "lzo"

suite "SnapshotType enum":
  test "snapshot types have correct string values":
    check $stFull == "full"
    check $stIncremental == "incremental"

suite "CompressionLevel parsing":
  test "valid zstd compression level":
    let result = parseCompressionLevel("zstd:3")
    check result.isOk
    check result.value.algo == caZstd
    check result.value.level == 3

  test "valid zlib compression level":
    let result = parseCompressionLevel("zlib:6")
    check result.isOk
    check result.value.algo == caZlib
    check result.value.level == 6

  test "valid lzo compression level":
    let result = parseCompressionLevel("lzo:1")
    check result.isOk
    check result.value.algo == caLzo
    check result.value.level == 1

  test "zstd max level 15":
    let result = parseCompressionLevel("zstd:15")
    check result.isOk
    check result.value.level == 15

  test "zstd level 16 fails (out of range)":
    let result = parseCompressionLevel("zstd:16")
    check result.isErr

  test "zlib level 10 fails (out of range)":
    let result = parseCompressionLevel("zlib:10")
    check result.isErr

  test "invalid format fails":
    check parseCompressionLevel("zstd").isErr
    check parseCompressionLevel("zstd:").isErr
    check parseCompressionLevel(":3").isErr
    check parseCompressionLevel("").isErr

  test "unknown algorithm fails":
    check parseCompressionLevel("gzip:5").isErr
    check parseCompressionLevel("unknown:1").isErr

  test "non-numeric level fails":
    check parseCompressionLevel("zstd:abc").isErr
    check parseCompressionLevel("zstd:three").isErr

suite "RetentionPolicy defaults":
  test "default values are correct":
    let policy = RetentionPolicy(
      hourly: 24,
      daily: 7,
      weekly: 4,
      monthly: 6,
      yearly: 2
    )
    check policy.hourly == 24
    check policy.daily == 7
    check policy.weekly == 4
    check policy.monthly == 6
    check policy.yearly == 2

suite "Percentage range type":
  test "percentage accepts 0":
    let p: Percentage = 0
    check p == 0

  test "percentage accepts 100":
    let p: Percentage = 100
    check p == 100

  test "percentage accepts mid-range values":
    let p: Percentage = 50
    check p == 50

  test "percentage can be used in OptimizationConfig":
    let config = OptimizationConfig(
      enabled: true,
      balanceThreshold: 75,
      defragThreshold: 50
    )
    check config.balanceThreshold == 75
    check config.defragThreshold == 50

suite "Snapshot type":
  test "snapshot can be created with optional parent":
    let snap = Snapshot(
      path: "/snapshots/backup.2024-01-01T120000Z",
      name: "backup.2024-01-01T120000Z",
      timestamp: now().utc,
      snapshotType: stFull,
      parent: Opt.none(string),
      uuid: "test-uuid",
      verified: false
    )
    check snap.parent.isNone

  test "incremental snapshot has parent":
    let snap = Snapshot(
      path: "/snapshots/backup.2024-01-02T120000Z",
      name: "backup.2024-01-02T120000Z",
      timestamp: now().utc,
      snapshotType: stIncremental,
      parent: Opt.some("/snapshots/backup.2024-01-01T120000Z"),
      uuid: "test-uuid-2",
      verified: true
    )
    check snap.parent.isSome
    check snap.parent.get == "/snapshots/backup.2024-01-01T120000Z"
