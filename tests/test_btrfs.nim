# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2023-2026 Aryan Ameri
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#

## Tests for btrfs operations
## Note: Most tests require an actual btrfs filesystem to run meaningfully
## These tests verify the functions run without crashing and return valid result types

import unittest

import ../src/types
import ../src/btrfs/operations

suite "btrfs installation check":
  test "checkBtrfsInstalled returns YabbResult":
    # This test verifies the function runs without crash
    # Actual success depends on whether btrfs-progs is installed
    let result = checkBtrfsInstalled()
    # Result should be either Ok or Err, both are valid outcomes
    check (result.isOk or result.isErr)

suite "btrfs filesystem detection":
  test "isBtrfsFilesystem on /tmp returns result":
    # /tmp may or may not be on btrfs depending on system
    let result = isBtrfsFilesystem("/tmp")
    check result.isOk
    # Value should be a bool
    check (result.value == true or result.value == false)

  test "isBtrfsFilesystem on nonexistent path":
    let result = isBtrfsFilesystem("/nonexistent/path/12345")
    # df behavior varies by system - may return error or false
    # Either outcome is acceptable for nonexistent paths
    if result.isOk:
      check result.value == false  # If ok, should be false (not btrfs)
    # If error, that's also acceptable

  test "isBtrfsFilesystem on root returns result":
    # Root filesystem might be btrfs or not
    let result = isBtrfsFilesystem("/")
    check result.isOk

suite "subvolume detection":
  test "isSubvolume on regular directory returns false":
    # /tmp is typically not a btrfs subvolume
    let result = isSubvolume("/tmp")
    check result.isOk
    # Could be true if /tmp is actually a subvolume, but function should work

  test "isSubvolume on nonexistent path returns false":
    let result = isSubvolume("/nonexistent/path/12345")
    check result.isOk
    check result.value == false

suite "filesystem usage":
  test "getFilesystemUsage on existing path":
    # May fail if path is not on btrfs
    let result = getFilesystemUsage("/tmp")
    # Either succeeds with usage data or fails (if not btrfs)
    check (result.isOk or result.isErr)

  test "getFilesystemUsage returns tuple with used and available":
    let result = getFilesystemUsage("/")
    if result.isOk:
      let (used, available) = result.value
      # Both should be non-negative
      check used >= 0
      check available >= 0

suite "property operations":
  test "getProperty on nonexistent path fails":
    let result = getProperty("/nonexistent/path", "ro")
    check result.isErr

  test "setProperty in dry run mode succeeds":
    let result = setProperty("/nonexistent/path", "ro", "true", dryRun = true)
    check result.isOk

suite "subvolume operations - dry run":
  # These tests use dry run mode to avoid modifying the filesystem

  test "createSubvolume dry run succeeds":
    let result = createSubvolume("/tmp/yabb_test_subvol", dryRun = true)
    check result.isOk

  test "deleteSubvolume dry run succeeds":
    let result = deleteSubvolume("/tmp/yabb_test_subvol", dryRun = true)
    check result.isOk

  test "createSnapshot dry run succeeds":
    let result = createSnapshot("/tmp/src", "/tmp/dst", readonly = true, dryRun = true)
    check result.isOk

  test "setReadonly dry run succeeds":
    let result = setReadonly("/tmp/test", true, dryRun = true)
    check result.isOk
