# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2023-2026 Aryan Ameri
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#

## Prerequisites checking for YABB
## Verifies system requirements before backup operations

import std/[os, posix, strutils, sequtils, options]
import ../wrappers/log
import ../types
import ../errors
import ../btrfs/storage
import process
import retry
import functional

const RequiredCommands* = [
  ("btrfs", "For btrfs operations"),
  ("pv", "For transfer progress display"),
  ("setfattr", "For setting extended attributes"),
  ("getfattr", "For reading extended attributes"),
  ("date", "For timestamp operations"),
  ("find", "For finding snapshots"),
  ("grep", "For text processing"),
  ("awk", "For text processing"),
  ("uuidgen", "For generating unique IDs"),
  ("df", "For disk space checks"),
  ("flock", "For file locking"),
  ("mktemp", "For temporary file creation"),
]

{.push raises: [].}

proc checkRoot*(): YabbResult[void] =
  ## Check if running as root (EUID = 0)
  if geteuid() != 0:
    return err(prereqError("This program must be run as root"))
  ok()

proc checkCommand*(cmd: string): bool =
  ## Check if a command exists in PATH
  let res = runCommand("which", [cmd])
  res.isOk and res.value.exitCode == 0

proc checkBtrfsFeatures*(): YabbResult[void] =
  ## Verify btrfs-progs is working
  let res = runBtrfs(["version"])
  if res.isErr or res.value.exitCode != 0:
    return err(prereqError("btrfs-progs not working properly"))
  ok()

proc checkBtrfsSendReceive*(): YabbResult[void] =
  ## Verify btrfs send/receive functionality by checking btrfs-progs
  ## supports required features (--compressed-data flag)
  let res = runCommand("btrfs", ["send", "--help"])
  if res.isErr or res.value.exitCode != 0:
    return err(prereqError("btrfs send command not functional"))

  # Verify --compressed-data flag is supported (btrfs-progs >= 5.14)
  if not res.value.output.contains("compressed-data"):
    return err(
      prereqError(
        "btrfs-progs version doesn't support --compressed-data (requires >= 5.14)"
      )
    )

  debug "btrfs send/receive verified", compressedData = true
  ok()

proc checkDirectoryWritable*(dir: string, dryRun: bool = false): YabbResult[void] =
  ## Verify directory is writable by creating temp file
  if dryRun:
    debug "DRY_RUN: Would check write access", dir = dir
    return ok()

  let tempPath = dir / ".yabb_write_test_" & $getpid()
  try:
    writeFile(tempPath, "test")
    removeFile(tempPath)
    ok()
  except IOError, OSError:
    err(prereqError("Directory not writable: " & dir))

proc checkPrerequisites*(config: YabbConfig): YabbResult[void] =
  ## Full prerequisites check matching bash script behavior
  ## Checks: root, commands, btrfs, compression, directories

  # 1. Check root privileges
  checkRoot().isOkOr:
    return err(error)

  # 2. Check required commands - find first missing
  let missingCmd = RequiredCommands.toSeq.findFirst(not checkCommand(it[0]))
  if missingCmd.isSome:
    return err(
      prereqError(
        "Required command not found: " & missingCmd.get[0] & " (" & missingCmd.get[1] &
          ")"
      )
    )
  RequiredCommands.toSeq.applyIt:
    debug "Found required command", cmd = it[0]

  # 3. Check btrfs tools with retry

  retry(
    config.retryCount,
    config.retryDelay,
    proc(): YabbResult[void] {.raises: [].} =
      checkBtrfsFeatures(),
    "Checking btrfs tools",
  ).isOkOr:
    return err(error)

  # 3b. Check btrfs send/receive functionality
  checkBtrfsSendReceive().isOkOr:
    return err(error)

  # 4. Check for BTRFS device errors (pre-flight safety check)
  if not config.dryRun:
    let srcErrors = hasErrors($config.srcDir)
    if srcErrors.isOk and srcErrors.value:
      return err(
        yabbErr(
          ecDeviceErrors,
          "PREREQ",
          "BTRFS device has errors on source directory. Run 'btrfs scrub' first: " &
            $config.srcDir,
        )
      )

  # 6. Check directory write permissions - use helper to avoid closure capture issues
  if not config.dryRun:
    proc checkDir(dir: string): bool =
      retry(
        config.retryCount,
        config.retryDelay,
        proc(): YabbResult[void] {.raises: [].} =
          checkDirectoryWritable(dir, config.dryRun),
        "Checking write access to " & dir,
      ).isErr

    let requiredDirs = @["/tmp", parentDir(LockFile), parentDir(LastSnapshotFile)]
    let failedDir = requiredDirs.findFirst(checkDir(it))
    if failedDir.isSome:
      return err(prereqError("Directory not writable: " & failedDir.get))

  debug "All prerequisites checked successfully"
  ok()

{.pop.}
