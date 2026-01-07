# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2023-2026 Aryan Ameri
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#

## BTRFS operations module
## Wraps btrfs commands for subvolume and filesystem operations

{.push raises: [].}

import std/[strutils, sequtils]
import ../wrappers/log
import ../types
import ../errors
import ../utils/process

proc checkBtrfsInstalled*(): YabbResult[void] =
  ## Verify btrfs-progs is installed and working
  let res = runCommand("btrfs", ["version"])
  if res.isErr or res.value.exitCode != 0:
    return err(prereqError("btrfs-progs not installed or not working"))
  debug "btrfs version", output = res.value.output.strip()
  ok()

proc isBtrfsFilesystem*(path: string): YabbResult[bool] =
  ## Check if path is on a btrfs filesystem
  ## Uses stat -f which works correctly for btrfs subvolumes (df -T shows "-")
  let res = runCommand("stat", ["-f", "-c", "%T", path])
  if res.isErr:
    return err(res.error)
  if res.value.exitCode != 0:
    return ok(false)
  ok(res.value.output.strip().toLowerAscii() == "btrfs")

proc getFilesystemUsage*(path: string): YabbResult[tuple[used, available: int64]] =
  ## Get filesystem usage in bytes
  let res = runBtrfs(["filesystem", "usage", "-b", path])
  if res.isErr:
    return err(res.error)

  # Parse output using fold with pattern matching on ParsedUsageLine
  let (used, available) = res.value.output.splitLines().foldl(
      block:
        let parsed = parseBtrfsUsageLine(b)
        case parsed.kind
        of pulUsed:
          (parsed.usedBytes, a[1])
        of pulFreeEstimated:
          (a[0], parsed.bytes)
        of pulDeviceSize, pulDeviceUnallocated, pulUnknown:
          a,
      (0'i64, 0'i64),
    )

  ok((used: used, available: available))

proc createSubvolume*(path: string, dryRun: bool = false): YabbResult[void] =
  ## Create a new btrfs subvolume
  if dryRun:
    debug "DRY_RUN: Would create subvolume", path = path
    return ok()

  let res = runBtrfs(["subvolume", "create", path])
  if res.isErr or res.value.exitCode != 0:
    return err(btrfsError("Failed to create subvolume: " & path))
  debug "Created subvolume", path = path
  ok()

proc deleteSubvolume*(path: string, dryRun: bool = false): YabbResult[void] =
  ## Delete a btrfs subvolume
  if dryRun:
    debug "DRY_RUN: Would delete subvolume", path = path
    return ok()

  let res = runBtrfs(["subvolume", "delete", path])
  if res.isErr or res.value.exitCode != 0:
    return err(btrfsError("Failed to delete subvolume: " & path))
  debug "Deleted subvolume", path = path
  ok()

proc createSnapshot*(
    source: string, dest: string, readonly: bool = true, dryRun: bool = false
): YabbResult[void] =
  ## Create a btrfs snapshot
  if dryRun:
    debug "DRY_RUN: Would create snapshot",
      source = source, dest = dest, readonly = readonly
    return ok()

  # Use immutable concatenation instead of mutable append
  let args =
    @["subvolume", "snapshot"] & (if readonly: @["-r"] else: @[]) & @[source, dest]

  let res = runCommand("btrfs", args)
  if res.isErr or res.value.exitCode != 0:
    return err(btrfsError("Failed to create snapshot from " & source & " to " & dest))

  debug "Created snapshot", source = source, dest = dest, readonly = readonly
  ok()

proc isSubvolume*(path: string): YabbResult[bool] =
  ## Check if path is a btrfs subvolume
  let res = runBtrfs(["subvolume", "show", path])
  if res.isErr:
    return ok(false)
  ok(res.value.exitCode == 0)

proc isReadonly*(path: string): YabbResult[bool] =
  ## Check if subvolume is read-only
  let res = runBtrfs(["property", "get", path, "ro"])
  if res.isErr:
    return err(res.error)
  ok(res.value.output.contains("ro=true"))

proc setReadonly*(
    path: string, readonly: bool, dryRun: bool = false
): YabbResult[void] =
  ## Set read-only status on subvolume
  if dryRun:
    debug "DRY_RUN: Would set readonly", path = path, readonly = readonly
    return ok()

  let value = if readonly: "true" else: "false"
  let res = runBtrfs(["property", "set", path, "ro", value])
  if res.isErr or res.value.exitCode != 0:
    return err(btrfsError("Failed to set readonly=" & value & " on " & path))
  ok()

proc setProperty*(
    path, property, value: string, dryRun: bool = false
): YabbResult[void] =
  ## Set a property on a subvolume
  ## Uses setfattr for user.* extended attributes, btrfs property for native properties
  if dryRun:
    debug "DRY_RUN: Would set property", path = path, property = property, value = value
    return ok()

  if property.startsWith("user."):
    # Extended attributes use setfattr
    let res = runCommand("setfattr", ["-n", property, "-v", value, path])
    if res.isErr or res.value.exitCode != 0:
      return err(btrfsError("Failed to set xattr " & property & " on " & path))
  else:
    # Native btrfs properties
    let res = runBtrfs(["property", "set", path, property, value])
    if res.isErr or res.value.exitCode != 0:
      return err(btrfsError("Failed to set property " & property & " on " & path))
  ok()

proc getProperty*(path, property: string): YabbResult[string] =
  ## Get a property value from a subvolume
  ## Uses getfattr for user.* extended attributes, btrfs property for native properties
  if property.startsWith("user."):
    # Extended attributes use getfattr
    let res = runCommand("getfattr", ["--only-values", "-n", property, path])
    if res.isErr or res.value.exitCode != 0:
      return err(btrfsError("Failed to get xattr " & property & " from " & path))
    ok(res.value.output.strip())
  else:
    # Native btrfs properties
    let res = runBtrfs(["property", "get", path, property])
    if res.isErr or res.value.exitCode != 0:
      return err(btrfsError("Failed to get property " & property & " from " & path))
    # Parse property value from output (format: "property=value")
    let parts = res.value.output.strip().split('=')
    if parts.len >= 2:
      ok(parts[1].strip())
    else:
      err(btrfsError("Invalid property format for " & property))

func parseReceivedUuid(output: string): Opt[string] =
  ## Parse Received UUID from btrfs subvolume show output
  ## Returns Opt.none if '-' or empty, Opt.some(uuid) otherwise
  for line in output.splitLines():
    let trimmed = line.strip()
    if trimmed.startsWith("Received UUID:"):
      let parts = trimmed.split(":", maxsplit = 1)
      if parts.len >= 2:
        let uuid = parts[1].strip()
        if uuid.len > 0 and uuid != "-":
          return Opt.some(uuid)
  Opt.none(string)

proc getReceivedUuid*(path: string): YabbResult[Opt[string]] =
  ## Get the Received UUID from a btrfs subvolume
  ## Returns Opt.none if no Received UUID (incomplete receive or local snapshot)
  ## Returns Opt.some(uuid) if successfully received from another filesystem
  let res = runBtrfs(["subvolume", "show", path])
  if res.isErr:
    return err(res.error)
  if res.value.exitCode != 0:
    return err(btrfsError("Not a valid btrfs subvolume: " & path))
  ok(parseReceivedUuid(res.value.output))
