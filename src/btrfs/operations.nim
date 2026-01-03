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
  let res = runCommand("df", ["-T", path])
  if res.isErr:
    return err(res.error)
  ok(res.value.output.contains("btrfs"))

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
        a
    , (0'i64, 0'i64))

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
  source: string,
  dest: string,
  readonly: bool = true,
  dryRun: bool = false
): YabbResult[void] =
  ## Create a btrfs snapshot
  if dryRun:
    debug "DRY_RUN: Would create snapshot", source = source, dest = dest, readonly = readonly
    return ok()

  # Use immutable concatenation instead of mutable append
  let args = @["subvolume", "snapshot"] &
             (if readonly: @["-r"] else: @[]) &
             @[source, dest]

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

proc setReadonly*(path: string, readonly: bool, dryRun: bool = false): YabbResult[void] =
  ## Set read-only status on subvolume
  if dryRun:
    debug "DRY_RUN: Would set readonly", path = path, readonly = readonly
    return ok()

  let value = if readonly: "true" else: "false"
  let res = runBtrfs(["property", "set", path, "ro", value])
  if res.isErr or res.value.exitCode != 0:
    return err(btrfsError("Failed to set readonly=" & value & " on " & path))
  ok()

proc setProperty*(path, property, value: string, dryRun: bool = false): YabbResult[void] =
  ## Set a property on a subvolume
  if dryRun:
    debug "DRY_RUN: Would set property", path = path, property = property, value = value
    return ok()

  let res = runBtrfs(["property", "set", path, property, value])
  if res.isErr or res.value.exitCode != 0:
    return err(btrfsError("Failed to set property " & property & " on " & path))
  ok()

proc getProperty*(path, property: string): YabbResult[string] =
  ## Get a property value from a subvolume
  let res = runBtrfs(["property", "get", path, property])
  if res.isErr or res.value.exitCode != 0:
    return err(btrfsError("Failed to get property " & property & " from " & path))

  # Parse property value from output (format: "property=value")
  let parts = res.value.output.strip().split('=')
  if parts.len >= 2:
    ok(parts[1].strip())
  else:
    err(btrfsError("Invalid property format for " & property))
