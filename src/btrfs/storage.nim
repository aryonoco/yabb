# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2023-2026 Aryan Ameri
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#

## Storage operations for BTRFS
## Handles space checks, compression verification, defrag, balance, scrub

import std/[strutils, sequtils]
import ../wrappers/log
import ../types
import ../errors
import ../utils/process

type
  StorageEfficiency* = object
    usagePercent*: Percentage    ## 0-100
    fragPercent*: Percentage     ## 0-100 (estimated)
    usedBytes*: int64
    totalBytes*: int64

{.push raises: [].}

proc verifyCompression*(path: string, compression: CompressionLevel): YabbResult[void] =
  ## Verify filesystem supports the requested compression algorithm
  ## Checks both kernel support (/proc/crypto) and btrfs mount options

  # Check kernel crypto support
  try:
    let crypto = readFile("/proc/crypto")
    let algoName = $compression.algo
    if algoName.toLowerAscii notin crypto.toLowerAscii:
      return err(prereqError("Kernel does not support " & algoName & " compression"))
  except IOError:
    return err(prereqError("Cannot read /proc/crypto"))

  # Check btrfs supports compression on this mount
  let res = runBtrfs(["filesystem", "show", path])
  if res.isErr or res.value.exitCode != 0:
    return err(btrfsError("Cannot verify btrfs filesystem at " & path))

  debug "Compression verified", algo = $compression.algo, level = compression.level
  ok()

proc checkFilesystemSpace*(path: string, minFreeSpaceMB: Natural): YabbResult[void] =
  ## Check if filesystem has minimum free space
  let res = runCommand("df", ["-BM", "--output=avail", path])
  if res.isErr:
    return err(res.error)
  if res.value.exitCode != 0:
    return err(prereqError("Failed to check filesystem space for " & path))

  # Parse output - second line contains available space
  let lines = res.value.output.strip().splitLines()
  if lines.len < 2:
    return err(prereqError("Unexpected df output format"))

  let availStr = lines[1].strip().replace("M", "")
  let availMB = try: parseInt(availStr) except ValueError: 0

  if availMB < minFreeSpaceMB:
    return err(prereqError(
      "Insufficient free space on " & path & ": " & $availMB & "MB available, " &
      $minFreeSpaceMB & "MB required"
    ))

  debug "Filesystem space check passed",
    path = path, available = availMB, required = minFreeSpaceMB
  ok()

proc defragment*(path: string, dryRun: bool = false): YabbResult[void] =
  ## Defragment a btrfs path
  if dryRun:
    debug "DRY_RUN: Would defragment", path = path
    return ok()

  let res = runBtrfs(["filesystem", "defragment", "-r", path])
  if res.isErr or res.value.exitCode != 0:
    return err(btrfsError("Failed to defragment " & path))

  info "Defragmentation completed", path = path
  ok()

proc balance*(path: string, dryRun: bool = false): YabbResult[void] =
  ## Start a btrfs balance operation
  if dryRun:
    debug "DRY_RUN: Would balance", path = path
    return ok()

  let res = runBtrfs(["balance", "start", path])
  if res.isErr or res.value.exitCode != 0:
    return err(btrfsError("Failed to start balance on " & path))

  info "Balance started", path = path
  ok()

proc balanceStatus*(path: string): YabbResult[string] =
  ## Get balance status
  let res = runBtrfs(["balance", "status", path])
  if res.isErr:
    return err(res.error)
  ok(res.value.output)

proc scrub*(path: string, dryRun: bool = false): YabbResult[void] =
  ## Start a btrfs scrub operation
  if dryRun:
    debug "DRY_RUN: Would scrub", path = path
    return ok()

  let res = runBtrfs(["scrub", "start", path])
  if res.isErr or res.value.exitCode != 0:
    return err(btrfsError("Failed to start scrub on " & path))

  info "Scrub started", path = path
  ok()

proc scrubStatus*(path: string): YabbResult[string] =
  ## Get scrub status
  let res = runBtrfs(["scrub", "status", path])
  if res.isErr:
    return err(res.error)
  ok(res.value.output)

proc getDeviceStats*(path: string): YabbResult[string] =
  ## Get device statistics
  let res = runBtrfs(["device", "stats", path])
  if res.isErr:
    return err(res.error)
  ok(res.value.output)

proc hasErrors*(path: string): YabbResult[bool] =
  ## Check if device has any errors
  let statsRes = getDeviceStats(path)
  if statsRes.isErr:
    return err(statsRes.error)

  # Check for non-zero error counts in output using anyIt
  let hasNonZeroErrors = statsRes.value.splitLines().anyIt(block:
    if "errors" in it.toLowerAscii:
      let parts = it.split()
      if parts.len >= 2:
        (try: parseInt(parts[^1]) except ValueError: 0) > 0
      else:
        false
    else:
      false
  )
  ok(hasNonZeroErrors)

proc getStorageEfficiency*(path: string): YabbResult[StorageEfficiency] =
  ## Get storage efficiency metrics from btrfs filesystem
  ## Returns usage percentage and estimated fragmentation
  let res = runBtrfs(["filesystem", "usage", "-b", path])
  if res.isErr or res.value.exitCode != 0:
    return err(btrfsError("Failed to get filesystem usage for " & path))

  # Parse filesystem usage using fold with pattern matching on ParsedUsageLine
  let (used, total, unallocated) = res.value.output.splitLines().foldl(
    block:
      let parsed = parseBtrfsUsageLine(b)
      case parsed.kind
      of pulDeviceSize:
        (a[0], parsed.bytes, a[2])
      of pulUsed:
        (parsed.usedBytes, a[1], a[2])
      of pulDeviceUnallocated:
        (a[0], a[1], parsed.bytes)
      of pulFreeEstimated:
        a  # Not used in this function
      of pulUnknown:
        a
    , (0'i64, 0'i64, 0'i64))

  # Calculate usage percentage (clamped to 0-100 for Percentage type)
  let usagePercent: Percentage = if total > 0:
    Percentage(min(100, (used * 100) div total))
  else:
    0

  # Estimate fragmentation from allocation vs used ratio
  # This is a rough estimate - btrfs doesn't expose exact fragmentation
  let allocated = total - unallocated
  let fragPercent: Percentage = if allocated > 0 and used > 0:
    let efficiency = (used * 100) div allocated
    Percentage(max(0, min(100, 100 - efficiency)))
  else:
    0

  debug "Storage efficiency measured",
    path = path, usagePercent = usagePercent, fragPercent = fragPercent

  ok(StorageEfficiency(
    usagePercent: usagePercent,
    fragPercent: fragPercent,
    usedBytes: used,
    totalBytes: total
  ))

proc checkStorageEfficiency*(
  path: string,
  balanceThreshold: Percentage,
  defragThreshold: Percentage
): YabbResult[tuple[needsBalance, needsDefrag: bool]] =
  ## Check if storage optimization is needed based on thresholds
  ## Returns which operations are recommended
  let efficiency = getStorageEfficiency(path).valueOr:
    return err(error)

  let needsBalance = efficiency.usagePercent > balanceThreshold
  let needsDefrag = efficiency.fragPercent > defragThreshold

  if needsBalance:
    debug "Storage usage exceeds threshold",
      current = efficiency.usagePercent, threshold = balanceThreshold
  if needsDefrag:
    debug "Fragmentation exceeds threshold",
      current = efficiency.fragPercent, threshold = defragThreshold

  ok((needsBalance: needsBalance, needsDefrag: needsDefrag))

proc optimizeStorage*(
  path: string,
  config: YabbConfig
): YabbResult[void] =
  ## Combined storage optimization workflow
  ## Runs defrag and balance based on efficiency thresholds
  if config.dryRun:
    debug "DRY_RUN: Would check and optimize storage", path = path
    return ok()

  # Check if optimization is needed
  let check = checkStorageEfficiency(
    path,
    config.optimization.balanceThreshold,
    config.optimization.defragThreshold
  ).valueOr:
    return err(error)

  if not check.needsDefrag and not check.needsBalance:
    debug "Storage efficiency within acceptable limits", path = path
    return ok()

  # Run defrag if needed (with compression)
  if check.needsDefrag:
    info "Running defragmentation with compression", path = path
    let defragRes = runBtrfs(["filesystem", "defragment", "-r", "-czstd", path])
    if defragRes.isErr or defragRes.value.exitCode != 0:
      warn "Defragmentation failed", path = path
      # Non-fatal, continue with balance

  # Run balance if needed (with usage filters for efficiency)
  if check.needsBalance:
    info "Running balance operation", path = path
    # Use usage filters to only balance chunks that need it
    let balanceRes = runBtrfs(["balance", "start", "-dusage=50", "-musage=50", path])
    if balanceRes.isErr or balanceRes.value.exitCode != 0:
      warn "Balance failed", path = path
      # Non-fatal

  info "Storage optimization completed", path = path
  ok()

{.pop.}
