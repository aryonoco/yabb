# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2023-2026 Aryan Ameri
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#

## Chain management for BTRFS snapshots
## Handles chain optimization and verification

import std/[os, algorithm, sequtils, options]
import ../wrappers/log
import ../types
import ../errors
import ../btrfs/[snapshot, properties]
import ../utils/functional

proc validateParentState*(meta: YabbResult[SnapshotMetadata]): ParentValidationState =
  ## Determine parent validation state from snapshot metadata result.
  ## Used for pattern matching in chain verification.
  if meta.isErr:
    pvsMetadataError
  elif meta.value.snapshotType == stFull:
    pvsFullSnapshot
  elif meta.value.parent.isNone:
    pvsNoParentRef
  elif not dirExists(meta.value.parent.get):
    pvsMissingParentPath
  else:
    pvsValidParent

type ChainInfo* = object
  snapshots*: seq[Snapshot]
  fullSnapshotCount*: int
  incrementalCount*: int
  totalSize*: int64
  chainLength*: int
  isValid*: bool

{.push raises: [].}

# Forward declaration - defined after shouldForceFullSnapshot
proc getChainDepth*(path: string): int

proc getChainInfo*(snapshotDir: string): YabbResult[ChainInfo] =
  ## Get information about the snapshot chain
  let snapshots = listSnapshots(snapshotDir).valueOr:
    return err(error)

  if snapshots.len == 0:
    return ok(
      ChainInfo(
        snapshots: @[],
        fullSnapshotCount: 0,
        incrementalCount: 0,
        totalSize: 0,
        chainLength: 0,
        isValid: true,
      )
    )

  # Sort by timestamp (oldest first) - immutable sorted copy
  let sorted = snapshots.sorted(
    proc(a, b: Snapshot): int {.raises: [].} =
      cmp(a.timestamp, b.timestamp)
  )

  # Count full and incremental snapshots using fold pattern
  let (fullCount, incrCount) = sorted.foldl(
    block:
      let meta = getSnapshotMetadata(b.path)
      if meta.isOk:
        if meta.value.snapshotType == stFull:
          (a[0] + 1, a[1])
        else:
          (a[0], a[1] + 1)
      else:
        a,
    (0, 0),
  )

  ok(
    ChainInfo(
      snapshots: sorted,
      fullSnapshotCount: fullCount,
      incrementalCount: incrCount,
      totalSize: 0, # Would need to sum snapshot sizes
      chainLength: sorted.len,
      isValid: fullCount > 0 or sorted.len == 0,
    )
  )

proc verifyChain*(snapshotDir: string, config: YabbConfig): YabbResult[bool] =
  ## Verify the integrity of the snapshot chain
  ## Checks that all incrementals have valid parents
  if config.dryRun:
    debug "DRY_RUN: Would verify snapshot chain", snapshotDir = snapshotDir
    return ok(true)

  let chainInfo = getChainInfo(snapshotDir).valueOr:
    return err(error)

  if chainInfo.snapshots.len == 0:
    return ok(true)

  # Check that chain starts with a full snapshot
  if chainInfo.fullSnapshotCount == 0:
    return err(btrfsError("Chain has no full snapshot"))

  # Verify each snapshot's parent exists - find first invalid
  let invalidSnap = chainInfo.snapshots.findFirst(
    block:
      let meta = getSnapshotMetadata(it.path)
      let state = validateParentState(meta)
      case state
      of pvsMetadataError:
        debug "Snapshot missing metadata, skipping parent check", path = it.path
        false # Not an error - skip this one
      of pvsNoParentRef, pvsMissingParentPath:
        true # Invalid snapshot
      of pvsFullSnapshot, pvsValidParent:
        false # Valid snapshot
  )
  if invalidSnap.isSome:
    let snap = invalidSnap.get
    let meta = getSnapshotMetadata(snap.path)
    case validateParentState(meta)
    of pvsNoParentRef:
      return err(btrfsError("Incremental snapshot missing parent: " & snap.path))
    of pvsMissingParentPath:
      return err(btrfsError("Parent snapshot not found: " & meta.value.parent.get))
    of pvsMetadataError, pvsFullSnapshot, pvsValidParent:
      return err(btrfsError("Invalid snapshot: " & snap.path))

  # Validate chainPosition metadata against actual parent chain depth
  # This detects metadata corruption where chainPosition doesn't match reality
  var depthMismatches = 0
  for snap in chainInfo.snapshots:
    let meta = getSnapshotMetadata(snap.path)
    if meta.isOk:
      let actualDepth = getChainDepth(snap.path)
      let storedPosition = meta.value.chainPosition
      if actualDepth != storedPosition:
        depthMismatches += 1
        warn "Chain depth mismatch detected",
          path = snap.path, storedPosition = storedPosition, actualDepth = actualDepth

  if depthMismatches > 0:
    warn "Chain has metadata inconsistencies",
      mismatches = depthMismatches, total = chainInfo.snapshots.len

  debug "Chain verification passed", snapshots = chainInfo.snapshots.len
  ok(true)

proc shouldForceFullSnapshot*(
    snapshotDir: string, maxChainLength: Natural, dryRun: bool = false
): YabbResult[bool] =
  ## Check if chain length exceeds maximum and a full snapshot should be forced
  ## Returns true if a full snapshot is required
  if dryRun:
    debug "DRY_RUN: Would check chain length",
      snapshotDir = snapshotDir, maxChainLength = maxChainLength
    return ok(false)

  let chainInfo = getChainInfo(snapshotDir).valueOr:
    return err(error)

  if chainInfo.chainLength >= maxChainLength:
    info "Chain length exceeds limit, forcing full snapshot",
      current = chainInfo.chainLength, max = maxChainLength
    return ok(true)

  debug "Chain length within limits",
    current = chainInfo.chainLength, max = maxChainLength
  ok(false)

proc getChainDepth*(path: string): int =
  ## Get the depth of a snapshot in the chain (number of parents)
  ## Uses tail recursion instead of while loop for immutability
  proc traverse(currentPath: string, depth: int): int =
    # Safety limit to prevent infinite loops
    if depth > 1000:
      return depth

    let meta = getSnapshotMetadata(currentPath)
    if meta.isErr:
      return depth

    if meta.value.parent.isNone or meta.value.snapshotType == stFull:
      return depth

    traverse(meta.value.parent.get, depth + 1)

  traverse(path, 0)

{.pop.}
