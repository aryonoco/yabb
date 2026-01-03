# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2023-2026 Aryan Ameri
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#

## Chain recovery logic for BTRFS snapshots
## Handles recovery from broken chains and missing parents

import std/[os, algorithm, times, sequtils, options]
import ../wrappers/log
import ../types
import ../errors
import ../btrfs/[snapshot, properties, operations]
import ../utils/functional
import manager

type
  ChainIssue* = enum
    ciMissingParent = "Missing parent snapshot"
    ciMissingMetadata = "Missing required metadata"
    ciInvalidChainPos = "Invalid chain position"
    ciBrokenChain = "Broken chain linkage"

  ChainDiagnostic* = object
    path*: string
    issue*: ChainIssue
    details*: string

{.push raises: [].}

proc diagnoseSnapshot(snap: Snapshot): seq[ChainDiagnostic] =
  ## Diagnose issues for a single snapshot, returning 0 or more diagnostics
  # Check for required metadata
  let hasMeta = hasRequiredProperties(snap.path)
  if hasMeta.isErr or not hasMeta.value:
    return @[ChainDiagnostic(
      path: snap.path,
      issue: ciMissingMetadata,
      details: "Snapshot is missing required properties"
    )]

  let meta = getSnapshotMetadata(snap.path)
  if meta.isErr:
    return @[ChainDiagnostic(
      path: snap.path,
      issue: ciMissingMetadata,
      details: meta.error.msg
    )]

  # Check parent exists for incremental snapshots using pattern matching
  case validateParentState(meta)
  of pvsNoParentRef:
    return @[ChainDiagnostic(
      path: snap.path,
      issue: ciMissingParent,
      details: "Incremental snapshot has no parent defined"
    )]
  of pvsMissingParentPath:
    return @[ChainDiagnostic(
      path: snap.path,
      issue: ciMissingParent,
      details: "Parent snapshot not found: " & meta.value.parent.get
    )]
  of pvsFullSnapshot, pvsValidParent, pvsMetadataError:
    discard  # No issues for these states

  @[]  # No issues found

proc diagnoseChain*(snapshotDir: string): YabbResult[seq[ChainDiagnostic]] =
  ## Diagnose issues in the snapshot chain
  let snapshots = listSnapshots(snapshotDir).valueOr:
    return err(error)

  if snapshots.len == 0:
    return ok(newSeq[ChainDiagnostic]())

  # Collect all diagnostics from all snapshots using flatMap pattern
  let issues = snapshots.mapIt(diagnoseSnapshot(it)).concat()
  ok(issues)

proc canRecoverSnapshot*(path: string, snapshotDir: string): YabbResult[bool] =
  ## Check if a snapshot with issues can be recovered
  let meta = getSnapshotMetadata(path)

  if meta.isErr:
    # No metadata - can't recover without full resend
    return ok(false)

  if meta.value.snapshotType == stFull:
    # Full snapshots are self-contained
    return ok(true)

  # For incremental, check if we can find an ancestor that exists
  if meta.value.parent.isNone:
    return ok(false)

  if dirExists(meta.value.parent.get):
    return ok(true)

  # Check if any snapshot in chain exists
  let chainInfo = getChainInfo(snapshotDir).valueOr:
    return err(error)

  let foundFull = chainInfo.snapshots.findFirst(block:
    it.timestamp < meta.value.timestamp and
    (let snapMeta = getSnapshotMetadata(it.path); snapMeta.isOk and snapMeta.value.snapshotType == stFull)
  )
  ok(foundFull.isSome)

proc repairChainMetadata*(
  snapshotDir: string,
  config: YabbConfig
): YabbResult[int] =
  ## Attempt to repair chain metadata issues
  ## Returns number of snapshots repaired
  if config.dryRun:
    debug "DRY_RUN: Would repair chain metadata", snapshotDir = snapshotDir
    return ok(0)

  let snapshots = listSnapshots(snapshotDir).valueOr:
    return err(error)

  if snapshots.len == 0:
    return ok(0)

  # Sort by timestamp (oldest first) - immutable sorted copy
  let sorted = snapshots.sorted(proc(a, b: Snapshot): int {.raises: [].} = cmp(a.timestamp, b.timestamp))

  # Update chain length on all snapshots and count successes
  let chainLen = sorted.len
  let repaired = sorted.countIt(setProperty(it.path, PropChainLength, $chainLen).isOk)

  info "Repaired chain metadata", repaired = repaired, total = sorted.len
  ok(repaired)

proc findRecoveryPoint*(snapshotDir: string): YabbResult[Opt[string]] =
  ## Find the best point to recover from (most recent full or valid incremental)
  let chainInfo = getChainInfo(snapshotDir).valueOr:
    return err(error)

  if chainInfo.snapshots.len == 0:
    return ok(Opt.none(string))

  # Sort by timestamp descending (newest first) - immutable sorted copy
  let sorted = chainInfo.snapshots.sorted(proc(a, b: Snapshot): int {.raises: [].} = cmp(b.timestamp, a.timestamp))

  # Find most recent full snapshot
  let fullSnap = sorted.findFirst(block:
    let meta = getSnapshotMetadata(it.path)
    meta.isOk and meta.value.snapshotType == stFull
  )
  if fullSnap.isSome:
    return ok(Opt.some(fullSnap.get.path))

  # If no full snapshot, find most recent with valid parent chain
  let recoverableSnap = sorted.findFirst(block:
    let canRecover = canRecoverSnapshot(it.path, snapshotDir)
    canRecover.isOk and canRecover.value
  )
  if recoverableSnap.isSome:
    ok(Opt.some(recoverableSnap.get.path))
  else:
    ok(Opt.none(string))

proc rebuildChainFromFull*(
  snapshotDir: string,
  fullSnapshotPath: string,
  config: YabbConfig
): YabbResult[void] =
  ## Rebuild chain starting from a full snapshot
  ## Deletes orphaned incrementals that can't be recovered
  if config.dryRun:
    debug "DRY_RUN: Would rebuild chain from full snapshot",
      snapshotDir = snapshotDir, fullSnapshot = fullSnapshotPath
    return ok()

  let meta = getSnapshotMetadata(fullSnapshotPath)
  if meta.isErr:
    return err(btrfsError("Cannot read full snapshot metadata"))

  if meta.value.snapshotType != stFull:
    return err(btrfsError("Specified snapshot is not a full snapshot"))

  let snapshots = listSnapshots(snapshotDir).valueOr:
    return err(error)

  # Use fold to count kept and deleted while processing
  let (keptCount, deletedCount) = snapshots.foldl(
    block:
      # Keep the full snapshot
      if b.path == fullSnapshotPath:
        (a[0] + 1, a[1])
      else:
        let snapMeta = getSnapshotMetadata(b.path)
        if snapMeta.isErr:
          # Delete snapshots without metadata
          let delRes = deleteSubvolume(b.path, config.dryRun)
          if delRes.isOk: (a[0], a[1] + 1) else: a
        elif snapMeta.value.timestamp < meta.value.timestamp:
          # Older than full snapshot - delete
          let delRes = deleteSubvolume(b.path, config.dryRun)
          if delRes.isOk: (a[0], a[1] + 1) else: a
        else:
          (a[0] + 1, a[1])
    , (0, 0))

  info "Chain rebuilt from full snapshot",
    kept = keptCount, deleted = deletedCount

  ok()

{.pop.}
