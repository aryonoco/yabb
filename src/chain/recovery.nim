# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2023-2026 Aryan Ameri
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#

## Chain recovery logic for BTRFS snapshots
## Handles recovery from broken chains and missing parents

import std/[os, algorithm, times, sequtils, options, strutils]
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
    ciNotReadonly = "Snapshot is not read-only"
    ciInvalidSubvolume = "Not a valid btrfs subvolume"

  ChainDiagnostic* = object
    path*: string
    issue*: ChainIssue
    details*: string

{.push raises: [].}

proc diagnoseSnapshot(snap: Snapshot): seq[ChainDiagnostic] =
  ## Diagnose issues for a single snapshot, returning 0 or more diagnostics
  ## Checks for incomplete snapshots (not subvolume, not readonly) BEFORE metadata

  # Check subvolume validity first (before metadata checks)
  # Incomplete snapshots may not have metadata, so check structure first
  let isSubvol = isSubvolume(snap.path)
  if isSubvol.isErr or not isSubvol.value:
    return
      @[
        ChainDiagnostic(
          path: snap.path,
          issue: ciInvalidSubvolume,
          details: "Path is not a valid btrfs subvolume",
        )
      ]

  # Check read-only status (interrupted snapshot creation leaves ro=false)
  let roStatus = isReadonly(snap.path)
  if roStatus.isErr or not roStatus.value:
    return
      @[
        ChainDiagnostic(
          path: snap.path,
          issue: ciNotReadonly,
          details: "Snapshot is not read-only (incomplete creation)",
        )
      ]

  # Check for required metadata
  let hasMeta = hasRequiredProperties(snap.path)
  if hasMeta.isErr or not hasMeta.value:
    return
      @[
        ChainDiagnostic(
          path: snap.path,
          issue: ciMissingMetadata,
          details: "Snapshot is missing required properties",
        )
      ]

  let meta = getSnapshotMetadata(snap.path)
  if meta.isErr:
    return
      @[
        ChainDiagnostic(
          path: snap.path, issue: ciMissingMetadata, details: meta.error.msg
        )
      ]

  # Check parent exists for incremental snapshots using pattern matching
  case validateParentState(meta)
  of pvsNoParentRef:
    return
      @[
        ChainDiagnostic(
          path: snap.path,
          issue: ciMissingParent,
          details: "Incremental snapshot has no parent defined",
        )
      ]
  of pvsMissingParentPath:
    return
      @[
        ChainDiagnostic(
          path: snap.path,
          issue: ciMissingParent,
          details: "Parent snapshot not found: " & meta.value.parent.get,
        )
      ]
  of pvsFullSnapshot, pvsValidParent, pvsMetadataError:
    discard # No issues for these states

  @[] # No issues found

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

  let foundFull = chainInfo.snapshots.findFirst(
    block:
      it.timestamp < meta.value.timestamp and (
        let snapMeta = getSnapshotMetadata(it.path)
        snapMeta.isOk and snapMeta.value.snapshotType == stFull
      )
  )
  ok(foundFull.isSome)

proc repairChainMetadata*(snapshotDir: string, config: YabbConfig): YabbResult[int] =
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
  let sorted = snapshots.sorted(
    proc(a, b: Snapshot): int {.raises: [].} =
      cmp(a.timestamp, b.timestamp)
  )

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
  let sorted = chainInfo.snapshots.sorted(
    proc(a, b: Snapshot): int {.raises: [].} =
      cmp(b.timestamp, a.timestamp)
  )

  # Find most recent full snapshot
  let fullSnap = sorted.findFirst(
    block:
      let meta = getSnapshotMetadata(it.path)
      meta.isOk and meta.value.snapshotType == stFull
  )
  if fullSnap.isSome:
    return ok(Opt.some(fullSnap.get.path))

  # If no full snapshot, find most recent with valid parent chain
  let recoverableSnap = sorted.findFirst(
    block:
      let canRecover = canRecoverSnapshot(it.path, snapshotDir)
      canRecover.isOk and canRecover.value
  )
  if recoverableSnap.isSome:
    ok(Opt.some(recoverableSnap.get.path))
  else:
    ok(Opt.none(string))

proc rebuildChainFromFull*(
    snapshotDir: string, fullSnapshotPath: string, config: YabbConfig
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
          if delRes.isOk:
            (a[0], a[1] + 1)
          else:
            a
        elif snapMeta.value.timestamp < meta.value.timestamp:
          # Older than full snapshot - delete
          let delRes = deleteSubvolume(b.path, config.dryRun)
          if delRes.isOk:
            (a[0], a[1] + 1)
          else:
            a
        else:
          (a[0] + 1, a[1]),
    (0, 0),
  )

  info "Chain rebuilt from full snapshot", kept = keptCount, deleted = deletedCount

  ok()

proc cleanupIncompleteSnapshots*(
    snapshotDir: string, config: YabbConfig
): YabbResult[tuple[cleaned: int, failed: int]] =
  ## Find and delete incomplete snapshots (not readonly or invalid subvolumes)
  ## Returns count of cleaned and failed deletions
  ## Follows bash script's recover_snapshot_chain() behavior for cleanup

  # Get all diagnostics (includes new ciNotReadonly and ciInvalidSubvolume checks)
  let diagnostics = diagnoseChain(snapshotDir).valueOr:
    return err(error)

  # Filter to only incomplete snapshot issues using set membership
  let incompleteIssues =
    diagnostics.filterIt(it.issue in {ciNotReadonly, ciInvalidSubvolume})

  if incompleteIssues.len == 0:
    debug "No incomplete snapshots found", snapshotDir = snapshotDir
    return ok((cleaned: 0, failed: 0))

  # Use fold pattern for deletion with counters (matching rebuildChainFromFull style)
  let (cleaned, failed) = incompleteIssues.foldl(
    block:
      if config.dryRun:
        info "DRY_RUN: Would delete incomplete snapshot",
          path = b.path, issue = $b.issue
        (a[0] + 1, a[1])
      else:
        let delRes = deleteSubvolume(b.path, config.dryRun)
        if delRes.isOk:
          info "Deleted incomplete snapshot", path = b.path, issue = $b.issue
          (a[0] + 1, a[1])
        else:
          warn "Failed to delete incomplete snapshot",
            path = b.path, error = delRes.error.msg
          (a[0], a[1] + 1),
    (0, 0),
  )

  info "Incomplete snapshot cleanup completed", cleaned = cleaned, failed = failed
  ok((cleaned: cleaned, failed: failed))

proc isOrphanedDestSnapshot*(path: string): YabbResult[bool] =
  ## Check if a snapshot is orphaned (no Received UUID = incomplete receive)
  ## Orphaned snapshots are left behind by failed btrfs receive operations
  let isSubvol = isSubvolume(path)
  if isSubvol.isErr or not isSubvol.value:
    return ok(false) # Not a subvolume, skip

  let recvUuid = getReceivedUuid(path)
  if recvUuid.isErr:
    return ok(false) # Cannot determine, skip

  # Orphaned if it's a subvolume with no Received UUID
  ok(recvUuid.value.isNone)

proc cleanupOrphanedDestSnapshots*(
    destDir: string, config: YabbConfig
): YabbResult[tuple[cleaned: int, failed: int]] =
  ## Clean up orphaned destination snapshots (those with no Received UUID)
  ## These are left behind by failed btrfs receive operations
  ## Returns count of cleaned and failed deletions

  if not dirExists(destDir):
    return ok((cleaned: 0, failed: 0))

  let entries =
    try:
      toSeq(walkDir(destDir))
    except OSError as e:
      return err(btrfsError("Failed to list destination directory: " & e.msg))

  # Filter to snapshot directories that are orphaned
  let orphans = entries
    .filterIt(it.kind == pcDir and extractFilename(it.path).startsWith(SnapshotPrefix))
    .filterIt(
      block:
        let check = isOrphanedDestSnapshot(it.path)
        check.isOk and check.value
    )
    .mapIt(it.path)

  if orphans.len == 0:
    debug "No orphaned destination snapshots found", destDir = destDir
    return ok((cleaned: 0, failed: 0))

  info "Found orphaned destination snapshots", count = orphans.len

  # Use fold pattern for deletion with counters (matching cleanupIncompleteSnapshots style)
  let (cleaned, failed) = orphans.foldl(
    block:
      if config.dryRun:
        info "DRY_RUN: Would delete orphaned destination snapshot", path = b
        (a[0] + 1, a[1])
      else:
        let delRes = deleteSubvolume(b, config.dryRun)
        if delRes.isOk:
          info "Deleted orphaned destination snapshot", path = b
          (a[0] + 1, a[1])
        else:
          warn "Failed to delete orphaned destination snapshot",
            path = b, error = delRes.error.msg
          (a[0], a[1] + 1),
    (0, 0),
  )

  info "Orphaned destination snapshot cleanup completed",
    cleaned = cleaned, failed = failed
  ok((cleaned: cleaned, failed: failed))

proc recoverChain*(
    snapshotDir: string, config: YabbConfig
): YabbResult[
    tuple[incompletesCleaned: int, orphansRemoved: int, metadataRepaired: int]
] =
  ## Full chain recovery: find recovery point, cleanup, and repair metadata
  ## Enhanced recovery with intelligent anchor point detection
  ##
  ## Recovery steps:
  ## 1. Find the best recovery point (most recent full or valid incremental)
  ## 2. If a full snapshot exists, rebuild chain from it (remove orphaned incrementals)
  ## 3. Delete incomplete snapshots (not readonly, invalid subvolumes)
  ## 4. Repair chain metadata on remaining valid snapshots

  var orphansRemoved = 0

  # Step 1: Find the best recovery point
  let recoveryPoint = findRecoveryPoint(snapshotDir).valueOr:
    warn "Failed to find recovery point, proceeding with basic recovery",
      error = error.msg
    Opt.none(string)

  # Step 2: If we found a full snapshot, rebuild chain from it
  if recoveryPoint.isSome:
    let recoveryPath = recoveryPoint.get
    let meta = getSnapshotMetadata(recoveryPath)
    if meta.isOk and meta.value.snapshotType == stFull:
      info "Found recovery anchor point (full snapshot)", path = recoveryPath

      # Count snapshots before rebuild to calculate orphans removed
      let beforeSnapshots = listSnapshots(snapshotDir).valueOr:
        return err(error)
      let beforeCount = beforeSnapshots.len

      rebuildChainFromFull(snapshotDir, recoveryPath, config).isOkOr:
        warn "Chain rebuild from full snapshot failed, continuing with cleanup",
          error = error.msg

      # Count after to determine orphans removed
      let afterSnapshots = listSnapshots(snapshotDir).valueOr:
        return err(error)
      orphansRemoved = beforeCount - afterSnapshots.len
      if orphansRemoved > 0:
        info "Removed orphaned snapshots during chain rebuild", count = orphansRemoved
    else:
      debug "Recovery point is incremental, skipping chain rebuild", path = recoveryPath

  # Step 3: Clean up incomplete snapshots
  let cleanupRes = cleanupIncompleteSnapshots(snapshotDir, config).valueOr:
    return err(error)

  # Step 4: Repair metadata on remaining valid snapshots
  let repairRes = repairChainMetadata(snapshotDir, config).valueOr:
    return err(error)

  info "Chain recovery completed",
    incompletesCleaned = cleanupRes.cleaned,
    orphansRemoved = orphansRemoved,
    metadataRepaired = repairRes

  ok(
    (
      incompletesCleaned: cleanupRes.cleaned,
      orphansRemoved: orphansRemoved,
      metadataRepaired: repairRes,
    )
  )

{.pop.}
