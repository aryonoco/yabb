# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2023-2026 Aryan Ameri
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#

## Retention manager - applies retention policies to snapshots
## Determines which snapshots to keep and which to delete

import std/[algorithm, sets, times, sequtils]
import ../wrappers/log
import ../types
import ../btrfs/[snapshot, operations, properties]
import ../utils/functional
import policy

type
  ## Represents the outcome of a snapshot deletion attempt
  DeletionOutcome = enum
    doDryRun ## Dry run mode - no actual deletion
    doSuccess ## Deletion succeeded
    doFailure ## Deletion failed

  ## Represents the result of checking a retention period for snapshots
  RetentionPeriodResult = enum
    rprEmpty ## No snapshots found in this period
    rprAlreadyKept ## Latest snapshot already in keep set
    rprNewSnapshot ## Found new snapshot to keep

{.push raises: [].}

proc keepCurrentPartialHour*(
    snapshots: seq[Snapshot],
    existingKeepSet: HashSet[string],
    referenceTime: DateTime = now().utc,
): HashSet[string] =
  ## Keep all snapshots in the current partial hour
  ## Returns a new HashSet with the existing entries plus new ones
  let currentHourStart = dateTime(
    referenceTime.year,
    referenceTime.month,
    referenceTime.monthday,
    referenceTime.hour,
    0,
    0,
    zone = utc(),
  )
  let currentHourEpoch = currentHourStart.toTime.toUnix

  # Filter snapshots in current hour
  let snapshotsToKeep =
    snapshots.filterIt(it.timestamp.toTime.toUnix >= currentHourEpoch)

  # Build new set with existing entries plus new ones - immutable pattern
  let newPaths = snapshotsToKeep.mapIt(it.path).toHashSet()

  # Log each kept snapshot
  snapshotsToKeep.applyIt:
    debug "Keeping snapshot from current partial hour", path = it.path

  debug "Kept snapshots from current partial hour", count = snapshotsToKeep.len

  existingKeepSet + newPaths

proc selectSnapshotsToKeep*(
    snapshots: seq[Snapshot],
    retention: RetentionPolicy,
    referenceTime: DateTime = now().utc,
): HashSet[string] =
  ## Determine which snapshots to keep based on retention policy
  ## Uses functional patterns to build the set immutably
  if snapshots.len == 0:
    return initHashSet[string]()

  # Sort by timestamp descending (newest first) - immutable sorted copy
  let sorted = snapshots.sorted(
    proc(a, b: Snapshot): int {.raises: [].} =
      cmp(b.timestamp, a.timestamp)
  )

  # 1. Start with most recent snapshot
  let baseSet = [sorted[0].path].toHashSet()
  info "Keeping most recent snapshot", path = sorted[0].path

  # 2. Keep all snapshots in the current partial hour
  let withPartialHour = keepCurrentPartialHour(sorted, baseSet, referenceTime)

  # 3. Apply each retention tier using functional accumulation
  proc applyRetentionPeriod(
      currentSet: HashSet[string],
      period: RetentionPeriod,
      count: Natural,
      periodName: string,
      sorted: seq[Snapshot],
      referenceTime: DateTime,
  ): HashSet[string] =
    if count == 0:
      return currentSet

    # Collect paths to keep from all periods using pattern matching
    let periodsToCheck = toSeq(0 ..< count)
    let pathsToAdd = periodsToCheck
      .mapIt(
        block:
          let (periodStart, periodEnd) = getPeriodBoundaries(period, it, referenceTime)
          let inPeriod =
            sorted.filterIt(isInPeriod(it.timestamp, periodStart, periodEnd))

          # Determine retention check result
          let (checkResult, latestPath) =
            if inPeriod.len == 0:
              (rprEmpty, "")
            else:
              let latest = inPeriod.foldl(if a.timestamp > b.timestamp: a else: b)
              if latest.path in currentSet:
                (rprAlreadyKept, latest.path)
              else:
                (rprNewSnapshot, latest.path)

          case checkResult
          of rprEmpty, rprAlreadyKept:
            Opt.none(string)
          of rprNewSnapshot:
            Opt.some(latestPath)
      )
      .filterIt(it.isSome)
      .mapIt(it.get)

    # Log the kept snapshots
    pathsToAdd.applyIt:
      info "Keeping retention snapshot", periodType = periodName, path = it

    currentSet + pathsToAdd.toHashSet()

  # Chain all retention periods
  let withHourly = applyRetentionPeriod(
    withPartialHour, rpHourly, retention.hourly, "hourly", sorted, referenceTime
  )
  let withDaily = applyRetentionPeriod(
    withHourly, rpDaily, retention.daily, "daily", sorted, referenceTime
  )
  let withWeekly = applyRetentionPeriod(
    withDaily, rpWeekly, retention.weekly, "weekly", sorted, referenceTime
  )
  let withMonthly = applyRetentionPeriod(
    withWeekly, rpMonthly, retention.monthly, "monthly", sorted, referenceTime
  )
  applyRetentionPeriod(
    withMonthly, rpYearly, retention.yearly, "yearly", sorted, referenceTime
  )

proc applyRetention*(
    snapshotDir: string, retention: RetentionPolicy, config: YabbConfig
): YabbResult[tuple[kept, deleted: int]] =
  ## Apply retention policy and delete expired snapshots
  # List all snapshots
  let snapshots = listSnapshots(snapshotDir).valueOr:
    return err(error)

  if snapshots.len == 0:
    info "No snapshots found for retention processing"
    return ok((kept: 0, deleted: 0))

  var toKeep = selectSnapshotsToKeep(snapshots, retention)

  # Always keep at least one full snapshot to prevent total data loss
  # (Parent protection removed - btrfs snapshots are independent after receive)
  let fullSnapshots =
    snapshots.filterIt(getProperty(it.path, PropType).valueOr("") == "full")
  if fullSnapshots.len > 0 and fullSnapshots.allIt(it.path notin toKeep):
    # Add oldest full snapshot to keep set
    let oldestFull = fullSnapshots.sortedByIt(it.timestamp)[0]
    info "Keeping oldest full snapshot to prevent data loss", path = oldestFull.path
    toKeep.incl(oldestFull.path)

  # Split into kept and to-delete using filter
  let keptSnapshots = snapshots.filterIt(it.path in toKeep)
  let toDeleteSnapshots = snapshots.filterIt(it.path notin toKeep)
  let kept = keptSnapshots.len

  # Process deletions and count successes using fold with pattern matching
  let (deleted, deletedList) = toDeleteSnapshots.foldl(
    block:
      # Determine deletion outcome
      let outcome =
        if config.dryRun:
          doDryRun
        elif deleteSubvolume(b.path, config.dryRun).isOk:
          doSuccess
        else:
          doFailure

      case outcome
      of doDryRun:
        info "DRY_RUN: Would delete snapshot", path = b.path
        (a[0] + 1, a[1])
      of doSuccess:
        (a[0] + 1, a[1] & @[b.path])
      of doFailure:
        warn "Failed to delete snapshot", path = b.path
        a # Keep counts unchanged on failure
    ,
    (0, newSeq[string]()),
  )

  # Log retention summary
  info "Retention process completed", retained = kept, deleted = deleted

  if kept > 0:
    toKeep.toSeq.applyIt:
      debug "Snapshot retained", path = it

  if deletedList.len > 0:
    deletedList.applyIt:
      debug "Snapshot deleted", path = it

  ok((kept: kept, deleted: deleted))

proc getRetentionSummary*(
    snapshotDir: string, retention: RetentionPolicy
): YabbResult[tuple[total, toKeep, toDelete: int]] =
  ## Get a summary of what retention would do (without applying)
  let snapshots = listSnapshots(snapshotDir).valueOr:
    return err(error)

  if snapshots.len == 0:
    return ok((total: 0, toKeep: 0, toDelete: 0))

  let toKeep = selectSnapshotsToKeep(snapshots, retention)

  ok((total: snapshots.len, toKeep: toKeep.len, toDelete: snapshots.len - toKeep.len))

{.pop.}
