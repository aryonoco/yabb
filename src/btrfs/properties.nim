# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2023-2026 Aryan Ameri
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#

## BTRFS snapshot property management
## Uses user.yabb.* namespace for snapshot metadata

import std/[times, strutils, os, sequtils]
import ../wrappers/log
import ../types
import ../errors
import ../utils/functional
import operations

type SnapshotMetadata* = object # Required fields
  uuid*: string
  timestamp*: DateTime
  snapshotType*: SnapshotType
  parent*: Opt[string]
  chainPosition*: Natural
  chainLength*: Natural
  compression*: string
  # Optional fields - use Opt[string] for explicit absence tracking
  source*: Opt[string]
  hostname*: Opt[string]
  kernel*: Opt[string]
  fsUuid*: Opt[string]
  fsLabel*: Opt[string]
  platform*: Opt[string]
  destination*: Opt[string]
  sizeBytes*: int64

const
  PropPrefix* = "user.yabb."

  # Required properties (for verification + chain logic)
  PropUuid* = PropPrefix & "uuid"
  PropTimestamp* = PropPrefix & "timestamp"
  PropType* = PropPrefix & "type"
  PropParent* = PropPrefix & "parent"
  PropChainPosition* = PropPrefix & "chain.pos"
  PropChainLength* = PropPrefix & "chain.len"
  PropCompression* = PropPrefix & "compression"

  # Optional properties (additional metadata)
  PropSource* = PropPrefix & "source"
  PropHostname* = PropPrefix & "hostname"
  PropKernel* = PropPrefix & "kernel"
  PropFsUuid* = PropPrefix & "fs.uuid"
  PropFsLabel* = PropPrefix & "fs.label"
  PropPlatform* = PropPrefix & "platform"
  PropDestination* = PropPrefix & "destination"
  PropSizeBytes* = PropPrefix & "size"
  PropVerified* = PropPrefix & "verified"

  # Required properties for verification
  RequiredProps* = [
    PropUuid, PropTimestamp, PropType, PropParent, PropCompression, PropChainPosition,
    PropChainLength,
  ]

  # Sentinel value for serializing absent parent
  NoParentSentinel* = "none"

{.push raises: [].}

proc setSnapshotMetadata*(
    path: string, meta: SnapshotMetadata, dryRun: bool = false
): YabbResult[void] =
  ## Set all metadata properties on a snapshot
  ## Required properties must succeed; optional properties log warnings on failure
  if dryRun:
    debug "DRY_RUN: Would set snapshot metadata", path = path
    return ok()

  # Required properties
  setProperty(path, PropUuid, meta.uuid, dryRun).isOkOr:
    return err(error)

  setProperty(
    path, PropTimestamp, meta.timestamp.format("yyyy-MM-dd'T'HH:mm:ss'Z'"), dryRun
  ).isOkOr:
    return err(error)
  setProperty(path, PropType, $meta.snapshotType, dryRun).isOkOr:
    return err(error)

  setProperty(
    path,
    PropParent,
    if meta.parent.isSome: meta.parent.get else: NoParentSentinel,
    dryRun,
  ).isOkOr:
    return err(error)
  setProperty(path, PropChainPosition, $meta.chainPosition, dryRun).isOkOr:
    return err(error)
  setProperty(path, PropChainLength, $meta.chainLength, dryRun).isOkOr:
    return err(error)
  setProperty(path, PropCompression, meta.compression, dryRun).isOkOr:
    return err(error)

  # Optional properties (warn on failure, don't fail)
  if meta.source.isSome:
    discard setProperty(path, PropSource, meta.source.get, dryRun)
  if meta.hostname.isSome:
    discard setProperty(path, PropHostname, meta.hostname.get, dryRun)
  if meta.kernel.isSome:
    discard setProperty(path, PropKernel, meta.kernel.get, dryRun)
  if meta.fsUuid.isSome:
    discard setProperty(path, PropFsUuid, meta.fsUuid.get, dryRun)
  if meta.fsLabel.isSome:
    discard setProperty(path, PropFsLabel, meta.fsLabel.get, dryRun)
  if meta.platform.isSome:
    discard setProperty(path, PropPlatform, meta.platform.get, dryRun)
  if meta.destination.isSome:
    discard setProperty(path, PropDestination, meta.destination.get, dryRun)
  if meta.sizeBytes > 0:
    discard setProperty(path, PropSizeBytes, $meta.sizeBytes, dryRun)

  debug "Set snapshot metadata", path = path, uuid = meta.uuid
  ok()

proc getSnapshotMetadata*(path: string): YabbResult[SnapshotMetadata] =
  ## Read metadata properties from a snapshot
  let uuid = getProperty(path, PropUuid).valueOr:
    return err(error)
  let tsStr = getProperty(path, PropTimestamp).valueOr:
    return err(error)

  let timestamp =
    try:
      parse(tsStr, "yyyy-MM-dd'T'HH:mm:ss'Z'", utc())
    except TimeParseError:
      return err(btrfsError("Invalid timestamp format: " & tsStr))

  let typeStr = getProperty(path, PropType).valueOr:
    return err(error)
  let snapshotType =
    case typeStr
    of "full":
      stFull
    of "incremental":
      stIncremental
    else:
      return err(btrfsError("Invalid snapshot type: " & typeStr))

  let parentStr = getProperty(path, PropParent).valueOr:
    NoParentSentinel
  let parent =
    if parentStr.len > 0 and parentStr != NoParentSentinel:
      Opt.some(parentStr)
    else:
      Opt.none(string)

  let compression = getProperty(path, PropCompression).valueOr:
    ""

  # Optional fields - convert to Opt[string] for explicit absence tracking
  let hostnameRes = getProperty(path, PropHostname)
  let hostname =
    if hostnameRes.isOk and hostnameRes.value.len > 0:
      Opt.some(hostnameRes.value)
    else:
      Opt.none(string)

  let sourceRes = getProperty(path, PropSource)
  let source =
    if sourceRes.isOk and sourceRes.value.len > 0:
      Opt.some(sourceRes.value)
    else:
      Opt.none(string)

  let kernelRes = getProperty(path, PropKernel)
  let kernel =
    if kernelRes.isOk and kernelRes.value.len > 0:
      Opt.some(kernelRes.value)
    else:
      Opt.none(string)

  let fsUuidRes = getProperty(path, PropFsUuid)
  let fsUuid =
    if fsUuidRes.isOk and fsUuidRes.value.len > 0:
      Opt.some(fsUuidRes.value)
    else:
      Opt.none(string)

  let fsLabelRes = getProperty(path, PropFsLabel)
  let fsLabel =
    if fsLabelRes.isOk and fsLabelRes.value.len > 0:
      Opt.some(fsLabelRes.value)
    else:
      Opt.none(string)

  let platformRes = getProperty(path, PropPlatform)
  let platform =
    if platformRes.isOk and platformRes.value.len > 0:
      Opt.some(platformRes.value)
    else:
      Opt.none(string)

  let destinationRes = getProperty(path, PropDestination)
  let destination =
    if destinationRes.isOk and destinationRes.value.len > 0:
      Opt.some(destinationRes.value)
    else:
      Opt.none(string)

  let chainPosStr = getProperty(path, PropChainPosition).valueOr:
    "0"
  let chainPos =
    try:
      parseInt(chainPosStr)
    except ValueError:
      0

  let chainLenStr = getProperty(path, PropChainLength).valueOr:
    "0"
  let chainLen =
    try:
      parseInt(chainLenStr)
    except ValueError:
      0

  let sizeStr = getProperty(path, PropSizeBytes).valueOr:
    "0"
  let sizeBytes =
    try:
      parseBiggestInt(sizeStr)
    except ValueError:
      0i64

  ok(
    SnapshotMetadata(
      uuid: uuid,
      timestamp: timestamp,
      snapshotType: snapshotType,
      parent: parent,
      chainPosition: chainPos,
      chainLength: chainLen,
      compression: compression,
      source: source,
      hostname: hostname,
      kernel: kernel,
      fsUuid: fsUuid,
      fsLabel: fsLabel,
      platform: platform,
      destination: destination,
      sizeBytes: sizeBytes,
    )
  )

proc getChainPosition*(path: string): int =
  ## Get chain position from snapshot, returns 0 if not set
  let res = getProperty(path, PropChainPosition)
  if res.isOk:
    try:
      return parseInt(res.value)
    except ValueError:
      discard
  0

proc updateChainLength*(
    snapshotDir: string, length: Natural, dryRun: bool = false
): YabbResult[void] =
  ## Update chain length on ALL snapshots in the backup set
  ## This ensures all snapshots know the total chain length for verification
  if dryRun:
    debug "DRY_RUN: Would update chain length",
      snapshotDir = snapshotDir, length = length
    return ok()

  let entries =
    try:
      toSeq(walkDir(snapshotDir))
    except OSError:
      @[]

  entries.filterIt(
    it.kind == pcDir and extractFilename(it.path).startsWith(SnapshotPrefix)
  ).applyIt:
    discard setProperty(it.path, PropChainLength, $length, dryRun)

  debug "Updated chain length on snapshots", snapshotDir = snapshotDir, length = length
  ok()

proc hasRequiredProperties*(path: string): YabbResult[bool] =
  ## Check if snapshot has all required properties
  let allPresent = RequiredProps.toSeq.allIt(getProperty(path, it).isOk)
  ok(allPresent)

{.pop.}
