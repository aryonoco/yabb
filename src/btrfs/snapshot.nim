## Snapshot creation, verification, and management
## Main module for BTRFS snapshot workflow

import std/[times, os, strutils, posix, sequtils, options]
import uuids
import ../wrappers/log
import ../types
import ../errors
import ../utils/[paths, retry, process, tempfile, functional]
import operations
import properties

{.push raises: [].}

func isValidSnapshotName*(name: string): bool =
  ## Validate snapshot name format: backup.YYYY-MM-DDTHHMMSSZ
  ## Pure Nim implementation - no PCRE dependency
  ## Equivalent to regex: ^backup\.[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{6}Z$
  if not name.startsWith(SnapshotPrefix):
    return false

  let tspart = name[SnapshotPrefix.len .. ^1]
  # Expected format: YYYY-MM-DDTHHMMSSZ (18 chars)
  # Breakdown: 4 + 1 + 2 + 1 + 2 + 1 + 6 + 1 = 18
  if tspart.len != 18:
    return false

  # Check each character position
  # YYYY-MM-DDTHHMMSSZ
  # 0123456789012345678
  #           1111111
  template isDigit(c: char): bool = c >= '0' and c <= '9'

  result = tspart[0].isDigit and tspart[1].isDigit and tspart[2].isDigit and tspart[3].isDigit and  # YYYY
           tspart[4] == '-' and
           tspart[5].isDigit and tspart[6].isDigit and  # MM
           tspart[7] == '-' and
           tspart[8].isDigit and tspart[9].isDigit and  # DD
           tspart[10] == 'T' and
           tspart[11].isDigit and tspart[12].isDigit and  # HH
           tspart[13].isDigit and tspart[14].isDigit and  # MM
           tspart[15].isDigit and tspart[16].isDigit and  # SS
           tspart[17] == 'Z'

proc formatSnapshotName*(timestamp: DateTime): string =
  ## Format a snapshot name from timestamp
  SnapshotPrefix & timestamp.format("yyyy-MM-dd'T'HHmmss'Z'")

proc formatSnapshotName*(): string =
  ## Format snapshot name using current UTC time
  formatSnapshotName(now().utc)

proc parseSnapshotTimestamp*(name: string): YabbResult[DateTime] =
  ## Parse timestamp from snapshot name
  if not name.startsWith(SnapshotPrefix):
    return err(yabbErr(ecInvalidVar, "SNAPSHOT", "Invalid snapshot name format: " & name))
  let tsStr = name[SnapshotPrefix.len..^1]
  try:
    ok(parse(tsStr, "yyyy-MM-dd'T'HHmmss'Z'", utc()))
  except TimeParseError:
    err(yabbErr(ecInvalidVar, "SNAPSHOT", "Invalid timestamp in snapshot name: " & name))

proc getLastSnapshot*(): Opt[string] =
  ## Read last snapshot path from tracking file
  if fileExists(LastSnapshotFile):
    try:
      let path = readFile(LastSnapshotFile).strip()
      if path.len > 0 and dirExists(path):
        return Opt.some(path)
    except IOError:
      discard
  Opt.none(string)

proc saveLastSnapshot*(path: string, dryRun: bool): YabbResult[void] =
  ## Save snapshot path to tracking file
  if dryRun:
    debug "DRY_RUN: Would update last snapshot reference", path = path
    return ok()
  try:
    writeFile(LastSnapshotFile, path & "\n")
    ok()
  except IOError as e:
    err(btrfsError("Failed to update last snapshot file: " & e.msg))

proc detectChanges*(
  parentSnapshot: string,
  currentSnapshot: string,
  config: YabbConfig
): YabbResult[bool] =
  ## Detect if there are changes between snapshots
  ## Returns err(ecNoChanges) if no changes detected
  if config.dryRun:
    debug "DRY_RUN: Would check for changes",
      parentSnapshot = parentSnapshot, currentSnapshot = currentSnapshot
    return ok(true)  # Assume changes in dry run

  # Validate input paths exist
  if not dirExists(parentSnapshot):
    return err(btrfsError("Parent snapshot does not exist: " & parentSnapshot))
  if not dirExists(currentSnapshot):
    return err(btrfsError("Current snapshot does not exist: " & currentSnapshot))

  # Create temp file for send output - RAII guard handles cleanup
  let tempGuard = createTempFileGuard(TempSendPrefix, ".bin").valueOr:
    return err(error)

  debug "Comparing snapshots", parentSnapshot = parentSnapshot, currentSnapshot = currentSnapshot

  # Run btrfs send to temp file with retry
  let sendRes = retry(
    config.retryCount,
    config.retryDelay,
    proc(): YabbResult[int64] {.raises: [].} =
      runBtrfsSend(@["--quiet", "-p", parentSnapshot, currentSnapshot], tempGuard.path)
    ,
    "Generating incremental send stream for change detection"
  )

  # Check result - empty file means no changes
  if sendRes.isErr:
    # Check if file exists but is empty (no changes case)
    let fileSize = try: getFileSize(tempGuard.path) except OSError: -1
    if fileExists(tempGuard.path) and fileSize == 0:
      debug "No changes detected between snapshots"
      return err(noChangesError("No changes detected between snapshots"))
    # Real error occurred
    return err(btrfsError("Failed to compare snapshots: " & sendRes.error.msg))

  let bytesWritten = sendRes.value

  # Empty stream means no changes
  let finalSize = try: getFileSize(tempGuard.path) except OSError: -1
  if bytesWritten == 0 or finalSize == 0:
    debug "No changes detected between snapshots"
    return err(noChangesError("No changes detected between snapshots"))

  # Verify send stream integrity
  let validateRes = retry(
    config.retryCount,
    config.retryDelay,
    proc(): YabbResult[void] {.raises: [].} = validateSendStream(tempGuard.path),
    "Validating send stream integrity"
  )
  if validateRes.isErr:
    return err(btrfsError("Invalid send stream between snapshots"))

  if config.debug:
    debug "Detected changes", streamSize = bytesWritten

  info "Changes detected between snapshots"
  ok(true)

proc verifySnapshot*(path: string, config: YabbConfig): YabbResult[bool] =
  ## Verify snapshot integrity
  ## Checks: directory, subvolume, readonly, required props, name, timestamp, parent
  if config.dryRun:
    debug "DRY_RUN: Would verify snapshot", path = path
    return ok(true)

  # 1. Verify directory existence
  if not dirExists(path):
    return err(btrfsError("Snapshot path does not exist: " & path))

  # 2. Verify btrfs subvolume with retry
  let showRes = retry(
    config.retryCount,
    config.retryDelay,
    proc(): YabbResult[CommandResult] {.raises: [].} = runBtrfs(["subvolume", "show", path]),
    "Verifying btrfs subvolume"
  )
  if showRes.isErr or showRes.value.exitCode != 0:
    return err(btrfsError("Not a valid btrfs subvolume: " & path))

  # 3. Verify read-only status with retry
  let roRes = retry(
    config.retryCount,
    config.retryDelay,
    proc(): YabbResult[string] {.raises: [].} = getProperty(path, "ro"),
    "Checking read-only property"
  )
  if roRes.isErr or roRes.value != "true":
    return err(btrfsError("Snapshot is not read-only: " & path))

  # 4. Verify required metadata properties - find first missing
  proc checkProp(prop: string): bool =
    retry(
      config.retryCount,
      config.retryDelay,
      proc(): YabbResult[string] {.raises: [].} = getProperty(path, prop),
      "Checking property " & prop
    ).isErr
  let missingProp = RequiredProps.toSeq.findFirst(checkProp(it))
  if missingProp.isSome:
    return err(btrfsError("Missing required property: " & missingProp.get))

  # 5. Verify snapshot name format
  let name = extractFilename(path)
  if not isValidSnapshotName(name):
    return err(btrfsError("Invalid snapshot name format: " & name))

  # 6. Verify snapshot timestamp is valid
  let tsRes = parseSnapshotTimestamp(name)
  if tsRes.isErr:
    return err(btrfsError("Invalid snapshot timestamp: " & name))

  # 7. Verify parent snapshot exists if incremental
  let typeRes = getProperty(path, PropType)
  if typeRes.isOk and typeRes.value == "incremental":
    let parentRes = getProperty(path, PropParent)
    if parentRes.isOk:
      let parentPath = parentRes.value
      if parentPath != "none" and not dirExists(parentPath):
        return err(btrfsError("Parent snapshot not found: " & parentPath))

  debug "Snapshot verified successfully", path = path
  ok(true)

proc getHostname(): string =
  ## Get system hostname
  try:
    readFile("/etc/hostname").strip()
  except IOError:
    "unknown"

type
  SnapshotDecision = object
    ## Immutable snapshot planning result
    parentSnapshot: Opt[string]
    doFullSnapshot: bool
    tempCompareSnapshot: string  # Path to temp snapshot for cleanup (empty if none)
    noChangesDetected: bool

proc determineSnapshotDecision(
  config: YabbConfig,
  srcDir: string,
  snapshotDir: string
): SnapshotDecision =
  ## Determine snapshot strategy based on previous snapshot and change detection
  ## Returns an immutable decision object with all necessary information

  # If forcing full snapshot, skip all change detection
  if config.forceFull:
    return SnapshotDecision(
      parentSnapshot: Opt.none(string),
      doFullSnapshot: true,
      tempCompareSnapshot: "",
      noChangesDetected: false
    )

  let lastSnapshot = getLastSnapshot()
  if lastSnapshot.isNone:
    return SnapshotDecision(
      parentSnapshot: Opt.none(string),
      doFullSnapshot: true,
      tempCompareSnapshot: "",
      noChangesDetected: false
    )

  # Verify last snapshot is valid
  let verifyRes = verifySnapshot(lastSnapshot.get, config)
  if verifyRes.isErr:
    warn "Last snapshot verification failed, proceeding with full snapshot"
    return SnapshotDecision(
      parentSnapshot: Opt.none(string),
      doFullSnapshot: true,
      tempCompareSnapshot: "",
      noChangesDetected: false
    )

  # Create temporary readonly snapshot for comparison
  let tempPath = snapshotDir / (TempComparePrefix & "." & $getpid())
  let tempSnapRes = retry(
    config.retryCount,
    config.retryDelay,
    proc(): YabbResult[void] {.raises: [].} =
      operations.createSnapshot(srcDir, tempPath, readonly = true, dryRun = config.dryRun)
    ,
    "Creating temp snapshot for change detection"
  )

  if tempSnapRes.isErr:
    warn "Failed to create temp snapshot for comparison, proceeding with full snapshot"
    return SnapshotDecision(
      parentSnapshot: Opt.none(string),
      doFullSnapshot: true,
      tempCompareSnapshot: "",
      noChangesDetected: false
    )

  # Check for changes using readonly temp snapshot
  let changesRes = detectChanges(lastSnapshot.get, tempPath, config)
  if changesRes.isErr and changesRes.error.code == ecNoChanges:
    return SnapshotDecision(
      parentSnapshot: Opt.none(string),
      doFullSnapshot: true,
      tempCompareSnapshot: tempPath,
      noChangesDetected: true
    )

  if changesRes.isOk:
    return SnapshotDecision(
      parentSnapshot: lastSnapshot,
      doFullSnapshot: false,
      tempCompareSnapshot: tempPath,
      noChangesDetected: false
    )

  # Change detection failed for another reason - proceed with full
  SnapshotDecision(
    parentSnapshot: Opt.none(string),
    doFullSnapshot: true,
    tempCompareSnapshot: tempPath,
    noChangesDetected: false
  )

proc createBackupSnapshot*(
  config: YabbConfig,
  srcDir: string,
  snapshotDir: string
): YabbResult[Snapshot] =
  ## Create a new btrfs snapshot with full backup workflow
  let timestamp = now().utc
  let snapshotName = formatSnapshotName(timestamp)
  let snapshotPath = snapshotDir / snapshotName

  # Ensure snapshot directory exists
  ensureDir(snapshotDir, config.dryRun).isOkOr:
    return err(error)

  # Determine snapshot strategy - all decisions made upfront (immutable)
  let decision = determineSnapshotDecision(config, srcDir, snapshotDir)

  # Cleanup temp snapshot when done
  defer:
    if decision.tempCompareSnapshot.len > 0 and dirExists(decision.tempCompareSnapshot):
      discard deleteSubvolume(decision.tempCompareSnapshot, config.dryRun)

  # Check if no changes were detected
  if decision.noChangesDetected:
    info "No changes detected, skipping snapshot"
    return err(noChangesError("No changes detected"))

  # Use immutable references from decision
  let parentSnapshot = decision.parentSnapshot
  let doFullSnapshot = decision.doFullSnapshot

  # Create readonly snapshot
  let createRes = retry(
    config.retryCount,
    config.retryDelay,
    proc(): YabbResult[void] {.raises: [].} =
      operations.createSnapshot(srcDir, snapshotPath, readonly = true, dryRun = config.dryRun)
    ,
    "Creating snapshot"
  )
  if createRes.isErr:
    return err(createRes.error)

  # Set metadata properties
  let uuid = try: $genUUID()
             except OSError, IOError: "unknown-" & $now().utc.toTime.toUnix
  let snapshotType = if doFullSnapshot: stFull else: stIncremental
  let chainPos = if parentSnapshot.isSome: getChainPosition(parentSnapshot.get) + 1 else: 0

  if not config.dryRun:
    # Get optional system info
    let kernelRes = runCommand("uname", ["-r"])
    let kernel = if kernelRes.isOk and kernelRes.value.output.strip.len > 0:
      Opt.some(kernelRes.value.output.strip())
    else:
      Opt.none(string)

    let fsUuidRes = runCommand("btrfs", ["filesystem", "show", srcDir])
    let fsUuid = if fsUuidRes.isOk:
      let match = fsUuidRes.value.output.find("uuid: ")
      if match >= 0:
        Opt.some(fsUuidRes.value.output[match + 6 ..< min(match + 42, fsUuidRes.value.output.len)])
      else:
        Opt.none(string)
    else:
      Opt.none(string)

    discard setSnapshotMetadata(snapshotPath, SnapshotMetadata(
      uuid: uuid,
      timestamp: timestamp,
      snapshotType: snapshotType,
      parent: parentSnapshot,
      chainPosition: chainPos,
      chainLength: chainPos + 1,
      compression: $config.compression.algo & ":" & $config.compression.level,
      source: Opt.some(srcDir),
      hostname: Opt.some(getHostname()),
      kernel: kernel,
      fsUuid: fsUuid,
      sizeBytes: 0
    ), config.dryRun)

  # Send snapshot to destination using temp file - RAII guard handles cleanup
  let sendTempGuard = createTempFileGuard(TempSendPrefix, ".bin").valueOr:
    return err(error)

  # Build send args - immutable conditional expression
  let isIncremental = parentSnapshot.isSome and not doFullSnapshot
  let sendArgs = if isIncremental:
    @["--compressed-data", "-c", parentSnapshot.get, "-p", parentSnapshot.get, snapshotPath]
  else:
    @["--compressed-data", snapshotPath]

  if isIncremental:
    info "Performing incremental snapshot send from parent"
  else:
    info "Performing full snapshot send"

  # Step 1: btrfs send > temp file
  let sendRes = retry(
    config.retryCount,
    config.retryDelay,
    proc(): YabbResult[int64] {.raises: [].} = runBtrfsSend(sendArgs, sendTempGuard.path, config.dryRun),
    "Sending snapshot"
  )
  if sendRes.isErr:
    # Fallback to full send if incremental fails
    if parentSnapshot.isSome and not doFullSnapshot:
      warn "Incremental send failed, falling back to full send"
      let fullSendRes = retry(
        config.retryCount,
        config.retryDelay,
        proc(): YabbResult[int64] {.raises: [].} = runBtrfsSend(
          @["--compressed-data", snapshotPath],
          sendTempGuard.path,
          config.dryRun
        ),
        "Sending full snapshot (fallback)"
      )
      if fullSendRes.isErr:
        return err(fullSendRes.error)
    else:
      return err(sendRes.error)

  # Step 2: btrfs receive -f temp file destdir
  let recvRes = retry(
    config.retryCount,
    config.retryDelay,
    proc(): YabbResult[void] {.raises: [].} = runBtrfsReceive(
      @["--max-errors", "10", "-v", config.dstDir],
      sendTempGuard.path,
      config.dryRun
    ),
    "Receiving snapshot"
  )
  if recvRes.isErr:
    return err(recvRes.error)

  # Update chain length on all snapshots in the chain
  if not config.dryRun:
    let newChainLength = chainPos + 1
    discard updateChainLength(snapshotDir, newChainLength, config.dryRun)

  # Verify the new snapshot
  let verifyRes = verifySnapshot(snapshotPath, config)
  if verifyRes.isErr:
    return err(verifyRes.error)

  # Update last snapshot tracking
  saveLastSnapshot(snapshotPath, config.dryRun).isOkOr:
    warn "Failed to update last snapshot reference", error = error.msg

  info "Snapshot created successfully", path = snapshotPath

  ok(Snapshot(
    path: snapshotPath,
    name: snapshotName,
    timestamp: timestamp,
    snapshotType: snapshotType,
    parent: parentSnapshot,
    uuid: uuid,
    verified: true
  ))

proc tryParseSnapshot(path: string): Opt[Snapshot] =
  ## Try to parse a path as a valid snapshot, returning None if invalid
  let name = extractFilename(path)
  if not name.startsWith(SnapshotPrefix):
    return Opt.none(Snapshot)
  let tsRes = parseSnapshotTimestamp(name)
  if tsRes.isErr:
    debug "Skipping invalid snapshot", path = path, error = tsRes.error.msg
    return Opt.none(Snapshot)
  Opt.some(Snapshot(
    path: path,
    name: name,
    timestamp: tsRes.value,
    snapshotType: stFull,  # Will be updated if we read metadata
    parent: Opt.none(string),
    uuid: "",
    verified: false
  ))

proc listSnapshots*(snapshotDir: string): YabbResult[seq[Snapshot]] =
  ## List all valid snapshots in directory
  if not dirExists(snapshotDir):
    return ok(newSeq[Snapshot]())

  let entries = try: toSeq(walkDir(snapshotDir))
    except OSError as e: return err(btrfsError("Failed to list snapshots: " & e.msg))

  # Filter directories, parse as snapshots, keep valid ones
  let snapshots = entries
    .filterIt(it.kind == pcDir)
    .mapIt(tryParseSnapshot(it.path))
    .filterIt(it.isSome)
    .mapIt(it.get)

  ok(snapshots)

{.pop.}
