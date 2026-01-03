# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2023-2026 Aryan Ameri
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#

## CLI interface using cligen

import std/[os, times, strutils, json, sequtils]
import cligen
import wrappers/log
import types
import config
import errors
import logging
import btrfs/[snapshot, operations, storage]
import chain/[manager, recovery]
import retention/manager as retentionManager
import utils/[lock, prereq, terminal, functional, progress, shutdown]

type
  OutputFormat = enum
    ofText, ofJson

  OutputContext* = object
    ## Immutable context for output formatting - replaces global state
    format*: OutputFormat
    colorEnabled*: bool

func newOutputContext*(json: bool, isTty: bool): OutputContext =
  ## Create output context based on CLI flags and terminal detection
  OutputContext(
    format: if json: ofJson else: ofText,
    colorEnabled: not json and isTty
  )

const LockTimeout* = 300  # 5 minutes

# Workflow progress steps for the main backup operation
const BackupWorkflowSteps* = @[
  WorkflowStep(name: "Load config", activeName: "Loading configuration..."),
  WorkflowStep(name: "Check prerequisites", activeName: "Checking prerequisites..."),
  WorkflowStep(name: "Acquire lock", activeName: "Acquiring lock..."),
  WorkflowStep(name: "Validate config", activeName: "Validating configuration..."),
  WorkflowStep(name: "Check space", activeName: "Checking filesystem space..."),
  WorkflowStep(name: "Cleanup incomplete", activeName: "Cleaning up incomplete snapshots..."),
  WorkflowStep(name: "Create snapshot", activeName: "Creating backup snapshot..."),
  WorkflowStep(name: "Apply retention", activeName: "Applying retention policy..."),
  WorkflowStep(name: "Finalize", activeName: "Finalizing backup..."),
]

{.push raises: [].}

# =============================================================================
# Output Helpers
# =============================================================================

proc outputSuccess*(ctx: OutputContext, msg: string) =
  ## Output success message based on output context
  try:
    if ctx.format == ofJson:
      echo(%*{"status": "success", "message": msg})
    else:
      userSuccess(msg)
  except IOError:
    discard

proc outputError*(ctx: OutputContext, msg: string) =
  ## Output error message based on output context
  try:
    if ctx.format == ofJson:
      echo(%*{"status": "error", "message": msg})
    else:
      userError(msg)
  except IOError:
    discard

proc outputInfo*(ctx: OutputContext, msg: string) =
  ## Output info message based on output context
  try:
    if ctx.format == ofJson:
      echo(%*{"status": "info", "message": msg})
    else:
      userInfo(msg)
  except IOError:
    discard

proc outputJson*(ctx: OutputContext, data: JsonNode) =
  ## Output JSON data (only in JSON mode, silent in text mode)
  try:
    if ctx.format == ofJson:
      echo data.pretty
  except IOError:
    discard

proc withSpinner*[T](ctx: OutputContext, msg: string, op: proc(): YabbResult[T] {.closure, raises: [].},
                     successCodes: set[ExitCode] = {}): YabbResult[T] {.raises: [].} =
  ## Execute operation with spinner feedback (only in text mode)
  ## successCodes: error codes that should show as success (e.g., ecNoChanges)
  if ctx.format == ofJson:
    return op()

  let spinner = newSpinnerState(msg)
  spinner.renderStart()
  result = op()
  if result.isOk or (result.isErr and result.error.code in successCodes):
    spinner.renderFinish(true)
  else:
    spinner.renderFinish(false)

proc cleanupResources*(cfg: YabbConfig) =
  if cfg.dryRun:
    return
  let cutoff = (now() - initDuration(minutes = 60)).toTime()

  # Cleanup temp files in /tmp - use functional filter then loop for side effects
  let tmpEntries = try: toSeq(walkDir("/tmp")) except OSError: @[]
  let oldTempFiles = tmpEntries
    .filterIt(it.kind == pcFile and extractFilename(it.path).startsWith("yabb"))
    .filterIt(block:
      try:
        let info = getFileInfo(it.path)
        info.lastWriteTime < cutoff
      except OSError: false
    )
  oldTempFiles.applyIt:
    try: removeFile(it.path)
    except OSError: discard

  # Cleanup old temp snapshots - use functional filter then loop for side effects
  if cfg.snapshotDir.len > 0 and dirExists($cfg.snapshotDir):
    let snapEntries = try: toSeq(walkDir($cfg.snapshotDir)) except OSError: @[]
    let oldTempSnaps = snapEntries
      .filterIt(it.kind == pcDir and extractFilename(it.path).startsWith("yabb-"))
      .filterIt(block:
        try:
          let info = getFileInfo(it.path)
          info.lastWriteTime < cutoff
        except OSError: false
      )
    oldTempSnaps.applyIt:
      discard deleteSubvolume(it.path, cfg.dryRun)

proc run*(
  configPath: string = DefaultConfigPath,
  debug: bool = false,
  dryRun: bool = false,
  forceFull: bool = false,
  json: bool = false
): int =
  ## Run BTRFS backup with optional incremental detection
  # Install signal handlers for graceful shutdown (SIGTERM, SIGINT, etc.)
  installSignalHandlers()

  # Initialize stats with start time for runtime tracking
  let baseStats = initStats(epochTime())

  let ctx = newOutputContext(json, isTerminal())
  if ctx.colorEnabled:
    useColors = true
  else:
    useColors = false
  initLogging(debug)

  # Create workflow progress tracker (TTY-only visual feedback)
  let jsonMode = ctx.format == ofJson
  var wp = newWorkflowProgress("YABB Backup", BackupWorkflowSteps)

  # Helper to advance and render progress
  template advanceProgress(step: int) =
    wp = wp.atStep(step)
    wp.renderStep(jsonMode)

  # Helper to log summary and return status
  proc finish(cfg: YabbConfig, fileLock: sink FileLock, status: int, stats: ExecutionStats, success: bool): int =
    release(fileLock)
    cleanupResources(cfg)
    wp.renderComplete(success, jsonMode)
    logSummary(status, stats)
    # Forward to journald if available
    if journalCtx.available:
      let statusMsg = if status != 0 or stats.errors > 0:
        "Backup completed with errors (status=" & $status & ", errors=" & $stats.errors & ")"
      elif stats.warnings > 0:
        "Backup completed with warnings (warnings=" & $stats.warnings & ")"
      else:
        "Backup completed successfully"
      let priority = if status != 0 or stats.errors > 0: jpErr
                     elif stats.warnings > 0: jpWarning
                     else: jpInfo
      journalCtx.logToJournal(statusMsg, priority)
    status

  # Step 0: Load config
  advanceProgress(0)
  let baseConfig = loadConfig(configPath).valueOr:
    error "Configuration error", msg = error.msg
    logSummary(error.code.ord, baseStats.withError())
    return error.code.ord

  # Use immutable merge instead of mutation
  let initialCfg = baseConfig.withOverrides(debug, dryRun, forceFull)

  # Step 1: Check prerequisites
  advanceProgress(1)
  checkPrerequisites(initialCfg).isOkOr:
    error "Prerequisite check failed", msg = error.msg
    logSummary(error.code.ord, baseStats.withError())
    return error.code.ord

  # Step 2: Acquire lock
  advanceProgress(2)
  let fileLock = acquireLock(LockFile, LockTimeout).valueOr:
    if error.code == ecLockHeld:
      # Another instance running - informational, not an error
      info "Another instance is running"
      return ecSuccess.ord
    # Real lock error (permission denied, I/O failure, etc.)
    error "Failed to acquire lock", msg = error.msg
    logSummary(error.code.ord, baseStats.withError())
    return error.code.ord

  # Check for shutdown before validation
  checkShutdown().isOkOr:
    info "Shutdown requested, exiting"
    return finish(initialCfg, fileLock, ecShutdown.ord, baseStats, false)

  # Step 3: Validate config
  advanceProgress(3)
  validateConfig(initialCfg).isOkOr:
    error "Config validation failed", msg = error.msg
    return finish(initialCfg, fileLock, error.code.ord, baseStats.withError(), false)

  # Step 4: Check space
  advanceProgress(4)
  checkFilesystemSpace($initialCfg.srcDir, initialCfg.minFreeSpace).isOkOr:
    error "Insufficient space in source", msg = error.msg
    return finish(initialCfg, fileLock, error.code.ord, baseStats.withError(), false)

  checkFilesystemSpace($initialCfg.dstDir, initialCfg.minFreeSpace).isOkOr:
    error "Insufficient space in destination", msg = error.msg
    return finish(initialCfg, fileLock, error.code.ord, baseStats.withError(), false)

  verifyCompression($initialCfg.srcDir, initialCfg.compression).isOkOr:
    error "Compression verification failed", msg = error.msg
    return finish(initialCfg, fileLock, error.code.ord, baseStats.withError(), false)

  # Check chain length and determine final forceFull value
  let needsForceFull = if initialCfg.forceFull:
    false  # Already forcing full, no need to check
  else:
    let needsFull = shouldForceFullSnapshot(
      $initialCfg.snapshotDir,
      initialCfg.chain.maxLength,
      initialCfg.dryRun
    ).valueOr:
      warn "Chain length check failed, proceeding with incremental", msg = error.msg
      false
    if needsFull:
      info "Forcing full snapshot due to chain length limit"
    needsFull

  # Create final config with potentially updated forceFull
  let cfg = if needsForceFull:
    initialCfg.withOverrides(debug, dryRun, forceFull = true)
  else:
    initialCfg

  # Check for shutdown before cleanup
  checkShutdown().isOkOr:
    info "Shutdown requested, exiting"
    return finish(cfg, fileLock, ecShutdown.ord, baseStats, false)

  # Step 5: Cleanup incomplete snapshots (always run before backup)
  advanceProgress(5)
  let cleanupRes = withSpinner(ctx, "Cleaning up incomplete snapshots", proc(): YabbResult[tuple[cleaned: int, failed: int]] =
    cleanupIncompleteSnapshots($cfg.snapshotDir, cfg)
  )
  if cleanupRes.isErr:
    # Cleanup failure is non-fatal - warn and continue
    warn "Incomplete snapshot cleanup failed (non-fatal)", msg = cleanupRes.error.msg
  elif cleanupRes.value.cleaned > 0:
    info "Cleaned up incomplete snapshots", cleaned = cleanupRes.value.cleaned

  # Check for shutdown before snapshot creation
  checkShutdown().isOkOr:
    info "Shutdown requested, exiting"
    return finish(cfg, fileLock, ecShutdown.ord, baseStats, false)

  # Step 6: Create snapshot
  advanceProgress(6)
  let snapshotRes = withSpinner(ctx, "Creating backup snapshot", proc(): YabbResult[Snapshot] =
    createBackupSnapshot(cfg, $cfg.srcDir, $cfg.snapshotDir)
  , successCodes = {ecNoChanges, ecShutdown})
  if snapshotRes.isErr:
    if snapshotRes.error.code == ecNoChanges:
      info "No changes detected, skipping backup"
      return finish(cfg, fileLock, ecNoChanges.ord, baseStats, true)  # No changes is success
    if snapshotRes.error.code == ecShutdown:
      info "Shutdown requested during snapshot"
      return finish(cfg, fileLock, ecShutdown.ord, baseStats, false)
    error "Snapshot creation failed", msg = snapshotRes.error.msg
    return finish(cfg, fileLock, snapshotRes.error.code.ord, baseStats.withError(), false)

  info "Snapshot created successfully", path = snapshotRes.value.path
  let snapshotStats = baseStats.withSnapshotCreated().withOperation("snapshot created")

  # Check for shutdown before retention
  checkShutdown().isOkOr:
    info "Shutdown requested, exiting"
    return finish(cfg, fileLock, ecShutdown.ord, snapshotStats, false)

  # Step 7: Apply retention
  advanceProgress(7)
  let retentionRes = withSpinner(ctx, "Applying retention policy", proc(): YabbResult[tuple[kept, deleted: int]] =
    applyRetention($cfg.snapshotDir, cfg.retention, cfg)
  )
  if retentionRes.isErr:
    error "Retention policy failed", msg = retentionRes.error.msg
    return finish(cfg, fileLock, retentionRes.error.code.ord, snapshotStats.withError(), false)

  let (kept, deleted) = retentionRes.value
  info "Retention applied", kept = kept, deleted = deleted
  let retentionStats = snapshotStats.withSnapshotsDeleted(deleted).withOperation("retention applied")

  # Step 8: Finalize (includes optional storage optimization)
  advanceProgress(8)

  # Auto-optimize storage after retention if enabled and deletions occurred
  let finalStats = if cfg.optimization.enabled and deleted > 0:
    let optRes = optimizeStorage($cfg.snapshotDir, cfg)
    if optRes.isErr:
      warn "Storage optimization failed (non-fatal)", msg = optRes.error.msg
      retentionStats.withWarning()
    else:
      retentionStats.withOperation("storage optimized")
  else:
    retentionStats

  finish(cfg, fileLock, ecSuccess.ord, finalStats, true)

# =============================================================================
# Validate Subcommand
# =============================================================================

proc validate*(
  configPath: string = DefaultConfigPath,
  json: bool = false
): int =
  ## Validate configuration without running backup
  let ctx = newOutputContext(json, isTerminal())
  useColors = ctx.colorEnabled

  let cfgResult = loadConfig(configPath)
  if cfgResult.isErr:
    outputError(ctx, "Config error: " & cfgResult.error.msg)
    return cfgResult.error.code.ord

  let cfg = cfgResult.value

  let valResult = validateConfig(cfg)
  if valResult.isErr:
    outputError(ctx, "Validation failed: " & valResult.error.msg)
    return valResult.error.code.ord

  let prereqResult = checkPrerequisites(cfg)
  if prereqResult.isErr:
    outputError(ctx, "Prerequisite check failed: " & prereqResult.error.msg)
    return prereqResult.error.code.ord

  if ctx.format == ofJson:
    outputJson(ctx, %*{
      "status": "valid",
      "config": {
        "srcDir": $cfg.srcDir,
        "dstDir": $cfg.dstDir,
        "snapshotDir": $cfg.snapshotDir,
        "compression": {
          "algorithm": $cfg.compression.algo,
          "level": cfg.compression.level
        },
        "retention": {
          "hourly": cfg.retention.hourly,
          "daily": cfg.retention.daily,
          "weekly": cfg.retention.weekly,
          "monthly": cfg.retention.monthly,
          "yearly": cfg.retention.yearly
        }
      }
    })
  else:
    outputSuccess(ctx, "Configuration is valid")
    printHeader("Configuration")
    printKeyValue("Source", $cfg.srcDir)
    printKeyValue("Destination", $cfg.dstDir)
    printKeyValue("Snapshots", $cfg.snapshotDir)
    printKeyValue("Compression", $cfg.compression.algo & " (level " & $cfg.compression.level & ")")
    printSeparator()
    printHeader("Retention Policy")
    printKeyValue("Hourly", $cfg.retention.hourly)
    printKeyValue("Daily", $cfg.retention.daily)
    printKeyValue("Weekly", $cfg.retention.weekly)
    printKeyValue("Monthly", $cfg.retention.monthly)
    printKeyValue("Yearly", $cfg.retention.yearly)

  ecSuccess.ord

# =============================================================================
# Status Subcommand
# =============================================================================

proc status*(
  configPath: string = DefaultConfigPath,
  json: bool = false
): int =
  ## Show current snapshot status and disk usage
  let ctx = newOutputContext(json, isTerminal())
  useColors = ctx.colorEnabled

  let cfgResult = loadConfig(configPath)
  if cfgResult.isErr:
    outputError(ctx, "Config error: " & cfgResult.error.msg)
    return cfgResult.error.code.ord

  let cfg = cfgResult.value

  # Get snapshot list - immutable binding
  let snapshots = listSnapshots($cfg.snapshotDir).valueOr(@[])

  # Get disk usage
  let srcUsage = getFilesystemUsage($cfg.srcDir)
  let dstUsage = getFilesystemUsage($cfg.dstDir)

  if ctx.format == ofJson:
    # Build JSON array using mapIt
    let snapshotsArray = snapshots.mapIt(%*{
      "name": it.name,
      "path": it.path,
      "timestamp": $it.timestamp,
      "type": $it.snapshotType
    })

    # Build complete JSON object immutably
    let baseData = %*{
      "snapshotCount": snapshots.len,
      "snapshots": %snapshotsArray
    }

    # Add optional usage data using functional composition
    let withSrcUsage = if srcUsage.isOk:
      let (used, available) = srcUsage.value
      block:
        let data = baseData.copy()
        data["sourceUsage"] = %*{"usedBytes": used, "availableBytes": available}
        data
    else:
      baseData

    let jsonData = if dstUsage.isOk:
      let (used, available) = dstUsage.value
      block:
        let data = withSrcUsage.copy()
        data["destUsage"] = %*{"usedBytes": used, "availableBytes": available}
        data
    else:
      withSrcUsage

    outputJson(ctx, jsonData)
  else:
    printHeader("YABB Status")
    printKeyValue("Snapshot directory", $cfg.snapshotDir)
    printKeyValue("Total snapshots", $snapshots.len)
    printSeparator()

    if srcUsage.isOk:
      let (used, available) = srcUsage.value
      let usedMB = used div (1024 * 1024)
      let availMB = available div (1024 * 1024)
      printKeyValue("Source used", $usedMB & " MB")
      printKeyValue("Source available", $availMB & " MB")

    if dstUsage.isOk:
      let (used, available) = dstUsage.value
      let usedMB = used div (1024 * 1024)
      let availMB = available div (1024 * 1024)
      printKeyValue("Dest used", $usedMB & " MB")
      printKeyValue("Dest available", $availMB & " MB")

    if snapshots.len > 0:
      printSeparator()
      printHeader("Recent Snapshots")
      let displayCount = min(5, snapshots.len)
      snapshots[0..<displayCount].applyIt:
        printKeyValue(it.name, $it.timestamp.format("yyyy-MM-dd HH:mm"))

  ecSuccess.ord

# =============================================================================
# Optimize Subcommand
# =============================================================================

proc optimize*(
  configPath: string = DefaultConfigPath,
  dryRun: bool = false,
  defrag: bool = true,
  balance: bool = true,
  scrub: bool = false,
  json: bool = false
): int =
  ## Manually run storage optimization operations
  let ctx = newOutputContext(json, isTerminal())
  useColors = ctx.colorEnabled

  let cfgResult = loadConfig(configPath)
  if cfgResult.isErr:
    outputError(ctx, "Config error: " & cfgResult.error.msg)
    return cfgResult.error.code.ord

  # Use immutable merge instead of mutation
  let cfg = cfgResult.value.withOverrides(debug = false, dryRun = dryRun, forceFull = false)

  # Validate config
  let valResult = validateConfig(cfg)
  if valResult.isErr:
    outputError(ctx, "Validation failed: " & valResult.error.msg)
    return valResult.error.code.ord

  # Run operations and collect results with spinner feedback
  let defragResult = if defrag:
    let res = withSpinner(ctx, "Defragmenting " & $cfg.snapshotDir, proc(): YabbResult[void] =
      defragment($cfg.snapshotDir, dryRun)
    )
    if res.isErr and ctx.format == ofJson:
      outputError(ctx, "Defragmentation failed: " & res.error.msg)
    Opt.some(res.isOk)
  else:
    Opt.none(bool)

  let balanceResult = if balance:
    let res = withSpinner(ctx, "Balancing " & $cfg.snapshotDir, proc(): YabbResult[void] =
      storage.balance($cfg.snapshotDir, dryRun)
    )
    if res.isErr and ctx.format == ofJson:
      outputError(ctx, "Balance failed: " & res.error.msg)
    Opt.some(res.isOk)
  else:
    Opt.none(bool)

  let scrubResult = if scrub:
    let res = withSpinner(ctx, "Scrubbing " & $cfg.snapshotDir, proc(): YabbResult[void] =
      storage.scrub($cfg.snapshotDir, dryRun)
    )
    if res.isErr and ctx.format == ofJson:
      outputError(ctx, "Scrub failed: " & res.error.msg)
    Opt.some(res.isOk)
  else:
    Opt.none(bool)

  # Collect results and count - immutable pattern
  let results = @[defragResult, balanceResult, scrubResult].filterIt(it.isSome).mapIt(it.get)
  let opCount = results.countIt(it)
  let errCount = results.countIt(not it)

  if ctx.format == ofJson:
    outputJson(ctx, %*{
      "status": if errCount == 0: "success" else: "partial",
      "operationsCompleted": opCount,
      "errors": errCount,
      "dryRun": dryRun
    })
  else:
    if errCount == 0:
      outputSuccess(ctx, "Optimization completed: " & $opCount & " operations")
    else:
      outputError(ctx, "Optimization completed with errors: " & $opCount & " ok, " & $errCount & " failed")

  if errCount > 0: ecInvalidVar.ord else: ecSuccess.ord

# =============================================================================
# Health Subcommand
# =============================================================================

proc health*(
  configPath: string = DefaultConfigPath,
  repair: bool = false,
  json: bool = false
): int =
  ## Check snapshot chain health and optionally repair issues
  let ctx = newOutputContext(json, isTerminal())
  useColors = ctx.colorEnabled

  let cfgResult = loadConfig(configPath)
  if cfgResult.isErr:
    outputError(ctx, "Config error: " & cfgResult.error.msg)
    return cfgResult.error.code.ord

  # Use immutable merge instead of mutation
  # If not repairing, treat as dry run
  let cfg = cfgResult.value.withOverrides(debug = false, dryRun = not repair, forceFull = false)

  # Validate config
  let valResult = validateConfig(cfg)
  if valResult.isErr:
    outputError(ctx, "Validation failed: " & valResult.error.msg)
    return valResult.error.code.ord

  # Get chain info
  let chainInfoRes = getChainInfo($cfg.snapshotDir)
  if chainInfoRes.isErr:
    outputError(ctx, "Failed to get chain info: " & chainInfoRes.error.msg)
    return chainInfoRes.error.code.ord

  let chainInfo = chainInfoRes.value

  # Diagnose chain issues
  let diagRes = withSpinner(ctx, "Diagnosing chain health", proc(): YabbResult[seq[ChainDiagnostic]] =
    diagnoseChain($cfg.snapshotDir)
  )
  if diagRes.isErr:
    outputError(ctx, "Failed to diagnose chain: " & diagRes.error.msg)
    return diagRes.error.code.ord

  let issues = diagRes.value

  # Check for device errors
  let hasErr = hasErrors($cfg.snapshotDir)
  let deviceErrors = if hasErr.isOk: hasErr.value else: false

  if ctx.format == ofJson:
    # Build issues array using mapIt - immutable pattern
    let issuesList = issues.mapIt(%*{
      "path": it.path,
      "issue": $it.issue,
      "details": it.details
    })

    outputJson(ctx, %*{
      "status": if issues.len == 0 and not deviceErrors: "healthy" else: "issues",
      "chainLength": chainInfo.chainLength,
      "fullSnapshots": chainInfo.fullSnapshotCount,
      "incrementalSnapshots": chainInfo.incrementalCount,
      "isValid": chainInfo.isValid,
      "deviceErrors": deviceErrors,
      "issues": %issuesList,
      "issueCount": issues.len
    })
  else:
    printHeader("Chain Health Report")
    printKeyValue("Snapshot directory", $cfg.snapshotDir)
    printKeyValue("Chain length", $chainInfo.chainLength)
    printKeyValue("Full snapshots", $chainInfo.fullSnapshotCount)
    printKeyValue("Incremental snapshots", $chainInfo.incrementalCount)
    printKeyValue("Chain valid", if chainInfo.isValid: "Yes" else: "No")
    printKeyValue("Device errors", if deviceErrors: "Yes" else: "No")
    printSeparator()

    if issues.len == 0 and not deviceErrors:
      outputSuccess(ctx, "Chain is healthy - no issues detected")
    else:
      outputError(ctx, "Found " & $issues.len & " issue(s)")
      issues.applyIt:
        printKeyValue("  " & extractFilename(it.path), $it.issue)
        if it.details.len > 0:
          try: echo "    Details: " & it.details
          except IOError: discard

  # Attempt repair if requested
  if repair and issues.len > 0:
    if ctx.format != ofJson:
      printSeparator()

    # Use recoverChain() which does cleanup, chain rebuild, and metadata repair
    let recoverRes = withSpinner(ctx, "Recovering chain (cleanup + rebuild + repair)", proc(): YabbResult[tuple[incompletesCleaned: int, orphansRemoved: int, metadataRepaired: int]] =
      recoverChain($cfg.snapshotDir, cfg)
    )
    if recoverRes.isErr:
      outputError(ctx, "Recovery failed: " & recoverRes.error.msg)
      return recoverRes.error.code.ord

    let (cleaned, orphans, repaired) = recoverRes.value
    if ctx.format == ofJson:
      outputJson(ctx, %*{"incompletesCleaned": cleaned, "orphansRemoved": orphans, "metadataRepaired": repaired})
    else:
      if orphans > 0:
        outputSuccess(ctx, "Removed " & $orphans & " orphaned snapshot(s)")
      if cleaned > 0:
        outputSuccess(ctx, "Cleaned " & $cleaned & " incomplete snapshot(s)")
      outputSuccess(ctx, "Repaired " & $repaired & " snapshot(s)")

    # Verify chain after repair
    let verifyRes = withSpinner(ctx, "Verifying chain after repair", proc(): YabbResult[bool] =
      verifyChain($cfg.snapshotDir, cfg)
    )
    if verifyRes.isErr:
      outputError(ctx, "Chain verification after repair failed: " & verifyRes.error.msg)
      return verifyRes.error.code.ord

    if ctx.format != ofJson:
      if verifyRes.value:
        outputSuccess(ctx, "Chain verification passed after repair")
      else:
        outputError(ctx, "Chain still has issues after repair")

  if issues.len > 0 or deviceErrors:
    return ecInvalidVar.ord
  ecSuccess.ord

{.pop.}

# =============================================================================
# Main Entry Point
# =============================================================================

const YabbUsage = """YABB - Yet Another BTRFS Backup
A robust incremental backup tool using BTRFS snapshots and send/receive.

Usage: yabb <command> [options]

Commands:
$subcmds
Examples:
  yabb run              Run backup with default config
  yabb run --dryRun     Preview what would happen
  yabb run --forceFull  Force full (non-incremental) backup
  yabb validate         Verify config before running
  yabb status           See current snapshots
  yabb health --repair  Fix chain issues

Config: /etc/yabb.toml (override with --configPath)
Run 'yabb <command> --help' for command details.
"""

proc main*(): int =
  try:
    dispatchMulti(
      ["multi", cmdName = "yabb", usage = YabbUsage],

      [run, help = {
        "configPath": "Path to TOML configuration file",
        "debug": "Enable debug logging",
        "dryRun": "Show what would be done without changes",
        "forceFull": "Force full snapshot instead of incremental",
        "json": "Output in JSON format"
      }, short = {"debug": 'd', "dryRun": 'n', "forceFull": 'f', "json": 'j'}],

      [validate, help = {
        "configPath": "Path to TOML configuration file",
        "json": "Output in JSON format"
      }, short = {"json": 'j'}],

      [status, help = {
        "configPath": "Path to TOML configuration file",
        "json": "Output in JSON format"
      }, short = {"json": 'j'}],

      [optimize, help = {
        "configPath": "Path to TOML configuration file",
        "dryRun": "Show what would be done without changes",
        "defrag": "Run defragmentation (default: true)",
        "balance": "Run balance operation (default: true)",
        "scrub": "Run scrub operation (default: false)",
        "json": "Output in JSON format"
      }, short = {"dryRun": 'n', "json": 'j'}],

      [health, help = {
        "configPath": "Path to TOML configuration file",
        "repair": "Attempt to repair chain issues",
        "json": "Output in JSON format"
      }, short = {"repair": 'r', "json": 'j'}]
    )
  except CatchableError:
    return ecInvalidArgument.ord
