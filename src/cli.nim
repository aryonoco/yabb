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
import utils/[lock, prereq, terminal, functional, progress]

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
  if cfg.snapshotDir.len > 0 and dirExists(cfg.snapshotDir):
    let snapEntries = try: toSeq(walkDir(cfg.snapshotDir)) except OSError: @[]
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
  let ctx = newOutputContext(json, isTerminal())
  if ctx.colorEnabled:
    useColors = true
  else:
    useColors = false
  initLogging(debug)

  # Helper to log summary and return status
  proc finish(cfg: YabbConfig, fileLock: sink FileLock, status: int, stats: ExecutionStats): int =
    release(fileLock)
    cleanupResources(cfg)
    logSummary(status, stats)
    status

  let baseConfig = loadConfig(configPath).valueOr:
    error "Configuration error", msg = error.msg
    logSummary(error.code.ord, initStats().withError())
    return error.code.ord

  # Use immutable merge instead of mutation
  let initialCfg = baseConfig.withOverrides(debug, dryRun, forceFull)

  checkPrerequisites(initialCfg).isOkOr:
    error "Prerequisite check failed", msg = error.msg
    logSummary(error.code.ord, initStats().withError())
    return error.code.ord

  let fileLock = acquireLock(LockFile, LockTimeout).valueOr:
    if error.code == ecLockHeld:
      # Another instance running - informational, not an error
      info "Another instance is running"
      return ecSuccess.ord
    # Real lock error (permission denied, I/O failure, etc.)
    error "Failed to acquire lock", msg = error.msg
    logSummary(error.code.ord, initStats().withError())
    return error.code.ord

  validateConfig(initialCfg).isOkOr:
    error "Config validation failed", msg = error.msg
    return finish(initialCfg, fileLock, error.code.ord, initStats().withError())

  checkFilesystemSpace(initialCfg.srcDir, initialCfg.minFreeSpace).isOkOr:
    error "Insufficient space in source", msg = error.msg
    return finish(initialCfg, fileLock, error.code.ord, initStats().withError())

  checkFilesystemSpace(initialCfg.dstDir, initialCfg.minFreeSpace).isOkOr:
    error "Insufficient space in destination", msg = error.msg
    return finish(initialCfg, fileLock, error.code.ord, initStats().withError())

  verifyCompression(initialCfg.srcDir, initialCfg.compression).isOkOr:
    error "Compression verification failed", msg = error.msg
    return finish(initialCfg, fileLock, error.code.ord, initStats().withError())

  # Check chain length and determine final forceFull value
  let needsForceFull = if initialCfg.forceFull:
    false  # Already forcing full, no need to check
  else:
    let needsFull = shouldForceFullSnapshot(
      initialCfg.snapshotDir,
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

  let snapshotRes = withSpinner(ctx, "Creating backup snapshot", proc(): YabbResult[Snapshot] =
    createBackupSnapshot(cfg, cfg.srcDir, cfg.snapshotDir)
  , successCodes = {ecNoChanges})
  if snapshotRes.isErr:
    if snapshotRes.error.code == ecNoChanges:
      info "No changes detected, skipping backup"
      return finish(cfg, fileLock, ecNoChanges.ord, initStats())
    error "Snapshot creation failed", msg = snapshotRes.error.msg
    return finish(cfg, fileLock, snapshotRes.error.code.ord, initStats().withError())

  info "Snapshot created successfully", path = snapshotRes.value.path

  let retentionRes = withSpinner(ctx, "Applying retention policy", proc(): YabbResult[tuple[kept, deleted: int]] =
    applyRetention(cfg.snapshotDir, cfg.retention, cfg)
  )
  if retentionRes.isErr:
    error "Retention policy failed", msg = retentionRes.error.msg
    return finish(cfg, fileLock, retentionRes.error.code.ord, initStats().withError())

  let (kept, deleted) = retentionRes.value
  info "Retention applied", kept = kept, deleted = deleted

  # Auto-optimize storage after retention if enabled and deletions occurred
  let finalStats = if cfg.optimization.enabled and deleted > 0:
    let optRes = optimizeStorage(cfg.snapshotDir, cfg)
    if optRes.isErr:
      warn "Storage optimization failed (non-fatal)", msg = optRes.error.msg
      initStats().withWarning()
    else:
      initStats()
  else:
    initStats()

  finish(cfg, fileLock, ecSuccess.ord, finalStats)

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
        "srcDir": cfg.srcDir,
        "dstDir": cfg.dstDir,
        "snapshotDir": cfg.snapshotDir,
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
    printKeyValue("Source", cfg.srcDir)
    printKeyValue("Destination", cfg.dstDir)
    printKeyValue("Snapshots", cfg.snapshotDir)
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
  let snapshots = listSnapshots(cfg.snapshotDir).valueOr(@[])

  # Get disk usage
  let srcUsage = getFilesystemUsage(cfg.srcDir)
  let dstUsage = getFilesystemUsage(cfg.dstDir)

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
    printKeyValue("Snapshot directory", cfg.snapshotDir)
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
    let res = withSpinner(ctx, "Defragmenting " & cfg.snapshotDir, proc(): YabbResult[void] =
      defragment(cfg.snapshotDir, dryRun)
    )
    if res.isErr and ctx.format == ofJson:
      outputError(ctx, "Defragmentation failed: " & res.error.msg)
    Opt.some(res.isOk)
  else:
    Opt.none(bool)

  let balanceResult = if balance:
    let res = withSpinner(ctx, "Balancing " & cfg.snapshotDir, proc(): YabbResult[void] =
      storage.balance(cfg.snapshotDir, dryRun)
    )
    if res.isErr and ctx.format == ofJson:
      outputError(ctx, "Balance failed: " & res.error.msg)
    Opt.some(res.isOk)
  else:
    Opt.none(bool)

  let scrubResult = if scrub:
    let res = withSpinner(ctx, "Scrubbing " & cfg.snapshotDir, proc(): YabbResult[void] =
      storage.scrub(cfg.snapshotDir, dryRun)
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
  let chainInfoRes = getChainInfo(cfg.snapshotDir)
  if chainInfoRes.isErr:
    outputError(ctx, "Failed to get chain info: " & chainInfoRes.error.msg)
    return chainInfoRes.error.code.ord

  let chainInfo = chainInfoRes.value

  # Diagnose chain issues
  let diagRes = withSpinner(ctx, "Diagnosing chain health", proc(): YabbResult[seq[ChainDiagnostic]] =
    diagnoseChain(cfg.snapshotDir)
  )
  if diagRes.isErr:
    outputError(ctx, "Failed to diagnose chain: " & diagRes.error.msg)
    return diagRes.error.code.ord

  let issues = diagRes.value

  # Check for device errors
  let hasErr = hasErrors(cfg.snapshotDir)
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
    printKeyValue("Snapshot directory", cfg.snapshotDir)
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

    let repairRes = withSpinner(ctx, "Repairing chain metadata", proc(): YabbResult[int] =
      repairChainMetadata(cfg.snapshotDir, cfg)
    )
    if repairRes.isErr:
      outputError(ctx, "Repair failed: " & repairRes.error.msg)
      return repairRes.error.code.ord

    let repaired = repairRes.value
    if ctx.format == ofJson:
      outputJson(ctx, %*{"repaired": repaired})
    else:
      outputSuccess(ctx, "Repaired " & $repaired & " snapshot(s)")

    # Verify chain after repair
    let verifyRes = withSpinner(ctx, "Verifying chain after repair", proc(): YabbResult[bool] =
      verifyChain(cfg.snapshotDir, cfg)
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

proc main*(): int =
  try:
    dispatchMulti(
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
