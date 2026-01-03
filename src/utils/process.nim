## Process execution utilities for YABB
## Wraps external command execution with timeout and error handling

{.push raises: [].}

import std/[osproc, streams, os, sequtils]
import ../wrappers/log
import ../types
import ../errors

type
  CommandResult* = object
    exitCode*: int
    output*: string  # Combined stdout (stderr merged if poStdErrToStdOut)

proc runCommand*(
  cmd: string,
  args: openArray[string] = [],
  workingDir: string = "",
  timeout: int = 120_000,  # ms
  dryRun: bool = false
): YabbResult[CommandResult] =
  ## Execute external command with timeout
  ## Respects DRY_RUN mode for commands that modify state
  if dryRun:
    debug "DRY_RUN: Would execute", cmd = cmd, args = $args
    return ok(CommandResult(exitCode: 0, output: ""))

  debug "Running command", cmd = cmd, args = $args

  try:
    # Note: outputStream is available by default (no poParentStreams)
    let process = startProcess(
      cmd,
      workingDir = if workingDir.len > 0: workingDir else: getCurrentDir(),
      args = @args,
      options = {poUsePath, poStdErrToStdOut}
    )

    defer: process.close()

    # Wait with timeout
    let finished = process.waitForExit(timeout)
    if finished == -1:
      process.kill()
      return err(yabbErr(ecInvalidVar, "PROCESS", "Command timed out: " & cmd))

    let output = process.outputStream.readAll()
    ok(CommandResult(exitCode: finished, output: output))
  except OSError as e:
    err(yabbErr(ecInvalidVar, "PROCESS", "Failed to run command " & cmd & ": " & e.msg))
  except IOError as e:
    err(yabbErr(ecInvalidVar, "PROCESS", "IO error running command " & cmd & ": " & e.msg))
  except ValueError as e:
    err(yabbErr(ecInvalidVar, "PROCESS", "Invalid argument running command " & cmd & ": " & e.msg))

proc runBtrfs*(args: openArray[string], dryRun: bool = false): YabbResult[CommandResult] =
  ## Convenience wrapper for btrfs commands
  runCommand("btrfs", args, dryRun = dryRun)

proc runBtrfsSend*(
  args: openArray[string],
  tempFile: string,
  dryRun: bool = false
): YabbResult[int64] =
  ## Run btrfs send with -f flag for direct file output
  ## Uses `btrfs send -f tempFile ...` instead of piping through Nim
  ## This is more robust for large streams and avoids buffer issues
  if dryRun:
    debug "DRY_RUN: Would run btrfs send", args = $args
    return ok(0i64)

  # Build args with -f for direct file output (more robust than pipe)
  # Use immutable filterIt + concatenation instead of mutable append
  let sendArgs = @["send", "-f", tempFile] & toSeq(args).filterIt(it != "send")

  debug "Running btrfs send", args = $sendArgs

  let sendRes = runCommand("btrfs", sendArgs)
  if sendRes.isErr:
    return err(sendRes.error)
  if sendRes.value.exitCode != 0:
    return err(btrfsError("btrfs send failed with exit code " & $sendRes.value.exitCode))

  # Get file size
  try:
    let size = getFileSize(tempFile)
    ok(size)
  except OSError as e:
    err(btrfsError("Failed to get send stream size: " & e.msg))

proc runBtrfsReceive*(
  args: openArray[string],
  tempFile: string,
  dryRun: bool = false
): YabbResult[void] =
  ## Run btrfs receive -f tempfile (direct file read, no piping through Nim)
  ## Uses `btrfs receive -f <tempfile> <destpath>` for robustness with large streams
  ## IMPORTANT: args MUST include the destination mount path (e.g., config.dstDir)
  if dryRun:
    debug "DRY_RUN: Would run btrfs receive", args = $args
    return ok()

  # Build args with -f for direct file input (more robust than piping through Nim)
  # Use immutable filterIt + concatenation instead of mutable append
  let recvArgs = @["receive", "-f", tempFile] & toSeq(args).filterIt(it != "receive")

  debug "Running btrfs receive", args = $recvArgs

  let recvRes = runCommand("btrfs", recvArgs)
  if recvRes.isErr:
    return err(recvRes.error)
  if recvRes.value.exitCode != 0:
    return err(btrfsError("btrfs receive failed with exit code " & $recvRes.value.exitCode))

  ok()

proc validateSendStream*(tempFile: string): YabbResult[void] =
  ## Validate send stream using btrfs receive --dump
  ## NOTE: btrfs receive --dump needs -f FILE to read from file (not positional arg)
  let dumpRes = runCommand("btrfs", ["receive", "--quiet", "--dump", "-f", tempFile])
  if dumpRes.isErr:
    return err(dumpRes.error)
  if dumpRes.value.exitCode != 0:
    return err(btrfsError("Invalid send stream - btrfs receive --dump failed"))
  ok()

{.pop.}
