# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2023-2026 Aryan Ameri
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#

## Process execution utilities for YABB
## Wraps external command execution with timeout and error handling

{.push raises: [].}

import std/[osproc, streams, os, sequtils, strutils]
import ../wrappers/log
import ../types
import ../errors

const
  DefaultTimeout* = 120_000 ## 2 minutes - general commands
  LongOperationTimeout* = 600_000_000 ## About a week- btrfs send/receive, scrub, balance

type CommandResult* = object
  exitCode*: int
  output*: string # Combined stdout (stderr merged if poStdErrToStdOut)

proc runCommand*(
    cmd: string,
    args: openArray[string] = [],
    workingDir: string = "",
    timeout: int = DefaultTimeout,
    dryRun: bool = false,
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
      workingDir =
        if workingDir.len > 0:
          workingDir
        else:
          getCurrentDir(),
      args = @args,
      options = {poUsePath, poStdErrToStdOut},
    )

    defer:
      process.close()

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
    err(
      yabbErr(ecInvalidVar, "PROCESS", "IO error running command " & cmd & ": " & e.msg)
    )
  except ValueError as e:
    err(
      yabbErr(
        ecInvalidVar,
        "PROCESS",
        "Invalid argument running command " & cmd & ": " & e.msg,
      )
    )

proc runBtrfs*(
    args: openArray[string], dryRun: bool = false
): YabbResult[CommandResult] =
  ## Convenience wrapper for btrfs commands
  runCommand("btrfs", args, dryRun = dryRun)

proc runBtrfsReceiveFromFile*(
    args: openArray[string], tempFile: string, dryRun: bool = false
): YabbResult[void] =
  ## Run btrfs receive -f tempfile (direct file read)
  ## Used internally - for main backups, use runBtrfsSendReceive() for streaming
  ## IMPORTANT: args MUST include the destination mount path (e.g., config.dstDir)
  if dryRun:
    debug "DRY_RUN: Would run btrfs receive", args = $args
    return ok()

  # Build args with -f for direct file input (more robust than piping through Nim)
  # Use immutable filterIt + concatenation instead of mutable append
  let recvArgs = @["receive", "-f", tempFile] & toSeq(args).filterIt(it != "receive")

  debug "Running btrfs receive", args = $recvArgs

  let recvRes = runCommand("btrfs", recvArgs, timeout = LongOperationTimeout)
  if recvRes.isErr:
    return err(recvRes.error)
  if recvRes.value.exitCode != 0:
    return
      err(btrfsError("btrfs receive failed with exit code " & $recvRes.value.exitCode))

  ok()

proc quoteShellArg(s: string): string =
  ## Quote a string for safe use in shell commands
  ## Wraps in single quotes and escapes any single quotes within
  if s.len == 0:
    return "''"
  result = "'"
  for c in s:
    if c == '\'':
      result.add("'\"'\"'") # End quote, add escaped quote, start new quote
    else:
      result.add(c)
  result.add("'")

proc runBtrfsSendReceive*(
    sendArgs: openArray[string], destDir: string, dryRun: bool = false
): YabbResult[void] =
  ## Stream btrfs send directly to btrfs receive via pipe with progress
  ## Uses: btrfs send [args] | pv -pterb | btrfs receive [destDir]
  ##
  ## This is the PRIMARY method for backups - no temp files, true streaming.
  ## Progress is displayed via pv (pipe viewer).
  if dryRun:
    debug "DRY_RUN: Would stream btrfs send | pv | btrfs receive",
      sendArgs = $sendArgs, destDir = destDir
    return ok()

  # Build shell command with proper escaping
  let sendCmd = "btrfs send " & sendArgs.mapIt(quoteShellArg(it)).join(" ")
  let recvCmd = "btrfs receive " & quoteShellArg(destDir)

  # Use pv for progress: -p progress bar, -t timer, -e ETA, -r rate, -b bytes
  let fullCmd = sendCmd & " | pv -pterb | " & recvCmd

  info "Starting streaming backup", dest = destDir
  debug "Running shell command", cmd = fullCmd

  # Execute via shell for pipe support
  try:
    let exitCode = execShellCmd(fullCmd)
    if exitCode != 0:
      return err(btrfsError("btrfs send|receive failed with exit code " & $exitCode))
    ok()
  except OSError as e:
    err(btrfsError("Failed to execute streaming backup: " & e.msg))

proc checkSendStreamHasContent*(
    parentSnapshot: string, currentSnapshot: string, dryRun: bool = false
): YabbResult[bool] =
  ## Check if btrfs send produces meaningful content (i.e., there are changes)
  ## Uses streaming with early termination via SIGPIPE - O(1) regardless of delta size
  ## Returns ok(true) if changes exist, ok(false) if no changes
  ##
  ## This avoids writing terabyte-sized deltas to temp files.
  ## head terminates btrfs send after reading StreamCheckBytes via SIGPIPE.
  if dryRun:
    debug "DRY_RUN: Would check for changes",
      parent = parentSnapshot, current = currentSnapshot
    return ok(true) # Assume changes in dry run

  # Stream check with early termination via SIGPIPE
  # head -c N reads max N bytes then sends SIGPIPE to terminate btrfs send
  # btrfs send header alone is ~188 bytes; anything more means real changes
  const
    StreamCheckBytes = 512
    NoChangesThreshold = 300

  let shellCmd =
    "btrfs send --quiet -p " & quoteShellArg(parentSnapshot) & " " &
    quoteShellArg(currentSnapshot) & " 2>/dev/null | head -c " & $StreamCheckBytes &
    " | wc -c"

  debug "Checking for changes (streaming)",
    parent = parentSnapshot, current = currentSnapshot

  try:
    # Must run through shell for pipe/redirection support
    let output = execProcess("/bin/sh", args = ["-c", shellCmd], options = {poUsePath})
    let byteCount =
      try:
        parseInt(output.strip())
      except ValueError:
        -1

    if byteCount < 0:
      return err(btrfsError("Failed to parse change detection output"))

    # Return whether changes were detected (immutable expression)
    ok(byteCount >= NoChangesThreshold)
  except OSError as e:
    err(btrfsError("Change detection failed: " & e.msg))
  except IOError as e:
    err(btrfsError("Change detection IO error: " & e.msg))

{.pop.}
