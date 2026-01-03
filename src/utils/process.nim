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
  DefaultTimeout* = 120_000        ## 2 minutes - general commands
  LongOperationTimeout* = 600_000_000  ## About a week- btrfs send/receive, scrub, balance

type
  CommandResult* = object
    exitCode*: int
    output*: string  # Combined stdout (stderr merged if poStdErrToStdOut)

proc runCommand*(
  cmd: string,
  args: openArray[string] = [],
  workingDir: string = "",
  timeout: int = DefaultTimeout,
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

proc runBtrfsSendToFile*(
  args: openArray[string],
  tempFile: string,
  dryRun: bool = false
): YabbResult[int64] =
  ## Run btrfs send with -f flag for direct file output
  ## Used for change detection (small metadata diffs) - NOT for main backups
  ## For main backups, use runBtrfsSendReceive() for streaming
  if dryRun:
    debug "DRY_RUN: Would run btrfs send", args = $args
    return ok(0i64)

  # Build args with -f for direct file output (more robust than pipe)
  # Use immutable filterIt + concatenation instead of mutable append
  let sendArgs = @["send", "-f", tempFile] & toSeq(args).filterIt(it != "send")

  debug "Running btrfs send", args = $sendArgs

  let sendRes = runCommand("btrfs", sendArgs, timeout = LongOperationTimeout)
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

proc runBtrfsReceiveFromFile*(
  args: openArray[string],
  tempFile: string,
  dryRun: bool = false
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
    return err(btrfsError("btrfs receive failed with exit code " & $recvRes.value.exitCode))

  ok()

proc quoteShellArg(s: string): string =
  ## Quote a string for safe use in shell commands
  ## Wraps in single quotes and escapes any single quotes within
  if s.len == 0:
    return "''"
  result = "'"
  for c in s:
    if c == '\'':
      result.add("'\"'\"'")  # End quote, add escaped quote, start new quote
    else:
      result.add(c)
  result.add("'")

proc runBtrfsSendReceive*(
  sendArgs: openArray[string],
  destDir: string,
  dryRun: bool = false
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
