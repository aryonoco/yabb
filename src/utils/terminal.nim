# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2023-2026 Aryan Ameri
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#

## Terminal output utilities with color support
## Uses std/terminal for cross-platform color support
## Coexists with chronicles for structured logging

{.push raises: [].}

import std/[terminal, exitprocs, posix, strutils]

# Register cleanup on module load to restore terminal state
addExitProc(proc() {.raises: [].} =
  try: resetAttributes(stdout); resetAttributes(stderr)
  except IOError: discard
)

type
  OutputLevel* = enum
    olSuccess   ## Green checkmark - operation succeeded
    olInfo      ## Cyan info icon - informational message
    olError     ## Red X icon - error message

var
  useColors* = true   ## Can be disabled for non-TTY or --json mode
  useUnicode* = true  ## Can be disabled for terminals without unicode support

proc isTerminal*(): bool =
  ## Check if stdout is a TTY (for color/interactive decisions)
  isatty(stdout.getFileHandle()) != 0

proc isTTY*(f: File): bool =
  ## Check if a specific file handle is a TTY
  isatty(f.getFileHandle()) != 0

proc getSymbol(level: OutputLevel): string =
  ## Get the appropriate symbol for each output level
  if useUnicode:
    case level
    of olSuccess: "✓"
    of olInfo:    "ℹ"
    of olError:   "✗"
  else:
    case level
    of olSuccess: "[OK]"
    of olInfo:    "[i]"
    of olError:   "[X]"

proc colorWrite*(level: OutputLevel, msg: string) =
  ## Write colored message based on level (for user-facing output)
  let output = if level == olError: stderr else: stdout
  let symbol = getSymbol(level)

  try:
    if not useColors or not output.isTTY():
      # Fallback to plain text
      output.writeLine(symbol, " ", msg)
      return

    case level
    of olSuccess:
      output.styledWriteLine(fgGreen, symbol, " ", resetStyle, msg)
    of olInfo:
      output.styledWriteLine(fgCyan, symbol, " ", resetStyle, msg)
    of olError:
      output.styledWriteLine(fgRed, symbol, " ", resetStyle, msg)
  except IOError:
    discard  # Terminal output failure is non-fatal

proc userSuccess*(msg: string) =
  ## Display a success message with green checkmark
  colorWrite(olSuccess, msg)

proc userInfo*(msg: string) =
  ## Display an info message with cyan info icon
  colorWrite(olInfo, msg)

proc userError*(msg: string) =
  ## Display an error message with red X icon
  colorWrite(olError, msg)

# Table formatting for status output
proc printHeader*(title: string) =
  ## Print a section header with underline
  try:
    if useColors and stdout.isTTY():
      stdout.styledWriteLine(styleBright, fgCyan, title)
      stdout.styledWriteLine(styleDim, "─".repeat(min(title.len + 4, 60)))
    else:
      stdout.writeLine(title)
      stdout.writeLine("-".repeat(min(title.len + 4, 60)))
  except IOError:
    discard

proc printKeyValue*(key: string, value: string, keyWidth: int = 20) =
  ## Print a key-value pair with aligned formatting
  let paddedKey = key & ":".repeat(1) & " ".repeat(max(0, keyWidth - key.len - 1))
  try:
    if useColors and stdout.isTTY():
      stdout.styledWrite(styleDim, paddedKey)
      stdout.styledWriteLine(resetStyle, value)
    else:
      stdout.writeLine(paddedKey, value)
  except IOError:
    discard

proc printSeparator*() =
  ## Print a visual separator line
  try:
    if useColors and stdout.isTTY():
      stdout.styledWriteLine(styleDim, "─".repeat(60))
    else:
      stdout.writeLine("-".repeat(60))
  except IOError:
    discard

{.pop.}
