# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2023-2026 Aryan Ameri
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#

## Progress tracking utilities for YABB
## Uses immutable state types with pure functional update methods
## Rendering is separate from state management

{.push raises: [].}

import std/[terminal, times, posix]
import ../wrappers/log

# =============================================================================
# Immutable Progress State Types
# =============================================================================

type
  SpinnerState* = object ## Immutable spinner state
    frames*: seq[string]
    current*: int
    message*: string

  WorkflowStep* = object ## A single step in a workflow
    name*: string # Step name for logging
    activeName*: string # Message shown during step (e.g., "Creating snapshot...")

  WorkflowProgress* = object
    ## Immutable workflow progress state
    ## Tracks multi-step operations with TTY-only visual feedback
    operationName*: string
    steps*: seq[WorkflowStep]
    currentStep*: int
    startTime*: float

const
  SpinnerBraille* =
    @["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
  SpinnerDots* = @["⣾", "⣽", "⣻", "⢿", "⡿", "⣟", "⣯", "⣷"]
  SpinnerLine* = @["-", "\\", "|", "/"]

# =============================================================================
# Utility Functions
# =============================================================================

proc isTTY(): bool =
  isatty(stdout.getFileHandle()) != 0

proc formatEta(seconds: float): string =
  let s = int(seconds)
  if s < 60:
    return $s & "s"
  elif s < 3600:
    return $(s div 60) & "m" & $(s mod 60) & "s"
  else:
    return $(s div 3600) & "h" & $((s mod 3600) div 60) & "m"

# =============================================================================
# SpinnerState - Pure Functional API
# =============================================================================

func newSpinnerState*(
    message: string, frames: seq[string] = SpinnerBraille
): SpinnerState =
  ## Create a new spinner state
  SpinnerState(frames: frames, current: 0, message: message)

func ticked*(s: SpinnerState): SpinnerState =
  ## Return a new state with the frame advanced
  SpinnerState(
    frames: s.frames, current: (s.current + 1) mod s.frames.len, message: s.message
  )

func withMessage*(s: SpinnerState, message: string): SpinnerState =
  ## Return a new state with updated message
  SpinnerState(frames: s.frames, current: s.current, message: message)

# SpinnerState rendering (side effects)
proc render*(s: SpinnerState) =
  ## Render the spinner to the terminal
  if not isTTY():
    return

  try:
    stdout.eraseLine()
    stdout.write("\r")
    stdout.styledWrite(fgCyan, s.frames[s.current], " ")
    stdout.write(s.message)
    stdout.flushFile()
  except IOError:
    discard

proc renderStart*(s: SpinnerState) =
  ## Initialize the spinner display
  if isTTY():
    try:
      hideCursor(stdout)
    except IOError:
      discard
  s.render()

proc renderFinish*(s: SpinnerState, success: bool, message: string = "") =
  ## Finish the spinner and show completion status
  let finalMsg = if message.len > 0: message else: s.message

  try:
    if isTTY():
      stdout.eraseLine()
      stdout.write("\r")
      showCursor(stdout)
      if success:
        stdout.styledWriteLine(fgGreen, "✓ ", resetStyle, finalMsg)
      else:
        stdout.styledWriteLine(fgRed, "✗ ", resetStyle, finalMsg)
    else:
      if success:
        stdout.writeLine("[OK] ", finalMsg)
      else:
        stdout.writeLine("[FAILED] ", finalMsg)
  except IOError:
    discard

# =============================================================================
# WorkflowProgress - Pure Functional API
# =============================================================================

proc newWorkflowProgress*(name: string, steps: seq[WorkflowStep]): WorkflowProgress =
  ## Create a new workflow progress tracker
  WorkflowProgress(
    operationName: name, steps: steps, currentStep: 0, startTime: epochTime()
  )

func atStep*(wp: WorkflowProgress, step: int): WorkflowProgress =
  ## Return a new state at the specified step
  WorkflowProgress(
    operationName: wp.operationName,
    steps: wp.steps,
    currentStep: min(max(0, step), wp.steps.len),
    startTime: wp.startTime,
  )

func nextStep*(wp: WorkflowProgress): WorkflowProgress =
  ## Return a new state advanced to the next step
  wp.atStep(wp.currentStep + 1)

# WorkflowProgress rendering (side effects)
proc renderStep*(wp: WorkflowProgress, jsonMode: bool = false) =
  ## Render current step: [3/8] Creating snapshot...
  ## TTY-only: Shows animated progress in interactive terminals
  ## Non-TTY/JSON: Silent (use structured logging instead)
  if wp.currentStep >= wp.steps.len:
    return
  if jsonMode:
    return # JSON mode doesn't render progress
  if not isTTY():
    return # Non-TTY: silent, use structured logging

  let step = wp.steps[wp.currentStep]
  let stepNum = wp.currentStep + 1
  let total = wp.steps.len
  try:
    stdout.eraseLine()
    stdout.write("\r")
    stdout.styledWrite(fgCyan, "[", $stepNum, "/", $total, "] ")
    stdout.write(step.activeName)
    stdout.flushFile()
  except IOError:
    discard

proc renderComplete*(wp: WorkflowProgress, success: bool, jsonMode: bool = false) =
  ## Render completion: TTY shows colored output, non-TTY uses structured logging
  let elapsed = epochTime() - wp.startTime
  if jsonMode:
    return

  try:
    if isTTY():
      stdout.eraseLine()
      stdout.write("\r")
      showCursor(stdout)
      if success:
        stdout.styledWriteLine(
          fgGreen,
          "✓ ",
          resetStyle,
          wp.operationName,
          " completed in ",
          formatEta(elapsed),
        )
      else:
        stdout.styledWriteLine(fgRed, "✗ ", resetStyle, wp.operationName, " failed")
    else:
      # Non-TTY: use structured logging instead of terminal output
      if success:
        info "Workflow completed",
          operation = wp.operationName, elapsed = formatEta(elapsed)
      else:
        error "Workflow failed", operation = wp.operationName
  except IOError:
    discard

{.pop.}
