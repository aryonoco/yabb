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

import std/[terminal, strutils, times, posix]
import ../wrappers/log

# =============================================================================
# Immutable Progress State Types
# =============================================================================

type
  ProgressState* = object
    ## Immutable progress tracking state
    operation*: string
    current*: int
    total*: int
    started*: bool

  ProgressBarState* = object
    ## Immutable progress bar state
    total*: int
    current*: int
    width*: int
    startTime*: float
    message*: string
    showPercent*: bool
    showEta*: bool

  SpinnerState* = object
    ## Immutable spinner state
    frames*: seq[string]
    current*: int
    message*: string

const
  SpinnerBraille* = @["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
  SpinnerDots* = @["⣾", "⣽", "⣻", "⢿", "⡿", "⣟", "⣯", "⣷"]
  SpinnerLine* = @["-", "\\", "|", "/"]

# =============================================================================
# ProgressState - Pure Functional API
# =============================================================================

func newProgressState*(operation: string, total: int = 0): ProgressState =
  ## Create a new progress state
  ProgressState(operation: operation, current: 0, total: total, started: false)

func started*(p: ProgressState): ProgressState =
  ## Return a new state marked as started
  ProgressState(operation: p.operation, current: p.current, total: p.total, started: true)

func updated*(p: ProgressState, current: int): ProgressState =
  ## Return a new state with updated current value
  ProgressState(operation: p.operation, current: current, total: p.total, started: true)

func incremented*(p: ProgressState): ProgressState =
  ## Return a new state with current incremented by 1
  p.updated(p.current + 1)

func completed*(p: ProgressState): ProgressState =
  ## Return a new state marked as complete
  if p.total > 0:
    p.updated(p.total)
  else:
    p

# ProgressState rendering (side effects)
proc renderStart*(p: ProgressState) =
  ## Log the start of an operation
  if p.total > 0:
    info "Starting operation", operation = p.operation, total = p.total
  else:
    info "Starting operation", operation = p.operation

proc renderUpdate*(p: ProgressState) =
  ## Log a progress update
  if p.total > 0:
    let percent = (p.current * 100) div p.total
    debug "Progress update", operation = p.operation,
          progress = $p.current & "/" & $p.total,
          percent = $percent & "%"
  else:
    debug "Progress update", operation = p.operation, step = p.current

proc renderComplete*(p: ProgressState) =
  ## Log completion of an operation
  info "Operation completed", operation = p.operation, steps = p.current

proc renderFail*(p: ProgressState, reason: string) =
  ## Log failure of an operation
  error "Operation failed", operation = p.operation, step = p.current, reason = reason

# =============================================================================
# ProgressBarState - Pure Functional API
# =============================================================================

proc isTTY(): bool =
  isatty(stdout.getFileHandle()) != 0

proc formatEta(seconds: float): string =
  let s = int(seconds)
  if s < 60: return $s & "s"
  elif s < 3600: return $(s div 60) & "m" & $(s mod 60) & "s"
  else: return $(s div 3600) & "h" & $((s mod 3600) div 60) & "m"

proc newProgressBarState*(total: int, message: string = "", width: int = 40): ProgressBarState =
  ## Create a new progress bar state
  ProgressBarState(
    total: total,
    current: 0,
    width: width,
    startTime: epochTime(),
    message: message,
    showPercent: true,
    showEta: total > 0
  )

func updated*(pb: ProgressBarState, current: int): ProgressBarState =
  ## Return a new state with updated current value
  ProgressBarState(
    total: pb.total,
    current: min(current, pb.total),
    width: pb.width,
    startTime: pb.startTime,
    message: pb.message,
    showPercent: pb.showPercent,
    showEta: pb.showEta
  )

func incremented*(pb: ProgressBarState): ProgressBarState =
  ## Return a new state with current incremented by 1
  pb.updated(pb.current + 1)

# ProgressBarState rendering (side effects)
proc render*(pb: ProgressBarState) =
  ## Render the progress bar to the terminal
  try:
    if not isTTY():
      # Non-TTY: log progress at 10% intervals
      let prevPercent = if pb.total > 0: ((pb.current - 1) * 10) div pb.total else: 0
      let currPercent = if pb.total > 0: (pb.current * 10) div pb.total else: 0
      if currPercent > prevPercent:
        let actualPercent = (pb.current * 100) div pb.total
        stdout.writeLine(pb.message, " ", actualPercent, "%")
      return

    let percent = if pb.total > 0: (pb.current * 100) div pb.total else: 0
    let filled = if pb.total > 0: (pb.width * pb.current) div pb.total else: 0
    let empty = pb.width - filled

    # Move to start of line and clear
    stdout.eraseLine()
    stdout.write("\r")

    # Write message if present
    if pb.message.len > 0:
      stdout.styledWrite(styleBright, pb.message, " ")

    # Draw progress bar: [████████░░░░░░░░]
    stdout.write("[")
    stdout.styledWrite(fgGreen, "█".repeat(filled))
    stdout.styledWrite(styleDim, "░".repeat(empty))
    stdout.write("] ")

    # Percentage
    stdout.styledWrite(fgCyan, $percent, "%")

    # ETA calculation
    if pb.showEta and pb.current > 0 and pb.current < pb.total:
      let elapsed = epochTime() - pb.startTime
      let eta = (elapsed / float(pb.current)) * float(pb.total - pb.current)
      stdout.styledWrite(styleDim, " ETA: ", formatEta(eta))

    stdout.flushFile()
  except IOError:
    discard

proc renderStart*(pb: ProgressBarState) =
  ## Initialize the progress bar display
  if isTTY():
    try: hideCursor(stdout)
    except IOError: discard
  pb.render()

proc renderFinish*(pb: ProgressBarState, success: bool) =
  ## Finish the progress bar and show completion status
  try:
    if isTTY():
      stdout.eraseLine()
      stdout.write("\r")
      showCursor(stdout)
      if success:
        stdout.styledWriteLine(fgGreen, "✓ ", resetStyle, pb.message, " completed")
      else:
        stdout.styledWriteLine(fgRed, "✗ ", resetStyle, pb.message, " failed")
    else:
      if success:
        stdout.writeLine("[OK] ", pb.message, " completed")
      else:
        stdout.writeLine("[FAILED] ", pb.message, " failed")
  except IOError:
    discard

# =============================================================================
# SpinnerState - Pure Functional API
# =============================================================================

func newSpinnerState*(message: string, frames: seq[string] = SpinnerBraille): SpinnerState =
  ## Create a new spinner state
  SpinnerState(frames: frames, current: 0, message: message)

func ticked*(s: SpinnerState): SpinnerState =
  ## Return a new state with the frame advanced
  SpinnerState(
    frames: s.frames,
    current: (s.current + 1) mod s.frames.len,
    message: s.message
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
    try: hideCursor(stdout)
    except IOError: discard
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

{.pop.}

# =============================================================================
# Callback-based Progress Helpers (Immutable Interface)
# =============================================================================

type
  ProgressUpdate* = proc(current: int) {.closure.}
  BarUpdate* = proc(current: int) {.closure.}
  SpinnerTick* = proc(frame: int) {.closure.}

proc runWithProgress*[T](
  operation: string,
  total: int,
  action: proc(update: ProgressUpdate): T
): T {.raises: [CatchableError].} =
  ## Execute action with progress tracking via callback
  ## The action receives an update callback to report progress
  let initialState = newProgressState(operation, total)
  initialState.started.renderStart()
  try:
    result = action(proc(current: int) =
      initialState.updated(current).renderUpdate()
    )
    initialState.completed.renderComplete()
  except CatchableError as e:
    initialState.renderFail(e.msg)
    raise

proc runWithProgressBar*[T](
  total: int,
  message: string,
  action: proc(update: proc(current: int) {.closure.}): T
): T {.raises: [CatchableError].} =
  ## Execute action with visual progress bar via callback
  ## The action receives an update callback that takes current value explicitly
  let initialState = newProgressBarState(total, message)
  initialState.renderStart()
  try:
    result = action(proc(current: int) =
      initialState.updated(current).render()
    )
    initialState.updated(total).renderFinish(true)
  except CatchableError as e:
    initialState.renderFinish(false)
    raise

proc runWithSpinner*[T](
  message: string,
  action: proc(tick: proc(frame: int) {.closure.}): T
): T {.raises: [CatchableError].} =
  ## Execute action with spinner animation via callback
  ## The action receives a tick callback that takes frame number explicitly
  let initialState = newSpinnerState(message)
  initialState.renderStart()
  try:
    result = action(proc(frame: int) =
      SpinnerState(
        frames: initialState.frames,
        current: frame mod initialState.frames.len,
        message: initialState.message
      ).render()
    )
    initialState.renderFinish(true)
  except CatchableError as e:
    initialState.renderFinish(false)
    raise
