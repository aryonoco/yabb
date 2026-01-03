# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2023-2026 Aryan Ameri
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#

## Cooperative shutdown system for YABB
##
## FP-aligned design with minimal mutable state:
## - Single atomic boolean for shutdown state (the ONLY mutable state)
## - Signal handlers just set the flag, no cleanup logic
## - Shutdown propagates through normal YabbResult[T] control flow
## - Cleanup happens via existing RAII (TempFileGuard, FileLock, defer)

{.push raises: [].}

import std/[atomics, posix]
import ../types
import ../errors

# The ONLY mutable state in the entire shutdown system
var shutdownRequested: Atomic[bool]

proc isShutdownRequested*(): bool {.inline.} =
  ## Query function for shutdown state
  ## Returns true if a shutdown signal has been received
  ## Note: uses proc not func because atomic read is technically a side effect
  shutdownRequested.load(moRelaxed)

proc requestShutdown*() =
  ## Request shutdown - called by signal handlers
  ## This is the ONLY mutation in the shutdown system
  shutdownRequested.store(true, moRelease)

proc checkShutdown*(): YabbResult[void] =
  ## Convert shutdown state to Result type for FP control flow
  ## Use with .isOkOr: to propagate shutdown through normal control flow
  ##
  ## Example:
  ##   checkShutdown().isOkOr:
  ##     return err(error)
  if isShutdownRequested():
    err(shutdownError("Operation cancelled by signal"))
  else:
    ok()

proc resetShutdown*() =
  ## Reset shutdown flag - only for testing purposes
  ## Should NOT be used in production code
  shutdownRequested.store(false, moRelease)

# Signal handler - exits immediately for interactive signals
proc signalHandler(sig: cint) {.noconv.} =
  ## POSIX signal handler
  ## For SIGINT (Ctrl+C): exit immediately - user expects this
  ## For other signals: set flag for graceful shutdown
  if sig == SIGINT:
    # Ctrl+C should exit immediately
    quit(130)  # 128 + SIGINT(2) = standard interrupted exit code
  else:
    requestShutdown()

proc installSignalHandlers*() =
  ## Install signal handlers for graceful shutdown
  ##
  ## Handled signals (trigger graceful shutdown):
  ## - SIGTERM: Standard termination request (systemd, kill)
  ## - SIGINT:  Ctrl+C from terminal
  ## - SIGHUP:  Terminal hangup or config reload request
  ## - SIGQUIT: Ctrl+\ from terminal (we handle gracefully instead of core dump)
  ## - SIGABRT: abort() called - allows cleanup before termination
  ##
  ## Ignored signals:
  ## - SIGPIPE: Broken pipe - returns EPIPE instead of crashing
  ##
  ## Each handler just calls requestShutdown() - nothing else.
  ## Cleanup happens when control flow returns through normal paths,
  ## triggering existing RAII cleanup (TempFileGuard, FileLock, defer).
  var action: Sigaction
  action.sa_handler = signalHandler
  action.sa_flags = 0
  discard sigemptyset(action.sa_mask)

  # Install for all relevant signals - these trigger graceful shutdown
  discard sigaction(SIGTERM, action, nil)
  discard sigaction(SIGINT, action, nil)
  discard sigaction(SIGHUP, action, nil)
  # Note: SIGQUIT typically generates core dump, but we handle it gracefully
  discard sigaction(SIGQUIT, action, nil)
  # SIGABRT: Allow cleanup when abort() is called
  discard sigaction(SIGABRT, action, nil)

  # SIGPIPE: Ignore so broken pipe returns EPIPE error instead of crashing
  # This is important when piping to tools like `head` or when SSH connections drop
  var ignoreAction: Sigaction
  ignoreAction.sa_handler = SIG_IGN
  ignoreAction.sa_flags = 0
  discard sigemptyset(ignoreAction.sa_mask)
  discard sigaction(SIGPIPE, ignoreAction, nil)

{.pop.}
