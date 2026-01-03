# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2023-2026 Aryan Ameri
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#

## Retry mechanism with exponential backoff
## Used for all btrfs operations that may need retry

{.push raises: [].}

import std/[os]
import ../wrappers/log
import ../types
import ../errors
import shutdown

const MaxRetryDelay = 300  # 5 minutes max

proc retryImpl[T](
  attempt: int,
  delay: Natural,
  maxAttempts: Positive,
  operation: proc(): YabbResult[T] {.closure, raises: [].},
  description: string
): YabbResult[T] =
  ## Internal tail-recursive implementation of retry
  ## Checks for shutdown before each attempt and after sleep

  # Check for shutdown before attempting operation
  if isShutdownRequested():
    debug "Shutdown requested, aborting retry", description = description
    return err(shutdownError("Operation cancelled by signal"))

  let res = operation()
  if res.isOk:
    if attempt > 1:
      debug "Operation succeeded after retry",
        attempt = attempt, description = description
    return res

  if attempt == maxAttempts:
    error "Operation failed after all attempts",
      attempts = maxAttempts, description = description
    return res

  warn "Operation failed, retrying",
    attempt = attempt, maxAttempts = maxAttempts,
    delay = delay, description = description

  sleep(delay * 1000)

  # Check for shutdown after sleep to avoid unnecessary retry
  if isShutdownRequested():
    debug "Shutdown requested during retry delay", description = description
    return err(shutdownError("Operation cancelled by signal during retry"))

  let nextDelay = min(delay * 2, MaxRetryDelay)
  retryImpl(attempt + 1, nextDelay, maxAttempts, operation, description)

proc retry*[T](
  maxAttempts: Positive,
  initialDelay: Natural,
  operation: proc(): YabbResult[T] {.closure, raises: [].},
  description: string = ""
): YabbResult[T] =
  ## Retry an operation with exponential backoff
  ## - maxAttempts: Maximum number of retry attempts
  ## - initialDelay: Initial delay in seconds before first retry
  ## - operation: The operation to retry (returns YabbResult[T], must not raise)
  ## - description: Human-readable description for logging
  retryImpl(1, initialDelay, maxAttempts, operation, description)

{.pop.}
