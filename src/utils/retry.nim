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

const MaxRetryDelay = 300  # 5 minutes max

proc retryImpl[T](
  attempt: int,
  delay: Natural,
  maxAttempts: Positive,
  operation: proc(): YabbResult[T] {.closure, raises: [].},
  description: string
): YabbResult[T] =
  ## Internal tail-recursive implementation of retry
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
