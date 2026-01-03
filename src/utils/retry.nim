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
