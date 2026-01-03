## Functional utilities for immutable programming patterns
## Provides apply template and other functional helpers

import std/options

{.push raises: [].}

template applyIt*[T](items: openArray[T], body: untyped): untyped =
  ## Apply a side-effect operation to each item in sequence
  ## Uses `it` as the injected variable (like mapIt, filterIt)
  ##
  ## Example:
  ##   snapshots.applyIt:
  ##     debug "Processing", path = it.path
  for it {.inject.} in items:
    body

template applyIt*[T](items: seq[T], body: untyped): untyped =
  ## Overload for seq type
  for it {.inject.} in items:
    body

template findFirst*[T](items: openArray[T], pred: untyped): Option[T] =
  ## Find first item matching predicate, return Option
  ## More functional alternative to for loop with early return
  ##
  ## Example:
  ##   let found = snapshots.findFirst(it.snapshotType == stFull)
  block:
    var findFirstResult: Option[T] = none(T)
    for it {.inject.} in items:
      if pred:
        findFirstResult = some(it)
        break
    findFirstResult

{.pop.}
