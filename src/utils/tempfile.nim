# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2023-2026 Aryan Ameri
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#

## Temporary file and snapshot RAII guards for automatic cleanup
## Uses destructors to ensure temp resources are always removed

{.push raises: [].}

import std/[os, tempfiles]
import ../types
import ../errors

type
  TempFileGuard* = object
    ## RAII guard for temporary files
    ## Automatically removes the file when the guard goes out of scope
    path*: string
    valid: bool

proc `=destroy`*(g: TempFileGuard) =
  ## Destructor - automatically removes temp file on scope exit
  if g.valid and g.path.len > 0:
    try:
      removeFile(g.path)
    except OSError:
      discard  # Ignore removal errors

proc `=copy`*(dest: var TempFileGuard, src: TempFileGuard) {.error: "TempFileGuard cannot be copied - use move semantics".}

proc `=dup`*(src: TempFileGuard): TempFileGuard {.error: "TempFileGuard cannot be duplicated".}

proc createTempFileGuard*(prefix, suffix: string): YabbResult[TempFileGuard] =
  ## Create a temporary file and return an RAII guard
  ## The file is automatically deleted when the guard goes out of scope
  try:
    let (file, path) = createTempFile(prefix, suffix)
    file.close()
    ok(TempFileGuard(path: path, valid: true))
  except OSError as e:
    err(btrfsError("Failed to create temp file: " & e.msg))

proc invalidate*(g: sink TempFileGuard) =
  ## Consume the guard without deleting the file
  ## Use this if you've moved/renamed the temp file elsewhere
  ## The guard is consumed via sink semantics - no mutation needed
  discard

{.pop.}
