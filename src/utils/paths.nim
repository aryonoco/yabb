# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2023-2026 Aryan Ameri
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#

## Path sanitization and validation utilities
## Ensures all paths are safe and valid before use

{.push raises: [].}

import std/[os, strutils]
import ../types
import ../errors

const MaxPathLength* = 4096

proc sanitizePath*(path: string): YabbResult[string] =
  ## Sanitize and normalize a path
  ## - Strips whitespace and trailing slashes
  ## - Converts to absolute path
  ## - Resolves symlinks
  ## - Checks path length
  if path.len == 0:
    return err(yabbErr(ecInvalidVar, "PATH", "Empty path provided"))

  # Chain strip operations into single immutable binding
  let stripped = path.strip().strip(chars = {'/'}, leading = false, trailing = true)

  if stripped in ["", ".", ".."]:
    return err(yabbErr(ecInvalidVar, "PATH", "Invalid path: " & stripped))

  # Convert to absolute path - immutable binding with conditional
  let absolutePath = if stripped.isAbsolute:
    stripped
  else:
    try:
      getCurrentDir() / stripped
    except OSError as e:
      return err(yabbErr(ecInvalidVar, "PATH", "Failed to get current directory: " & e.msg))

  # Normalize and resolve symlinks - immutable binding with try expression
  let resolved = try:
    expandFilename(absolutePath)
  except OSError as e:
    return err(yabbErr(ecInvalidVar, "PATH", "Failed to resolve path: " & e.msg))

  # Check path length
  if resolved.len > MaxPathLength:
    return err(yabbErr(ecInvalidVar, "PATH", "Path exceeds maximum length"))

  ok(resolved)

proc validatePath*(
  path: string,
  pathType: string = "any",  # "directory", "file", "any"
  mustExist: bool = true
): YabbResult[string] =
  ## Validate a path exists and is of the correct type
  ## - pathType: "directory", "file", or "any"
  ## - mustExist: If true, path must exist
  let sanitized = sanitizePath(path).valueOr:
    return err(error)

  if mustExist:
    if not fileExists(sanitized) and not dirExists(sanitized):
      return err(yabbErr(ecDirInvalid, "PATH", "Path does not exist: " & sanitized))

  case pathType
  of "directory":
    if mustExist and not dirExists(sanitized):
      return err(yabbErr(ecDirInvalid, "PATH", "Not a directory: " & sanitized))
  of "file":
    if mustExist and not fileExists(sanitized):
      return err(yabbErr(ecDirInvalid, "PATH", "Not a file: " & sanitized))
  of "any":
    discard
  else:
    return err(yabbErr(ecInvalidVar, "PATH", "Invalid path type: " & pathType))

  ok(sanitized)

proc joinPaths*(base, sub: string): YabbResult[string] =
  ## Safely join two path components
  let cleanBase = sanitizePath(base).valueOr:
    return err(error)
  let cleanSub = sub.strip(chars = {'/'}, leading = true)
  sanitizePath(cleanBase / cleanSub)

proc isSubPath*(child, parent: string): bool =
  ## Check if child is a subpath of parent
  let childNorm = try: expandFilename(child) except: return false
  let parentNorm = try: expandFilename(parent) except: return false
  childNorm.startsWith(parentNorm & "/") or childNorm == parentNorm

proc ensureDir*(path: string, dryRun: bool = false): YabbResult[void] =
  ## Ensure directory exists, creating if necessary
  if dryRun:
    return ok()

  if dirExists(path):
    return ok()

  try:
    createDir(path)
    ok()
  except OSError as e:
    err(dirError("Failed to create directory " & path & ": " & e.msg))
  except IOError as e:
    err(dirError("IO error creating directory " & path & ": " & e.msg))

{.pop.}
