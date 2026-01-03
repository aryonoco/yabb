# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2023-2026 Aryan Ameri
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#

## Error handling utilities for YABB
## Uses Result[T, YabbError] for explicit error propagation

{.push raises: [].}

import std/[times, strutils]
import wrappers/log
import types

# YabbError constructors - return value type for use with Result[T, YabbError]
func yabbErr*(code: ExitCode, cat, msg: string): YabbError =
  YabbError(code: code, category: cat, msg: msg)

# Convenience constructors (return value type, not ref) - pure functions
func configError*(msg: string): YabbError =
  yabbErr(ecConfigMissing, "CONFIG", msg)

func validationError*(msg: string): YabbError =
  yabbErr(ecInvalidVar, "VALIDATION", msg)

func prereqError*(msg: string): YabbError =
  yabbErr(ecPrereqMissing, "PREREQ", msg)

func btrfsError*(msg: string): YabbError =
  yabbErr(ecInvalidVar, "BTRFS", msg)

func noChangesError*(msg: string): YabbError =
  yabbErr(ecNoChanges, "CHANGES", msg)

func dirError*(msg: string): YabbError =
  yabbErr(ecDirInvalid, "DIR", msg)

func argError*(msg: string): YabbError =
  yabbErr(ecInvalidArgument, "ARG", msg)

func lockHeldError*(msg: string): YabbError =
  yabbErr(ecLockHeld, "LOCK", msg)

func lockError*(msg: string): YabbError =
  yabbErr(ecLockError, "LOCK", msg)

func shutdownError*(msg: string): YabbError =
  yabbErr(ecShutdown, "SHUTDOWN", msg)

# Summary reporting (matches bash script behavior)
proc logSummary*(scriptStatus: int, stats: ExecutionStats) =
  ## Log comprehensive execution summary with immutable stats
  ## Includes runtime, snapshots created/deleted, operations, and status
  # Calculate runtime if start time was set
  let runtime = if stats.startTime > 0.0:
    let elapsed = epochTime() - stats.startTime
    let mins = int(elapsed) div 60
    let secs = int(elapsed) mod 60
    if mins > 0: $mins & "m " & $secs & "s"
    else: $secs & "s"
  else:
    "unknown"

  # Log summary line with all details
  if scriptStatus != 0 or stats.errors > 0:
    error "Backup completed with errors",
      status = scriptStatus,
      runtime = runtime,
      snapshotsCreated = stats.snapshotsCreated,
      snapshotsDeleted = stats.snapshotsDeleted,
      errors = stats.errors,
      warnings = stats.warnings
  elif stats.warnings > 0:
    warn "Backup completed with warnings",
      runtime = runtime,
      snapshotsCreated = stats.snapshotsCreated,
      snapshotsDeleted = stats.snapshotsDeleted,
      warnings = stats.warnings
  else:
    info "Backup completed successfully",
      runtime = runtime,
      snapshotsCreated = stats.snapshotsCreated,
      snapshotsDeleted = stats.snapshotsDeleted

  # Log operations performed if any
  if stats.operations.len > 0:
    info "Operations performed", operations = stats.operations.join(", ")

{.pop.}
