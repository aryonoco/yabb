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

# Summary reporting (matches bash script behavior)
proc logSummary*(scriptStatus: int, stats: ExecutionStats) =
  ## Log execution summary with immutable stats
  if scriptStatus != 0 or stats.errors > 0:
    error "Script completed with errors",
      status = scriptStatus, errors = stats.errors, warnings = stats.warnings
  else:
    info "Script completed successfully", warnings = stats.warnings

{.pop.}
