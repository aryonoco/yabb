# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2023-2026 Aryan Ameri
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#

## Logging configuration for YABB
## Uses chronicles for structured logging
##
## Configure at compile time via nim.cfg or command line:
##   -d:chronicles_sinks=textlines
##   -d:chronicles_log_level=INFO
##   -d:chronicles_timestamps=UnixTime

{.push raises: [].}

import wrappers/log
export log  # Re-export so other modules can use logging macros

proc initLogging*(debug: bool = false) =
  ## Initialize logging - chronicles is configured at compile time
  ## Runtime debug flag only controls message verbosity, not sink setup
  if debug:
    info "Debug logging enabled"

{.pop.}
