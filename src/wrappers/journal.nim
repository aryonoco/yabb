# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2023-2026 Aryan Ameri
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#

## Optional journald integration via systemd-cat
## Pure functional design - no global mutable state
##
## The JournalContext is created once at startup and passed through
## to logging functions. This avoids global mutable state while still
## allowing efficient journald integration.

import std/os
import ../utils/process

{.push raises: [].}

type
  JournalPriority* = enum
    ## syslog priority levels used by journald
    jpEmerg = "emerg"
    jpAlert = "alert"
    jpCrit = "crit"
    jpErr = "err"
    jpWarning = "warning"
    jpNotice = "notice"
    jpInfo = "info"
    jpDebug = "debug"

  JournalContext* = object ## Immutable journal context - created once at startup
    available*: bool
    tag*: string

proc isJournaldAvailable*(): bool =
  ## Check if systemd-cat is available
  ## Uses file existence check - fast enough to call at startup
  fileExists("/usr/bin/systemd-cat") or fileExists("/bin/systemd-cat")

proc newJournalContext*(tag: string = "yabb"): JournalContext =
  ## Create immutable journal context at startup
  JournalContext(available: isJournaldAvailable(), tag: tag)

proc logToJournal*(ctx: JournalContext, message: string, priority: JournalPriority) =
  ## Log message to journald via systemd-cat
  ## Context-based design - no global state
  ## Fire-and-forget - failures silently ignored
  if ctx.available:
    # Use echo to pipe through systemd-cat
    # Shell escaping handled by quoteShell
    discard runCommand(
      "sh",
      [
        "-c",
        "echo " & message.quoteShell & " | systemd-cat -t " & ctx.tag & " -p " &
          $priority,
      ],
      timeout = 1000,
    )

{.pop.}
