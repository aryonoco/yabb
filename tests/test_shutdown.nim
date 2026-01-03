# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2023-2026 Aryan Ameri
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#

## Tests for cooperative shutdown system
## Tests shutdown state management and Result-based control flow

import unittest
import std/strutils

import ../src/utils/shutdown
import ../src/types

suite "Shutdown state":
  setup:
    # Reset shutdown state before each test
    resetShutdown()

  test "isShutdownRequested returns false initially":
    check not isShutdownRequested()

  test "requestShutdown sets the shutdown flag":
    check not isShutdownRequested()
    requestShutdown()
    check isShutdownRequested()

  test "resetShutdown clears the shutdown flag":
    requestShutdown()
    check isShutdownRequested()
    resetShutdown()
    check not isShutdownRequested()

suite "checkShutdown Result integration":
  setup:
    resetShutdown()

  test "checkShutdown returns ok when not shutdown":
    let result = checkShutdown()
    check result.isOk

  test "checkShutdown returns error when shutdown requested":
    requestShutdown()
    let result = checkShutdown()
    check result.isErr
    check result.error.code == ecShutdown
    check result.error.category == "SHUTDOWN"

  test "checkShutdown error contains descriptive message":
    requestShutdown()
    let result = checkShutdown()
    check result.isErr
    check "cancelled" in result.error.msg or "signal" in result.error.msg

suite "Signal handler installation":
  test "installSignalHandlers does not crash":
    # Just verify it can be called without error
    # Actual signal handling requires sending signals which is complex to test
    installSignalHandlers()
    check true  # If we got here, installation succeeded
