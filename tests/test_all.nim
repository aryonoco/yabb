# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2023-2026 Aryan Ameri
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#

## YABB Test Suite
## Main test entry point for testament
## Run with: nimble test or testament all

import unittest

# Import all test modules
import test_config
import test_paths
import test_retention
import test_types
import test_btrfs
import test_shutdown

echo "Running YABB test suite..."
