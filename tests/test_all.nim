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

echo "Running YABB test suite..."
