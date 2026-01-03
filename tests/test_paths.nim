## Tests for path utilities
## Tests path sanitization, validation, and manipulation

import unittest
import std/[os, strutils]

import ../src/types
import ../src/utils/paths

# Note: Many path tests require existing paths due to expandFilename behavior
# Tests are designed to work across different Unix environments

suite "Path sanitization - edge cases":
  test "empty path returns error":
    let result = sanitizePath("")
    check result.isErr

  test "whitespace-only path returns error":
    let result = sanitizePath("   ")
    check result.isErr

  test "single dot path returns error":
    check sanitizePath(".").isErr

  test "double dot path returns error":
    check sanitizePath("..").isErr

  test "relative path to nonexistent dir fails":
    # expandFilename in Nim 2.x requires the path to exist
    let result = sanitizePath("nonexistent_random_path_12345")
    check result.isErr

suite "Path sanitization - existing paths":
  # These tests use paths that should exist on any Unix system

  test "root path returns error":
    # Root "/" becomes "" after trailing slash strip, which is invalid
    let result = sanitizePath("/")
    check result.isErr

  test "var directory works":
    if dirExists("/var"):
      let result = sanitizePath("/var")
      check result.isOk
      check result.value == "/var"

  test "etc directory works":
    if dirExists("/etc"):
      let result = sanitizePath("/etc")
      check result.isOk

suite "Path validation":
  test "root directory is not allowed":
    # Root path "/" becomes "" after sanitization
    let result = validatePath("/", "directory", true)
    check result.isErr

  test "var directory validates":
    if dirExists("/var"):
      let result = validatePath("/var", "directory", true)
      check result.isOk

  test "non-existent path fails when mustExist":
    let result = validatePath("/nonexistent/path/12345", "any", true)
    check result.isErr

  test "file validated as directory fails":
    if fileExists("/etc/passwd"):
      let result = validatePath("/etc/passwd", "directory", true)
      check result.isErr

  test "directory validated as file fails":
    if dirExists("/var"):
      let result = validatePath("/var", "file", true)
      check result.isErr

suite "Path joining":
  test "join non-existent paths fails":
    let result = joinPaths("/nonexistent", "sub")
    check result.isErr

  test "join with existing base works":
    if dirExists("/var"):
      let result = joinPaths("/var", "log")
      # May fail if /var/log doesn't exist
      if result.isOk:
        check result.value.endsWith("log")

suite "Subpath detection":
  test "subpath of parent":
    if dirExists("/var/log"):
      check isSubPath("/var/log", "/var")

  test "same path is subpath of itself":
    if dirExists("/var"):
      check isSubPath("/var", "/var")

  test "parent is not subpath of child":
    check not isSubPath("/var", "/var/log")

  test "nonexistent paths return false":
    check not isSubPath("/nonexistent/path", "/var")

suite "Directory ensuring":
  test "ensureDir succeeds for existing dir":
    if dirExists("/var"):
      let result = ensureDir("/var")
      check result.isOk

  test "ensureDir in dry run always succeeds":
    let result = ensureDir("/nonexistent/path/12345", dryRun = true)
    check result.isOk

  test "ensureDir creates new directory in tmp":
    let testDir = "/tmp/yabb_test_ensuredir_" & $getCurrentProcessId()
    defer:
      if dirExists(testDir):
        removeDir(testDir)

    check not dirExists(testDir)
    let result = ensureDir(testDir)
    check result.isOk
    check dirExists(testDir)

suite "MaxPathLength constant":
  test "MaxPathLength is 4096":
    check MaxPathLength == 4096
