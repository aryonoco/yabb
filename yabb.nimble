# Package

version       = "2.0.0"
author        = "yabb"
description   = "Yet Another BTRFS Backup - Nim edition"
license       = "MIT"
srcDir        = "src"
binDir        = "bin"
bin           = @["yabb"]

# Strict type safety (Nim 2.2+)
# Note: strictCaseObjects and strictFuncs disabled due to external library compatibility
# (chronicles, faststreams). strictDefs is the most impactful for catching bugs.
switch("experimental", "strictDefs")
switch("experimental", "strictNotNil")  # Nil safety tracking

# Dependencies

requires "nim >= 2.2.0"
requires "cligen >= 1.7.0"
requires "results >= 0.5.0"
requires "chronicles >= 0.10.0"
requires "parsetoml >= 0.7.0"
requires "uuids >= 0.1.0"
# termstyle removed - using std/terminal instead

# Tasks

task test, "Run tests":
  exec "testament all"

task clean, "Clean build artifacts":
  exec "rm -rf bin/yabb nimcache/"
