# Package

version       = "0.1.0"
author        = "yabb"
description   = "Yet Another BTRFS Backup"
license       = "MPL 2.0"
srcDir        = "src"
binDir        = "bin"
bin           = @["yabb"]

# Strict type safety (Nim 2.2+)
# Note: strictCaseObjects and strictFuncs disabled due to external library compatibility
# (chronicles, faststreams).
switch("experimental", "strictDefs")
switch("experimental", "strictNotNil")  # Nil safety tracking

# Release build optimizations (same as musl build, but dynamic glibc)
when defined(release):
  switch("opt", "speed")
  switch("mm", "orc")
  switch("define", "lto")
  switch("passC", "-march=x86-64-v2")
  switch("passC", "-mtune=skylake")
  switch("passC", "-flto")
  switch("passL", "-flto")

# Dependencies

requires "nim >= 2.2.0"
requires "cligen >= 1.7.0"
requires "results >= 0.5.0"
requires "chronicles >= 0.10.0"
requires "parsetoml >= 0.7.0"
requires "uuids >= 0.1.0"

# Tasks

task test, "Run tests":
  exec "testament all"

task clean, "Clean build artifacts":
  exec "rm -rf bin/yabb bin/yabb-static nimcache/"

task release, "Build optimized static musl binary (default for deployment)":
  exec "nim c " &
       "-d:release " &
       "--opt:speed " &
       "--mm:orc " &
       "-d:lto " &
       "--passC:-march=x86-64-v2 " &
       "--passC:-mtune=skylake " &
       "--passC:-flto " &
       "--gcc.exe:musl-gcc " &
       "--gcc.linkerexe:musl-gcc " &
       "--passL:-static " &
       "--passL:-flto " &
       "-o:bin/yabb " &
       "src/yabb.nim"
  exec "strip -s bin/yabb"
  echo "Built: bin/yabb (static musl)"

task glibc, "Build optimized dynamic glibc binary (for debugging)":
  exec "nimble build -d:release"
  exec "strip -s bin/yabb"
  echo "Built: bin/yabb (dynamic glibc)"
