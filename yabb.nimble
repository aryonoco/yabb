# Package

version = "0.4.5"
author = "Aryan Ameri"
description = "Yet Another BTRFS Backup"
license = "MPL 2.0"
srcDir = "src"
binDir = "bin"
bin = @["yabb"]

# Type safety
# Note: strictCaseObjects and strictFuncs disabled due to external library compatibility
# (chronicles, faststreams).
switch("experimental", "strictDefs")
switch("experimental", "strictNotNil")

# Debug build configuration (default via `nimble build`)
when not defined(release):
  switch("debugger", "native") # Native debugger support (LLDB/GDB)
  switch("lineDir", "on") # Include line info for debugging
  switch("stackTrace", "on") # Stack traces on crash
  switch("lineTrace", "on") # Line traces on crash
  switch("assertions", "on") # Enable assertions
  switch("checks", "on") # Enable runtime checks
  switch("opt", "none") # No optimisation

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

task release, "Build static musl binary for x86_64":
  exec "nim c " & "-d:release " & "--opt:speed " & "--mm:orc " & "-d:lto " &
    "--passC:-march=x86-64-v2 " & "--passC:-mtune=skylake " & "--passC:-flto " &
    "--gcc.exe:musl-gcc " & "--gcc.linkerexe:musl-gcc " & "--passL:-static " &
    "--passL:-flto " & "-o:bin/yabb " & "src/yabb.nim"
  exec "strip -s bin/yabb"
  echo "Built: bin/yabb (static musl x86_64)"

task releaseArm64, "Build static musl binary for ARM64":
  exec "nim c " & "-d:release " & "--opt:speed " & "--mm:orc " & "-d:lto " &
    "--passC:-march=armv8-a " & "--passC:-mtune=cortex-a72 " & "--passC:-flto " &
    "--gcc.exe:musl-gcc " & "--gcc.linkerexe:musl-gcc " & "--passL:-static " &
    "--passL:-flto " & "-o:bin/yabb " & "src/yabb.nim"
  exec "strip -s bin/yabb"
  echo "Built: bin/yabb (static musl arm64)"
