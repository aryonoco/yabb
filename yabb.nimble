# Package

version = "0.4.5"
author = "Aryan Ameri"
description = "Yet Another BTRFS Backup"
license = "MPL 2.0"
srcDir = "src"
binDir = "bin"
bin = @["yabb"]

# =============================================================================
# Configuration
# =============================================================================


--experimental:strictDefs
--experimental:strictNotNil
--experimental:strictFuncs
--experimental:strictCaseObjects

# Style
switch("styleCheck", "error")

switch("warningAsError", "UnusedImport")
switch("warningAsError", "Deprecated")
switch("warningAsError", "CStringConv")
switch("warningAsError", "EnumConv")
switch("warningAsError", "HoleEnumConv")
switch("hintAsError", "DuplicateModuleImport")

# Debug build (default `nimble build`)
when not defined(release):
  switch("debugger", "native")
  switch("lineDir", "on")
  switch("stackTrace", "on")
  switch("lineTrace", "on")
  switch("assertions", "on")
  switch("checks", "on")
  switch("opt", "none")

# Dependencies

requires "nim >= 2.2.0"
requires "cligen == 1.9.5"
requires "results == 0.5.1"
requires "chronicles == 0.12.0"
requires "parsetoml == 0.7.2"
requires "uuids == 0.1.12"

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
