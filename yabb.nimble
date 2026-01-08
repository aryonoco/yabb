# Package

version = "0.4.14"
author = "Aryan Ameri"
description = "Yet Another BTRFS Backup"
license = "MPL 2.0"
srcDir = "src"
binDir = "bin"
bin = @["yabb"]

# =============================================================================
# Configuration
# =============================================================================

# Memory management - explicit ORC for cycle collection
--mm:
  orc

# Type safety
--experimental:
  strictDefs
--experimental:
  strictNotNil
--experimental:
  strictFuncs
--experimental:
  strictCaseObjects
# --experimental:views  #  disabled due to incompatibility with chronicles and results libraries
--threads:
  on

# Style enforcement
--styleCheck:
  error

# Warnings as errors
--warningAsError:
  UnusedImport
--warningAsError:
  Deprecated
--warningAsError:
  CStringConv
--warningAsError:
  EnumConv
--warningAsError:
  HoleEnumConv
--warningAsError:
  Uninit
--warningAsError:
  ProveInit
--warningAsError:
  UnsafeSetLen
--hintAsError:
  DuplicateModuleImport
--floatChecks:
  on

# Debug build (default `nimble build`)
when not defined(release):
  --debugger:
    native
  --lineDir:
    on
  --stackTrace:
    on
  --lineTrace:
    on
  --excessiveStackTrace:
    on
  --assertions:
    on
  --checks:
    on
  --opt:
    none

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
  exec "rm -rf bin/yabb bin/yabb-linux-* nimcache/"

# =============================================================================
# Release builds
# =============================================================================

# Common release flags
const releaseFlags = "-d:release --opt:speed --mm:orc -d:lto"

# Zig compiler flags
const zigccFlags = "--cc:clang --clang.exe:zigcc --clang.linkerexe:zigcc"

# LTO flags for LLVM/Zig
const ltoFlags = "--passC:-flto=thin --passL:-flto=thin"

task releaseAmd64, "Build static binary for x86_64 Linux":
  exec "nim c " & releaseFlags & " " & zigccFlags & " " &
    "--passC:'-target x86_64-linux-musl' " & "--passL:'-target x86_64-linux-musl' " &
    "--passC:-march=x86_64 --passC:-mno-avx --passC:-mno-avx2 " & ltoFlags &
    " -o:bin/yabb-linux-amd64 src/yabb.nim"
  exec "llvm-strip -s bin/yabb-linux-amd64"
  echo "Built: bin/yabb-linux-amd64"

task releaseArm64, "Build static binary for ARM64 Linux":
  exec "nim c " & releaseFlags & " " & zigccFlags & " " & "--cpu:arm64 " &
    "--passC:'-target aarch64-linux-musl' " & "--passL:'-target aarch64-linux-musl' " &
    "--passC:-march=armv8-a --passC:-mtune=cortex_a72 " & ltoFlags &
    " -o:bin/yabb-linux-arm64 src/yabb.nim"
  exec "llvm-strip -s bin/yabb-linux-arm64"
  echo "Built: bin/yabb-linux-arm64"

task releaseRiscv64, "Build static binary for RISC-V 64-bit Linux":
  # Uses RISCstar musl toolchain with lp64d ABI (hard-float)
  # Zig's musl uses soft-float which is incompatible with Debian riscv64
  # See: https://github.com/ziglang/zig/issues/4863
  # Note: GCC for RISC-V doesn't support -mtune=generic, uses march default
  exec "nim c -d:release --opt:speed --mm:orc -d:lto " & "--cpu:riscv64 " &
    "--gcc.exe:riscv64-none-linux-musl-gcc " &
    "--gcc.linkerexe:riscv64-none-linux-musl-gcc " & "--passL:-static " &
    "--passC:-O3 --passC:-march=rv64gc " & "-o:bin/yabb-linux-riscv64 src/yabb.nim"
  exec "riscv64-none-linux-musl-strip -s bin/yabb-linux-riscv64"
  echo "Built: bin/yabb-linux-riscv64"

task releasePpc64le, "Build static binary for PowerPC 64-bit LE Linux":
  exec "nim c " & releaseFlags & " " & zigccFlags & " " & "--cpu:powerpc64 " &
    "--passC:'-target powerpc64le-linux-musl' " &
    "--passL:'-target powerpc64le-linux-musl' " &
    "--passC:-mcpu=pwr8 --passC:-mtune=pwr9 " & ltoFlags &
    " -o:bin/yabb-linux-ppc64le src/yabb.nim"
  exec "llvm-strip -s bin/yabb-linux-ppc64le"
  echo "Built: bin/yabb-linux-ppc64le"

task releaseLoong64, "Build static binary for LoongArch64 Linux":
  exec "nim c " & releaseFlags & " " & zigccFlags & " " & "--cpu:loongarch64 " &
    "--passC:'-target loongarch64-linux-musl' " &
    "--passL:'-target loongarch64-linux-musl' " & "--passC:-march=loongarch64 " &
    ltoFlags & " -o:bin/yabb-linux-loong64 src/yabb.nim"
  exec "llvm-strip -s bin/yabb-linux-loong64"
  echo "Built: bin/yabb-linux-loong64"

task releaseAll, "Build static binaries for all Linux architectures":
  exec "nimble releaseAmd64"
  exec "nimble releaseArm64"
  exec "nimble releaseRiscv64"
  exec "nimble releasePpc64le"
  exec "nimble releaseLoong64"
  echo ""
  echo "All architectures built:"
  exec "ls -lh bin/yabb-linux-*"
