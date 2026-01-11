# SPDX-License-Identifier: 0BSD
# Copyright (c) 2023-2026 Aryan Ameri
#
# Package

version = "0.5.2"
author = "Aryan Ameri"
description = "Yet Another BTRFS Backup"
license = "MPL 2.0"
srcDir = "src"
binDir = "bin"
bin = @["yabb"]

# =============================================================================
# Configuration
# =============================================================================

# Memory management
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
  exec "rm -rf bin/yabb bin/yabb-* nimcache/"

# =============================================================================
# Release builds
# =============================================================================

# Common release flags
const releaseFlags = "-d:release --opt:speed --mm:orc -d:lto"

# Zig compiler flags
const zigccFlags = "--cc:clang --clang.exe:zigcc --clang.linkerexe:zigcc"

const ltoFlags =
  "--passC:-ffunction-sections --passC:-fdata-sections " &
  "--passC:-flto=thin --passL:-flto=thin --passL:-Wl,--gc-sections --passL:-s"

task releaseAmd64, "Build static binary for x86_64 Linux":
  exec "nim c " & releaseFlags & " " & zigccFlags & " " &
    "--passC:'-target x86_64-linux-musl' " & "--passL:'-target x86_64-linux-musl' " &
    "--passC:-march=x86_64 --passC:-mno-avx --passC:-mno-avx2 " & ltoFlags &
    " -o:bin/yabb-linux-amd64 src/yabb.nim"
  echo "Built: bin/yabb-linux-amd64"

task releaseArm64, "Build static binary for ARM64 Linux":
  exec "nim c " & releaseFlags & " " & zigccFlags & " " & "--cpu:arm64 " &
    "--passC:'-target aarch64-linux-musl' " & "--passL:'-target aarch64-linux-musl' " &
    "--passC:-march=armv8-a --passC:-mtune=cortex_a72 " & ltoFlags &
    " -o:bin/yabb-linux-arm64 src/yabb.nim"
  echo "Built: bin/yabb-linux-arm64"

task releaseArmhf, "Build static binary for ARMv7 Linux (armhf)":
  # Debian armhf: ARMv7-A + VFPv3 + Thumb-2 + NEON, hard-float EABI
  # Note: Zig's musl includes NEON-optimised routines, so NEON is unavoidable
  exec "nim c " & releaseFlags & " " & zigccFlags & " " & "--cpu:arm " &
    "--passC:'-target arm-linux-musleabihf' " & "--passL:'-target arm-linux-musleabihf' " &
    "--passC:-mcpu=baseline " & ltoFlags & " -o:bin/yabb-linux-armhf src/yabb.nim"
  echo "Built: bin/yabb-linux-armhf"

task releaseArmel, "Build static binary for ARMv5 Linux (armel - CI only)":
  # Debian armel: ARMv5T baseline, soft-float EABI
  # Uses Bootlin musl toolchain
  # CI-only, not available in devcontainer due to lack of arm64 host support)
  # See: https://wiki.debian.org/ArmEabiPort
  # Using -flto=auto for parallel LTO
  exec "nim c -d:release --opt:speed --mm:orc " & "--cpu:arm " &
    "--gcc.exe:arm-buildroot-linux-musleabi-gcc " &
    "--gcc.linkerexe:arm-buildroot-linux-musleabi-gcc " & "--passL:-static " &
    "--passC:-O3 " &
    "--passC:-march=armv5t --passC:-mfloat-abi=soft --passC:-mabi=aapcs-linux " &
    "--passC:-ffunction-sections --passC:-fdata-sections " &
    "--passC:-flto=auto --passL:-flto=auto " & "--passL:-Wl,--gc-sections " &
    "-o:bin/yabb-linux-armel src/yabb.nim"
  exec "arm-buildroot-linux-musleabi-strip --strip-all bin/yabb-linux-armel"
  echo "Built: bin/yabb-linux-armel"

task releaseRiscv64, "Build static binary for RISC-V 64-bit Linux":
  # Uses RISCstar musl toolchain with lp64d ABI (hard-float)
  # Zig's musl uses soft-float which is incompatible with Debian riscv64
  # See: https://github.com/ziglang/zig/issues/4863
  exec "nim c -d:release --opt:speed --mm:orc " & "--cpu:riscv64 " &
    "--gcc.exe:riscv64-none-linux-musl-gcc " &
    "--gcc.linkerexe:riscv64-none-linux-musl-gcc " & "--passL:-static " &
    "--passC:-O3 --passC:-march=rv64gc " &
    "--passC:-ffunction-sections --passC:-fdata-sections " &
    "--passC:-flto=auto --passL:-flto=auto " & "--passL:-Wl,--gc-sections " &
    "-o:bin/yabb-linux-riscv64 src/yabb.nim"
  exec "riscv64-none-linux-musl-strip -s bin/yabb-linux-riscv64"
  echo "Built: bin/yabb-linux-riscv64"

task releasePpc64el, "Build static binary for PowerPC 64-bit LE Linux":
  exec "nim c " & releaseFlags & " " & zigccFlags & " " & "--cpu:powerpc64 " &
    "--passC:'-target powerpc64le-linux-musl' " &
    "--passL:'-target powerpc64le-linux-musl' " &
    "--passC:-mcpu=pwr8 --passC:-mtune=pwr9 " & ltoFlags &
    " -o:bin/yabb-linux-ppc64el src/yabb.nim"
  echo "Built: bin/yabb-linux-ppc64el"

task releaseLoong64, "Build static binary for LoongArch64 Linux":
  exec "nim c " & releaseFlags & " " & zigccFlags & " " & "--cpu:loongarch64 " &
    "--passC:'-target loongarch64-linux-musl' " &
    "--passL:'-target loongarch64-linux-musl' " & "--passC:-march=loongarch64 " &
    ltoFlags & " -o:bin/yabb-linux-loong64 src/yabb.nim"
  echo "Built: bin/yabb-linux-loong64"

task releaseMips64el, "Build static binary for MIPS64EL Linux":
  # Debian mips64el: MIPS64R2 baseline, N64 ABI, hard-float
  # Uses Zig cross-compilation with musl
  # See: https://wiki.debian.org/MIPSPort
  exec "nim c " & releaseFlags & " " & zigccFlags & " " & "--cpu:mips64 " &
    "--passC:'-target mips64el-linux-muslabi64' " &
    "--passL:'-target mips64el-linux-muslabi64' " & "--passC:-mcpu=mips64r2 " & ltoFlags &
    " -o:bin/yabb-linux-mips64el src/yabb.nim"
  echo "Built: bin/yabb-linux-mips64el"

task releaseMipsel, "Build static binary for MIPS32 LE Linux (ALT Linux mipsel)":
  # ALT Linux mipsel: MIPS32R2 baseline, o32 ABI, hard-float
  # Common denominator for Baikal-T1 (P5600) and Loongson 3A
  # See: https://www.altlinux.org/Ports/mipsel
  exec "nim c " & releaseFlags & " " & zigccFlags & " " & "--cpu:mips " &
    "--passC:'-target mipsel-linux-musleabihf' " &
    "--passL:'-target mipsel-linux-musleabihf' " & "--passC:-mcpu=mips32r2 " & ltoFlags &
    " -o:bin/yabb-linux-mipsel src/yabb.nim"
  echo "Built: bin/yabb-linux-mipsel"

task releaseAll, "Build static binaries for all Linux architectures":
  exec "nimble releaseAmd64"
  exec "nimble releaseArm64"
  exec "nimble releaseArmhf"
  exec "nimble releaseRiscv64"
  exec "nimble releasePpc64el"
  exec "nimble releaseLoong64"
  exec "nimble releaseMips64el"
  exec "nimble releaseMipsel"
  echo ""
  echo "All architectures built:"
  exec "ls -lh bin/yabb-linux-*"
