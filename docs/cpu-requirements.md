<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: 2023-2026 Aryan Ameri <info@ameri.me> -->

# YABB Binary Compatibility

| Binary | ISA | Required Extensions | ABI |
|--------|-----|---------------------|-----|
| `amd64` | x86-64 | SSE2 | SysV AMD64 |
| `amd64_v4` | x86-64-v4 | AVX-512 (F, VL, BW, CD, DQ), AVX2, BMI2 | SysV AMD64 |
| `i686` | Pentium 4 | SSE, SSE2, MMX | SysV i386 |
| `i586` | Pentium | (none) | SysV i386 |
| `arm64` | ARMv8-A | FP, NEON | AAPCS64 |
| `arm64v9` | ARMv9.0-A | FP, NEON, SVE2, MTE, BF16 | AAPCS64 |
| `armhf` | ARMv7-A | VFPv3, NEON, Thumb-2 | EABI5 hard-float |
| `armel` | ARMv5TEJ | Thumb | EABI5 soft-float |
| `riscv64` | RV64I 2.1 | M 2.0, A 2.1, F 2.2, D 2.2, C 2.0, Zicsr 2.0, Zifencei 2.0, Zmmul 1.0, Zaamo 1.0, Zalrsc 1.0, Zca 1.0, Zcd 1.0 | LP64D |
| `ppc64el` | POWER8 | VSX | ELFv2 |
| `loong64` | LA64 | FPU (double) | LP64D |
| `mips64el` | MIPS64r2 | FPU (double) | n64 |
| `mipsel` | MIPS32r2 | FPU (double) | o32 |
