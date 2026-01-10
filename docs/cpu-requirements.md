<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: 2023-2026 Aryan Ameri <info@ameri.me> -->

# YABB Binary Compatibility

| Binary | ISA | Required Extensions | ABI |
|--------|-----|---------------------|-----|
| `amd` | x86-64 | SSE2 | SysV AMD64 |
| `arm64` | ARMv8-A | FP, NEON | AAPCS64 |
| `armv7l` | ARMv7-A | VFPv3, NEON, Thumb-2 | EABI5 hard-float |
| `armv5l` | ARMv5TEJ | Thumb | EABI5 soft-float |
| `riscv64` | RV64I 2.1 | M 2.0, A 2.1, F 2.2, D 2.2, C 2.0, Zicsr 2.0, Zifencei 2.0, Zmmul 1.0, Zaamo 1.0, Zalrsc 1.0, Zca 1.0, Zcd 1.0 | LP64D |
| `ppc64le` | POWER8 | VSX | ELFv2 |
| `loong64` | LA64 | FPU (double) | LP64D |
| `mips64el` | MIPS64r2 | FPU (double) | n64 |
| `mipsel` | MIPS32r2 | FPU (double) | o32 |
