<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: 2023-2026 Aryan Ameri <info@ameri.me> -->

# YABB Docker Test Environments

Docker images used to verify binary compatibility for each supported architecture.

| Binary | Docker Image | OS | `uname -m` | `dpkg --print-architecture` |
|--------|--------------|----|-----------:|----------------------------:|
| `amd64` | `debian:trixie` | Debian 13 (trixie) | `x86_64` | `amd64` |
| `arm64` | `arm64v8/debian:trixie` | Debian 13 (trixie) | `aarch64` | `arm64` |
| `armhf` | `arm32v7/debian:trixie` | Debian 13 (trixie) | `armv7l` | `armhf` |
| `armel` | `arm32v5/debian:latest` | Debian 13 (trixie) | `armv7l`* | `armel` |
| `riscv64` | `riscv64/debian:trixie` | Debian 13 (trixie) | `riscv64` | `riscv64` |
| `ppc64el` | `ppc64le/debian:trixie` | Debian 13 (trixie) | `ppc64le` | `ppc64el` |
| `loong64` | `loongarch64/debian:latest` | Debian trixie/sid | `loongarch64` | `loong64` |
| `mips64el` | `mips64le/debian:buster` | Debian 10 (buster) | `mips64` | `mips64el` |
| `mipsel` | `aoqi/debian-mipsel:latest` | Debian 9 (stretch) | `mips` | `mipsel` |

\* QEMU user-mode emulation reports `armv7l` even for ARMv5 containers.
