# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2023-2026 Aryan Ameri
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#
# =============================================================================
# YABB Development Container
# Nim development environment with Zig cross-compilation support
# =============================================================================

FROM mcr.microsoft.com/devcontainers/base:debian-13

# Avoid warnings by switching to noninteractive
ENV DEBIAN_FRONTEND=noninteractive

# Build arguments for version management
ARG NIM_VERSION=2.2.6
ARG NIMLANGSERVER_VERSION=1.12.0
ARG ZIG_VERSION=0.15.2
ARG RISCSTAR_VERSION=15.2-r1

# Environment variables
ENV NIM_VERSION=${NIM_VERSION}
ENV ZIG_VERSION=${ZIG_VERSION}
ENV RISCSTAR_VERSION=${RISCSTAR_VERSION}
ENV PATH="/home/vscode/riscv64-toolchain/bin:/home/vscode/nim-${NIM_VERSION}/bin:/home/vscode/.nimble/bin:/home/vscode/zig:${PATH}"
ENV SHELL=/bin/zsh

# Install system dependencies
# NOTE: musl-tools and musl-dev REMOVED - Zig provides musl
# NOTE: g++ REMOVED - not needed for C compilation
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Build essentials (still needed for Nim bootstrap)
    build-essential \
    gcc \
    # Clang for LLDB debugging compatibility (not for compilation)
    clang \
    # LLVM tools (llvm-strip for cross-architecture binary stripping)
    llvm \
    # Debugging
    lldb \
    gdb \
    # BTRFS tools (for local testing)
    btrfs-progs \
    attr \
    e2fsprogs \
    # yabb runtime prerequisites
    pv \
    uuid-runtime \
    # Documentation generation
    graphviz \
    # Utilities
    file \
    curl \
    wget \
    xz-utils \
    zstd \
    git \
    # File watching (for just watch commands)
    entr \
    # Clean up
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    # Use bash for /bin/sh (dash causes issues with some VS Code extensions)
    && ln -sf /bin/bash /bin/sh

# Switch to vscode user for Nim/Zig installation
USER vscode
WORKDIR /home/vscode

# Install Zig (cross-compilation toolchain for amd64, arm64, ppc64le)
# URL format: zig-{ARCH}-linux-{VERSION}.tar.xz (architecture before OS)
RUN echo "Installing Zig ${ZIG_VERSION}..." \
    && ARCH=$(uname -m) \
    && if [ "$ARCH" = "x86_64" ]; then ZIG_ARCH="x86_64"; \
    elif [ "$ARCH" = "aarch64" ]; then ZIG_ARCH="aarch64"; \
    else echo "Unsupported architecture: $ARCH" && exit 1; fi \
    && curl -LO "https://ziglang.org/download/${ZIG_VERSION}/zig-${ZIG_ARCH}-linux-${ZIG_VERSION}.tar.xz" \
    && tar xf "zig-${ZIG_ARCH}-linux-${ZIG_VERSION}.tar.xz" \
    && mv "zig-${ZIG_ARCH}-linux-${ZIG_VERSION}" zig \
    && rm -f "zig-${ZIG_ARCH}-linux-${ZIG_VERSION}.tar.xz" \
    && echo "Zig ${ZIG_VERSION} installed successfully"

# Install RISCstar RISC-V64 musl toolchain (lp64d hard-float ABI)
# Zig's musl uses soft-float which is incompatible with Debian riscv64
# RISCstar provides both x86-64 and ARM64 hosted variants
RUN ARCH=$(uname -m) \
    && echo "Installing RISCstar RISC-V64 toolchain ${RISCSTAR_VERSION} for $ARCH host..." \
    && if [ "$ARCH" = "x86_64" ]; then RISCSTAR_HOST="x86_64"; \
    elif [ "$ARCH" = "aarch64" ]; then RISCSTAR_HOST="aarch64"; \
    else echo "Unsupported host architecture: $ARCH" && exit 1; fi \
    && curl --tlsv1.2 -LO "https://releases.riscstar.com/toolchain/${RISCSTAR_VERSION}/riscstar-toolchain-${RISCSTAR_VERSION}+qemu-${RISCSTAR_HOST}-riscv64-none-linux-musl.tar.xz" \
    && mkdir -p ~/riscv64-toolchain \
    && tar xf "riscstar-toolchain-${RISCSTAR_VERSION}+qemu-${RISCSTAR_HOST}-riscv64-none-linux-musl.tar.xz" -C ~/riscv64-toolchain --strip-components=1 \
    && rm -f "riscstar-toolchain-${RISCSTAR_VERSION}+qemu-${RISCSTAR_HOST}-riscv64-none-linux-musl.tar.xz" \
    && echo "RISCstar RISC-V64 toolchain ${RISCSTAR_VERSION} installed successfully"

# Create compatibility symlinks for Nim cross-compilation
# Nim expects riscv64-linux-gnu-* but RISCstar provides riscv64-none-linux-musl-*
RUN cd ~/riscv64-toolchain/bin \
    && for tool in gcc g++ ar ld strip objcopy objdump ranlib nm readelf; do \
    ln -sf "riscv64-none-linux-musl-$tool" "riscv64-linux-gnu-$tool"; \
    done \
    && echo "Created Nim compatibility symlinks for RISC-V64 toolchain"

# Install Nim from source (works on both AMD64 and ARM64)
RUN echo "Installing Nim ${NIM_VERSION} from source..." \
    && curl -LO "https://nim-lang.org/download/nim-${NIM_VERSION}.tar.xz" \
    && tar xf "nim-${NIM_VERSION}.tar.xz" \
    && cd "nim-${NIM_VERSION}" \
    && sh build.sh \
    && ./bin/nim c -d:release koch \
    && ./koch boot -d:release \
    && ./koch nimble \
    && ./bin/nim c -d:release -o:bin/testament testament/testament.nim \
    && ./bin/nim c -d:release -o:bin/nimsuggest nimsuggest/nimsuggest.nim \
    && cd .. \
    && rm -f "nim-${NIM_VERSION}.tar.xz" \
    && echo "Nim ${NIM_VERSION} installed successfully"

# Install nimlangserver to nim/bin (ensures availability before VS Code extensions load)
ARG NIMLANGSERVER_VERSION
RUN cd /tmp \
    && git clone --depth 1 --branch "v${NIMLANGSERVER_VERSION}" \
    https://github.com/nim-lang/langserver.git nimlangserver \
    && cd nimlangserver \
    && $HOME/nim-${NIM_VERSION}/bin/nimble setup --accept \
    && $HOME/nim-${NIM_VERSION}/bin/nim c -d:release \
    -o:$HOME/nim-${NIM_VERSION}/bin/nimlangserver nimlangserver.nim \
    && cd / && rm -rf /tmp/nimlangserver

# Create version-agnostic symlink for tooling configs
RUN ln -s ~/nim-${NIM_VERSION} ~/nim

# Install zigcc (Nim wrapper for zig cc)
RUN $HOME/nim-${NIM_VERSION}/bin/nimble install -y zigcc

# Verify installation
RUN nim --version && nimble --version && zig version && zigcc --version \
    && riscv64-none-linux-musl-gcc --version

# Reset to root for devcontainer features
USER root

# Labels
LABEL org.opencontainers.image.title="YABB Development Container"
LABEL org.opencontainers.image.description="Nim + Zig cross-compilation environment for YABB"
LABEL org.opencontainers.image.version="2.0.0"
