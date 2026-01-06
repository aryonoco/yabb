# =============================================================================
# YABB Development Container
# Nim development environment with multi-arch support (AMD64 + ARM64)
# =============================================================================

FROM mcr.microsoft.com/devcontainers/base:debian-13

# Avoid warnings by switching to noninteractive
ENV DEBIAN_FRONTEND=noninteractive

# Build arguments for version management
ARG NIM_VERSION=2.2.6
ARG NIMLANGSERVER_VERSION=1.12.0

# Environment variables
ENV NIM_VERSION=${NIM_VERSION}
ENV PATH="/home/vscode/nim-${NIM_VERSION}/bin:/home/vscode/.nimble/bin:${PATH}"

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Build essentials
    build-essential \
    gcc \
    g++ \
    clang \
    # Static compilation (musl)
    musl-tools \
    musl-dev \
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
    git \
    # File watching (for just watch commands)
    entr \
    # Clean up
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Switch to vscode user for Nim installation
USER vscode
WORKDIR /home/vscode

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

# Verify installation
RUN nim --version && nimble --version

# Reset to root for devcontainer features
USER root

# Labels
LABEL org.opencontainers.image.title="YABB Development Container"
LABEL org.opencontainers.image.description="Nim development environment for YABB (multi-arch)"
LABEL org.opencontainers.image.version="1.1.0"
