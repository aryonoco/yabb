# =============================================================================
# YABB Development Container
# Nim 2.2.6+ development environment with modern tooling
# =============================================================================

FROM mcr.microsoft.com/devcontainers/base:debian-13

# Avoid warnings by switching to noninteractive
ENV DEBIAN_FRONTEND=noninteractive

# Build arguments for version management
ARG NIM_VERSION=2.2.6
ARG CHOOSENIM_VERSION=0.8.16

# Environment variables
ENV NIM_VERSION=${NIM_VERSION}
ENV CHOOSENIM_NO_ANALYTICS=1
ENV PATH="/home/vscode/.nimble/bin:/home/vscode/.choosenim/toolchains/nim-${NIM_VERSION}/bin:${PATH}"

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

# Install choosenim and Nim
RUN curl https://nim-lang.org/choosenim/init.sh -sSf | sh -s -- -y \
    && choosenim ${NIM_VERSION} \
    && choosenim update self

# Verify installation
RUN nim --version && nimble --version

# Reset to root for devcontainer features
USER root

# Labels
LABEL org.opencontainers.image.title="YABB Development Container"
LABEL org.opencontainers.image.description="Nim 2.2.6+ development environment for YABB"
LABEL org.opencontainers.image.version="1.0.0"
