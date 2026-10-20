# syntax=docker/dockerfile:1.7
# hadolint global ignore=DL3008
#
# usc-message-relayer image.
#
#   docker build -t gluwa/usc-message-relayer:dev .
#
# Cluster nodes are amd64 — from Apple Silicon, build and push with:
#   docker buildx build --platform linux/amd64 -t gluwa/usc-message-relayer:<git-sha> --push .
#
# BuildKit cache mounts persist the cargo registry + build artifacts across builds, so a code-only
# change rebuilds in minutes. The runtime stage keeps the binary at /bin/message-relayer and ships
# a shell, matching how the creditcoin-message-relayer Helm chart invokes it — the chart's
# /bin/sh wrapper substitutes mounted secrets into the config, then execs the binary.
#
# The runtime stage uses ubuntu:26.04 to match the CI runner OS (ubuntu-26.04); the
# check-image-sync CI job enforces that these stay aligned. Building on the older
# rust:1.96-bookworm (glibc 2.36) and running on ubuntu:26.04 (glibc 2.39) is the safe
# forward-compatible direction — an older build glibc links fine against a newer runtime glibc.

# Matches rust-toolchain.toml.
FROM rust:1.97-bookworm AS builder
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        clang libclang-dev cmake pkg-config libssl-dev protobuf-compiler && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .
# The target dir lives in a cache mount (not an image layer), so copy the binary out within the
# same RUN step.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/src/target \
    cargo build --release -p message-relayer -p observer-node && \
    cp target/release/message-relayer /message-relayer && \
    cp target/release/observer-node /observer-node


# Runtime base is kept in sync with the CI runner OS (ubuntu-26.04) by
# .github/scripts/check-image-sync.sh — update both together.
FROM ubuntu:26.04
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates libssl3 && \
    rm -rf /var/lib/apt/lists/* && \
    useradd --home-dir /relayer --create-home relayer

# Both workspace binaries ship in one image (deps dominate the build; the observer adds a few MB).
# The default entrypoint stays the relayer; the observer-node Helm chart overrides the command to
# /bin/observer-node.
COPY --from=builder /message-relayer /bin/message-relayer
COPY --from=builder /observer-node /bin/observer-node

USER relayer
WORKDIR /relayer
# 3200 = relayer HTTP (/metrics, /health, /votes); 9100 = libp2p gossip.
# The observer chart exposes its own ports (ws + p2p) via the container spec.
EXPOSE 3200 9100/tcp 9100/udp
ENTRYPOINT ["/bin/message-relayer"]
