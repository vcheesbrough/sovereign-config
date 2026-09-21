# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

# The CLI for Woodpecker pipelines: the docker CLI image the deploy steps
# already use, plus a static musl `sovereign-config` binary built from the same
# source and release version as the installer the server serves, so a step can
# `sovereign-config render -- docker compose …` with no install. Published under
# the same semver as the server. It needs no web bundle.
# `docker build --platform linux/amd64 -f docker/cli.Dockerfile .`

FROM docker.io/library/rust@sha256:cf9dd0ec73e75f827fe59123fff9dc65af1a1c8363c3c31ee8d7f8ad0b6a5fb2 AS builder
ARG RELEASE_VERSION
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY test-consumers ./test-consumers
COPY proto ./proto
# Fully static x86_64 musl (ring, no OpenSSL, so musl links cleanly), stripped
# like the served installer's binary, and kept outside the cache mount. It
# builds into its own directory of the shared target cache: server.Dockerfile
# builds and strips the same musl binary in place, possibly concurrently, and
# must not be able to overwrite this one (or this one it) mid-packaging.
RUN --mount=type=cache,id=sovereign-config-cargo-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=sovereign-config-cargo-git,target=/usr/local/cargo/git \
    --mount=type=cache,id=sovereign-config-cargo-target,target=/src/target \
    apt-get update && apt-get install -y --no-install-recommends musl-tools \
    && rustup target add x86_64-unknown-linux-musl \
    && SOVEREIGN_CONFIG_RELEASE="$RELEASE_VERSION" cargo build --release --locked \
        --target x86_64-unknown-linux-musl --target-dir /src/target/cli-image \
        --package sovereign-config-cli \
    && strip /src/target/cli-image/x86_64-unknown-linux-musl/release/sovereign-config \
    && cp /src/target/cli-image/x86_64-unknown-linux-musl/release/sovereign-config /tmp/sovereign-config

# It keeps the base image's root user and entrypoint, because pipeline steps
# drive the host Docker socket through `commands:`. The build gates on the
# binary running on this base and, when a release is given, reporting exactly
# that release.
FROM docker:27-cli@sha256:851f91d241214e7c6db86513b270d58776379aacc5eb9c4a87e5b47115e3065c AS cli-runtime
ARG RELEASE_VERSION
COPY --from=builder /tmp/sovereign-config /usr/local/bin/sovereign-config
RUN version="$(sovereign-config --version | awk '{print $NF}')" \
    && test -n "$version" \
    && { test -z "$RELEASE_VERSION" || test "$version" = "$RELEASE_VERSION"; }
