# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

# The release WebAssembly bundle on its own, for the checks workflow's
# web-bundle step, which unit-test and the Playwright suite both use:
# `docker build -f docker/web.Dockerfile --output type=local,dest=web-dist .`
# web-dist/ is not in the checkout (card #278); this is how CI gets one.
# The server image builds the same bundle in docker/server.Dockerfile, which
# duplicates these stages; keep the two in step.

FROM docker.io/library/rust@sha256:cf9dd0ec73e75f827fe59123fff9dc65af1a1c8363c3c31ee8d7f8ad0b6a5fb2 AS web-builder
WORKDIR /src
RUN --mount=type=cache,id=sovereign-config-cargo-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=sovereign-config-cargo-git,target=/usr/local/cargo/git \
    --mount=type=cache,id=sovereign-config-cargo-target,target=/src/target \
    cargo install --locked --version 0.21.14 trunk
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY test-consumers ./test-consumers
COPY proto ./proto
RUN --mount=type=cache,id=sovereign-config-cargo-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=sovereign-config-cargo-git,target=/usr/local/cargo/git \
    --mount=type=cache,id=sovereign-config-cargo-target,target=/src/target \
    rustup target add wasm32-unknown-unknown \
    && cd crates/sovereign-config-web \
    && NO_COLOR=false trunk build --release --dist ../../web-dist

FROM scratch AS web-dist-artifact
COPY --from=web-builder /src/web-dist /
