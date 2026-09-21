# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

# The Woodpecker CI secrets extension. Published as its own image under the same
# workspace semver as the server, so the pair is protocol-matched by
# construction. It needs neither the web bundle nor the server binary.
# `docker build --platform linux/amd64 -f docker/broker.Dockerfile .`

FROM docker.io/library/rust@sha256:cf9dd0ec73e75f827fe59123fff9dc65af1a1c8363c3c31ee8d7f8ad0b6a5fb2 AS builder
ARG RELEASE_VERSION
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY test-consumers ./test-consumers
COPY proto ./proto
RUN --mount=type=cache,id=sovereign-config-cargo-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=sovereign-config-cargo-git,target=/usr/local/cargo/git \
    --mount=type=cache,id=sovereign-config-cargo-target,target=/src/target \
    SOVEREIGN_CONFIG_RELEASE="$RELEASE_VERSION" cargo build --release --locked \
        --package sovereign-config-woodpecker-broker \
    && cp /src/target/release/sovereign-config-woodpecker-broker /tmp/sovereign-config-woodpecker-broker

# The broker makes outbound HTTPS calls (OAuth token fetch, Sovereign Config API
# calls), so it needs a trusted root store — a bare debian image ships none.
# The healthcheck calls the broker's own /health over loopback in process, so
# the runtime image needs no curl.
FROM docker.io/library/debian@sha256:60eac759739651111db372c07be67863818726f754804b8707c90979bda511df AS broker-runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && update-ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN useradd --system --uid 10001 --create-home sovereign-config-broker
USER sovereign-config-broker
COPY --from=builder /tmp/sovereign-config-woodpecker-broker /usr/local/bin/sovereign-config-woodpecker-broker
HEALTHCHECK --interval=5s --timeout=3s --start-period=5s --retries=12 \
    CMD ["/usr/local/bin/sovereign-config-woodpecker-broker", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/sovereign-config-woodpecker-broker"]
