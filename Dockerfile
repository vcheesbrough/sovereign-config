# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

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
COPY web-dist ./web-dist
RUN --mount=type=cache,id=sovereign-config-cargo-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=sovereign-config-cargo-git,target=/usr/local/cargo/git \
    --mount=type=cache,id=sovereign-config-cargo-target,target=/src/target \
    rustup target add wasm32-unknown-unknown \
    && cd crates/sovereign-config-web \
    && NO_COLOR=false trunk build --release

FROM scratch AS web-dist-artifact
COPY --from=web-builder /src/web-dist /

FROM web-builder AS builder
ARG RELEASE_VERSION
RUN --mount=type=cache,id=sovereign-config-cargo-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=sovereign-config-cargo-git,target=/usr/local/cargo/git \
    --mount=type=cache,id=sovereign-config-cargo-target,target=/src/target \
    SOVEREIGN_CONFIG_RELEASE="$RELEASE_VERSION" cargo build --release --locked \
        --package sovereign-config-server \
        --package sovereign-config-woodpecker-broker \
    && cp /src/target/release/sovereign-config-server /tmp/sovereign-config-server \
    && cp /src/target/release/sovereign-config-woodpecker-broker /tmp/sovereign-config-woodpecker-broker

# Build the first-party CLI as a fully static x86_64 musl binary (ring, no
# OpenSSL, so musl links cleanly) and wrap it in a self-extracting installer.
# The binary is stamped with the same release version as the server, so the
# installer a running server hands out is protocol-matched by construction.
FROM web-builder AS installer-builder
ARG RELEASE_VERSION
COPY scripts ./scripts
RUN --mount=type=cache,id=sovereign-config-cargo-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=sovereign-config-cargo-git,target=/usr/local/cargo/git \
    --mount=type=cache,id=sovereign-config-cargo-target,target=/src/target \
    apt-get update && apt-get install -y --no-install-recommends musl-tools \
    && rustup target add x86_64-unknown-linux-musl \
    && SOVEREIGN_CONFIG_RELEASE="$RELEASE_VERSION" cargo build --release --locked \
        --target x86_64-unknown-linux-musl \
        --package sovereign-config-cli --package sovereign-config-mcp \
    && mkdir -p /tmp/dist /tmp/bin \
    # Package each first-party binary as a self-extracting installer. The label
    # (cli/mcp) names the installer file; the binary keeps its own name so the
    # host launches it directly. The gate extracts each finished installer and
    # confirms it installs a binary reporting exactly the version it was built
    # with, so the served installer is protocol-matched to the server. The
    # stripped binary is also kept outside the cache mount for cli-runtime.
    && for pair in "sovereign-config:cli" "sovereign-config-mcp:mcp"; do \
        name="${pair%:*}"; label="${pair#*:}"; \
        bin="/src/target/x86_64-unknown-linux-musl/release/$name"; \
        strip "$bin"; \
        cp "$bin" "/tmp/bin/$name"; \
        version="$("$bin" --version | awk '{print $NF}')"; \
        installer="/tmp/dist/install-sovereign-config-$label-$version-x86_64-linux.sh"; \
        sh scripts/make-installer.sh --binary "$bin" --name "$name" \
            --version "$version" --output "$installer"; \
        SOVEREIGN_CONFIG_BIN="/tmp/verify-$label" sh "$installer"; \
        test "$("/tmp/verify-$label/$name" --version | awk '{print $NF}')" = "$version"; \
    done

# Shared base for both runtime stages below. Both the server (OIDC token
# introspection, Authentik admin API calls) and the broker (OAuth token fetch,
# Sovereign Config API calls) make outbound HTTPS calls, so both need a
# trusted root store — a bare debian image ships none.
FROM docker.io/library/debian@sha256:60eac759739651111db372c07be67863818726f754804b8707c90979bda511df AS runtime-base
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && update-ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# This file builds two images from one source tree, so every build MUST name its
# target. `server-runtime` is not the last stage, and an unnamed `docker build .`
# would silently produce the broker image under the server's tag.
FROM runtime-base AS server-runtime
RUN useradd --system --uid 10001 --create-home sovereign-config
USER sovereign-config
COPY --from=builder /tmp/sovereign-config-server /usr/local/bin/sovereign-config-server
COPY --from=installer-builder /tmp/dist /usr/local/share/sovereign-config/dist
ENV SOVEREIGN_CONFIG_DIST_DIR=/usr/local/share/sovereign-config/dist
HEALTHCHECK --interval=5s --timeout=3s --start-period=5s --retries=12 \
    CMD ["/usr/local/bin/sovereign-config-server", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/sovereign-config-server"]

# The CLI for Woodpecker pipelines: the docker CLI image the deploy steps
# already use, plus the same static musl `sovereign-config` binary the served
# installer carries, so a step can `sovereign-config render -- docker compose …`
# with no install. Published under the same semver as the server. It keeps the
# base image's root user and entrypoint, because pipeline steps drive the
# host Docker socket through `commands:`. The build gates on the binary running
# on this base and, when a release is given, reporting exactly that release.
FROM docker:27-cli@sha256:851f91d241214e7c6db86513b270d58776379aacc5eb9c4a87e5b47115e3065c AS cli-runtime
ARG RELEASE_VERSION
COPY --from=installer-builder /tmp/bin/sovereign-config /usr/local/bin/sovereign-config
RUN version="$(sovereign-config --version | awk '{print $NF}')" \
    && test -n "$version" \
    && { test -z "$RELEASE_VERSION" || test "$version" = "$RELEASE_VERSION"; }

# The Woodpecker CI secrets extension. Published as its own image under the same
# workspace semver as the server, so the pair is protocol-matched by
# construction. The healthcheck calls the broker's own /health over loopback in
# process, so the runtime image needs no curl.
FROM runtime-base AS broker-runtime
RUN useradd --system --uid 10001 --create-home sovereign-config-broker
USER sovereign-config-broker
COPY --from=builder /tmp/sovereign-config-woodpecker-broker /usr/local/bin/sovereign-config-woodpecker-broker
HEALTHCHECK --interval=5s --timeout=3s --start-period=5s --retries=12 \
    CMD ["/usr/local/bin/sovereign-config-woodpecker-broker", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/sovereign-config-woodpecker-broker"]
