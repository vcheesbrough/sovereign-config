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
    SOVEREIGN_CONFIG_RELEASE="$RELEASE_VERSION" cargo build --release --locked --package sovereign-config-server \
    && cp /src/target/release/sovereign-config-server /tmp/sovereign-config-server

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
    && mkdir -p /tmp/dist \
    # Package each first-party binary as a self-extracting installer. The label
    # (cli/mcp) names the installer file; the binary keeps its own name so the
    # host launches it directly. The gate extracts each finished installer and
    # confirms it installs a binary reporting exactly the version it was built
    # with, so the served installer is protocol-matched to the server.
    && for pair in "sovereign-config:cli" "sovereign-config-mcp:mcp"; do \
        name="${pair%:*}"; label="${pair#*:}"; \
        bin="/src/target/x86_64-unknown-linux-musl/release/$name"; \
        strip "$bin"; \
        version="$("$bin" --version | awk '{print $NF}')"; \
        installer="/tmp/dist/install-sovereign-config-$label-$version-x86_64-linux.sh"; \
        sh scripts/make-installer.sh --binary "$bin" --name "$name" \
            --version "$version" --output "$installer"; \
        SOVEREIGN_CONFIG_BIN="/tmp/verify-$label" sh "$installer"; \
        test "$("/tmp/verify-$label/$name" --version | awk '{print $NF}')" = "$version"; \
    done

FROM docker.io/library/debian@sha256:60eac759739651111db372c07be67863818726f754804b8707c90979bda511df
RUN useradd --system --uid 10001 --create-home sovereign-config
USER sovereign-config
COPY --from=builder /tmp/sovereign-config-server /usr/local/bin/sovereign-config-server
COPY --from=installer-builder /tmp/dist /usr/local/share/sovereign-config/dist
ENV SOVEREIGN_CONFIG_DIST_DIR=/usr/local/share/sovereign-config/dist
HEALTHCHECK --interval=5s --timeout=3s --start-period=5s --retries=12 \
    CMD ["/usr/local/bin/sovereign-config-server", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/sovereign-config-server"]
