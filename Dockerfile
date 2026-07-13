FROM docker.io/library/rust@sha256:cf9dd0ec73e75f827fe59123fff9dc65af1a1c8363c3c31ee8d7f8ad0b6a5fb2 AS builder
WORKDIR /src
ARG RELEASE_VERSION
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY proto ./proto
RUN SOVEREIGN_CONFIG_RELEASE="$RELEASE_VERSION" cargo build --release --locked --package sovereign-config-server

FROM docker.io/library/debian@sha256:60eac759739651111db372c07be67863818726f754804b8707c90979bda511df
RUN useradd --system --uid 10001 --create-home sovereign-config
USER sovereign-config
COPY --from=builder /src/target/release/sovereign-config-server /usr/local/bin/sovereign-config-server
ENTRYPOINT ["/usr/local/bin/sovereign-config-server"]
