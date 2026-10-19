# syntax=docker/dockerfile:1.7
#
# webfast as one static binary (musl) on an empty image: no shell, no libc, no packages — nothing
# to scan or to exploit besides the server itself. Built with profile-guided optimisation
# (pgo/build.sh: an instrumented build serves the sample site under a training load, without
# network, and the release build is optimised by the profile it writes — about twice the build
# time; --build-arg WEBFAST_PGO=0 builds without it). It starts with sample/Caddyfile and serves
# /srv: mount or copy a site there, and a Caddyfile of your own at /etc/webfast/Caddyfile
# (docs/operations.md). The roots for HTTPS fetches (JWKS, API specs) are built in (webpki-roots).

ARG RUST_VERSION=1

FROM rust:${RUST_VERSION}-slim-bookworm AS build
# TARGETARCH is amd64 or arm64 (set by BuildKit for the platform built for).
ARG TARGETARCH
RUN apt-get update && apt-get install -y --no-install-recommends musl-tools && rm -rf /var/lib/apt/lists/* \
 && case "$TARGETARCH" in \
      amd64) echo x86_64-unknown-linux-musl > /target ;; \
      arm64) echo aarch64-unknown-linux-musl > /target ;; \
      *) echo "no musl target for $TARGETARCH" >&2; exit 1 ;; \
    esac \
 && rustup target add "$(cat /target)" \
 && rustup component add llvm-tools
WORKDIR /src
COPY Cargo.toml Cargo.lock rustfmt.toml ./
COPY src ./src
COPY examples ./examples
COPY pgo ./pgo
COPY sample ./sample
RUN --mount=type=cache,target=/usr/local/cargo/registry cargo fetch --locked
ARG WEBFAST_PGO=1
RUN --network=none \
    --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,id=webfast-target-${TARGETARCH},target=/src/target \
    CARGO_NET_OFFLINE=true TARGET="$(cat /target)" RUSTFLAGS="-Ctarget-feature=+crt-static" \
    sh pgo/build.sh /out \
 && mkdir -p /srv /etc/webfast && chown 10002:10002 /srv \
 && cp sample/Caddyfile sample/headers.caddy /etc/webfast/

FROM scratch
COPY --from=build /out/webfast /usr/local/bin/webfast
COPY --from=build /etc/webfast /etc/webfast
COPY --from=build --chown=10002:10002 /srv /srv
ENV LOG_LEVEL=info \
    WEB_MAX_MEMORY=512MiB
USER 10002:10002
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD ["/usr/local/bin/webfast", "healthcheck", "http://127.0.0.1:8080/healthz"]
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/webfast"]
CMD ["run", "--config", "/etc/webfast/Caddyfile"]
