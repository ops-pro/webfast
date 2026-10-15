# syntax=docker/dockerfile:1.7
#
# webfast, built with profile-guided optimisation (pgo/build.sh: an instrumented build serves the
# sample site under a training load, without network, and the release build is optimised by the
# profile it writes — about twice the build time; --build-arg WEBFAST_PGO=0 builds without it), on
# Debian slim. It starts with sample/Caddyfile and serves /srv: mount or copy a site there, and a
# Caddyfile of your own at /etc/webfast/Caddyfile (docs/operations.md).

ARG RUST_VERSION=1

FROM rust:${RUST_VERSION}-slim-bookworm AS build
RUN rustup component add llvm-tools
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
    --mount=type=cache,id=webfast-target,target=/src/target \
    CARGO_NET_OFFLINE=true sh pgo/build.sh /out

FROM debian:bookworm-slim
RUN groupadd --system --gid 10002 webfast \
 && useradd --system --uid 10002 --gid webfast --home-dir /srv --shell /usr/sbin/nologin webfast \
 && mkdir -p /srv
COPY --from=build /out/webfast /usr/local/bin/webfast
COPY sample/Caddyfile sample/headers.caddy /etc/webfast/
ENV LOG_LEVEL=info \
    WEB_MAX_MEMORY=512MiB
USER 10002:10002
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD ["/usr/local/bin/webfast", "healthcheck", "http://127.0.0.1:8080/healthz"]
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/webfast"]
CMD ["run", "--config", "/etc/webfast/Caddyfile"]
