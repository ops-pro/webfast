# Development

Rust 1.88 or later (`rust-version` in Cargo.toml; CI checks it). Everything below also runs in
Docker, so the host needs nothing but Docker and a POSIX shell.

## Layout

| Path                                             | What                                                                                                |
| ------------------------------------------------ | --------------------------------------------------------------------------------------------------- |
| `src/main.rs`                                    | the `webfast` command: `run`, `validate`, `healthcheck`; the environment                            |
| `src/caddyfile.rs`                               | Caddyfile syntax: tokens, `{$ENV}`, snippets, imports, the block tree                               |
| `src/config.rs`                                  | from the tree to servers, sites and handler chains; the subset and its errors                       |
| `src/handler.rs`                                 | the handler chain, as Caddy runs it                                                                 |
| `src/matcher.rs`                                 | request matchers                                                                                    |
| `src/placeholder.rs`                             | placeholders, parsed once, filled in per request                                                    |
| `src/static_files.rs`                            | `file_server`: index files, canonical slashes, precompressed siblings, conditional requests, ranges |
| `src/files.rs`                                   | the site files in memory: ETags, LZ4, snapshots replaced on change                                  |
| `src/memo.rs`                                    | ready answers for the files                                                                         |
| `src/watch.rs`                                   | changed files picked up: inotify or polling                                                         |
| `src/encode.rs`                                  | Accept-Encoding and on-the-fly zstd / Brotli / gzip                                                 |
| `src/proxy.rs`                                   | `reverse_proxy` to plain-HTTP upstreams                                                             |
| `src/server.rs`                                  | listeners, connections, runtimes; one request on any protocol                                       |
| `src/h3.rs`, `src/h3limit.rs`                    | HTTP/3 over QUIC, and its frame size limit                                                          |
| `src/tls.rs`                                     | rustls: certificates from PEM files, re-read on change; tickets, 0-RTT                              |
| `src/guard.rs`                                   | connection limits, idle, stall and grace timeouts                                                   |
| `src/sockets.rs`                                 | socket options                                                                                      |
| `src/accesslog.rs`, `src/date.rs`, `src/body.rs` | access logs, the shared `Date`, the body type                                                       |
| `tests/serve.rs`                                 | end to end, against real HTTP/1.1, HTTP/2 and HTTP/3 clients                                        |
| `examples/train.rs`                              | the PGO workload, and the sample site (`train site <dir>`)                                          |
| `examples/bench.rs`                              | the handler chain in process: time, TSC ticks, allocations per request                              |
| `examples/rtt.rs`                                | the client of `bench/rtt.sh`                                                                        |
| `sample/`                                        | the sample configuration: the image's, the PGO training's, compat's and the benchmarks'             |
| `pgo/`                                           | the release build with profile-guided optimisation                                                  |
| `compat/`                                        | the differential check against Caddy                                                                |
| `bench/`                                         | load and latency benchmarks                                                                         |
| `scripts/`                                       | `check.sh` (the CI checks), `volumes.sh` (a site and configuration in Docker volumes)               |

## Checks

```bash
scripts/check.sh            # all of them
scripts/check.sh fmt clippy # some
```

| Check    | What                                                                                    |
| -------- | --------------------------------------------------------------------------------------- |
| `fmt`    | `cargo fmt --check` (rustfmt.toml: edition 2024, 120 columns)                           |
| `clippy` | `cargo clippy --all-targets -- -D warnings`                                             |
| `test`   | `cargo test` on the current stable Rust                                                 |
| `msrv`   | `cargo test` on the `rust-version` of Cargo.toml                                        |
| `deny`   | `cargo deny check`: advisories (RustSec), licenses, banned or duplicate crates, sources |

`check.sh` runs each in a `rust:*-slim-bookworm` container, with the crate cache, the build
directory and the tools in Docker volumes (`webfast-cargo`, `webfast-target`, `webfast-tools`).
CI ([`.gitlab-ci.yml`](../.gitlab-ci.yml)) runs the same jobs on every push and merge request, and
builds the image on the default branch and tags.

## Tests

`cargo test` — unit tests in the modules, and `tests/serve.rs` end to end: a site shaped like
`sample/Caddyfile` with a stub upstream; HTTP/1.1, HTTP/2 over TLS and HTTP/3 clients; SSE
timing; ready answers against the chain for every case; slow readers and senders; idle HTTP/2;
connection limits; oversized HTTP/3 header frames; both runtimes and their shutdown; changed files
picked up by inotify and by polling.

## The PGO build

```bash
rustup component add llvm-tools
sh pgo/build.sh /tmp/webfast          # → /tmp/webfast/webfast
WEBFAST_PGO=0 sh pgo/build.sh /tmp/webfast   # a plain release build
```

`pgo/build.sh` builds the server instrumented (`-Cprofile-generate`), runs `pgo/train.sh` — the
instrumented server on `sample/Caddyfile` with the sample site, plain and over TLS, under 15 s of
`examples/train.rs run` — merges the profiles and builds again with `-Cprofile-use`. Only the
loopback is used. A new kind of work the server does (a handler, a protocol feature, an upstream
answer of a new shape) belongs in `examples/train.rs`, or it is optimised as cold code.

## The sample site

`examples/train.rs site <dir>` writes the same site on every run: pages in four languages (one with
a section of its own), hashed build assets, fonts, images, a service worker and its manifest, every
text file with `.br`, `.zst` and `.gz` siblings; it prints the paths to request. It is what the PGO
training, `compat/` and `bench/` serve, with `sample/Caddyfile` and `sample/headers.caddy`.

```bash
cargo build --release --example train --example bench --example rtt
```

## The compatibility check

```bash
WEBFAST_BIN=target/release/webfast TRAIN_BIN=target/release/examples/train compat/run.sh
```

Caddy (`caddy:2-alpine`) and webfast serve the same Caddyfile and site from Docker volumes, stub
upstreams (`compat/upstream.mjs`) play `app` and `stream`, and `compat/compare.mjs` sends ~80 requests to
both — pages, precompressed files, ranges, conditional requests, redirects, path tricks, methods,
proxying, SSE — comparing status, headers and decoded bodies. Expected differences
(docs/configuration.md) are counted, not failed. `SITE_DIR`, `CADDYFILE` and `HEADERS` serve
something else; the request list is written for the sample site. Stock Caddy has no Brotli
encoder, so both get the Caddyfile without `br` in `encode`.

## Benchmarks

```bash
# oha at a fixed rate (RATE=1000/s, RUNS=10 × REQUESTS=5000) per scenario — a page, a build asset, a
# redirect — the server's CPU time per request from its cgroup; then examples/bench.rs in process
WEBFAST_BIN=… TRAIN_BIN=… BENCH_BIN=…/examples/bench bench/run.sh <label>

# time from a new connection to the first response over a slow link (tc netem, DELAY_MS=25 on each
# side): HTTP/2 over TCP + TLS, HTTP/3, HTTP/3 with 0-RTT
WEBFAST_BIN=… RTT_BIN=…/examples/rtt bench/rtt.sh
```

`examples/bench.rs` (`bench <Caddyfile> <iterations> <rounds> <path>…`; `304:<path>` revalidates,
`identity:<path>` asks without Accept-Encoding; `BENCH_CHAIN=1` takes the chain instead of the
ready answers) loads the configuration's files where the Caddyfile says, so `bench/run.sh` runs it
in a container with the site and configuration volumes. For a profile, run one path with many
iterations under `perf record -e cpu-clock`.

## Releasing

1. Update `version` in Cargo.toml and the [changelog](../CHANGELOG.md).
2. `scripts/check.sh`, and `compat/run.sh` with a release build.
3. Commit, tag `vX.Y.Z`, push the tag: CI builds and pushes the image (`:X.Y.Z` and `:latest`).
