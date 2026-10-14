# web-server

The static front of the Docker deployment (`web` service): serves the built site from memory and
routes the dynamic paths to the app and the streaming service. It is configured with a **strict subset
of the Caddyfile** — [`docker/Caddyfile`](../../docker/Caddyfile) — so the same file also runs in
Caddy, and the two can be compared request by request ([`compat/`](compat)).

What it adds over Caddy, with no extra directives:

- **Files from memory.** Every site root is read once at startup; requests never touch the disk.
  `WEB_MAX_MEMORY` (default `512MiB`) caps it; the reference site takes about 32 MB with its
  precompressed siblings.
- **ETag = hash of the content** (BLAKE3, 80 bits) instead of modification time + size: unchanged
  files keep their ETag across deploys (304 instead of a full response) and every replica sends the
  same one. There is no `Last-Modified`.
- **Brotli on the fly** (`encode zstd br gzip`), besides zstd and gzip. Responses of known length up
  to 1 MiB are compressed whole and sent with `Content-Length`; streams are compressed frame by frame,
  so they still flow.

Protocols: HTTP/1.1; HTTP/2 over TLS (h2c on request); **HTTP/3** (QUIC, quinn + h3) on the same port
when the site has `tls`, advertised with `Alt-Svc`. TLS is rustls with aws-lc-rs: TLS 1.3/1.2, the
post-quantum key exchange X25519MLKEM768 preferred, ML-DSA certificates accepted. Certificates come
from PEM files and are re-read within a minute when they change — there is no ACME client.

Connections:

- **SO_REUSEPORT**: one listening socket per CPU, each with its own accept loop; the kernel spreads
  new connections over them, and a new process can bind the port while the old one drains.
- **TLS resumption**: TLS 1.3 session tickets (keys live in the process, so a restart or another
  replica means a full handshake), and a cache of 16 384 sessions for resumption by ID.
- **HTTP/3 0-RTT**: a resumed QUIC client sends its first request with the handshake. Early requests
  are answered only for GET, HEAD and OPTIONS (they change nothing if an attacker replays them) and
  reach the handler with `Early-Data: 1`; anything else gets `425 Too Early` and the browser repeats
  it after the handshake (RFC 8470). TCP does not take early data.

## Configuration subset

| Kind           | Supported                                                                                                                                                                                                                                                         |
| -------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Syntax         | blocks, quotes and backticks, comments, `\` line continuation, `{$ENV}` / `{$ENV:default}`, snippets `(name)`, `import <snippet>` / `import <file or glob>`                                                                                                       |
| Global options | `auto_https off`, `admin off`, `http_port`, `https_port`, `grace_period`, `debug`, `order`, `servers [:port] { trusted_proxies static …, trusted_proxies_strict, client_ip_headers, protocols, timeouts { read_header } }`                                        |
| Site           | addresses `:port`, `host`, `host:port`, `http://…`, `https://…` (several per block); `tls <cert> <key>`; `log { output stdout\|stderr\|discard; format json\|console }`                                                                                           |
| Directives     | `root`, `header` (set, `+`add, `-`delete incl. `-Prefix*`, `?`default, `defer`), `request_header`, `redir` (3xx, `permanent`, `temporary`, `html`), `rewrite`, `try_files`, `encode`, `route`, `handle`, `handle_path`, `respond`, `reverse_proxy`, `file_server` |
| Matchers       | `path`, `path_regexp`, `file` (`root`, `try_files`, `try_policy first_exist`), `not`, `host`, `method`, `header`, `client_ip`, `remote_ip`, `protocol`; inline `*`, `/path`, `@name`                                                                              |
| reverse_proxy  | plain-HTTP upstreams (`host:port`), `to`, `lb_policy random\|first\|round_robin`, `lb_try_duration`, `lb_try_interval`, `flush_interval`, `header_up`, `header_down`, `transport http { dial_timeout, response_header_timeout, keepalive, versions 1.1 }`         |
| file_server    | `root`, `index`, `hide`, `precompressed`, `pass_thru`, `disable_canonical_uris`                                                                                                                                                                                   |
| Placeholders   | `{path}`, `{dir}`, `{file}`, `{query}`, `{uri}`, `{host}`, `{hostport}`, `{method}`, `{scheme}`, `{remote_host}`, `{remote_port}`, `{client_ip}`, `{header.*}`, `{re.<name>.<group>}`, `{file_match.*}`, `{env.*}` and their `http.*` long forms                  |

Anything else — an unknown directive, option, matcher or placeholder — stops the server at startup
with the file and line, instead of being ignored. Semantics follow Caddy: directive order and
path-specificity sorting outside `route`, mutually exclusive `handle` blocks, deferred `header`
operations, `try_files` matching directories only for patterns ending in `/`, canonical trailing
slashes, the empty 200 at the end of a chain.

**Known differences from Caddy** (all checked by `compat/`): no `Last-Modified` and content-hash ETag
values; no `Via` on proxied responses; the upstream gets the client's `Accept-Encoding` as is (Caddy's
transport asks for gzip when the client sent none); handler errors such as file_server's 405 keep the
site's deferred headers (Caddy drops them); `text/event-stream` is never compressed. Caddy needs the
`caddy-brotli` plugin to read `encode … br`.

## Commands

```bash
web-server run --config /etc/caddy/Caddyfile   # serve (also: --adapter caddyfile is accepted)
web-server validate --config Caddyfile         # parse, compile and load the files, then exit
web-server healthcheck http://127.0.0.1:8080/healthz
```

Environment: `LOG_LEVEL` (`info`; `debug` also via the `debug` global option), `WEB_MAX_MEMORY`,
`WEB_LOG_FLUSH_MS` (10: access log lines are written in batches by a background thread; a full
queue drops lines instead of slowing requests, and they are counted).
Logs are JSON on stderr; access logs go where the site's `log` block says.

## Tests

```bash
# unit + integration (HTTP/1.1 against a stub upstream, SSE timing, TLS with HTTP/2 and HTTP/3)
docker run --rm --network host -v cargo-cache:/cargo -v web-target:/target \
  -e CARGO_HOME=/cargo -e CARGO_TARGET_DIR=/target -v "$PWD/services/web-server:/src:ro" -w /src \
  rust:1-slim-bookworm cargo test --locked

# differential check against Caddy: docker/Caddyfile + the built site (npm run build) served by both,
# ~80 requests (pages, precompressed files, ranges, 304, redirects, proxying, SSE, path tricks)
WEB_SERVER_BIN=/path/to/linux/web-server services/web-server/compat/run.sh
```

## Benchmarks

```bash
# oha at a fixed rate (RATE=1000/s, RUNS=10 × REQUESTS=5000) per scenario — a page, a build asset, a
# redirect — with docker/Caddyfile and the built site; the server's CPU time per request from its
# cgroup; then examples/bench.rs: the handler chain in process (no sockets, no access log) with
# time, CPU time-stamp-counter ticks and heap allocations per request
WEB_SERVER_BIN=… BENCH_BIN=…/examples/bench services/web-server/bench/run.sh <label>

# time from a new connection to the first response over a slow link (tc netem, DELAY_MS=25 on each
# side): HTTP/2 over TCP + TLS, HTTP/3, HTTP/3 with 0-RTT; examples/rtt.rs is the client
WEB_SERVER_BIN=… RTT_BIN=…/examples/rtt services/web-server/bench/rtt.sh
```

On the development host (WSL2, Docker bridge network) most of the CPU time per request is the
kernel's network stack, and there are no hardware performance counters (profiles use `perf record
-e cpu-clock`). Measured 2026-10-14, medians.

Handler chain in process, page `/en/contact` (precompressed br):

| Version                                                                                                                                                                                                         | ns     | TSC ticks | allocations | bytes allocated |
| --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ | --------- | ----------- | --------------- |
| first version                                                                                                                                                                                                   | 10 402 | –         | –           | –               |
| path normalised once, patterns and regexp groups prepared at load, header values built once, `try_files` in one buffer                                                                                          | 5 954  | –         | –           | –               |
| `rewrite` without the decode round trip, FxHash file table                                                                                                                                                      | 5 853  | –         | –           | –               |
| same, measured with the counting allocator                                                                                                                                                                      | 6 370  | 20 303    | 64          | 43 286          |
| one loop for the chain (no future per handler), deferred `header`/`encode` as response hooks, Accept-Encoding parsed once, no copies of path and Host, `'static` header values, connection facts per connection | 3 825  | 12 191    | 29          | 8 922           |
| release profile: one codegen unit, fat LTO                                                                                                                                                                      | 3 997  | 12 740    | 29          | 8 922           |
| mimalloc as the global allocator                                                                                                                                                                                | 3 645  | 11 618    | 29          | 8 922           |
| `Content-Length` and `Content-Type` of every file prepared at load                                                                                                                                              | 3 566  | 11 364    | 26          | 8 874           |

(The allocation counts include building the test request: 6 allocations, 709 bytes. Rows were
measured at different times on the same host; fat LTO alone was within the noise of ±5 % here, its
gain shows under load below.)

Load test, 1000 requests/s, page / asset / redirect:

| Version                                                                          | p50 ms                | p99 ms                | server CPU µs per request |
| -------------------------------------------------------------------------------- | --------------------- | --------------------- | ------------------------- |
| first version                                                                    | 0.252 / 0.251 / 0.240 | 0.943 / 0.972 / 1.031 | 127.5 / 126.8 / 118.5     |
| all of the above, access log written in batches every 10 ms (`WEB_LOG_FLUSH_MS`) | 0.230 / 0.228 / 0.229 | 0.955 / 0.932 / 1.007 | 104.2 / 104.3 / 101.4     |

The access log costs about 5–14 µs of CPU per request even in batches (formatting and the write);
batches of 100 ms gave a higher p99 than 10 ms at the same CPU time.

After a restart of the WSL host this test runs about 50 % slower than in the table above — most
likely the VM's network path, as the in-process numbers did not change — so the next builds were
compared with each other in one sitting, all with SO_REUSEPORT listeners and the per-file headers:

| Build                                  | p50 ms                | p99 ms                | server CPU µs per request |
| -------------------------------------- | --------------------- | --------------------- | ------------------------- |
| thin LTO, system allocator             | 0.391 / 0.387 / 0.377 | 1.641 / 1.550 / 1.685 | 167.9 / 163.5 / 157.2     |
| thin LTO, mimalloc                     | 0.386 / 0.385 / 0.371 | 1.625 / 1.653 / 1.727 | 165.5 / 163.6 / 154.6     |
| fat LTO, one codegen unit, mimalloc    | 0.379 / 0.376 / 0.363 | 2.072 / 1.584 / 1.586 | 160.2 / 154.8 / 147.8     |
| same build, run again after the others | 0.368 / 0.365 / 0.354 | 1.806 / 1.498 / 1.526 | 152.2 / 150.9 / 143.5     |

SO_REUSEPORT (one listener per CPU) against a single listener, thin LTO with the system allocator,
two alternating runs each (`OHA_ARGS=--disable-keepalive` for a new connection per request):

| Listeners                       | p50 ms                | server CPU µs per request |
| ------------------------------- | --------------------- | ------------------------- |
| one, keep-alive connections     | 0.374 / 0.371 / 0.354 | 157.0 / 156.8 / 146.1     |
| one per CPU, keep-alive         | 0.373 / 0.374 / 0.357 | 157.1 / 156.7 / 147.5     |
| one, new connection per request | 0.616 / 0.579 / 0.560 | 234.9 / 216.9 / 204.2     |
| one per CPU, new connection     | 0.592 / 0.580 / 0.557 | 225.1 / 220.6 / 201.2     |

No difference within the noise (the first single-listener page run warmed up slowly): at 1000 new
connections per second a single accept loop is not the bottleneck. What SO_REUSEPORT gives here is
restarts without a gap — a new process binds the port while the old one drains.

New connection to the first response over a 50 ms round trip (`bench/rtt.sh`: `tc netem` 25 ms on
each side, 20 connections, medians):

| Connection                                    | ms    |
| --------------------------------------------- | ----- |
| HTTP/2 over TCP + TLS 1.3, session resumed    | 152.8 |
| HTTP/3, full handshake                        | 102.6 |
| HTTP/3 resumed with 0-RTT (accepted 20 of 20) | 51.6  |
