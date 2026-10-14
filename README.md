# web-server

The static front of the Docker deployment (`web` service): serves the built site from memory and
routes the dynamic paths to the app and the streaming service. It is configured with a **strict subset
of the Caddyfile** — [`docker/Caddyfile`](../../docker/Caddyfile) — so the same file also runs in
Caddy, and the two can be compared request by request ([`compat/`](compat)).

What it adds over Caddy, with no extra directives:

- **Files from memory.** Every site root is read once at startup; requests never touch the disk.
  `WEB_MAX_MEMORY` (default `512MiB`) caps it. A file of up to 1 MiB is kept as an LZ4 block when
  that saves at least `WEB_LZ4_MIN_SAVING` percent (25; `off`: never) — text, in practice: images,
  fonts and the precompressed siblings do not shrink and stay as they are. Only a response that
  sends such a file's bytes as they are (a client without Accept-Encoding, a range of them)
  decompresses it: about 10 µs for a 30–80 KB file (the 1 MiB cap bounds what one request can make
  the server do: `Range: bytes=0-0` decompresses the whole block); browsers get the `.br` / `.zst`
  siblings, and 304s and HEAD need no bytes. The reference site: 30 MiB of files (with their
  siblings) take 19 MiB, 250 of them in LZ4. What is kept lies in one buffer.
- **ETag = hash of the content** (BLAKE3, 80 bits) instead of modification time + size: unchanged
  files keep their ETag across deploys (304 instead of a full response) and every replica sends the
  same one. There is no `Last-Modified`.
- **Brotli on the fly** (`encode zstd br gzip`), besides zstd and gzip. Responses of known length up
  to 1 MiB are compressed whole and sent with `Content-Length`; streams are compressed frame by frame,
  so they still flow.
- **One `Date` for all threads**: a background thread formats it just after each second starts;
  responses take it without reading the clock (a proxied response keeps the upstream's `Date`).
- **Ready answers for files** ([`src/memo.rs`](src/memo.rs)): the files never change while the
  server runs, so when a site's routes decide by the request path alone (no host, method, header or
  address matchers, no `request_header`, only path-derived placeholders — true for
  `docker/Caddyfile`), the answer for every path that serves a file — the 200 with all its headers
  and the 304 for its ETag, for each of the 26 ways Accept-Encoding can rank zstd, br and gzip — is
  worked out at startup by running the real handler chain. A GET or HEAD for such a path is then a
  lookup and a copy of a header map. Ranges, If-Match, another If-None-Match, other spellings of a
  path, files compressed on the fly and everything else take the chain. The reference site: 300 paths,
  1050 distinct answers, 3.8 MB (the bodies are the files' own bytes).
- **Startup on every CPU**: files are read, hashed and compressed, and the answers worked out, on one
  thread per CPU; what is kept is then built on the main thread, so the workers' memory is all given
  back (mimalloc's `mi_collect`). The reference site: about 25 ms for the files and 40–50 ms for the
  answers, 49 MiB resident in all (sequentially it was 60 + 190 ms and 66 MiB; started in parallel
  but with the kept data on the workers, 160 MiB).
- **Compression off the request threads**: an on-the-fly body over 64 KiB is compressed on the
  blocking pool, so a worker thread does not spend milliseconds of Brotli while other requests wait.

Protocols: HTTP/1.1; HTTP/2 over TLS (h2c on request); **HTTP/3** (QUIC, quinn + h3) on the same port
when the site has `tls`, advertised with `Alt-Svc`. TLS is rustls with aws-lc-rs: TLS 1.3/1.2, the
post-quantum key exchange X25519MLKEM768 preferred, ML-DSA certificates accepted. Certificates come
from PEM files and are re-read within a minute when they change — there is no ACME client.

Connections:

- **SO_REUSEPORT**: one listening socket per CPU, each with its own accept loop; the kernel spreads
  new connections over them, and a new process can bind the port while the old one drains.
- **Socket options** ([`src/sockets.rs`](src/sockets.rs), Linux; set on the listening socket and
  inherited by every connection; one the system refuses stays at its default, with a warning at
  startup):
  - congestion control `WEB_TCP_CONGESTION` (`bbr`; `system`: the kernel's default) — BBR keeps its
    pace on long, lossy paths (between continents, mobile) where cubic backs off;
  - `TCP_NOTSENT_LOWAT` 16 KiB: little unsent data waits in the kernel, so HTTP/2 can still send an
    urgent stream (CSS, HTML) before a long one;
  - `TCP_DEFER_ACCEPT`: a connection reaches the server only once it has sent something;
  - `TCP_USER_TIMEOUT` = `WEB_STALL_TIMEOUT` and keepalive (60 s, then 3 probes 10 s apart): the
    kernel ends connections whose peer vanished;
  - listen backlog 4096 (capped at `net.core.somaxconn`);
  - HTTP/3's UDP socket: 4 MiB receive and send buffers (capped at `net.core.rmem_max` / `wmem_max`;
    UDP has no autotuning). quinn adds GSO/GRO, ECN, pacing and path MTU discovery.

  On the host: BBR needs the `tcp_bbr` module and, as the container has no capabilities, to be
  allowed (`net.ipv4.tcp_allowed_congestion_control = reno cubic bbr`, or make it the host's
  default with `net.core.default_qdisc = fq` and `net.ipv4.tcp_congestion_control = bbr`); larger
  UDP buffers need `net.core.rmem_max` / `wmem_max` of at least 4 MiB. `compose.yaml` sets the
  per-container `net.ipv4.tcp_slow_start_after_idle = 0` (a keep-alive connection keeps its
  congestion window across pauses, so the next page does not start slowly) and `net.core.somaxconn`.

- **TLS resumption**: TLS 1.3 session tickets (keys live in the process, so a restart or another
  replica means a full handshake), and a cache of 16 384 sessions for resumption by ID.
- **HTTP/3 0-RTT**: a resumed QUIC client sends its first request with the handshake. Early requests
  are answered only for GET, HEAD and OPTIONS (they change nothing if an attacker replays them) and
  reach the handler with `Early-Data: 1`; anything else gets `425 Too Early` and the browser repeats
  it after the handshake (RFC 8470). TCP does not take early data.

What keeps one client from holding the server ([`src/guard.rs`](src/guard.rs),
[`src/h3limit.rs`](src/h3limit.rs)):

| Threat                                                | Limit                                                                                                                                                             |
| ----------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Many connections (one address, or many)               | `WEB_MAX_CONNECTIONS_PER_IP` (256; an IPv6 /64 is one address; trusted proxies exempt) and `WEB_MAX_CONNECTIONS` (16 384), TCP and QUIC together: refused at once |
| Slowloris: headers sent byte by byte                  | `timeouts { read_header }` (30 s) for the whole header block; the TLS handshake gets 10 s                                                                         |
| Connections opened and left silent                    | HTTP/2 and HTTP/3 must send their first request within `read_header` (HTTP/1.1 already must)                                                                      |
| Idle keep-alive connections                           | `timeouts { idle }` (5 min, Caddy's default) with no request in progress: graceful close (GOAWAY); one that has not finished 10 s later is cut                    |
| Slow reader: a response the client stops taking       | `WEB_STALL_TIMEOUT` (30 s) with the socket accepting nothing (HTTP/3: the stream) cuts the connection; a slow but moving download is fine                         |
| Slow sender: a request body the client stops sending  | `WEB_STALL_TIMEOUT` with no body data arriving ends the body; the proxy answers 408 and the upstream connection is freed                                           |
| Hung upstream (headers never come)                    | `reverse_proxy` `response_header_timeout`, 60 s by default here (Caddy: none; `0` restores that): 504                                                             |
| Range header asking for thousands of parts            | more than 64 ranges, or overlapping ones, are ignored and the whole file is sent (200), as Go does for ranges adding up to more than the file                     |
| Redirect targets built from the path                  | `redir` and the canonical trailing-slash redirect turn a leading `//host` or `/\host` into `/host`, so no path can send a browser off the site                   |
| Headers an upstream trusts for the client's identity  | `X-Real-IP`, `CF-Connecting-IP`, `CF-IPCountry`, `Forwarded`, … are dropped unless the peer is a trusted proxy (src/proxy.rs `CLIENT_IDENTITY_HEADERS`)           |
| HTTP/3 headers of any size (h3 buffers a frame whole) | frames other than DATA over 64 KiB end the stream (`H3_EXCESSIVE_LOAD`), also on the control and QPACK streams; `SETTINGS_MAX_FIELD_SECTION_SIZE` 64 KiB          |
| QUIC handshake floods from spoofed addresses          | with 64 handshakes under way, unproven addresses get a Retry first; at most 4096 handshakes queued, 32 MB of their packets                                        |
| HTTP/2 Rapid Reset, CONTINUATION flood, MadeYouReset  | h2 0.4.20; 250 streams per connection, 16 KiB of headers                                                                                                          |

## Configuration subset

| Kind           | Supported                                                                                                                                                                                                                                                         |
| -------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Syntax         | blocks, quotes and backticks, comments, `\` line continuation, `{$ENV}` / `{$ENV:default}`, snippets `(name)`, `import <snippet>` / `import <file or glob>`                                                                                                       |
| Global options | `auto_https off`, `admin off`, `http_port`, `https_port`, `grace_period`, `debug`, `order`, `servers [:port] { trusted_proxies static …, trusted_proxies_strict, client_ip_headers, protocols, timeouts { read_header, idle } }`                                  |
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
site's deferred headers (Caddy drops them); `text/event-stream` is never compressed; the limits in the
table above that Caddy does not have — `response_header_timeout` 60 s by default, 408 for a stalled
request body, at most 64 non-overlapping ranges, redirect targets kept on the site, client identity
headers dropped from untrusted peers. Caddy needs the `caddy-brotli` plugin to read `encode … br`.

## Commands

```bash
web-server run --config /etc/caddy/Caddyfile   # serve (also: --adapter caddyfile is accepted)
web-server validate --config Caddyfile         # parse, compile and load the files, then exit
web-server healthcheck http://127.0.0.1:8080/healthz
```

Environment: `LOG_LEVEL` (`info`; `debug` also via the `debug` global option), `WEB_MAX_MEMORY`,
`WEB_LOG_FLUSH_MS` (10: access log lines are written in batches by a background thread; a full
queue drops lines instead of slowing requests, and they are counted), `WEB_LZ4_MIN_SAVING` (25),
`WEB_MAX_CONNECTIONS`
(16384), `WEB_MAX_CONNECTIONS_PER_IP` (256; 0 turns a limit off), `WEB_STALL_TIMEOUT` (30s),
`WEB_TCP_CONGESTION` (`bbr`).
Logs are JSON on stderr; access logs go where the site's `log` block says.

At startup the log says what was loaded and what it cost — per site root `site files loaded`
(files, bytes, bytes in memory, files in LZ4, ms), per site `ready answers for the site's files` (paths, distinct answers, their
memory, ms; or why there are none), and one summary:

```json
{
  "message": "started",
  "ports": 1,
  "files": 1000,
  "files_mib": 30.0,
  "files_in_memory_mib": 19.0,
  "lz4_files": 250,
  "ready_paths": 300,
  "ready_answers": 1050,
  "ready_mib": 3.8,
  "ready_ms": 51,
  "resident_mib": 48.5,
  "startup_ms": 141
}
```

`web-server validate` prints the same for the files: `valid configuration: 1 port(s), 1 site(s),
1000 files (30 MiB; 19 MiB in memory, 250 in LZ4), loaded in 92 ms`.

## Tests

```bash
# unit + integration (HTTP/1.1 against a stub upstream, SSE timing, TLS with HTTP/2 and HTTP/3,
# ready answers against the chain, slow readers, idle HTTP/2, connection limits, oversized HTTP/3
# header frames)
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

304 for the same page (`304:/en/contact`, If-None-Match with its ETag): 3 829–3 956 ns and 28
allocations, against 3 580–3 615 ns and 24 once the ETag comparison stopped copying strings, the
`encode` suffix check stopped formatting, and the 304 was answered before `Content-Type` and
`Content-Encoding` were set — now no dearer than the 200.

Through a socket, one request at a time, the access log shows 6–12 µs per request back to back and
22–33 µs after a second of idle (CPU caches and TLB gone cold under the VM), whatever the handler:
`/healthz` costs as much as a page. The first file request after another kind of request pays most
of it — with `/healthz`, 304, 200 in turn the 304 looked 9 µs slower than the 200, and the other way
round when the order was swapped. Caddy, same Caddyfile and requests: 40–255 µs.

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

Ready answers (`BENCH_CHAIN=1` makes `examples/bench.rs` take the chain for comparison), same binary:

| Request                         | through the chain   | ready answer      |
| ------------------------------- | ------------------- | ----------------- |
| page, in process                | 3 639 ns, 26 allocs | 883 ns, 10 allocs |
| 304 for it, in process          | 3 607 ns, 24 allocs | 853 ns, 8 allocs  |
| build asset, in process         | 3 281 ns, 26 allocs | 888 ns, 10 allocs |
| page via socket, back to back   | 11–12 µs            | 4.0–4.3 µs        |
| page via socket, after 1 s idle | 26–36 µs            | 9–12 µs           |
| 304 via socket, back to back    | 11–12 µs            | 3.5–3.9 µs        |
| 304 via socket, after 1 s idle  | 24–34 µs            | 9–10 µs           |

Files kept in LZ4, in process (`identity:` requests send the file's own bytes), same binary:

| Request                                     | `WEB_LZ4_MIN_SAVING=off` | 25 (default)                                             |
| ------------------------------------------- | ------------------------ | -------------------------------------------------------- |
| page without Accept-Encoding (77 KB)        | 0.72 µs                  | 11.7 µs (decompressed)                                   |
| build asset without Accept-Encoding (32 KB) | 0.72 µs                  | 9.9 µs                                                   |
| page as br; its 304                         | 0.91 µs; 0.85 µs         | the same (a .br sibling does not shrink, stays as it is) |
| files in memory; process resident           | 30 MiB; 78.2 MiB       | 19 MiB; 65.9 MiB                                       |
| loading the files                           | 28 ms                    | 61 ms (compressing, checking every block once)           |

(Allocations include the 6 of building the test request. Through a socket: the access log's
`duration`, one request at a time.) Under load (1000 requests/s) a page and an asset now cost 134–136
µs of server CPU against 146 for the redirect, which still takes the chain; before, the page cost
about 6 µs more than the redirect.
