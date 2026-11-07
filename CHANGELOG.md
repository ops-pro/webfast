# Changelog

## Unreleased

- The repository is a Cargo workspace: `crates/webfast-core` (the server as a library,
  `webfast_core`) and `crates/webfast` (the binary: `main.rs` and `compose.rs`, which names the
  modules it is built with). The request filter (NGFW) and the browser challenge moved to
  https://github.com/ops-pro/webfast-modules as the crates `webfast-ngfw` and `webfast-challenge`,
  with their documentation and changelog; this binary composes none yet. `cargo build --release`
  at the root still yields `target/release/webfast`; `Cargo.lock` stays at the root; the release
  profiles and the dependency versions are the workspace's. The checks run on both crates
  (`scripts/check.sh`, CI).
- A module API (`webfast_core::module`, docs/modules.md): the core knows no module by name. A
  module is a crate against the core's public API — a `Module` the binary registers (its
  directives with their place in the directive order, its environment, its files into
  `Config::modules`, its lines for `validate`, its reload), route handlers
  (`Handler::Extension`), request checks (`Check`: the head decides synchronously, a boxed
  future only for a body) and inspectors of proxied responses (`Inspect`) — composed in the
  binary's `compose.rs` as tuples the core calls through one `&'static dyn` per kind. A clean
  request allocates nothing more than before. The request filter and the browser challenge are
  written on it, with `webfast_core::` paths alone, and their tests on the core's test harness
  (`webfast_core::harness`, cargo feature `test-harness`). What the modules needed of the core
  became public: the directive parser's types and helpers (`config::{Cx, Scope, SiteCx, Entry,
  entry, matcher_token, add_matcher, at_err, token_err}`), `guard::address_key`,
  `proxy::remove_lookalikes`, `accesslog::json_escape`; `eventlog` and `yaml` are always built,
  the HTTPS client is the core's `fetch` feature.

## 0.1.2 — 2026-11-06

Fewer allocations on the request path, buffers sized once where their size is known, and bounds
where a client chose them: range answers, compression, the proxy's headers, placeholders, rate
limit keys, path cleaning, the API firewall's query strings and forms.

Worth knowing when upgrading from 0.1.1:

- The API firewall reads at most 1000 pairs of a query string or form body; more is a violation
  (`request-query:too-many`, or the body's reason), 403 in `block`.

- A `multipart/byteranges` answer is built in one buffer of its final size, without a string per
  part (the same bytes as before).
- Compressed variants (`compress_best`, the whole-body path of `encode`) and decoded cache bodies
  hold their length, no more: a Bytes kept the Vec's capacity, up to twice the length the memory
  budgets count. Checking an upstream's encoded variant decodes it at most to its identity's
  length (it was up to `max_cacheable_body_bytes`).
- Placeholders write their values into the rendered text in place; a `rate_limit` zone keyed by
  a template hashes it from a buffer the thread keeps.
- `X-Forwarded-For/-Proto/-Host`, `handle_path`, path cleaning, `encode { match }` content types,
  the JWT claim headers, the access log line and a `Location` with control characters are built
  without intermediate strings.
- The API firewall decodes a query string or form in one pass and counts its pairs first (a
  1 MB body of `a&a&…` was a million allocations and 51 MB); a body's buffer reserves at most
  64 KiB of what `Content-Length` declares; a `Range` header keeps at most one range past the 64
  it may have.

Measured in process (a single-threaded runtime pinned to one core, Linux, the release profile,
mimalloc with a counting allocator), the mean of two runs of each build, per request or call:

| Case                                                   | 0.1.1    | 0.1.2          | Allocations   | Reallocations | Allocated         |
| ------------------------------------------------------ | -------- | -------------- | ------------- | ------------- | ----------------- |
| Range, 8 × 64 KiB (multipart)                          | 67.8 µs  | 18.2 µs        | 58 → 25       | 53 → 4        | 2.05 MB → 537 KB  |
| Range, 2 × 100 B (multipart)                           | 4.3 µs   | 3.3 µs         | 34 → 25       | 18 → 2        | 13.8 → 11.3 KB    |
| Range, 1500 ranges (the whole file is sent)            | 53 µs    | 56 µs ¹        | 15 → 15       | 9 → 5         | 75.5 → 14.1 KB    |
| `rate_limit`, key `{remote_host}-{header.X-Api-Key}`   | 1.95 µs  | 1.75 µs        | 20 → 16       | 2 → 0         | 8.3 → 8.1 KB      |
| Proxy, 8 KiB, identity                                 | 19.1 µs  | 18.9 µs        | 53 → 49       | 2 → 2         | =                 |
| Proxy, 8 KiB, gzip                                     | 104 µs   | 102 µs ²       | 70 → 66       | 4 → 2         | +1 KB             |
| Proxy, 8 KiB, gzip, `match` types without `*`          | 110 µs   | 106 µs         | 74 → 67       | 7 → 2         | +1 KB             |
| Proxy, 8 KiB, br                                       | 113 µs ² | 113 µs         | 89 → 86       | 2 → 2         | +2.8 KB           |
| Proxy, chunked 16 × 4 KiB, gzip / br / zstd            | =        | =              | −4 each       | =             | =                 |
| `handle_path`                                          | 1.7 µs   | 1.7 µs         | 18 → 17       | 0 → 0         | =                 |
| `compressible("text/html; charset=utf-8")`             | 170 ns   | 73 ns          | 0 → 0         | 0 → 0         | 0                 |
| Path cleaning, `/a/./b//c/../d/e/f/`                   | 124 ns   | 80 ns          | 2 → 1         | 1 → 0         | 211 → 21 B        |
| Placeholders, `{scheme}://{host}{uri}`                 | 215 ns   | 85 ns          | 4 → 1         | 2 → 0         | 134 → 75 B        |
| Placeholders, `{method} {uri} {client_ip}`             | 244 ns   | 100 ns         | 4 → 1         | 2 → 0         | 175 → 74 B        |
| Placeholders, `{remote_host}-{header.X-Api-Key}`       | 255 ns   | 110 ns         | 4 → 1         | 2 → 0         | 146 → 49 B        |
| API firewall, a query string of 7 pairs                | 1.05 µs  | 650 ns         | 29 → 15       | 1 → 0         | 706 → 401 B       |
| API firewall, a 1 MB form body of `a&a&…`              | 44 ms    | 1.4 ms (a 403) | 1 000 000 → 0 | 17 → 0        | 51.3 MB → 0       |
| A 256 KiB variant, held (gzip / zstd / br)             | =        | =              | =             | 2 / 1 / 3 → 0 | 48.5 / 44.1 / 32.8 → 24.3 / 22.0 / 22.6 KB |

¹ The same loop with one comparison more: between builds it is 5 % slower or 10 % faster, as the
code is laid out; the memory is what changed.

² Without one run's outlier (119 µs, 164 µs); the other run and earlier ones agree.

## 0.1.1 — 2026-11-06

Automatic certificates (ACME, with ARI renewal windows), load balancing over several upstreams,
a Caddy-compatible image, error pages, reloads without dropped connections, compression
dictionaries, rate limits, a proxy cache, JWT and OpenAPI checks at the edge, and the hardening
Caddy 2.11.4–2.11.9 brought that applies here (look-alike headers, a header size limit, Host
checks, `Incremental`).

Worth knowing when upgrading from 0.1.0:

- Rust 1.89 or later builds it (serde-saphyr).
- Request headers over 16 KiB get 431 on every protocol (`servers { max_header_size }`).
- A Host that names no host, two Hosts, or a Host for another host than the `:authority` get 400.
- Request headers spelled like a trusted one with `_` or `.` (`X_User`, `X_Real_IP`) are dropped.
- In the JWT and API firewall YAML files a mapping key `~` (null) is an error.

- A response with `Incremental: ?1` (RFC 10036, the standard form of NGINX's
  `X-Accel-Buffering: no`, as Caddy 2.11.7) is neither compressed by `encode` nor kept by `cache`,
  as an event stream: a body of known length was compressed whole, so it reached the client only
  at its end. The proxy already passed every response on as it came.

- A request whose Host names no host is answered 400 before the routes (as Caddy 2.11.8): dots
  only (`..`), a `/` or `\`, user information, a port that is not a number, characters no host
  name has; so are two Host headers, and a Host for another host than HTTP/2's or HTTP/3's
  `:authority` (or an HTTP/1.1 absolute target), which a proxy and the app behind it could each
  read their own way (Caddy 2.11.9). The authority is now the one used where both are sent; it
  was the Host. HTTP/1.1 closes the connection after a 400 or 431 of this kind.

- Request headers are limited to 16 KiB on every protocol (`servers { max_header_size <size> }`,
  1 KiB to 1 MiB, as Caddy 2.11.6): more is 431. HTTP/2 had hyper's 16 KiB already; HTTP/3 took
  up to 64 KiB, HTTP/1.1 up to hyper's ~400 KiB buffer. Each field counts its name, its value and
  32 bytes, as HTTP/2 and HTTP/3 count it.

- Request headers spelled like a header the server sets or trusts, but with `_` or `.` for a `-`
  (`X_User`, `X.Forwarded.For`, `X_Real_IP`), are taken off before the request goes upstream. PHP,
  CGI, WSGI and Rack read them as the same variable (`HTTP_X_USER`), so a client could pass one
  for a JWT claim header (even without a token, on an `allow_missing` rule) or for its own
  address. Kept: every other header with `_` or `.` (Caddy 2.11.4 and 2.11.6 drop them all).

- The JWT and API firewall files and OpenAPI specs in YAML are read with serde-saphyr (pure Rust)
  instead of serde_yaml_ng, whose libyaml port (unsafe-libyaml) is unmaintained
  (RUSTSEC-2024-0449); read as before (YAML 1.2 booleans, the last of a repeated key, `<<` an
  ordinary key), errors on one line without the file's text. A mapping key `~` is now an error.
  Reading a spec takes a quarter of the allocations and 40 % of the peak memory, and half as much
  time again (the GitHub REST API's, 10 MB: 356 ms against 236).
  The minimum Rust version is 1.89 (serde-saphyr's).

- Automatic certificates are renewed in the window the CA suggests (ARI, RFC 9773): asked at
  start, at a reload and as often as the CA's `Retry-After` says, a point of the window chosen at
  random; a certificate the CA revoked is renewed at once, and the order names the certificate it
  replaces. Two thirds of the life as before when the CA has no ARI or cannot be reached. A reload
  now looks at every managed host at once (a host in back-off keeps it).

- A Caddy-compatible image (`Dockerfile` target `caddy`, the `-caddy` tags): the same binary in
  the layout of the official `caddy` image (`/usr/bin/caddy`, `/etc/caddy/Caddyfile`,
  `/usr/share/caddy`, `/data`, `/config`, ports 80 and 443), so a Compose file changes only its
  image line. The commands take `caddy`'s names and flags: `reload` (checks the file, then SIGHUP
  to the server; `--pid` outside a container), `--envfile`, `--adapter caddyfile`, `--watch`.
  The README now says what the server is for: the static front end with an application behind
  it, as a drop-in for Caddy there.

- Automatic certificates (cargo feature `acme`, on by default; docs/acme.md): a site with a host
  name and no `tls` files gets its certificate from an ACME CA (Let's Encrypt, or `acme_ca`) by
  HTTP-01 or TLS-ALPN-01, renewed at two thirds of its life by a background thread, kept under
  `WEB_ACME_DIR` (`/data/acme`; the image has a `/data` volume); `email`, `tls <email>`,
  `acme_ca_root`, and `auto_https off | disable_redirects | disable_certs` as in Caddy, with the
  HTTP to HTTPS redirect on `http_port`. The challenges are answered before any route; nothing
  of it runs on a request. Not done: DNS-01 (wildcards), `tls internal`, `tls { … }` blocks.
- `reverse_proxy` balances over several upstreams with Caddy's words: every `lb_policy`
  (`random_choose`, `weighted_round_robin`, `least_conn`, the hashes, `cookie`), `lb_retries`,
  passive health (`fail_duration`, `max_fails`, `unhealthy_status`, `unhealthy_latency`,
  `unhealthy_request_count`), 503 with every server down. The unit is an address: a name with
  several is as many servers. Upstream names are resolved at start (one that does not resolve yet
  answers 502 until it does) and refreshed in the background at their TTL (`WEB_DNS_*`, `transport http {
  resolvers }`); a request never waits for DNS (docs/dns.md). A `reverse_proxy` with one literal
  address pays nothing for any of this.

- Requests read the compressed variants from a snapshot (`ArcSwap`) instead of under a `RwLock`;
  the proxy cache hashes its keys with ahash (keyed per process) instead of SipHash.
- The static musl build reads the clock through the vDSO on arm64 too: musl looks vDSO functions
  up only by DT_HASH, which the arm64 vDSO of recent kernels (6.12) no longer has, so every clock
  read — tokio's and hyper's timers, the access log, about eight per request — was a system call.
  The binary now finds `clock_gettime` by DT_GNU_HASH or DT_HASH itself (`src/vdso.rs`).
- Ready answers for redirects: a `redir` whose target is made of the path alone (`{re.html.1}`,
  `{path}/`) is prepared with the site's files, for their `.html` paths and their directories
  without the slash; the `.html` redirect is a table lookup instead of the whole chain (on a 4-core
  Neoverse-N1, 67k → 94k requests per second). A target with `{query}`, `{host}` or other request
  placeholders still takes the chain.
- ETags are 8 characters of base64url (48 bits of the BLAKE3 hash) instead of 20 of hex; a
  representation `encode` makes on the fly gets a ninth character (`b`, `g`, `z`) instead of
  `-br` / `-gzip` / `-zstd`, a `dcz` delta `d` and 8 characters of its dictionary's hash, an
  upstream's ETag `.` and the letter. Files served from disk use the same form. After the
  upgrade every conditional request misses once (the ETags clients hold are of the old form).
  Compressed variants are keyed by the file's SHA-256, not its ETag.
- Extensions (docs/extensions.md): the optional pieces plug into the core through hook traits
  composed at compile time (`src/extensions.rs`), with nothing on the request path for a feature
  that is off and a direct call for one that is on; one `Worker` and one `Budget`
  (`src/background.rs`) for their background threads and bounded memory. No change in behaviour;
  the chain benchmark and the allocations per request are the same.
- Compressed variants: a compressible file without a `.br`, `.zst` or `.gz` sibling gets one made
  in the background when it is first asked for (cargo feature `compress-files`), at the highest
  level, then answered like a sibling (its own ETag, 304s, ranges, ready answers). Bounded by
  `WEB_COMPRESSED_FILES_MEMORY` (64 MiB; CLOCK eviction); a variant goes with its file.
- Request checks, each a cargo feature on by default and used only when its YAML file is named:
  JWT validation (`WEB_JWT_CONFIG`, after Istio's RequestAuthentication: providers with JWKS by
  URL, inline or file, rules by host, path and method, verified tokens cached) and OpenAPI request
  validation (`WEB_API_FIREWALL_CONFIG`, after Wallarm API Firewall: the spec compiled once,
  parameters, bodies and security requirements checked). A rule or an API can be bound to an
  upstream (`upstreams: [app:8787]`): it then covers what the routes send there, checked by the
  `reverse_proxy` before anything is sent, and by `cache` before a stored answer is given; an
  upstream no `reverse_proxy` sends to stops the startup, and a reload. `mode: log_only` lets
  failures through and writes them down; `log: { output }` gives each module an event log of its
  own, without tokens or the values that failed a schema. An API's spec can come from a URL or a
  path of the server itself, looked at again with conditional requests (`refresh`, `ttl`).
- `cache` keeps the answer to a request whose JWT was verified only when the answer says it may be
  shared, as for a request with `Authorization`.
- TLS: several certificates per site (`tls` repeated; each client gets the first it can verify),
  certificate compression (RFC 8879), `WEB_TLS_STRICT_SNI=on` (no certificate without SNI or for a
  name no site names), and 421 for a Host served with another certificate than the connection's
  (`strict_sni_host`, on by default; RFC 9110 §15.5.20).
- `request_body { max_size }`: 413 before the upstream is called for a body over the limit.
- Redirects built from the path stay on the site also with a tab or a newline between the slashes.
- WebSocket through `reverse_proxy`: a `Connection: upgrade` handshake over HTTP/1.1 goes to the
  upstream, and its 101 joins the two connections into a tunnel. Tunnels count against the
  connection limits and close when the server stops.
- `handle_errors [<status codes>]` and `error`: error pages, as in Caddy. A failed request
  (file_server's 404 and 405, the proxy's 502 and 504, `error`) is answered by the site's error
  routes, with `{err.status_code}`, `{err.status_text}` and `{err.message}`; checked against Caddy
  by a second compat scenario (`SCENARIO=errors`). The static-site recipe serves the build's
  404.html.
- SIGHUP reloads the Caddyfile without dropping a connection: sites, trusted proxies, client IP
  headers, certificates and the grace period are replaced; site roots that stay are taken over;
  what needs a restart (ports, TLS on or off, protocols, timeouts) is refused, as is anything that
  fails, and the running configuration stays. The systemd recipe has `ExecReload` (validate, then
  SIGHUP). `WEB_RELOAD` says what open connections get: `immediate` (the default), the new
  configuration for their next request; `lazy`, the one they were accepted with, for as long as
  they stay open; `drain`, as lazy, and each is closed gracefully at a moment drawn at random
  within `WEB_RELOAD_DRAIN` (60 s), so that clients reconnect spread over it.
- Compression dictionaries (RFC 9842): a file marked with `Use-As-Dictionary` is a dictionary
  for the files its pattern names, and a browser that holds it (or a version a deploy replaced)
  gets them as `dcz` deltas — checked in Chromium. `dcb` is not offered.
- Files over `WEB_MAX_FILE_IN_MEMORY` (16 MiB; `off`: all in memory) are streamed from disk,
  64 KiB at a time, instead of being held in memory: their ETag from size and modification time,
  checked on each response; conditional requests and one range; no ready answers; nothing of
  `WEB_MAX_MEMORY`.
- `respond 103`: Early Hints, as in Caddy — the headers set so far go out as an interim response
  and the chain goes on. Sent over HTTP/3; over HTTP/1.1 and HTTP/2 (hyper sends no interim
  responses) the headers come with the final response.
- `rate_limit` (cargo feature `rate-limit`, on by default), in the syntax of Caddy's
  caddy-ratelimit plugin: zones of a matcher, a key (`{client_ip}`, any placeholder, `static`;
  `ipv4_prefix`, `ipv6_prefix`), `events` and `window`; `jitter`, `sweep_interval`,
  `log_key`. Each zone is a GCRA in 64 shards with keyed hashes; the tightest zone exceeded
  refuses with 429 and `Retry-After`, which `handle_errors 429` can answer
  (`{http.rate_limit.exceeded.name}`). Refused requests are logged as a summary per zone;
  `WEB_RATE_LIMIT_KEYS` (a million) bounds the keys of a zone, `WEB_RATE_LIMIT_DRY_RUN` only
  counts. The counts outlive a reload; the paths no zone takes keep their ready answers. Checked
  against Caddy with the plugin (`SCENARIO=ratelimit`).
- With the same feature, `WEB_MAX_UPSTREAM_REQUESTS_PER_IP` (256): a client's requests at the
  upstreams at once, a response counting until its body ends; more are refused with 429. Behind a
  trusted proxy, the client it names; the proxy's own requests are not limited.
- `cache` (cargo feature `proxy-cache`, on by default), in the syntax of Caddy's cache-handler
  plugin (the global option and the directive; `ttl`, `stale`, `default_cache_control`,
  `max_cacheable_body_bytes`, `cache_name`, `regex { exclude }`, `mode strict`): proxied GET
  200 answers kept in memory (`WEB_PROXY_CACHE_MEMORY`, 64 MiB). The first client is answered as
  the upstream sends; a tee keeps the frames, and a background thread decides, decodes (bounded),
  asks an encoding upstream for its other encodings and makes the rest at the highest levels.
  Hits come from memory in the best encoding the client takes, with Age, Cache-Status and 304s;
  stale answers while a conditional request revalidates them, and when the upstream fails.
  Checked against Caddy with the plugin (`SCENARIO=cache`).
- An HTTP/3 connection asked to finish (idle, or drained) with no request left is closed at once
  after its GOAWAY, not 10 s later.
- Per request, only the connection's own reference counts change: the port's state and the
  WebSocket bookkeeping (the server's stop signal) are held once per connection.
- Header values with bytes outside visible ASCII no longer stop the startup with a panic.

## 0.1.0 — 2026-10-15

The first version as a project of its own (its history before that is kept: it began as the static
front of a site's Docker deployment).

- A strict subset of the Caddyfile (docs/configuration.md); anything else stops the startup with
  the file and line. Checked against Caddy request by request (`compat/`).
- Sites from memory: content-hash ETags (BLAKE3), precompressed `.br`/`.zst`/`.gz` siblings, LZ4
  for text in memory, ready answers for every file path.
- Changed files picked up while running: inotify on local filesystems, polling elsewhere
  (`WEB_FILES_WATCH`, `WEB_FILES_POLL`); snapshots replaced whole.
- On-the-fly zstd, Brotli and gzip; `reverse_proxy` to plain-HTTP upstreams with streaming (SSE).
- HTTP/1.1, HTTP/2 (TLS; h2c on request), HTTP/3 with 0-RTT for safe methods; rustls on aws-lc-rs
  with the post-quantum key exchange preferred; certificates re-read when renewed.
- A runtime per core with SO_REUSEPORT listeners; `WEB_WORKERS`, `WEB_RUNTIME`.
- Limits against slow and greedy clients (docs/operations.md, Limits); tuned sockets (BBR,
  `TCP_NOTSENT_LOWAT`, `TCP_DEFER_ACCEPT`, `TCP_USER_TIMEOUT`, UDP buffers).
- A Docker image built with profile-guided optimisation, trained on a sample site of its own.
- Recipes for common setups (static site, single-page app, a site in front of an application with
  docker-compose.yml, behind nginx, HTTPS and HTTP/3 directly, a systemd service), checked by the
  tests; a security policy (SECURITY.md).
- Licensed under MIT or Apache-2.0, at your option.
- Renamed from `web-server`: the crate, library and binary are `webfast`, the image's
  configuration is `/etc/webfast/Caddyfile`; the environment variables keep their `WEB_` names;
  the minimum Rust version is 1.88 (it said 1.85, but let chains need 1.88).
