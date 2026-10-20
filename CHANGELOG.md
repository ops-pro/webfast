# Changelog

## Unreleased

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
  several is as many servers. Upstream names are resolved at start (one that does not resolve
  stops it) and refreshed in the background at their TTL (`WEB_DNS_*`, `transport http {
  resolvers }`); a request never waits for DNS (docs/dns.md). A `reverse_proxy` with one literal
  address pays nothing for any of this.

- Requests read the compressed variants from a snapshot (`ArcSwap`) instead of under a `RwLock`;
  the proxy cache hashes its keys with ahash (keyed per process) instead of SipHash.
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
