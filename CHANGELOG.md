# Changelog

## Unreleased

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
