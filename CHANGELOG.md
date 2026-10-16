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
