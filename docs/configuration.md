# Configuration

webfast reads a Caddyfile — a strict subset of Caddy's: what it accepts, Caddy reads the same way,
so a site can move between the two, and [`compat/`](../compat) checks that both answer ~80 kinds of
request alike. Anything outside the subset — an unknown directive, option, matcher or placeholder —
stops the server at startup with the file and line, instead of being ignored.

[`sample/Caddyfile`](../sample/Caddyfile) is a complete example: a static site with precompressed
siblings, an application behind it for the dynamic paths, and an event-streaming service. The
Docker image starts with it.

## The subset

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

Semantics follow Caddy: the directive order and path-specificity sorting outside `route`, mutually
exclusive `handle` blocks, deferred `header` operations, `try_files` matching directories only for
patterns ending in `/`, canonical trailing slashes, the empty 200 at the end of a chain. Sites are
chosen by host: exact names first, then wildcards, then the catch-all; a host no site serves gets
an empty 200, as in Caddy.

Files are served from memory, so a site that uses `file_server` or the `file` matcher needs an
explicit `root * <dir>` (the files are loaded from it at startup).

`reverse_proxy` passes WebSocket (any `Connection: upgrade` request over HTTP/1.1) with nothing to
configure: the handshake goes to the upstream with the same `header_up` and forwarded headers as
any request, and when the upstream answers 101 the two connections are joined and copied both ways
until either side closes. Any other answer reaches the client as it is. Browsers open WebSocket
over HTTP/1.1 (webfast does not offer it over HTTP/2, RFC 8441), so keep `h1` in `protocols`.

## Differences from Caddy

All of them are checked by `compat/`:

- ETags are hashes of the content (BLAKE3, 80 bits), not modification time and size; there is no
  `Last-Modified`.
- Proxied responses get no `Via`; the upstream gets the client's `Accept-Encoding` as it is (Caddy's
  transport asks for gzip when the client sent none).
- Handler errors such as `file_server`'s 405 keep the site's deferred headers (Caddy drops them).
- `text/event-stream` is never compressed.
- Limits Caddy does not have (docs/operations.md, Limits): `response_header_timeout` 60 s by
  default (`0` restores Caddy's none), 408 for a request body the client stops sending, at most 64
  non-overlapping ranges, redirect targets kept on the site, client identity headers
  (`X-Real-IP`, `CF-Connecting-IP`, `Forwarded`, …) dropped from untrusted peers.
- A WebSocket tunnel keeps the place of the connection it came from, so it counts against the
  connection limits; it has no idle limit, and closes when the server stops (Caddy's default,
  `stream_close_delay 0`). `stream_timeout` and `stream_close_delay` are not supported.
- Brotli on the fly is built in; Caddy needs the `caddy-brotli` plugin to read `encode … br`.
- No automatic certificates (ACME): `tls` takes PEM files, which are re-read when they change.

## Environment

| Variable                     | Default    | What it sets                                                                                                                                  |
| ---------------------------- | ---------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| `LOG_LEVEL`                  | `info`     | the server's own log (JSON on stderr); `debug` also via the `debug` global option                                                             |
| `WEB_MAX_MEMORY`             | `512MiB`   | what the site files may take in memory, over all roots; a site that does not fit stops the startup, a change that does not fit is not taken   |
| `WEB_LZ4_MIN_SAVING`         | `25`       | a file of up to 1 MiB is kept as an LZ4 block when that saves at least this many percent; `off`: never                                        |
| `WEB_FILES_WATCH`            | `auto`     | changed files picked up: `auto` (inotify on a local filesystem, polling elsewhere), `inotify`, `poll`, `off` (the files as loaded at startup) |
| `WEB_FILES_POLL`             | `30s`      | how often a polled root is looked at again                                                                                                    |
| `WEB_WORKERS`                | `auto`     | threads serving connections, 1–1024 (`auto`: one per CPU the process may use, at most 64 — a container's CPU limit counts)                    |
| `WEB_RUNTIME`                | `per-core` | `per-core`: a thread with its own runtime per listening socket (Unix); `shared`: one multi-threaded runtime for all connections               |
| `WEB_MAX_CONNECTIONS`        | `16384`    | open connections, TCP and QUIC together; `0`: no limit                                                                                        |
| `WEB_MAX_CONNECTIONS_PER_IP` | `256`      | open connections per client address (an IPv6 /64 is one; trusted proxies are exempt); `0`: no limit                                           |
| `WEB_STALL_TIMEOUT`          | `30s`      | a response the client stops taking, or a request body it stops sending, for this long ends it                                                 |
| `WEB_TCP_CONGESTION`         | `bbr`      | TCP congestion control for the clients' connections; `system`: the kernel's default                                                           |
| `WEB_LOG_FLUSH_MS`           | `10`       | access log lines are written in batches this often by a background thread; a full queue drops lines (counted) instead of slowing requests     |

Durations are written as in the Caddyfile (`500ms`, `30s`, `5m`); sizes as `512MiB`, `1G` or bytes.
A value that does not parse stops the server at startup.
