# Configuration

webfast reads a Caddyfile — a strict subset of Caddy's: what it accepts, Caddy reads the same way,
so a site can move between the two, and [`compat/`](../compat) checks that both answer ~80 kinds of
request alike. Anything outside the subset — an unknown directive, option, matcher or placeholder —
stops the server at startup with the file and line, instead of being ignored.

[`sample/Caddyfile`](../sample/Caddyfile) is a complete example: a static site with precompressed
siblings, an application behind it for the dynamic paths, and an event-streaming service. The
Docker image starts with it.

## The subset

| Kind           | Supported                                                                                                                                                                                                                                                                                                                                      |
| -------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Syntax         | blocks, quotes and backticks, comments, `\` line continuation, `{$ENV}` / `{$ENV:default}`, snippets `(name)`, `import <snippet>` / `import <file or glob>`                                                                                                                                                                                    |
| Global options | `auto_https off`, `admin off`, `http_port`, `https_port`, `grace_period`, `debug`, `order`, `servers [:port] { trusted_proxies static …, trusted_proxies_strict, client_ip_headers, protocols, timeouts { read_header, idle } }`                                                                                                               |
| Site           | addresses `:port`, `host`, `host:port`, `http://…`, `https://…` (several per block); `tls <cert> <key>`; `log { output stdout\|stderr\|discard; format json\|console }`; `handle_errors [<status codes>] { … }`                                                                                                                                |
| Directives     | `root`, `header` (set, `+`add, `-`delete incl. `-Prefix*`, `?`default, `defer`), `request_header`, `redir` (3xx, `permanent`, `temporary`, `html`), `rewrite`, `try_files`, `encode`, `route`, `handle`, `handle_path`, `error`, `respond`, `reverse_proxy`, `file_server`, `rate_limit` (Rate limits)                                         |
| Matchers       | `path`, `path_regexp`, `file` (`root`, `try_files`, `try_policy first_exist`), `not`, `host`, `method`, `header`, `client_ip`, `remote_ip`, `protocol`; inline `*`, `/path`, `@name`                                                                                                                                                           |
| reverse_proxy  | plain-HTTP upstreams (`host:port`), `to`, `lb_policy random\|first\|round_robin`, `lb_try_duration`, `lb_try_interval`, `flush_interval`, `header_up`, `header_down`, `transport http { dial_timeout, response_header_timeout, keepalive, versions 1.1 }`                                                                                      |
| file_server    | `root`, `index`, `hide`, `precompressed`, `pass_thru`, `disable_canonical_uris`                                                                                                                                                                                                                                                                |
| Placeholders   | `{path}`, `{dir}`, `{file}`, `{query}`, `{uri}`, `{host}`, `{hostport}`, `{method}`, `{scheme}`, `{remote_host}`, `{remote_port}`, `{client_ip}`, `{header.*}`, `{re.<name>.<group>}`, `{file_match.*}`, `{env.*}`, `{err.status_code}`, `{err.status_text}`, `{err.message}` and their `http.*` long forms; `{http.rate_limit.exceeded.name}` |

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

`respond 103` sends Early Hints, as in Caddy: the headers set so far (`header Link …`) go out as
an interim response and the chain goes on, so a browser starts loading the page's styles and
scripts while the application behind `reverse_proxy` is still working on the page:

```caddyfile
@pages not path /api/* /assets/*
header @pages Link "</assets/app.css>; rel=preload; as=style"
respond @pages 103
reverse_proxy app:8080
```

Early Hints go out over HTTP/3. Over HTTP/1.1 and HTTP/2 hyper sends no interim responses, so
there the same headers come only with the final response (where browsers use them too).

### Compression dictionaries

A browser that has an earlier version of a script or stylesheet can get the new one as a delta to
it (RFC 9842, Compression Dictionary Transport; Chrome and Edge 130 and later): after a deploy a
returning visitor downloads kilobytes instead of the whole bundle. Mark what may serve as a
dictionary with a header — the pattern names the URLs it is a dictionary for:

```caddyfile
header /assets/*.js Use-As-Dictionary "match=\"/assets/app-*.js\""
header /assets/*.css Use-As-Dictionary "match=\"/assets/app-*.css\""
```

A browser that stored `/assets/app-1a2b.js` with that header asks for `/assets/app-3c4d.js` with
`Available-Dictionary` (the old file's SHA-256) and `dcz` in `Accept-Encoding`; webfast answers
with the new file compressed by Zstandard against the old one (`Content-Encoding: dcz`, `Vary:
Accept-Encoding, Available-Dictionary`), when it is smaller than the best other answer.

- The dictionary must be a file webfast has: one of the site's files now, or a version it
  replaced since it started (a deploy that rewrote or removed it: the last 16 MiB per root of
  scripts, styles, pages and data are kept). Hidden files are not used.
- Each delta is worked out once (Zstandard level 19) and kept, at most 32 MiB of them; whoever
  asks for it first waits for it.
- Only for requests that read their answer themselves: same-origin, or a navigation (RFC 9842
  §9.3.3); a cross-origin request gets the usual answer. Not for ranges, nor in `handle_errors`.
- Only `dcz`: `dcb` (Brotli with a dictionary) is not offered, the Rust Brotli encoder has no
  shared dictionaries. Browsers asking for `dcb` and `dcz` get `dcz`.
- Without the header nothing changes; Caddy reads the same lines and sends the header, but no
  deltas.

### Error pages

A handler that fails — `file_server` with no file (404) or asked with a method other than GET and
HEAD (405), `reverse_proxy` with no answer (502, 504), `error` — answers with the bare status. The
site's `handle_errors` blocks can answer instead, as in Caddy:

```caddyfile
error /drafts/* 403
file_server

handle_errors 404 410 {
	rewrite * /404.html
	file_server
}
handle_errors 5xx {
	respond "{err.status_code} {err.status_text}"
}
```

- The blocks run on the request as the client sent it (its method and URI before any rewrite,
  without its body), with the site root it had, and with `{err.status_code}`, `{err.status_text}`
  and `{err.message}` (what `error` was given, otherwise the status text).
- A block with status codes (`404`, a class such as `5xx`) is for those; blocks with codes are
  tried before a block without, and one that does not answer (say, only `header`) lets the next
  that matches run.
- `respond` without a status, and `file_server`, answer with the failure's status.
- With no block for the status, or when the block fails too (the page is missing), the answer is
  the bare status.
- The headers set before the failure (`header`, a 405's `Allow`) stay on the page unless it sets
  its own.
- `respond` with an error status is an answer, not a failure: `handle_errors` does not see it.

### Rate limits

`rate_limit` is read as Caddy's [caddy-ratelimit](https://github.com/mholt/caddy-ratelimit) plugin
reads it (built in: the cargo feature `rate-limit`, on by default). Each zone has a matcher, a key,
and how many requests (`events`) a key may make in a `window`:

```caddyfile
rate_limit {
	zone login {
		match {
			method POST
			path /login /api/auth/*
		}
		key {client_ip}
		events 5
		window 1m
	}
	zone api {
		match {
			path /api/*
		}
		key {client_ip}
		events 600
		window 1m
		ipv6_prefix 64
	}
}
handle_errors 429 {
	respond "Too many requests: try again in a minute."
}
```

- A request is counted in each zone that matches it, from the tightest zone (the fewest events per
  unit of time) to the most permissive. The first zone it exceeds refuses it with 429 and
  `Retry-After` (seconds); the zones after that one do not count it. `handle_errors 429` can
  answer, with the zone's name in `{http.rate_limit.exceeded.name}`.
- `key` is any placeholder or text: `{client_ip}` (behind a trusted proxy, the client it names),
  `{remote_host}` (the peer), `{header.X-Api-Key}`, `static` (one limit for the whole zone).
  `ipv4_prefix` and `ipv6_prefix` make one key of the addresses in a network (`ipv6_prefix 64`:
  a client often has a whole /64).
- A rested key may make `events` requests at once, and then one more every `window / events`:
  a client that keeps asking gets its requests back steadily, not when a window ends (GCRA; the
  plugin counts a sliding window, Differences from Caddy).
- `jitter <fraction>` adds up to that fraction of the wait to `Retry-After`, at random, so that
  refused clients do not all come back at the same moment.
- Refused requests are not logged one by one: once per `sweep_interval` (1 min) a zone that
  refused any logs a warning with how many (`requests limited`, with `zone`, `limited` and
  `keys`); `log_key` adds up to ten of the keys it refused. Keys at rest again are dropped at
  the same time.
- `WEB_RATE_LIMIT_KEYS` (a million) is how many keys a zone holds, some 34 MiB when full. A full
  zone drops the keys at rest; if none is, a new key is refused (as nginx's `limit_req` does)
  rather than let through uncounted.
- `WEB_RATE_LIMIT_DRY_RUN=on` refuses nothing: the zones count and log what they would refuse
  (`requests would be limited`), to try limits on real traffic first.
- A reload keeps a zone's counts when its name, `events`, `window`, `key` and prefixes stay.
- The answers ready in advance for files (docs/performance.md) stay on the paths no zone takes. A
  zone that takes GET or HEAD by more than the path (a header, the client's address) costs the
  whole site its ready answers; a zone for `method POST` only costs nothing.
- `distributed` and `storage` (limits shared by several instances) and `disable_metrics` are
  not supported: the limits are each instance's own.

## Differences from Caddy

Those an answer shows are checked by `compat/`:

- ETags are hashes of the content (BLAKE3, 80 bits), not modification time and size; there is no
  `Last-Modified`.
- Proxied responses get no `Via`; the upstream gets the client's `Accept-Encoding` as it is (Caddy's
  transport asks for gzip when the client sent none).
- A failed request keeps the site's deferred headers, on the bare status and on the page
  `handle_errors` answers with (Caddy drops them).
- Error pages: `file_server` in `handle_errors` sends the page whole, never a 304 or a range (Caddy
  answers a bare status for a matching ETag, and cuts the page to a range); `{err.message}` of a
  proxy failure is the status text (Caddy's is the network error, with the upstream's address);
  the blocks see the request's headers as the client sent them (Caddy: as `request_header` left
  them); `{err.id}` and `{err.trace}` are not supported.
- `text/event-stream` is never compressed.
- Limits Caddy does not have (docs/operations.md, Limits): `response_header_timeout` 60 s by
  default (`0` restores Caddy's none), 408 for a request body the client stops sending, at most 64
  non-overlapping ranges, redirect targets kept on the site, client identity headers
  (`X-Real-IP`, `CF-Connecting-IP`, `Forwarded`, …) dropped from untrusted peers.
- A WebSocket tunnel keeps the place of the connection it came from, so it counts against the
  connection limits; it has no idle limit, and closes when the server stops (Caddy's default,
  `stream_close_delay 0`). `stream_timeout` and `stream_close_delay` are not supported.
- A file larger than `WEB_MAX_FILE_IN_MEMORY` is streamed from disk with an ETag from its size and
  modification time (as Caddy's), and answers at most one range: several get the whole file (Caddy:
  multipart/byteranges).
- Brotli on the fly is built in; Caddy needs the `caddy-brotli` plugin to read `encode … br`.
- No automatic certificates (ACME): `tls` takes PEM files, which are re-read when they change.
- Compression dictionaries (`dcz`): Caddy has none; the `Use-As-Dictionary` header is just a
  header to it.
- Early Hints (`respond 103`) go out over HTTP/3 only (Caddy: over every protocol); a file's ready
  answer is not preceded by them (it is as quick as they would be). Of the 1xx statuses `respond`
  takes only 103.
- The configuration is reloaded with SIGHUP (docs/operations.md, Reloading); Caddy reloads
  through its admin API (`caddy reload`), which `admin off` turns off.
- `rate_limit` is built in; Caddy needs the caddy-ratelimit plugin. A zone is a GCRA, not a
  sliding window: after `events` at once a key gets one request back every `window / events`,
  so a key that rested may pass up to twice `events` within one window (the plugin: never more
  than `events` in any window, but it keeps a timestamp per request of the window, where a key
  here takes 16 bytes), and the `Retry-After` values differ. Refused requests are logged as a
  summary per zone and `sweep_interval` (the plugin: each one); a zone holds at most
  `WEB_RATE_LIMIT_KEYS` keys (the plugin: no bound); no metrics, no `distributed` limits.

## Environment

| Variable                     | Default     | What it sets                                                                                                                                                                                                                                                       |
| ---------------------------- | ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `LOG_LEVEL`                  | `info`      | the server's own log (JSON on stderr); `debug` also via the `debug` global option                                                                                                                                                                                  |
| `WEB_MAX_MEMORY`             | `512MiB`    | what the site files may take in memory, over all roots; a site that does not fit stops the startup, a change that does not fit is not taken                                                                                                                        |
| `WEB_MAX_FILE_IN_MEMORY`     | `16MiB`     | a larger file (a video, an archive) is not held in memory but streamed from disk for each response; `off`: every file in memory (docs/operations.md, Files and memory)                                                                                             |
| `WEB_LZ4_MIN_SAVING`         | `25`        | a file of up to 1 MiB is kept as an LZ4 block when that saves at least this many percent; `off`: never                                                                                                                                                             |
| `WEB_FILES_WATCH`            | `auto`      | changed files picked up: `auto` (inotify on a local filesystem, polling elsewhere), `inotify`, `poll`, `off` (the files as loaded at startup)                                                                                                                      |
| `WEB_FILES_POLL`             | `30s`       | how often a polled root is looked at again                                                                                                                                                                                                                         |
| `WEB_WORKERS`                | `auto`      | threads serving connections, 1–1024 (`auto`: one per CPU the process may use, at most 64 — a container's CPU limit counts)                                                                                                                                         |
| `WEB_RUNTIME`                | `per-core`  | `per-core`: a thread with its own runtime per listening socket (Unix); `shared`: one multi-threaded runtime for all connections                                                                                                                                    |
| `WEB_RELOAD`                 | `immediate` | what a reload (SIGHUP) does to open connections: `immediate`, their next request gets the new configuration; `lazy`, they keep theirs until they close; `drain`, as lazy, each closed at a random moment within `WEB_RELOAD_DRAIN` (docs/operations.md, Reloading) |
| `WEB_RELOAD_DRAIN`           | `60s`       | with `WEB_RELOAD=drain`, the window over which the connections a reload leaves on the old configuration are closed; `0`: all at once                                                                                                                               |
| `WEB_RATE_LIMIT_KEYS`        | `1000000`   | the keys a `rate_limit` zone holds at most (some 34 MiB when full); a full zone refuses a new key unless keys at rest can be dropped                                                                                                                               |
| `WEB_RATE_LIMIT_DRY_RUN`     | `off`       | `on`: `rate_limit` refuses nothing, its zones only count and log what they would refuse                                                                                                                                                                            |
| `WEB_MAX_CONNECTIONS`        | `16384`     | open connections, TCP and QUIC together; `0`: no limit                                                                                                                                                                                                             |
| `WEB_MAX_CONNECTIONS_PER_IP` | `256`       | open connections per client address (an IPv6 /64 is one; trusted proxies are exempt); `0`: no limit                                                                                                                                                                |
| `WEB_STALL_TIMEOUT`          | `30s`       | a response the client stops taking, or a request body it stops sending, for this long ends it                                                                                                                                                                      |
| `WEB_TCP_CONGESTION`         | `bbr`       | TCP congestion control for the clients' connections; `system`: the kernel's default                                                                                                                                                                                |
| `WEB_LOG_FLUSH_MS`           | `10`        | access log lines are written in batches this often by a background thread; a full queue drops lines (counted) instead of slowing requests                                                                                                                          |

Durations are written as in the Caddyfile (`500ms`, `30s`, `5m`); sizes as `512MiB`, `1G` or bytes.
A value that does not parse stops the server at startup.
