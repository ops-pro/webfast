# Changelog

## 0.1.9 — 2026-11-14

WebSocket through `reverse_proxy`: over HTTP/2 as well as HTTP/1.1; tunnels that the server ends
in WebSocket's own words — a Close frame — when it stops, after a reload, or when their time is
up; that count against the connection limits whichever way they were opened; and that leave a
line in the access log when they close (docs/configuration.md, the start and Upstreams;
docs/operations.md, Reloading; recipes/websocket).

Worth knowing when upgrading from 0.1.8:

- Browsers that speak RFC 8441 (Chrome, Firefox) now open WebSocket over the HTTP/2 connection
  they already have, with nothing to configure. A tunnel still counts as one connection:
  `WEB_MAX_CONNECTIONS` and `WEB_MAX_CONNECTIONS_PER_IP` bound a client's tunnels as before, and
  a handshake over HTTP/2 past them is answered 429 or 503. `WEB_H2_WEBSOCKET=off` keeps
  WebSocket on HTTP/1.1.
- A site with `log` gets a second access log line for each tunnel, when it closes
  (`"msg":"closed tunnel"`); what counts lines by `handled request` is not affected.
- A stopping server now writes a WebSocket Close frame (1001) to both sides of a tunnel before
  it closes the connections, and waits up to 1 s for them to close.
- A reload that removes an upstream from a port's `reverse_proxy` now closes the tunnels open to
  it. Before, they stayed until either side closed.
- An upstream that answers a handshake with a 101 for another protocol than the one asked for
  is now answered 502.
- For code written against `webfast-core`: `guard::Place::new` takes the connection's
  `Activity`, and `upstreams::Upstreams::new` the fallback policy. webfast-modules 0.1.4 uses
  neither.

### Changes

- **WebSocket over HTTP/2** (RFC 8441, extended CONNECT): offered on HTTP/2 connections, turned
  into the HTTP/1.1 handshake before the routes, the request checks and the modules see it, and
  sent to the upstream as that handshake; the switch is answered 200, a 2xx that is no switch and
  a CONNECT for another protocol 501. A connection with a tunnel on it is not idle, and a close
  of the server's own (`WEB_RELOAD=drain`) waits for the tunnel.
- **A tunnel is a connection of the limits** over HTTP/2 too: on a stream it takes a place of
  its own, counted for its client's address as the connection's is, and gives it back when it
  closes; one that finds none is refused (429 for the address's limit, 503 for the server's)
  before an upstream is asked. No directive for tunnels alone — nginx and others count them by
  their limit on connections too; per upstream, `unhealthy_request_count` counts a tunnel until
  it closes.
- **Going away**: when the server ends a tunnel it writes a Close frame with the status 1001 to
  the client and (masked) to the upstream, between two frames only — it follows the frame
  headers for that, and reads no payload — then waits up to 1 s for each side to close.
- **`stream_timeout`** and **`stream_close_delay`** in `reverse_proxy`: a tunnel's longest life;
  and the tunnels a reload left on the old configuration closed within the delay, each at a
  moment of its own.
- **A reload that takes an upstream out closes its tunnels**: without `stream_close_delay`, the
  tunnels to an upstream that the port's new configuration no longer names are closed at once
  with a Close frame, so the instance can be stopped; the other tunnels stay, as before.
- **The handshake is retried**: a WebSocket handshake whose connection to the upstream fails goes
  to another upstream while `lb_retries` and `lb_try_duration` allow, as a request without a body
  does (before: 502 at once). Passive health counts its answer (`unhealthy_status`,
  `unhealthy_latency`), and `lb_policy cookie` sets its cookie on it.
- **A 101 is checked**: an upstream that switches to another protocol than the one asked for, or
  names none, is answered 502 instead of being tunnelled (as Caddy does).
- **Keepalive to the upstream** on a tunnel's connection (probes after 60 s of silence, and on
  Linux `TCP_USER_TIMEOUT` 90 s): an upstream that vanished no longer holds the tunnel and the
  client's place.
- **The access log's line at a tunnel's close**: the tunnel's life as `duration`, `bytes_read`,
  `size`, and `closed_by` (`client`, `upstream`, `stop`, `reload`, `upstream_removed`,
  `stream_timeout`).
- Open tunnels are counted, in the process (`webfast_core::tunnel::open`, and `tunnels` in the
  `shutting down` and `configuration reloaded` log lines) and per upstream address
  (`upstreams::Server::tunnels`), for the metrics endpoint to come.
- **`fallback`** of `lb_policy query`, `header` and `cookie`, in Caddy's syntax
  (`lb_policy cookie { fallback least_conn }`): what chooses for a request without the key;
  `random` unless set, as it was. A policy that needs no key only (Caddy nests keyed ones).
- **recipes/websocket**: an application with WebSocket — a handshake from a page of another
  site refused by its `Origin` (also over HTTP/2), `stream_timeout`, `stream_close_delay`.
- WebSocket over HTTP/3 (RFC 9220) is not offered: the released `h3` crate (0.0.8) refuses
  `:protocol: websocket`; noted in docs/configuration.md (What `reverse_proxy` reads) and
  src/h3.rs for its next release.

## 0.1.8 — 2026-11-13

A build with every module active: the `-full` images (`ghcr.io/ops-pro/webfast:0.1.8-full`,
`0.1.8-full-caddy`, `latest-full`, `latest-full-caddy`) and the `webfast-full-*` binaries carry
the OWASP CRS in the request filter too, next to the default build, which is as it was.

Worth knowing when choosing:

- On the `-full` images the request filter (on when `WEB_NGFW_CONFIG` names its file) runs the
  CRS, and its built-in rule sets are off but `cve` unless `rules.builtin` in its file names them:
  the same filter file filters differently than on the default image. `engines: { crs: false }`
  turns the CRS off.
- The default images, tags and binaries are unchanged.

### Changes

- **The `-full` images and binaries**: the build with every module, the OWASP CRS in the request
  filter too (the cargo feature `ngfw-crs`), as the tags `-full` and `-full-caddy`
  (`latest-full`, `<version>-full`, `sha-…-full`) and the release assets `webfast-full-*`
  (docs/operations.md, The full images). With the CRS the filter's built-in sets are off but `cve`
  unless its file names them. `WEBFAST_FEATURES` in the Dockerfile, `FEATURES` in pgo/build.sh,
  the Dockerfile's `binary` target.
- The release notes list the images, with their links on ghcr.io and `docker pull`.
- Dependencies: the week's compatible releases (rustls-webpki 0.103.17, webpki-roots 1.0.12,
  zstd 0.14.4, flate2 1.1.11 and others).

## 0.1.7 — 2026-11-11

One log policy for every log line about a request: the access log, the JWT check's and the API
firewall's event logs, and the request filter's of
[webfast-modules 0.1.4](https://github.com/ops-pro/webfast-modules/releases/tag/v0.1.4). A
credential is no longer written anywhere — not in a URI, not in a rule's matched text — and every
line carries the request's id (docs/configuration.md, Log privacy; the design in
docs/logging.md).

Worth knowing when upgrading from 0.1.6:

- With nothing configured the lines are as they were, with `REDACTED` where a credential was: the
  query parameters a JWT may come in, in the access log's URI too; in the request filter's hits,
  what a rule matched in `Authorization`, a cookie, a password field, a token's parameter or a
  query, `Referer` or JSON body that carries one.
- `request.id` is new in the access log's JSON line and in every event line, the same in all;
  `{http.request.id}` gives it to an upstream (`header_up X-Request-Id {http.request.id}`). An
  `X-Request-Id` and a `traceparent` are taken from a peer in `trusted_proxies` only.
- New: the global option `log_policy` (webfast's own, not Caddy's: a Caddyfile with it does not
  load in Caddy), `privacy` in a site's `log` and in a check's or the filter's `log:`, and
  `WEB_LOG_HASH_KEY` for `hash` across replicas and restarts.
- The access log's JSON line costs about 15% more to make (the id); the console line is as it was.

### Changes

- The modules of webfast-modules 0.1.4: the request filter's lines on the event API, each hit's
  matched text classed by where it came from, `log.privacy`, `request.id`.
- **The access log hides tokens in the URI**: the values of the query parameters a JWT may come
  in (`from_params`) are `REDACTED` there, as the event logs have shown them; it wrote them as
  sent (a `?access_token=…` in clear on every request). The names are the JWT check's as loaded
  now, for the access log and for every event log's URI, so a reload that adds a parameter to
  `from_params` hides it in the request filter's lines too (they kept the startup list; its hits'
  `matched` still do, until docs/logging.md's later steps). `eventlog::set_token_params` and
  `eventlog::redact_uri` are the shared list and its use.
- **Log privacy** (docs/configuration.md, Log privacy; docs/logging.md step 2, its first part):
  the global option `log_policy` sets what every log shows of a request by the class of each value
  (`secret`, `personal`, `payload`, `public`) and where it came from (a query parameter, a header,
  a cookie, a body field): `secret_params`, `secret_headers`, `secret_fields`, `path_classes`, and
  per class `show`, `truncate`, `hash`, `redact` or `drop`, within the class's bounds. A site's
  `log { privacy { … } }` and a JWT or API firewall file's `log: {privacy: …}` set their own. A
  reload puts a new policy in place. `hash` is a keyed HMAC (`WEB_LOG_HASH_KEY`, else derived from
  the ticket seed). The defaults keep the lines as they were. In the API: `privacy` (the policy,
  `privacy::policy()`), `AccessLog::privacy`, `Config::log_policy`, `eventlog::CheckLog` and
  `EventLog::of_check` for the core checks' `log:`; `eventlog::LogConfig` is as it was.
- **The request's id** in every log line about a request: `request.id` in the access log's JSON
  line and in every event log's, the same in all; `{http.request.id}` for `header_up` and error
  pages; an `X-Request-Id` taken, and a `traceparent`'s trace id as `request.trace_id`, from a
  trusted proxy only (docs/configuration.md, Log privacy). The id is made from a reference the
  request carries (`reqid::RequestId`, in its extensions when its site logs or a request check
  is loaded), its text at the line. The access log's JSON line costs about 15% more to make with
  it (one core: 525 → 611 ns); the console line is as it was.
- **The event API** (docs/logging.md, Events): a check declares its kinds of event and their
  fields with their classes (`eventlog::EventKind`, `Field`) and gives each event through
  `EventLog::event`; payload values come with their source (`Fields::value`), a hit raised to
  secret by its source is hidden whole, and nothing is made for an output that does not want the
  line. The JWT check and the API firewall write through it (the lines as before, with the id);
  `EventLog::record` and the modules' `record_with` stay. For the modules (docs/logging.md,
  step 3): `EventLog::event_with` and `EventKind::request` (fields inside `request`),
  `Fields::strs`, `numbers`, `object` and `policy`, `Source::Personal`, and `Policy::query_class`,
  `path_class` and `uri_class` (the class of the part of a query, path or URI a match touched).
- docs/logging.md: the design of one log service with one privacy policy (value classes, sources,
  the event API for modules, the policy and its reload, the request's id), step 1 of it built.
- **A reload (SIGHUP) reads the request checks' files again**: the JWT check's (`WEB_JWT_CONFIG`)
  and the API firewall's (`WEB_API_FIREWALL_CONFIG`), with the Caddyfile and taken with it or not
  at all. A file that does not load, or a check bound to an upstream the new Caddyfile no longer
  sends to, refuses the reload and the running checks stay; otherwise the next request is
  checked by the new files (one under way finishes with the old). They were read at startup only.
  The checks are held as `checkfile::Reloadable` (staged, committed after the server took the
  Caddyfile, or discarded); the JWKS and spec refresh tasks hold their check weakly and end with
  it. `Config::jwt` and `Config::api_firewall` are `Reloadable`s: a check given by hand is
  `Reloadable::new(check)`. A test of the binary (`tests/reload.rs`) sends it SIGHUP with both
  files changed, with a broken one, with a broken Caddyfile and with a binding no route has.

## 0.1.6 — 2026-11-11

The OWASP Core Rule Set v4 in the request filter, as an option: the cargo feature `ngfw-crs` builds
in [webfast-modules 0.1.3](https://github.com/ops-pro/webfast-modules/releases/tag/v0.1.3)'s
`webfast-ngfw-crs`, which runs the CRS as released, in SecLang, as a rule engine of the filter —
one decision, one log line and one ban list with its built-in rules. How it differs from
ModSecurity, Coraza and CrowdSec: [the CRS's documentation](https://github.com/ops-pro/webfast-modules/blob/main/docs/ngfw-crs.md#compared-with-modsecurity-coraza-and-crowdsec).

Worth knowing when upgrading from 0.1.5:

- The default build is unchanged: `ngfw-crs` is not a default feature, and the images are built
  without it.
- Built with it, the CRS is on in every filter file (`engines.crs` configures it, `engines: { crs:
  false }` turns it off), and `rules.builtin` left out means the `cve` set alone — the `leakage`
  set too is off then unless the file names it (`rules.builtin: [cve, leakage]`).
- The filter's `log.passed` writes every request let through with hits, those that only log
  included; a filter file may have `engines` (`engines.<name>: false` is no error in a build
  without that engine).

### Changes

- The feature `ngfw-crs` (`ngfw` and `webfast-ngfw-crs`); `src/compose.rs` registers the CRS
  engine with the filter before its file is read.
- The request filter and the browser challenge are those of webfast-modules 0.1.3 (Cargo.lock):
  the rule engine API of the filter, the CRS engine, and a body of a type the filter does not list
  read for an engine that has rules for it.
- CI's clippy builds the binary with `ngfw-crs` too; README and docs/overview.md name the feature.

## 0.1.5 — 2026-11-09

The client's TLS fingerprint (JA4) on every TLS connection, and the request filter of
[webfast-modules 0.1.2](https://github.com/ops-pro/webfast-modules/releases/tag/v0.1.2), which
logs it and flags a browser's User-Agent over a handshake no browser makes; a certificate index
built outside its lock; JSON checked without a tree where only its validity counts.

Worth knowing when upgrading from 0.1.4:

- The request filter has a new built-in rule, wf-920-600, in `log_only`: a line for each request
  whose User-Agent claims a current browser over a TLS handshake none makes (a library or script
  borrowing the browser's User-Agent; also a TLS-inspecting proxy in front of a real browser). It
  refuses nothing until a site arms it (`override: {wf-920-600: {mode: challenge}}`);
  `disable: [wf-920-600]` silences it. Its log lines, and every other, carry `request.ja4`.
- The module API: `ConnInfo` has a field more, `ja4`; a module that makes one by hand (its tests)
  adds `ja4: None`.
- The fingerprint is worked out once per TLS connection over TCP, after the handshake, from a copy
  of the ClientHello's bytes (16 KiB at most, dropped once read); HTTP/3 connections have none yet.

### Changes

- The request filter and the browser challenge are those of webfast-modules 0.1.2 (Cargo.lock):
  rule examples and a JSON Schema for the rules files, comparison operators beside `gt`, a corpus
  of known evasions in its tests, the query parameters hidden from the logs shared rather than
  copied per request, one ban list lookup, the challenge's answer length checked before its hash,
  and the client's fingerprint as the target `tls.ja4`.
- **The client's JA4 fingerprint** (FoxIO's JA4, BSD 3-Clause): over TLS on TCP the handshake
  reads the ClientHello through a stream that keeps a copy of those first bytes (no `peek`, no
  second read; 16 KiB at most), and the fingerprint is worked out once per connection, after the
  handshake, into `ConnInfo::ja4` (36 characters held inline, `None` for plain HTTP, HTTP/3 and a
  hello that cannot be read). `webfast_core::ja4` parses a hello (records joined, GREASE left out)
  and gives JA4 and JA4_r, checked against the specification's example; `Ja4::parse` reads one
  as written. A `ConnInfo` made by hand
  needs `ja4: None`; `ServerState::connection_tls` takes the fingerprint, `connection_named` stays.
- A new certificate set (`tls` files re-read, an ACME renewal) is indexed before the lock is
  taken: handshakes and the host check wait only for the swap, not for the index to be built.
- A `respond` body with placeholders is checked for being JSON (its Content-Type) without
  building the document, per request.
- The API firewall checks a JSON or text request body of a media type without a schema for being
  JSON or UTF-8 alone, without making a value of it (a form's fields are read as before).

## 0.1.4 — 2026-11-09

A fix for the request filter, which panicked on a request with a query parameter or a cookie
without `=`; the filter of
[webfast-modules 0.1.1](https://github.com/ops-pro/webfast-modules/releases/tag/v0.1.1), with
libinjection's detectors, a set for known exploited CVEs and a description of every rule; a 200
streamed through the filter instead of held; and the module API's staged checks by value.

Worth knowing when upgrading from 0.1.3:

- With the request filter on (`WEB_NGFW_CONFIG`), 0.1.3 panicked in the request's head phase on
  a query parameter or a cookie without `=` (`?a&b=1`, `Cookie: flag`), a request any client can
  send. Upgrade if the filter is on.
- The filter has more built-in rules: `builtin: all` now also takes libinjection's SQL injection
  and XSS detectors (wf-942-170, wf-941-150), the rules added beside them, and the `cve` set. A
  site that ran clean on 0.1.3 may see new refusals; `log_only` for a set or a rule, `disable`
  or `disable_tags` turn them off (docs/ngfw.md in webfast-modules).
- Each hit in the filter's log carries the rule's severity, confidence, tags and references, and
  its number as `ruleId` next to `id`; a reader that took the lines as they were sees new fields.
- A proxied 200 goes through the filter as it streams; a leak cuts it instead of turning it into
  a 500 (`response.stream: false` keeps the 0.1.3 behaviour).
- A module written against the core changes its `Check` and `Inspect` implementations (below).

### Changes

- **The module API's staged checks hand the head's state to the body by value, and a set boxes
  once** (`webfast_core::module`, docs/modules.md). `Check` has an associated
  `type Pending: Send + 'static`; `head` returns `Head<Self::Pending>` (`Pass`, `Refuse`,
  `Body(pending)`) and `body(pending, req, body, client)` returns `impl Future<Output = Checked> +
  Send` (an `async fn` implements it) instead of a `BoxFuture`. The composed set is two traits:
  the generic `CheckSet` (for every `Check`, `()`, `Option<T>`, `Arc<T>` and pairs; a pair's
  pending is `Stage::First`/`Stage::Second`) and the object-safe `Checks`, whose
  `check(req, body, client) -> Checking` gives `Done(checked)` from the heads alone or
  `Body(future)` — the one boxed future of the request, over the asking check's body and the
  heads and bodies after it. `Decided`, `Checks::head`/`body`/`leaves` are gone. The same for the
  response side: `Inspect::inspect` returns `impl Future`, `InspectSet` is the generic set (each
  inspector is called only for a response its `covers` took), and `Inspectors::inspect` boxes one
  future for a covered response, none for the others (pairs boxed twice before, `()` and `None`
  once more). A module that carried state from `head` to `body` in `req.extensions` now returns
  it in `Head::Body`. With the request filter's matching change, a 1 KiB form POST through it
  allocates 37 times where it allocated 49 (the filter on), a 4 KiB multipart upload
  43 instead of 58; a GET is unchanged at 6, the browser challenge's GET with a cookie at 4.
- The request filter (webfast-modules) streams a proxied 200 instead of holding it: its body is
  scanned as it goes out and the response is cut (the connection closed, the HTTP/2 stream reset)
  at a leak; a 5xx is held and replaced as before (`response.stream: false` holds a 200 too).
- The request filter comes with libinjection's SQL injection and XSS detectors: the `ngfw`
  feature turns on webfast-ngfw's `libinjection` feature (the `barbacane-libinjection` crate, pure
  Rust, BSD-3-Clause), so the operators `detect_sqli` and `detect_xss` and the built-in rules
  wf-942-170 and wf-941-150 are in the binary. From webfast-modules 0.1.1 the filter also has the
  `cve` set (known exploited vulnerabilities of web products), a severity, confidence, CWE and
  CVE references and a description for every rule (written with each hit, together with the
  rule's number as `ruleId`), `disable_tags`, and no longer panics on a query parameter or cookie
  without `=`.

## 0.1.3 — 2026-11-07

Less CPU and fewer allocations wherever a response is compressed, proxied, cached or goes through
the chain; the repository as a workspace with a module API; and the first modules, compiled into
the binary: the NGFW request filter and the browser challenge
([webfast-modules 0.1.0](https://github.com/ops-pro/webfast-modules/releases/tag/v0.1.0)).

Worth knowing when upgrading from 0.1.2:

- The modules are in the binary and off until configured: the request filter when
  `WEB_NGFW_CONFIG` names its file, the browser challenge where a site has the `challenge`
  directive. A binary built without one of them (`--no-default-features`) refuses to start when
  that module's variable is set, instead of ignoring it.
- A refusal of the JWT or the API firewall without `log.output` is written by the batching
  stderr writer in the event log's own JSON shape, no longer through `tracing`'s unbuffered
  writer.
- The shared runtime has at most four workers when every server runs per core and HTTP/3 is off;
  the per-core threads already number the CPUs.
- `rewrite * ?q=1` keeps the path's percent-encoding, as Caddy does.
- Building from source: the repository is a Cargo workspace; `cargo build --release` at the root
  still yields `target/release/webfast` (`-p webfast`), and the modules are git dependencies on
  webfast-modules pinned by `Cargo.lock`.

### Faster

- Compression: a compressor's state is kept per thread and reset between responses (gzip drives
  deflate and writes its own header and trailer, zstd a reused context; Brotli's window fits the
  body); gzip runs on zlib-rs, already in the tree for rustls; a body known at once is not
  collected again; `compressible` checks the common types first.
- Static files: a file's `.br`/`.gz`/`.zst` siblings are found once at load; a direct hit is
  looked up without copying the path; `hide` patterns are normalized once.
- Cache: Cache-Control directives compared in place; a miss's Cache-Status values made once; an
  entry's ETag, Content-Length and Age as ready header values; a storable miss builds its fetch on
  the worker, not before the first byte.
- The chain: its future is not boxed per request; two deferred hooks inline; a failure's reason is
  a static string and marked only where `handle_errors` reads it; `rewrite` and `handle_path`
  build the new URI in one string; `path_regexp` groups in one allocation.
- Proxy: the upstream's headers copied in one pass with room for all of them, Connection tokens
  removed by their text, the response's hop-by-hop fields in one pass, the body boxed once;
  `header_down` without placeholders applied as it is; a body's stall or excess size told by its
  error instead of shared flags (a proxied POST: 37 → 30 allocations).
- Connections: hyper's per-request header timer is off (the connection's own timer bounds the
  heads, with the same limits); the idle timer is not re-armed on every poll; the access log line
  is written by the tracking body, not a second wrapper; the stop signal, the per-address
  admission counts (64 shards) and hyper's builders are no longer shared or rebuilt per
  connection; HTTP/2 and HTTP/3 requests without a body get the empty body without an allocation.
- Logs and limits: timestamps and durations written from integers, the event log's writer
  resolved once, ahash for rate-limit keys and upstream slots, shards on cache lines of their own.

Measured as for 0.1.2 (in process, a single-threaded runtime pinned to one core, Linux, the
release profile, mimalloc with a counting allocator; "through a connection" is a keep-alive
HTTP/1.1 connection over loopback), the mean of two runs of each build, per request or call:

| Case                                                   | 0.1.2    | 0.1.3    | Allocations | Allocated          |
| ------------------------------------------------------ | -------- | -------- | ----------- | ------------------ |
| Through a connection: a ready answer                   | 10.6 µs  | 10.5 µs  | 5 → 4       | 8.7 → 8.6 KB       |
| Through a connection: `respond {path}` (not ready)     | 11.3 µs  | 11.2 µs  | 7 → 5       | 15.8 → 8.9 KB      |
| Through a connection: a 404 through the chain          | 12.1 µs  | 11.6 µs  | 16 → 8      | 17.1 → 9.6 KB      |
| Through a connection: a file, 8 KiB, chain and log     | 13.2 µs  | 13.0 µs  | 12 → 7      | 18.8 → 11.5 KB     |
| Through a connection: a file, 8 KiB, gzip on the fly   | 95.3 µs  | 76.9 µs  | 26 → 11     | 375 → 15.7 KB      |
| Through a connection: a cache hit, 8 KiB               | 13.1 µs  | 12.8 µs  | 9 → 5       | 16.5 → 9.6 KB      |
| Through a connection: proxy, 8 KiB, identity           | 31.2 µs  | 29.2 µs  | 29 → 26     | 51.7 → 44.2 KB     |
| Through a connection: proxy, `Connection: keep-alive`  | 31.3 µs  | 29.6 µs  | 31 → 26     | 51.3 → 44.9 KB     |
| Through a connection: proxy, POST of 1 KiB             | 33.0 µs  | 30.7 µs  | 37 → 30     | 52.0 → 45.5 KB     |
| Through a connection: proxy, 8 KiB, zstd               | 83.1 µs  | 48.3 µs  | 35 → 30     | 88.4 → 53.3 KB     |
| Through a connection: proxy, 8 KiB, br                 | 122 µs   | 122 µs   | 62 → 58     | 736 → 730 KB       |
| Proxy, 8 KiB, gzip, ETag                               | 101 µs   | 81.4 µs  | 51 → 41     | 402 → 49.2 KB      |
| Proxy, chunked 16 × 4 KiB, gzip                        | 672 µs   | 554 µs   | 65 → 55     | 399 → 46.3 KB      |
| Proxy, chunked 16 × 4 KiB, zstd                        | 116 µs   | 81.8 µs  | 58 → 71 ¹   | 65.5 → 66.9 KB     |
| `compressible("text/html; charset=utf-8")`             | 88 ns    | 17 ns    | 0 → 0       | 0                  |
| `compress_best`, gzip, 256 KiB                         | 43.5 ms  | 20.4 ms  | 10 → 5      | 442 → 503 KB       |
| A TLS handshake (full or resumed)                      | =        | =        | 262 → 259   | +5.5 KB ²          |

¹ zstd's stream calls take more, smaller allocations than the crate's writer did; the context
itself, several MB, is no longer made per response.

² The connection's task holds hyper's builders by reference and its timers inline: a few KB
more for each connection's future, allocated once, not per request.

### Modules

The repository is a Cargo workspace: `crates/webfast-core`, the server as a library
(`webfast_core`), and `crates/webfast`, the binary, whose `compose.rs` names the modules it is
built with. The module API (`webfast_core::module`, docs/modules.md): a module is a crate against
the core's public API — a `Module` the binary registers (its directives and their place in the
directive order, its environment, its files into `Config::modules`, its lines for `validate`, its
reload), route handlers (`Handler::Extension`), request checks (`Check`: the head decides
synchronously, a future is boxed only for a body) and inspectors of proxied responses (`Inspect`),
composed as tuples the core calls through one `&'static dyn` per kind; the core names no module.
A clean request allocates nothing more than before. Modules are tested on the core's harness
(`webfast_core::harness`, cargo feature `test-harness`). What a module needs became public: the
directive parser's types and helpers, the event log, `Activity::cut` (a connection closed without
an answer, the 444), the inspection step of every proxied response, `fetch` (the HTTPS client, a
cargo feature of the core). A request check's refusal marked `ErrorPage` goes through the site's
`handle_errors`, like a handler's failure.

The two modules of this release, from
[webfast-modules](https://github.com/ops-pro/webfast-modules) (documentation and changelog
there):

- **The NGFW request filter** (`webfast-ngfw`): rules with anomaly scoring over the request's
  head and body and over proxied responses — eleven built-in sets of seventy rules: protocol
  anomalies, scanners and probes, path traversal, remote inclusion, command, PHP, SQL, template
  and script injection, file uploads, leaking error pages — which a site's own file extends,
  replaces, overrides or disables; access by address lists and feeds, country and ASN, honeypot
  paths and a ban list. A clean GET costs it 2–3 µs and no allocation; a refusal is cheaper than
  an answer.
- **The browser challenge** (`webfast-challenge`): a client proves it is a browser — a cookie, a
  script, a proof-of-work or a CAPTCHA (Turnstile, hCaptcha, reCAPTCHA) — before a site answers,
  for every request or only once it is over a rate (`defer`), asked by the `challenge` directive
  or by the request filter (`action: challenge`). A signed cookie bound to the client's address
  block and browser, keys from the TLS ticket seed so replicas accept each other's cookies, no
  state per client; a request with a good cookie costs no more than one without the directive.

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
