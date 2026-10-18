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
| Global options | `auto_https off`, `admin off`, `http_port`, `https_port`, `grace_period`, `debug`, `order`, `servers [:port] { trusted_proxies static …, trusted_proxies_strict, client_ip_headers, protocols, strict_sni_host [on|insecure_off], timeouts { read_header, idle } }`, `cache { … }` (Proxy cache)                                                                           |
| Site           | addresses `:port`, `host`, `host:port`, `http://…`, `https://…` (several per block); `tls <cert> <key>` (repeatable: several certificates, each client gets one it can verify); `log { output stdout\|stderr\|discard; format json\|console }`; `handle_errors [<status codes>] { … }`                                                                                                                                |
| Directives     | `root`, `header` (set, `+`add, `-`delete incl. `-Prefix*`, `?`default, `defer`), `request_header`, `request_body { max_size }`, `redir` (3xx, `permanent`, `temporary`, `html`), `rewrite`, `try_files`, `encode`, `route`, `handle`, `handle_path`, `error`, `respond`, `reverse_proxy`, `file_server`, `rate_limit` (Rate limits), `cache` (Proxy cache)                  |
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

A rate does not stop one client from taking all of an application's workers with a few slow
requests, so with the same feature a client may have at most `WEB_MAX_UPSTREAM_REQUESTS_PER_IP`
(256) requests at the upstreams at once — whatever `reverse_proxy` sends on, a response counting
until its body ends (a server-sent event stream for as long as it is open; a WebSocket tunnel
counts as its connection instead). The next is refused with 429 (`handle_errors 429` answers it
too, with an empty `{http.rate_limit.exceeded.name}`) until one of them ends; files and other
answers webfast makes itself are not counted. The client is `{client_ip}`: an IPv6 /64 is one,
behind a trusted proxy it is the client the proxy names, and a trusted proxy's own requests are not
limited. `WEB_RATE_LIMIT_DRY_RUN` applies here too; the refusals are logged once a minute.

### Proxy cache

`cache` keeps what `reverse_proxy` answers in memory and answers from there, read as Caddy's
[cache-handler](https://github.com/caddyserver/cache-handler) plugin reads it (built in: the cargo
feature `proxy-cache`, on by default). The global option sets the defaults; the directive in a
site (with a matcher, or for all its requests) turns the cache on there and may change them:

```caddyfile
{
	cache {
		ttl 120s
		stale 1h
	}
}
example.com {
	encode zstd br gzip
	cache /api/catalog/*
	reverse_proxy app:8080
}
```

- What is kept: the answer to a GET with status 200, whole, of at most `max_cacheable_body_bytes`
  (a sixteenth of `WEB_PROXY_CACHE_MEMORY` unless set), without Set-Cookie, not `private`,
  `no-store` or `no-cache`, varying on nothing but Accept-Encoding, not an event stream; the answer
  to a request with Authorization only when it is `public` (or has `s-maxage` or
  `must-revalidate`). It is fresh for its `s-maxage`, `max-age` or `Expires`, otherwise for
  `ttl` (120 s); `default_cache_control` is the Cache-Control of an answer that has none (the
  client gets it too).
- The first client gets the answer as it comes, and the cache keeps its frames on the side; once
  it has ended whole, a background thread stores it: each encoding the site's `encode` lists is
  made once, at the highest level (zstd 19, Brotli 11, gzip 9), and an upstream that sent its
  answer encoded is asked first for its own other encodings. Every client then gets the best
  encoding it takes, from memory, with `Age`, `Cache-Status: webfast; hit; ttl=<seconds>` and 304
  for its ETag or Last-Modified; HEAD is answered from what GET stored.
- Past its freshness, within `stale` (or the answer's own `stale-while-revalidate`), an answer is
  still given as it is (`Cache-Status: …; fwd=stale`) while one conditional request brings it up
  to date in the background; within `stale` (or `stale-if-error`) it also answers in place of an
  upstream that fails or answers 5xx (`fwd-status=<status>`). `must-revalidate` turns both off.
- The client's own Cache-Control counts (`mode strict`: the plugin's default, and the only mode
  here): `no-cache`, or a `max-age` the stored answer is older than, goes to the upstream and keeps
  what it brings; `no-store` keeps nothing; `only-if-cached` gets 504 when nothing is stored. A
  browser's reload sends `max-age=0`, so it reaches the upstream.
- A POST, PUT, PATCH or DELETE drops what is stored for its URI. Ranges, WebSocket and requests for
  an event stream pass through; so do request URIs (path and query) that `regex { exclude
  <regexp> }` matches.
- As with any shared cache, an answer that differs from one user to another must say so: `private`
  or `no-store`, a Set-Cookie, or `Vary: Cookie`. The cache comes before `rate_limit` in the
  directive order (as in Caddy), so answers from it are not counted.
- Misses are not collapsed: until an answer is stored, every request for it goes to the upstream.
- `WEB_PROXY_CACHE_MEMORY` (64 MiB; `off`: nothing is kept) is what the stored answers take,
  every encoding counted; past it, those not asked for since eviction last passed go first. The
  cache outlives a reload.
- Background requests (revalidations, the upstream's own encodings) carry the headers of the
  request that brought the answer, without its client's address, credentials and cookies.
- `cache_name` is the name in `Cache-Status`. Not supported: the plugin's storages (`redis`,
  `badger`, `nuts`, `otter`, `olric`, `etcd`: the cache is in memory), `cdn`, `api`, `key`,
  `cache_keys` and the other modes.

### Request checks: JWT and OpenAPI


Two modules check requests: their JWT ([`src/jwt`](../src/jwt)), then the OpenAPI spec of the API
they are for ([`src/apifw`](../src/apifw)). Each is a Cargo feature (`jwt`, `api-firewall`, both in
the default build; without one, none of its code or dependencies is built) and is used only when
its YAML file is named — the Caddyfile stays Caddy's. A file that does not load stops the server
at startup with the reason; `webfast validate` loads them too and says what it found. A
refused request is answered, and logged in the site's access log, like any other. Each module
also writes what it refused, and what `log_only` let through, to its own event log (below).

**What a check covers** is set in the module's own file, never in the Caddyfile, so an edit there
cannot switch a check off. A JWT rule or an API covers requests in one of two ways:

- **By host, path and method**, checked before the site's routes and ready answers, so no file or
  proxied path is served past it.
- **By upstream**, with `upstreams: [app:8787]`: what the routes send to that upstream, checked
  by the `reverse_proxy` just before the request goes, as it goes there (after any `rewrite` or
  `handle_path`). Host, path and method narrow it further. This follows the routes: the app's
  spec bound to `app:8787` with `base_path: /api` covers the app's API, but neither an
  event-streaming service under `/api/stream/*` nor the pages the app renders outside `/api`.

Upstreams are written as `reverse_proxy` takes them. One that no `reverse_proxy` sends to stops
the server at startup, and `validate` says so, so a typo or a changed route cannot leave requests
unchecked. Among the rules, or the APIs, of one kind the first that matches decides; a request
can meet one of each kind.

With `cache` (Proxy cache), a stored answer goes only to a request that passes the checks bound
to the upstream it came from, and the answer to a request whose token was verified is kept only
when it says it may be shared (`public`, `s-maxage`, `must-revalidate`), as for a request with
`Authorization`: the token may not reach the upstream. The checks are read at startup; a reload
(SIGHUP) keeps them, and refuses a Caddyfile whose routes no longer send to an upstream they are
bound to.

**JWT** (`WEB_JWT_CONFIG`), after Istio's RequestAuthentication and Envoy's jwt_authn:

```yaml
mode: block # block | log_only; a rule may set its own
log: { output: /var/log/web/jwt.log } # see "Event logs" below; none: the server's log
providers:
  keycloak:
    issuer: https://id.example.com/realms/main
    audiences: [api] # the token's aud must name one (403 otherwise)
    jwks_uri: https://id.example.com/realms/main/protocol/openid-connect/certs # or jwks / jwks_file
    # from_headers: [{name: Authorization, prefix: "Bearer "}]   the default
    # from_params: [access_token]   from_cookies: [session]
    output_claim_to_headers:
      [{ header: X-User, claim: sub }, { header: X-Roles, claim: realm_access.roles }]
    # output_payload_to_header: X-Jwt-Payload   forward_original_token: false   clock_skew: 60s
    # require_expiration: true   max_lifetime: 24h   jwks_cache_duration: 10m   jwks_fetch_timeout: 5s
rules: # the first that matches decides; none: the request is not looked at
  - match: { paths: ['/api/public/*'] } # no providers: not checked
  - match: { paths: ['/api/v2/*'] }
    providers: [keycloak]
    mode: log_only # tried on live traffic first: failures are written down, requests go on
  - match: { paths: ['/api/*'], methods: [POST, PUT, DELETE] }
    providers: [keycloak]
  - match: { paths: ['/api/*'] }
    providers: [keycloak]
    allow_missing: true # as Istio: no token passes, a bad one does not
  - match: { upstreams: [stream:8800] } # what the routes send to the streaming service
    providers: [keycloak]
cache: { tokens: 10000 }
```

- Paths match as the `path` matcher does (decoded, cleaned, case-insensitive). Missing token: 401
  `Jwt is missing`; bad signature, wrong issuer, expired, not yet valid: 401; audience: 403
  (Envoy's answers, with `WWW-Authenticate: Bearer`).
- In `log_only` a failed check is written to the event log and the request goes on as it came:
  the token left in place, no claim headers. That way a rule can run on live traffic before it
  refuses anything.
- Accepted: RS256/384/512, PS256/384/512, ES256, ES384, EdDSA. Not: `none`, HMAC (a shared secret
  has no place at the edge, and refusing it rules out algorithm confusion), RSA under 2048 bits,
  tokens with `crit`, tokens over 16 KiB.
- Keys are parsed into aws-lc-rs keys once; a `jwks_uri` (HTTPS with the Mozilla roots built in) or
  `jwks_file` is read again every `jwks_cache_duration` in the background, sooner after a failure.
  A token signed with a key id not known yet asks for an early read and waits for it — at most one
  every 30 s, so made-up key ids cannot make the server hammer the issuer.
- The headers claims are written to are taken off every request first: a client cannot send
  `X-User` itself, also on paths no rule covers.
- Verified tokens are kept (by their BLAKE3 hash; 16 shards, two generations): a token seen again
  costs 0.6–0.85 µs, a new one 20 µs (RS256), 43 µs (EdDSA) or 68 µs (ES256) — release build.

**OpenAPI** (`WEB_API_FIREWALL_CONFIG`), after Wallarm API Firewall:

```yaml
log: { output: /var/log/web/api-firewall.log } # see "Event logs" below; none: the server's log
apis:
  - spec: openapi.yaml # relative to this file; YAML or JSON, OpenAPI 3.0 or 3.1; or a source, below
    upstreams: [app:8787] # what the routes send to the app; none: checked before the routes
    base_path: /api # the spec's paths are under it; hosts: [api.example.com] to narrow it
    mode: block # block | log_only | off
    unknown_query_params: block # block | allow
    strict_bodies: false # true: objects may not carry properties their schema does not name
    max_body_size: 1MB
    # block_status: 403   reason_header: false   pass_options: false
    endpoints: # per operation: the spec's path template, the method optional
      - { method: POST, path: /orders, mode: log_only }
```

- Every request under the base must be an operation of the spec, with its path, query, header
  and cookie parameters and its body as the spec says, and the credentials its `security` asks
  for present (presence only: the JWT module verifies tokens). In `block` a violation answers 403
  with an empty body (`reason_header: true` adds `apifw-validation-status`); in `log_only` it is
  written to the event log and the request goes on. A body over `max_body_size` gets 413 and a
  compressed one 415, in any mode.
- The spec is compiled once: a trie of path segments to operations, typed readers for the
  parameters, JSON Schema 2020-12 validators (OpenAPI 3.0 schemas converted: `nullable`, boolean
  exclusive bounds, `int32` ranges, `readOnly` properties refused in requests; patterns with the
  linear-time `regex` engine; formats checked). A request costs 32 ns outside any API, 1.1 µs for a
  GET with three parameters, 1.5 µs for a POST with a small JSON body.
- Where Wallarm's source showed gaps, this does otherwise: the body is read once and exactly those
  bytes go upstream; paths and query strings are decoded once and strictly (a broken escape, an
  encoded `/`, dot segments, `//`, a parameter that is not an array given twice are violations);
  whether a request is under an API is decided on the path as the matchers see it, so `/API/x` or
  `/x/../api/y` do not slip past; compressed bodies are refused, not inflated; nothing fails open
  (an undeclared body type is a violation).
- Not done yet: request bodies declared as multipart, binary or XML are checked for their type and
  size only; responses are not validated; references to other files are not followed.

`spec` is a file name, read once at startup, or a source kept current while the server runs:

```yaml
spec:
  uri: /api/openapi.json # a path, asked of this server's own routes in process; or an http(s) URL
  # file: openapi.yaml   instead of uri: a file, read again when it changes
  refresh: 1m # how often to look again; 1m for a uri by default, a file only when set
  ttl: 24h # how long the last good spec holds while its source fails; by default for ever
  timeout: 5s
  headers: { Authorization: 'Bearer ${SPEC_TOKEN}' } # a uri only; ${VAR} from the environment
```

- A path goes through the site's routes as a request would: a file the server serves, or the app
  it proxies to. It is marked so that the request checks skip it, so the spec can sit under the
  API's own base path without being in the spec. The same path asked from outside is checked
  like any other.
- Each look is a conditional request (`If-None-Match`, `If-Modified-Since`; for a file its size,
  time and inode). An unchanged spec costs a 304 and nothing is compiled. A changed one is
  compiled off the request threads and replaces the old one whole; requests in flight keep the
  one they found.
- A source that cannot be read, or a spec that does not compile, leaves the last good one in place
  and is tried again sooner: after 1 s, then doubling, at most `refresh` or 60 s. Until there is a
  spec, or once `ttl` passes without a good look, the API's requests get 503 `spec:unavailable`
  in `block` and go on in `log_only`. The rest of the site is not held up.

**Event logs.** With `log: { output: … }` in a module's file, what it refused, and what `log_only`
let through, goes there as one JSON line per request: to a file (relative to the module's file,
appended to and opened again when logrotate moves it), `stdout`, `stderr` or `discard`. The access
log's writer threads write the lines in batches, so no request waits for the disk. Without `log`
the events go to the server's own log. In a read-only container a file needs a writable mount for
its directory.

```json
{
  "level": "info",
  "ts": 1760788800.123,
  "logger": "jwt",
  "msg": "request refused",
  "request": {
    "client_ip": "203.0.113.7",
    "method": "GET",
    "host": "api.example.com",
    "uri": "/api/orders?limit=10&access_token=REDACTED"
  },
  "reason": "expired",
  "detail": "",
  "status": 401
}
```

- A request let through has `"level": "warn"` and `"msg": "request let through (log_only)"`, with
  the status it would have got.
- `reason` is short and fixed. The JWT module gives `missing`, `malformed`, `unknown-issuer`,
  `unsupported-algorithm`, `unknown-key`, `bad-signature`, `no-expiration`, `expired`,
  `not-yet-valid`, `lifetime-too-long` or `audience`. The API firewall gives what
  `apifw-validation-status` carries, such as `request:unknown-operation`,
  `request-parameter:query:limit`, `request-body:application/json` or `spec:unavailable`, with
  the particulars in `detail`.
- Tokens are not written: the values of the query parameters a JWT may come in show as
  `REDACTED`. A schema error says where and which keyword failed, such as `/password: minLength`,
  never the value. The rest of the URI is as the access log has it.

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
- `strict_sni_host` is on by default and answers 421 to a request whose Host is served with
  another certificate than the connection's (RFC 9110 §15.5.20); Caddy's `on` wants the Host to
  equal the SNI name and answers 403, which coalesced HTTP/2 connections do not survive.
  `insecure_off` turns it off. `WEB_TLS_STRICT_SNI=on` gives no certificate to a handshake without
  SNI or for a name no site names (Caddy: the default certificate).
- JWT validation and OpenAPI request validation are built in (Request checks) and configured
  outside the Caddyfile; Caddy needs plugins for either.
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
- A client's requests at the upstreams at once are limited (`WEB_MAX_UPSTREAM_REQUESTS_PER_IP`,
  256): Caddy has no such limit.
- `cache` is built in; Caddy needs the cache-handler plugin (Souin). Kept are GET answers with
  status 200 only (Souin: also 203, 204, 301, 404, 410 and others, and answers with Set-Cookie);
  one entry per URI, every encoding made from it (Souin stores what `encode` made, a variant per
  Accept-Encoding, each from the upstream); stored after the first client has its answer, so a
  miss's `Cache-Status` says `stored` before it is (Souin answers once stored); `stale` lets every
  answer be served stale (Souin: those whose Cache-Control allows it); HEAD is answered from what
  GET stored (Souin passes it on), and an identity answer from the cache carries `Vary:
  Accept-Encoding` too. `Cache-Status` names `webfast` and shows no key, and its values and `Age`
  differ; only memory as storage.

## Environment

| Variable                           | Default     | What it sets                                                                                                                                                                                                                                                       |
| ---------------------------------- | ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `LOG_LEVEL`                        | `info`      | the server's own log (JSON on stderr); `debug` also via the `debug` global option                                                                                                                                                                                  |
| `WEB_MAX_MEMORY`                   | `512MiB`    | what the site files may take in memory, over all roots; a site that does not fit stops the startup, a change that does not fit is not taken                                                                                                                        |
| `WEB_MAX_FILE_IN_MEMORY`           | `16MiB`     | a larger file (a video, an archive) is not held in memory but streamed from disk for each response; `off`: every file in memory (docs/operations.md, Files and memory)                                                                                             |
| `WEB_LZ4_MIN_SAVING`               | `25`        | a file of up to 1 MiB is kept as an LZ4 block when that saves at least this many percent; `off`: never                                                                                                                                                             |
| `WEB_FILES_WATCH`                  | `auto`      | changed files picked up: `auto` (inotify on a local filesystem, polling elsewhere), `inotify`, `poll`, `off` (the files as loaded at startup)                                                                                                                      |
| `WEB_FILES_POLL`                   | `30s`       | how often a polled root is looked at again                                                                                                                                                                                                                         |
| `WEB_WORKERS`                      | `auto`      | threads serving connections, 1–1024 (`auto`: one per CPU the process may use, at most 64 — a container's CPU limit counts)                                                                                                                                         |
| `WEB_RUNTIME`                      | `per-core`  | `per-core`: a thread with its own runtime per listening socket (Unix); `shared`: one multi-threaded runtime for all connections                                                                                                                                    |
| `WEB_RELOAD`                       | `immediate` | what a reload (SIGHUP) does to open connections: `immediate`, their next request gets the new configuration; `lazy`, they keep theirs until they close; `drain`, as lazy, each closed at a random moment within `WEB_RELOAD_DRAIN` (docs/operations.md, Reloading) |
| `WEB_RELOAD_DRAIN`                 | `60s`       | with `WEB_RELOAD=drain`, the window over which the connections a reload leaves on the old configuration are closed; `0`: all at once                                                                                                                               |
| `WEB_RATE_LIMIT_KEYS`              | `1000000`   | the keys a `rate_limit` zone holds at most (some 34 MiB when full); a full zone refuses a new key unless keys at rest can be dropped                                                                                                                               |
| `WEB_RATE_LIMIT_DRY_RUN`           | `off`       | `on`: `rate_limit` refuses nothing, its zones only count and log what they would refuse                                                                                                                                                                            |
| `WEB_MAX_UPSTREAM_REQUESTS_PER_IP` | `256`       | a client's requests at the upstreams at once (`reverse_proxy`, until the response ends; behind a trusted proxy, the client it names); more are refused with 429; `0`: no limit (docs/configuration.md, Rate limits)                                                |
| `WEB_PROXY_CACHE_MEMORY`           | `64MiB`     | what the answers kept by `cache` may take, every encoding counted; past it the least asked for go first; `off`: nothing is kept (docs/configuration.md, Proxy cache)                                                                                               |
| `WEB_TLS_STRICT_SNI`               | `off`       | `on`: a TLS handshake without SNI, or for a name no site names exactly or by a wildcard, gets no certificate and ends with an alert (docs/operations.md, TLS and HTTP/3) |
| `WEB_JWT_CONFIG`                   |             | the JWT module's YAML file; unset: no JWT checks (Request checks) |
| `WEB_API_FIREWALL_CONFIG`          |             | the API firewall's YAML file; unset: no OpenAPI checks (Request checks) |
| `WEB_MAX_CONNECTIONS`              | `16384`     | open connections, TCP and QUIC together; `0`: no limit                                                                                                                                                                                                             |
| `WEB_MAX_CONNECTIONS_PER_IP`       | `256`       | open connections per client address (an IPv6 /64 is one; trusted proxies are exempt); `0`: no limit                                                                                                                                                                |
| `WEB_STALL_TIMEOUT`                | `30s`       | a response the client stops taking, or a request body it stops sending, for this long ends it                                                                                                                                                                      |
| `WEB_TCP_CONGESTION`               | `bbr`       | TCP congestion control for the clients' connections; `system`: the kernel's default                                                                                                                                                                                |
| `WEB_LOG_FLUSH_MS`                 | `10`        | access log lines are written in batches this often by a background thread; a full queue drops lines (counted) instead of slowing requests                                                                                                                          |

Durations are written as in the Caddyfile (`500ms`, `30s`, `5m`); sizes as `512MiB`, `1G` or bytes.
A value that does not parse stops the server at startup.
