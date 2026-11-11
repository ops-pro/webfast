# Logging: one service, one privacy policy (design, proposed)

Status: a proposal; step 1 is built (the access log and every event log's URI hide the JWT's
token parameters as loaded now), and step 2: the policy (classes, sources, actions,
`log_policy`, `privacy` per output, `hash`, `path_classes`), the event API (src/eventlog.rs) with
the JWT check and the API firewall on it, and the request's id (src/reqid.rs) in the access log's
JSON line and in every event line; and step 3: the request filter of webfast-modules on the
event API, its hits classed by their sources (its src/source.rs), its `log.privacy`. Step 4 is
not. Where the build differs from the text below: an `EventKind` has no `logger` (the `EventLog` has it, as the output is configured there);
a payload field written with `str` is not refused at compile time but taken as a secret, and a
debug build panics, as on a field not declared; the head of a line has no User-Agent (the access
log never wrote one, and the event logs' lines keep their fields); the request filter's
User-Agent stays inside `request` as its own field. A module's fields inside `request` are
declared apart (`EventKind::request`) and written by `EventLog::event_with`. `Config::hidden_params`
and `HiddenParams` stay in the core until step 4, unused by the modules: the policy holds the
JWT's parameters. It describes how every log line of the server — the access log,
the request checks' event logs (JWT, API firewall), the modules' (the request filter, the browser
challenge) — would be made, filtered and written by one service of the core, with the modules
saying only *what happened* and *what each value is*, never where it goes or what to hide.

## Why

What the server writes today, and where it falls short:

- **The writing is already off the request path, and stays.** A line is queued with `try_send`
  on a bounded queue (`accesslog::Writer`, 65 536 lines) and written in batches by one
  `log-writer` thread per output (`WEB_LOG_FLUSH_MS`); a full queue drops the line and counts it,
  so no request ever waits for a disk or a pipe. The access log's line is made when the response
  body has gone (`accesslog::Logged::finish`). What remains on the request's thread is making the
  line (some 300 bytes of JSON, about a microsecond).
- **Each logger decides on its own what to hide, and they disagree.**
  - The access log writes the URI as sent: a token given as `?access_token=…` is in it, in clear,
    on every request (src/accesslog.rs `line`).
  - The event logs hide the values of the query parameters a JWT may come in, by a list put on
    the request (`eventlog::HiddenParams`). The JWT check puts its own; the request filter, which
    logs before it, puts a copy taken at startup (`Config::hidden_params`, `Ngfw::hide_params`).
    Since a reload reads the JWT file again (src/checkfile.rs), a parameter added to `from_params`
    is hidden by the JWT's log and shown, with the token, by the filter's until a restart.
  - Nothing hides headers. A rule that matches in `Authorization` or `Cookie` (the CRS's
    `REQUEST_HEADERS` rules) writes what it matched, and the CRS's `logdata`, as they are.
  - The request filter writes `REDACTED` itself for a hidden parameter's `matched`, and only for
    the `args` targets.
- **Each logger knows its output and formats its own JSON**: a `log: { output: … }` in each
  module's file, the request filter's lines put together by hand (webfast-ngfw's src/log.rs).

So the mechanics stay; what moves is the responsibility: the policy of what is written, and how,
in one place.

## The model

### Classes

Every value a line carries has a class, and the policy says per class what an output does with
it:

| Class | What | Actions allowed |
| --- | --- | --- |
| `secret` | credentials: tokens, `Authorization`, `Cookie`, `Set-Cookie`, passwords, the JWT's `from_params`, the parameters a site names | `redact`, `hash` — never shown |
| `personal` | about a person: the client's address, a token's `sub` or `email`, the User-Agent, the JA4 fingerprint, a path segment the policy names | `show`, `truncate` (an address to its /24 or /48), `hash`, `redact`, `drop` |
| `payload` | what the request carried: query and body values, a rule's `matched` and `logdata`, the URI's query | `show` (cut to the output's length), `redact`, `drop` |
| `public` | what the server decided: rule ids and `ruleId`, status, decision, scores, phase, reason, time, the path | always shown |

`hash` is a keyed HMAC-SHA256 cut to 16 hexadecimal characters (`h:3f9a…`): equal values give
equal hashes within a key's life, so fifty refusals of one user or one address show as such
without the value. The key is the process's (from `WEB_LOG_HASH_KEY`, or drawn at start); a
deployment that correlates across replicas or restarts sets it. A reload keeps the key: lines
before and after a SIGHUP correlate.

`redact` writes `REDACTED` (the marker the event logs use today) and keeps the key, for the
dashboards that expect it; `drop` leaves the field out.

The actions have an order, from the most shown to the least: `show`, `truncate`, `hash`,
`redact`, `drop`. A class's row above is the part of that order it may take.

Two rules hold whatever the policy says:

- **Hide, then cut.** A value is classed and hidden whole, and only what is left to show is cut
  to the output's length, at a character's boundary — never the other way, which would leave the
  head of a token in the line.
- **A guessable secret is never hashed.** A value from a `body:<name>` source raised to `secret`
  (a password, a PIN) is `redact`ed even under `secret hash`: a hash of a value with little
  entropy tells who mistyped the same password, and gives it to whoever gets the key. `hash` is
  for the secrets that are long and random (tokens, session cookies, API keys).

### Sources

A field's class is declared by the module, but a value's class may depend on where it came from:
a rule's `matched` is `payload`, unless it was read from `REQUEST_HEADERS:authorization` or
`ARGS:access_token` — then it is a credential. So a value carries its **source**, and the policy
raises its class by it:

| Source | Example | Raised to |
| --- | --- | --- |
| `header:<name>` | `header:authorization`, `header:cookie`, `header:set-cookie`, `header:proxy-authorization` | `secret` (a list, extended by the policy) |
| `query:<name>` | `query:access_token` | `secret` when the name is in the JWT's `from_params` (as loaded now) or the policy's `secret_params` |
| `cookie:<name>` | `cookie:session` | `secret` |
| `body:<name>` | `body:password`, `json.user.password` | `secret` when the last name is in the policy's `secret_fields` (`password`, `passwd`, `secret`, `token`, `api_key`, …) |
| `names:<collection>` | `ARGS_NAMES`, `REQUEST_HEADERS_NAMES`, `REQUEST_COOKIES_NAMES` | `payload`, whatever the names: a parameter called `access_token` is not its value |
| `count:<collection>` | `&REQUEST_HEADERS:accept`, `&ARGS` | `derived`: a count is not a value |
| `response.header:<name>` | `response.header:set-cookie` | as `header:<name>` (`set-cookie`: `secret`) |
| `response.body` | a leak the response phase found | `payload` |
| `derived` | a fingerprint, a count, a length | the field's own class |

A source is what the module already knows: the request filter's `target` (`args.q`,
`REQUEST_HEADERS:authorization`), the JWT check's token location.

A value a rule engine computed from the request is not `derived`: the CRS copies what it
matched into its variables and reads them in the next rule of a chain. So `MATCHED_VAR(S)` takes
the source of the link that set it (the engine knows it), and `TX:<name>` is `payload`, never
`public`.

The URI is not one value: the path is `public`, each query parameter's value is classed by its
`query:<name>` source, so `/api/orders?limit=10&access_token=REDACTED` comes out of the same
policy in every log.

A name is compared as the server reads it, not as it was sent: percent-decoded, a header's and a
cookie's without regard to case, every occurrence of a repeated parameter — by the same function
the JWT check finds its token with, so `?access%5Ftoken=…` is the same parameter to the check and
to the policy.

#### Composite sources

Some sources are not one value but several of different classes in one string, and a rule that
reads them gives a `matched` cut from anywhere in it:

| Source | Holds | Done with it |
| --- | --- | --- |
| `REQUEST_URI`, `REQUEST_URI_RAW`, `REQUEST_LINE`, `QUERY_STRING` | the path and every query parameter | parsed as the head's URI is: each parameter's value by its `query:<name>` source |
| a header whose value is a URI: `Referer`, `Location` | another URI, with its own query | the same |
| `REQUEST_HEADERS` (all of them), `REQUEST_COOKIES` | every header or cookie | by each one's `header:<name>` / `cookie:<name>` when the hit names it; `secret` when it does not (a count of them is `count:`, above) |
| `REQUEST_BODY`, `FULL_REQUEST`, a body the server did not parse | anything | `secret` |

A composite source that cannot be taken apart is `secret` whole: what is lost is a rule's
`matched` for a raw body, what is kept is the rule's id, its target and the decision.

**A hit is hidden as a whole.** A rule's free text — the CRS's `logdata`, which is the rule's
message with `%{MATCHED_VAR}` put into it — carries the same value as `matched` without a source
of its own. So when a hit's source raises `matched` to `secret`, every `payload` field of that hit
takes the class too.

#### What a list of names does not reach

The sources hide what is named. A secret where no name says so is not seen: a token in the path
(`/reset/<token>`, `/s/<session>/…`), a credential in a header a site invented and did not list.
The path stays `public` — a log without paths is not one — and a site with such paths classes
their segments in the policy (`path_classes`: a pattern and a class, the segment under each `*`
taking it): `/reset/*` `secret`, `/users/*` `personal` — an address or a phone number in a path is
not a credential but is not public either. The value-shape check of the open questions is the
net under this.

### The request's id

A request may write several lines — the filter's event, the JWT check's, the access log's — in
several outputs. Nothing ties them today but the time, the address and the URI, and the policy
takes two of those away (`personal hash`, the query hidden). So the head of every line carries
`request.id`, `public`, the same in every output whatever its privacy.

**It costs nothing until something asks for it.** Every request carries a reference to its id,
not the id: 16 bytes inline in the request, no allocation and no random draw —

- 64 random bits drawn once, when the process starts, shared by all its requests;
- the connection thread's number and its count of requests (an increment).

The text — 32 hexadecimal characters, the shape of a W3C trace id — is made from it at its first
use, and kept: a log line (any of them), a site's `header_up X-Request-Id {http.request.id}`
before the proxy, a refusal that shows it. A request nothing asks it of makes no text. Unique
within a process by construction, across processes and restarts by the 64 random bits; not
unguessable, nor need it be — it ties lines together, it grants nothing.

- **To the upstream only when a site asks**, by the header or placeholder: then the text is made
  before the proxy, and the access log's line, written after the response, takes the same from the
  same reference.
- **Taken from the request** (`X-Request-Id`) only from a peer the configuration trusts for the
  client's address; then the reference holds that value. From anyone else it is ignored, or a
  client would tie its lines to another's, or untie its own.
- **A trace is not a request.** One trace id covers many requests (retries, calls across
  services), so a trusted `traceparent` gives a field of its own, `trace_id` (`public`), and never
  the request's id.
- **In a refusal** when a site asks (a header, or `{http.request.id}` in a `handle_errors`
  page), so that a user refused can name the line to whoever reads the log.

### Events

A module does not make lines. It declares, once, the events it writes and their fields with
their default classes, and gives the service an event when something happens:

```rust
/// At load: the event kinds a module writes (src/log/schema.rs).
pub static NGFW_REFUSED: EventKind = EventKind {
    logger: "ngfw",
    name: "request refused",
    fields: &[
        Field::public("decision"),
        Field::public("status"),
        Field::public("score"),
        Field::list("hits", &[
            Field::public("id"),
            Field::public("ruleId"),
            Field::public("severity"),
            Field::public("target"),
            Field::payload("matched"),   // classed again by each hit's source
            Field::payload("data"),
        ]),
        Field::personal("ja4"),
    ],
};

/// When it happens: the request it is about, and the fields, written only if some output wants
/// the line (nothing is made for `discard`).
log.event(&NGFW_REFUSED, Level::Info, parts, client_ip, |e| {
    e.str("decision", "block");
    e.u64("status", 403);
    e.u64("score", 15);
    e.list("hits", |l| {
        for hit in &hits {
            l.item(|h| {
                h.str("id", &hit.id);
                h.u64("ruleId", hit.number);
                h.str("target", &hit.target);
                h.value("matched", hit.source(), &hit.matched);   // value + where it came from
                h.value("data", hit.source(), &hit.data);         // the same source: hidden with it
            });
        }
    });
});
```

The common head of every line — time, level, logger, message, and `request` with its id
(`public`), the client's address (`personal`), method and host (`public`), URI (classed as
above), User-Agent (`personal`) — is the service's: a module passes the request, not its fields.

The API does not let a value through unclassed:

- A `payload` field is written only with `value(name, source, text)`; `str` on it does not
  compile (the field's writer has no such method) — a module cannot forget the source.
- A field written that the kind did not declare is `secret`, and a debug build panics on it:
  a mistake hides a value, it never shows one.

The fields are written through the closure only when the event will be written (an output that is
not `discard`, at a level it shows): a clean request costs what it costs now, nothing.

## The policy

One policy for the process, with per-output overrides; it is read at startup and by every reload
(SIGHUP), and the JWT's `from_params` feed it as the JWT file is loaded — so the gap a reload
leaves today closes by itself.

```caddyfile
{
	log_policy {
		secret_params token sessionid          # beside the JWT's from_params
		secret_headers x-api-key               # beside authorization, cookie, set-cookie, proxy-authorization
		secret_fields password secret api_key  # body fields, by their last name
		path_classes {                          # the segment under each * takes the class
			/reset/*  secret
			/s/*/     secret
			/users/*  personal
		}

		personal show                          # the defaults below, for every output
		payload show 200                       # cut to 200 bytes
		secret redact
	}
}
```

A webfast-only global option (listed in "Differences from Caddy"), as the policy must reload with
the Caddyfile and cover the modules too. Outputs keep where they are configured — a site's `log`
for its access log, a module's `log:` in its file — and may set their own action for a class, in either direction of
the order: an access log shipped to a third party hides more than the process's policy, the
SOC's event log shows more. The bounds are the classes', not the policy's: no output shows
`secret` more than `hash`, and none hashes a guessable one.

```caddyfile
example.com {
	log {
		output file /var/log/web/access.log
		privacy {                                    # this output only
			personal hash
			payload drop
		}
	}
}
```

```yaml
# a module's file (WEB_NGFW_CONFIG): its event log for the SOC, with what the analysts need
log:
  output: /var/log/web/ngfw.log
  privacy: { personal: show, payload: show, secret: hash }
```

The key of `hash` is `WEB_LOG_HASH_KEY`, else derived from `WEB_TLS_TICKET_SEED`, never written in
the Caddyfile (a key in a file that is shown and versioned is no secret).

**The defaults are today's lines minus the leaks:** `secret` redacted everywhere (the access log
too), `personal` shown, `payload` shown and cut as now (`log.matched`, 200 bytes). A deployment
that changes nothing sees the same lines, with `REDACTED` where a credential was.

A module's `log.matched` (the request filter's, 200 by default) keeps its meaning: it is the
`payload` length of that module's output, over the policy's; `log.matched: 0` is `payload drop`
there. Today's files read as they did.

## What does not change

- The pipeline: the queue, the writer threads, the batches, the drop-and-count when full, the
  flush at shutdown, files opened again when logrotate moves them.
- The formats: the access log's JSON and `console` lines and the event logs' JSON are the same,
  field for field, but for the values the policy hides. go-ftw finds `ruleId` (`public`) as now.
- Where a line is made: on the request's thread, the access log's after the body. Making it on
  the writer's thread would mean copying what the request had (its URI, its headers) into the
  queue, which costs what formatting does; a typed record in the queue may come later if the
  formatting grows (a second format, a network output), without a change of the module API.

## How it is checked

- **Canaries**: for every event kind of every module (the service knows them all, by their
  declarations), a request carrying known secrets — a token in the query under each secret name,
  `Authorization`, a cookie, a password in a form and in a JSON body — through a path that writes
  the event, then every output's lines searched for the secrets: under the default policy none is
  there, under `secret hash` only their hashes (and the password still `REDACTED`). The canaries
  find a leak only on the paths they walk; that a module cannot write a value without its source
  is the API's (above), not the test's.
- The composite sources: a rule on `REQUEST_URI`, on `REQUEST_HEADERS`, on the raw body and on
  `Referer`, each matching around a canary — neither `matched` nor `data` shows it.
- The names: `access%5Ftoken`, `Access_Token` for a header or cookie, a parameter given twice —
  hidden as the plain one. A hit on `ARGS_NAMES` with a secret name: the name stays shown. A hit
  on a count (`&REQUEST_HEADERS:accept`): its number stays shown.
- More canaries: `Proxy-Authorization`, a header of `secret_headers`, a cookie under a name no
  list has (every cookie is `secret`), `Set-Cookie` in the response phase, a segment of
  `path_classes`, a CRS chain whose second link reads `MATCHED_VARS` of a secret.
- Hide, then cut: a secret that crosses the 200th byte leaves no part of itself.
- The request's id: the lines of one request in two outputs carry the same id, the one the
  upstream got when the site sends it; an id sent by a peer that is not trusted is not taken; a
  trusted `traceparent` gives `trace_id`, not the id; a request that writes no line and sends no
  header makes no text.
- The JWT reload case: `from_params` grown by a reload, the filter's line hides the new
  parameter (the case of today's warning).
- The formats unchanged: the lines of today's tests (accesslog, eventlog, the filter's log
  tests, go-ftw) as they are, under the default policy.
- The cost: a clean request makes no line and no field (an allocation test, as the filter's
  `a_clean_request_matches_nothing_and_allocates_no_hit`); the cost of a refused request's line
  measured on one core against today's.

## The steps

1. **The access log hides the credentials** (small, alone, first): the values of the JWT's
   `from_params` in its URI, read from the JWT check as it is loaded now — not from the request's
   `HiddenParams`, which the JWT check puts there only when it ran, after the access log took the
   request — and the CHANGELOG says the access log changed. Closes today's worst leak before
   anything else lands.
2. **The service in the core** (webfast-core `log`): classes, sources, `EventKind`, the event API,
   the policy and its reload, `hash`, `path_classes`, the request's id (its reference on every
   request, its text on first use, `{http.request.id}`) in the head of every line. The access log, the JWT check and the API firewall on it;
   `eventlog::EventLog` kept as a thin shim for the modules until step 3.
3. **The modules on it** (webfast-modules): the request filter's src/log.rs gives events (its
   hits with their sources, the composite ones, the names, the counts, `MATCHED_VAR(S)` and the
   CRS's `logdata` included; the response phase's), its own `REDACTED` and `hide_params` go; the
   browser challenge's lines likewise. `Config::hidden_params` and `Ngfw::hide_params` go from the
   module API. A release of webfast-modules, then of webfast with it.
4. **The shim goes**, with the warning the JWT reload writes today.

## Open questions

- The policy's place: a global Caddyfile option (as above: reloads with the Caddyfile, but not
  Caddy's) or variables (`WEB_LOG_*`: Caddy-clean, but read at startup only). Leaning: the
  option — a policy that does not reload loses what closes the JWT gap.
- Whether `personal show` is the right default for the client's address everywhere, or the access
  log alone (as Caddy and most servers), the event logs `hash`. Leaning: `show` everywhere — an
  event log without the address is of little use to who reads it; an output that must not have
  it says `hash`.
- `secret_fields` by name only, or also by value shape for a payload whose source is a body the
  server did not parse, or a path. Leaning: a JWT's shape only (`eyJ…` with its two dots), which
  is cheap and not mistaken; a long hex or base64 string is as often an id or a digest the
  analyst needs.
- The hash key across replicas: derived from `WEB_TLS_TICKET_SEED`, which the replicas already
  share (HKDF with a label of its own — never the seed itself: one key for two uses means one
  leak for both), unless `WEB_LOG_HASH_KEY` is set. Leaning: so.
- The request's id: which peers are trusted to give one (the same list as for the client's
  address, or its own). Leaning: the same list, one notion of a trusted peer.
