# Upstream names: design

How `reverse_proxy` turns an upstream's host name into addresses. Not built yet; this is the
decision, written before the code so that the code can be checked against it.

## Today

`HttpConnector` with its default resolver: `getaddrinfo` on a blocking thread pool, the system's
`/etc/resolv.conf`, no cache in the process. Every new connection resolves the name again; the
connection pool is all that stands between a request and a DNS round trip. Caddy does the same
(Go's resolver has no cache either); nginx resolves static upstreams once at start and re-resolves
on a `resolver … valid=` schedule.

## The decision

**Requests never wait for DNS.** A name's addresses are a snapshot (`ArcSwap`, as the compressed
variants and the proxy cache are read), and the resolver given to `HttpConnector`
(`new_with_resolver`) answers from that snapshot with a ready future: no I/O, no await, no
blocking pool on the hot path.

**One background thread refreshes the snapshots.** A `Worker` (`src/background.rs`): one thread for
every name of every `reverse_proxy`, niced, a tick a second, a queue ordered by due time. The
queries are blocking UDP (TCP on a truncated answer) on that thread; no Tokio there, as none is
needed.

**When a name is refreshed:** at `refresh` when the directive gives one; otherwise at the smallest
TTL of the answer, clamped to `[WEB_DNS_TTL_MIN, WEB_DNS_TTL_MAX]` (5s and 1h unless set). The
refresh is scheduled at about 90% of the term, so a snapshot is never past its term while the DNS
answers.

**The first resolution is at start and at reload, synchronous, with a timeout** (`WEB_DNS_TIMEOUT`,
5s unless set), as nginx does: a static upstream that does not resolve is a configuration error
at start, not a 502 on the first request. At a reload a name that stopped resolving keeps its
addresses, with a warning.

**A failed refresh changes nothing:** the addresses stay (stale while revalidating), the next try
backs off (1s doubling to the term), the failure is logged once at warn and then at debug, and
counted for the metrics.

**Changed addresses take effect on the next dial.** Connections to addresses no longer answered
live on until the pool's idle timeout; nothing is torn down, so a change costs no burst of
reconnections.

**Resolvers:** `/etc/resolv.conf` (Docker mounts it, and `/etc/hosts`, into every container, the
scratch image included); `transport http { resolvers <ip>… }` overrides it for that proxy, the
Caddyfile's own syntax. `/etc/hosts` is read for the names in it. An IP literal, or `localhost`,
goes through none of this.

**The library:** `hickory-proto` for the messages (A, AAAA, the wire format), not
`hickory-resolver`, whose runtime and cache this design replaces. About three hundred lines of our
own, in the core (as `reverse_proxy` is), no feature.

## In the Caddyfile

The subset of Caddy's that this covers, meaning the same:

```
reverse_proxy app.internal:8080 {
    transport http {
        resolvers 10.0.0.2 10.0.0.3
    }
}
```

Later, when upstreams that come and go are needed, `dynamic a { name … port … refresh … resolvers …
versions ipv4 }` and `dynamic srv`: the same worker and snapshot, with the set of upstreams itself
in the snapshot rather than the addresses of each.

Outside the Caddyfile, as every setting Caddy has no word for: `WEB_DNS_TTL_MIN`, `WEB_DNS_TTL_MAX`,
`WEB_DNS_TIMEOUT`, `WEB_DNS_IPV6=off`.
