# Upstream names

How `reverse_proxy` turns an upstream's host name into addresses (`src/dns.rs`,
`src/upstreams.rs`). Written as the decision before the code; kept as the description of it.

## The decision

**Requests never wait for DNS.** A proxy's servers are a snapshot (`ArcSwap`, read as the
compressed variants and the proxy cache are) of the addresses its names resolved to; a request
loads it once, chooses a server, and dials an address. No name is looked up on a request: not by
`getaddrinfo` on a blocking pool (what `HttpConnector` does by default, and Caddy, whose Go
resolver has no cache either), not by anything else.

**One background thread keeps the snapshots current.** A `Worker` (`src/background.rs`,
`webfast-dns`): one thread for every name of every `reverse_proxy`, niced, a tick a second, each
name refreshed when its term is up. The queries are blocking UDP (TCP when the answer is
truncated) on that thread, with the module's own codec for A and AAAA (RFC 1035): no resolver
library, as its runtime and cache are what this replaces.

**When a name is refreshed:** at the smallest TTL of the answer, clamped to
`[WEB_DNS_TTL_MIN, WEB_DNS_TTL_MAX]` (5s and 1h unless set), scheduled at 90% of it, so that a
snapshot is never past its term while the nameserver answers. (`dynamic a { refresh }` is not
read yet; the code takes a `refresh` in place of the TTL when it is.)

**The first resolution is at start and at reload, synchronous, with a timeout**
(`WEB_DNS_TIMEOUT`, 5s unless set). A name that does not resolve then is not an error: the
start goes on with a warning, a request to that upstream gets 502 (what a failed connection
answers; the rest of the site serves), and the DNS thread keeps trying — a second, then two,
four, up to a minute apart — so a container that Compose brings up later, or one being recreated,
is found within a minute of appearing. This is how Caddy and nginx with `resolve` behave; a
server that refuses to start because a neighbour is not up yet takes the site down with it.

**A failed refresh changes nothing:** the addresses stay (stale while revalidating), the next try
backs off (1s doubling, up to the term), the failure is logged once at warn and then at debug,
and the name's recovery at info.

**Changed addresses take effect on the next dial.** A server whose address stays keeps its count
of requests under way and its health; a new address is a new server; one no longer answered is
dropped from the snapshot, and the pool's connections to it live on until its idle timeout. Nothing
is torn down, so a change costs no burst of reconnections.

**A name with several addresses is several servers** (docs/configuration.md, Upstreams): the
policies and the health settings work per address, as HAProxy and nginx have it, not per name as
Caddy does. `to app:8080` with three replicas behind the name is `least_conn` over the three. At
most 64 servers per `reverse_proxy`; further addresses are not used, with a warning.

**Resolvers:** `/etc/resolv.conf` (Docker mounts it, and `/etc/hosts`, into every container, the
scratch image included), asked in its order, the next on a failure; `transport http { resolvers
<ip>… }` overrides it for that proxy, in the Caddyfile's own syntax (a port after a colon; 53
without). `/etc/hosts` is read for the names in it, `localhost` is the loopback, and a literal
address goes through none of this.

**IPv6:** A and AAAA are both asked for, the IPv4 addresses first in the snapshot; `WEB_DNS_IPV6=off`
leaves AAAA out (a network where IPv6 is not routed).

## In the Caddyfile

```
reverse_proxy app.internal:8080 {
    transport http {
        resolvers 10.0.0.2 10.0.0.3
    }
}
```

Outside the Caddyfile, as every setting Caddy has no word for: `WEB_DNS_TTL_MIN`,
`WEB_DNS_TTL_MAX`, `WEB_DNS_TIMEOUT`, `WEB_DNS_IPV6`.

Not read: `dynamic a` and `dynamic srv` (upstreams that come and go by a name's answer). The
snapshot is where they would go: the set of upstreams itself in it rather than the addresses of
each.
