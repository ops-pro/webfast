# Overview

How webfast answers a request: what a connection goes through, what a request goes through, the
handler chain a site's routes make, and the work done in the background. Steps drawn dashed belong
to a cargo feature (all on in the default build); without it they are not built, and the request
goes on as if the step were not there. The table at the end lists where each feature takes part.

## A connection

```mermaid
flowchart TD
    accept["accept: a listening socket per worker (SO_REUSEPORT)<br/>or a QUIC endpoint on the same port (UDP)"]
    admit{"WEB_MAX_CONNECTIONS<br/>WEB_MAX_CONNECTIONS_PER_IP"}
    refused["closed at once"]
    tls{"TLS?"}
    hello["ClientHello: certificate for the SNI name<br/>exact host, then wildcard, then any host;<br/>of a site's certificates the first the client can verify"]
    strict{"WEB_TLS_STRICT_SNI=on<br/>and no SNI, or a name no site names?"}
    alert["handshake ends with an alert:<br/>no certificate sent"]
    compress["certificate chain compressed<br/>(RFC 8879, when offered)"]
    alpn["ALPN: h2 or http/1.1;<br/>h3 over QUIC (0-RTT for safe methods)"]
    plain["plain HTTP: HTTP/1.1, h2c on request"]
    serve["hyper / h3 serve the connection<br/>timeouts: read_header, idle; WEB_STALL_TIMEOUT"]
    request(["each request: handle()"])

    accept --> admit
    admit -- over --> refused
    admit -- within --> tls
    tls -- yes --> hello --> strict
    strict -- yes --> alert
    strict -- no --> compress --> alpn --> serve
    tls -- no --> plain --> serve
    serve --> request
```

The connection keeps the SNI name its handshake asked for, for the Host check of each request.
With `WEB_RELOAD=lazy` or `drain` it also keeps the routing it was accepted with.

## A request

```mermaid
flowchart TD
    start(["request"]) --> internal{"asked by the server itself?<br/>(an API spec given as a path)"}
    internal -- no --> misdirected{"TLS, and the Host served with<br/>another certificate than the SNI's?"}
    misdirected -- yes --> r421["421 Misdirected Request"]
    misdirected -- no --> site
    internal -- yes --> site
    site{"a site for the Host?"}
    site -- no --> empty["empty 200, as Caddy"]
    site -- yes --> ip["client IP: the peer, or from<br/>trusted proxies' headers"]
    ip --> ready["ready answer looked up<br/>(path, Accept-Encoding)"]
    ready --> jwt
    subgraph checks ["request checks, before the routes (skipped for the server's own requests)"]
        jwt["JWT: claim headers taken off,<br/>the first rule without upstreams decides"]
        fw["API firewall: the first API<br/>without upstreams the path is under"]
        jwt --> fw
    end
    jwt -- refused --> refusal["401 / 403"]
    fw -- refused --> refusal2["403 / 413 / 415 / 503"]
    fw --> which{"ready answer?"}
    which -- yes --> answer["a copy of its headers,<br/>the file's bytes"]
    which -- no --> chain["the site's handler chain"]
    chain --> failed{"failed, and the site has<br/>handle_errors?"}
    failed -- yes --> errors["the error routes"]
    failed -- no --> out
    errors --> out
    answer --> out
    refusal --> out
    refusal2 --> out
    r421 --> out
    out["Date, Alt-Svc (TLS ports with HTTP/3);<br/>access log line when the response ends"]

    classDef feature stroke-dasharray: 5 5
    class jwt,fw,refusal,refusal2 feature
```

A refusal replaces the answer: it is logged in the site's access log like any other response, and
the check's event log says why (docs/configuration.md, Request checks).

## The handler chain

Outside `route` blocks the directives are sorted as Caddy sorts them; inside, they run in the
order written. Each step either changes the request and goes on, or answers; the diagram shows
the usual order of the steps a site has.

```mermaid
flowchart TD
    in(["request"]) --> mods["root, header, request_header,<br/>rewrite, uri strip_prefix (handle_path)"]
    mods --> body["request_body: a Content-Length over<br/>max_size is refused later with 413"]
    body --> rl{"rate_limit zone?"}
    rl -- over --> r429["429 Retry-After"]
    rl -- within --> cache{"cache: stored answer?"}
    cache -- "fresh or stale-while-revalidate" --> hitcheck{"checks bound to the<br/>upstream it came from"}
    hitcheck -- pass --> hit["answer from memory<br/>(best encoding, Age, Cache-Status)"]
    hitcheck -- refused --> hitref["401 / 403"]
    cache -- "miss: marked for the proxy" --> enc["encode: a hook on the response"]
    enc --> terminal{"the handler that answers"}
    terminal --> redir["redir / respond / error"]
    terminal --> files["file_server"]
    terminal --> proxy["reverse_proxy"]

    classDef feature stroke-dasharray: 5 5
    class rl,r429,cache,hitcheck,hit,hitref feature
```

### file_server

```mermaid
flowchart TD
    f(["file_server"]) --> find["the file in memory (or an index file);<br/>canonical trailing slash: 308"]
    find --> dict{"a compression dictionary offered<br/>(Available-Dictionary)?"}
    dict -- yes --> dcz["the file as a dcz delta,<br/>worked out once"]
    dict -- no --> rank["encodings the client takes,<br/>in precompressed's order"]
    rank --> sibling{".br / .zst / .gz sibling?"}
    sibling -- yes --> send
    sibling -- no --> variant{"compressed variant made?"}
    variant -- yes --> send
    variant -- "not yet" --> ask["queued for the variants' thread;<br/>this answer: the file as it is"]
    ask --> send
    send["304 for a matching ETag, ranges,<br/>or the whole representation"]
    send --> hook["encode hook: compresses what<br/>is not compressed yet, on the fly"]
    hook --> back(["response"])
    dcz --> back

    classDef feature stroke-dasharray: 5 5
    class variant,ask feature
```

A file larger than `WEB_MAX_FILE_IN_MEMORY` is streamed from disk instead, with one range at
most.

### reverse_proxy

```mermaid
flowchart TD
    p(["reverse_proxy"]) --> prep{"preparing ready answers?"}
    prep -- yes --> r502["502 at once: never kept"]
    prep -- no --> big{"body over request_body?"}
    big -- yes --> r413["413, the upstream not called"]
    big -- no --> bound["checks bound to this proxy's upstreams:<br/>JWT rules, then the API firewall"]
    bound -- refused --> refused["401 / 403 / 413 / 415 / 503"]
    bound -- pass --> slot{"WEB_MAX_UPSTREAM_REQUESTS_PER_IP"}
    slot -- over --> r429["429"]
    slot -- within --> ws{"WebSocket upgrade (HTTP/1.1)?"}
    ws -- yes --> tunnel["handshake to the upstream;<br/>on 101 a tunnel both ways"]
    ws -- no --> send["headers: hop-by-hop dropped,<br/>X-Forwarded-*, client identity headers<br/>only from trusted proxies, header_up"]
    send --> up["upstream: lb_policy, retries within<br/>lb_try_duration, response_header_timeout"]
    up --> resp{"response"}
    resp -- "502 / 504 / 408 / 413" --> fail["the failure, or a stored answer<br/>within stale-if-error"]
    resp -- ok --> tee["header_down; a cache miss's body<br/>kept on the side while it streams"]
    tee --> back(["response (encode hook)"])

    classDef feature stroke-dasharray: 5 5
    class bound,refused,slot,r429,tee feature
```

## In the background

```mermaid
flowchart LR
    subgraph files ["site files"]
        watch["web-watch: inotify, or polling<br/>(WEB_FILES_WATCH)"] --> rescan["rescan: new and changed files read,<br/>unchanged taken over"]
        rescan --> answers["ready answers worked out again<br/>(the real chain, every Accept-Encoding)"]
    end
    subgraph variants ["webfast-compress (compress-files)"]
        queue["queue of files asked for"] --> best["compressed at the highest level"]
        best --> store["kept within WEB_COMPRESSED_FILES_MEMORY<br/>(CLOCK eviction)"]
        store --> answers
    end
    subgraph cache ["web-cache (proxy-cache)"]
        cq["answers to store,<br/>revalidations"] --> cstore["every encoding made;<br/>kept within WEB_PROXY_CACHE_MEMORY"]
    end
    subgraph checks ["request checks (jwt, api-firewall)"]
        jwks["JWKS read again every<br/>jwks_cache_duration, sooner for a new key id"]
        spec["API specs looked at again every refresh<br/>(conditional requests), compiled off the request threads"]
    end
    certs["certificates: files looked at every minute"]
    reload["SIGHUP: the Caddyfile read again,<br/>put in place without dropping connections"]
    logs["log-writer: access and event logs,<br/>written in batches"]
```

## Where the features take part

| Feature          | Where                                                                         | What it adds                                                                                               |
| ---------------- | ----------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- |
| `jwt`            | `handle()` before the routes; `reverse_proxy` and `cache` hits for `upstreams` | JWT validation (`WEB_JWT_CONFIG`); claim headers set, the token taken off; `Credentialed` for the cache     |
| `api-firewall`   | `handle()` before the routes; `reverse_proxy` and `cache` hits for `upstreams` | OpenAPI request validation (`WEB_API_FIREWALL_CONFIG`); the body read once and passed on                   |
| `rate-limit`     | the `rate_limit` directive; `reverse_proxy` before the upstream               | requests per key and window; a client's requests at the upstreams at once                                  |
| `proxy-cache`    | the `cache` directive; `reverse_proxy` on a miss                              | proxied answers kept in memory, in every encoding, stale answers while revalidating or when the upstream fails |
| `compress-files` | `file_server` when a file has no precompressed sibling                        | compressed variants made in the background, served like siblings                                           |
| `mimalloc`       | the allocator                                                                 | mimalloc instead of the system's                                                                           |

The request checks are configured outside the Caddyfile, so an edit there cannot switch them off;
a check bound to an upstream that no `reverse_proxy` sends to stops the startup and a reload.
