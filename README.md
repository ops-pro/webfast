# webfast

[![CI](https://github.com/ops-pro/webfast/actions/workflows/ci.yml/badge.svg)](https://github.com/ops-pro/webfast/actions/workflows/ci.yml)

A web server for the most common small deployment: a front end built ahead of time, an
application behind it for the dynamic paths, HTTPS in front. It is configured with a **strict
subset of the Caddyfile** and is a **drop-in for Caddy** in that role: the same file, the same
image layout, the same answers request by request ([`compat/`](compat)) — several times faster,
and safe by default.

```caddyfile
example.com {
	root * /srv
	encode zstd br gzip
	reverse_proxy /api/* app:8787
	file_server {
		precompressed br zstd gzip
	}
}
```

That is a complete configuration: the certificate comes from Let's Encrypt and is renewed, HTTP
redirects to HTTPS, the site is served from memory with the precompressed files the build made,
`/api/*` goes to the application, and HTTP/1.1, HTTP/2 and HTTP/3 are all on.

## Why, for a static front end with a backend

- **The site is in memory and the answers are ready.** Every file of the site is read at start
  (and again when it changes); for each path the whole answer — status, headers, the 304 for its
  ETag, each of zstd, br and gzip — is worked out once. A request for a file is a lookup: a few
  microseconds of CPU, where Caddy spends hundreds. On the same machine that is 230 thousand
  requests a second against Caddy's 31 thousand, with the same Caddyfile
  ([How it compares](#how-it-compares)).
- **The application sees only what it should.** The dynamic paths are proxied with streaming
  (server-sent events as they come), WebSocket, retries and balancing over several instances
  (every `lb_policy` of Caddy, passive health, names resolved in the background), and a client's
  requests at the upstreams are counted and bounded. Headers that name the client are accepted
  only from the proxies you trust, so the application cannot be fed a made-up address.
- **Safe without configuration.** Connection limits per address, header, idle and stall
  timeouts, a timeout for a hung upstream, request bodies bounded before the upstream is called,
  no certificate for a handshake without SNI or for a name no site serves (scanners see nothing),
  421 for a Host that another certificate serves; a setting that is not understood stops the
  server at start with the file and line, instead of being ignored. JWT and OpenAPI request
  validation can be put in front of the application without touching it (configured outside the
  Caddyfile, so an edit there cannot switch them off).
- **One static binary, 26 MB, on an empty image.** No shell, no libc, no package manager,
  nothing to scan or to exploit but the server; runs as an ordinary user; HTTPS, HTTP/3 and the
  certificates need no other container.
- **A deploy costs the browser a delta.** Compression dictionaries (RFC 9842, `dcz`): a returning
  visitor gets the new bundle as a difference to the one it has, 170 bytes instead of 229 KB for a
  script with a few changed lines. ETags are hashes of the content, so unchanged files keep
  theirs across deploys and replicas.

## Drop-in for Caddy

The scenarios it covers whole: a static site, a static site with an application behind it, TLS
terminated here with certificates from Let's Encrypt (HTTP-01, TLS-ALPN-01) or your own files.
The Caddyfile is read as Caddy reads it; what Caddy has and this does not is refused at start
with the file and line, never ignored — so a Caddyfile that starts is one that behaves the same.
[docs/configuration.md](docs/configuration.md) lists the subset and every difference.

The `-caddy` image has the official image's layout, so a Compose file changes only its image
line:

```yaml
services:
  web:
    image: ghcr.io/ops-pro/webfast:latest-caddy   # was: caddy:2
    ports: ["80:80", "443:443", "443:443/udp"]
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile:ro
      - ./public:/usr/share/caddy:ro
      - caddy_data:/data
      - caddy_config:/config
volumes:
  caddy_data:
  caddy_config:
```

`caddy run`, `caddy validate`, `caddy reload` and `--envfile` work as the commands they replace
(`reload` sends the server SIGHUP; there is no admin API). What is not there, by design: DNS
challenges and wildcard certificates, `tls internal`, on-demand TLS, the admin API, Caddy's
plugins, `php_fastcgi` (for now), and anything that needs a request to be buffered whole. For
those, Caddy.

## How it compares

The same site (1000 files, 30 MiB with the precompressed siblings), the same response headers
configured in each server, on 8 CPUs under WSL2 with the load generator on the same machine
(2026-10-15, two passes in opposite order; [docs/performance.md](docs/performance.md)):

| Server              | requests/s, 32 connections | requests/s, 128 connections | CPU per request at 1000 requests/s | memory    |
| ------------------- | -------------------------- | --------------------------- | ---------------------------------- | --------- |
| **webfast** (PGO)   | 178–187 thousand           | 228–229 thousand            | 61–69 µs                           | 56–60 MiB |
| nginx 1.28          | 140–149 thousand           | 184–185 thousand            | 68–81 µs                           | 30 MiB    |
| lighttpd 1.4        | 53 thousand                | 58–60 thousand              | 51–57 µs (one thread)              | 2 MiB     |
| static-web-server 2 | 75–76 thousand             | 104–106 thousand            | 81–102 µs                          | 22 MiB    |
| Caddy 2             | 30 thousand                | 31–32 thousand              | 286–387 µs                         | 39–40 MiB |

With one worker (`WEB_WORKERS=1`) a request at 1000 requests/s costs 49 µs, less than lighttpd's.

## What it does, in more detail

- **Changes picked up while running.** inotify on local filesystems, polling where events do not
  come (NFS, SMB, FUSE, 9p); only changed files are read again, and the site's snapshot is replaced
  whole, so a page and its assets switch together. A changed Caddyfile is put in place on SIGHUP,
  without dropping a connection. `WEB_FILES_WATCH=off` keeps the files as loaded at start.
- **A runtime per core**, as nginx's workers: one thread with its own epoll per listening socket
  (SO_REUSEPORT), connections stay where they were accepted; `WEB_WORKERS` sets how many.
- **Built with profile-guided optimisation** (the Docker image): 10–20 % less CPU per request.
- **TLS** with rustls on aws-lc-rs (post-quantum key exchange preferred); **HTTP/3** with 0-RTT
  for safe methods; certificate compression; several certificates per site, each client gets one
  it can verify.
- **Error pages** with `handle_errors`; **rate limits** with `rate_limit` and a **proxy cache**
  with `cache`, in the syntax of Caddy's caddy-ratelimit and cache-handler plugins (the cache
  answers the first client as the upstream sends, then keeps every encoding, made once at the
  highest levels in the background).
- Every optional piece is a cargo feature, on by default, that costs nothing when it is off or
  unused ([docs/extensions.md](docs/extensions.md)).

## Quick start

With Docker — the image serves `/srv` with the configuration at `/etc/webfast/Caddyfile` (until
replaced, [`sample/Caddyfile`](sample/Caddyfile), which sends what is not a file to an app at
`app:8787`); the `-caddy` image serves `/usr/share/caddy` with `/etc/caddy/Caddyfile`:

```bash
docker run --rm -p 8080:8080 -v "$PWD/public:/srv:ro" -v "$PWD/Caddyfile:/etc/webfast/Caddyfile:ro" ghcr.io/ops-pro/webfast:latest
```

From source (Rust 1.88 or later):

```bash
cargo build --release
target/release/webfast validate --config Caddyfile   # parse, compile, load the files; then exit
target/release/webfast run --config Caddyfile
target/release/webfast reload --config Caddyfile --pid <pid>
target/release/webfast healthcheck http://127.0.0.1:8080/healthz
```

[Recipes](recipes) has complete configurations for common setups — a static site, a single-page
app, a site in front of an application (with docker-compose.yml), behind nginx or another proxy,
HTTPS and HTTP/3 served directly, a hardened systemd service — each checked by the tests.

## Documentation

- [Recipes](recipes): configurations for common setups.
- [Configuration](docs/configuration.md): the Caddyfile subset, automatic certificates, upstreams
  and balancing, what `reverse_proxy` reads and what not, how it differs from Caddy, the
  environment variables.
- [Operations](docs/operations.md): the images (static, on `scratch`; the Caddy-compatible one),
  running behind a proxy or with TLS and HTTP/3, the host's settings, logs, limits, changed files,
  workers.
- [Overview](docs/overview.md): how a connection and a request are handled, with diagrams, and
  where each cargo feature takes part.
- [Extensions](docs/extensions.md): how the optional pieces plug in: hook traits composed at
  compile time, one worker and one memory budget.
- [Automatic certificates](docs/acme.md) and [upstream names](docs/dns.md): the designs.
- [Performance](docs/performance.md): how it is built for speed, and every measurement.
- [Development](docs/development.md): layout, checks, tests, the PGO build, the compatibility check
  and the benchmarks.
- [Changelog](CHANGELOG.md).
- [Security policy](SECURITY.md): how to report a vulnerability, privately.

## Checks

```bash
scripts/check.sh          # formatting, lints, tests, the minimum Rust version, cargo-deny (in Docker)
```

The same jobs run in CI ([`ci.yml`](.github/workflows/ci.yml)); [`release.yml`](.github/workflows/release.yml)
builds the images for x86-64 and arm64 (`ghcr.io/ops-pro/webfast`, and `-caddy`) and the static
binaries, with provenance attestations.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in
webfast by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any
additional terms or conditions.
