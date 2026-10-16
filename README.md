# webfast

A static-first web server for sites that are built ahead of time. It holds the whole site in
memory, sends browsers the precompressed `.br` / `.zst` / `.gz` siblings the build made, proxies
the dynamic paths to the application behind it, and speaks HTTP/1.1, HTTP/2 and HTTP/3. It is
configured with a **strict subset of the Caddyfile**: the same file runs in Caddy, and the two are
compared request by request ([`compat/`](compat)).

```caddyfile
:8080 {
	root * /srv
	encode zstd br gzip
	reverse_proxy /api/* app:8787
	file_server {
		precompressed br zstd gzip
	}
}
```

## What it does differently

- **Files from memory, answers ready in advance.** Every site root is read at startup; requests
  never touch the disk. For each path that serves a file the full answer — the 200 with all its
  headers and the 304 for its ETag, for every way a browser can rank zstd, br and gzip — is worked
  out once by the real handler chain; a request is then a lookup (0.8–0.9 µs in process).
- **Changes picked up while running.** inotify on local filesystems, polling where events do not
  come (NFS, SMB, FUSE, 9p); only changed files are read again, and the site's snapshot is replaced
  whole, so a page and its assets switch together.
- **ETag = hash of the content** (BLAKE3): unchanged files keep their ETag across deploys and
  replicas.
- **A runtime per core**, as nginx's workers: one thread with its own epoll per listening socket
  (SO_REUSEPORT), connections stay where they were accepted; `WEB_WORKERS` sets how many.
- **Built with profile-guided optimisation** (the Docker image): 10–20 % less CPU per request.
- **Safe defaults against slow and greedy clients**: connection limits per address, header,
  idle and stall timeouts, a timeout for hung upstreams, bounded ranges, HTTP/3 frame limits.
- **TLS** with rustls on aws-lc-rs (post-quantum key exchange preferred), certificates re-read when
  renewed; **HTTP/3** with 0-RTT for safe methods.
- Unknown directives, options and placeholders stop the server at startup with the file and line,
  instead of being ignored.

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

## Quick start

With Docker — the image serves `/srv` with the configuration at `/etc/webfast/Caddyfile` (until
replaced, [`sample/Caddyfile`](sample/Caddyfile), which sends what is not a file to an app at
`app:8787`):

```bash
docker build -t webfast .
docker run --rm -p 8080:8080 -v "$PWD/public:/srv:ro" -v "$PWD/Caddyfile:/etc/webfast/Caddyfile:ro" webfast
```

From source (Rust 1.88 or later):

```bash
cargo build --release
target/release/webfast validate --config Caddyfile   # parse, compile, load the files; then exit
target/release/webfast run --config Caddyfile
target/release/webfast healthcheck http://127.0.0.1:8080/healthz
```

## Documentation

- [Configuration](docs/configuration.md): the Caddyfile subset, how it differs from Caddy, the
  environment variables.
- [Operations](docs/operations.md): the Docker image, running behind a proxy or with TLS and
  HTTP/3, the host's settings, logs, limits, changed files, workers.
- [Performance](docs/performance.md): how it is built for speed, and every measurement.
- [Development](docs/development.md): layout, checks, tests, the PGO build, the compatibility check
  and the benchmarks.
- [Changelog](CHANGELOG.md).

## Checks

```bash
scripts/check.sh          # formatting, lints, tests, the minimum Rust version, cargo-deny (in Docker)
```

The same jobs run in CI ([`.gitlab-ci.yml`](.gitlab-ci.yml)), which also builds the image.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in
webfast by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any
additional terms or conditions.
