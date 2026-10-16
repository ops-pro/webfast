# Operations

## Commands

```bash
webfast run --config /etc/webfast/Caddyfile   # serve (also accepted: --adapter caddyfile)
webfast validate --config Caddyfile           # parse, compile and load the files, then exit
webfast healthcheck http://127.0.0.1:8080/healthz   # exit 0 for a 2xx answer (the image's HEALTHCHECK)
webfast --version
```

SIGTERM or SIGINT stop it gracefully: no new connections, open ones are asked to finish (HTTP/2
and HTTP/3: GOAWAY), WebSocket tunnels are closed, and whatever is still open after
`grace_period` (30 s) is closed.

## Reloading

SIGHUP reads the Caddyfile again and puts it in place without dropping a connection:

```bash
kill -HUP "$(pidof webfast)"
docker kill --signal HUP web
systemctl reload webfast          # recipes/systemd: validates first, then sends SIGHUP
```

- Each port's sites, `trusted_proxies`, `client_ip_headers` and `grace_period` are replaced whole;
  the next request is answered by the new configuration, also on a connection that stays open,
  and a request under way finishes with the one it started with. The certificates are read again,
  and the ready answers are worked out for the new sites before anything changes.
- Site roots that stay are taken over as they are, not read again (with `WEB_FILES_WATCH` on they
  are looked at again at once, as at startup); new roots are loaded, and what all of them take
  must fit `WEB_MAX_MEMORY`.
- What only a restart can change is refused: other ports, TLS on or off on a port, `protocols`,
  `timeouts`, and the `WEB_*` variables (read at startup). The `debug` option takes effect on a
  restart.
- A reload that fails — a syntax error, a root that is missing, a certificate that cannot be read,
  one of the above — changes nothing: the log says `configuration not reloaded; the running one
  stays` with the reason. A reload that succeeds says `configuration reloaded`.
- With `WEB_FILES_WATCH=off` a root is held in one buffer for the life of the process: a root that
  a reload drops keeps its memory until a restart.

## The Docker image

[`Dockerfile`](../Dockerfile) builds webfast with profile-guided optimisation (`--build-arg
WEBFAST_PGO=0` builds without it, in about half the time) on Debian slim:

| What          | Where                                                                                 |
| ------------- | ------------------------------------------------------------------------------------- |
| binary        | `/usr/local/bin/webfast`, the entry point; `CMD run --config /etc/webfast/Caddyfile`  |
| configuration | `/etc/webfast/Caddyfile` and `/etc/webfast/headers.caddy`: the sample, until replaced |
| site          | `/srv`, empty until a site is mounted or copied in                                    |
| user          | 10002:10002, no capabilities needed (ports above 1024)                                |
| port          | 8080; add 443/tcp and 443/udp when it terminates TLS itself                           |
| health        | `webfast healthcheck http://127.0.0.1:8080/healthz` every 30 s                        |

The sample configuration sends every path that is not a file to `app:8787` and the event stream to
`stream:8800`; for a static site alone, mount a Caddyfile of your own:

```bash
docker run -d --name web -p 8080:8080 --read-only --cap-drop ALL \
  -v "$PWD/public:/srv:ro" -v "$PWD/Caddyfile:/etc/webfast/Caddyfile:ro" webfast
```

A site baked into an image of its own:

```dockerfile
FROM webfast
COPY --chown=10002:10002 public/ /srv/
COPY Caddyfile /etc/webfast/Caddyfile
```

## Behind a reverse proxy

The sample listens on plain HTTP and expects a proxy in front that terminates TLS and forwards the
original `Host` and `X-Forwarded-For` / `X-Forwarded-Proto`. List the proxies in `servers {
trusted_proxies static … }` (the sample trusts private ranges): only their `X-Forwarded-*` headers
are believed, and with `trusted_proxies_strict` the client is the right-most address that is not a
proxy (a client can write anything into the left-most). Requests from trusted proxies are not
limited per address. Publish the port only to the proxy: anyone who can reach it from a private
address may set `X-Forwarded-For`.

## TLS and HTTP/3

Give a site host names and `tls <cert.pem> <key.pem>`, and publish 443/tcp and 443/udp:

```caddyfile
example.com, www.example.com {
	tls /certs/fullchain.pem /certs/privkey.pem
	root * /srv
	file_server
}
```

- rustls on aws-lc-rs: TLS 1.3 and 1.2, the post-quantum key exchange X25519MLKEM768 preferred,
  ML-DSA certificates accepted; the certificate is chosen by SNI.
- The PEM files are looked at every minute and re-read when they change (renewals); there is no
  ACME client — certbot, lego or acme.sh write the files.
- HTTP/2 over TLS; HTTP/3 (QUIC) on the same port number over UDP, advertised with `Alt-Svc`.
- Resumption: TLS 1.3 session tickets (their keys live in the process: after a restart, or on
  another replica, a full handshake) and a cache of 16 384 sessions.
- HTTP/3 0-RTT: a resumed client sends its first request with the handshake. Early requests are
  answered only for GET, HEAD and OPTIONS, which change nothing if replayed, and reach the
  handlers with `Early-Data: 1`; anything else gets `425 Too Early` and the browser sends it again
  after the handshake (RFC 8470). TCP takes no early data.

## The host

The listening sockets are tuned (Linux; an option the system refuses stays at its default, with a
warning at startup): BBR congestion control (`WEB_TCP_CONGESTION`), `TCP_NOTSENT_LOWAT` 16 KiB (so
HTTP/2 can send an urgent stream before a long one), `TCP_DEFER_ACCEPT`, `TCP_USER_TIMEOUT` =
`WEB_STALL_TIMEOUT` and keepalive probes (dead peers are dropped by the kernel), a listen backlog
of 4096, and 4 MiB UDP buffers for HTTP/3. For all of them to take effect:

```bash
# BBR: the module, and allowed for unprivileged containers (or made the host's default)
modprobe tcp_bbr
sysctl -w net.ipv4.tcp_allowed_congestion_control="reno cubic bbr"
# or: sysctl -w net.core.default_qdisc=fq net.ipv4.tcp_congestion_control=bbr
# UDP buffers for HTTP/3
sysctl -w net.core.rmem_max=4194304 net.core.wmem_max=4194304
```

Per container (Docker `--sysctl` or compose `sysctls:`): `net.ipv4.tcp_slow_start_after_idle=0` (a
keep-alive connection keeps its congestion window across pauses, so the next page does not start
slowly) and `net.core.somaxconn=4096`.

Restarts without a gap: the listening sockets use SO_REUSEPORT, so a new process can bind the port
while the old one drains its connections.

## Workers

`WEB_WORKERS` (default: one per CPU the process may use; a container's `cpus` limit or CPU set
counts) sets the listening sockets per port, so the threads that serve the connections. Each has
its own runtime and epoll, and a connection stays on the thread that accepted it. Flat out, one
worker is at most one core. Under light load fewer cost less: connections are spread over all
workers, and a thread that gets a request only every few milliseconds finds its CPU caches cold —
at 1000 requests/s on 8 CPUs a request cost 69 µs of CPU with 8 workers, 57–58 with 2 and 49 with
1. A small site with little traffic does well with 1–2. One HTTP/2 connection carrying many
clients (a CDN in front) is served by one core.

## Files and memory

The site roots are read at startup on every CPU and held in memory, at most `WEB_MAX_MEMORY` over
all of them. Text files of up to 1 MiB are kept as LZ4 blocks when that saves at least
`WEB_LZ4_MIN_SAVING` percent; only a response that sends their bytes as they are (a client without
Accept-Encoding, a range) decompresses them — about 10 µs for a 30–80 KB page. Browsers get the
precompressed siblings, which stay as they are.

Changed files are picked up while the server runs (`WEB_FILES_WATCH=auto`):

- on a local filesystem (ext4, xfs, btrfs, zfs, overlay, tmpfs, …) a watch per directory, nothing
  done until an event comes; after a burst (200 ms without events, at most 2 s) the root is looked
  at again;
- on NFS, SMB, FUSE or 9p (WSL's `/mnt/*`, Docker Desktop's bind mounts), where changes made by
  another system raise no event, the root is looked at every `WEB_FILES_POLL` (30 s);
- a look compares each file's size, modification time, inode and status-change time with what was
  read and reads only what differs; the snapshot of the site is replaced whole, a request keeps the
  one it found;
- files that changed while being read are looked at again half a second later; new directories are
  watched at once; a root that is a symlink is followed when it is switched;
- a change that would not fit `WEB_MAX_MEMORY` is not taken (the log says so).

A changed page is served about 0.6 s after it was written. Each new version of a file keeps about
30 bytes (its ETag and length) for the life of the process. `WEB_FILES_WATCH=off` keeps the files as
loaded and holds them in one buffer, with a little less memory (2–3 MiB).

## Logs

The server's own log is JSON lines on stderr (`LOG_LEVEL`). At startup it says what was loaded and
what it cost — per root `site files loaded` (files, bytes, bytes in memory, files in LZ4, ms) and
`watching the site files` (`inotify` with the directories watched, or `poll` with the interval and
why), per site `ready answers for the site's files` (paths, distinct answers, their memory, ms; or
why there are none) — and then one summary:

```json
{
  "message": "started",
  "ports": 1,
  "files": 1000,
  "files_mib": 30.0,
  "files_in_memory_mib": 19.0,
  "lz4_files": 250,
  "ready_paths": 300,
  "ready_answers": 1050,
  "ready_mib": 3.8,
  "ready_ms": 51,
  "resident_mib": 48.5,
  "startup_ms": 141
}
```

Later, per change: `site files changed` (added, changed, removed, ms) and `ready answers worked out
again`. `webfast validate` prints the same for the files: `valid configuration: 1 port(s), 1
site(s), 1000 files (30 MiB; 19 MiB in memory, 250 in LZ4), loaded in 92 ms`.

Access logs go where a site's `log` block says (`stdout`, `stderr`, `discard`), one line per request
when its response has been sent: JSON in Caddy's shape (`logger: http.log.access`, `msg: handled
request`) or a console line. Request headers are not logged (they carry cookies). Lines are written
in batches (`WEB_LOG_FLUSH_MS`); a full queue drops lines instead of slowing requests, and says how
many.

## Limits

What keeps one client from holding the server:

| Threat                                                | Limit                                                                                                                                                             |
| ----------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Many connections (one address, or many)               | `WEB_MAX_CONNECTIONS_PER_IP` (256; an IPv6 /64 is one address; trusted proxies exempt) and `WEB_MAX_CONNECTIONS` (16 384), TCP and QUIC together: refused at once |
| Slowloris: headers sent byte by byte                  | `timeouts { read_header }` (30 s) for the whole header block; the TLS handshake gets 10 s                                                                         |
| Connections opened and left silent                    | HTTP/2 and HTTP/3 must send their first request within `read_header` (HTTP/1.1 already must)                                                                      |
| Idle keep-alive connections                           | `timeouts { idle }` (5 min, Caddy's default) with no request in progress: graceful close (GOAWAY); one that has not finished 10 s later is cut                    |
| Slow reader: a response the client stops taking       | `WEB_STALL_TIMEOUT` (30 s) with the socket accepting nothing (HTTP/3: the stream) cuts the connection; a slow but moving download is fine                         |
| Slow sender: a request body the client stops sending  | `WEB_STALL_TIMEOUT` with no body data arriving ends the body; the proxy answers 408 and the upstream connection is freed                                          |
| Hung upstream (headers never come)                    | `reverse_proxy` `response_header_timeout`, 60 s by default (Caddy: none; `0` restores that): 504                                                                  |
| Range header asking for thousands of parts            | more than 64 ranges, or overlapping ones, are ignored and the whole file is sent (200), as Go does for ranges adding up to more than the file                     |
| Redirect targets built from the path                  | `redir` and the canonical trailing-slash redirect turn a leading `//host` or `/\host` into `/host`, so no path can send a browser off the site                    |
| Headers an upstream trusts for the client's identity  | `X-Real-IP`, `CF-Connecting-IP`, `CF-IPCountry`, `Forwarded`, … are dropped unless the peer is a trusted proxy                                                    |
| HTTP/3 headers of any size (h3 buffers a frame whole) | frames other than DATA over 64 KiB end the stream (`H3_EXCESSIVE_LOAD`), also on the control and QPACK streams; `SETTINGS_MAX_FIELD_SECTION_SIZE` 64 KiB          |
| QUIC handshake floods from spoofed addresses          | with 64 handshakes under way, unproven addresses get a Retry first; at most 4096 handshakes queued, 32 MB of their packets                                        |
| HTTP/2 Rapid Reset, CONTINUATION flood, MadeYouReset  | h2 0.4.20 or later; 250 streams per connection, 16 KiB of headers                                                                                                 |
| A file that one request would make the server unpack  | LZ4 only for files of up to 1 MiB, so `Range: bytes=0-0` decompresses at most that                                                                                |
| WebSocket tunnels held open                           | a tunnel keeps its connection's place, so the connection limits count it; the idle and stall timeouts end with the handshake (a quiet socket is a live one)       |
