# Performance

How webfast is built for speed, and what was measured. The measurements use a production site of
1000 files (30 MiB with its precompressed siblings; pages of about 77 KB, 11 KB as br) on 8 CPUs
under WSL2 with Docker's bridge network, where most of a request's CPU time is the kernel's network
stack and there are no hardware performance counters (profiles use `perf record -e cpu-clock`).
Numbers from different days differ — the VM's network path varies — so what is compared was
measured in one sitting, in alternating order.

## Design

- **Files from memory.** Every root is read once, on every CPU, then kept by the main thread, so
  the loading threads' memory goes back (mimalloc's `mi_collect`): about 25 ms for the files, 49
  MiB resident in all (one by one it was 60 ms and 66 MiB; kept on the loading threads, 160 MiB).
  Text of up to 1 MiB is kept in LZ4 when that saves 25 %: 30 MiB take 19 MiB.
- **Ready answers** (src/memo.rs). When a site's routes decide by the request path alone (no host,
  method, header or address matchers, no `request_header`, only path-derived placeholders), the
  answer for every path that serves a file — the 200 with all its headers and the 304 for its ETag,
  for each of the 26 ways Accept-Encoding can rank zstd, br and gzip — is worked out by running the
  real handler chain at startup and after a change (40–85 ms). A GET or HEAD for such a path is a
  lookup and a copy of a header map; ranges, If-Match, another If-None-Match, other spellings of a
  path and files compressed on the fly take the chain. The reference site: 300 paths, 1050
  distinct answers, 3.8 MB. Header values are interned (`'static`), so a response's copy counts no
  references.
- **One `Date` for all threads**: formatted by a background thread just after each second starts
  and copied by each thread once a second: 26–28 ns per response on 1 or 8 threads. One value
  cloned by all threads costs 35 ns alone but 830–880 ns on 8 (they fight over its reference
  count); formatting it per response, 120–130 ns.
- **A runtime per core**: each listening socket (SO_REUSEPORT, one per worker) gets a thread with a
  single-threaded tokio runtime and its own epoll; connections stay there, no work is handed between
  threads. HTTP/3 runs on the shared runtime (quinn drives one UDP socket).
- **Three system calls per request** on a keep-alive connection: `epoll_wait`, `recvfrom`, `writev`
  (headers and body in one) — strace, 1000 requests/s.
- **Compression off the request threads**: an on-the-fly body over 64 KiB is compressed on the
  blocking pool, so a worker does not spend milliseconds of Brotli while other requests wait;
  bodies of known length up to 1 MiB are compressed whole and sent with `Content-Length`, streams
  frame by frame.
- **Build**: one codegen unit, fat LTO, mimalloc, and profile-guided optimisation (below).

## Against other servers

The same site and response headers in each server, the load generator (oha) on the same CPUs,
2026-10-15, two passes in opposite order. At 1000 requests/s (20 connections) server CPU per
request for a page as br, an asset, a 304 and the page without Accept-Encoding; then as fast as it
goes:

| Server              | CPU per request at 1000/s, µs (page / asset / 304 / raw) | 32 connections   | 128 connections  | CPU per request flat out | memory    |
| ------------------- | -------------------------------------------------------- | ---------------- | ---------------- | ------------------------ | --------- |
| webfast, PGO        | 64–68 / 64–69 / 61–62 / 63–68                            | 178–187 thousand | 228–229 thousand | 17.4 µs                  | 56–60 MiB |
| webfast without PGO | 73–74 / 71–75 / 71 / 74                                  | 179–181 thousand | 226–233 thousand | 18.3–18.6 µs             | 57–59 MiB |
| nginx 1.28          | 77–79 / 75–80 / 68–70 / 77–81                            | 140–149 thousand | 184–185 thousand | 22.7–23.2 µs             | 30 MiB    |
| lighttpd 1.4.85     | 55–57 / 53 / 51–53 / 56–57                               | 53 thousand      | 58–60 thousand   | 18.9 µs                  | 2 MiB     |
| static-web-server 2 | 101–102 / 94–95 / 81–82 / 99–102                         | 75–76 thousand   | 104–106 thousand | 42 µs                    | 22 MiB    |
| Caddy 2             | 385–387 / 380 / 286 / 380–384                            | 30 thousand      | 31–32 thousand   | 164 µs                   | 39–40 MiB |

At 1000 requests/s latencies were alike for webfast, nginx and lighttpd (p50 about 0.19 ms). Flat
out the load generator shares the CPUs, so the ceiling is the machine's; there PGO shows in the CPU
per request rather than in requests per second. Memory is the price of the files and ready answers
held in memory.

Why lighttpd costs less at light load: one thread. A request cost (user / system / all, µs, and
context switches; 1000 requests/s):

| Server              | user  | system | all   | switches |
| ------------------- | ----- | ------ | ----- | -------- |
| webfast, 8 workers  | 14–19 | 51–55  | 69    | 0.97     |
| webfast, 4 workers  | 13–14 | 47–48  | 61    | 0.96     |
| webfast, 2 workers  | 11–15 | 44–47  | 57–58 | 0.91     |
| webfast, 1 worker   | 10–11 | 38–39  | 49    | 0.85     |
| lighttpd (1 thread) | 12    | 46     | 57    | 0.84     |
| nginx, 8 workers    | 21–22 | 60–63  | 81–84 | 0.97     |
| nginx, 1 worker     | 12–15 | 41–44  | 55–56 | 0.84     |

Spread over 8 threads, each gets a request every 8 ms and finds its caches and TLB cold; one thread
stays warm. lighttpd makes 8 system calls per request (two `read`, two `epoll_ctl`, `epoll_pwait`,
`pread`, `stat`, `writev`), webfast 3 — with one worker it costs less than lighttpd in the kernel
and in its own code. Hence `WEB_WORKERS` (docs/operations.md, Workers).

## Profile-guided optimisation

`pgo/build.sh` (the Docker image's build): an instrumented build serves the sample site
(`examples/train.rs site`: pages in four languages, hashed assets, fonts, images, `.br`/`.zst`/`.gz`
siblings) with `sample/Caddyfile`, plain and over TLS, while `examples/train.rs run` sends 15 s of
every kind of request over HTTP/1.1, HTTP/2 and HTTP/3 and plays the upstreams (answers compressed
on the fly, whole, on the blocking pool and streamed; an event stream). The release build is then
optimised by the profile. The training needs no network and nothing from a site's build, so the
stage is cached until the code changes; it doubles the build time. What the training never runs is
optimised as cold code, so new kinds of work belong in `examples/train.rs` too.

In process, against the plain release build (medians of 3 alternating rounds, ns):

| Request                      | plain  | PGO, sample site | PGO, trained on the reference site | x86-64-v3 | PGO + x86-64-v3 |
| ---------------------------- | ------ | ---------------- | ---------------------------------- | --------- | --------------- |
| page, through the chain      | 3 559  | 2 830 (−20 %)    | 2 752 (−23 %)                      | +1 %      | −22 %           |
| 304, through the chain       | 3 479  | 2 741 (−21 %)    | 2 686 (−23 %)                      | 0 %       | −23 %           |
| build asset, through chain   | 3 221  | 2 649 (−18 %)    | 2 604 (−19 %)                      | +1 %      | −20 %           |
| redirect (`.html`)           | 2 812  | 2 403 (−15 %)    | 2 359 (−16 %)                      | 0 %       | −18 %           |
| internal path, 404           | 1 679  | 1 308 (−22 %)    | 1 304 (−22 %)                      | −2 %      | −25 %           |
| page, ready answer           | 931    | 851 (−9 %)       | 860 (−8 %)                         | +1 %      | −9 %            |
| 304, ready answer            | 888    | 831 (−6 %)       | 834 (−6 %)                         | −6 %      | −12 %           |
| page without Accept-Encoding | 11 382 | 11 715 (+3 %)    | 11 974 (+5 %)                      | +6 %      | +8 %            |

(The x86-64-v3 columns come from another sitting against its own plain build; the last row is LZ4
decompression of 77 KB, which no build made faster.) Under load, 1000 requests/s, server CPU per
request: plain 105–127 µs, PGO 92–108 µs. There is no `-C target-cpu`: x86-64-v3 (AVX2, BMI2) was
no faster with or without the profile, and the libraries with vector loops — memchr, aws-lc,
BLAKE3, zstd — choose them at runtime.

## Watching files

Watched files lie in shared buffers of about 1 MiB (each file in a buffer of its own took 16 MiB
more of the heap), freed when no snapshot or response holds any of their files, and copied into new
ones when replaced files fill more than a quarter of them. Unwatched (`WEB_FILES_WATCH=off`) they
lie in one buffer for good and a response's copy of a body counts no references. No difference
measured: 97–105 µs of CPU per request at 1000 requests/s watched, 99–104 off; flat out 160–170
thousand requests/s over 32 connections and 209–214 thousand over 128 either way. Resident 60–62
MiB watched, 57–59 off; over 30 rounds of replacing 93 files the allocator settles about 15 MiB
higher (it keeps freed memory for reuse; no growth). One changed page: 3–12 ms to look at the root,
65–85 ms to work the answers out again, served about 0.6 s after the write. Under load (133
thousand requests/s, the page rewritten every 100 ms, every asset once): all 1.3 million responses
200, the 100 changes looked at 6 times.

## Compression dictionaries

A 229 KB script whose new version changes 31 of its 3000 lines, in Chromium 152 with the old
version stored as a dictionary (2026-10-17): the response came as `dcz`, 170 bytes of body (470
transferred), and the page read the new version whole. Without a dictionary it takes 4.9 KB as
zstd at level 19, 6.0 KB as Brotli 11, 15.7 KB as gzip 9. A delta is worked out once per file and
dictionary on the blocking pool and kept.

## Large files from disk

A 300 MB file over `WEB_MAX_FILE_IN_MEMORY`, from the page cache, plain release build, loopback
(2026-10-17): four downloads at once took 0.68 s, about 0.5 GB/s each, every byte as on disk.
Resident memory over rounds of 16 downloads at once: 24 MB idle, 47–55 MB after each round,
with no growth over 8 rounds. Two things decided that: the 64 KiB pieces (256 KiB ones went
0.9–1.7 GB/s per download but held 85–100 MB), and allocating each piece on the connection's
thread — allocated on the blocking pool's threads, the pieces stayed in those threads' heaps,
240 MB after one round and growing.

## Reloading

What a request pays for the configuration to be replaceable (SIGHUP; docs/operations.md,
Reloading): with `WEB_RELOAD=immediate` one atomic read of the port's current configuration (an
`ArcSwap` load: a slot of the thread's own, no shared reference count); with `lazy` nothing, the
connection holds its configuration. A request's other reference counts are its connection's own:
the port's state and the WebSocket bookkeeping are held once per connection (before, every
request cloned the port's state and the server's stop signal, counts that all connections share).

Plain release builds (no PGO), the sample site, 2026-10-16, two passes in opposite order; at 1000
requests/s server CPU per request, median of 12 runs; as fast as it goes over 128 connections,
requests per second, median of 8 runs:

| Build                                              | CPU µs at 1000/s (page / asset / redirect) | thousand/s flat out (page / asset / redirect) | CPU µs flat out, page |
| -------------------------------------------------- | ------------------------------------------ | --------------------------------------------- | --------------------- |
| before WebSocket and reloading                     | 163.7 / 170.3 / 168.9                      | 161 / 138 / 165                               | 20.9                  |
| WebSocket (a per-request clone of the stop signal) | 163.3 / 169.2 / 169.7                      | 167 / 145 / 164                               | 20.6                  |
| reloading, the configuration read per request      | 165.0 / 168.9 / 168.1                      | 163 / 147 / 163                               | 21.2                  |
| now, `WEB_RELOAD=immediate`                        | 162.4 / 170.4 / 167.7                      | 164 / 148 / 158                               | 20.8                  |
| now, `WEB_RELOAD=lazy`                             | 168.4 / 172.9 / 172.8                      | 166 / 145 / 162                               | 20.7                  |

No difference within the noise: a variant's own runs spread over 10–25 µs at 1000 requests/s and
by 10–30 thousand requests/s flat out, while what is measured costs nanoseconds. The choice
between the modes is about what open connections get after a reload, not about speed.

## The way here

Handler chain in process, a page as br (precompressed):

| Version                                                                                                                                                                                                         | ns     | TSC ticks | allocations | bytes allocated |
| --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ | --------- | ----------- | --------------- |
| first version                                                                                                                                                                                                   | 10 402 | –         | –           | –               |
| path normalised once, patterns and regexp groups prepared at load, header values built once, `try_files` in one buffer                                                                                          | 5 954  | –         | –           | –               |
| `rewrite` without the decode round trip, FxHash file table                                                                                                                                                      | 5 853  | –         | –           | –               |
| same, measured with the counting allocator                                                                                                                                                                      | 6 370  | 20 303    | 64          | 43 286          |
| one loop for the chain (no future per handler), deferred `header`/`encode` as response hooks, Accept-Encoding parsed once, no copies of path and Host, `'static` header values, connection facts per connection | 3 825  | 12 191    | 29          | 8 922           |
| release profile: one codegen unit, fat LTO                                                                                                                                                                      | 3 997  | 12 740    | 29          | 8 922           |
| mimalloc as the global allocator                                                                                                                                                                                | 3 645  | 11 618    | 29          | 8 922           |
| `Content-Length` and `Content-Type` of every file prepared at load                                                                                                                                              | 3 566  | 11 364    | 26          | 8 874           |

(The allocation counts include building the test request: 6 allocations, 709 bytes. Fat LTO alone
was within the noise of ±5 % in process; its gain shows under load.) A 304 for the same page cost
3 829–3 956 ns and 28 allocations until the ETag comparison stopped copying strings, the `encode`
suffix check stopped formatting, and the 304 was answered before `Content-Type` and
`Content-Encoding` were set: now 3 580–3 615 ns and 24, no dearer than the 200.

Ready answers against the chain, same binary:

| Request                         | through the chain   | ready answer      |
| ------------------------------- | ------------------- | ----------------- |
| page, in process                | 3 639 ns, 26 allocs | 883 ns, 10 allocs |
| 304 for it, in process          | 3 607 ns, 24 allocs | 853 ns, 8 allocs  |
| build asset, in process         | 3 281 ns, 26 allocs | 888 ns, 10 allocs |
| page via socket, back to back   | 11–12 µs            | 4.0–4.3 µs        |
| page via socket, after 1 s idle | 26–36 µs            | 9–12 µs           |
| 304 via socket, back to back    | 11–12 µs            | 3.5–3.9 µs        |
| 304 via socket, after 1 s idle  | 24–34 µs            | 9–10 µs           |

(Through a socket: the access log's `duration`, one request at a time; after a second of idle the
CPU caches and TLB have gone cold under the VM, whatever the handler. Caddy, same Caddyfile and
requests: 40–255 µs.)

Files kept in LZ4, in process (`identity:` requests send the file's own bytes):

| Request                                     | `WEB_LZ4_MIN_SAVING=off` | 25 (default)                                             |
| ------------------------------------------- | ------------------------ | -------------------------------------------------------- |
| page without Accept-Encoding (77 KB)        | 0.72 µs                  | 11.7 µs (decompressed)                                   |
| build asset without Accept-Encoding (32 KB) | 0.72 µs                  | 9.9 µs                                                   |
| page as br; its 304                         | 0.91 µs; 0.85 µs         | the same (a .br sibling does not shrink, stays as it is) |
| files in memory; process resident           | 30 MiB; 78.2 MiB         | 19 MiB; 65.9 MiB                                         |
| loading the files                           | 28 ms                    | 61 ms (compressing, checking every block once)           |

Load test, 1000 requests/s, page / asset / redirect, in one sitting:

| Build                                  | p50 ms                | p99 ms                | server CPU µs per request |
| -------------------------------------- | --------------------- | --------------------- | ------------------------- |
| thin LTO, system allocator             | 0.391 / 0.387 / 0.377 | 1.641 / 1.550 / 1.685 | 167.9 / 163.5 / 157.2     |
| thin LTO, mimalloc                     | 0.386 / 0.385 / 0.371 | 1.625 / 1.653 / 1.727 | 165.5 / 163.6 / 154.6     |
| fat LTO, one codegen unit, mimalloc    | 0.379 / 0.376 / 0.363 | 2.072 / 1.584 / 1.586 | 160.2 / 154.8 / 147.8     |
| same build, run again after the others | 0.368 / 0.365 / 0.354 | 1.806 / 1.498 / 1.526 | 152.2 / 150.9 / 143.5     |

The access log costs about 5–14 µs of CPU per request even in batches (formatting and the write);
batches every 100 ms gave a higher p99 than every 10 ms at the same CPU time.

SO_REUSEPORT (one listener per CPU) against a single listener, at 1000 requests/s: no difference
within the noise, with keep-alive connections (157 µs either way) or a new connection per request
(about 220 µs) — a single accept loop is not the bottleneck there; what SO_REUSEPORT gives is
restarts without a gap. The runtime per core against one shared multi-threaded runtime, flat out
(32 connections): 142–150 thousand requests/s at 21–22 µs each against 77–83 thousand at 27–28 µs
(nginx in the same sitting: 119–123 thousand at 26–27 µs), for about 7 MiB more.

New connection to the first response over a 50 ms round trip (`bench/rtt.sh`: `tc netem` 25 ms on
each side, 20 connections, medians):

| Connection                                    | ms    |
| --------------------------------------------- | ----- |
| HTTP/2 over TCP + TLS 1.3, session resumed    | 152.8 |
| HTTP/3, full handshake                        | 102.6 |
| HTTP/3 resumed with 0-RTT (accepted 20 of 20) | 51.6  |
