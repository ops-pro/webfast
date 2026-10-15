//! In-process benchmark of the handler chain (no sockets, no access log) for the given paths through
//! a real Caddyfile and site: per request the time (median and best of `rounds` rounds), the CPU's
//! time-stamp counter ticks (x86-64: reference cycles), and the heap allocations (count and bytes,
//! counted by this program's allocator).
//!
//!   cargo run --release --example bench -- <Caddyfile> <iterations> <rounds> <path> [<path>…]
//!
//! `304:<path>` sends the path with If-None-Match set to the ETag of its 200 response;
//! `identity:<path>` sends it without Accept-Encoding (the file's own bytes: decompressed when kept in
//! LZ4, see WEB_LZ4_MIN_SAVING, read as by the server). Requests
//! with a ready answer (src/memo.rs) take it, as in the server; `BENCH_CHAIN=1` runs every
//! request through the handler chain instead.
//!
//! bench/run.sh runs it next to the load test; for a profile, run one path with
//! many iterations under `perf record -e cpu-clock`.

use http::{HeaderValue, Request};
use http_body_util::BodyExt;
#[cfg(not(feature = "mimalloc"))]
use std::alloc::System;
use std::alloc::{GlobalAlloc, Layout};
use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use webfast::handler::{ConnInfo, Ctx, Next};

/// The binary's allocator (mimalloc, or the system's without the `mimalloc` feature), counting
/// allocations (reallocations included) and bytes requested.
struct Counting;

#[cfg(feature = "mimalloc")]
const INNER: mimalloc::MiMalloc = mimalloc::MiMalloc;
#[cfg(not(feature = "mimalloc"))]
const INNER: System = System;

static ALLOCATIONS: AtomicU64 = AtomicU64::new(0);
static BYTES: AtomicU64 = AtomicU64::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
        // SAFETY: forwarded unchanged to the inner allocator.
        unsafe { INNER.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: forwarded unchanged to the inner allocator.
        unsafe { INNER.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        BYTES.fetch_add(new_size as u64, Ordering::Relaxed);
        // SAFETY: forwarded unchanged to the inner allocator.
        unsafe { INNER.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

#[cfg(target_arch = "x86_64")]
fn ticks() -> u64 {
    // SAFETY: RDTSC has no preconditions on x86-64.
    #[allow(unused_unsafe)]
    unsafe {
        std::arch::x86_64::_rdtsc()
    }
}

#[cfg(not(target_arch = "x86_64"))]
fn ticks() -> u64 {
    0
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (Some(config_path), Some(iterations), Some(rounds)) = (args.first(), args.get(1), args.get(2)) else {
        eprintln!("usage: bench <Caddyfile> <iterations> <rounds> <path> [<path>…]");
        std::process::exit(2);
    };
    let iterations: u32 = iterations.parse().expect("iterations");
    let rounds: usize = rounds.parse().expect("rounds");
    let paths = &args[3..];
    let lz4 = webfast::files::lz4_min_saving_from_env().expect("WEB_LZ4_MIN_SAVING");
    let file = webfast::caddyfile::parse_file(Path::new(config_path)).expect("Caddyfile");
    let config = webfast::load_parsed_with(&file, webfast::DEFAULT_MAX_MEMORY, lz4).expect("configuration");
    let routes = config.servers[0].sites[0].routes.clone();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let remote = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 40000);
    let conn = Arc::new(ConnInfo {
        remote,
        tls: false,
        trusted: false,
    });
    let answers = if std::env::var_os("BENCH_CHAIN").is_some() {
        None
    } else {
        webfast::memo::Answers::prepare(&routes, false)
    };

    let once = |path: &str, if_none_match: &Option<HeaderValue>, identity: bool| {
        let mut request = Request::builder()
            .uri(path)
            .header("host", "example.test")
            .header("user-agent", "bench");
        if !identity {
            request = request.header("accept-encoding", "gzip, deflate, br, zstd");
        }
        if let Some(etag) = if_none_match {
            request = request.header("if-none-match", etag.clone());
        }
        let request = request.body(webfast::body::empty()).expect("request");
        let (parts, body) = request.into_parts();
        let ready = answers.as_ref().and_then(|a| a.answer(&parts));
        let conn = conn.clone();
        let routes = routes.clone();
        async move {
            let response = match ready {
                Some(response) => response,
                None => Next::start(routes).run(Ctx::new(conn, parts, body, remote.ip())).await,
            };
            let status = response.status().as_u16();
            let body = response.into_body().collect().await.expect("body").to_bytes();
            (status, body.len())
        }
    };
    // The ETag of a path's 200 response.
    let etag_of = |path: &str| {
        let request = Request::builder()
            .uri(path)
            .header("host", "example.test")
            .header("accept-encoding", "gzip, deflate, br, zstd")
            .body(webfast::body::empty())
            .expect("request");
        let (parts, body) = request.into_parts();
        let ctx = Ctx::new(conn.clone(), parts, body, remote.ip());
        let routes = routes.clone();
        runtime.block_on(async move { Next::start(routes).run(ctx).await.headers().get("etag").cloned() })
    };

    println!(
        "{:<36} {:>6} {:>7} {:>10} {:>10} {:>11} {:>8} {:>9}",
        "path", "status", "bytes", "median ns", "best ns", "TSC ticks", "allocs", "alloc B"
    );
    // What building the test request itself costs (included in every line below).
    {
        let (a0, b0) = (ALLOCATIONS.load(Ordering::Relaxed), BYTES.load(Ordering::Relaxed));
        let started = Instant::now();
        let t0 = ticks();
        for _ in 0..iterations {
            let request = Request::builder()
                .uri("/en/contact")
                .header("host", "example.test")
                .header("accept-encoding", "gzip, deflate, br, zstd")
                .header("user-agent", "bench")
                .body(webfast::body::empty())
                .expect("request");
            black_box(request.into_parts());
        }
        let n = f64::from(iterations);
        println!(
            "{:<36} {:>6} {:>7} {:>10.0} {:>10} {:>11.0} {:>8.1} {:>9.0}",
            "(building the request only)",
            "-",
            "-",
            started.elapsed().as_nanos() as f64 / n,
            "-",
            (ticks() - t0) as f64 / n,
            (ALLOCATIONS.load(Ordering::Relaxed) - a0) as f64 / n,
            (BYTES.load(Ordering::Relaxed) - b0) as f64 / n
        );
    }
    for label in paths {
        let (path, identity) = match label.strip_prefix("identity:") {
            Some(path) => (path, true),
            None => (label.as_str(), false),
        };
        let (path, if_none_match) = match path.strip_prefix("304:") {
            Some(path) => (path, Some(etag_of(path).expect("an ETag for the 304 case"))),
            None => (path, None),
        };
        let inm = &if_none_match;
        let (status, bytes) = runtime.block_on(once(path, inm, identity));
        // Warm-up, then timed rounds.
        runtime.block_on(async {
            for _ in 0..iterations / 10 {
                black_box(once(path, inm, identity).await);
            }
        });
        let mut per_request: Vec<(f64, f64)> = (0..rounds)
            .map(|_| {
                let started = Instant::now();
                let t0 = ticks();
                runtime.block_on(async {
                    for _ in 0..iterations {
                        black_box(once(path, inm, identity).await);
                    }
                });
                let elapsed = started.elapsed().as_nanos() as f64 / f64::from(iterations);
                let tsc = (ticks() - t0) as f64 / f64::from(iterations);
                (elapsed, tsc)
            })
            .collect();
        per_request.sort_by(|a, b| a.0.total_cmp(&b.0));
        let (median, median_tsc) = per_request[per_request.len() / 2];
        // Allocations of one more pass (the request itself — built the same way for every version).
        let (a0, b0) = (ALLOCATIONS.load(Ordering::Relaxed), BYTES.load(Ordering::Relaxed));
        runtime.block_on(async {
            for _ in 0..iterations {
                black_box(once(path, inm, identity).await);
            }
        });
        let allocs = (ALLOCATIONS.load(Ordering::Relaxed) - a0) as f64 / f64::from(iterations);
        let alloc_bytes = (BYTES.load(Ordering::Relaxed) - b0) as f64 / f64::from(iterations);
        println!(
            "{label:<36} {status:>6} {bytes:>7} {median:>10.0} {:>10.0} {median_tsc:>11.0} {allocs:>8.1} {alloc_bytes:>9.0}",
            per_request[0].0
        );
    }
}
