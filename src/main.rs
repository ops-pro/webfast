//! `webfast run [--config Caddyfile]` serves; `webfast validate [--config …]` checks the
//! configuration and loads the site files without listening; `webfast healthcheck <http-url>`
//! probes a running instance (the container HEALTHCHECK, so the image needs no curl).
//! Environment: LOG_LEVEL (info), WEB_MAX_MEMORY (512MiB) for the site files held in memory,
//! WEB_LOG_FLUSH_MS (10): how often access log lines are written out, in batches;
//! WEB_LZ4_MIN_SAVING (25): files are kept in memory as LZ4 when that saves at least this many
//! percent (`off`: never; src/files.rs);
//! WEB_MAX_FILE_IN_MEMORY (16MiB): larger files are served from disk (`off`: all in memory);
//! WEB_MAX_CONNECTIONS (16384) and WEB_MAX_CONNECTIONS_PER_IP (256) open connections (0: no
//! limit), WEB_STALL_TIMEOUT (30s): a response the client stops taking for that long ends its
//! connection (src/guard.rs); WEB_TCP_CONGESTION (bbr; `system`: the kernel's default) for the
//! clients' TCP connections (src/sockets.rs); WEB_RUNTIME (`per-core`: a thread and runtime per
//! listening socket, the default on Unix; `shared`: one runtime for all, src/server.rs);
//! WEB_WORKERS (one per CPU; `auto`): the listening sockets per port, so the threads that serve
//! the connections, and the shared runtime's threads; WEB_FILES_WATCH (`auto`: inotify on local
//! filesystems, polling elsewhere; `inotify`, `poll`, `off`: as loaded at startup) and
//! WEB_FILES_POLL (30s): how changed site files are picked up (src/watch.rs).
//! SIGHUP reads the Caddyfile again and puts it in place without dropping a connection —
//! WEB_RELOAD (`immediate`: open connections take it for their next request; `lazy`: they keep
//! the configuration they were accepted with until they close; `drain`: as lazy, and each is
//! closed gracefully at a random moment within WEB_RELOAD_DRAIN, 60s); SIGTERM
//! and SIGINT stop gracefully.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;
use tracing_subscriber::EnvFilter;
use webfast::{DEFAULT_MAX_MEMORY, caddyfile, config, load_parsed_reusing, parse_size, server};

/// mimalloc: the requests' many small, short-lived allocations are cheaper than with glibc malloc.
#[cfg(feature = "mimalloc")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

const USAGE: &str =
    "usage: webfast [run|validate] [--config <Caddyfile>] | healthcheck <http://host:port/path> | --version";

fn main() -> ExitCode {
    let started = std::time::Instant::now();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (command, rest) = match args.first().map(String::as_str) {
        Some("--version" | "-V" | "version") => {
            println!("webfast {}", env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
        }
        Some("healthcheck") => return healthcheck(args.get(1).map(String::as_str)),
        Some(c @ ("run" | "validate")) => (c, &args[1..]),
        None => ("run", &args[..]),
        Some(other) if other.starts_with("--") => ("run", &args[..]),
        Some(other) => {
            eprintln!("unknown command {other:?}; {USAGE}");
            return ExitCode::from(2);
        }
    };
    let mut config_path = PathBuf::from("Caddyfile");
    let mut i = 0;
    while i < rest.len() {
        match rest[i].as_str() {
            "--config" | "-c" => {
                let Some(path) = rest.get(i + 1) else {
                    eprintln!("--config needs a path; {USAGE}");
                    return ExitCode::from(2);
                };
                config_path = PathBuf::from(path);
                i += 2;
            }
            // Accepted for familiarity with `caddy run --adapter caddyfile`.
            "--adapter" if rest.get(i + 1).map(String::as_str) == Some("caddyfile") => i += 2,
            other => {
                eprintln!("unknown argument {other:?}; {USAGE}");
                return ExitCode::from(2);
            }
        }
    }
    let max_memory = match std::env::var("WEB_MAX_MEMORY") {
        Ok(value) => match parse_size(&value) {
            Some(bytes) => bytes,
            None => {
                eprintln!("WEB_MAX_MEMORY: invalid size {value:?} (e.g. 512MiB)");
                return ExitCode::from(2);
            }
        },
        Err(_) => DEFAULT_MAX_MEMORY,
    };

    let file = match caddyfile::parse_file(&config_path) {
        Ok(file) => file,
        Err(e) => {
            eprintln!("configuration error: {e}");
            return ExitCode::from(2);
        }
    };
    init_tracing(config::wants_debug(&file));
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let workers = match workers_from_env() {
        Ok(workers) => workers,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    let mut builder = tokio::runtime::Builder::new_multi_thread();
    if let Some(n) = workers {
        builder.worker_threads(n);
    }
    let runtime = match builder.enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            tracing::error!(error = %e, "cannot start the async runtime");
            return ExitCode::FAILURE;
        }
    };
    let lz4_min_saving = match webfast::files::lz4_min_saving_from_env() {
        Ok(setting) => setting,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    let max_in_memory = match webfast::files::max_file_in_memory_from_env() {
        Ok(setting) => setting,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    let watch = match webfast::watch::Watch::from_env() {
        Ok(watch) => watch,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    // Nothing to watch when only validating.
    let watch = if command == "validate" {
        webfast::watch::Watch::default()
    } else {
        watch
    };
    let loaded =
        runtime.block_on(async { load_parsed_reusing(&file, max_memory, lz4_min_saving, max_in_memory, watch, &[]) });
    let mut config = match loaded {
        Ok(config) => config,
        Err(e) => {
            tracing::error!(error = %e, config = %config_path.display(), "configuration error");
            eprintln!("configuration error: {e}");
            return ExitCode::from(2);
        }
    };
    if let Err(e) = limits_from_env(&mut config, workers) {
        eprintln!("{e}");
        return ExitCode::from(2);
    }
    if command == "validate" {
        let sites: usize = config.servers.iter().map(|s| s.sites.len()).sum();
        let files = config.files;
        println!(
            "valid configuration: {} port(s), {sites} site(s), {} files ({:.1} MiB; {:.1} MiB in memory, {} in LZ4, {} from disk), loaded in {} ms",
            config.servers.len(),
            files.files,
            files.bytes as f64 / 1048576.0,
            files.stored as f64 / 1048576.0,
            files.lz4,
            files.disk,
            started.elapsed().as_millis()
        );
        return ExitCode::SUCCESS;
    }
    let reload = Reload {
        path: config_path,
        max_memory,
        lz4_min_saving,
        max_in_memory,
        watch,
        workers,
        debug: config.debug,
    };
    match runtime.block_on(run(config, started, reload)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!(error = %e, "webfast stopped with an error");
            ExitCode::FAILURE
        }
    }
}

/// WEB_WORKERS: how many threads serve connections (`auto` or unset: one per CPU).
fn workers_from_env() -> Result<Option<usize>, String> {
    match std::env::var("WEB_WORKERS") {
        Ok(value) if value.trim().eq_ignore_ascii_case("auto") => Ok(None),
        Ok(value) => match value.trim().parse::<usize>() {
            Ok(n) if (1..=1024).contains(&n) => Ok(Some(n)),
            _ => Err(format!("WEB_WORKERS: auto or 1 to 1024 threads, not {value:?}")),
        },
        Err(_) => Ok(None),
    }
}

/// Connection limits and threads from the environment, for every port.
fn limits_from_env(config: &mut config::Config, workers: Option<usize>) -> Result<(), String> {
    let count = |name: &str| -> Result<Option<usize>, String> {
        match std::env::var(name) {
            Ok(value) => value
                .trim()
                .parse()
                .map(Some)
                .map_err(|_| format!("{name}: not a number: {value:?}")),
            Err(_) => Ok(None),
        }
    };
    let max_connections = count("WEB_MAX_CONNECTIONS")?;
    let max_per_ip = count("WEB_MAX_CONNECTIONS_PER_IP")?;
    let stall = match std::env::var("WEB_STALL_TIMEOUT") {
        Ok(value) => match config::parse_duration(&value) {
            Ok(d) if !d.is_zero() => Some(d),
            _ => return Err(format!("WEB_STALL_TIMEOUT: invalid duration {value:?} (e.g. 30s)")),
        },
        Err(_) => None,
    };
    let congestion: Option<Option<&'static str>> = match std::env::var("WEB_TCP_CONGESTION") {
        Ok(value) if value.trim().eq_ignore_ascii_case("system") => Some(None),
        Ok(value)
            if !value.trim().is_empty() && value.trim().bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') =>
        {
            Some(Some(webfast::files::intern(&value.trim().to_ascii_lowercase())))
        }
        Ok(value) => {
            return Err(format!(
                "WEB_TCP_CONGESTION: an algorithm name or system, not {value:?}"
            ));
        }
        Err(_) => None,
    };
    let per_core = match std::env::var("WEB_RUNTIME") {
        Ok(value) if value.trim().eq_ignore_ascii_case("per-core") => Some(true),
        Ok(value) if value.trim().eq_ignore_ascii_case("shared") => Some(false),
        Ok(value) => return Err(format!("WEB_RUNTIME: shared or per-core, not {value:?}")),
        Err(_) => None,
    };
    let drain = match std::env::var("WEB_RELOAD_DRAIN") {
        Ok(value) => match config::parse_duration(&value) {
            Ok(window) => Some(window),
            Err(_) => return Err(format!("WEB_RELOAD_DRAIN: a duration (e.g. 60s), not {value:?}")),
        },
        Err(_) => None,
    };
    let reload = match std::env::var("WEB_RELOAD") {
        Ok(value) if value.trim().eq_ignore_ascii_case("immediate") => config::ReloadMode::Immediate,
        Ok(value) if value.trim().eq_ignore_ascii_case("lazy") => config::ReloadMode::Lazy,
        Ok(value) if value.trim().eq_ignore_ascii_case("drain") => {
            config::ReloadMode::Drain(drain.unwrap_or(config::ReloadMode::DRAIN))
        }
        Ok(value) => return Err(format!("WEB_RELOAD: immediate, lazy or drain, not {value:?}")),
        Err(_) => config::ReloadMode::default(),
    };
    if drain.is_some() && !matches!(reload, config::ReloadMode::Drain(_)) {
        return Err("WEB_RELOAD_DRAIN is the window of WEB_RELOAD=drain".to_string());
    }
    for server in &mut config.servers {
        if let Some(per_core) = per_core {
            server.per_core = per_core;
        }
        server.workers = workers;
        server.reload = reload;
        if let Some(congestion) = congestion {
            server.limits.tcp_congestion = congestion;
        }
        if let Some(n) = max_connections {
            server.limits.max_connections = n;
        }
        if let Some(n) = max_per_ip {
            server.limits.max_per_ip = n;
        }
        if let Some(d) = stall {
            server.limits.stall = d;
        }
    }
    Ok(())
}

fn init_tracing(debug: bool) {
    let level = std::env::var("LOG_LEVEL").unwrap_or_else(|_| if debug { "debug".into() } else { "info".into() });
    let filter = EnvFilter::try_new(&level).unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(filter)
        .flatten_event(true)
        .with_target(true)
        .with_writer(std::io::stderr)
        .init();
}

/// What loading the configuration again (SIGHUP) needs, as at startup.
struct Reload {
    path: PathBuf,
    max_memory: u64,
    lz4_min_saving: Option<u8>,
    max_in_memory: Option<u64>,
    watch: webfast::watch::Watch,
    workers: Option<usize>,
    /// The `debug` option as started (logging is set up once).
    debug: bool,
}

async fn run(config: config::Config, started: std::time::Instant, reload: Reload) -> anyhow::Result<()> {
    let mut grace = config.grace_period;
    let (ports, files) = (config.servers.len(), config.files);
    // Before anything else: from here on, SIGHUP reloads instead of ending the process.
    let mut hangup = hangups();
    tracing::info!(version = env!("CARGO_PKG_VERSION"), "starting");
    let mut running = server::start(config).await?;
    webfast::release_free_memory();
    let mib = |bytes: u64| (bytes as f64 / 1048576.0 * 10.0).round() / 10.0;
    tracing::info!(
        ports,
        files = files.files,
        files_mib = mib(files.bytes),
        files_in_memory_mib = mib(files.stored),
        lz4_files = files.lz4,
        disk_files = files.disk,
        ready_paths = running.ready.paths,
        ready_answers = running.ready.answers,
        ready_mib = mib(running.ready.bytes),
        ready_ms = running.ready.millis,
        resident_mib = webfast::resident_bytes().map_or(0.0, mib),
        startup_ms = started.elapsed().as_millis() as u64,
        "started"
    );
    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            _ = next_hangup(&mut hangup) => match reload_config(&mut running, &reload).await {
                Ok(new_grace) => grace = new_grace,
                Err(e) => tracing::error!(error = format!("{e:#}"), "configuration not reloaded; the running one stays"),
            },
        }
    }
    tracing::info!(grace_secs = grace.as_secs(), "shutting down");
    running.shutdown(grace).await;
    webfast::accesslog::flush_all(Duration::from_secs(2));
    tracing::info!("stopped");
    Ok(())
}

/// SIGHUP: reads the Caddyfile again and puts it in place (`server::Running::reload`); the
/// configuration's grace period is returned.
async fn reload_config(running: &mut server::Running, reload: &Reload) -> anyhow::Result<Duration> {
    let started = std::time::Instant::now();
    tracing::info!(config = %reload.path.display(), "reloading the configuration");
    let file = caddyfile::parse_file(&reload.path)?;
    if config::wants_debug(&file) != reload.debug {
        tracing::warn!("the debug option takes effect on a restart");
    }
    let stores = running.stores();
    let (max_memory, lz4_min_saving, max_in_memory, watch) = (
        reload.max_memory,
        reload.lz4_min_saving,
        reload.max_in_memory,
        reload.watch,
    );
    let mut config = tokio::task::spawn_blocking(move || {
        load_parsed_reusing(&file, max_memory, lz4_min_saving, max_in_memory, watch, &stores)
    })
    .await??;
    limits_from_env(&mut config, reload.workers).map_err(anyhow::Error::msg)?;
    let grace = config.grace_period;
    let ports = config.servers.len();
    let sites: usize = config.servers.iter().map(|s| s.sites.len()).sum();
    let files = config.files;
    let ready = running.reload(config).await?;
    webfast::release_free_memory();
    tracing::info!(
        ports,
        sites,
        files = files.files,
        files_in_memory_mib = (files.stored as f64 / 1048576.0 * 10.0).round() / 10.0,
        ready_paths = ready.paths,
        ready_answers = ready.answers,
        ms = started.elapsed().as_millis() as u64,
        "configuration reloaded"
    );
    Ok(grace)
}

#[cfg(unix)]
type Hangups = Option<tokio::signal::unix::Signal>;
#[cfg(not(unix))]
type Hangups = ();

/// SIGHUP, caught (where there is one).
fn hangups() -> Hangups {
    #[cfg(unix)]
    {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()).ok()
    }
}

/// The next SIGHUP; never where there is none.
async fn next_hangup(hangups: &mut Hangups) {
    #[cfg(unix)]
    if let Some(signal) = hangups
        && signal.recv().await.is_some()
    {
        return;
    }
    let _ = hangups;
    std::future::pending::<()>().await
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}

/// GET over plain HTTP; success on any 2xx status.
fn healthcheck(url: Option<&str>) -> ExitCode {
    let Some(url) = url.and_then(|u| u.strip_prefix("http://")) else {
        eprintln!("healthcheck needs an http:// URL; {USAGE}");
        return ExitCode::from(2);
    };
    let (authority, path) = match url.find('/') {
        Some(i) => (&url[..i], &url[i..]),
        None => (url, "/"),
    };
    let address = if authority.contains(':') {
        authority.to_string()
    } else {
        format!("{authority}:80")
    };
    let Some(addr) = address.to_socket_addrs().ok().and_then(|mut a| a.next()) else {
        eprintln!("healthcheck: cannot resolve {authority}");
        return ExitCode::FAILURE;
    };
    let result = (|| -> std::io::Result<String> {
        let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(2))?;
        stream.set_read_timeout(Some(Duration::from_secs(3)))?;
        write!(
            stream,
            "GET {path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\nUser-Agent: webfast-healthcheck\r\n\r\n"
        )?;
        let mut response = String::new();
        stream.take(4096).read_to_string(&mut response)?;
        Ok(response)
    })();
    match result {
        Ok(response) if response.split_whitespace().nth(1).is_some_and(|s| s.starts_with('2')) => ExitCode::SUCCESS,
        Ok(response) => {
            eprintln!("unhealthy: {}", response.lines().next().unwrap_or(""));
            ExitCode::FAILURE
        }
        Err(e) => {
            eprintln!("unhealthy: {e}");
            ExitCode::FAILURE
        }
    }
}
