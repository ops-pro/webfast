//! From the Caddyfile tree to servers, sites and handler chains.
//!
//! Supported (anything else is a startup error naming the file and line):
//!   global options  auto_https off|disable_redirects|disable_certs, admin off, http_port, https_port,
//!                   grace_period, debug, order, servers { trusted_proxies static …,
//!                   trusted_proxies_strict, client_ip_headers, protocols, timeouts { read_header, idle } }
//!   site            addresses (`:port`, `host`, `host:port`, `http://…`, `https://…`), tls <cert> <key>, log
//!   directives      root, header, request_header, redir, rewrite, try_files, encode, route, handle,
//!                   handle_path, respond, reverse_proxy, file_server
//!   matchers        path, path_regexp, file, not, host, method, header, client_ip, remote_ip, protocol
//!
//! Directives outside `route` blocks are sorted like Caddy does: by its directive order, then — for
//! the same directive — routes with a single path pattern by specificity (longest first).

use crate::accesslog::{AccessLog, Format, Output};
use crate::caddyfile::{Caddyfile, Line, Location, Token};
use crate::encode::{DEFAULT_TYPES, Encode, Encoding};
use crate::files::Loader;
use crate::handler::{Handler, HeaderOp, Route, Value};
use crate::matcher::{FileMatcher, Matcher, MatcherSet, PathPattern, TryFile};
use crate::placeholder::Template;
use crate::proxy::{HttpClient, LbPolicy, ReverseProxy};
use crate::static_files::FileServer;
use anyhow::{Result, anyhow, bail};
use http::uri::Authority;
use http::{HeaderName, Method, StatusCode};
use ipnet::IpNet;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::time::Duration;

pub struct Config {
    pub servers: Vec<ServerConfig>,
    /// Site files in memory (precompressed siblings included): count, size, what they take.
    pub files: crate::files::Totals,
    /// Every site root, loaded once.
    pub stores: Vec<Arc<crate::files::FileStore>>,
    /// What the site files may take together (WEB_MAX_MEMORY), also when they are read again.
    pub max_memory: u64,
    /// Whether and how changed files are picked up while the server runs (src/watch.rs).
    pub watch: crate::watch::Watch,
    pub grace_period: Duration,
    pub debug: bool,
}

pub struct ServerConfig {
    pub port: u16,
    /// Certificates (TLS sites); `None`: plain HTTP.
    pub tls: Option<Vec<CertSpec>>,
    pub protocols: Protocols,
    pub trusted_proxies: Vec<IpNet>,
    pub trusted_strict: bool,
    pub client_ip_headers: Vec<HeaderName>,
    pub limits: Limits,
    /// TCP connections on one thread per listening socket (one per CPU), each with a runtime of its
    /// own, as nginx's workers (the default on Unix, where there is a socket per CPU); otherwise on
    /// the process's shared runtime (src/server.rs).
    pub per_core: bool,
    /// Listening sockets for the port on Unix — with `per_core`, the threads that serve its
    /// connections (WEB_WORKERS); `None`: one per CPU, at most 64.
    pub workers: Option<usize>,
    pub sites: Vec<Site>,
}

/// What a connection may take of the server (src/guard.rs); `timeouts` in the Caddyfile, the
/// rest from the environment (src/main.rs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Open connections, TCP and QUIC together; 0: no limit.
    pub max_connections: usize,
    /// Open connections per client address (an IPv6 /64 is one); trusted proxies are exempt, many
    /// clients come through them. 0: no limit.
    pub max_per_ip: usize,
    /// The request headers must arrive within this — on a new connection, the first request's.
    pub read_header: Duration,
    /// With no request in progress for this long, a connection is closed gracefully.
    pub idle: Duration,
    /// A response the client does not take (the socket accepts nothing) for this long: the
    /// connection is cut.
    pub stall: Duration,
    /// A graceful close (GOAWAY) that has not finished after this: the connection is cut.
    pub grace: Duration,
    /// HTTP/3: the largest frame other than DATA, i.e. a request's encoded headers.
    pub h3_frame: u64,
    /// TCP congestion control for the clients' connections (`None`: the system's; src/sockets.rs).
    pub tcp_congestion: Option<&'static str>,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_connections: 16_384,
            max_per_ip: 256,
            read_header: Duration::from_secs(30),
            // Caddy's default.
            idle: Duration::from_secs(300),
            stall: Duration::from_secs(30),
            grace: Duration::from_secs(10),
            h3_frame: 64 * 1024,
            tcp_congestion: Some("bbr"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct CertSpec {
    /// Host names the certificate is for (empty: any).
    pub hosts: Vec<String>,
    pub cert: PathBuf,
    pub key: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Protocols {
    pub h1: bool,
    pub h2: bool,
    pub h2c: bool,
    pub h3: bool,
}

impl Default for Protocols {
    fn default() -> Self {
        Protocols {
            h1: true,
            h2: true,
            h2c: false,
            h3: true,
        }
    }
}

pub struct Site {
    /// Lowercase host patterns; empty: any host.
    pub hosts: Vec<String>,
    pub routes: Arc<[Route]>,
    pub log: Option<Arc<AccessLog>>,
    /// Ready answers for its files, worked out when the server starts and again when its files
    /// change (src/memo.rs, src/watch.rs); empty meanwhile: requests take the chain.
    pub answers: arc_swap::ArcSwapOption<crate::memo::Answers>,
}

/// Caddy's default directive order (httpcaddyfile).
const DIRECTIVE_ORDER: &[&str] = &[
    "tracing",
    "map",
    "vars",
    "fs",
    "root",
    "log_append",
    "skip_log",
    "log_skip",
    "log_name",
    "header",
    "copy_response_headers",
    "request_body",
    "redir",
    "method",
    "rewrite",
    "uri",
    "try_files",
    "basicauth",
    "basic_auth",
    "forward_auth",
    "request_header",
    "encode",
    "push",
    "intercept",
    "templates",
    "invoke",
    "handle",
    "handle_path",
    "route",
    "abort",
    "error",
    "copy_response",
    "respond",
    "metrics",
    "reverse_proxy",
    "php_fastcgi",
    "file_server",
    "acme_server",
];

/// `reverse_proxy`: how long an upstream may take to send its response headers before the client
/// gets 504 (Caddy: no limit; `transport http { response_header_timeout 0 }` restores that). A
/// request in progress has no other clock, so without this a hung upstream would hold the client's
/// connection and its own for as long as the client waits.
pub const DEFAULT_RESPONSE_HEADER_TIMEOUT: Duration = Duration::from_secs(60);

const PRIVATE_RANGES: &[&str] = &[
    "192.168.0.0/16",
    "172.16.0.0/12",
    "10.0.0.0/8",
    "127.0.0.1/8",
    "fd00::/8",
    "::1/128",
];

fn at_err(at: &Location, message: impl std::fmt::Display) -> anyhow::Error {
    anyhow!("{at}: {message}")
}

fn token_err(token: &Token, message: impl std::fmt::Display) -> anyhow::Error {
    at_err(&token.at(), message)
}

#[derive(Clone, Default)]
struct ServerOpts {
    trusted: Option<Vec<IpNet>>,
    strict: Option<bool>,
    client_ip_headers: Option<Vec<HeaderName>>,
    protocols: Option<Protocols>,
    read_header: Option<Duration>,
    idle: Option<Duration>,
}

struct Globals {
    http_port: u16,
    https_port: u16,
    grace: Duration,
    debug: bool,
    servers: Vec<(Option<u16>, ServerOpts)>,
    order: Vec<String>,
}

impl Default for Globals {
    fn default() -> Self {
        Globals {
            http_port: 80,
            https_port: 443,
            grace: Duration::from_secs(30),
            debug: false,
            servers: Vec::new(),
            order: DIRECTIVE_ORDER.iter().map(|s| s.to_string()).collect(),
        }
    }
}

/// Whether the global options ask for debug logs (read before logging is set up).
pub fn wants_debug(file: &Caddyfile) -> bool {
    file.global
        .as_ref()
        .is_some_and(|g| g.iter().any(|l| l.name() == "debug"))
}

pub fn compile(file: &Caddyfile, loader: &mut Loader, client: HttpClient) -> Result<Config> {
    let globals = parse_globals(file.global.as_deref().unwrap_or(&[]))?;
    let mut cx = Cx {
        globals: &globals,
        loader,
        client,
        next_group: 0,
    };
    struct Placed {
        port: u16,
        tls: Option<CertSpec>,
        hosts: Vec<String>,
        site: Site,
        at: Location,
    }
    let mut placed: Vec<Placed> = Vec::new();
    for block in &file.sites {
        let mut addresses = Vec::new();
        for key in &block.keys {
            for part in key.text.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                addresses.push(parse_address(part).map_err(|e| token_err(key, e))?);
            }
        }
        if addresses.is_empty() {
            bail!(at_err(&block.at, "a site block needs an address"));
        }
        let mut tls: Option<(PathBuf, PathBuf)> = None;
        let mut log: Option<Arc<AccessLog>> = None;
        let mut body = Vec::new();
        for line in &block.body {
            match line.name() {
                "tls" => {
                    if line.block.is_some() || line.tokens.len() != 3 {
                        bail!(at_err(
                            &line.at,
                            "tls: only `tls <cert_file> <key_file>` is supported (no automatic certificates)"
                        ));
                    }
                    let cert = static_text(&line.tokens[1])?;
                    let key = static_text(&line.tokens[2])?;
                    tls = Some((PathBuf::from(cert), PathBuf::from(key)));
                }
                "log" => log = Some(Arc::new(parse_log(line)?)),
                "bind" => bail!(at_err(&line.at, "bind is not supported")),
                _ => body.push(line.clone()),
            }
        }
        let mut site_cx = SiteCx {
            has_root: false,
            needs_root: None,
        };
        let routes = compile_block(&body, None, true, &mut cx, &mut site_cx)?;
        if let Some(at) = site_cx.needs_root
            && !site_cx.has_root
        {
            bail!(at_err(
                &at,
                "files are served from memory and need a site root: add `root * <dir>`"
            ));
        }
        let routes: Arc<[Route]> = routes.into();
        for address in addresses {
            let port = match (address.port, address.scheme.as_deref()) {
                (Some(port), _) => port,
                (None, Some("http")) => globals.http_port,
                (None, Some("https")) => globals.https_port,
                (None, _) if !address.host.is_empty() => globals.https_port,
                (None, _) => bail!(at_err(&block.at, "an address needs a host or a port")),
            };
            let secure = match address.scheme.as_deref() {
                Some("http") => {
                    if tls.is_some() {
                        bail!(at_err(&block.at, "an http:// address cannot use tls"));
                    }
                    false
                }
                Some("https") => true,
                _ => tls.is_some() || port == globals.https_port,
            };
            if secure && tls.is_none() {
                bail!(at_err(
                    &block.at,
                    format!(
                        "{}: HTTPS needs `tls <cert_file> <key_file>` (certificates are not obtained automatically)",
                        address.text
                    )
                ));
            }
            let hosts = if address.host.is_empty() || address.host == "*" {
                Vec::new()
            } else {
                vec![address.host.clone()]
            };
            let spec = tls.as_ref().filter(|_| secure).map(|(cert, key)| CertSpec {
                hosts: hosts.clone(),
                cert: cert.clone(),
                key: key.clone(),
            });
            placed.push(Placed {
                port,
                tls: spec,
                hosts: hosts.clone(),
                site: Site {
                    hosts,
                    routes: routes.clone(),
                    log: log.clone(),
                    answers: arc_swap::ArcSwapOption::empty(),
                },
                at: block.at.clone(),
            });
        }
    }

    let mut servers: Vec<ServerConfig> = Vec::new();
    for p in placed {
        let opts = server_opts(&globals, p.port);
        let server = match servers.iter_mut().position(|s| s.port == p.port) {
            Some(i) => &mut servers[i],
            None => {
                servers.push(ServerConfig {
                    port: p.port,
                    tls: p.tls.as_ref().map(|_| Vec::new()),
                    protocols: opts.protocols.unwrap_or_default(),
                    trusted_proxies: opts.trusted.clone().unwrap_or_default(),
                    trusted_strict: opts.strict.unwrap_or(false),
                    client_ip_headers: opts
                        .client_ip_headers
                        .clone()
                        .unwrap_or_else(|| vec![HeaderName::from_static("x-forwarded-for")]),
                    limits: Limits {
                        read_header: opts.read_header.unwrap_or(Limits::default().read_header),
                        idle: opts.idle.unwrap_or(Limits::default().idle),
                        ..Limits::default()
                    },
                    per_core: cfg!(unix),
                    workers: None,
                    sites: Vec::new(),
                });
                servers.last_mut().expect("just pushed")
            }
        };
        if server.tls.is_some() != p.tls.is_some() {
            bail!(at_err(&p.at, format!("port {} mixes HTTP and HTTPS sites", p.port)));
        }
        let duplicate = server.sites.iter().any(|s| s.hosts == p.hosts);
        if duplicate {
            let host = if p.hosts.is_empty() {
                "*".to_string()
            } else {
                p.hosts.join(",")
            };
            bail!(at_err(
                &p.at,
                format!("site {host} on port {} is defined more than once", p.port)
            ));
        }
        if let (Some(list), Some(spec)) = (server.tls.as_mut(), p.tls) {
            list.push(spec);
        }
        server.sites.push(p.site);
    }
    for server in &mut servers {
        // Exact hosts first, then wildcards, then the catch-all (stable within each kind).
        server.sites.sort_by_key(|s| match s.hosts.first() {
            None => 2,
            Some(h) if h.starts_with("*.") => 1,
            Some(_) => 0,
        });
        if server.tls.is_none() {
            server.protocols.h3 = false;
            server.protocols.h2 = false;
        }
        if !server.protocols.h1 && !server.protocols.h2 && !server.protocols.h2c && !server.protocols.h3 {
            bail!("port {}: no protocol enabled", server.port);
        }
    }
    if servers.is_empty() {
        bail!("the Caddyfile defines no sites");
    }
    Ok(Config {
        servers,
        files: crate::files::Totals::default(),
        stores: Vec::new(),
        max_memory: 0,
        watch: crate::watch::Watch::default(),
        grace_period: globals.grace,
        debug: globals.debug,
    })
}

fn server_opts(globals: &Globals, port: u16) -> ServerOpts {
    let mut out = ServerOpts::default();
    for (listener, opts) in &globals.servers {
        if listener.is_some_and(|p| p != port) {
            continue;
        }
        if opts.trusted.is_some() {
            out.trusted = opts.trusted.clone();
        }
        if opts.strict.is_some() {
            out.strict = opts.strict;
        }
        if opts.client_ip_headers.is_some() {
            out.client_ip_headers = opts.client_ip_headers.clone();
        }
        if opts.protocols.is_some() {
            out.protocols = opts.protocols;
        }
        if opts.read_header.is_some() {
            out.read_header = opts.read_header;
        }
        if opts.idle.is_some() {
            out.idle = opts.idle;
        }
    }
    out
}

struct Address {
    text: String,
    scheme: Option<String>,
    host: String,
    port: Option<u16>,
}

fn parse_address(text: &str) -> Result<Address> {
    let (scheme, rest) = match text.split_once("://") {
        Some((scheme, rest)) => (Some(scheme.to_ascii_lowercase()), rest),
        None => (None, text),
    };
    if let Some(s) = &scheme
        && s != "http"
        && s != "https"
    {
        bail!("unsupported scheme {s}://");
    }
    if rest.contains('/') {
        bail!("{text}: paths in site addresses are not supported (use a path matcher)");
    }
    let (host, port) = if let Some(inner) = rest.strip_prefix('[') {
        let (host, after) = inner
            .split_once(']')
            .ok_or_else(|| anyhow!("{text}: unclosed [ in address"))?;
        (host.to_string(), after.strip_prefix(':'))
    } else {
        match rest.rsplit_once(':') {
            Some((host, port)) => (host.to_string(), Some(port)),
            None => (rest.to_string(), None),
        }
    };
    let port = match port {
        Some(p) => Some(p.parse::<u16>().map_err(|_| anyhow!("{text}: invalid port {p:?}"))?),
        None => None,
    };
    Ok(Address {
        text: text.to_string(),
        scheme,
        host: host.to_ascii_lowercase(),
        port,
    })
}

fn parse_globals(lines: &[Line]) -> Result<Globals> {
    let mut g = Globals::default();
    for line in lines {
        let args = &line.tokens[1..];
        match line.name() {
            "auto_https" => {
                let ok = args.len() == 1
                    && matches!(
                        args[0].text.as_str(),
                        "off" | "disable_redirects" | "disable_certs" | "ignore_loaded_certs"
                    );
                if !ok {
                    bail!(at_err(
                        &line.at,
                        "auto_https: only off / disable_redirects / disable_certs (no automatic HTTPS here)"
                    ));
                }
            }
            "admin" => {
                if args.len() != 1 || args[0].text != "off" {
                    bail!(at_err(&line.at, "admin: only `admin off` (there is no admin endpoint)"));
                }
            }
            "http_port" | "https_port" => {
                let port = one_arg(line)?
                    .parse::<u16>()
                    .map_err(|_| at_err(&line.at, "invalid port"))?;
                if line.name() == "http_port" {
                    g.http_port = port;
                } else {
                    g.https_port = port;
                }
            }
            "grace_period" => g.grace = parse_duration(&one_arg(line)?).map_err(|e| at_err(&line.at, e))?,
            "debug" => g.debug = true,
            "order" => apply_order(&mut g.order, line)?,
            "servers" => {
                let listener = match args.first() {
                    Some(t) => {
                        let address = parse_address(&t.text).map_err(|e| token_err(t, e))?;
                        Some(
                            address
                                .port
                                .ok_or_else(|| token_err(t, "servers: the listener address needs a port"))?,
                        )
                    }
                    None => None,
                };
                g.servers.push((listener, parse_server_opts(line)?));
            }
            other => bail!(at_err(&line.at, format!("unsupported global option {other:?}"))),
        }
    }
    Ok(g)
}

fn apply_order(order: &mut Vec<String>, line: &Line) -> Result<()> {
    let args: Vec<&str> = line.tokens[1..].iter().map(|t| t.text.as_str()).collect();
    let (name, position) = match args.as_slice() {
        [name, "first"] => (*name, None),
        [name, "last"] => (*name, Some(usize::MAX)),
        [name, how @ ("before" | "after"), other] => {
            let current: Vec<String> = order.iter().filter(|d| d != name).cloned().collect();
            let i = current
                .iter()
                .position(|d| d == other)
                .ok_or_else(|| at_err(&line.at, format!("order: unknown directive {other:?}")))?;
            (*name, Some(if *how == "before" { i } else { i + 1 }))
        }
        _ => bail!(at_err(
            &line.at,
            "order: `order <directive> first|last|before <d>|after <d>`"
        )),
    };
    order.retain(|d| d != name);
    match position {
        None => order.insert(0, name.to_string()),
        Some(i) => order.insert(i.min(order.len()), name.to_string()),
    }
    Ok(())
}

fn parse_server_opts(line: &Line) -> Result<ServerOpts> {
    let mut opts = ServerOpts::default();
    for sub in line.block.as_deref().unwrap_or(&[]) {
        let args = &sub.tokens[1..];
        match sub.name() {
            "trusted_proxies" => {
                if args.first().map(|t| t.text.as_str()) != Some("static") {
                    bail!(at_err(
                        &sub.at,
                        "trusted_proxies: only the `static` source is supported"
                    ));
                }
                opts.trusted = Some(parse_ranges(&args[1..])?);
            }
            "trusted_proxies_strict" => opts.strict = Some(true),
            "client_ip_headers" => {
                let mut headers = Vec::new();
                for t in args {
                    headers.push(
                        HeaderName::from_bytes(t.text.as_bytes()).map_err(|_| token_err(t, "invalid header name"))?,
                    );
                }
                opts.client_ip_headers = Some(headers);
            }
            "protocols" => {
                let mut p = Protocols {
                    h1: false,
                    h2: false,
                    h2c: false,
                    h3: false,
                };
                for t in args {
                    match t.text.as_str() {
                        "h1" => p.h1 = true,
                        "h2" => p.h2 = true,
                        "h2c" => p.h2c = true,
                        "h3" => p.h3 = true,
                        other => bail!(token_err(t, format!("unknown protocol {other:?}"))),
                    }
                }
                opts.protocols = Some(p);
            }
            "timeouts" => {
                for t in sub.block.as_deref().unwrap_or(&[]) {
                    match t.name() {
                        "read_header" | "idle" => {
                            let value = parse_duration(&one_arg(t)?).map_err(|e| at_err(&t.at, e))?;
                            if value.is_zero() {
                                bail!(at_err(&t.at, format!("timeouts: {} must be more than 0", t.name())));
                            }
                            if t.name() == "idle" {
                                opts.idle = Some(value);
                            } else {
                                opts.read_header = Some(value);
                            }
                        }
                        other => bail!(at_err(
                            &t.at,
                            format!("timeouts: unsupported option {other:?} (only read_header and idle)")
                        )),
                    }
                }
            }
            other => bail!(at_err(&sub.at, format!("servers: unsupported option {other:?}"))),
        }
    }
    Ok(opts)
}

fn parse_ranges(tokens: &[Token]) -> Result<Vec<IpNet>> {
    let mut nets = Vec::new();
    for t in tokens {
        if t.text == "private_ranges" {
            nets.extend(PRIVATE_RANGES.iter().map(|r| r.parse::<IpNet>().expect("valid range")));
            continue;
        }
        let net = match t.text.parse::<IpNet>() {
            Ok(net) => net,
            Err(_) => IpNet::from(
                t.text
                    .parse::<std::net::IpAddr>()
                    .map_err(|_| token_err(t, "invalid IP range"))?,
            ),
        };
        nets.push(net);
    }
    if nets.is_empty() {
        bail!("an IP range list needs at least one range");
    }
    Ok(nets)
}

fn parse_log(line: &Line) -> Result<AccessLog> {
    if line.tokens.len() > 2 {
        bail!(at_err(&line.at, "log: `log [name] { … }`"));
    }
    let mut log = AccessLog {
        output: Output::Stderr,
        format: Format::Json,
    };
    for sub in line.block.as_deref().unwrap_or(&[]) {
        let value = one_arg(sub)?;
        match (sub.name(), value.as_str()) {
            ("output", "stdout") => log.output = Output::Stdout,
            ("output", "stderr") => log.output = Output::Stderr,
            ("output", "discard") => log.output = Output::Discard,
            ("format", "json") => log.format = Format::Json,
            ("format", "console") => log.format = Format::Console,
            ("level", "INFO" | "info" | "DEBUG" | "debug") => {}
            (name, value) => bail!(at_err(&sub.at, format!("log: unsupported {name} {value:?}"))),
        }
    }
    Ok(log)
}

fn one_arg(line: &Line) -> Result<String> {
    if line.tokens.len() != 2 || line.block.is_some() {
        bail!(at_err(&line.at, format!("{} takes exactly one argument", line.name())));
    }
    Ok(line.tokens[1].text.clone())
}

fn static_text(token: &Token) -> Result<String> {
    Template::parse(&token.text)
        .map_err(|e| token_err(token, e))?
        .as_static()
        .ok_or_else(|| token_err(token, "placeholders are not allowed here"))
}

fn template(token: &Token) -> Result<Template> {
    Template::parse(&token.text).map_err(|e| token_err(token, e))
}

/// Go-style durations (`300ms`, `30s`, `5m`, `1h30m`, `2d`); a bare number is seconds, `-1` is "never".
pub fn parse_duration(text: &str) -> std::result::Result<Duration, String> {
    let text = text.trim();
    if text == "0" || text.starts_with('-') {
        return Ok(Duration::ZERO);
    }
    if let Ok(seconds) = text.parse::<u64>() {
        return Ok(Duration::from_secs(seconds));
    }
    let mut total = 0f64;
    let mut number = String::new();
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c.is_ascii_digit() || c == '.' {
            number.push(c);
            continue;
        }
        let mut unit = c.to_string();
        while let Some(&n) = chars.peek() {
            if n.is_ascii_alphabetic() || n == 'µ' {
                unit.push(n);
                chars.next();
            } else {
                break;
            }
        }
        let value: f64 = number.parse().map_err(|_| format!("invalid duration {text:?}"))?;
        number.clear();
        let factor = match unit.as_str() {
            "ns" => 1e-9,
            "us" | "µs" => 1e-6,
            "ms" => 1e-3,
            "s" => 1.0,
            "m" => 60.0,
            "h" => 3600.0,
            "d" => 86400.0,
            _ => return Err(format!("invalid duration unit in {text:?}")),
        };
        total += value * factor;
    }
    if !number.is_empty() {
        return Err(format!("duration {text:?} needs a unit"));
    }
    Ok(Duration::from_secs_f64(total))
}

struct Cx<'a> {
    globals: &'a Globals,
    loader: &'a mut Loader,
    client: HttpClient,
    next_group: u32,
}

struct SiteCx {
    has_root: bool,
    /// Where a file server or file matcher first needs the site root.
    needs_root: Option<Location>,
}

/// Named matchers visible in a block (its own, then the enclosing blocks').
struct Scope<'p> {
    defs: HashMap<String, MatcherSet>,
    parent: Option<&'p Scope<'p>>,
}

impl Scope<'_> {
    fn lookup(&self, name: &str) -> Option<&MatcherSet> {
        self.defs.get(name).or_else(|| self.parent.and_then(|p| p.lookup(name)))
    }
}

struct Entry {
    directive: String,
    route: Route,
}

fn compile_block(
    lines: &[Line],
    parent: Option<&Scope>,
    sort: bool,
    cx: &mut Cx,
    site: &mut SiteCx,
) -> Result<Vec<Route>> {
    let mut scope = Scope {
        defs: HashMap::new(),
        parent,
    };
    for line in lines.iter().filter(|l| l.name().starts_with('@')) {
        let name = line.name()[1..].to_string();
        if name.is_empty() {
            bail!(at_err(&line.at, "a named matcher needs a name"));
        }
        if scope.defs.contains_key(&name) {
            bail!(at_err(&line.at, format!("matcher @{name} is defined more than once")));
        }
        let set = parse_matcher_def(line, &name, cx, site)?;
        scope.defs.insert(name, set);
    }
    let mut entries = Vec::new();
    for line in lines.iter().filter(|l| !l.name().starts_with('@')) {
        entries.extend(compile_directive(line, &scope, cx, site)?);
    }
    if sort {
        let positions: HashMap<&str, usize> = cx
            .globals
            .order
            .iter()
            .enumerate()
            .map(|(i, d)| (d.as_str(), i))
            .collect();
        go_stable_sort(&mut entries, |a, b| less(a, b, &positions));
    }
    cx.next_group += 1;
    let group = cx.next_group;
    Ok(entries
        .into_iter()
        .map(|mut e| {
            if e.directive == "handle" || e.directive == "handle_path" {
                e.route.group = Some(group);
            }
            e.route
        })
        .collect())
}

/// Caddy's `sortRoutes` comparator.
fn less(a: &Entry, b: &Entry, positions: &HashMap<&str, usize>) -> bool {
    if a.directive != b.directive {
        let pa = positions.get(a.directive.as_str()).copied().unwrap_or(usize::MAX);
        let pb = positions.get(b.directive.as_str()).copied().unwrap_or(usize::MAX);
        return pa < pb;
    }
    let pa = a.route.matcher.as_ref().and_then(|m| m.single_path());
    let pb = b.route.matcher.as_ref().and_then(|m| m.single_path());
    let (la, lb) = (pa.map_or(0, str::len), pb.map_or(0, str::len));
    let by_path = if la > 0 && lb > 0 {
        let (pa, pb) = (pa.unwrap_or(""), pb.unwrap_or(""));
        if pa.trim_end_matches('*') == pb.trim_end_matches('*') {
            la < lb
        } else {
            la > lb
        }
    } else {
        a.route.matcher.is_some() && b.route.matcher.is_none()
    };
    if a.directive == "vars" { !by_path } else { by_path }
}

/// Go's `sort.Stable`: insertion sort on blocks of 20, then SymMerge — the same order as Caddy even
/// when the comparator is not a strict weak order.
fn go_stable_sort<T>(data: &mut [T], less: impl Fn(&T, &T) -> bool) {
    let n = data.len();
    let mut block = 20;
    let (mut a, mut b) = (0, block);
    while b <= n {
        insertion_sort(data, a, b, &less);
        a = b;
        b += block;
    }
    insertion_sort(data, a, n, &less);
    while block < n {
        let (mut a, mut b) = (0, 2 * block);
        while b <= n {
            sym_merge(data, a, a + block, b, &less);
            a = b;
            b += 2 * block;
        }
        let m = a + block;
        if m < n {
            sym_merge(data, a, m, n, &less);
        }
        block *= 2;
    }
}

fn insertion_sort<T>(data: &mut [T], a: usize, b: usize, less: &impl Fn(&T, &T) -> bool) {
    for i in a + 1..b {
        let mut j = i;
        while j > a && less(&data[j], &data[j - 1]) {
            data.swap(j, j - 1);
            j -= 1;
        }
    }
}

fn sym_merge<T>(data: &mut [T], a: usize, m: usize, b: usize, less: &impl Fn(&T, &T) -> bool) {
    if m - a == 1 {
        let (mut i, mut j) = (m, b);
        while i < j {
            let h = (i + j) / 2;
            if less(&data[h], &data[a]) {
                i = h + 1;
            } else {
                j = h;
            }
        }
        for k in a..i - 1 {
            data.swap(k, k + 1);
        }
        return;
    }
    if b - m == 1 {
        let (mut i, mut j) = (a, m);
        while i < j {
            let h = (i + j) / 2;
            if !less(&data[m], &data[h]) {
                i = h + 1;
            } else {
                j = h;
            }
        }
        let mut k = m;
        while k > i {
            data.swap(k, k - 1);
            k -= 1;
        }
        return;
    }
    let mid = (a + b) / 2;
    let n = mid + m;
    let (mut start, mut r) = if m > mid { (n - b, mid) } else { (a, m) };
    let p = n - 1;
    while start < r {
        let c = (start + r) / 2;
        if !less(&data[p - c], &data[c]) {
            start = c + 1;
        } else {
            r = c;
        }
    }
    let end = n - start;
    if start < m && m < end {
        rotate(data, start, m, end);
    }
    if a < start && start < mid {
        sym_merge(data, a, start, mid, less);
    }
    if mid < end && end < b {
        sym_merge(data, mid, end, b, less);
    }
}

fn rotate<T>(data: &mut [T], a: usize, m: usize, b: usize) {
    data[a..b].rotate_left(m - a);
}

/// The matcher token after the directive name: `*`, `/path`, `@name` (unquoted), and where the
/// arguments start.
fn matcher_token(line: &Line, scope: &Scope) -> Result<(Option<MatcherSet>, usize)> {
    let Some(t) = line.tokens.get(1) else {
        return Ok((None, 1));
    };
    if t.quoted {
        return Ok((None, 1));
    }
    if t.text == "*" {
        return Ok((None, 2));
    }
    if t.text.starts_with('/') {
        return Ok((
            Some(MatcherSet {
                matchers: vec![Matcher::Path(vec![PathPattern::new(&t.text)])],
            }),
            2,
        ));
    }
    if let Some(name) = t.text.strip_prefix('@') {
        let set = scope
            .lookup(name)
            .ok_or_else(|| token_err(t, format!("matcher @{name} is not defined")))?;
        return Ok((Some(set.clone()), 2));
    }
    Ok((None, 1))
}

fn entry(directive: &str, matcher: Option<MatcherSet>, handler: Handler) -> Entry {
    Entry {
        directive: directive.to_string(),
        route: Route {
            matcher,
            group: None,
            handler,
        },
    }
}

fn no_block(line: &Line) -> Result<()> {
    if line.block.is_some() {
        bail!(at_err(&line.at, format!("{} takes no block", line.name())));
    }
    Ok(())
}

fn compile_directive(line: &Line, scope: &Scope, cx: &mut Cx, site: &mut SiteCx) -> Result<Vec<Entry>> {
    let name = line.name();
    match name {
        "root" => {
            no_block(line)?;
            let args = &line.tokens[1..];
            let (matcher, path) = match args.len() {
                1 => (None, &args[0]),
                2 => {
                    let (matcher, start) = matcher_token(line, scope)?;
                    if start != 2 {
                        bail!(at_err(&line.at, "root: `root [<matcher>] <path>`"));
                    }
                    (matcher, &args[1])
                }
                _ => bail!(at_err(&line.at, "root: `root [<matcher>] <path>`")),
            };
            let store = cx.loader.store(&static_text(path)?).map_err(|e| token_err(path, e))?;
            site.has_root = true;
            Ok(vec![entry(name, matcher, Handler::Root(store))])
        }
        "header" | "request_header" => {
            let (matcher, start) = matcher_token(line, scope)?;
            let mut ops = Vec::new();
            let mut deferred = false;
            if line.tokens.len() > start {
                ops.push(parse_header_op(&line.tokens[start..], &line.at)?);
            }
            for sub in line.block.as_deref().unwrap_or(&[]) {
                if name == "request_header" {
                    bail!(at_err(&sub.at, "request_header takes no block"));
                }
                if sub.name() == "defer" && sub.tokens.len() == 1 && sub.block.is_none() {
                    deferred = true;
                    continue;
                }
                if sub.name() == "match" {
                    bail!(at_err(&sub.at, "header: response matchers are not supported"));
                }
                no_block(sub)?;
                ops.push(parse_header_op(&sub.tokens, &sub.at)?);
            }
            if ops.is_empty() {
                bail!(at_err(&line.at, format!("{name} needs a header field")));
            }
            if name == "request_header" {
                return Ok(vec![entry(name, matcher, Handler::RequestHeader(ops))]);
            }
            deferred |= ops.iter().any(HeaderOp::needs_defer);
            let dynamic = ops.iter().any(HeaderOp::is_dynamic);
            Ok(vec![entry(name, matcher, Handler::Header { ops, deferred, dynamic })])
        }
        "redir" => {
            no_block(line)?;
            let (matcher, start) = matcher_token(line, scope)?;
            let args = &line.tokens[start..];
            if args.is_empty() || args.len() > 2 {
                bail!(at_err(&line.at, "redir: `redir [<matcher>] <to> [<code>]`"));
            }
            let to = template(&args[0])?;
            let (status, html) = match args.get(1).map(|t| t.text.as_str()) {
                None | Some("temporary") => (StatusCode::FOUND, false),
                Some("permanent") => (StatusCode::MOVED_PERMANENTLY, false),
                Some("html") => (StatusCode::OK, true),
                Some(code) => {
                    let code: u16 = code
                        .parse()
                        .map_err(|_| token_err(&args[1], "redir: invalid status code"))?;
                    if !(300..=399).contains(&code) {
                        bail!(token_err(&args[1], "redir: the status code must be 3xx"));
                    }
                    (StatusCode::from_u16(code).expect("3xx"), false)
                }
            };
            Ok(vec![entry(name, matcher, Handler::Redir { to, status, html })])
        }
        "rewrite" => {
            no_block(line)?;
            let (matcher, start) = matcher_token(line, scope)?;
            if line.tokens.len() != start + 1 {
                bail!(at_err(&line.at, "rewrite: `rewrite [<matcher>] <to>`"));
            }
            Ok(vec![entry(
                name,
                matcher,
                Handler::Rewrite(template(&line.tokens[start])?),
            )])
        }
        "try_files" => {
            no_block(line)?;
            if line.tokens.len() < 2 {
                bail!(at_err(&line.at, "try_files needs at least one file"));
            }
            let mut candidates = Vec::new();
            for t in &line.tokens[1..] {
                if t.text.contains('?') || t.text.starts_with('=') {
                    bail!(token_err(
                        t,
                        "try_files: query strings and =status entries are not supported"
                    ));
                }
                candidates.push(TryFile::new(template(t)?));
            }
            site.needs_root.get_or_insert(line.at.clone());
            let matcher = MatcherSet {
                matchers: vec![Matcher::File(FileMatcher {
                    root: None,
                    try_files: candidates,
                })],
            };
            let to = Template::parse("{file_match.relative}").expect("valid");
            Ok(vec![entry(name, Some(matcher), Handler::Rewrite(to))])
        }
        "encode" => {
            let (matcher, start) = matcher_token(line, scope)?;
            Ok(vec![entry(
                name,
                matcher,
                Handler::Encode(Arc::new(parse_encode(line, start)?)),
            )])
        }
        "route" | "handle" => {
            let (matcher, start) = matcher_token(line, scope)?;
            if line.tokens.len() != start {
                bail!(at_err(&line.at, format!("{name}: `{name} [<matcher>] {{ … }}`")));
            }
            let block = line.block.as_deref().unwrap_or(&[]);
            let routes = compile_block(block, Some(scope), name == "handle", cx, site)?;
            Ok(vec![entry(name, matcher, Handler::Subroute(routes.into()))])
        }
        "handle_path" => {
            let pattern = match line.tokens.get(1) {
                Some(t) if !t.quoted && t.text.starts_with('/') && line.tokens.len() == 2 => t.text.to_lowercase(),
                _ => bail!(at_err(&line.at, "handle_path: `handle_path <path_prefix>* { … }`")),
            };
            let prefix = pattern.trim_end_matches('*').trim_end_matches('/').to_string();
            let block = line.block.as_deref().unwrap_or(&[]);
            let mut routes = vec![Route {
                matcher: None,
                group: None,
                handler: Handler::StripPrefix(prefix),
            }];
            routes.extend(compile_block(block, Some(scope), true, cx, site)?);
            let matcher = MatcherSet {
                matchers: vec![Matcher::Path(vec![PathPattern::new(&pattern)])],
            };
            Ok(vec![entry(name, Some(matcher), Handler::Subroute(routes.into()))])
        }
        "respond" => {
            let (matcher, start) = matcher_token(line, scope)?;
            let args = &line.tokens[start..];
            let status_of = |t: &Token| -> Option<StatusCode> {
                (t.text.len() == 3)
                    .then(|| t.text.parse::<u16>().ok())
                    .flatten()
                    .and_then(|c| StatusCode::from_u16(c).ok())
            };
            let (mut body, mut status) = (Template::default(), StatusCode::OK);
            match args {
                [] => {}
                [one] => match status_of(one) {
                    Some(code) => status = code,
                    None => body = template(one)?,
                },
                [text, code] => {
                    body = template(text)?;
                    status = status_of(code).ok_or_else(|| token_err(code, "respond: invalid status code"))?;
                }
                _ => bail!(at_err(&line.at, "respond: `respond [<matcher>] [<body>] [<status>]`")),
            }
            let mut close = false;
            for sub in line.block.as_deref().unwrap_or(&[]) {
                match sub.name() {
                    "body" => body = template(sub.tokens.get(1).ok_or_else(|| at_err(&sub.at, "body needs a value"))?)?,
                    "close" => close = true,
                    other => bail!(at_err(&sub.at, format!("respond: unsupported option {other:?}"))),
                }
            }
            Ok(vec![entry(name, matcher, Handler::Respond { status, body, close })])
        }
        "reverse_proxy" => {
            let (matcher, start) = matcher_token(line, scope)?;
            let proxy = parse_reverse_proxy(line, start, cx)?;
            Ok(vec![entry(name, matcher, Handler::Proxy(Arc::new(proxy)))])
        }
        "file_server" => {
            let (matcher, start) = matcher_token(line, scope)?;
            if line.tokens.len() > start {
                bail!(at_err(&line.at, "file_server: browse is not supported"));
            }
            let mut fs = FileServer::default();
            for sub in line.block.as_deref().unwrap_or(&[]) {
                let args = &sub.tokens[1..];
                match sub.name() {
                    "root" => {
                        fs.root = Some(
                            cx.loader
                                .store(&static_text(&args[0])?)
                                .map_err(|e| at_err(&sub.at, e))?,
                        )
                    }
                    "hide" => fs.hide.extend(args.iter().map(|t| t.text.clone())),
                    "index" => fs.index = args.iter().map(|t| t.text.clone()).collect(),
                    "precompressed" => {
                        fs.precompressed = if args.is_empty() {
                            vec![Encoding::Br, Encoding::Zstd, Encoding::Gzip]
                        } else {
                            args.iter()
                                .map(|t| {
                                    Encoding::parse(&t.text)
                                        .ok_or_else(|| token_err(t, "precompressed: br, zstd or gzip"))
                                })
                                .collect::<Result<_>>()?
                        }
                    }
                    "pass_thru" => fs.pass_thru = true,
                    "disable_canonical_uris" => fs.canonical_uris = false,
                    other => bail!(at_err(&sub.at, format!("file_server: unsupported option {other:?}"))),
                }
            }
            if fs.root.is_none() {
                site.needs_root.get_or_insert(line.at.clone());
            }
            Ok(vec![entry(name, matcher, Handler::Files(Arc::new(fs)))])
        }
        "tls" | "log" | "bind" => bail!(at_err(
            &line.at,
            format!("{name} is only allowed at the top of a site block")
        )),
        "import" => bail!(at_err(&line.at, "unresolved import")),
        other => bail!(at_err(&line.at, format!("unsupported directive {other:?}"))),
    }
}

fn parse_header_op(tokens: &[Token], at: &Location) -> Result<HeaderOp> {
    let field = &tokens[0];
    let (kind, name) = match field.text.chars().next() {
        Some(c @ ('+' | '-' | '?' | '>')) => (Some(c), &field.text[1..]),
        _ => (None, field.text.as_str()),
    };
    if kind == Some('>') {
        bail!(token_err(field, "header: the > prefix is not supported (use defer)"));
    }
    if tokens.len() > 2 {
        bail!(at_err(at, "header: find/replace is not supported"));
    }
    if kind == Some('-') {
        if tokens.len() != 1 {
            bail!(at_err(at, "header: a deleted field takes no value"));
        }
        if let Some(prefix) = name.strip_suffix('*') {
            return Ok(HeaderOp::DeletePrefix(prefix.to_ascii_lowercase()));
        }
        return Ok(HeaderOp::Delete(header_name(field, name)?));
    }
    let value = tokens
        .get(1)
        .ok_or_else(|| at_err(at, format!("header {name}: a value is required")))?;
    let header = header_name(field, name)?;
    let value = Value::new(template(value)?).map_err(|e| token_err(value, e))?;
    Ok(match kind {
        Some('+') => HeaderOp::Add(header, value),
        Some('?') => HeaderOp::Default(header, value),
        _ => HeaderOp::Set(header, value),
    })
}

/// Checked, then kept as a `'static` name for the life of the process (cloned without a reference
/// count; the configuration is never reloaded).
fn header_name(token: &Token, name: &str) -> Result<HeaderName> {
    let checked = HeaderName::from_bytes(name.as_bytes())
        .map_err(|_| token_err(token, format!("invalid header name {name:?}")))?;
    Ok(HeaderName::from_static(Box::leak(
        checked.as_str().to_owned().into_boxed_str(),
    )))
}

fn parse_encode(line: &Line, start: usize) -> Result<Encode> {
    let mut encode = Encode {
        formats: Vec::new(),
        ..Encode::default()
    };
    let add = |formats: &mut Vec<Encoding>, t: &Token| -> Result<()> {
        let e = Encoding::parse(&t.text).ok_or_else(|| token_err(t, "encode: formats are zstd, br and gzip"))?;
        if !formats.contains(&e) {
            formats.push(e);
        }
        Ok(())
    };
    for t in &line.tokens[start..] {
        add(&mut encode.formats, t)?;
    }
    let mut prefer: Option<Vec<Encoding>> = None;
    for sub in line.block.as_deref().unwrap_or(&[]) {
        let args = &sub.tokens[1..];
        match sub.name() {
            "gzip" => {
                add(&mut encode.formats, &sub.tokens[0])?;
                if let Some(level) = args.first() {
                    encode.gzip_level = level
                        .text
                        .parse()
                        .ok()
                        .filter(|l| *l <= 9)
                        .ok_or_else(|| token_err(level, "gzip level 0–9"))?;
                }
            }
            "br" => {
                add(&mut encode.formats, &sub.tokens[0])?;
                if let Some(level) = args.first() {
                    encode.br_level = level
                        .text
                        .parse()
                        .ok()
                        .filter(|l| *l <= 11)
                        .ok_or_else(|| token_err(level, "br level 0–11"))?;
                }
            }
            "zstd" => {
                add(&mut encode.formats, &sub.tokens[0])?;
                if let Some(level) = args.first() {
                    encode.zstd_level = match level.text.as_str() {
                        "fastest" => 1,
                        "default" => 3,
                        "better" => 7,
                        "best" => 11,
                        other => other
                            .parse()
                            .ok()
                            .filter(|l| (1..=22).contains(l))
                            .ok_or_else(|| token_err(level, "zstd level"))?,
                    };
                }
            }
            "minimum_length" => {
                encode.minimum_length = one_arg(sub)?
                    .parse()
                    .map_err(|_| at_err(&sub.at, "minimum_length: a number of bytes"))?
            }
            "prefer" => {
                let mut list = Vec::new();
                for t in args {
                    add(&mut list, t)?;
                }
                prefer = Some(list);
            }
            "match" => {
                let mut types: Option<Vec<String>> = None;
                for m in sub.block.as_deref().unwrap_or(&[]) {
                    let margs = &m.tokens[1..];
                    match (m.name(), margs.first().map(|t| t.text.to_ascii_lowercase())) {
                        ("header", Some(field)) if field == "content-type" => {
                            types
                                .get_or_insert_with(Vec::new)
                                .extend(margs[1..].iter().map(|t| t.text.to_ascii_lowercase()));
                        }
                        ("status", _) => {
                            for t in margs {
                                encode.statuses.push(parse_status_range(t)?);
                            }
                        }
                        _ => bail!(at_err(
                            &m.at,
                            "encode match: only `header Content-Type …` and `status …`"
                        )),
                    }
                }
                if let Some(types) = types {
                    encode.types = types;
                }
            }
            other => bail!(at_err(&sub.at, format!("encode: unsupported option {other:?}"))),
        }
    }
    if encode.formats.is_empty() {
        encode.formats = vec![Encoding::Zstd, Encoding::Gzip];
    }
    if let Some(prefer) = prefer {
        let mut ordered = prefer.clone();
        ordered.extend(encode.formats.iter().filter(|e| !prefer.contains(e)));
        encode.formats = ordered;
    }
    if encode.types.is_empty() {
        encode.types = DEFAULT_TYPES.iter().map(|s| s.to_string()).collect();
    }
    Ok(encode)
}

fn parse_status_range(t: &Token) -> Result<(u16, u16)> {
    let text = t.text.to_ascii_lowercase();
    if text.len() == 3 && text.ends_with("xx") {
        let class: u16 = text[..1].parse().map_err(|_| token_err(t, "status: 2xx or 200"))?;
        return Ok((class * 100, class * 100 + 99));
    }
    let code: u16 = text.parse().map_err(|_| token_err(t, "status: 2xx or 200"))?;
    Ok((code, code))
}

fn parse_upstream(t: &Token) -> Result<Authority> {
    let text = static_text(t)?;
    let rest = match text.split_once("://") {
        Some(("http", rest)) => rest,
        Some((scheme, _)) => bail!(token_err(
            t,
            format!("reverse_proxy: {scheme}:// upstreams are not supported (only plain HTTP)")
        )),
        None => text.as_str(),
    };
    if rest.starts_with("unix/") || rest.contains('/') {
        bail!(token_err(
            t,
            "reverse_proxy: an upstream is host:port (no unix sockets or paths)"
        ));
    }
    let with_port = if rest.starts_with(':') {
        format!("localhost{rest}")
    } else if rest
        .rsplit_once(':')
        .is_some_and(|(_, p)| p.chars().all(|c| c.is_ascii_digit()) && !p.is_empty())
        && !rest.ends_with(']')
    {
        rest.to_string()
    } else {
        format!("{rest}:80")
    };
    with_port
        .parse::<Authority>()
        .map_err(|_| token_err(t, "reverse_proxy: invalid upstream address"))
}

fn parse_reverse_proxy(line: &Line, start: usize, cx: &mut Cx) -> Result<ReverseProxy> {
    let mut upstreams = Vec::new();
    for t in &line.tokens[start..] {
        upstreams.push(parse_upstream(t)?);
    }
    let mut policy = LbPolicy::Random;
    let mut try_duration = Duration::ZERO;
    let mut try_interval = Duration::from_millis(250);
    let mut header_up = Vec::new();
    let mut header_down = Vec::new();
    let mut dial_timeout = Duration::from_secs(3);
    let mut keepalive = Some(Duration::from_secs(120));
    let mut response_header_timeout = Some(DEFAULT_RESPONSE_HEADER_TIMEOUT);
    let mut own_client = false;
    for sub in line.block.as_deref().unwrap_or(&[]) {
        let args = &sub.tokens[1..];
        match sub.name() {
            "to" => {
                for t in args {
                    upstreams.push(parse_upstream(t)?);
                }
            }
            "lb_policy" => {
                policy = match one_arg(sub)?.as_str() {
                    "random" => LbPolicy::Random,
                    "first" => LbPolicy::First,
                    "round_robin" => LbPolicy::RoundRobin,
                    other => bail!(at_err(
                        &sub.at,
                        format!("lb_policy {other:?} is not supported (random, first, round_robin)")
                    )),
                }
            }
            "lb_try_duration" => try_duration = parse_duration(&one_arg(sub)?).map_err(|e| at_err(&sub.at, e))?,
            "lb_try_interval" => try_interval = parse_duration(&one_arg(sub)?).map_err(|e| at_err(&sub.at, e))?,
            // Responses are always streamed as they arrive (the same as `flush_interval -1`).
            "flush_interval" => {
                parse_duration(&one_arg(sub)?).map_err(|e| at_err(&sub.at, e))?;
            }
            "header_up" => header_up.push(parse_header_op(args, &sub.at)?),
            "header_down" => header_down.push(parse_header_op(args, &sub.at)?),
            "transport" => {
                if args.first().map(|t| t.text.as_str()) != Some("http") || args.len() != 1 {
                    bail!(at_err(&sub.at, "reverse_proxy: only `transport http` is supported"));
                }
                for t in sub.block.as_deref().unwrap_or(&[]) {
                    match t.name() {
                        "dial_timeout" => {
                            dial_timeout = parse_duration(&one_arg(t)?).map_err(|e| at_err(&t.at, e))?;
                            own_client = true;
                        }
                        "response_header_timeout" => {
                            let value = parse_duration(&one_arg(t)?).map_err(|e| at_err(&t.at, e))?;
                            // `0` (Caddy's default) or `-1`: no limit.
                            response_header_timeout = Some(value).filter(|d| !d.is_zero());
                        }
                        "keepalive" => {
                            let value = one_arg(t)?;
                            keepalive = if value == "off" {
                                None
                            } else {
                                Some(parse_duration(&value).map_err(|e| at_err(&t.at, e))?)
                            };
                            own_client = true;
                        }
                        "versions" => {
                            if t.tokens[1..].iter().any(|v| v.text != "1.1") {
                                bail!(at_err(
                                    &t.at,
                                    "reverse_proxy: upstreams are spoken to over HTTP/1.1 only"
                                ));
                            }
                        }
                        other => bail!(at_err(&t.at, format!("transport http: unsupported option {other:?}"))),
                    }
                }
            }
            other => bail!(at_err(&sub.at, format!("reverse_proxy: unsupported option {other:?}"))),
        }
    }
    if upstreams.is_empty() {
        bail!(at_err(&line.at, "reverse_proxy needs an upstream"));
    }
    let client = if own_client {
        crate::proxy::client(dial_timeout, keepalive)
    } else {
        cx.client.clone()
    };
    Ok(ReverseProxy {
        upstreams,
        policy,
        try_duration,
        try_interval,
        header_up,
        header_down,
        response_header_timeout,
        dial_timeout,
        client,
        counter: AtomicUsize::new(0),
    })
}

fn parse_matcher_def(line: &Line, name: &str, cx: &mut Cx, site: &mut SiteCx) -> Result<MatcherSet> {
    let mut set = MatcherSet::default();
    if line.tokens.len() >= 2 {
        let first = &line.tokens[1];
        if first.quoted || first.text.starts_with('{') {
            bail!(token_err(first, "expression matchers are not supported"));
        }
        add_matcher(
            &mut set,
            &first.text,
            &line.tokens[2..],
            line.block.as_deref(),
            &line.at,
            name,
            cx,
            site,
        )?;
    } else {
        let Some(block) = line.block.as_deref() else {
            bail!(at_err(&line.at, format!("matcher @{name} is empty")));
        };
        for sub in block {
            add_matcher(
                &mut set,
                sub.name(),
                &sub.tokens[1..],
                sub.block.as_deref(),
                &sub.at,
                name,
                cx,
                site,
            )?;
        }
    }
    if set.matchers.is_empty() {
        bail!(at_err(&line.at, format!("matcher @{name} is empty")));
    }
    Ok(set)
}

#[allow(clippy::too_many_arguments)]
fn add_matcher(
    set: &mut MatcherSet,
    kind: &str,
    args: &[Token],
    block: Option<&[Line]>,
    at: &Location,
    def_name: &str,
    cx: &mut Cx,
    site: &mut SiteCx,
) -> Result<()> {
    let texts = || args.iter().map(|t| t.text.clone()).collect::<Vec<_>>();
    let need_args = || -> Result<()> {
        if args.is_empty() {
            bail!(at_err(at, format!("{kind} needs arguments")));
        }
        Ok(())
    };
    if kind != "file" && kind != "not" && block.is_some() {
        bail!(at_err(at, format!("{kind} takes no block")));
    }
    let existing = set.matchers.iter_mut();
    match kind {
        "path" => {
            need_args()?;
            let patterns: Vec<PathPattern> = args.iter().map(|t| PathPattern::new(&t.text)).collect();
            for m in existing {
                if let Matcher::Path(list) = m {
                    list.extend(patterns);
                    return Ok(());
                }
            }
            set.matchers.push(Matcher::Path(patterns));
        }
        "host" => {
            need_args()?;
            let hosts: Vec<String> = texts().into_iter().map(|h| h.to_ascii_lowercase()).collect();
            for m in existing {
                if let Matcher::Host(list) = m {
                    list.extend(hosts);
                    return Ok(());
                }
            }
            set.matchers.push(Matcher::Host(hosts));
        }
        "method" => {
            need_args()?;
            let mut methods = Vec::new();
            for t in args {
                methods.push(
                    Method::from_bytes(t.text.to_ascii_uppercase().as_bytes())
                        .map_err(|_| token_err(t, "invalid method"))?,
                );
            }
            for m in existing {
                if let Matcher::Method(list) = m {
                    list.extend(methods);
                    return Ok(());
                }
            }
            set.matchers.push(Matcher::Method(methods));
        }
        "header" => {
            need_args()?;
            let (field, negate) = match args[0].text.strip_prefix('!') {
                Some(f) => (f, true),
                None => (args[0].text.as_str(), false),
            };
            let name = header_name(&args[0], field)?;
            let entry = (name, negate, args[1..].iter().map(|t| t.text.clone()).collect());
            for m in existing {
                if let Matcher::Header(list) = m {
                    list.push(entry);
                    return Ok(());
                }
            }
            set.matchers.push(Matcher::Header(vec![entry]));
        }
        "client_ip" | "remote_ip" => {
            need_args()?;
            let nets = parse_ranges(args)?;
            set.matchers.push(if kind == "client_ip" {
                Matcher::ClientIp(nets)
            } else {
                Matcher::RemoteIp(nets)
            });
        }
        "protocol" => {
            if args.len() != 1 {
                bail!(at_err(at, "protocol takes one argument"));
            }
            set.matchers.push(Matcher::Protocol(args[0].text.to_ascii_lowercase()));
        }
        "path_regexp" => {
            if set.matchers.iter().any(|m| matches!(m, Matcher::PathRegexp { .. })) {
                bail!(at_err(at, "path_regexp may appear once per matcher"));
            }
            let (name, pattern) = match args {
                [pattern] => (def_name.to_string(), pattern),
                [name, pattern] => (name.text.clone(), pattern),
                _ => bail!(at_err(at, "path_regexp: `path_regexp [<name>] <regexp>`")),
            };
            let re =
                regex::Regex::new(&pattern.text).map_err(|e| token_err(pattern, format!("invalid regexp: {e}")))?;
            set.matchers.push(Matcher::regexp(&name, re));
        }
        "file" => {
            if set.matchers.iter().any(|m| matches!(m, Matcher::File(_))) {
                bail!(at_err(at, "file may appear once per matcher"));
            }
            let mut fm = FileMatcher {
                root: None,
                try_files: Vec::new(),
            };
            for t in args {
                fm.try_files.push(TryFile::new(template(t)?));
            }
            for sub in block.unwrap_or(&[]) {
                let sargs = &sub.tokens[1..];
                match sub.name() {
                    "root" => {
                        fm.root = Some(
                            cx.loader
                                .store(&static_text(&sargs[0])?)
                                .map_err(|e| at_err(&sub.at, e))?,
                        )
                    }
                    "try_files" => {
                        for t in sargs {
                            if t.text.contains('?') || t.text.starts_with('=') {
                                bail!(token_err(
                                    t,
                                    "try_files: query strings and =status entries are not supported"
                                ));
                            }
                            fm.try_files.push(TryFile::new(template(t)?));
                        }
                    }
                    "try_policy" => {
                        if one_arg(sub)? != "first_exist" {
                            bail!(at_err(&sub.at, "try_policy: only first_exist is supported"));
                        }
                    }
                    other => bail!(at_err(&sub.at, format!("file: unsupported option {other:?}"))),
                }
            }
            if fm.try_files.is_empty() {
                fm.try_files
                    .push(TryFile::new(Template::parse("{path}").expect("valid")));
            }
            if fm.root.is_none() {
                site.needs_root.get_or_insert(at.clone());
            }
            set.matchers.push(Matcher::File(fm));
        }
        "not" => {
            let mut inner = MatcherSet::default();
            if let Some((first, rest)) = args.split_first() {
                add_matcher(&mut inner, &first.text, rest, block, at, def_name, cx, site)?;
            } else {
                for sub in block.unwrap_or(&[]) {
                    add_matcher(
                        &mut inner,
                        sub.name(),
                        &sub.tokens[1..],
                        sub.block.as_deref(),
                        &sub.at,
                        def_name,
                        cx,
                        site,
                    )?;
                }
            }
            if inner.matchers.is_empty() {
                bail!(at_err(at, "not needs a matcher"));
            }
            for m in existing {
                if let Matcher::Not(list) = m {
                    list.push(inner);
                    return Ok(());
                }
            }
            set.matchers.push(Matcher::Not(vec![inner]));
        }
        other => bail!(at_err(at, format!("unsupported matcher {other:?}"))),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::caddyfile::parse_str;
    use std::path::Path;

    fn compile_text(text: &str) -> Result<Config> {
        let file = parse_str(text, Path::new("Caddyfile"))?;
        let mut loader = Loader::new(1 << 20);
        compile(&file, &mut loader, crate::proxy::client(Duration::from_secs(3), None))
    }

    fn names(routes: &[Route]) -> Vec<String> {
        routes
            .iter()
            .map(|r| match &r.handler {
                Handler::Root(_) => "root".to_string(),
                Handler::Header { .. } => format!(
                    "header{}",
                    r.matcher.as_ref().and_then(|m| m.single_path()).unwrap_or("")
                ),
                Handler::Respond { .. } => format!(
                    "respond{}",
                    r.matcher.as_ref().and_then(|m| m.single_path()).unwrap_or("")
                ),
                Handler::Subroute(_) => "subroute".to_string(),
                Handler::Proxy(_) => "proxy".to_string(),
                Handler::Files(_) => "files".to_string(),
                Handler::Redir { .. } => "redir".to_string(),
                Handler::Encode(_) => "encode".to_string(),
                _ => "other".to_string(),
            })
            .collect()
    }

    #[test]
    fn sorts_like_caddy() {
        let config = compile_text(
            ":8080 {\n\trespond \"x\"\n\treverse_proxy app:1\n\trespond /a* \"a\"\n\tredir /r /t\n\theader X 1\n\trespond /abc* \"abc\"\n\theader /p Y 2\n\tencode\n}\n",
        )
        .unwrap();
        let routes = &config.servers[0].sites[0].routes;
        assert_eq!(
            names(routes),
            [
                "header/p",
                "header",
                "redir",
                "encode",
                "respond/abc*",
                "respond/a*",
                "respond",
                "proxy"
            ]
        );
    }

    #[test]
    fn route_blocks_keep_their_order_and_handles_are_grouped() {
        let config = compile_text(":8080 {\n\troute {\n\t\trespond /b 200\n\t\theader X 1\n\t}\n\thandle /x {\n\t\trespond 1\n\t}\n\thandle {\n\t\trespond 2\n\t}\n}\n").unwrap();
        let routes = &config.servers[0].sites[0].routes;
        let Handler::Subroute(inner) = &routes[2].handler else {
            panic!("route block last")
        };
        assert_eq!(names(inner), ["respond/b", "header"]);
        assert_eq!(routes[0].group, routes[1].group);
        assert!(routes[0].group.is_some());
        assert!(routes[0].matcher.is_some(), "handle /x sorts before the bare handle");
    }

    #[test]
    fn addresses_and_servers() {
        let config = compile_text("{\n\tservers {\n\t\tprotocols h1 h2c\n\t}\n}\na.example:8080, b.example:8080 {\n\trespond a\n}\n:8080 {\n\trespond any\n}\n:9090 {\n\trespond z\n}\n").unwrap();
        assert_eq!(config.servers.len(), 2);
        let s = &config.servers[0];
        assert_eq!(s.port, 8080);
        assert_eq!(s.sites.len(), 3);
        assert!(s.sites[2].hosts.is_empty(), "catch-all last");
        assert!(s.protocols.h2c && !s.protocols.h3);
    }

    #[test]
    fn rejects_what_is_not_supported() {
        for (text, message) in [
            (":80 {\n\tphp_fastcgi x:9000\n}\n", "unsupported directive"),
            (":80 {\n\tfile_server\n}\n", "need a site root"),
            ("example.com {\n\trespond x\n}\n", "HTTPS needs `tls"),
            (":80 {\n\trespond @nope 404\n}\n", "@nope is not defined"),
            (
                ":80 {\n\t@m expression {path} == '/'\n\trespond @m 1\n}\n",
                "unsupported matcher",
            ),
            (":80 {\n\treverse_proxy https://x\n}\n", "not supported"),
            ("{\n\temail a@b.c\n}\n:80 {\n}\n", "unsupported global option"),
            (":80 {\n\theader X\n}\n", "a value is required"),
            (":80 {\n\trespond {nope}\n}\n", "unknown placeholder"),
            (":80 {\n}\n:80 {\n}\n", "more than once"),
        ] {
            let err = compile_text(text).err().map(|e| e.to_string()).unwrap_or_default();
            assert!(err.contains(message), "{text:?}: {err}");
        }
    }

    #[test]
    fn durations() {
        assert_eq!(parse_duration("300ms").unwrap(), Duration::from_millis(300));
        assert_eq!(parse_duration("1h30m").unwrap(), Duration::from_secs(5400));
        assert_eq!(parse_duration("-1").unwrap(), Duration::ZERO);
        assert_eq!(parse_duration("10").unwrap(), Duration::from_secs(10));
        assert!(parse_duration("5x").is_err());
    }

    #[test]
    fn go_stable_sort_matches_simple_cases() {
        let mut v: Vec<u32> = (0..50).rev().collect();
        go_stable_sort(&mut v, |a, b| a < b);
        assert_eq!(v, (0..50).collect::<Vec<_>>());
        let mut pairs: Vec<(u32, u32)> = (0..45).map(|i| (i % 3, i)).collect();
        go_stable_sort(&mut pairs, |a, b| a.0 < b.0);
        assert!(
            pairs
                .windows(2)
                .all(|w| w[0].0 < w[1].0 || (w[0].0 == w[1].0 && w[0].1 < w[1].1))
        );
    }
}
