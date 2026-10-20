//! A configuration put in place while the server runs (`Running::reload`, SIGHUP): the sites
//! change for the next request, also on a connection that stays open; site roots that stay are
//! taken over, not read again; certificates are read again; what only a restart can change is
//! refused, and the running configuration stays.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use webfast::server::{self, Running};

fn load(text: &str, running: Option<&Running>) -> anyhow::Result<webfast::config::Config> {
    load_watching(text, running, webfast::watch::Watch::default())
}

fn load_watching(
    text: &str,
    running: Option<&Running>,
    watch: webfast::watch::Watch,
) -> anyhow::Result<webfast::config::Config> {
    let file = webfast::caddyfile::parse_str(text, Path::new("Caddyfile"))?;
    let stores = running.map(Running::stores).unwrap_or_default();
    webfast::load_parsed_reusing(
        &file,
        1 << 24,
        None,
        Some(webfast::files::DEFAULT_MAX_FILE_IN_MEMORY),
        watch,
        &stores,
    )
}

/// One request on an open connection; the head and body as text.
async fn ask(stream: &mut TcpStream, path: &str) -> String {
    ask_with(stream, path, "").await
}

/// `extra`: more header lines, each ending in CRLF.
async fn ask_with(stream: &mut TcpStream, path: &str, extra: &str) -> String {
    let request = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n{extra}\r\n");
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut answer = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
            .await
            .expect("an answer")
            .unwrap();
        assert!(n > 0, "the connection was closed");
        answer.extend_from_slice(&buf[..n]);
        let text = String::from_utf8_lossy(&answer);
        if let Some(end) = text.find("\r\n\r\n") {
            let length: usize = text[..end]
                .lines()
                .find_map(|l| l.strip_prefix("content-length: "))
                .map_or(0, |v| v.trim().parse().unwrap());
            if answer.len() >= end + 4 + length {
                return text.into_owned();
            }
        }
    }
}

#[tokio::test]
async fn a_reload_replaces_the_sites_for_the_next_request() {
    let site = tempfile::tempdir().unwrap();
    std::fs::write(site.path().join("page.html"), "the page").unwrap();
    let root = site.path().display();
    let first = format!(":0 {{\n\troot * {root}\n\theader X-Version 1\n\tfile_server\n}}\n");
    let mut running = server::start(load(&first, None).unwrap()).await.unwrap();
    let port = running.bound[0].1.port();
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let answer = ask(&mut stream, "/page.html").await;
    assert!(
        answer.contains("x-version: 1") && answer.ends_with("the page"),
        "{answer}"
    );
    let before = running.stores();

    let second = format!(
        ":0 {{\n\troot * {root}\n\theader X-Version 2\n\trespond /new \"new\"\n\tfile_server\n\thandle_errors {{\n\t\trespond \"missing\"\n\t}}\n}}\n"
    );
    running.reload(load(&second, Some(&running)).unwrap()).await.unwrap();
    // The same connection, the new configuration.
    let answer = ask(&mut stream, "/page.html").await;
    assert!(
        answer.contains("x-version: 2") && answer.ends_with("the page"),
        "{answer}"
    );
    assert!(ask(&mut stream, "/new").await.ends_with("new"));
    let missing = ask(&mut stream, "/nope").await;
    assert!(
        missing.starts_with("HTTP/1.1 404") && missing.ends_with("missing"),
        "{missing}"
    );
    // The root it kept was taken over, not read again.
    let after = running.stores();
    assert_eq!(after.len(), 1);
    assert!(Arc::ptr_eq(&before[0], &after[0]));

    // What only a restart can change is refused; the running configuration stays.
    for (text, why) in [
        (
            format!("{{\n\tservers {{\n\t\tprotocols h1 h2c\n\t}}\n}}\n{second}"),
            "protocols changed",
        ),
        (format!("{second}:0 {{\n\trespond x\n}}\n"), "defined more than once"),
    ] {
        let refused = match load(&text, Some(&running)) {
            Ok(config) => running.reload(config).await.err(),
            Err(e) => Some(e),
        };
        let refused = refused.map(|e| format!("{e:#}")).unwrap_or_default();
        assert!(refused.contains(why), "{refused}");
    }
    let other_port = format!("{second}127.0.0.1:1 {{\n\trespond x\n}}\n");
    let refused = running
        .reload(load(&other_port, Some(&running)).unwrap())
        .await
        .unwrap_err();
    assert!(refused.to_string().contains("the ports changed"), "{refused}");
    assert!(ask(&mut stream, "/page.html").await.contains("x-version: 2"));
    running.shutdown(Duration::from_secs(1)).await;
}

#[tokio::test]
async fn after_a_reload_the_files_watched_are_the_new_configurations() {
    let (a, b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    std::fs::write(a.path().join("one.txt"), "a1").unwrap();
    std::fs::write(b.path().join("two.txt"), "b1").unwrap();
    let watch = webfast::watch::Watch {
        mode: webfast::watch::Mode::Poll,
        poll: Duration::from_millis(200),
    };
    let first = format!(":0 {{\n\troot * {}\n\tfile_server\n}}\n", a.path().display());
    let mut running = server::start(load_watching(&first, None, watch).unwrap())
        .await
        .unwrap();
    let port = running.bound[0].1.port();
    // A root it keeps, and one it adds.
    let second = format!(
        ":0 {{\n\troot * {}\n\thandle_path /b/* {{\n\t\troot * {}\n\t\tfile_server\n\t}}\n\tfile_server\n}}\n",
        a.path().display(),
        b.path().display()
    );
    running
        .reload(load_watching(&second, Some(&running), watch).unwrap())
        .await
        .unwrap();
    assert_eq!(running.stores().len(), 2);
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    assert!(ask(&mut stream, "/b/two.txt").await.ends_with("b1"));
    std::fs::write(a.path().join("one.txt"), "a2").unwrap();
    std::fs::write(b.path().join("two.txt"), "b2").unwrap();
    let started = std::time::Instant::now();
    loop {
        let one = ask(&mut stream, "/one.txt").await;
        let two = ask(&mut stream, "/b/two.txt").await;
        if one.ends_with("a2") && two.ends_with("b2") {
            break;
        }
        assert!(started.elapsed() < Duration::from_secs(10), "{one}\n{two}");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    running.shutdown(Duration::from_secs(1)).await;
}

#[tokio::test]
async fn a_connection_open_across_a_reload_is_trusted_as_the_new_configuration_says() {
    let site = ":0 {\n\trespond \"{client_ip}\"\n}\n";
    let mut running = server::start(load(site, None).unwrap()).await.unwrap();
    let port = running.bound[0].1.port();
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let forwarded = "X-Forwarded-For: 203.0.113.9\r\n";
    assert!(ask_with(&mut stream, "/", forwarded).await.ends_with("127.0.0.1"));
    let trusting = format!("{{\n\tservers {{\n\t\ttrusted_proxies static 127.0.0.1/8\n\t}}\n}}\n{site}");
    running.reload(load(&trusting, Some(&running)).unwrap()).await.unwrap();
    assert!(ask_with(&mut stream, "/", forwarded).await.ends_with("203.0.113.9"));
    running.reload(load(site, Some(&running)).unwrap()).await.unwrap();
    assert!(ask_with(&mut stream, "/", forwarded).await.ends_with("127.0.0.1"));
    running.shutdown(Duration::from_secs(1)).await;
}

#[tokio::test]
async fn lazy_connections_keep_their_configuration_until_they_close() {
    let site = tempfile::tempdir().unwrap();
    std::fs::write(site.path().join("page.txt"), "v1").unwrap();
    let watch = webfast::watch::Watch {
        mode: webfast::watch::Mode::Poll,
        poll: Duration::from_millis(200),
    };
    let lazy = |version: u32, running: Option<&Running>| {
        let text = format!(
            ":0 {{\n\troot * {}\n\theader X-Version {version}\n\tfile_server\n}}\n",
            site.path().display()
        );
        let mut config = load_watching(&text, running, watch).unwrap();
        config.servers[0].reload = webfast::config::ReloadMode::Lazy;
        config
    };
    let mut running = server::start(lazy(1, None)).await.unwrap();
    let port = running.bound[0].1.port();
    let mut old = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    assert!(ask(&mut old, "/page.txt").await.contains("x-version: 1"));

    running.reload(lazy(2, Some(&running))).await.unwrap();
    // The connection open before the reload keeps its configuration; a new one gets the new.
    let mut new = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    assert!(ask(&mut new, "/page.txt").await.contains("x-version: 2"));
    for _ in 0..3 {
        assert!(ask(&mut old, "/page.txt").await.contains("x-version: 1"));
    }

    // Changed files reach both: the old configuration's ready answers are forgotten too.
    std::fs::write(site.path().join("page.txt"), "v2").unwrap();
    let started = std::time::Instant::now();
    loop {
        let (before, after) = (ask(&mut old, "/page.txt").await, ask(&mut new, "/page.txt").await);
        if before.ends_with("v2") && after.ends_with("v2") {
            assert!(before.contains("x-version: 1") && after.contains("x-version: 2"));
            break;
        }
        assert!(started.elapsed() < Duration::from_secs(10), "{before}\n{after}");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // The mode itself needs a restart.
    let mut immediate = lazy(3, Some(&running));
    immediate.servers[0].reload = webfast::config::ReloadMode::Immediate;
    let refused = running.reload(immediate).await.unwrap_err();
    assert!(refused.to_string().contains("WEB_RELOAD"), "{refused}");
    running.shutdown(Duration::from_secs(1)).await;
}

/// The configuration `:0 { header X-Version <version>; respond "ok" }` with WEB_RELOAD=drain.
fn draining(version: u32, window: Duration, running: Option<&Running>) -> webfast::config::Config {
    let text = format!(":0 {{\n\theader X-Version {version}\n\trespond \"ok\"\n}}\n");
    let mut config = load(&text, running).unwrap();
    config.servers[0].reload = webfast::config::ReloadMode::Drain(window);
    config
}

/// How long until the server closes `stream`, at most `limit`.
async fn closed_after(mut stream: TcpStream, started: std::time::Instant, limit: Duration) -> Option<Duration> {
    let mut buf = [0u8; 256];
    loop {
        match tokio::time::timeout_at((started + limit).into(), stream.read(&mut buf)).await {
            Ok(Ok(0)) | Ok(Err(_)) => return Some(started.elapsed()),
            Ok(Ok(_)) => continue,
            Err(_) => return None,
        }
    }
}

#[tokio::test]
async fn drain_closes_the_old_connections_spread_over_the_window() {
    let window = Duration::from_millis(1500);
    let mut running = server::start(draining(1, window, None)).await.unwrap();
    let port = running.bound[0].1.port();
    let mut old = Vec::new();
    for _ in 0..24 {
        let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        assert!(ask(&mut stream, "/").await.contains("x-version: 1"));
        old.push(stream);
    }

    running.reload(draining(2, window, Some(&running))).await.unwrap();
    let started = std::time::Instant::now();
    let mut new = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    assert!(ask(&mut new, "/").await.contains("x-version: 2"));
    let limit = window + Duration::from_secs(1);
    let waits: Vec<_> = old
        .into_iter()
        .map(|stream| tokio::spawn(closed_after(stream, started, limit)))
        .collect();
    let mut times = Vec::new();
    for wait in waits {
        times.push(
            wait.await
                .unwrap()
                .expect("every old connection closed within the window"),
        );
    }
    times.sort();
    let (first, last) = (times[0], times[times.len() - 1]);
    // Spread over the window, not all at once (24 moments drawn: their range is under a third of
    // the window about once in four billion times).
    assert!(last - first > window / 3, "{times:?}");
    // The new connection is not touched.
    assert!(
        closed_after(new, std::time::Instant::now(), Duration::from_millis(500))
            .await
            .is_none()
    );
    running.shutdown(Duration::from_secs(1)).await;
}

#[tokio::test]
async fn drain_closes_old_http3_connections_too() {
    let dir = tempfile::tempdir().unwrap();
    let cert = self_signed(dir.path(), "cert");
    let text = |version: u32| {
        format!(
            "localhost:0 {{\n\ttls {d}/cert.pem {d}/cert.key\n\theader X-Version {version}\n\trespond \"ok\"\n}}\n",
            d = dir.path().display()
        )
    };
    let window = Duration::from_millis(300);
    let draining = |version: u32, running: Option<&Running>| {
        let mut config = load(&text(version), running).unwrap();
        config.servers[0].reload = webfast::config::ReloadMode::Drain(window);
        config
    };
    let mut running = server::start(draining(1, None)).await.unwrap();
    let port = running.bound[0].1.port();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.der().clone()).unwrap();
    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    let quic = quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap();
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(quic)));
    let conn = endpoint
        .connect(std::net::SocketAddr::from(([127, 0, 0, 1], port)), "localhost")
        .unwrap()
        .await
        .unwrap();
    let (mut driver, mut send_request) = h3::client::new(h3_quinn::Connection::new(conn.clone())).await.unwrap();
    let drive = tokio::spawn(async move { std::future::poll_fn(|cx| driver.poll_close(cx)).await });
    let mut stream = send_request
        .send_request(
            http::Request::get(format!("https://localhost:{port}/"))
                .body(())
                .unwrap(),
        )
        .await
        .unwrap();
    stream.finish().await.unwrap();
    let response = stream.recv_response().await.unwrap();
    assert_eq!(response.headers()["x-version"], "1");
    while stream.recv_data().await.unwrap().is_some() {}

    running.reload(draining(2, Some(&running))).await.unwrap();
    tokio::time::timeout(window + Duration::from_secs(5), conn.closed())
        .await
        .expect("the old QUIC connection was closed after the reload");
    drop(send_request);
    drive.abort();
    endpoint.close(0u32.into(), b"done");
    running.shutdown(Duration::from_secs(1)).await;
}

fn self_signed(dir: &Path, name: &str) -> rcgen::Certificate {
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    std::fs::write(dir.join(format!("{name}.pem")), certified.cert.pem()).unwrap();
    std::fs::write(dir.join(format!("{name}.key")), certified.signing_key.serialize_pem()).unwrap();
    certified.cert
}

/// Whether a TLS handshake that trusts only `cert` succeeds.
async fn handshake_trusting(cert: &rcgen::Certificate, port: u16) -> bool {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.der().clone()).unwrap();
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    connector.connect("localhost".try_into().unwrap(), tcp).await.is_ok()
}

#[tokio::test]
async fn a_reload_reads_the_certificates_again() {
    let dir = tempfile::tempdir().unwrap();
    let first = self_signed(dir.path(), "first");
    let second = self_signed(dir.path(), "second");
    let text = |name: &str| {
        format!(
            "localhost:0 {{\n\ttls {d}/{name}.pem {d}/{name}.key\n\trespond \"ok\"\n}}\n",
            d = dir.path().display()
        )
    };
    let mut running = server::start(load(&text("first"), None).unwrap()).await.unwrap();
    let port = running.bound[0].1.port();
    assert!(handshake_trusting(&first, port).await);
    assert!(!handshake_trusting(&second, port).await);

    running
        .reload(load(&text("second"), Some(&running)).unwrap())
        .await
        .unwrap();
    assert!(handshake_trusting(&second, port).await);
    assert!(!handshake_trusting(&first, port).await);

    // A certificate that cannot be read stops the reload; the one in use stays.
    let missing = text("second").replace("second.key", "missing.key");
    assert!(running.reload(load(&missing, Some(&running)).unwrap()).await.is_err());
    assert!(handshake_trusting(&second, port).await);
    running.shutdown(Duration::from_secs(1)).await;
}

/// The binary itself: SIGHUP reloads, a broken file is refused, SIGTERM stops.
#[cfg(target_os = "linux")]
#[test]
fn sighup_reloads_the_running_binary() {
    use std::io::{BufRead, BufReader, Read, Write};
    use std::process::{Command, Stdio};
    let dir = tempfile::tempdir().unwrap();
    let caddyfile = dir.path().join("Caddyfile");
    let write = |text: &str| std::fs::write(&caddyfile, text).unwrap();
    write(":0 {\n\trespond \"one\"\n}\n");
    let mut child = Command::new(env!("CARGO_BIN_EXE_webfast"))
        .args(["run", "--config"])
        .arg(&caddyfile)
        .env("WEB_WORKERS", "1")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let pid = child.id() as libc::pid_t;
    // The log, line by line, from a thread: the port it listens on, then the reloads.
    let (lines, log) = std::sync::mpsc::channel::<String>();
    let stderr = child.stderr.take().unwrap();
    std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            if lines.send(line).is_err() {
                break;
            }
        }
    });
    let wait_for = |message: &str| -> serde_json::Value {
        loop {
            let line = log.recv_timeout(Duration::from_secs(20)).expect("the log line");
            let json: serde_json::Value = serde_json::from_str(&line).unwrap_or_default();
            if json["message"] == message {
                return json;
            }
        }
    };
    let address = wait_for("listening")["address"].as_str().unwrap().to_string();
    let port: u16 = address.rsplit(':').next().unwrap().parse().unwrap();
    wait_for("started");
    let get = || {
        let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        stream
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .unwrap();
        let mut answer = String::new();
        stream.read_to_string(&mut answer).unwrap();
        answer
    };
    assert!(get().ends_with("one"));

    write(":0 {\n\trespond \"two\"\n}\n");
    // SAFETY: a signal to the child this test started.
    assert_eq!(unsafe { libc::kill(pid, libc::SIGHUP) }, 0);
    wait_for("configuration reloaded");
    assert!(get().ends_with("two"));

    write(":0 {\n\tnot_a_directive\n}\n");
    // SAFETY: as above.
    assert_eq!(unsafe { libc::kill(pid, libc::SIGHUP) }, 0);
    let refused = wait_for("configuration not reloaded; the running one stays");
    assert!(
        refused["error"].as_str().unwrap().contains("not_a_directive"),
        "{refused}"
    );
    assert!(get().ends_with("two"));

    // `webfast reload --pid`: the command checks the file first (a broken one is refused there,
    // nothing is sent), then signals the server.
    write(":0 {\n\trespond \"three\"\n}\n");
    let reload = |extra: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_webfast"))
            .args(["reload", "--config"])
            .arg(&caddyfile)
            .args(extra)
            .arg("--pid")
            .arg(pid.to_string())
            .output()
            .unwrap()
    };
    let sent = reload(&["--adapter", "caddyfile"]);
    assert!(sent.status.success(), "{}", String::from_utf8_lossy(&sent.stderr));
    wait_for("configuration reloaded");
    assert!(get().ends_with("three"));
    write(":0 {\n\tnot_a_directive\n}\n");
    let refused = reload(&[]);
    assert_eq!(refused.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&refused.stderr).contains("not_a_directive"));
    assert!(get().ends_with("three"), "nothing was sent");

    // SAFETY: as above.
    assert_eq!(unsafe { libc::kill(pid, libc::SIGTERM) }, 0);
    let status = child.wait().unwrap();
    assert!(status.success(), "{status}");
}

/// `--envfile`: the variables for the Caddyfile's `{$…}` placeholders, as `caddy run --envfile`.
#[test]
fn an_envfile_fills_the_placeholders() {
    use std::process::Command;
    let dir = tempfile::tempdir().unwrap();
    let caddyfile = dir.path().join("Caddyfile");
    std::fs::write(&caddyfile, ":0 {\n\trespond \"{$GREETING}\"\n}\n").unwrap();
    let envfile = dir.path().join("env");
    std::fs::write(
        &envfile,
        "# the greeting\nexport GREETING=\"hello there\"\n\nOTHER='x'\n",
    )
    .unwrap();
    let ok = Command::new(env!("CARGO_BIN_EXE_webfast"))
        .args(["validate", "--config"])
        .arg(&caddyfile)
        .arg("--envfile")
        .arg(&envfile)
        .output()
        .unwrap();
    assert!(ok.status.success(), "{}", String::from_utf8_lossy(&ok.stderr));
    std::fs::write(&envfile, "GREETING\n").unwrap();
    let bad = Command::new(env!("CARGO_BIN_EXE_webfast"))
        .args(["validate", "--config"])
        .arg(&caddyfile)
        .arg("--envfile")
        .arg(&envfile)
        .output()
        .unwrap();
    assert_eq!(bad.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&bad.stderr).contains("line 1: not KEY=VALUE"));
}
