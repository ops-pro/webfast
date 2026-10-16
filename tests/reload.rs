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
    webfast::load_parsed_reusing(&file, 1 << 24, None, watch, &stores)
}

/// One request on an open connection; the head and body as text.
async fn ask(stream: &mut TcpStream, path: &str) -> String {
    let request = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n");
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

    // SAFETY: as above.
    assert_eq!(unsafe { libc::kill(pid, libc::SIGTERM) }, 0);
    let status = child.wait().unwrap();
    assert!(status.success(), "{status}");
}
