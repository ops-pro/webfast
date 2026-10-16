//! The recipes (recipes/*/Caddyfile) stay valid: each is compiled and its site files loaded, with
//! its root pointed at a small site made here; the static site and the single-page app are also
//! served and asked a few requests.

use bytes::Bytes;
use http::{HeaderMap, Request, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;
use webfast::server;

fn recipes() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("recipes")
}

/// A built site: pages, a directory with an index, a hashed asset with its Brotli sibling.
fn site() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let write = |path: &str, body: &[u8]| {
        let file = dir.path().join(path);
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(file, body).unwrap();
    };
    write("index.html", b"<!doctype html><title>Home</title><div id=app></div>");
    write("about.html", b"<!doctype html><title>About</title>");
    write("docs/index.html", b"<!doctype html><title>Docs</title>");
    let js = b"console.log('the app');".repeat(40);
    write("assets/app-1a2b3c.js", &js);
    let mut br = Vec::new();
    {
        let mut writer = brotli::CompressorWriter::new(&mut br, 4096, 9, 22);
        writer.write_all(&js).unwrap();
    }
    write("assets/app-1a2b3c.js.br", &br);
    dir
}

/// The recipe's configuration, its site at `root` and its :8080 on a free port.
fn config(recipe: &str, root: &Path) -> webfast::config::Config {
    let text = std::fs::read_to_string(recipes().join(recipe).join("Caddyfile")).unwrap();
    let text = text
        .replace("root * /srv", &format!("root * {}", root.display()))
        .replace(":8080 {", ":0 {");
    let file = webfast::caddyfile::parse_str(&text, Path::new("Caddyfile")).unwrap_or_else(|e| panic!("{recipe}: {e}"));
    webfast::load_parsed(&file, 1 << 24).unwrap_or_else(|e| panic!("{recipe}: {e}"))
}

#[test]
fn every_recipe_loads() {
    let site = site();
    let mut loaded = Vec::new();
    for entry in std::fs::read_dir(recipes()).unwrap() {
        let dir = entry.unwrap().path();
        if dir.join("Caddyfile").exists() {
            let name = dir.file_name().unwrap().to_string_lossy().into_owned();
            assert!(!config(&name, site.path()).servers.is_empty(), "{name}");
            loaded.push(name);
        }
    }
    loaded.sort();
    assert_eq!(
        loaded,
        ["app-behind", "behind-proxy", "spa", "static-site", "tls-http3"]
    );
}

struct Served {
    running: server::Running,
    base: String,
    client: Client<HttpConnector, Full<Bytes>>,
}

impl Served {
    async fn start(recipe: &str, root: &Path) -> Served {
        let running = server::start(config(recipe, root)).await.unwrap();
        let base = format!("http://127.0.0.1:{}", running.bound[0].1.port());
        let client = Client::builder(TokioExecutor::new()).build_http();
        Served { running, base, client }
    }

    async fn get(&self, path: &str, accept_encoding: Option<&str>) -> (StatusCode, HeaderMap, Bytes) {
        let mut request = Request::get(format!("{}{path}", self.base));
        if let Some(accept) = accept_encoding {
            request = request.header("accept-encoding", accept);
        }
        let response = self
            .client
            .request(request.body(Full::new(Bytes::new())).unwrap())
            .await
            .unwrap();
        let (status, headers) = (response.status(), response.headers().clone());
        (
            status,
            headers,
            response.into_body().collect().await.unwrap().to_bytes(),
        )
    }
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> &'a str {
    headers.get(name).map_or("", |v| v.to_str().unwrap())
}

#[tokio::test]
async fn the_static_site_recipe_serves_clean_urls_and_siblings() {
    let site = site();
    let served = Served::start("static-site", site.path()).await;

    let (status, headers, body) = served.get("/about", None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.starts_with(b"<!doctype html><title>About"));
    assert_eq!(header(&headers, "x-content-type-options"), "nosniff");

    let (status, headers, _) = served.get("/about.html", None).await;
    assert_eq!(
        (status, header(&headers, "location")),
        (StatusCode::PERMANENT_REDIRECT, "/about")
    );

    let (status, _, body) = served.get("/docs/", None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.ends_with(b"<title>Docs</title>"));

    let (status, headers, _) = served
        .get("/assets/app-1a2b3c.js", Some("gzip, deflate, br, zstd"))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(header(&headers, "content-encoding"), "br");
    assert_eq!(header(&headers, "cache-control"), "public, max-age=31536000, immutable");

    assert_eq!(served.get("/missing", None).await.0, StatusCode::NOT_FOUND);
    served.running.shutdown(Duration::from_secs(1)).await;
}

#[tokio::test]
async fn the_spa_recipe_answers_every_other_path_with_the_app() {
    let site = site();
    let served = Served::start("spa", site.path()).await;
    for path in ["/", "/users/42", "/settings/profile"] {
        let (status, headers, body) = served.get(path, None).await;
        assert_eq!(status, StatusCode::OK, "{path}");
        assert!(body.ends_with(b"<div id=app></div>"), "{path}");
        assert_eq!(header(&headers, "cache-control"), "no-cache", "{path}");
    }
    let (status, headers, _) = served.get("/assets/app-1a2b3c.js", Some("br")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(header(&headers, "content-encoding"), "br");
    assert_eq!(header(&headers, "cache-control"), "public, max-age=31536000, immutable");
    served.running.shutdown(Duration::from_secs(1)).await;
}
