//! Where an API's spec comes from, and how it is kept current.
//!
//! ```yaml
//! spec: openapi.yaml                 # a file, read at startup (as before)
//! spec:
//!   file: openapi.yaml               # a file, read again when it changes…
//!   uri: /openapi.json               # …or a path, asked of this server's own routes (in-process)
//!   # uri: http://app:8787/openapi.json   or a URL, fetched directly
//!   refresh: 1m                      # how often to look again (1m for a uri; a file: only if set)
//!   ttl: 24h                         # how long the last spec holds when the source cannot be read
//!   timeout: 5s
//!   headers: {Authorization: "Bearer ${SPEC_TOKEN}"}   # ${VAR}: from the environment
//! ```
//!
//! A look sends `If-None-Match` / `If-Modified-Since` (a file: compares its size, modification
//! time and inode): unchanged, nothing is read or compiled. A changed spec is compiled on a
//! blocking thread and replaces the old one whole; requests in flight keep the one they found. A
//! source that cannot be read, or a spec that does not compile, leaves the last one in place (the
//! process never stops over it) and is tried again sooner. Until a spec is there — or once `ttl`
//! has passed without a successful look — the API's requests get 503 (in `block`).
//!
//! A path is asked of the server itself, through its routes (a file it serves from memory, or the
//! upstream it proxies to), marked so that the request checks do not check their own spec request.

use crate::body::Body;
use anyhow::{Context, Result, anyhow, bail};
use bytes::Bytes;
use http::header::{IF_MODIFIED_SINCE, IF_NONE_MATCH};
use http::{HeaderMap, HeaderName, HeaderValue, Response, StatusCode, Uri};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

/// A spec is not expected to be larger.
pub(super) const MAX_SPEC: usize = 10 << 20;

/// Requests to this server's own routes (src/server.rs builds it once the server runs).
pub type LocalFetch =
    Arc<dyn Fn(http::Request<Body>) -> Pin<Box<dyn Future<Output = Response<Body>> + Send>> + Send + Sync>;

pub(super) enum SpecConfig {
    File(String),
    Source(SourceConfig),
}

/// A file name, or a map with `deny_unknown_fields` errors kept (an untagged enum would hide them).
impl<'de> Deserialize<'de> for SpecConfig {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        struct Visit;
        impl<'de> serde::de::Visitor<'de> for Visit {
            type Value = SpecConfig;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a file name, or {file | uri, refresh, ttl, timeout, headers}")
            }
            fn visit_str<E: serde::de::Error>(self, v: &str) -> std::result::Result<SpecConfig, E> {
                Ok(SpecConfig::File(v.to_string()))
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(self, map: A) -> std::result::Result<SpecConfig, A::Error> {
                SourceConfig::deserialize(serde::de::value::MapAccessDeserializer::new(map)).map(SpecConfig::Source)
            }
        }
        d.deserialize_any(Visit)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SourceConfig {
    file: Option<String>,
    uri: Option<String>,
    refresh: Option<String>,
    ttl: Option<String>,
    timeout: Option<String>,
    #[serde(default)]
    headers: BTreeMap<String, String>,
}

pub(super) enum Origin {
    File(PathBuf),
    Url(Uri),
    /// A path and query asked of this server.
    Local(String),
    /// Given as text (tests, tools).
    Inline,
}

pub(super) struct Source {
    pub origin: Origin,
    /// `None`: read once.
    pub refresh: Option<Duration>,
    pub ttl: Option<Duration>,
    pub timeout: Duration,
    pub headers: HeaderMap,
}

/// What the last successful look found, to tell whether the next one changed anything.
#[derive(Default)]
pub(super) struct Seen {
    pub etag: Option<HeaderValue>,
    pub last_modified: Option<HeaderValue>,
    pub file: Option<(u64, Option<std::time::SystemTime>, u64)>,
    pub digest: Option<[u8; 32]>,
}

impl Source {
    pub fn inline() -> Source {
        Source {
            origin: Origin::Inline,
            refresh: None,
            ttl: None,
            timeout: Duration::from_secs(5),
            headers: HeaderMap::new(),
        }
    }

    pub fn from_config(config: &SpecConfig, base: &Path) -> Result<Source> {
        let duration = |value: &Option<String>, what: &str| -> Result<Option<Duration>> {
            match value {
                Some(text) => match crate::config::parse_duration(text) {
                    Ok(d) if !d.is_zero() => Ok(Some(d)),
                    Ok(_) => bail!("spec {what}: more than 0"),
                    Err(e) => bail!("spec {what}: {e}"),
                },
                None => Ok(None),
            }
        };
        let source = match config {
            SpecConfig::File(file) => Source {
                origin: Origin::File(base.join(file)),
                ..Source::inline()
            },
            SpecConfig::Source(c) => {
                let origin = match (&c.file, &c.uri) {
                    (Some(file), None) => Origin::File(base.join(file)),
                    (None, Some(uri)) if uri.starts_with('/') => {
                        uri.parse::<http::uri::PathAndQuery>()
                            .map_err(|e| anyhow!("spec uri {uri:?}: {e}"))?;
                        Origin::Local(uri.clone())
                    }
                    (None, Some(uri)) => {
                        let parsed: Uri = uri.parse().map_err(|e| anyhow!("spec uri {uri:?}: {e}"))?;
                        if !matches!(parsed.scheme_str(), Some("http" | "https")) || parsed.host().is_none() {
                            bail!("spec uri {uri:?}: a path (/openapi.json) or an http(s) URL");
                        }
                        Origin::Url(parsed)
                    }
                    _ => bail!("spec: either `file` or `uri`"),
                };
                let remote = !matches!(origin, Origin::File(_));
                let mut headers = HeaderMap::new();
                for (name, value) in &c.headers {
                    let name = HeaderName::from_bytes(name.as_bytes()).map_err(|_| anyhow!("spec header {name:?}"))?;
                    let value = HeaderValue::from_str(&expand(value)?)
                        .map_err(|_| anyhow!("spec header {name}: not a valid value"))?;
                    headers.insert(name, value);
                }
                if !headers.is_empty() && !remote {
                    bail!("spec headers: only for a uri");
                }
                Source {
                    origin,
                    refresh: duration(&c.refresh, "refresh")?.or(remote.then_some(Duration::from_secs(60))),
                    ttl: duration(&c.ttl, "ttl")?,
                    timeout: duration(&c.timeout, "timeout")?.unwrap_or(Duration::from_secs(5)),
                    headers,
                }
            }
        };
        Ok(source)
    }

    /// For the log.
    pub fn describe(&self) -> String {
        match &self.origin {
            Origin::File(path) => path.display().to_string(),
            Origin::Url(uri) => uri.to_string(),
            Origin::Local(path) => format!("{path} (this server)"),
            Origin::Inline => "inline".into(),
        }
    }

    /// Read at startup, before the server runs (a file); the others once it runs.
    pub fn read_at_startup(&self) -> bool {
        matches!(self.origin, Origin::File(_))
    }

    /// The spec's bytes when they may have changed since `seen` (`None`: unchanged), and what
    /// to remember of this look.
    pub async fn look(
        &self,
        seen: &SeenNow,
        client: Option<&crate::fetch::Client>,
        local: Option<&LocalFetch>,
        host: Option<&str>,
    ) -> Result<(Option<Bytes>, Seen)> {
        let mut next = Seen {
            digest: seen.digest,
            ..Seen::default()
        };
        match &self.origin {
            Origin::Inline => Ok((None, next)),
            Origin::File(path) => {
                let path = path.clone();
                let previous = seen.file;
                let read = tokio::task::spawn_blocking(move || -> Result<_> {
                    let metadata = std::fs::metadata(&path).with_context(|| format!("{}", path.display()))?;
                    let stamp = file_stamp(&metadata);
                    if previous == Some(stamp) {
                        return Ok((None, stamp));
                    }
                    let bytes = std::fs::read(&path).with_context(|| format!("{}", path.display()))?;
                    if bytes.len() > MAX_SPEC {
                        bail!("{}: over {MAX_SPEC} bytes", path.display());
                    }
                    Ok((Some(Bytes::from(bytes)), stamp))
                })
                .await
                .map_err(|e| anyhow!("{e}"))??;
                next.file = Some(read.1);
                Ok((read.0, next))
            }
            Origin::Url(uri) => {
                let client = client.ok_or_else(|| anyhow!("no HTTP client"))?;
                let fetched = crate::fetch::get(client, uri, &self.conditional(seen), MAX_SPEC, self.timeout).await?;
                self.answered(fetched.status, &fetched.headers, fetched.body, seen, next)
            }
            Origin::Local(path) => {
                let local = local.ok_or_else(|| anyhow!("the server does not run yet"))?;
                let mut request = http::Request::get(path.as_str()).body(crate::body::empty())?;
                *request.headers_mut() = self.conditional(seen);
                if let Some(host) = host
                    && let Ok(value) = HeaderValue::from_str(host)
                {
                    request.headers_mut().insert(http::header::HOST, value);
                }
                let work = async {
                    let response = local(request).await;
                    let (parts, body) = response.into_parts();
                    let body = super::read_body(body, MAX_SPEC)
                        .await
                        .map_err(|v| anyhow!("{}: {}", v.reason, v.detail))?;
                    Ok::<_, anyhow::Error>((parts, body))
                };
                let (parts, body) = tokio::time::timeout(self.timeout, work)
                    .await
                    .map_err(|_| anyhow!("{path}: no answer within {} ms", self.timeout.as_millis()))??;
                self.answered(parts.status, &parts.headers, body, seen, next)
            }
        }
    }

    fn conditional(&self, seen: &SeenNow) -> HeaderMap {
        let mut headers = self.headers.clone();
        if let Some(etag) = &seen.etag {
            headers.insert(IF_NONE_MATCH, etag.clone());
        }
        if let Some(date) = &seen.last_modified {
            headers.insert(IF_MODIFIED_SINCE, date.clone());
        }
        headers
    }

    fn answered(
        &self,
        status: StatusCode,
        headers: &HeaderMap,
        body: Bytes,
        seen: &SeenNow,
        mut next: Seen,
    ) -> Result<(Option<Bytes>, Seen)> {
        next.etag = headers.get(http::header::ETAG).cloned();
        next.last_modified = headers.get(http::header::LAST_MODIFIED).cloned();
        match status {
            StatusCode::NOT_MODIFIED => {
                // A 304 need not repeat the validators: the ones the source gave stay.
                next.etag = next.etag.or_else(|| seen.etag.clone());
                next.last_modified = next.last_modified.or_else(|| seen.last_modified.clone());
                Ok((None, next))
            }
            StatusCode::OK => Ok((Some(body), next)),
            other => bail!("{} answered {other}", self.describe()),
        }
    }
}

/// What `look` needs of the last look (copied out, so no lock is held while it waits).
pub(super) struct SeenNow {
    pub etag: Option<HeaderValue>,
    pub last_modified: Option<HeaderValue>,
    pub file: Option<(u64, Option<std::time::SystemTime>, u64)>,
    pub digest: Option<[u8; 32]>,
}

impl Seen {
    pub fn now(&self) -> SeenNow {
        SeenNow {
            etag: self.etag.clone(),
            last_modified: self.last_modified.clone(),
            file: self.file,
            digest: self.digest,
        }
    }
}

fn file_stamp(metadata: &std::fs::Metadata) -> (u64, Option<std::time::SystemTime>, u64) {
    #[cfg(unix)]
    let inode = {
        use std::os::unix::fs::MetadataExt;
        metadata.ino()
    };
    #[cfg(not(unix))]
    let inode = 0;
    (metadata.len(), metadata.modified().ok(), inode)
}

/// `${NAME}` replaced with the environment variable; one that is not set is an error.
fn expand(text: &str) -> Result<String> {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find("${") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let end = after.find('}').ok_or_else(|| anyhow!("unclosed ${{ in {text:?}"))?;
        let name = &after[..end];
        let value = std::env::var(name).map_err(|_| anyhow!("environment variable {name} is not set"))?;
        out.push_str(&value);
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(yaml: &str) -> Result<Source> {
        let config: SpecConfig = serde_yaml_ng::from_str(yaml)?;
        Source::from_config(&config, Path::new("/etc/web"))
    }

    #[test]
    fn spec_sources_are_read_from_their_configuration() {
        let file = config("openapi.yaml").unwrap();
        assert!(matches!(&file.origin, Origin::File(p) if p == Path::new("/etc/web/openapi.yaml")));
        assert_eq!(file.refresh, None, "a file named as a string is read once");
        let local = config("{uri: /openapi.json}").unwrap();
        assert!(matches!(&local.origin, Origin::Local(p) if p == "/openapi.json"));
        assert_eq!(local.refresh, Some(Duration::from_secs(60)));
        let url = config("{uri: 'https://app.test/spec.yaml', refresh: 30s, ttl: 24h, timeout: 2s}").unwrap();
        assert!(matches!(url.origin, Origin::Url(_)));
        assert_eq!(
            (url.refresh, url.ttl, url.timeout),
            (
                Some(Duration::from_secs(30)),
                Some(Duration::from_secs(86400)),
                Duration::from_secs(2)
            )
        );
        let watched = config("{file: openapi.yaml, refresh: 10s}").unwrap();
        assert_eq!(watched.refresh, Some(Duration::from_secs(10)));
        // SAFETY: tests in this module do not read the environment concurrently with this write.
        unsafe { std::env::set_var("WEB_SERVER_TEST_SPEC_TOKEN", "s3cret") };
        let with_header =
            config("{uri: /s, headers: {Authorization: 'Bearer ${WEB_SERVER_TEST_SPEC_TOKEN}'}}").unwrap();
        assert_eq!(with_header.headers["authorization"], "Bearer s3cret");
        for (yaml, message) in [
            ("{file: a, uri: /b}", "either"),
            ("{}", "either"),
            ("{uri: 'ftp://x/s'}", "http(s)"),
            ("{uri: 'openapi.json'}", "http(s)"),
            ("{uri: /s, refresh: 0}", "more than 0"),
            ("{uri: /s, headers: {X: '${WEB_SERVER_TEST_NOT_SET}'}}", "not set"),
            ("{file: a, headers: {X: y}}", "only for a uri"),
        ] {
            let err = config(yaml).err().map(|e| e.to_string()).unwrap_or_default();
            assert!(err.contains(message), "{yaml}: {err}");
        }
        let err = config("{uri: /s, colour: red}")
            .err()
            .map(|e| e.to_string())
            .unwrap_or_default();
        assert!(err.contains("unknown field `colour`"), "{err}");
        let numbers = config("{uri: /s, refresh: 30, ttl: 86400, timeout: 1500ms}").unwrap();
        assert_eq!(
            (numbers.refresh, numbers.ttl, numbers.timeout),
            (
                Some(Duration::from_secs(30)),
                Some(Duration::from_secs(86400)),
                Duration::from_millis(1500)
            )
        );
    }
}
