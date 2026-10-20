//! The answers to the challenges (RFC 8555 §8.3, RFC 8737), put up by the ACME thread while an
//! order runs and taken down after. HTTP-01: `Http01`, a request check before the routes, answers
//! `/.well-known/acme-challenge/<token>` from the tokens put up; every other request costs it a
//! look at the path's first bytes. TLS-ALPN-01: the resolver (src/tls.rs) gives a handshake that
//! offers `acme-tls/1` for a host with an answer up that host's challenge certificate, a
//! self-signed one with the `acmeIdentifier` extension.

use crate::body::Body;
use crate::extensions::{Checked, Client, RequestCheck};
use arc_swap::ArcSwap;
use http::{HeaderValue, Response, StatusCode};
use rustls::sign::CertifiedKey;
use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex};

pub const HTTP01_PATH: &str = "/.well-known/acme-challenge/";
pub const ALPN: &[u8] = b"acme-tls/1";

/// Token → key authorization, for `Http01`; a snapshot, replaced whole under `HTTP01_WRITER`.
static HTTP01: LazyLock<ArcSwap<HashMap<String, String>>> = LazyLock::new(|| ArcSwap::from_pointee(HashMap::new()));
static HTTP01_WRITER: Mutex<()> = Mutex::new(());

/// Host → challenge certificate, for the resolver.
static ALPN_KEYS: LazyLock<ArcSwap<HashMap<String, Arc<CertifiedKey>>>> =
    LazyLock::new(|| ArcSwap::from_pointee(HashMap::new()));
static ALPN_WRITER: Mutex<()> = Mutex::new(());

pub(crate) fn http01_set(token: &str, key_authorization: &str) {
    let _writing = HTTP01_WRITER.lock().unwrap_or_else(|e| e.into_inner());
    let mut map = HashMap::clone(&HTTP01.load());
    map.insert(token.to_string(), key_authorization.to_string());
    HTTP01.store(Arc::new(map));
}

pub(crate) fn http01_clear(token: &str) {
    let _writing = HTTP01_WRITER.lock().unwrap_or_else(|e| e.into_inner());
    let mut map = HashMap::clone(&HTTP01.load());
    map.remove(token);
    HTTP01.store(Arc::new(map));
}

pub(crate) fn alpn_set(host: &str, key: Arc<CertifiedKey>) {
    let _writing = ALPN_WRITER.lock().unwrap_or_else(|e| e.into_inner());
    let mut map = HashMap::clone(&ALPN_KEYS.load());
    map.insert(host.to_ascii_lowercase(), key);
    ALPN_KEYS.store(Arc::new(map));
}

pub(crate) fn alpn_clear(host: &str) {
    let _writing = ALPN_WRITER.lock().unwrap_or_else(|e| e.into_inner());
    let mut map = HashMap::clone(&ALPN_KEYS.load());
    map.remove(&host.to_ascii_lowercase());
    ALPN_KEYS.store(Arc::new(map));
}

/// The challenge certificate for a handshake that offers `acme-tls/1` and names `host`, while
/// its challenge is up.
pub fn alpn_certificate(host: &str) -> Option<Arc<CertifiedKey>> {
    let map = ALPN_KEYS.load();
    if map.is_empty() {
        return None;
    }
    map.get(&host.to_ascii_lowercase()).cloned()
}

/// Whether `alpn` (the protocols a handshake offers) asks for the challenge.
pub fn offers_challenge<'a>(mut alpn: impl Iterator<Item = &'a [u8]>) -> bool {
    alpn.any(|p| p == ALPN)
}

/// The challenge certificate (RFC 8737 §3): self-signed for `host` alone, with the critical
/// `acmeIdentifier` extension holding the SHA-256 of the key authorization.
pub(crate) fn alpn_key(host: &str, digest: &[u8]) -> Result<Arc<CertifiedKey>, String> {
    let key_pair = rcgen::KeyPair::generate().map_err(|e| e.to_string())?;
    let mut params = rcgen::CertificateParams::new(vec![host.to_string()]).map_err(|e| e.to_string())?;
    params
        .custom_extensions
        .push(rcgen::CustomExtension::new_acme_identifier(digest));
    let cert = params.self_signed(&key_pair).map_err(|e| e.to_string())?;
    let key =
        rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(key_pair.serialize_der()));
    let signing = crate::tls::provider()
        .key_provider
        .load_private_key(key)
        .map_err(|e| e.to_string())?;
    Ok(Arc::new(CertifiedKey::new(vec![cert.der().clone()], signing)))
}

/// Answers HTTP-01 challenges before the routes (src/extensions.rs `RequestChecks`).
#[derive(Debug, Clone, Copy)]
pub struct Http01;

impl RequestCheck for Http01 {
    async fn check(&self, req: &mut http::request::Parts, body: Body, _: Client<'_>) -> Checked {
        let Some(token) = req.uri.path().strip_prefix(HTTP01_PATH) else {
            return Ok(body);
        };
        let map = HTTP01.load();
        let Some(key_authorization) = map.get(token) else {
            return Ok(body);
        };
        let mut response = Response::new(crate::body::full(key_authorization.clone()));
        *response.status_mut() = StatusCode::OK;
        response
            .headers_mut()
            .insert(http::header::CONTENT_TYPE, HeaderValue::from_static("text/plain"));
        response
            .headers_mut()
            .insert(http::header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        Err(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handler::ConnInfo;
    use http_body_util::BodyExt;
    use std::net::SocketAddr;

    async fn answer(path: &str) -> Option<(u16, String)> {
        let remote: SocketAddr = "10.0.0.2:4000".parse().unwrap();
        let (mut parts, _) = http::Request::builder().uri(path).body(()).unwrap().into_parts();
        let conn = Arc::new(ConnInfo {
            remote,
            tls: false,
            trusted: false,
            sni: None,
        });
        let client = Client {
            ip: remote.ip(),
            conn: &conn,
            at: crate::extensions::At::Routes,
        };
        match RequestCheck::check(&Http01, &mut parts, crate::body::empty(), client).await {
            Ok(_) => None,
            Err(response) => {
                let status = response.status().as_u16();
                let body = response.into_body().collect().await.unwrap().to_bytes();
                Some((status, String::from_utf8(body.to_vec()).unwrap()))
            }
        }
    }

    #[tokio::test]
    async fn http01_answers_the_tokens_put_up_and_nothing_else() {
        assert!(answer("/.well-known/acme-challenge/abc").await.is_none(), "nothing up");
        assert!(answer("/index.html").await.is_none());
        http01_set("abc", "abc.thumbprint");
        assert_eq!(
            answer("/.well-known/acme-challenge/abc").await,
            Some((200, "abc.thumbprint".into()))
        );
        assert!(
            answer("/.well-known/acme-challenge/abd").await.is_none(),
            "another token"
        );
        http01_clear("abc");
        assert!(answer("/.well-known/acme-challenge/abc").await.is_none(), "taken down");
    }

    #[test]
    fn the_alpn_certificate_names_the_host_and_carries_the_digest() {
        let digest = [7u8; 32];
        let key = alpn_key("Example.Test", &digest).unwrap();
        let der = key.cert[0].as_ref();
        assert!(der.windows(12).any(|w| w == b"Example.Test"), "the SAN");
        // id-pe-acmeIdentifier 1.3.6.1.5.5.7.1.31, then the OCTET STRING of the digest.
        assert!(
            der.windows(8)
                .any(|w| w == [0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x1F])
        );
        assert!(der.windows(34).any(|w| w[0] == 0x04 && w[1] == 32 && w[2..] == digest));
        assert!(alpn_certificate("example.test").is_none());
        alpn_set("example.test", key.clone());
        assert!(Arc::ptr_eq(&alpn_certificate("EXAMPLE.test").unwrap(), &key));
        assert!(offers_challenge([b"h2".as_slice(), ALPN].into_iter()));
        assert!(!offers_challenge([b"h2".as_slice()].into_iter()));
        alpn_clear("example.test");
        assert!(alpn_certificate("example.test").is_none());
    }
}
