//! What agents meet at the edge, through a running server: a protected resource of OAuth 2.0
//! guarded by the JWT check (RFC 9728 — what an MCP server is to its clients), and the signed
//! requests of bots told from the rest (Web Bot Auth, src/botauth.rs).
#![cfg(all(feature = "jwt", feature = "bot-auth"))]

use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use webfast_core::checkfile::Reloadable;
use webfast_core::server;

fn base64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, &b)| n | (u32::from(b) << (16 - 8 * i)));
        for i in 0..=chunk.len() {
            out.push(char::from(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize]));
        }
    }
    out
}

/// The standard alphabet with padding.
fn base64(bytes: &[u8]) -> String {
    let mut text = base64url(bytes).replace('-', "+").replace('_', "/");
    while !text.len().is_multiple_of(4) {
        text.push('=');
    }
    text
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// An Ed25519 key: its JWKS, and its JWK thumbprint (RFC 7638, RFC 8037 A.3).
struct Key {
    pair: Ed25519KeyPair,
    jwks: String,
    thumbprint: String,
}

impl Key {
    fn new() -> Key {
        let pair = Ed25519KeyPair::generate().unwrap();
        let x = base64url(pair.public_key().as_ref());
        let canonical = format!("{{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"{x}\"}}");
        let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, canonical.as_bytes());
        Key {
            jwks: format!("{{\"keys\":[{{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"kid\":\"k\",\"x\":\"{x}\"}}]}}"),
            thumbprint: base64url(digest.as_ref()),
            pair,
        }
    }

    /// A JWT of `claims`.
    fn token(&self, claims: serde_json::Value) -> String {
        let input = format!(
            "{}.{}",
            base64url(br#"{"alg":"EdDSA","kid":"k"}"#),
            base64url(claims.to_string().as_bytes())
        );
        format!("{input}.{}", base64url(self.pair.sign(input.as_bytes()).as_ref()))
    }
}

async fn start(text: &str, prepare: impl FnOnce(&mut webfast_core::config::Config)) -> (server::Running, u16) {
    let file = webfast_core::caddyfile::parse_str(text, Path::new("Caddyfile")).unwrap();
    let mut config = webfast_core::load_parsed(&file, 1 << 24).unwrap();
    prepare(&mut config);
    let running = server::start(config).await.unwrap();
    let port = running.bound[0].1.port();
    (running, port)
}

/// One request on a connection of its own: the status, the head, the body.
async fn send(port: u16, method: &str, host: &str, path: &str, headers: &[(&str, String)]) -> (u16, String, String) {
    let mut request = format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n");
    for (name, value) in headers {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    request.push_str("\r\n");
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut answer = Vec::new();
    stream.read_to_end(&mut answer).await.unwrap();
    let text = String::from_utf8_lossy(&answer).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    (
        text[9..12].parse().unwrap(),
        head.to_ascii_lowercase(),
        body.to_string(),
    )
}

#[tokio::test]
async fn a_protected_resource_is_guarded_as_the_model_context_protocol_asks() {
    let key = Key::new();
    let yaml = format!(
        "providers:\n  id:\n    issuer: https://id.test\n    jwks: '{}'\n    output_claim_to_headers: [{{header: X-User, claim: sub}}]\nresources:\n  tools:\n    resource: https://mcp.test/mcp\n    scopes_supported: [\"mcp:tools\"]\nrules:\n  - match: {{hosts: [mcp.test], paths: [\"/mcp\", \"/mcp/*\"]}}\n    providers: [id]\n    resource: tools\n    scopes: [\"mcp:tools\"]\n",
        key.jwks
    );
    let jwt = webfast_core::jwt::JwtAuth::from_yaml(&yaml, Path::new(".")).unwrap();
    let site = ":0 {\n\trespond /mcp* \"tools for {http.request.header.X-User}\"\n\trespond \"a page\"\n}\n";
    let (running, port) = start(site, |config| config.jwt = Some(Arc::new(Reloadable::new(jwt)))).await;

    // No token: 401, and where the resource's metadata is.
    let metadata = "https://mcp.test/.well-known/oauth-protected-resource/mcp";
    let (status, head, _) = send(port, "POST", "mcp.test", "/mcp", &[]).await;
    assert_eq!(status, 401);
    assert!(
        head.contains(&format!(
            "www-authenticate: bearer scope=\"mcp:tools\", resource_metadata=\"{metadata}\""
        )),
        "{head}"
    );
    // The metadata, at that address, to anyone; nothing of it on another host.
    let (status, head, body) = send(
        port,
        "GET",
        "mcp.test",
        "/.well-known/oauth-protected-resource/mcp",
        &[],
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert!(head.contains("content-type: application/json"), "{head}");
    let document: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(document["resource"], "https://mcp.test/mcp");
    assert_eq!(document["authorization_servers"][0], "https://id.test");
    let (_, _, other) = send(
        port,
        "GET",
        "www.test",
        "/.well-known/oauth-protected-resource/mcp",
        &[],
    )
    .await;
    assert_eq!(other, "a page");

    // A token for this resource, with the scope: through, its claims with it.
    let claims = |aud: &str, scope: &str| serde_json::json!({"iss": "https://id.test", "sub": "u1", "exp": now() + 300, "aud": aud, "scope": scope});
    let bearer = |token: String| [("Authorization", format!("Bearer {token}"))];
    let good = bearer(key.token(claims("https://mcp.test/mcp", "mcp:tools")));
    let (status, _, body) = send(port, "POST", "mcp.test", "/mcp", &good).await;
    assert_eq!((status, body.as_str()), (200, "tools for u1"));
    // One issued for another resource: 401. One without the scope: 403.
    let elsewhere = bearer(key.token(claims("https://api.test", "mcp:tools")));
    let (status, head, _) = send(port, "POST", "mcp.test", "/mcp", &elsewhere).await;
    assert_eq!(status, 401);
    assert!(
        head.contains("error=\"invalid_token\"") && head.contains(metadata),
        "{head}"
    );
    let narrow = bearer(key.token(claims("https://mcp.test/mcp", "profile")));
    let (status, head, _) = send(port, "POST", "mcp.test", "/mcp", &narrow).await;
    assert_eq!(status, 403);
    assert!(
        head.contains("error=\"insufficient_scope\"") && head.contains("scope=\"mcp:tools\""),
        "{head}"
    );
    running.shutdown(Duration::from_secs(1)).await;
}

#[tokio::test]
async fn a_signed_bot_is_told_from_the_rest_before_the_routes() {
    let key = Key::new();
    let yaml = format!("agents:\n  crawler:\n    jwks: '{}'\n", key.jwks);
    let bots = webfast_core::botauth::BotAuth::from_yaml(&yaml, Path::new(".")).unwrap();
    // The test's own address is a proxy that ended TLS: what it says of the scheme is taken.
    let site = "{\n\tservers {\n\t\ttrusted_proxies static 127.0.0.1/32\n\t}\n}\n:0 {\n\t@bot header X-Verified-Bot *\n\trespond @bot \"bot {http.request.header.X-Verified-Bot}\"\n\trespond \"someone\"\n}\n";
    let (running, port) = start(site, |config| config.bot_auth = Some(Arc::new(Reloadable::new(bots)))).await;

    let signed = |host: &str, created: u64| {
        let parameters = format!(
            "(\"@authority\" \"signature-agent\";key=\"sig1\");created={created};expires={};keyid=\"{}\";alg=\"ed25519\";tag=\"web-bot-auth\"",
            created + 300,
            key.thumbprint
        );
        let agent = "sig1=\"https://crawler.example\"";
        let base = format!(
            "\"@authority\": {host}\n\"signature-agent\";key=\"sig1\": \"https://crawler.example\"\n\"@signature-params\": {parameters}"
        );
        [
            ("X-Forwarded-Proto", "https".to_string()),
            ("Signature-Agent", agent.to_string()),
            ("Signature-Input", format!("sig1={parameters}")),
            (
                "Signature",
                format!("sig1=:{}:", base64(key.pair.sign(base.as_bytes()).as_ref())),
            ),
        ]
    };
    // A request the named agent's key signed, for this host.
    let (status, _, body) = send(port, "GET", "example.test", "/", &signed("example.test", now())).await;
    assert_eq!((status, body.as_str()), (200, "bot crawler"));
    // Unsigned; saying so itself; signed for another host; signed long ago: an ordinary request.
    let (_, _, body) = send(port, "GET", "example.test", "/", &[]).await;
    assert_eq!(body, "someone");
    let claimed = [("X-Verified-Bot", "crawler".to_string())];
    let (_, _, body) = send(port, "GET", "example.test", "/", &claimed).await;
    assert_eq!(body, "someone");
    let (_, _, body) = send(port, "GET", "example.test", "/", &signed("other.test", now())).await;
    assert_eq!(body, "someone");
    let (_, _, body) = send(port, "GET", "example.test", "/", &signed("example.test", now() - 3600)).await;
    assert_eq!(body, "someone");
    running.shutdown(Duration::from_secs(1)).await;
}
