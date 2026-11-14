use super::jwks::tests::{Signer, jwks};
use super::*;
use http_body_util::BodyExt;
use serde_json::json;

fn ip() -> std::net::IpAddr {
    "203.0.113.7".parse().unwrap()
}

fn now() -> u64 {
    unix_now()
}

fn request(uri: &str, headers: &[(&str, &str)]) -> http::request::Parts {
    let mut builder = http::Request::get(uri).header("host", "api.test");
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    builder.body(()).unwrap().into_parts().0
}

fn bearer(token: &str) -> String {
    format!("Bearer {token}")
}

/// A provider `main` (issuer https://id.test, audience api) with `signer`'s key as `k1`, and
/// rules: /api/public/* not checked, /api/open/* token optional, /api/* token required.
fn auth(signer: &Signer, extra: &str) -> JwtAuth {
    let yaml = format!(
        "providers:\n  main:\n    issuer: https://id.test\n    audiences: [api]\n    jwks: '{}'\n    output_claim_to_headers:\n      - {{header: X-User, claim: sub}}\n      - {{header: X-Roles, claim: realm.roles}}\n{extra}rules:\n  - match: {{paths: [\"/api/public/*\"]}}\n  - match: {{paths: [\"/api/open/*\"]}}\n    providers: [main]\n    allow_missing: true\n  - match: {{paths: [\"/api/*\"]}}\n    providers: [main]\n",
        jwks(&[(signer, "k1")])
    );
    JwtAuth::from_yaml(&yaml, Path::new(".")).unwrap()
}

fn claims(extra: Value) -> Value {
    let mut base = json!({"iss": "https://id.test", "aud": "api", "sub": "u1", "exp": now() + 300,
        "realm": {"roles": ["admin", "ops"]}});
    if let (Value::Object(base), Value::Object(extra)) = (&mut base, extra) {
        for (k, v) in extra {
            if v.is_null() {
                base.remove(&k);
            } else {
                base.insert(k, v);
            }
        }
    }
    base
}

async fn refused(auth: &JwtAuth, parts: &mut http::request::Parts) -> (u16, String) {
    let response = auth.check(parts, ip()).await.expect_err("refused");
    let status = response.status().as_u16();
    assert!(response.headers().contains_key("www-authenticate"));
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&body).into_owned())
}

#[tokio::test]
async fn valid_tokens_pass_and_their_claims_go_upstream() {
    for signer in [Signer::ec(), Signer::rsa(), Signer::ed()] {
        let auth = auth(&signer, "");
        let token = signer.token("k1", &claims(json!({})));
        let mut parts = request("/api/orders", &[("authorization", &bearer(&token))]);
        auth.check(&mut parts, ip())
            .await
            .unwrap_or_else(|_| panic!("{}", signer.alg()));
        assert_eq!(parts.headers["x-user"], "u1");
        assert_eq!(parts.headers["x-roles"], "admin,ops", "nested claim, array joined");
        assert!(
            parts.headers.get("authorization").is_none(),
            "the token is not forwarded"
        );
        // Again: from the cache, the same result.
        let mut again = request("/api/orders", &[("authorization", &bearer(&token))]);
        auth.check(&mut again, ip()).await.unwrap();
        assert_eq!(again.headers["x-user"], "u1");
    }
}

#[tokio::test]
async fn tokens_that_do_not_hold_are_refused() {
    let signer = Signer::ec();
    let auth = auth(&signer, "");
    let other = Signer::ec();
    let cases = [
        (
            signer.token("k1", &claims(json!({"exp": now() - 120}))),
            401,
            "Jwt is expired",
        ),
        (
            signer.token("k1", &claims(json!({"nbf": now() + 120}))),
            401,
            "Jwt not yet valid",
        ),
        (
            signer.token("k1", &claims(json!({"aud": "other"}))),
            403,
            "Audiences in Jwt are not allowed",
        ),
        (
            signer.token("k1", &claims(json!({"aud": ["x", "y"]}))),
            403,
            "Audiences in Jwt are not allowed",
        ),
        (
            signer.token("k1", &claims(json!({"iss": "https://evil.test"}))),
            401,
            "Jwt issuer is not configured",
        ),
        (
            signer.token("k1", &claims(json!({"exp": null}))),
            401,
            "Jwt verification fails",
        ),
        (
            signer.token("k1", &claims(json!({"exp": "tomorrow"}))),
            401,
            "Jwt verification fails",
        ),
        (other.token("k1", &claims(json!({}))), 401, "Jwt verification fails"),
        (signer.token("k9", &claims(json!({}))), 401, "Jwt verification fails"),
        ("not.a.token".to_string(), 401, "Jwt verification fails"),
    ];
    for (token, status, message) in cases {
        let mut parts = request("/api/orders", &[("authorization", &bearer(&token))]);
        assert_eq!(
            refused(&auth, &mut parts).await,
            (status, message.to_string()),
            "{token}"
        );
    }
    // alg none, with claims that would otherwise hold.
    let payload = token::encode(claims(json!({})).to_string().as_bytes());
    let none = format!("{}.{payload}.", token::encode(br#"{"alg":"none"}"#));
    let mut parts = request("/api/orders", &[("authorization", &bearer(&none))]);
    assert_eq!(refused(&auth, &mut parts).await.0, 401);
    // A valid token with its signature changed.
    let good = signer.token("k1", &claims(json!({})));
    let at = good.rfind('.').unwrap() + 10;
    let swapped = if &good[at..=at] == "A" { "B" } else { "A" };
    let tampered = format!("{}{swapped}{}", &good[..at], &good[at + 1..]);
    let mut parts = request("/api/orders", &[("authorization", &bearer(&tampered))]);
    assert_eq!(refused(&auth, &mut parts).await.0, 401);
    // Within the clock skew (60 s) an expired token still passes.
    let late = signer.token("k1", &claims(json!({"exp": now() - 30})));
    let mut parts = request("/api/orders", &[("authorization", &bearer(&late))]);
    assert!(auth.check(&mut parts, ip()).await.is_ok());
}

#[tokio::test]
async fn rules_decide_which_requests_need_a_token() {
    let signer = Signer::ec();
    let auth = auth(&signer, "");
    let mut missing = request("/api/orders", &[]);
    assert_eq!(refused(&auth, &mut missing).await, (401, "Jwt is missing".to_string()));
    let mut wrong_scheme = request("/api/orders", &[("authorization", "Basic dXNlcjpwYXNz")]);
    assert_eq!(refused(&auth, &mut wrong_scheme).await.1, "Jwt is missing");
    // Paths are matched as the server's matchers do: decoded, cleaned, case-insensitive.
    for path in ["/API/orders", "/api//orders", "/x/../api/orders", "/%61pi/orders"] {
        let mut parts = request(path, &[]);
        assert_eq!(refused(&auth, &mut parts).await.0, 401, "{path}");
    }
    let mut public = request("/api/public/x", &[]);
    assert!(auth.check(&mut public, ip()).await.is_ok(), "a rule without providers");
    let mut elsewhere = request("/index.html", &[]);
    assert!(auth.check(&mut elsewhere, ip()).await.is_ok(), "no rule");
    let mut optional = request("/api/open/x", &[]);
    assert!(auth.check(&mut optional, ip()).await.is_ok(), "allow_missing");
    let bad = Signer::ec().token("k1", &claims(json!({})));
    let mut optional_bad = request("/api/open/x", &[("authorization", &bearer(&bad))]);
    assert_eq!(
        refused(&auth, &mut optional_bad).await.0,
        401,
        "allow_missing still checks a token"
    );
}

#[tokio::test]
async fn claim_headers_cannot_come_from_the_client() {
    let signer = Signer::ec();
    let auth = auth(&signer, "");
    // Look-alikes as well: PHP, CGI and WSGI read `X_User` and `X.Roles` as `X-User`, `X-Roles`.
    let forged = [
        ("x-user", "admin"),
        ("X-Roles", "root"),
        ("X_User", "admin"),
        ("x.roles", "root"),
    ];
    for path in ["/index.html", "/api/public/x", "/api/open/x"] {
        let mut parts = request(path, &forged);
        auth.check(&mut parts, ip()).await.unwrap();
        let left: Vec<&str> = parts.headers.keys().map(|k| k.as_str()).collect();
        assert_eq!(left, ["host"], "{path}");
    }
    let token = signer.token("k1", &claims(json!({"sub": "u2"})));
    let mut parts = request(
        "/api/orders",
        &[
            ("authorization", &bearer(&token)),
            ("x-user", "admin"),
            ("x_user", "admin"),
        ],
    );
    auth.check(&mut parts, ip()).await.unwrap();
    assert_eq!(parts.headers.get_all("x-user").iter().collect::<Vec<_>>(), ["u2"]);
    assert!(parts.headers.get("x_user").is_none());
}

#[tokio::test]
async fn tokens_in_cookies_and_parameters_and_kept_or_passed_on() {
    let signer = Signer::ed();
    let extra = "    from_cookies: [session]\n    from_params: [access_token]\n    from_headers: [{name: X-Token}]\n    forward_original_token: true\n    output_payload_to_header: X-Jwt-Payload\n    require_expiration: false\n";
    let auth = auth(&signer, extra);
    let token = signer.token("k1", &claims(json!({"exp": null})));
    let mut cookie = request("/api/x", &[("cookie", &format!("a=b; session={token}"))]);
    auth.check(&mut cookie, ip()).await.unwrap();
    let payload = token.split('.').nth(1).unwrap();
    assert_eq!(cookie.headers["x-jwt-payload"], payload);
    let mut param = request(&format!("/api/x?a=1&access_token={token}"), &[]);
    auth.check(&mut param, ip()).await.unwrap();
    let mut header = request("/api/x", &[("x-token", &token)]);
    auth.check(&mut header, ip()).await.unwrap();
    assert_eq!(header.headers["x-token"], token.as_str(), "forward_original_token");
    let mut authorization = request("/api/x", &[("authorization", &bearer(&token))]);
    assert_eq!(
        refused(&auth, &mut authorization).await.1,
        "Jwt is missing",
        "Authorization is not looked at once sources are given"
    );
}

#[test]
fn configurations_that_cannot_work_are_refused() {
    let signer = Signer::ec();
    let keys = jwks(&[(&signer, "k1")]);
    for (yaml, message) in [
        (
            "providers:\n  a:\n    issuer: x\nrules: []\n".to_string(),
            "one of jwks_uri",
        ),
        (
            format!("providers:\n  a:\n    issuer: x\n    jwks: '{keys}'\nrules:\n  - providers: [b]\n"),
            "no provider",
        ),
        (
            format!("providers:\n  a:\n    issuer: x\n    jwks: '{keys}'\n    colour: red\n"),
            "unknown field",
        ),
        (
            "providers:\n  a:\n    issuer: x\n    jwks_uri: ftp://x/k\n".to_string(),
            "http(s)",
        ),
        (
            "providers:\n  a:\n    issuer: x\n    jwks: '{\"keys\":[]}'\n".to_string(),
            "no usable",
        ),
        (
            format!(
                "providers:\n  a:\n    issuer: x\n    jwks: '{keys}'\n    output_claim_to_headers: [{{header: Authorization, claim: sub}}]\n"
            ),
            "carries the token",
        ),
        (
            format!("providers:\n  a:\n    issuer: x\n    jwks: '{keys}'\n    clock_skew: soon\n"),
            "clock_skew",
        ),
    ] {
        let err = JwtAuth::from_yaml(&yaml, Path::new("."))
            .err()
            .map(|e| format!("{e:#}"))
            .unwrap_or_default();
        assert!(err.contains(message), "{yaml}\n→ {err}");
    }
}

#[tokio::test]
async fn rotated_keys_are_picked_up_from_the_file() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("jwks.json");
    let (old, new) = (Signer::ec(), Signer::rsa());
    std::fs::write(&file, jwks(&[(&old, "old")])).unwrap();
    let yaml =
        "providers:\n  main:\n    issuer: https://id.test\n    jwks_file: jwks.json\nrules:\n  - providers: [main]\n";
    let auth = JwtAuth::from_yaml(yaml, dir.path()).unwrap();
    auth.start().unwrap();
    let check = |signer: &Signer, kid: &str| {
        let token = signer.token(kid, &claims(json!({"aud": null})));
        request("/x", &[("authorization", &bearer(&token))])
    };
    auth.check(&mut check(&old, "old"), ip()).await.unwrap();
    // The issuer rotates: the file gets the new key; a token with it makes the server read again.
    std::fs::write(&file, jwks(&[(&old, "old"), (&new, "new")])).unwrap();
    auth.check(&mut check(&new, "new"), ip()).await.unwrap();
    // Unknown key ids do not make it read again at once.
    let mut unknown = check(&Signer::ec(), "nobody");
    let started = std::time::Instant::now();
    assert_eq!(refused(&auth, &mut unknown).await.0, 401);
    assert!(
        started.elapsed() < Duration::from_millis(500),
        "no waiting: a read was asked for just now"
    );
}

#[tokio::test]
async fn keys_are_read_from_a_jwks_uri() {
    let signer = Signer::ec();
    let document = jwks(&[(&signer, "k1")]);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let document = document.clone();
            tokio::spawn(async move {
                let service = hyper::service::service_fn(move |_req: http::Request<hyper::body::Incoming>| {
                    let document = document.clone();
                    async move {
                        Ok::<_, std::convert::Infallible>(http::Response::new(http_body_util::Full::new(
                            bytes::Bytes::from(document),
                        )))
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    let yaml = format!(
        "providers:\n  main:\n    issuer: https://id.test\n    jwks_uri: http://{address}/certs\nrules:\n  - providers: [main]\n"
    );
    let auth = JwtAuth::from_yaml(&yaml, Path::new(".")).unwrap();
    auth.start().unwrap();
    let token = signer.token("k1", &claims(json!({"aud": null})));
    // The first read may still be under way: the unknown key makes the request wait for it.
    auth.check(&mut request("/x", &[("authorization", &bearer(&token))]), ip())
        .await
        .unwrap();
}

/// Costs per check, release build: `cargo test --release jwt::tests::timings -- --ignored --nocapture`.
#[tokio::test]
#[ignore = "a measurement, not a test"]
async fn timings() {
    for signer in [Signer::ec(), Signer::rsa(), Signer::ed()] {
        let auth = auth(&signer, "");
        let token = signer.token("k1", &claims(json!({})));
        let header = bearer(&token);
        let rounds = 20_000;
        // Every request a new token's work: decode, JSON, signature (the cache is bypassed by
        // checking with a fresh JwtAuth's verify directly).
        let rule = &auth.rules[2];
        let started = std::time::Instant::now();
        for _ in 0..rounds / 10 {
            auth.verify(&token, rule, now()).await.unwrap();
        }
        let verify = started.elapsed() / (rounds / 10);
        let started = std::time::Instant::now();
        for _ in 0..rounds {
            let mut parts = request("/api/orders", &[("authorization", &header)]);
            auth.check(&mut parts, ip()).await.unwrap();
        }
        let cached = started.elapsed() / rounds;
        let started = std::time::Instant::now();
        for _ in 0..rounds {
            let _ = request("/api/orders", &[("authorization", &header)]);
        }
        let baseline = started.elapsed() / rounds;
        println!(
            "{}: new token {:?}, seen token {:?} (building the request alone: {:?})",
            signer.alg(),
            verify,
            cached.saturating_sub(baseline),
            baseline
        );
    }
}

#[tokio::test]
async fn log_only_writes_failures_down_and_lets_requests_through() {
    let dir = tempfile::tempdir().unwrap();
    let signer = Signer::ec();
    let yaml = format!(
        "mode: log_only\nlog: {{output: events.log}}\nproviders:\n  main:\n    issuer: https://id.test\n    jwks: '{}'\n    output_claim_to_headers: [{{header: X-User, claim: sub}}]\nrules:\n  - match: {{paths: [\"/api/strict/*\"]}}\n    providers: [main]\n    mode: block\n  - match: {{paths: [\"/api/*\"]}}\n    providers: [main]\n",
        jwks(&[(&signer, "k1")])
    );
    let auth = JwtAuth::from_yaml(&yaml, dir.path()).unwrap();
    let mut missing = request("/api/x", &[]);
    assert!(
        auth.check(&mut missing, ip()).await.is_ok(),
        "log_only: no token passes"
    );
    let bad = Signer::ec().token("k1", &claims(json!({})));
    let mut forged = request("/api/x?page=2", &[("authorization", &bearer(&bad))]);
    assert!(
        auth.check(&mut forged, ip()).await.is_ok(),
        "log_only: a bad token passes"
    );
    assert!(
        forged.headers.get("x-user").is_none(),
        "but with no claims: nothing was verified"
    );
    assert!(forged.headers.contains_key("authorization"), "and as it came");
    let mut strict = request("/api/strict/x", &[]);
    assert_eq!(refused(&auth, &mut strict).await.0, 401, "the rule's own mode: block");
    let good = signer.token("k1", &claims(json!({})));
    let mut fine = request("/api/x", &[("authorization", &bearer(&good))]);
    auth.check(&mut fine, ip()).await.unwrap();
    assert_eq!(fine.headers["x-user"], "u1");

    crate::accesslog::flush_all(Duration::from_secs(2));
    let text = std::fs::read_to_string(dir.path().join("events.log")).unwrap();
    let events: Vec<Value> = text.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
    let seen: Vec<(&str, &str, &str)> = events
        .iter()
        .map(|e| {
            (
                e["msg"].as_str().unwrap(),
                e["reason"].as_str().unwrap(),
                e["request"]["uri"].as_str().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        seen,
        [
            ("request let through (log_only)", "missing", "/api/x"),
            ("request let through (log_only)", "bad-signature", "/api/x?page=2"),
            ("request refused", "missing", "/api/strict/x"),
        ],
        "valid tokens are not written down"
    );
    assert_eq!(events[0]["logger"], "jwt");
    assert_eq!(events[0]["request"]["client_ip"], "203.0.113.7");
    assert!(!text.contains(&bad), "tokens are never written");
}

#[tokio::test]
async fn rules_bound_to_an_upstream_are_checked_by_its_proxy() {
    let signer = Signer::ec();
    let yaml = format!(
        "providers:\n  main:\n    issuer: https://id.test\n    audiences: [api]\n    jwks: '{}'\n    output_claim_to_headers: [{{header: X-User, claim: sub}}]\nrules:\n  - match: {{upstreams: ['http://App:8787'], paths: ['/api/*']}}\n    providers: [main]\n",
        jwks(&[(&signer, "k1")])
    );
    let auth = JwtAuth::from_yaml(&yaml, Path::new(".")).unwrap();
    assert!(auth.bound_to_upstreams());
    let app = [crate::config::upstream_authority("app:8787").unwrap()];
    let ai = [crate::config::upstream_authority("ai:8800").unwrap()];

    // Before the routes the rule is not looked at; the claim headers still come off.
    let mut parts = request("/api/orders", &[("x-user", "forged")]);
    auth.check(&mut parts, ip()).await.unwrap();
    assert!(parts.headers.get("x-user").is_none());
    // At the proxy to the app a token is needed; at another proxy, or off the rule's paths, not.
    let response = auth.check_upstream(&mut parts, ip(), &app).await.expect_err("no token");
    assert_eq!(response.status(), 401);
    assert!(
        auth.check_upstream(&mut request("/api/orders", &[]), ip(), &ai)
            .await
            .is_ok()
    );
    assert!(
        auth.check_upstream(&mut request("/page", &[]), ip(), &app)
            .await
            .is_ok()
    );
    let token = signer.token("k1", &claims(json!({})));
    let mut parts = request("/api/orders", &[("authorization", &bearer(&token))]);
    auth.check_upstream(&mut parts, ip(), &app).await.unwrap();
    assert_eq!(parts.headers["x-user"], "u1");

    // Upstreams are written as reverse_proxy takes them: a host and a port, `http://`,
    // `https://` or `h2c://` before them at most.
    let err = JwtAuth::from_yaml(&yaml.replace("http://App:8787", "ftp://app"), Path::new("."))
        .err()
        .map(|e| format!("{e:#}"))
        .unwrap_or_default();
    assert!(err.contains("rule 1: upstream"), "{err}");
}

/// A provider `main` (issuer https://id.test) with `signer`'s key, the protected resource `mcp`
/// (https://mcp.test/mcp) and a rule that guards it, asking for the scope `mcp:tools`.
fn protected(signer: &Signer, provider_extra: &str) -> JwtAuth {
    let yaml = format!(
        "providers:\n  main:\n    issuer: https://id.test\n{provider_extra}    jwks: '{}'\nresources:\n  mcp:\n    resource: https://mcp.test/mcp\n    scopes_supported: [\"mcp:tools\", \"mcp:admin\"]\n    resource_name: Test tools\nrules:\n  - match: {{paths: [\"/mcp\", \"/mcp/*\"]}}\n    providers: [main]\n    resource: mcp\n    scopes: [\"mcp:tools\"]\n",
        jwks(&[(signer, "k1")])
    );
    JwtAuth::from_yaml(&yaml, Path::new(".")).unwrap()
}

fn asked(method: &str, host: &str, uri: &str, token: Option<&str>) -> http::request::Parts {
    let mut builder = http::Request::builder().method(method).uri(uri).header("host", host);
    if let Some(token) = token {
        builder = builder.header("authorization", bearer(token));
    }
    builder.body(()).unwrap().into_parts().0
}

/// What a request is answered with when the check does not let it through: the status, the
/// `WWW-Authenticate` field, the body.
async fn answered(auth: &JwtAuth, mut parts: http::request::Parts) -> Option<(u16, String, String)> {
    let response = auth.check(&mut parts, ip()).await.err()?;
    let status = response.status().as_u16();
    let challenge = response
        .headers()
        .get("www-authenticate")
        .map_or(String::new(), |v| v.to_str().unwrap().to_string());
    let body = response.into_body().collect().await.unwrap().to_bytes();
    Some((status, challenge, String::from_utf8_lossy(&body).into_owned()))
}

const METADATA: &str = "https://mcp.test/.well-known/oauth-protected-resource/mcp";

#[tokio::test]
async fn a_protected_resource_publishes_its_metadata() {
    let auth = protected(&Signer::ec(), "");
    // RFC 9728 §3.1: the well-known address is on the resource's host, the resource's path after
    // it; no token is asked for it.
    let mut parts = asked("GET", "mcp.test", "/.well-known/oauth-protected-resource/mcp", None);
    let response = auth.check(&mut parts, ip()).await.expect_err("answered here");
    assert_eq!(response.status(), 200);
    assert_eq!(response.headers()["content-type"], "application/json");
    assert_eq!(response.headers()["access-control-allow-origin"], "*");
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let document: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        document,
        json!({
            "resource": "https://mcp.test/mcp",
            // The issuers of the providers of the rules that guard it.
            "authorization_servers": ["https://id.test"],
            "scopes_supported": ["mcp:tools", "mcp:admin"],
            "bearer_methods_supported": ["header"],
            "resource_name": "Test tools",
        })
    );
    let head = asked(
        "HEAD",
        "MCP.test:443",
        "/.well-known/oauth-protected-resource/mcp",
        None,
    );
    assert!(answered(&auth, head).await.is_some_and(|(status, ..)| status == 200));
    // Not another host's, not another path's, not to a POST: those go on to the routes.
    for (method, host, path) in [
        ("GET", "other.test", "/.well-known/oauth-protected-resource/mcp"),
        ("GET", "mcp.test", "/.well-known/oauth-protected-resource"),
        ("GET", "mcp.test", "/.well-known/oauth-protected-resource/mcp/x"),
        ("POST", "mcp.test", "/.well-known/oauth-protected-resource/mcp"),
    ] {
        let other = asked(method, host, path, None);
        assert!(answered(&auth, other).await.is_none(), "{method} {host}{path}");
    }
}

#[tokio::test]
async fn a_refusal_says_where_the_metadata_is_and_what_to_ask_for() {
    let signer = Signer::ec();
    let auth = protected(&signer, "");
    let token = |extra: Value| signer.token("k1", &claims(extra));
    let post = |token: Option<&str>| asked("POST", "mcp.test", "/mcp", token);
    let mine = json!({"aud": "https://mcp.test/mcp", "scope": "mcp:tools profile"});

    // No token: 401, with the address of the metadata and the scopes to ask for.
    let (status, challenge, _) = answered(&auth, post(None)).await.unwrap();
    assert_eq!(status, 401);
    assert_eq!(
        challenge,
        format!("Bearer scope=\"mcp:tools\", resource_metadata=\"{METADATA}\"")
    );

    // A token issued for this resource, with the scope: through, and again from the cache.
    for _ in 0..2 {
        assert!(answered(&auth, post(Some(&token(mine.clone())))).await.is_none());
    }
    // `aud` as a list, with a slash at the end, the scopes as `scp`.
    let listed = json!({"aud": ["https://api.test", "https://mcp.test/mcp/"], "scp": ["mcp:tools"]});
    assert!(answered(&auth, post(Some(&token(listed)))).await.is_none());

    // A token for another resource, or for none: not valid here, 401 (403 is for scopes).
    for aud in [json!("https://other.test/mcp"), json!("api"), Value::Null] {
        let other = json!({"aud": aud, "scope": "mcp:tools"});
        let (status, challenge, body) = answered(&auth, post(Some(&token(other)))).await.unwrap();
        assert_eq!((status, body.as_str()), (401, "Jwt is not for this resource"));
        assert_eq!(
            challenge,
            format!("Bearer error=\"invalid_token\", scope=\"mcp:tools\", resource_metadata=\"{METADATA}\"")
        );
    }
    // The right resource without the scope: 403, and what to come back with.
    for scope in [json!("mcp:admin profile"), json!("mcp:toolsx"), Value::Null] {
        let narrow = json!({"aud": "https://mcp.test/mcp", "scope": scope});
        let (status, challenge, _) = answered(&auth, post(Some(&token(narrow)))).await.unwrap();
        assert_eq!(status, 403);
        assert_eq!(
            challenge,
            format!("Bearer error=\"insufficient_scope\", scope=\"mcp:tools\", resource_metadata=\"{METADATA}\"")
        );
    }
    // An expired one: 401 as ever, with the metadata's address.
    let old = json!({"aud": "https://mcp.test/mcp", "scope": "mcp:tools", "exp": now() - 120});
    let (status, challenge, _) = answered(&auth, post(Some(&token(old)))).await.unwrap();
    assert_eq!(status, 401);
    assert!(
        challenge.starts_with("Bearer error=\"invalid_token\"") && challenge.contains(METADATA),
        "{challenge}"
    );

    // A provider that says what its tokens' `aud` is (an issuer that names the API its own way):
    // that is what is asked of them, and a miss is still 401 for a protected resource.
    let named = protected(&signer, "    audiences: [tools-api]\n");
    let fits = json!({"aud": "tools-api", "scope": "mcp:tools"});
    assert!(answered(&named, post(Some(&token(fits)))).await.is_none());
    let (status, ..) = answered(&named, post(Some(&token(mine)))).await.unwrap();
    assert_eq!(status, 401);
}

#[test]
fn what_the_file_may_say_of_a_protected_resource() {
    let load = |resources: &str, rule: &str| {
        let yaml = format!(
            "providers:\n  main:\n    issuer: https://id.test\n    jwks: '{}'\nresources:\n{resources}rules:\n  - match: {{paths: [\"/mcp\"]}}\n{rule}",
            jwks(&[(&Signer::ec(), "k1")])
        );
        JwtAuth::from_yaml(&yaml, Path::new("."))
            .map(|_| ())
            .map_err(|e| format!("{e:#}"))
    };
    let mcp = "  mcp:\n    resource: https://mcp.test/mcp\n";
    let guarded = "    providers: [main]\n    resource: mcp\n";
    load(mcp, guarded).unwrap();
    // Its own authorization servers, a resource at the root of its host.
    load(
        "  mcp:\n    resource: https://mcp.test\n    authorization_servers: [https://login.test]\n",
        guarded,
    )
    .unwrap();
    for (resources, rule, says) in [
        (
            mcp,
            "    providers: [main]\n    resource: tools\n",
            "no resource \"tools\"",
        ),
        (mcp, "    providers: [main]\n", "no rule guards it"),
        (mcp, "    resource: mcp\n", "have no providers"),
        (
            "  mcp:\n    resource: https://mcp.test/mcp\n    authorization_servers: [https://login.test]\n",
            "    resource: mcp\n",
            "needs providers",
        ),
        ("  mcp:\n    resource: mcp.test/mcp\n", guarded, "an http(s) URL"),
        (
            "  mcp:\n    resource: https://mcp.test/mcp?x=1\n",
            guarded,
            "without a query",
        ),
        (
            "  mcp:\n    resource: https://mcp.test/mcp#top\n",
            guarded,
            "without a query",
        ),
        (
            mcp,
            "    providers: [main]\n    resource: mcp\n    scopes: [\"two words\"]\n",
            "is not a scope",
        ),
    ] {
        let error = load(resources, rule).unwrap_err();
        assert!(error.contains(says), "{rule}: {error}");
    }
}
