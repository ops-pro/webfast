use super::*;

const SPEC: &str = r##"
openapi: 3.0.3
info: {title: shop, version: "1"}
components:
  securitySchemes:
    bearer: {type: http, scheme: bearer}
    key: {type: apiKey, in: header, name: X-Api-Key}
  schemas:
    Base:
      type: object
      required: [name]
      properties:
        name: {type: string, minLength: 1, maxLength: 20}
        id: {type: integer, readOnly: true}
    Order:
      allOf:
        - $ref: '#/components/schemas/Base'
        - type: object
          properties:
            qty: {type: integer, format: int32, minimum: 1}
            note: {type: string, nullable: true}
            email: {type: string, format: email}
            price: {type: number, minimum: 0, exclusiveMinimum: true}
  parameters:
    Limit: {name: limit, in: query, schema: {type: integer, minimum: 1, maximum: 100}}
paths:
  /orders:
    get:
      parameters:
        - $ref: '#/components/parameters/Limit'
        - {name: tag, in: query, schema: {type: array, items: {type: string, enum: [a, b]}}}
        - {name: ids, in: query, explode: false, schema: {type: array, items: {type: integer}}}
        - {name: X-Trace, in: header, required: true, schema: {type: string, pattern: '^[a-f0-9]{8}$'}}
        - {name: session, in: cookie, schema: {type: string, minLength: 4}}
      responses: {"200": {description: ok}}
    post:
      security: [{bearer: []}, {key: []}]
      requestBody:
        required: true
        content:
          application/json: {schema: {$ref: '#/components/schemas/Order'}}
          application/x-www-form-urlencoded:
            schema:
              type: object
              required: [name]
              properties: {name: {type: string}, qty: {type: integer}, tags: {type: array, items: {type: string}}}
          multipart/form-data: {schema: {type: object}}
      responses: {"201": {description: created}}
  /orders/{id}:
    parameters:
      - {name: id, in: path, required: true, schema: {type: integer, minimum: 1}}
    get:
      responses: {"200": {description: ok}}
    delete:
      responses: {"204": {description: gone}}
  /files/{name}.{ext}:
    get:
      parameters:
        - {name: name, in: path, required: true, schema: {type: string}}
        - {name: ext, in: path, required: true, schema: {type: string, enum: [pdf, txt]}}
      responses: {"200": {description: ok}}
"##;

const TRACE: (&str, &str) = ("x-trace", "0123abcd");
const BEARER: (&str, &str) = ("authorization", "Bearer abc");

fn firewall(extra: &str) -> ApiFirewall {
    ApiFirewall::from_spec(
        SPEC,
        &format!("spec: inline\nbase_path: /api\nreason_header: true\n{extra}"),
    )
    .unwrap()
}

/// `Ok(body passed on)` or `Err((status, reason))`.
async fn run(
    fw: &ApiFirewall,
    method: &str,
    uri: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> std::result::Result<String, (u16, String)> {
    let mut builder = http::Request::builder()
        .method(method)
        .uri(uri)
        .header("host", "shop.test");
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let (mut parts, ()) = builder.body(()).unwrap().into_parts();
    let body = if body.is_empty() {
        crate::body::empty()
    } else {
        crate::body::full(body.to_string())
    };
    match fw
        .check(
            &mut parts,
            body,
            "203.0.113.7".parse().unwrap(),
            &["access_token".to_string()],
        )
        .await
    {
        Ok(body) => Ok(String::from_utf8(body.collect().await.unwrap().to_bytes().to_vec()).unwrap()),
        Err(response) => Err((
            response.status().as_u16(),
            response
                .headers()
                .get("apifw-validation-status")
                .map(|v| v.to_str().unwrap().to_string())
                .unwrap_or_default(),
        )),
    }
}

async fn reason(fw: &ApiFirewall, method: &str, uri: &str, headers: &[(&str, &str)], body: &str) -> String {
    match run(fw, method, uri, headers, body).await {
        Ok(_) => panic!("{method} {uri} {body}: passed"),
        Err((status, reason)) => {
            assert!(status == 403 || status == 413 || status == 415, "{status}");
            reason
        }
    }
}

#[tokio::test]
async fn parameters_are_checked_against_the_spec() {
    let fw = firewall("");
    let ok = |uri: &'static str, headers: Vec<(&'static str, &'static str)>| {
        let fw = &fw;
        async move { run(fw, "GET", uri, &headers, "").await }
    };
    assert!(
        ok("/api/orders?limit=10&tag=a&tag=b&ids=1,2,3", vec![TRACE])
            .await
            .is_ok()
    );
    assert!(ok("/api/orders", vec![TRACE, ("cookie", "session=abcd")]).await.is_ok());
    assert!(ok("/api/orders/5", vec![]).await.is_ok());
    assert!(run(&fw, "HEAD", "/api/orders/5", &[], "").await.is_ok(), "HEAD as GET");
    assert!(run(&fw, "DELETE", "/api/orders/5", &[], "").await.is_ok());
    assert!(ok("/api/files/report.pdf", vec![]).await.is_ok());
    assert!(ok("/api/files/re%20port.txt", vec![]).await.is_ok(), "decoded");
    for (uri, headers, expected) in [
        ("/api/orders?limit=0", vec![TRACE], "request-parameter:query:limit"),
        ("/api/orders?limit=ten", vec![TRACE], "request-parameter:query:limit"),
        ("/api/orders?limit=0x10", vec![TRACE], "request-parameter:query:limit"),
        (
            "/api/orders?limit=1&limit=2",
            vec![TRACE],
            "request-parameter:query:limit",
        ),
        ("/api/orders?limit=", vec![TRACE], "request-parameter:query:limit"),
        ("/api/orders?tag=c", vec![TRACE], "request-parameter:query:tag"),
        ("/api/orders?ids=1,x", vec![TRACE], "request-parameter:query:ids"),
        ("/api/orders?other=1", vec![TRACE], "request-parameter:query:other"),
        ("/api/orders?limit=%G1", vec![TRACE], "request-query:encoding"),
        ("/api/orders", vec![], "request-parameter:header:x-trace"),
        (
            "/api/orders",
            vec![("x-trace", "nothex!!")],
            "request-parameter:header:x-trace",
        ),
        (
            "/api/orders",
            vec![TRACE, ("cookie", "session=ab")],
            "request-parameter:cookie:session",
        ),
        ("/api/orders/0", vec![], "request-parameter:path:id"),
        ("/api/orders/x", vec![], "request-parameter:path:id"),
        ("/api/files/report.exe", vec![], "request-parameter:path:ext"),
    ] {
        assert_eq!(reason(&fw, "GET", uri, &headers, "").await, expected, "{uri}");
    }
}

#[tokio::test]
async fn requests_outside_the_spec_or_ambiguous_ones_are_refused() {
    let fw = firewall("");
    for (method, uri) in [
        ("GET", "/api/nope"),
        ("PUT", "/api/orders"),
        ("GET", "/api/ORDERS"),
        ("GET", "/api/orders/"),
        ("GET", "/api"),
    ] {
        assert_eq!(
            reason(&fw, method, uri, &[TRACE], "").await,
            "request:unknown-operation",
            "{method} {uri}"
        );
    }
    for uri in [
        "/api/orders/%2e%2e/files/a.pdf",
        "/api//orders",
        "/api/orders%2F5",
        "/x/../api/orders",
        "/api/orders/5/..",
    ] {
        assert_eq!(
            reason(&fw, "GET", uri, &[TRACE], "").await,
            "request-path:ambiguous",
            "{uri}"
        );
    }
    assert_eq!(
        reason(&fw, "GET", "/api/orders/%FF", &[], "").await,
        "request-path:encoding"
    );
    // The base is matched as the server's matchers do: `/API` is under `/api`.
    assert!(run(&fw, "GET", "/API/orders/5", &[], "").await.is_ok());
    assert!(run(&fw, "GET", "/%61pi/orders/5", &[], "").await.is_ok());
    assert!(
        run(&fw, "GET", "/other/thing", &[], "").await.is_ok(),
        "not under the API"
    );
    assert!(
        run(&fw, "GET", "/apis", &[], "").await.is_ok(),
        "a longer name is not under it"
    );
    assert_eq!(
        reason(&fw, "OPTIONS", "/api/orders", &[], "").await,
        "request:unknown-operation"
    );
    let options = firewall("pass_options: true\n");
    assert!(run(&options, "OPTIONS", "/api/orders", &[], "").await.is_ok());
    assert!(
        run(&options, "OPTIONS", "/api/nope", &[], "").await.is_err(),
        "only for known paths"
    );
}

#[tokio::test]
async fn bodies_are_checked_and_passed_on_unchanged() {
    let fw = firewall("");
    let json = [("content-type", "application/json"), BEARER];
    let order = r#"{"name":"pen","qty":2,"note":null,"email":"a@b.test","price":1.5}"#;
    assert_eq!(
        run(&fw, "POST", "/api/orders", &json, order).await,
        Ok(order.to_string())
    );
    let with_key = [("content-type", "application/json; charset=utf-8"), ("x-api-key", "k")];
    assert!(
        run(&fw, "POST", "/api/orders", &with_key, order).await.is_ok(),
        "the other security alternative"
    );
    let form = [("content-type", "application/x-www-form-urlencoded"), BEARER];
    assert!(
        run(&fw, "POST", "/api/orders", &form, "name=pen&qty=2&tags=a&tags=b")
            .await
            .is_ok()
    );
    let multipart = [("content-type", "multipart/form-data; boundary=x"), BEARER];
    assert_eq!(
        run(&fw, "POST", "/api/orders", &multipart, "--x--").await,
        Ok("--x--".to_string()),
        "declared, not looked into"
    );
    for (headers, body, expected) in [
        (&json[..], r#"{"qty":2}"#, "request-body:application/json"),
        (&json[..], r#"{"name":"pen","qty":0}"#, "request-body:application/json"),
        (
            &json[..],
            r#"{"name":"pen","qty":3000000000}"#,
            "request-body:application/json",
        ),
        (&json[..], r#"{"name":"pen","id":7}"#, "request-body:application/json"),
        (
            &json[..],
            r#"{"name":"pen","email":"nope"}"#,
            "request-body:application/json",
        ),
        (
            &json[..],
            r#"{"name":"pen","price":0}"#,
            "request-body:application/json",
        ),
        (&json[..], r#"{"name":"#, "request-body:application/json"),
        (&json[..], "", "request-body:missing"),
        (&form[..], "qty=2", "request-body:application/x-www-form-urlencoded"),
        (
            &form[..],
            "name=a&qty=x",
            "request-body:application/x-www-form-urlencoded",
        ),
        (
            &form[..],
            "name=a&name=b",
            "request-body:application/x-www-form-urlencoded",
        ),
        (
            &[("content-type", "text/xml"), BEARER][..],
            "<x/>",
            "request-body:content-type:text/xml",
        ),
        (
            &[("content-type", "application/json")][..],
            order,
            "security-requirements:missing",
        ),
        (
            &[("content-type", "application/json"), ("authorization", "Basic x")][..],
            order,
            "security-requirements:missing",
        ),
    ] {
        assert_eq!(
            reason(&fw, "POST", "/api/orders", headers, body).await,
            expected,
            "{body}"
        );
    }
    let gzip = [
        ("content-type", "application/json"),
        ("content-encoding", "gzip"),
        BEARER,
    ];
    assert_eq!(
        run(&fw, "POST", "/api/orders", &gzip, order).await,
        Err((415, "request-body:content-encoding".into()))
    );
    let small = firewall("max_body_size: 50\n");
    assert_eq!(
        run(&small, "POST", "/api/orders", &json, order).await.unwrap_err().0,
        413
    );
    assert_eq!(
        run(&small, "POST", "/api/orders", &multipart, &"x".repeat(60))
            .await
            .unwrap_err()
            .0,
        413
    );
}

#[tokio::test]
async fn strict_bodies_refuse_unknown_properties_also_through_allof() {
    let json = [("content-type", "application/json"), BEARER];
    let extra = r#"{"name":"pen","qty":1,"colour":"red"}"#;
    assert!(
        run(&firewall(""), "POST", "/api/orders", &json, extra).await.is_ok(),
        "not strict"
    );
    let strict = firewall("strict_bodies: true\n");
    assert_eq!(
        reason(&strict, "POST", "/api/orders", &json, extra).await,
        "request-body:application/json"
    );
    // Properties of both members of the allOf are known.
    assert!(
        run(&strict, "POST", "/api/orders", &json, r#"{"name":"pen","qty":1}"#)
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn modes_decide_what_a_violation_does() {
    let log_only = firewall("mode: log_only\n");
    assert!(run(&log_only, "GET", "/api/nope", &[], "").await.is_ok());
    assert!(run(&log_only, "GET", "/api/orders?limit=0", &[TRACE], "").await.is_ok());
    let off = firewall("mode: off\n");
    assert!(run(&off, "GET", "/api/orders/%2e%2e/x", &[], "").await.is_ok());
    // Per operation: POST /orders not checked, the rest blocked.
    let endpoint = firewall("endpoints:\n  - {method: POST, path: /orders, mode: off}\n");
    assert!(
        run(
            &endpoint,
            "POST",
            "/api/orders",
            &[("content-type", "text/xml")],
            "<x/>"
        )
        .await
        .is_ok()
    );
    assert!(run(&endpoint, "GET", "/api/orders/0", &[], "").await.is_err());
    // A body over the limit cannot be passed on, whatever the mode.
    let small = firewall("mode: log_only\nmax_body_size: 10\n");
    let json = [("content-type", "application/json"), BEARER];
    assert_eq!(
        run(&small, "POST", "/api/orders", &json, r#"{"name":"a long one"}"#)
            .await
            .unwrap_err()
            .0,
        413
    );
}

#[tokio::test]
async fn openapi_3_1_schemas_are_json_schema_already() {
    let spec = r#"
openapi: 3.1.0
info: {title: t, version: "1"}
paths:
  /items:
    post:
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [n]
              properties:
                n: {type: [integer, "null"], exclusiveMinimum: 0}
                tags: {type: array, prefixItems: [{const: first}]}
      responses: {"200": {description: ok}}
"#;
    let fw = ApiFirewall::from_spec(spec, "spec: inline\nreason_header: true\n").unwrap();
    let json = [("content-type", "application/json")];
    assert!(run(&fw, "POST", "/items", &json, r#"{"n":null}"#).await.is_ok());
    assert!(
        run(&fw, "POST", "/items", &json, r#"{"n":1,"tags":["first","x"]}"#)
            .await
            .is_ok()
    );
    assert!(run(&fw, "POST", "/items", &json, r#"{"n":0}"#).await.is_err());
    assert!(
        run(&fw, "POST", "/items", &json, r#"{"n":1,"tags":["second"]}"#)
            .await
            .is_err()
    );
}

#[test]
fn specs_and_configurations_that_cannot_work_are_refused() {
    let config = "spec: inline\n";
    for (spec, message) in [
        ("swagger: '2.0'\npaths: {}\n", "not an OpenAPI 3"),
        ("openapi: 4.0.0\npaths: {}\n", "not supported"),
        (
            "openapi: 3.0.0\npaths:\n  /a:\n    get:\n      parameters: [{$ref: 'other.yaml#/p'}]\n",
            "only references within the document",
        ),
        (
            "openapi: 3.0.0\npaths:\n  /a:\n    get:\n      parameters: [{name: id, in: path, schema: {type: string}}]\n",
            "not in the path",
        ),
        (
            "openapi: 3.0.0\npaths:\n  /a:\n    get:\n      security: [{nope: []}]\n",
            "nope is not defined",
        ),
        (
            "openapi: 3.0.0\npaths:\n  /a:\n    get:\n      parameters: [{name: q, in: query, schema: {type: string, pattern: '(?=x)'}}]\n",
            "parameter q",
        ),
    ] {
        let err = ApiFirewall::from_spec(spec, config)
            .err()
            .map(|e| format!("{e:#}"))
            .unwrap_or_default();
        assert!(err.contains(message), "{spec}\n→ {err}");
    }
    let err = ApiFirewall::from_spec(SPEC, "spec: inline\nendpoints: [{path: /nope, mode: off}]\n")
        .err()
        .map(|e| e.to_string())
        .unwrap_or_default();
    assert!(err.contains("no such operation"), "{err}");
}

/// Costs per request, release build: `cargo test --release apifw::tests::timings -- --ignored --nocapture`.
#[tokio::test]
#[ignore = "a measurement, not a test"]
async fn timings() {
    let fw = firewall("");
    let order = r#"{"name":"pen","qty":2,"note":null,"email":"a@b.test","price":1.5}"#;
    let cases = [
        ("outside the API", "GET", "/index.html", vec![], ""),
        (
            "GET with 3 parameters",
            "GET",
            "/api/orders?limit=10&tag=a&tag=b",
            vec![TRACE],
            "",
        ),
        (
            "POST, JSON body (70 B)",
            "POST",
            "/api/orders",
            vec![("content-type", "application/json"), BEARER],
            order,
        ),
        ("unknown path, refused", "GET", "/api/nope", vec![], ""),
    ];
    for (name, method, uri, headers, body) in cases {
        let rounds = 50_000u32;
        let started = std::time::Instant::now();
        for _ in 0..rounds {
            let _ = run(&fw, method, uri, &headers, body).await;
        }
        let total = started.elapsed() / rounds;
        // The same request without the firewall: building it and collecting its body.
        let none = ApiFirewall {
            apis: Vec::new(),
            log: EventLog::new("api-firewall", None, Path::new(".")),
        };
        let started = std::time::Instant::now();
        for _ in 0..rounds {
            let _ = run(&none, method, uri, &headers, body).await;
        }
        let baseline = started.elapsed() / rounds;
        println!(
            "{name}: {:?} (request alone {baseline:?})",
            total.saturating_sub(baseline)
        );
    }
}

/// A spec with the operations `GET /<name>` for each name.
fn small_spec(names: &[&str]) -> String {
    let mut text = "openapi: 3.0.3\ninfo: {title: t, version: '1'}\npaths:\n".to_string();
    for name in names {
        text.push_str(&format!(
            "  /{name}:\n    get:\n      responses: {{'200': {{description: ok}}}}\n"
        ));
    }
    text
}

/// The server's own routes as the spec source sees them: the spec in `text` with an ETag (a 304
/// for a matching If-None-Match), or only the status when it is not 200. `answers` counts the 200s
/// and the 304s.
fn served(text: Arc<Mutex<(String, u16)>>, answers: Arc<Mutex<(u32, u32)>>) -> LocalFetch {
    Arc::new(move |request: http::Request<Body>| {
        let (text, status) = text.lock().unwrap().clone();
        let answers = answers.clone();
        Box::pin(async move {
            let etag = format!("\"{}\"", &blake3::hash(text.as_bytes()).to_hex()[..16]);
            let mut response = http::Response::new(crate::body::empty());
            if status != 200 {
                *response.status_mut() = StatusCode::from_u16(status).unwrap();
                return response;
            }
            if request
                .headers()
                .get(http::header::IF_NONE_MATCH)
                .is_some_and(|v| v == etag.as_str())
            {
                answers.lock().unwrap().1 += 1;
                *response.status_mut() = StatusCode::NOT_MODIFIED;
            } else {
                answers.lock().unwrap().0 += 1;
                *response.body_mut() = crate::body::full(text);
            }
            response
                .headers_mut()
                .insert(http::header::ETAG, HeaderValue::from_str(&etag).unwrap());
            response
        })
    })
}

#[tokio::test]
async fn a_spec_from_the_servers_own_routes_is_kept_current() {
    let dir = tempfile::tempdir().unwrap();
    let yaml = "apis:\n  - spec: {uri: /openapi.yaml, refresh: 1h}\n    base_path: /api\n    reason_header: true\n";
    let fw = ApiFirewall::from_yaml(yaml, dir.path()).unwrap();
    assert_eq!(fw.counts(), (1, 0, 1));
    assert_eq!(
        run(&fw, "GET", "/api/a", &[], "").await,
        Err((503, "spec:unavailable".into())),
        "no spec yet"
    );
    assert!(
        run(&fw, "GET", "/elsewhere", &[], "").await.is_ok(),
        "the rest of the site is not held up"
    );

    let text = Arc::new(Mutex::new((small_spec(&["a"]), 200)));
    let answers = Arc::new(Mutex::new((0, 0)));
    let local = served(text.clone(), answers.clone());
    assert!(fw.look_now(Some(&local)).await[0].is_ok());
    assert!(run(&fw, "GET", "/api/a", &[], "").await.is_ok());
    assert_eq!(run(&fw, "GET", "/api/b", &[], "").await.unwrap_err().0, 403);

    // Unchanged: a 304, nothing read or compiled again.
    assert!(fw.look_now(Some(&local)).await[0].is_ok());
    assert_eq!(*answers.lock().unwrap(), (1, 1));
    // Changed: the new spec replaces the old one.
    text.lock().unwrap().0 = small_spec(&["a", "b"]);
    assert!(fw.look_now(Some(&local)).await[0].is_ok());
    assert!(run(&fw, "GET", "/api/b", &[], "").await.is_ok());
    // A failing source, or a spec that does not compile, leaves the last one in place.
    *text.lock().unwrap() = (String::new(), 500);
    assert!(fw.look_now(Some(&local)).await[0].is_err());
    *text.lock().unwrap() = ("openapi: 9.9.9\n".into(), 200);
    assert!(fw.look_now(Some(&local)).await[0].is_err());
    assert!(
        run(&fw, "GET", "/api/b", &[], "").await.is_ok(),
        "the last good spec holds"
    );

    let log_only = ApiFirewall::from_yaml(&yaml.replace("reason_header: true", "mode: log_only"), dir.path()).unwrap();
    assert!(
        run(&log_only, "GET", "/api/a", &[], "").await.is_ok(),
        "log_only: no spec, let through"
    );
}

#[tokio::test]
async fn a_spec_not_read_again_within_its_ttl_stops_holding() {
    let dir = tempfile::tempdir().unwrap();
    let yaml = "apis:\n  - spec: {uri: /openapi.yaml, refresh: 1h, ttl: 200ms}\n    base_path: /api\n";
    let fw = ApiFirewall::from_yaml(yaml, dir.path()).unwrap();
    let text = Arc::new(Mutex::new((small_spec(&["a"]), 200)));
    let local = served(text.clone(), Arc::new(Mutex::new((0, 0))));
    assert!(fw.look_now(Some(&local)).await[0].is_ok());
    assert!(run(&fw, "GET", "/api/a", &[], "").await.is_ok());
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        run(&fw, "GET", "/api/a", &[], "").await.unwrap_err().0,
        503,
        "past its ttl"
    );
    // A successful look, here a 304, makes it hold again.
    assert!(fw.look_now(Some(&local)).await[0].is_ok());
    assert!(run(&fw, "GET", "/api/a", &[], "").await.is_ok());
}

#[tokio::test]
async fn a_spec_file_is_read_again_when_it_changes() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("openapi.yaml"), small_spec(&["a"])).unwrap();
    let yaml = "apis:\n  - spec: {file: openapi.yaml, refresh: 1h}\n    base_path: /api\n";
    let fw = ApiFirewall::from_yaml(yaml, dir.path()).unwrap();
    assert_eq!(fw.counts(), (1, 1, 0), "read at startup");
    assert!(run(&fw, "GET", "/api/a", &[], "").await.is_ok());
    assert!(fw.look_now(None).await[0].is_ok(), "unchanged");
    std::fs::write(dir.path().join("openapi.yaml"), small_spec(&["a", "bb"])).unwrap();
    assert!(fw.look_now(None).await[0].is_ok());
    assert!(run(&fw, "GET", "/api/bb", &[], "").await.is_ok());
}

#[tokio::test]
async fn a_spec_from_a_url_is_fetched_with_its_headers() {
    let spec = small_spec(&["a"]);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let spec = spec.clone();
            tokio::spawn(async move {
                let service = hyper::service::service_fn(move |req: http::Request<hyper::body::Incoming>| {
                    let ok = req.headers().get("authorization").is_some_and(|v| v == "Bearer t0ken");
                    let body = if ok { spec.clone() } else { String::new() };
                    async move {
                        let mut response = http::Response::new(http_body_util::Full::new(Bytes::from(body)));
                        if !ok {
                            *response.status_mut() = StatusCode::UNAUTHORIZED;
                        }
                        Ok::<_, std::convert::Infallible>(response)
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    // SAFETY: no other test reads or writes these variables.
    unsafe {
        std::env::set_var("WEB_SERVER_TEST_APIFW_TOKEN", "t0ken");
        std::env::set_var("WEB_SERVER_TEST_APIFW_WRONG", "nope");
    }
    let dir = tempfile::tempdir().unwrap();
    let yaml = |var: &str| {
        format!(
            "apis:\n  - spec:\n      uri: http://{address}/spec\n      headers: {{Authorization: 'Bearer ${{{var}}}'}}\n    base_path: /api\n"
        )
    };
    let fw = ApiFirewall::from_yaml(&yaml("WEB_SERVER_TEST_APIFW_TOKEN"), dir.path()).unwrap();
    assert!(fw.look_now(None).await[0].is_ok());
    assert!(run(&fw, "GET", "/api/a", &[], "").await.is_ok());
    let wrong = ApiFirewall::from_yaml(&yaml("WEB_SERVER_TEST_APIFW_WRONG"), dir.path()).unwrap();
    let err = format!("{:#}", wrong.look_now(None).await.remove(0).unwrap_err());
    assert!(err.contains("401"), "{err}");
}

#[tokio::test]
async fn violations_are_written_to_the_firewalls_own_log() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("openapi.yaml"), small_spec(&["a"])).unwrap();
    let yaml = "log: {output: firewall.log}\napis:\n  - spec: openapi.yaml\n    base_path: /api\n    endpoints: [{path: /a, mode: log_only}]\n";
    let fw = ApiFirewall::from_yaml(yaml, dir.path()).unwrap();
    assert!(run(&fw, "GET", "/api/a?x=1", &[], "").await.is_ok(), "log_only for /a");
    assert_eq!(
        run(&fw, "GET", "/api/zzz?access_token=s3cret", &[], "")
            .await
            .unwrap_err()
            .0,
        403
    );
    crate::accesslog::flush_all(Duration::from_secs(2));
    let text = std::fs::read_to_string(dir.path().join("firewall.log")).unwrap();
    let events: Vec<Value> = text.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
    let seen: Vec<(&str, &str, u64)> = events
        .iter()
        .map(|e| {
            (
                e["msg"].as_str().unwrap(),
                e["reason"].as_str().unwrap(),
                e["status"].as_u64().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        seen,
        [
            ("request let through (log_only)", "request-parameter:query:x", 403),
            ("request refused", "request:unknown-operation", 403),
        ]
    );
    assert_eq!(events[0]["logger"], "api-firewall");
    assert_eq!(events[0]["request"]["client_ip"], "203.0.113.7");
    assert_eq!(
        events[1]["request"]["uri"], "/api/zzz?access_token=REDACTED",
        "the JWT module's parameter"
    );
}

#[test]
fn schema_errors_name_the_place_and_keyword_not_the_value() {
    let schema = serde_json::json!({
        "type": "object",
        "properties": {"password": {"type": "string", "minLength": 12}},
        "additionalProperties": false
    });
    let validator = jsonschema::validator_for(&schema).unwrap();
    let short = serde_json::json!({"password": "hunter2"});
    assert_eq!(
        schema_error(&validator.validate(&short).unwrap_err()),
        "/password: minLength"
    );
    let extra = serde_json::json!({"password": "correct horse battery", "admin": true});
    assert_eq!(
        schema_error(&validator.validate(&extra).unwrap_err()),
        "/: additionalProperties: admin"
    );
}

/// `Ok` or `Err((status, reason))` for a GET checked at a proxy sending to `upstream`.
async fn at_upstream(fw: &ApiFirewall, upstream: &str, uri: &str) -> std::result::Result<(), (u16, String)> {
    let (mut parts, ()) = http::Request::get(uri)
        .header("host", "shop.test")
        .body(())
        .unwrap()
        .into_parts();
    let upstreams = [crate::config::upstream_authority(upstream).unwrap()];
    let client_ip = "203.0.113.7".parse().unwrap();
    match fw.check_upstream(&mut parts, empty(), client_ip, &[], &upstreams).await {
        Ok(_) => Ok(()),
        Err(response) => Err((
            response.status().as_u16(),
            response
                .headers()
                .get("apifw-validation-status")
                .map(|v| v.to_str().unwrap().to_string())
                .unwrap_or_default(),
        )),
    }
}

#[tokio::test]
async fn apis_bound_to_an_upstream_are_checked_by_its_proxy() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("openapi.yaml"), small_spec(&["a"])).unwrap();
    let yaml =
        "apis:\n  - spec: openapi.yaml\n    upstreams: [app:8787]\n    base_path: /api\n    reason_header: true\n";
    let fw = ApiFirewall::from_yaml(yaml, dir.path()).unwrap();
    assert!(fw.bound_to_upstreams());
    assert!(
        run(&fw, "GET", "/api/zzz", &[], "").await.is_ok(),
        "not looked at before the routes"
    );
    assert!(at_upstream(&fw, "app:8787", "/api/a").await.is_ok());
    assert_eq!(
        at_upstream(&fw, "http://APP:8787", "/api/zzz").await,
        Err((403, "request:unknown-operation".into()))
    );
    assert!(
        at_upstream(&fw, "ai:8800", "/api/zzz").await.is_ok(),
        "another upstream"
    );
    assert!(at_upstream(&fw, "app:8787", "/page").await.is_ok(), "outside base_path");
    assert!(ApiFirewall::from_yaml(&yaml.replace("app:8787", "unix/app.sock"), dir.path()).is_err());
}
