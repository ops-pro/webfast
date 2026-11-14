use super::*;
use crate::extensions::{At, Client};
use crate::handler::ConnInfo;
use crate::jwt::jwks::tests::{Signer, jwks as jwks_of};

fn conn(tls: bool, trusted: bool) -> ConnInfo {
    ConnInfo {
        remote: "203.0.113.7:4000".parse().unwrap(),
        tls,
        trusted,
        sni: None,
        ja4: None,
    }
}

fn request(host: &str, uri: &str, headers: &[(&str, &str)]) -> http::request::Parts {
    let mut builder = http::Request::get(uri).header("host", host);
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    builder.body(()).unwrap().into_parts().0
}

/// The standard alphabet with padding, as a Byte Sequence has it.
fn base64(bytes: &[u8]) -> String {
    let mut text: String = jwks::base64url(bytes)
        .chars()
        .map(|c| match c {
            '-' => '+',
            '_' => '/',
            other => other,
        })
        .collect();
    while !text.len().is_multiple_of(4) {
        text.push('=');
    }
    text
}

#[test]
fn the_signature_base_is_rfc_9421_s() {
    // RFC 9421 B.2.6: the test request signed with the Ed25519 test key (B.1.4).
    let parts = {
        let mut builder = http::Request::post("/foo?param=Value&Pet=dog");
        for (name, value) in [
            ("host", "example.com"),
            ("date", "Tue, 20 Apr 2021 02:07:55 GMT"),
            ("content-type", "application/json"),
            ("content-length", "18"),
        ] {
            builder = builder.header(name, value);
        }
        builder.body(()).unwrap().into_parts().0
    };
    let written = "(\"date\" \"@method\" \"@path\" \"@authority\" \"content-type\" \"content-length\")\
                   ;created=1618884473;keyid=\"test-key-ed25519\"";
    let field = format!("sig-b26={written}");
    let (label, value) = members(&field)[0];
    assert_eq!((label, value), ("sig-b26", written));
    let input = Input::parse(value).unwrap();
    assert_eq!(input.created, Some(1_618_884_473));
    assert_eq!(input.keyid.as_deref(), Some("test-key-ed25519"));
    assert_eq!(input.components.len(), 6);
    let base = signature_base(&parts, &input, true, None).unwrap();
    assert_eq!(
        base,
        "\"date\": Tue, 20 Apr 2021 02:07:55 GMT\n\
         \"@method\": POST\n\
         \"@path\": /foo\n\
         \"@authority\": example.com\n\
         \"content-type\": application/json\n\
         \"content-length\": 18\n\
         \"@signature-params\": (\"date\" \"@method\" \"@path\" \"@authority\" \"content-type\" \"content-length\")\
         ;created=1618884473;keyid=\"test-key-ed25519\""
    );
    let keys = KeySet::parse(
        br#"{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"test-key-ed25519","x":"JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs"}]}"#,
    )
    .unwrap();
    let signature =
        byte_sequence(":wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==:")
            .unwrap();
    assert_eq!(signature.len(), 64);
    assert_eq!(
        keys.verify_thumbprint("test-key-ed25519", Some(Alg::EdDsa), 0, base.as_bytes(), &signature),
        Checked::Valid
    );
    assert_eq!(
        keys.verify_thumbprint("test-key-ed25519", None, 0, b"another base", &signature),
        Checked::BadSignature
    );
}

#[test]
fn a_key_is_named_by_its_thumbprint() {
    // RFC 8037 A.3: the thumbprint of the Ed25519 key of its A.2.
    let keys =
        KeySet::parse(br#"{"keys":[{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}]}"#)
            .unwrap();
    assert_eq!(keys.thumbprints(), ["kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"]);
}

#[test]
fn fields_are_taken_apart_as_structured_fields_are() {
    // A Dictionary's members: commas inside strings, inner lists and byte sequences stay.
    let field = "a=(\"x,y\" \"z\");k=\"1,2\", b=:AA==:, c=\"q, \\\"r\\\"\", d";
    assert_eq!(
        members(field),
        [
            ("a", "(\"x,y\" \"z\");k=\"1,2\""),
            ("b", ":AA==:"),
            ("c", "\"q, \\\"r\\\"\""),
            ("d", "")
        ]
    );
    let input =
        Input::parse("(\"@authority\" \"signature-agent\";key=\"sig1\");created=1;expires=2;keyid=\"k\";alg=\"ed25519\";tag=\"web-bot-auth\";nonce=\"a;b\"")
            .unwrap();
    assert_eq!(input.components[0].written, "\"@authority\"");
    assert_eq!(input.components[1].written, "\"signature-agent\";key=\"sig1\"");
    assert_eq!(input.components[1].key, Some("sig1"));
    assert_eq!((input.created, input.expires), (Some(1), Some(2)));
    assert_eq!(input.tag.as_deref(), Some("web-bot-auth"));
    assert_eq!(input.alg.as_deref(), Some("ed25519"));
    // A parameter this check does not fill in is seen as one.
    let other = Input::parse("(\"@query-param\";name=\"q\" \"content-digest\";sf);created=1").unwrap();
    assert!(other.components.iter().all(|c| c.other));
    for not in [
        "\"@authority\"",
        "(\"@authority\"",
        "(@authority);created=1",
        "(\"a\");created=soon",
    ] {
        assert!(Input::parse(not).is_none(), "{not}");
    }
    // The host a Signature-Agent names: a Dictionary of strings, or one string as at first.
    assert_eq!(
        agent_host("sig1=\"https://Agent.Example/x\"").as_deref(),
        Some("agent.example")
    );
    assert_eq!(
        agent_host("\"https://agent.example\"").as_deref(),
        Some("agent.example")
    );
    assert_eq!(agent_host("nonsense"), None);
    // `@authority`: lowercase, the scheme's own port left out.
    let host = |host: &str, https: bool| authority(&request(host, "/", &[]), https);
    assert_eq!(host("Example.COM:443", true), "example.com");
    assert_eq!(host("example.com:443", false), "example.com:443");
    assert_eq!(host("example.com:80", false), "example.com");
    assert_eq!(host("example.com:8443", true), "example.com:8443");
    assert_eq!(host("[2001:db8::1]:443", true), "[2001:db8::1]");
}

/// An agent `crawler` with `signer`'s key, and what it signs requests with.
struct Bot {
    auth: BotAuth,
    signer: Signer,
    keyid: String,
}

impl Bot {
    fn new() -> Bot {
        let signer = Signer::ed();
        let keys = jwks_of(&[(&signer, "k1")]);
        let keyid = KeySet::parse(keys.as_bytes()).unwrap().thumbprints().remove(0);
        let yaml = format!("agents:\n  crawler:\n    jwks: '{keys}'\n");
        Bot {
            auth: BotAuth::from_yaml(&yaml, Path::new(".")).unwrap(),
            signer,
            keyid,
        }
    }

    /// The fields of a signed request to `host`: `covered` and `parameters` as the input has
    /// them, the signature over the base they make with `agent` as `Signature-Agent`.
    fn sign(&self, host: &str, covered: &str, parameters: &str, agent: Option<&str>) -> Vec<(String, String)> {
        let written = format!("({covered}){parameters}");
        let mut headers = vec![("signature-input".to_string(), format!("sig1={written}"))];
        if let Some(agent) = agent {
            headers.push(("signature-agent".to_string(), agent.to_string()));
        }
        let borrowed: Vec<(&str, &str)> = headers.iter().map(|(n, v)| (n.as_str(), v.as_str())).collect();
        let parts = request(host, "/page?x=1", &borrowed);
        let input = Input::parse(&written).unwrap();
        // What cannot be filled in has no base: something is signed all the same.
        let base = signature_base(&parts, &input, true, agent).unwrap_or_else(|| written.clone());
        let Signer::Ed(pair) = &self.signer else { unreachable!() };
        headers.push((
            "signature".to_string(),
            format!("sig1=:{}:", base64(pair.sign(base.as_bytes()).as_ref())),
        ));
        headers
    }

    /// `created` now, valid for five minutes, this key, the tag.
    fn parameters(&self) -> String {
        let now = unix_now();
        format!(
            ";created={now};expires={};keyid=\"{}\";alg=\"ed25519\";tag=\"web-bot-auth\"",
            now + 300,
            self.keyid
        )
    }

    /// The agent the request is marked with after the check, over TLS unless `conn` says other.
    async fn seen(&self, host: &str, headers: &[(String, String)], conn: &ConnInfo) -> Option<String> {
        let borrowed: Vec<(&str, &str)> = headers.iter().map(|(n, v)| (n.as_str(), v.as_str())).collect();
        let mut parts = request(host, "/page?x=1", &borrowed);
        let client = Client {
            ip: conn.remote.ip(),
            conn,
            at: At::Routes,
        };
        self.auth.check(&mut parts, client).await;
        let header = parts
            .headers
            .get("x-verified-bot")
            .map(|v| v.to_str().unwrap().to_string());
        let marked = parts.extensions.get::<VerifiedBot>().map(|bot| bot.0.to_string());
        assert_eq!(header, marked, "the header and the mark say the same");
        header
    }
}

const AGENT: &str = "sig1=\"https://crawler.example\"";
const COVERED: &str = "\"@authority\" \"signature-agent\";key=\"sig1\"";

#[tokio::test]
async fn a_signed_request_of_a_named_agent_is_marked() {
    let bot = Bot::new();
    let tls = conn(true, false);
    let signed = bot.sign("example.test", COVERED, &bot.parameters(), Some(AGENT));
    assert_eq!(
        bot.seen("example.test", &signed, &tls).await.as_deref(),
        Some("crawler")
    );
    // Without a Signature-Agent, and with it as one string, as it was first written.
    let bare = bot.sign("example.test", "\"@authority\"", &bot.parameters(), None);
    assert_eq!(bot.seen("example.test", &bare, &tls).await.as_deref(), Some("crawler"));
    let legacy = bot.sign(
        "example.test",
        "\"@authority\" \"signature-agent\"",
        &bot.parameters(),
        Some("\"https://crawler.example\""),
    );
    assert_eq!(
        bot.seen("example.test", &legacy, &tls).await.as_deref(),
        Some("crawler")
    );
    // The whole address covered instead of the host.
    let whole = bot.sign("example.test", "\"@target-uri\" \"@method\"", &bot.parameters(), None);
    assert_eq!(bot.seen("example.test", &whole, &tls).await.as_deref(), Some("crawler"));
    // Behind a trusted proxy that ended TLS.
    let mut forwarded = signed.clone();
    forwarded.push(("x-forwarded-proto".to_string(), "https".to_string()));
    assert_eq!(
        bot.seen("example.test", &forwarded, &conn(false, true))
            .await
            .as_deref(),
        Some("crawler")
    );
}

#[tokio::test]
async fn what_does_not_hold_is_an_ordinary_request() {
    let bot = Bot::new();
    let tls = conn(true, false);
    let signed = bot.sign("example.test", COVERED, &bot.parameters(), Some(AGENT));
    // Made for another host: a signature a site was shown is of no use at the next one.
    assert_eq!(bot.seen("other.test", &signed, &tls).await, None);
    // The client's own word is taken off, signed or not.
    let claimed = [("x-verified-bot".to_string(), "crawler".to_string())];
    assert_eq!(bot.seen("example.test", &claimed, &tls).await, None);
    let lookalike = [("x_verified_bot".to_string(), "crawler".to_string())];
    let borrowed: Vec<(&str, &str)> = lookalike.iter().map(|(n, v)| (n.as_str(), v.as_str())).collect();
    let mut parts = request("example.test", "/", &borrowed);
    let client = Client {
        ip: tls.remote.ip(),
        conn: &tls,
        at: At::Routes,
    };
    bot.auth.check(&mut parts, client).await;
    assert!(parts.headers.get("x_verified_bot").is_none());

    let now = unix_now();
    let with = |times: String, tag: &str| format!("{times};keyid=\"{}\";tag=\"{tag}\"", bot.keyid);
    for (what, covered, parameters, agent) in [
        (
            "expired",
            COVERED,
            with(format!(";created={};expires={}", now - 900, now - 600), TAG),
            Some(AGENT),
        ),
        (
            "not yet valid",
            COVERED,
            with(format!(";created={};expires={}", now + 600, now + 900), TAG),
            Some(AGENT),
        ),
        (
            "valid for too long",
            COVERED,
            with(format!(";created={now};expires={}", now + 3 * 86_400), TAG),
            Some(AGENT),
        ),
        (
            "without expires",
            COVERED,
            with(format!(";created={now}"), TAG),
            Some(AGENT),
        ),
        (
            "another tag",
            COVERED,
            with(format!(";created={now};expires={}", now + 300), "other"),
            Some(AGENT),
        ),
        ("the host not covered", "\"@method\"", bot.parameters(), None),
        ("the agent not covered", "\"@authority\"", bot.parameters(), Some(AGENT)),
        (
            "a component not filled in",
            "\"@authority\" \"@status\"",
            bot.parameters(),
            None,
        ),
    ] {
        let headers = bot.sign("example.test", covered, &parameters, agent);
        assert_eq!(bot.seen("example.test", &headers, &tls).await, None, "{what}");
    }
    // A key no named agent has.
    let stranger = Bot::new();
    let foreign = stranger.sign("example.test", COVERED, &stranger.parameters(), Some(AGENT));
    assert_eq!(bot.seen("example.test", &foreign, &tls).await, None);
    // The signature of another request.
    let mut swapped = signed.clone();
    let other = bot.sign("example.test", "\"@authority\"", &bot.parameters(), None);
    swapped.retain(|(name, _)| name != "signature");
    swapped.push(other.into_iter().find(|(name, _)| name == "signature").unwrap());
    assert_eq!(bot.seen("example.test", &swapped, &tls).await, None);
    // Over a connection anyone on the way could read.
    assert_eq!(bot.seen("example.test", &signed, &conn(false, false)).await, None);
}

#[test]
fn what_the_file_may_say() {
    let keys = jwks_of(&[(&Signer::ed(), "k1")]);
    let load = |text: &str| BotAuth::from_yaml(text, Path::new(".")).map_err(|e| format!("{e:#}"));
    let named = load(&format!(
        "header: X-Bot\nmax_validity: 1h\nclock_skew: 10s\nagents:\n  a:\n    directory: https://agent.example\n  b:\n    directory: https://agent.example/keys/directory.json\n    cache_duration: 10m\n  c:\n    jwks: '{keys}'\n"
    ))
    .unwrap();
    assert_eq!((named.count(), named.header().as_str()), (3, "x-bot"));
    assert_eq!(named.agents[0].host.as_deref(), Some("agent.example"));
    let uri = |i: usize| match &named.agents[i].keys.source {
        jwks::Source::Uri(uri) => uri.to_string(),
        _ => String::new(),
    };
    assert_eq!(
        uri(0),
        "https://agent.example/.well-known/http-message-signatures-directory"
    );
    assert_eq!(uri(1), "https://agent.example/keys/directory.json");
    for (text, says) in [
        ("agents: {}\n".to_string(), "none named"),
        ("agents:\n  a: {}\n".to_string(), "one of directory, jwks, jwks_file"),
        (
            "agents:\n  a:\n    directory: agent.example\n".to_string(),
            "an https URL",
        ),
        (
            "agents:\n  a:\n    jwks: '{\"keys\":[]}'\n".to_string(),
            "no usable signing key",
        ),
        (
            format!("header: \"not a name\"\nagents:\n  a:\n    jwks: '{keys}'\n"),
            "is not a header name",
        ),
        (
            format!("agents:\n  a:\n    jwks: '{keys}'\n    unknown: 1\n"),
            "unknown",
        ),
    ] {
        let error = load(&text).err().unwrap_or_default();
        assert!(error.contains(says), "{text}: {error}");
    }
}
