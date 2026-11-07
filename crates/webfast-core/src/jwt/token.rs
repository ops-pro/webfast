//! A compact JWS (RFC 7515) taken apart: header, claims, the signed bytes and the signature.
//! Nothing here trusts the token: the signature is checked against the issuer's keys afterwards.

use super::jwks::Alg;
use serde::Deserialize;
use serde_json::{Map, Value};

pub(super) struct Parsed<'a> {
    /// `None`: an algorithm this server does not accept (`none`, HMAC, …).
    pub alg: Option<Alg>,
    pub kid: Option<String>,
    pub claims: Map<String, Value>,
    /// `<header>.<payload>` as sent: what the signature covers.
    pub signing_input: &'a [u8],
    pub signature: Vec<u8>,
    /// The payload as sent (base64url), passed on as it is (`output_payload_to_header`).
    pub payload: &'a str,
}

#[derive(Deserialize)]
struct Header {
    alg: String,
    kid: Option<String>,
    /// Extensions the verifier must understand (RFC 7515 §4.1.11): none are, so any is refused.
    crit: Option<Value>,
}

impl<'a> Parsed<'a> {
    /// `None` when the token is not a well-formed JWS with a JSON object as its payload.
    pub fn new(token: &'a str) -> Option<Parsed<'a>> {
        let mut parts = token.split('.');
        let (header, payload, signature) = (parts.next()?, parts.next()?, parts.next()?);
        if parts.next().is_some() {
            return None;
        }
        let head: Header = serde_json::from_slice(&decode(header)?).ok()?;
        if head.crit.is_some() {
            return None;
        }
        let claims = match serde_json::from_slice(&decode(payload)?).ok()? {
            Value::Object(claims) => claims,
            _ => return None,
        };
        Some(Parsed {
            alg: Alg::from_name(&head.alg),
            kid: head.kid,
            claims,
            signing_input: &token.as_bytes()[..header.len() + 1 + payload.len()],
            signature: decode(signature)?,
            payload,
        })
    }
}

/// base64url without padding (RFC 7515 §2); `None` for anything else.
pub(super) fn decode(text: &str) -> Option<Vec<u8>> {
    fn value(c: u8) -> Option<u32> {
        Some(u32::from(match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return None,
        }))
    }
    let bytes = text.as_bytes();
    if bytes.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    for chunk in bytes.chunks(4) {
        let mut n = 0u32;
        for (i, &c) in chunk.iter().enumerate() {
            n |= value(c)? << (18 - 6 * i);
        }
        let produced = chunk.len() - 1;
        out.extend_from_slice(&n.to_be_bytes()[1..1 + produced]);
    }
    Some(out)
}

/// base64url without padding.
#[cfg(test)]
pub(super) fn encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let mut n = 0u32;
        for (i, &b) in chunk.iter().enumerate() {
            n |= u32::from(b) << (16 - 8 * i);
        }
        for i in 0..=chunk.len() {
            out.push(char::from(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize]));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64url_round_trips_and_refuses_what_is_not() {
        for len in 0..40 {
            let bytes: Vec<u8> = (0..len).map(|i| (i * 37 + 11) as u8).collect();
            assert_eq!(decode(&encode(&bytes)).unwrap(), bytes, "{len}");
        }
        assert_eq!(decode("aGVsbG8").unwrap(), b"hello");
        assert!(decode("aGVsbG8=").is_none(), "padding");
        assert!(decode("aGV+bG8").is_none(), "standard alphabet");
        assert!(decode("a").is_none(), "a lone character is no byte");
    }

    #[test]
    fn tokens_are_taken_apart() {
        let header = encode(br#"{"alg":"ES256","kid":"k1","typ":"JWT"}"#);
        let payload = encode(br#"{"iss":"https://id.test","sub":"u1"}"#);
        let token = format!("{header}.{payload}.{}", encode(b"sig"));
        let parsed = Parsed::new(&token).unwrap();
        assert_eq!(parsed.alg, Some(Alg::Es256));
        assert_eq!(parsed.kid.as_deref(), Some("k1"));
        assert_eq!(parsed.claims["sub"], "u1");
        assert_eq!(parsed.signing_input, format!("{header}.{payload}").as_bytes());
        assert_eq!(parsed.signature, b"sig");
        assert_eq!(parsed.payload, payload);

        let none = format!("{}.{payload}.", encode(br#"{"alg":"none"}"#));
        assert_eq!(Parsed::new(&none).unwrap().alg, None, "alg none is not accepted");
        let hmac = format!("{}.{payload}.AA", encode(br#"{"alg":"HS256"}"#));
        assert_eq!(Parsed::new(&hmac).unwrap().alg, None);
        let crit = format!("{}.{payload}.AA", encode(br#"{"alg":"ES256","crit":["b64"]}"#));
        assert!(Parsed::new(&crit).is_none());
        assert!(Parsed::new(&format!("{header}.{payload}")).is_none(), "two parts");
        assert!(Parsed::new(&format!("{header}.{payload}.a.b.c")).is_none(), "JWE");
        let array = format!("{header}.{}.x", encode(b"[1]"));
        assert!(Parsed::new(&array).is_none(), "claims must be an object");
    }
}
