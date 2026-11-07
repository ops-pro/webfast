//! An issuer's signing keys (JWKS, RFC 7517): parsed once into aws-lc-rs keys ready to verify, so a
//! signature check does no key parsing. Loaded from `jwks` (inline), `jwks_file` or `jwks_uri`,
//! the last two read again every `jwks_cache_duration` in the background; a token signed with a
//! key not known yet (the issuer rotated its keys) asks for an early read — at most one every
//! `MIN_REFETCH`, so made-up key ids cannot make the server hammer the issuer.

use anyhow::{Context, Result, anyhow, bail};
use arc_swap::ArcSwap;
use aws_lc_rs::signature::{self, ParsedPublicKey, UnparsedPublicKey, VerificationAlgorithm};
use bytes::Bytes;
use serde::Deserialize;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{Notify, watch};

/// Signature algorithms accepted (RFC 7518 §3; Ed25519: RFC 8037). No `none`, no HMAC: a shared
/// secret has no place at the edge, and refusing it rules out algorithm confusion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Alg {
    Rs256,
    Rs384,
    Rs512,
    Ps256,
    Ps384,
    Ps512,
    Es256,
    Es384,
    EdDsa,
}

const RSA_ALGS: [Alg; 6] = [Alg::Rs256, Alg::Rs384, Alg::Rs512, Alg::Ps256, Alg::Ps384, Alg::Ps512];

impl Alg {
    pub fn from_name(name: &str) -> Option<Alg> {
        Some(match name {
            "RS256" => Alg::Rs256,
            "RS384" => Alg::Rs384,
            "RS512" => Alg::Rs512,
            "PS256" => Alg::Ps256,
            "PS384" => Alg::Ps384,
            "PS512" => Alg::Ps512,
            "ES256" => Alg::Es256,
            "ES384" => Alg::Es384,
            "EdDSA" => Alg::EdDsa,
            _ => return None,
        })
    }

    /// RSA keys of 2048 bits or more; ECDSA signatures as JWS sends them (r ‖ s).
    fn algorithm(self) -> &'static dyn VerificationAlgorithm {
        match self {
            Alg::Rs256 => &signature::RSA_PKCS1_2048_8192_SHA256,
            Alg::Rs384 => &signature::RSA_PKCS1_2048_8192_SHA384,
            Alg::Rs512 => &signature::RSA_PKCS1_2048_8192_SHA512,
            Alg::Ps256 => &signature::RSA_PSS_2048_8192_SHA256,
            Alg::Ps384 => &signature::RSA_PSS_2048_8192_SHA384,
            Alg::Ps512 => &signature::RSA_PSS_2048_8192_SHA512,
            Alg::Es256 => &signature::ECDSA_P256_SHA256_FIXED,
            Alg::Es384 => &signature::ECDSA_P384_SHA384_FIXED,
            Alg::EdDsa => &signature::ED25519,
        }
    }
}

/// One key, ready to verify with each algorithm it may sign with.
struct Key {
    kid: Option<String>,
    verifiers: Vec<(Alg, ParsedPublicKey)>,
}

/// An issuer's keys at one moment.
#[derive(Default)]
pub struct KeySet {
    keys: Vec<Key>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Checked {
    Valid,
    /// No key with the token's id (or, without one, none for its algorithm).
    NoKey,
    BadSignature,
}

#[derive(Deserialize)]
struct Jwks {
    keys: Vec<Jwk>,
}

#[derive(Deserialize)]
struct Jwk {
    kty: String,
    kid: Option<String>,
    alg: Option<String>,
    #[serde(rename = "use")]
    usage: Option<String>,
    crv: Option<String>,
    n: Option<String>,
    e: Option<String>,
    x: Option<String>,
    y: Option<String>,
}

impl KeySet {
    /// A JWKS document; keys this server cannot use (encryption keys, HMAC secrets, other curves,
    /// RSA under 2048 bits) are skipped, but at least one must be usable.
    pub fn parse(json: &[u8]) -> Result<KeySet> {
        let jwks: Jwks = serde_json::from_slice(json).context("not a JWKS document")?;
        let mut keys = Vec::new();
        let mut skipped = Vec::new();
        for jwk in jwks.keys {
            let id = jwk.kid.clone().unwrap_or_default();
            match Key::from_jwk(jwk) {
                Ok(key) => keys.push(key),
                Err(e) => skipped.push(format!("{id:?}: {e}")),
            }
        }
        if !skipped.is_empty() {
            tracing::debug!(skipped = ?skipped, "JWKS keys skipped");
        }
        if keys.is_empty() {
            bail!("no usable signing key in the JWKS ({})", skipped.join("; "));
        }
        Ok(KeySet { keys })
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Verifies `signature` over `input` with the keys that may have made it: the token's key id,
    /// or — without one — every key for its algorithm.
    pub(super) fn verify(&self, kid: Option<&str>, alg: Alg, input: &[u8], signature: &[u8]) -> Checked {
        let mut tried = false;
        for key in &self.keys {
            if kid.is_some() && key.kid.as_deref() != kid {
                continue;
            }
            for (key_alg, verifier) in &key.verifiers {
                if *key_alg != alg {
                    continue;
                }
                tried = true;
                if verifier.verify_sig(input, signature).is_ok() {
                    return Checked::Valid;
                }
            }
        }
        if tried { Checked::BadSignature } else { Checked::NoKey }
    }
}

impl Key {
    fn from_jwk(jwk: Jwk) -> Result<Key> {
        if jwk.usage.as_deref().is_some_and(|u| u != "sig") {
            bail!("not a signing key (use {:?})", jwk.usage);
        }
        let declared = match &jwk.alg {
            Some(name) => Some(Alg::from_name(name).ok_or_else(|| anyhow!("algorithm {name} not accepted"))?),
            None => None,
        };
        let field = |value: &Option<String>, name: &str| -> Result<Vec<u8>> {
            let text = value.as_deref().ok_or_else(|| anyhow!("no {name}"))?;
            super::token::decode(text).ok_or_else(|| anyhow!("{name} is not base64url"))
        };
        let (algs, bytes): (Vec<Alg>, Vec<u8>) = match (jwk.kty.as_str(), jwk.crv.as_deref()) {
            ("RSA", _) => {
                let n = field(&jwk.n, "n")?;
                let significant = n.iter().skip_while(|b| **b == 0).count();
                if significant < 256 {
                    bail!("RSA key of {} bits (2048 at least)", significant * 8);
                }
                (RSA_ALGS.to_vec(), rsa_public_key_der(&n, &field(&jwk.e, "e")?))
            }
            ("EC", Some(curve @ ("P-256" | "P-384"))) => {
                let (x, y) = (field(&jwk.x, "x")?, field(&jwk.y, "y")?);
                let size = if curve == "P-256" { 32 } else { 48 };
                if x.len() != size || y.len() != size {
                    bail!("{curve} coordinates of the wrong size");
                }
                let mut point = Vec::with_capacity(1 + 2 * size);
                point.push(4);
                point.extend_from_slice(&x);
                point.extend_from_slice(&y);
                let alg = if curve == "P-256" { Alg::Es256 } else { Alg::Es384 };
                (vec![alg], point)
            }
            ("OKP", Some("Ed25519")) => (vec![Alg::EdDsa], field(&jwk.x, "x")?),
            (kty, crv) => bail!("key type {kty} {} not accepted", crv.unwrap_or("")),
        };
        let algs: Vec<Alg> = match declared {
            Some(alg) if algs.contains(&alg) => vec![alg],
            Some(alg) => bail!("algorithm {alg:?} does not fit a {} key", jwk.kty),
            None => algs,
        };
        let mut verifiers = Vec::with_capacity(algs.len());
        for alg in algs {
            let parsed = UnparsedPublicKey::new(alg.algorithm(), &bytes)
                .parse()
                .map_err(|e| anyhow!("key rejected for {alg:?}: {e}"))?;
            verifiers.push((alg, parsed));
        }
        Ok(Key {
            kid: jwk.kid,
            verifiers,
        })
    }
}

/// `RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }` (RFC 8017), DER.
fn rsa_public_key_der(n: &[u8], e: &[u8]) -> Vec<u8> {
    fn length(out: &mut Vec<u8>, len: usize) {
        if len < 0x80 {
            out.push(len as u8);
        } else {
            let bytes = len.to_be_bytes();
            let skip = bytes.iter().take_while(|b| **b == 0).count();
            out.push(0x80 | (bytes.len() - skip) as u8);
            out.extend_from_slice(&bytes[skip..]);
        }
    }
    fn integer(value: &[u8]) -> Vec<u8> {
        let value = &value[value
            .iter()
            .take_while(|b| **b == 0)
            .count()
            .min(value.len().saturating_sub(1))..];
        let pad = value.first().is_some_and(|b| *b & 0x80 != 0);
        let mut out = vec![0x02];
        length(&mut out, value.len() + usize::from(pad));
        if pad {
            out.push(0);
        }
        out.extend_from_slice(value);
        out
    }
    let body = [integer(n), integer(e)].concat();
    let mut out = vec![0x30];
    length(&mut out, body.len());
    out.extend_from_slice(&body);
    out
}

/// Where an issuer's keys come from.
pub(super) enum Source {
    Inline,
    File(PathBuf),
    Uri(http::Uri),
}

/// The fewest seconds between two reads asked for by tokens with an unknown key id.
const MIN_REFETCH: Duration = Duration::from_secs(30);

/// A JWKS document is not expected to be larger.
const MAX_JWKS: usize = 1 << 20;

/// An issuer's keys, shared by the requests and the task that keeps them current.
pub(super) struct Keys {
    pub name: String,
    pub source: Source,
    set: ArcSwap<KeySet>,
    /// Changes when the keys do: verified tokens of an older generation are checked again.
    generation: AtomicU64,
    /// The document last read, to tell whether a read changed anything.
    digest: std::sync::Mutex<[u8; 32]>,
    /// Counts finished reads, for requests waiting for one.
    reads: watch::Sender<u64>,
    /// Asks the background task for an early read.
    wanted: Notify,
    /// Milliseconds since the Unix epoch of the last read asked for by a request.
    last_wanted: AtomicU64,
    pub cache_duration: Duration,
    pub fetch_timeout: Duration,
}

impl Keys {
    pub fn new(name: String, source: Source, set: KeySet, cache_duration: Duration, fetch_timeout: Duration) -> Keys {
        Keys {
            name,
            source,
            set: ArcSwap::from_pointee(set),
            generation: AtomicU64::new(1),
            digest: std::sync::Mutex::new([0; 32]),
            reads: watch::channel(0).0,
            wanted: Notify::new(),
            last_wanted: AtomicU64::new(0),
            cache_duration,
            fetch_timeout,
        }
    }

    pub fn current(&self) -> arc_swap::Guard<Arc<KeySet>> {
        self.set.load()
    }

    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    /// Whether the keys are read again while the server runs.
    pub fn refreshed(&self) -> bool {
        !matches!(self.source, Source::Inline)
    }

    /// For a token with a key not known: asks for an early read and waits for it (at most
    /// `fetch_timeout`) — unless one was asked for less than `MIN_REFETCH` ago; whether it did.
    pub async fn read_again(&self) -> bool {
        if !self.refreshed() {
            return false;
        }
        let now = unix_millis();
        let last = self.last_wanted.load(Ordering::Acquire);
        if now.saturating_sub(last) < MIN_REFETCH.as_millis() as u64
            || self
                .last_wanted
                .compare_exchange(last, now, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
        {
            return false;
        }
        let mut reads = self.reads.subscribe();
        reads.borrow_and_update();
        self.wanted.notify_one();
        tokio::time::timeout(self.fetch_timeout, reads.changed()).await.is_ok()
    }

    /// One read of the document; the keys are replaced when it changed.
    pub async fn load(&self, client: &Client) -> Result<()> {
        let result = async {
            let bytes = match &self.source {
                Source::Inline => return Ok(()),
                Source::File(path) => {
                    let path = path.clone();
                    tokio::task::spawn_blocking(move || std::fs::read(&path))
                        .await
                        .map_err(|e| anyhow!("{e}"))?
                        .context("reading the JWKS file")?
                }
                Source::Uri(uri) => fetch(client, uri, self.fetch_timeout).await?.to_vec(),
            };
            let digest = *blake3::hash(&bytes).as_bytes();
            if *self.digest.lock().unwrap_or_else(std::sync::PoisonError::into_inner) == digest {
                return Ok(());
            }
            let set = KeySet::parse(&bytes)?;
            tracing::info!(provider = %self.name, keys = set.len(), "JWT signing keys loaded");
            self.set.store(Arc::new(set));
            *self.digest.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = digest;
            self.generation.fetch_add(1, Ordering::AcqRel);
            Ok(())
        }
        .await;
        self.reads.send_modify(|n| *n += 1);
        result
    }
}

/// Keeps `keys` current: a read every `cache_duration`, after a failure again sooner (1 s,
/// doubling up to a minute), and early when a request asks.
pub(super) async fn refresh(keys: Arc<Keys>, client: Client) {
    let mut backoff = Duration::from_secs(1);
    loop {
        let wait = match keys.load(&client).await {
            Ok(()) => {
                backoff = Duration::from_secs(1);
                keys.cache_duration
            }
            Err(e) => {
                tracing::warn!(provider = %keys.name, error = %format!("{e:#}"), retry_secs = backoff.as_secs(), "cannot read the JWT signing keys");
                let wait = backoff;
                backoff = (backoff * 2).min(Duration::from_secs(60));
                wait
            }
        };
        tokio::select! {
            () = tokio::time::sleep(wait) => {}
            () = keys.wanted.notified() => {}
        }
    }
}

pub(super) use crate::fetch::{Client, client};

async fn fetch(client: &Client, uri: &http::Uri, timeout: Duration) -> Result<Bytes> {
    let mut headers = http::HeaderMap::new();
    headers.insert(http::header::ACCEPT, http::HeaderValue::from_static("application/json"));
    let fetched = crate::fetch::get(client, uri, &headers, MAX_JWKS, timeout).await?;
    if !fetched.status.is_success() {
        bail!("JWKS answered {}", fetched.status);
    }
    Ok(fetched.body)
}

fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use crate::jwt::token::encode;
    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::signature::{EcdsaKeyPair, Ed25519KeyPair, KeyPair, RsaKeyPair};

    /// A key that signs test tokens, and its JWK.
    pub enum Signer {
        Ec(EcdsaKeyPair),
        Rsa(RsaKeyPair),
        Ed(Ed25519KeyPair),
    }

    impl Signer {
        pub fn ec() -> Signer {
            Signer::Ec(EcdsaKeyPair::generate(&signature::ECDSA_P256_SHA256_FIXED_SIGNING).unwrap())
        }
        pub fn rsa() -> Signer {
            Signer::Rsa(RsaKeyPair::generate(aws_lc_rs::rsa::KeySize::Rsa2048).unwrap())
        }
        pub fn ed() -> Signer {
            Signer::Ed(Ed25519KeyPair::generate().unwrap())
        }

        pub fn alg(&self) -> &'static str {
            match self {
                Signer::Ec(_) => "ES256",
                Signer::Rsa(_) => "RS256",
                Signer::Ed(_) => "EdDSA",
            }
        }

        pub fn jwk(&self, kid: &str) -> serde_json::Value {
            match self {
                Signer::Ec(pair) => {
                    let point = pair.public_key().as_ref();
                    serde_json::json!({"kty": "EC", "crv": "P-256", "kid": kid, "use": "sig",
                        "x": encode(&point[1..33]), "y": encode(&point[33..65])})
                }
                Signer::Rsa(pair) => {
                    let key = pair.public_key();
                    serde_json::json!({"kty": "RSA", "kid": kid, "alg": "RS256",
                        "n": encode(key.modulus().big_endian_without_leading_zero()),
                        "e": encode(key.exponent().big_endian_without_leading_zero())})
                }
                Signer::Ed(pair) => {
                    serde_json::json!({"kty": "OKP", "crv": "Ed25519", "kid": kid,
                        "x": encode(pair.public_key().as_ref())})
                }
            }
        }

        /// A compact JWS of `claims` with this key, `kid` in its header.
        pub fn token(&self, kid: &str, claims: &serde_json::Value) -> String {
            let header = serde_json::json!({"alg": self.alg(), "kid": kid, "typ": "JWT"});
            let input = format!(
                "{}.{}",
                encode(header.to_string().as_bytes()),
                encode(claims.to_string().as_bytes())
            );
            let rng = SystemRandom::new();
            let signature = match self {
                Signer::Ec(pair) => pair.sign(&rng, input.as_bytes()).unwrap().as_ref().to_vec(),
                Signer::Rsa(pair) => {
                    let mut out = vec![0; pair.public_modulus_len()];
                    pair.sign(&signature::RSA_PKCS1_SHA256, &rng, input.as_bytes(), &mut out)
                        .unwrap();
                    out
                }
                Signer::Ed(pair) => pair.sign(input.as_bytes()).as_ref().to_vec(),
            };
            format!("{input}.{}", encode(&signature))
        }
    }

    pub fn jwks(keys: &[(&Signer, &str)]) -> String {
        let keys: Vec<serde_json::Value> = keys.iter().map(|(s, kid)| s.jwk(kid)).collect();
        serde_json::json!({ "keys": keys }).to_string()
    }

    #[test]
    fn keys_of_every_accepted_kind_verify_their_signatures() {
        let (ec, rsa, ed) = (Signer::ec(), Signer::rsa(), Signer::ed());
        let set = KeySet::parse(jwks(&[(&ec, "ec"), (&rsa, "rsa"), (&ed, "ed")]).as_bytes()).unwrap();
        assert_eq!(set.len(), 3);
        for (signer, kid, alg) in [
            (&ec, "ec", Alg::Es256),
            (&rsa, "rsa", Alg::Rs256),
            (&ed, "ed", Alg::EdDsa),
        ] {
            let token = signer.token(kid, &serde_json::json!({"iss": "x"}));
            let parsed = crate::jwt::token::Parsed::new(&token).unwrap();
            assert_eq!(parsed.alg, Some(alg));
            let check = |kid| set.verify(kid, alg, parsed.signing_input, &parsed.signature);
            assert_eq!(check(Some(kid)), Checked::Valid, "{kid}");
            assert_eq!(check(None), Checked::Valid, "{kid}: no key id, found by algorithm");
            assert_eq!(check(Some("other")), Checked::NoKey);
            let mut bad = parsed.signature.clone();
            bad[5] ^= 1;
            assert_eq!(
                set.verify(Some(kid), alg, parsed.signing_input, &bad),
                Checked::BadSignature
            );
        }
        // The RSA key declares RS256: a PS256 signature with it is not accepted.
        assert_eq!(set.verify(Some("rsa"), Alg::Ps256, b"x", b"y"), Checked::NoKey);
    }

    #[test]
    fn unusable_keys_are_skipped_and_an_empty_set_refused() {
        let ec = Signer::ec();
        let mixed = serde_json::json!({"keys": [
            {"kty": "oct", "k": "c2VjcmV0", "kid": "hmac"},
            {"kty": "EC", "crv": "P-256", "use": "enc", "x": "AA", "y": "AA"},
            ec.jwk("ok"),
        ]});
        assert_eq!(KeySet::parse(mixed.to_string().as_bytes()).unwrap().len(), 1);
        assert!(KeySet::parse(br#"{"keys":[{"kty":"oct","k":"c2VjcmV0"}]}"#).is_err());
        assert!(KeySet::parse(b"not json").is_err());
        // RSA under 2048 bits is refused.
        let small = serde_json::json!({"keys": [{"kty": "RSA", "n": encode(&[0xC5; 128]), "e": "AQAB"}]});
        assert!(KeySet::parse(small.to_string().as_bytes()).is_err());
    }

    #[test]
    fn rsa_public_keys_are_encoded_as_der() {
        // Leading zeros dropped, a high bit padded, short and long lengths.
        assert_eq!(
            rsa_public_key_der(&[0, 0x80], &[1, 0, 1]),
            [0x30, 0x09, 0x02, 0x02, 0x00, 0x80, 0x02, 0x03, 1, 0, 1]
        );
        let der = rsa_public_key_der(&[0xC0; 256], &[1, 0, 1]);
        assert_eq!(&der[..4], &[0x30, 0x82, 0x01, 0x0A]);
        assert_eq!(&der[4..8], &[0x02, 0x82, 0x01, 0x01]);
    }
}
