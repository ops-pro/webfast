//! TLS session tickets whose keys come from a shared seed (WEB_TLS_TICKET_SEED or
//! WEB_TLS_TICKET_SEED_FILE): every replica given the same seed makes and accepts the same tickets,
//! with no cache to share, and so does the process after a restart. A client resumes wherever it
//! lands, without a new certificate signature.
//!
//! The keys roll by the wall clock: one per `PERIOD`, derived from the seed with HKDF-SHA256, so
//! replicas agree on them as far as their clocks agree. A ticket is sealed with AES-256-GCM under a
//! key of its own, derived from the period's key and 16 random bytes it carries; no two tickets
//! share a key, however many replicas make them, so a nonce is never reused. Tickets of the
//! period before and after the current one are accepted too (clock skew, and a ticket made just
//! before the period changed). A period's keys are not kept anywhere: they are derived again
//! when needed, and past the window no ticket of theirs opens.
//!
//! What the seed gives away, if it leaks: whoever holds it can open the tickets of every replica,
//! and so take the resumption secret of a session (TLS 1.3: the traffic of a resumed session
//! stays protected by its fresh key exchange, as rustls resumes with psk_dhe_ke only; TLS 1.2
//! resumption has none). It is a secret like a private key, and changing it ends resumption with
//! the old tickets.

use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use aws_lc_rs::hkdf::{HKDF_SHA256, Prk, Salt};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// How long a key makes tickets; a ticket opens until the end of the next period.
pub const PERIOD: Duration = Duration::from_secs(6 * 60 * 60);

/// The shortest seed taken: 32 bytes, the strength of the keys made from it.
pub const MIN_SEED: usize = 32;

const VERSION: u8 = 1;
/// Version, period, salt: authenticated as the AEAD's additional data.
const HEADER: usize = 1 + 8 + SALT;
const SALT: usize = 16;
const TAG: usize = 16;

/// The ticket keys of a seed.
pub struct TicketKeys {
    seed: Prk,
}

impl std::fmt::Debug for TicketKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Nothing of the seed.
        f.write_str("TicketKeys")
    }
}

impl TicketKeys {
    /// The keys of `seed` (at least `MIN_SEED` bytes).
    pub fn new(seed: &[u8]) -> Result<TicketKeys, String> {
        if seed.len() < MIN_SEED {
            return Err(format!(
                "the ticket seed has {} bytes, at least {MIN_SEED} are needed",
                seed.len()
            ));
        }
        let seed = Salt::new(HKDF_SHA256, b"webfast tls ticket seed v1").extract(seed);
        Ok(TicketKeys { seed })
    }

    fn period_now() -> u64 {
        let since = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
        since.as_secs() / PERIOD.as_secs()
    }

    /// The key of one ticket: from the period's key and the ticket's salt.
    fn key(&self, period: u64, salt: &[u8]) -> Option<LessSafeKey> {
        let period = period.to_be_bytes();
        let mut period_key = [0u8; 32];
        self.seed
            .expand(&[b"period", &period], HKDF_SHA256)
            .ok()?
            .fill(&mut period_key)
            .ok()?;
        let period_key = Prk::new_less_safe(HKDF_SHA256, &period_key);
        let info: [&[u8]; 2] = [b"ticket", salt];
        let okm = period_key.expand(&info, &AES_256_GCM).ok()?;
        Some(LessSafeKey::new(UnboundKey::from(okm)))
    }

    fn seal(&self, period: u64, plain: &[u8]) -> Option<Vec<u8>> {
        let mut ticket = Vec::with_capacity(HEADER + plain.len() + TAG);
        ticket.push(VERSION);
        ticket.extend_from_slice(&period.to_be_bytes());
        let mut salt = [0u8; SALT];
        aws_lc_rs::rand::fill(&mut salt).ok()?;
        ticket.extend_from_slice(&salt);
        let key = self.key(period, &salt)?;
        let mut body = plain.to_vec();
        // The key is the ticket's own: a fixed nonce is used once.
        let tag = key
            .seal_in_place_separate_tag(
                Nonce::assume_unique_for_key([0; 12]),
                Aad::from(&ticket[..HEADER]),
                &mut body,
            )
            .ok()?;
        ticket.extend_from_slice(&body);
        ticket.extend_from_slice(tag.as_ref());
        Some(ticket)
    }

    fn open(&self, now: u64, ticket: &[u8]) -> Option<Vec<u8>> {
        if ticket.len() < HEADER + TAG || ticket[0] != VERSION {
            return None;
        }
        let period = u64::from_be_bytes(ticket[1..9].try_into().ok()?);
        // The period before, this one, and the next (a replica whose clock is a little ahead).
        if period.abs_diff(now) > 1 {
            return None;
        }
        let key = self.key(period, &ticket[9..HEADER])?;
        let mut body = ticket[HEADER..].to_vec();
        let plain = key
            .open_in_place(
                Nonce::assume_unique_for_key([0; 12]),
                Aad::from(&ticket[..HEADER]),
                &mut body,
            )
            .ok()?
            .len();
        body.truncate(plain);
        Some(body)
    }
}

impl rustls::server::ProducesTickets for TicketKeys {
    fn enabled(&self) -> bool {
        true
    }

    fn lifetime(&self) -> u32 {
        PERIOD.as_secs() as u32
    }

    fn encrypt(&self, plain: &[u8]) -> Option<Vec<u8>> {
        self.seal(TicketKeys::period_now(), plain)
    }

    fn decrypt(&self, cipher: &[u8]) -> Option<Vec<u8>> {
        self.open(TicketKeys::period_now(), cipher)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: &[u8] = b"0123456789abcdef0123456789abcdef";

    #[test]
    fn replicas_with_one_seed_open_each_others_tickets() {
        let (a, b) = (TicketKeys::new(SEED).unwrap(), TicketKeys::new(SEED).unwrap());
        let other = TicketKeys::new(b"another seed of thirty-two bytes!").unwrap();
        let plain = b"the session state".to_vec();
        let ticket = a.seal(100, &plain).unwrap();
        assert_eq!(b.open(100, &ticket).unwrap(), plain);
        assert_eq!(b.open(101, &ticket).unwrap(), plain, "in the next period");
        assert_eq!(b.open(99, &ticket).unwrap(), plain, "a replica a little behind");
        assert!(b.open(102, &ticket).is_none(), "past the window");
        assert!(other.open(100, &ticket).is_none(), "another seed");
        // Two tickets of the same state differ (each its own salt and key).
        assert_ne!(a.seal(100, &plain).unwrap(), ticket);
        // Any change to the ticket, its period included, and it does not open.
        for at in [0, 5, 9, 20, ticket.len() - 1] {
            let mut bad = ticket.clone();
            bad[at] ^= 1;
            assert!(b.open(100, &bad).is_none(), "byte {at}");
        }
        assert!(b.open(100, &ticket[..HEADER + TAG - 1]).is_none());
        assert!(b.open(100, &[]).is_none());
        assert!(TicketKeys::new(&SEED[..31]).is_err());
    }
}
