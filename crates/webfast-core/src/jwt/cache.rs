//! Verified tokens, kept so that a token seen again costs a hash and a lookup instead of base64,
//! JSON and a signature check. Keyed by the token's BLAKE3 hash (an attacker cannot aim tokens at
//! one bucket, and the token itself is not kept). Sharded by the hash, so the connection threads
//! rarely wait for each other; each shard keeps two generations — a lookup that finds an entry in
//! the older one moves it to the newer, and when the newer is full the older is dropped whole: an
//! LRU's behaviour without its list, O(1) for everything.

use rustc_hash::FxHashMap;
use std::sync::{Arc, Mutex, PoisonError};

pub(super) type Digest = [u8; 32];

pub(super) fn digest(token: &[u8]) -> Digest {
    *blake3::hash(token).as_bytes()
}

const SHARDS: usize = 16;

pub(super) struct TokenCache<V> {
    shards: Box<[Mutex<Shard<V>>]>,
    /// Entries a shard's newer generation holds before it becomes the older one.
    per_generation: usize,
}

struct Shard<V> {
    current: FxHashMap<Digest, Arc<V>>,
    previous: FxHashMap<Digest, Arc<V>>,
}

impl<V> TokenCache<V> {
    /// Room for about `capacity` tokens (0: nothing is kept).
    pub(super) fn new(capacity: usize) -> TokenCache<V> {
        let shards = if capacity == 0 { 0 } else { SHARDS };
        TokenCache {
            shards: (0..shards)
                .map(|_| {
                    Mutex::new(Shard {
                        current: FxHashMap::default(),
                        previous: FxHashMap::default(),
                    })
                })
                .collect(),
            per_generation: (capacity / (2 * SHARDS)).max(1),
        }
    }

    fn shard(&self, key: &Digest) -> Option<&Mutex<Shard<V>>> {
        if self.shards.is_empty() {
            return None;
        }
        Some(&self.shards[usize::from(key[0]) % self.shards.len()])
    }

    pub(super) fn get(&self, key: &Digest) -> Option<Arc<V>> {
        let mut shard = self.shard(key)?.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(value) = shard.current.get(key) {
            return Some(value.clone());
        }
        let value = shard.previous.remove(key)?;
        shard.put(*key, value.clone(), self.per_generation);
        Some(value)
    }

    pub(super) fn insert(&self, key: Digest, value: Arc<V>) {
        if let Some(shard) = self.shard(&key) {
            shard
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .put(key, value, self.per_generation);
        }
    }
}

impl<V> Shard<V> {
    fn put(&mut self, key: Digest, value: Arc<V>, per_generation: usize) {
        if self.current.len() >= per_generation {
            self.previous = std::mem::take(&mut self.current);
        }
        self.current.insert(key, value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_recent_tokens_and_forgets_old_ones() {
        let cache: TokenCache<u32> = TokenCache::new(64);
        // Keys of one shard (same first byte), to see the generations at work.
        let key = |i: u8| {
            let mut k = [0u8; 32];
            k[1] = i;
            k
        };
        for i in 0..2 {
            cache.insert(key(i), Arc::new(u32::from(i)));
        }
        assert_eq!(cache.get(&key(0)).as_deref(), Some(&0));
        // Two entries per generation here: the third moves the first two to the older one…
        cache.insert(key(2), Arc::new(2));
        assert_eq!(cache.get(&key(1)).as_deref(), Some(&1), "found in the older generation");
        // …and two more drop what was not looked at since.
        cache.insert(key(3), Arc::new(3));
        cache.insert(key(4), Arc::new(4));
        assert!(cache.get(&key(0)).is_none());
        assert_eq!(cache.get(&key(4)).as_deref(), Some(&4));
        let none: TokenCache<u32> = TokenCache::new(0);
        none.insert(key(1), Arc::new(1));
        assert!(none.get(&key(1)).is_none(), "capacity 0: nothing kept");
        assert_ne!(digest(b"a.b.c"), digest(b"a.b.d"));
    }
}
