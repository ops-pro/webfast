//! Compressed variants of the site files that have no precompressed sibling (cargo feature
//! `compress-files`). `file_server` with `precompressed` sends a file's `.br`, `.zst` or `.gz` when
//! there is one; for a compressible file without one, the first requests that would take it are
//! answered as before (by `encode` on the fly, or as the file is) and ask for the variant here. A
//! thread of its own, at a lower priority, makes it at the encoding's highest level and keeps it as
//! a file entry with an ETag of its own, so conditional requests and ranges work as for a sibling;
//! then the ready answers of the sites reading the file are worked out again (a batch at a time),
//! and the next requests get the variant from them.
//!
//! What the variants take is bounded by WEB_COMPRESSED_FILES_MEMORY (64 MiB; `off`: none are
//! made), apart from the files' own WEB_MAX_MEMORY: the files are needed, the variants are not.
//! Past it, the variants not asked for since the eviction last passed go first (CLOCK,
//! src/background.rs `Budget`). A variant goes when its file does (changed, removed, a root a
//! reload dropped). Its memory is free once the ready answers holding it are worked out again and
//! the responses sending it have ended.
//!
//! Nothing is made while ready answers are prepared: a startup or a rescan compresses nothing by
//! itself, only what is asked for is.

use crate::background::{Budget, Seen, Worker};
use crate::encode::{Encoding, compress_best};
use crate::extensions::Lookup;
use crate::files::{FileEntry, FileStore};
use rustc_hash::{FxHashMap, FxHashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock, Mutex, PoisonError, RwLock, Weak};
use std::time::{Duration, Instant};

/// The default of WEB_COMPRESSED_FILES_MEMORY.
pub const DEFAULT_MEMORY: usize = 64 << 20;
static MAX_MEMORY: AtomicUsize = AtomicUsize::new(DEFAULT_MEMORY);
/// Smaller files are not worth a variant (`encode`'s minimum_length).
const MIN_SIZE: usize = 512;
/// Larger files are left to `encode` (Brotli 11 on more would hold the thread for seconds).
const MAX_SIZE: usize = 8 << 20;
/// Files waiting for the thread; more are not taken (and asked for again by a later request).
const QUEUE: usize = 256;
/// The ready answers are worked out again at most this often while variants come and go.
const REFRESH_EVERY: Duration = Duration::from_secs(2);
/// Variants of files gone are dropped, and a summary logged, this often.
const SWEEP_EVERY: Duration = Duration::from_secs(60);

/// WEB_COMPRESSED_FILES_MEMORY: a size (`64MiB`), or `off`.
pub fn configure_from_env() -> Result<(), String> {
    if let Ok(value) = std::env::var("WEB_COMPRESSED_FILES_MEMORY") {
        let bytes = if value.trim().eq_ignore_ascii_case("off") {
            0
        } else {
            crate::parse_size(&value)
                .ok_or_else(|| format!("WEB_COMPRESSED_FILES_MEMORY: a size (e.g. 64MiB) or off, not {value:?}"))?
        };
        set_max_memory(usize::try_from(bytes).unwrap_or(usize::MAX));
    }
    Ok(())
}

/// What the variants may take (0: none are made); tests and WEB_COMPRESSED_FILES_MEMORY.
pub fn set_max_memory(bytes: usize) {
    MAX_MEMORY.store(bytes, Ordering::Relaxed);
}

/// A file (by its ETag, the hash of its content: 80 bits) in an encoding.
type Key = (u128, Encoding);

fn key_of(entry: &FileEntry, encoding: Encoding) -> Option<Key> {
    let etag = entry.etag.to_str().ok()?;
    let hex = etag.strip_prefix('"')?.strip_suffix('"')?;
    Some((u128::from_str_radix(hex, 16).ok()?, encoding))
}

struct Slot {
    variant: Arc<FileEntry>,
    touched: Arc<AtomicBool>,
    /// The file it was made from: gone, the variant goes too.
    source: Weak<FileEntry>,
    /// Where the file is, for its sites' ready answers.
    store: Weak<FileStore>,
    size: usize,
}

/// The variants kept, and their budget (the CLOCK order and what they take).
#[derive(Default)]
struct Variants {
    slots: FxHashMap<Key, Slot>,
    budget: Budget<Key>,
}

static VARIANTS: LazyLock<RwLock<Variants>> = LazyLock::new(Default::default);
/// Asked for and not made yet.
static PENDING: LazyLock<Mutex<FxHashSet<Key>>> = LazyLock::new(Default::default);
/// Made and found not worth keeping (they save less than a tenth): not asked for again.
static USELESS: LazyLock<Mutex<FxHashSet<Key>>> = LazyLock::new(Default::default);
/// The stores whose variants came or went since the ready answers were last worked out again.
static CHANGED: Mutex<Vec<Weak<FileStore>>> = Mutex::new(Vec::new());

static MADE: AtomicU64 = AtomicU64::new(0);
static EVICTED: AtomicU64 = AtomicU64::new(0);

/// What the server does when variants were added or dropped: work out again the ready answers of
/// the sites reading these stores (src/server.rs sets it).
pub type OnChange = Arc<dyn Fn(&[Arc<FileStore>]) + Send + Sync>;
static ON_CHANGE: Mutex<Option<OnChange>> = Mutex::new(None);

pub fn on_change(callback: OnChange) {
    *ON_CHANGE.lock().unwrap_or_else(PoisonError::into_inner) = Some(callback);
}

/// Whether `entry` may get variants at all.
fn eligible(entry: &FileEntry) -> bool {
    let max = MAX_MEMORY.load(Ordering::Relaxed);
    entry.compressible && entry.on_disk().is_none() && (MIN_SIZE..=MAX_SIZE.min(max / 8)).contains(&entry.len())
}

pub fn lookup(entry: &FileEntry, encoding: Encoding) -> Lookup {
    if !eligible(entry) {
        return Lookup::No;
    }
    let Some(key) = key_of(entry, encoding) else {
        return Lookup::No;
    };
    if let Some(slot) = VARIANTS.read().unwrap_or_else(PoisonError::into_inner).slots.get(&key) {
        slot.touched.store(true, Ordering::Relaxed);
        return Lookup::Have(slot.variant.clone());
    }
    if USELESS.lock().unwrap_or_else(PoisonError::into_inner).contains(&key) {
        return Lookup::No;
    }
    Lookup::Missing
}

/// One file to compress.
struct Job {
    source: Arc<FileEntry>,
    store: Weak<FileStore>,
    encodings: Vec<Encoding>,
}

/// The worker (src/background.rs): makes the variants asked for, at a lower priority; every
/// quarter second it works out the ready answers again when variants came or went (at most every
/// REFRESH_EVERY), and once a minute drops the variants of files gone and logs a summary.
static WORKER: LazyLock<Worker<Job>> = LazyLock::new(|| {
    let mut refreshed = Instant::now();
    let mut swept = Instant::now();
    let mut logged = (0, 0);
    Worker::start(
        "webfast-compress",
        QUEUE,
        10,
        Duration::from_millis(250),
        |job| async move { make(job) },
        move |dropped| {
            if swept.elapsed() >= SWEEP_EVERY {
                sweep();
                swept = Instant::now();
                let now = (MADE.load(Ordering::Relaxed), EVICTED.load(Ordering::Relaxed));
                if now != logged || dropped > 0 {
                    let (variants, used) = stored();
                    tracing::info!(
                        variants,
                        memory_kib = used / 1024,
                        made = now.0 - logged.0,
                        evicted = now.1 - logged.1,
                        not_queued = dropped,
                        "compressed variants of the site files"
                    );
                }
                logged = now;
            }
            if refreshed.elapsed() >= REFRESH_EVERY {
                refresh();
                refreshed = Instant::now();
            }
        },
    )
});

/// Asks for `entry`'s variants in `encodings` (those `lookup` found missing): queued once, made in
/// the background. A full queue takes nothing (a later request asks again).
pub fn wanted(entry: &Arc<FileEntry>, store: &Arc<FileStore>, encodings: &[Encoding]) {
    let mut pending = PENDING.lock().unwrap_or_else(PoisonError::into_inner);
    let fresh: Vec<Encoding> = encodings
        .iter()
        .copied()
        .filter(|&e| key_of(entry, e).is_some_and(|key| pending.insert(key)))
        .collect();
    drop(pending);
    if fresh.is_empty() {
        return;
    }
    let job = Job {
        source: entry.clone(),
        store: Arc::downgrade(store),
        encodings: fresh,
    };
    if let Err(job) = WORKER.submit(job) {
        let mut pending = PENDING.lock().unwrap_or_else(PoisonError::into_inner);
        for &encoding in &job.encodings {
            if let Some(key) = key_of(&job.source, encoding) {
                pending.remove(&key);
            }
        }
    }
}

/// The variants kept and what they take (for the log, tests and diagnostics).
pub fn stored() -> (usize, usize) {
    let variants = VARIANTS.read().unwrap_or_else(PoisonError::into_inner);
    (variants.slots.len(), variants.budget.used())
}

fn make(job: Job) {
    let body = job.source.body();
    for &encoding in &job.encodings {
        let Some(key) = key_of(&job.source, encoding) else {
            continue;
        };
        let max = MAX_MEMORY.load(Ordering::Relaxed);
        let made = if max == 0 {
            None
        } else {
            compress_best(encoding, &body).ok()
        };
        match made {
            // Kept when it saves at least a tenth and fits.
            Some(compressed) if compressed.len() * 10 <= body.len() * 9 && compressed.len() <= max => {
                let touched = Arc::new(AtomicBool::new(true));
                let size = compressed.len();
                let variant = Arc::new(FileEntry::variant(
                    compressed,
                    job.source.content_type.clone(),
                    touched.clone(),
                ));
                let mut variants = VARIANTS.write().unwrap_or_else(PoisonError::into_inner);
                let slot = Slot {
                    variant,
                    touched,
                    source: Arc::downgrade(&job.source),
                    store: job.store.clone(),
                    size,
                };
                if let Some(old) = variants.slots.insert(key, slot) {
                    variants.budget.release(old.size);
                }
                variants.budget.add(key, size);
                evict(&mut variants, max);
                drop(variants);
                MADE.fetch_add(1, Ordering::Relaxed);
                note(&job.store);
            }
            Some(_) => {
                let mut useless = USELESS.lock().unwrap_or_else(PoisonError::into_inner);
                if useless.len() >= 100_000 {
                    useless.clear();
                }
                useless.insert(key);
            }
            None => {}
        }
        PENDING.lock().unwrap_or_else(PoisonError::into_inner).remove(&key);
    }
}

/// The budget's CLOCK pass over the variants: past `max`, a variant asked for since the last pass
/// gets another round, the first that was not goes.
fn evict(variants: &mut Variants, max: usize) {
    let Variants { slots, budget } = variants;
    budget.evict(max, |key| match slots.get(key) {
        None => Seen::Gone,
        Some(slot) if slot.touched.swap(false, Ordering::Relaxed) => Seen::Marked,
        Some(_) => {
            let gone = slots.remove(key).expect("looked up just now");
            EVICTED.fetch_add(1, Ordering::Relaxed);
            note(&gone.store);
            Seen::Evicted(gone.size)
        }
    });
}

/// Drops the variants of files that are gone; past a lowered WEB_COMPRESSED_FILES_MEMORY, some
/// more.
fn sweep() {
    let mut variants = VARIANTS.write().unwrap_or_else(PoisonError::into_inner);
    let mut released = 0;
    let mut gone = Vec::new();
    variants.slots.retain(|_, slot| {
        let keep = slot.source.strong_count() > 0;
        if !keep {
            released += slot.size;
            gone.push(slot.store.clone());
        }
        keep
    });
    for store in &gone {
        note(store);
    }
    let Variants { slots, budget } = &mut *variants;
    budget.release(released);
    budget.retain(|key| slots.contains_key(key));
    let max = MAX_MEMORY.load(Ordering::Relaxed);
    evict(&mut variants, max);
}

/// A store whose variants changed: its sites' ready answers are worked out again (`refresh`).
fn note(store: &Weak<FileStore>) {
    if store.strong_count() == 0 {
        return;
    }
    let mut changed = CHANGED.lock().unwrap_or_else(PoisonError::into_inner);
    if !changed.iter().any(|s| s.ptr_eq(store)) {
        changed.push(store.clone());
    }
}

/// The ready answers of the sites reading the stores whose variants changed, worked out again.
fn refresh() {
    let stores: Vec<Arc<FileStore>> = std::mem::take(&mut *CHANGED.lock().unwrap_or_else(PoisonError::into_inner))
        .into_iter()
        .filter_map(|s| s.upgrade())
        .collect();
    if stores.is_empty() {
        return;
    }
    let callback = ON_CHANGE.lock().unwrap_or_else(PoisonError::into_inner).clone();
    if let Some(callback) = callback {
        callback(&stores);
        crate::release_free_memory();
    }
}

/// The variants as `file_server`'s hook (src/extensions.rs `Representation`; `Variants` is the store).
pub struct Hook;

impl crate::extensions::Representation for Hook {
    fn lookup(&self, file: &FileEntry, encoding: Encoding) -> Lookup {
        lookup(file, encoding)
    }

    fn wanted(&self, file: &Arc<FileEntry>, store: &Arc<FileStore>, encodings: &[Encoding]) {
        wanted(file, store, encodings);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn variants_of(sizes: &[usize]) -> Variants {
        let mut variants = Variants::default();
        for (i, &size) in sizes.iter().enumerate() {
            let touched = Arc::new(AtomicBool::new(false));
            let key = (i as u128, Encoding::Br);
            variants.slots.insert(
                key,
                Slot {
                    variant: Arc::new(FileEntry::variant(
                        bytes::Bytes::from(vec![0u8; size]),
                        None,
                        touched.clone(),
                    )),
                    touched,
                    source: Weak::new(),
                    store: Weak::new(),
                    size,
                },
            );
            variants.budget.add(key, size);
        }
        variants
    }

    #[test]
    fn the_variants_not_asked_for_go_first() {
        let mut variants = variants_of(&[100, 100, 100, 100]);
        // 1 and 3 were asked for since the last pass.
        for i in [1u128, 3] {
            variants.slots[&(i, Encoding::Br)]
                .touched
                .store(true, Ordering::Relaxed);
        }
        evict(&mut variants, 250);
        let mut kept: Vec<u128> = variants.slots.keys().map(|k| k.0).collect();
        kept.sort_unstable();
        assert_eq!(kept, [1, 3]);
        assert_eq!(variants.budget.used(), 200);
        // Their marks are spent: the next pass may take them.
        evict(&mut variants, 100);
        assert_eq!(variants.slots.len(), 1);
        assert_eq!(variants.budget.used(), 100);
    }

    #[test]
    fn a_variant_is_keyed_by_its_file_s_content() {
        let file = FileEntry::new("/app.js", b"let a = 1;".repeat(100), None);
        let key = key_of(&file, Encoding::Br).unwrap();
        let same = FileEntry::new("/other.js", b"let a = 1;".repeat(100), None);
        assert_eq!(key_of(&same, Encoding::Br), Some(key));
        assert_ne!(key_of(&same, Encoding::Gzip), Some(key));
        assert!(file.compressible && eligible(&file));
        let image = FileEntry::new("/photo.jpg", vec![7u8; 4096], None);
        assert!(!eligible(&image), "not a compressible type");
        assert!(!eligible(&FileEntry::new("/tiny.js", b"1".to_vec(), None)), "too small");
    }
}
