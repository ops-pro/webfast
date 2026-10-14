//! Site files held in memory: read once at startup, each with an ETag that is the hash of its
//! content, so the ETag changes exactly when the file does (and is the same on every replica).
//! Precompressed `.br` / `.zst` / `.gz` siblings are ordinary entries with their own ETags. The
//! header values a response needs (ETag, Content-Length, Content-Type) are built at load time.
//!
//! To save memory a file of up to `LZ4_MAX_SIZE` (1 MiB) is kept as an LZ4 block when that saves
//! at least `WEB_LZ4_MIN_SAVING` percent (25 by default) — text, typically; images, fonts and the
//! precompressed siblings do not shrink and stay as they are. A response that sends such a file's
//! bytes as they are decompresses them (some GB/s: tens of microseconds for a page); 304s, HEAD and
//! the precompressed siblings that browsers get cost nothing.

use bytes::Bytes;
use http::HeaderValue;
use rustc_hash::{FxHashMap, FxHashSet};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Files smaller than this stay as they are: little to save, and a buffer per response.
const LZ4_MIN_SIZE: usize = 1024;

/// Files larger than this stay as they are too: a response that sends the file's own bytes — a
/// client without Accept-Encoding, any `Range`, even `bytes=0-0` — decompresses the whole block,
/// so this bounds what one request can make the server allocate and compute.
pub const LZ4_MAX_SIZE: usize = 1 << 20;

/// The default of `WEB_LZ4_MIN_SAVING`.
pub const DEFAULT_LZ4_MIN_SAVING: u8 = 25;

/// `WEB_LZ4_MIN_SAVING`: the least saving, in percent (0–99), for which a file is kept in LZ4;
/// `off`: never.
pub fn lz4_min_saving_from_env() -> Result<Option<u8>, String> {
    match std::env::var("WEB_LZ4_MIN_SAVING") {
        Err(_) => Ok(Some(DEFAULT_LZ4_MIN_SAVING)),
        Ok(value) if value.trim().eq_ignore_ascii_case("off") => Ok(None),
        Ok(value) => match value.trim().trim_end_matches('%').parse::<u8>() {
            Ok(percent) if percent < 100 => Ok(Some(percent)),
            _ => Err(format!("WEB_LZ4_MIN_SAVING: a percentage 0–99 or off, not {value:?}")),
        },
    }
}

/// How a file's bytes are kept.
#[derive(Debug)]
enum Stored {
    Plain(Bytes),
    /// An LZ4 block of the file, `len` bytes once decompressed.
    Lz4 {
        block: &'static [u8],
        len: usize,
    },
}

#[derive(Debug)]
pub struct FileEntry {
    stored: Stored,
    pub etag: HeaderValue,
    /// Content-Length of the whole file.
    pub length: HeaderValue,
    /// By the extension (`None`: unknown, no header, as in Caddy).
    pub content_type: Option<HeaderValue>,
}

impl FileEntry {
    /// The file's bytes: a reference to them, or — kept in LZ4 — a new buffer decompressed now.
    pub fn body(&self) -> Bytes {
        match &self.stored {
            Stored::Plain(bytes) => bytes.clone(),
            Stored::Lz4 { block, len } => {
                Bytes::from(lz4_flex::block::decompress(block, *len).expect("a block checked when it was made"))
            }
        }
    }

    /// The file's size.
    pub fn len(&self) -> usize {
        match &self.stored {
            Stored::Plain(bytes) => bytes.len(),
            Stored::Lz4 { len, .. } => *len,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// What it takes in memory.
    pub fn stored_len(&self) -> usize {
        match &self.stored {
            Stored::Plain(bytes) => bytes.len(),
            Stored::Lz4 { block, .. } => block.len(),
        }
    }

    pub fn is_lz4(&self) -> bool {
        matches!(self.stored, Stored::Lz4 { .. })
    }

    /// The file from its bytes, kept in LZ4 when that saves at least `lz4_min_saving` percent.
    pub fn new(path: &str, bytes: Vec<u8>, lz4_min_saving: Option<u8>) -> FileEntry {
        let mut prepared = Prepared::new(bytes, lz4_min_saving);
        let stored: &'static [u8] = Box::leak(std::mem::take(&mut prepared.stored).into_boxed_slice());
        FileEntry::placed(path, &prepared, stored)
    }

    /// From a prepared file whose stored bytes are at `stored`. The files stay for the life of the
    /// process (never reloaded): `'static`, so a response's copy of a body or a header value counts
    /// no references.
    fn placed(path: &str, prepared: &Prepared, stored: &'static [u8]) -> FileEntry {
        let etag = HeaderValue::from_static(Box::leak(Box::from(prepared.etag.as_str())));
        let length = HeaderValue::from_static(Box::leak(prepared.len.to_string().into_boxed_str()));
        let content_type = content_type(path).map(HeaderValue::from_static);
        let stored = if prepared.lz4 {
            Stored::Lz4 {
                block: stored,
                len: prepared.len,
            }
        } else {
            Stored::Plain(Bytes::from_static(stored))
        };
        FileEntry {
            stored,
            etag,
            length,
            content_type,
        }
    }
}

/// A file read, hashed and — when worth it — compressed, its bytes not yet in their place.
struct Prepared {
    /// What will be kept: the file, or its LZ4 block.
    stored: Vec<u8>,
    len: usize,
    lz4: bool,
    etag: String,
}

impl Prepared {
    fn new(bytes: Vec<u8>, lz4_min_saving: Option<u8>) -> Prepared {
        let etag = etag_of(&bytes);
        let len = bytes.len();
        if let Some(saving) = lz4_min_saving
            && (LZ4_MIN_SIZE..=LZ4_MAX_SIZE).contains(&len)
        {
            let block = lz4_flex::block::compress(&bytes);
            let worth_it = block.len() * 100 <= len * (100 - usize::from(saving));
            // Checked once here, so decompressing it for a response cannot fail.
            if worth_it && lz4_flex::block::decompress(&block, len).is_ok_and(|back| back == bytes) {
                return Prepared {
                    stored: block,
                    len,
                    lz4: true,
                    etag,
                };
            }
        }
        Prepared {
            stored: bytes,
            len,
            lz4: false,
            etag,
        }
    }
}

/// Files of the stores, their size and what they take in memory.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Totals {
    pub files: usize,
    pub bytes: u64,
    /// In memory: LZ4 blocks count with their own size.
    pub stored: u64,
    /// Files kept in LZ4.
    pub lz4: usize,
}

#[derive(Debug)]
pub struct FileStore {
    pub root: PathBuf,
    /// "/dir/name.ext" → file. FxHash: the keys are our own paths, so a fast non-keyed hash is
    /// safe here (requests only look up, they never insert).
    files: FxHashMap<String, Arc<FileEntry>>,
    /// "/", "/dir/", "/dir/sub/": every directory that holds a file.
    dirs: FxHashSet<String>,
    pub totals: Totals,
}

impl FileStore {
    pub fn file(&self, path: &str) -> Option<&Arc<FileEntry>> {
        self.files.get(path)
    }

    /// Every file's path ("/dir/name.ext").
    pub fn paths(&self) -> impl Iterator<Item = &str> {
        self.files.keys().map(String::as_str)
    }

    /// `path` ends with `/`.
    pub fn is_dir(&self, path: &str) -> bool {
        self.dirs.contains(path)
    }

    pub fn len(&self) -> usize {
        self.files.len()
    }

    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }

    /// Reads every regular file under `root` (symlinks followed), charging `budget` with what they
    /// take in memory; `lz4_min_saving`: see `FileEntry::new`. The files are read, hashed and
    /// compressed on every CPU; the budget is checked in path order, as one by one would. What is
    /// kept then goes into one buffer allocated here: the files lie together, and the loading
    /// threads' memory is all given back.
    pub fn load(root: &Path, budget: &mut u64, lz4_min_saving: Option<u8>) -> anyhow::Result<FileStore> {
        let root = root
            .canonicalize()
            .map_err(|e| anyhow::anyhow!("site root {}: {e}", root.display()))?;
        if !root.is_dir() {
            anyhow::bail!("site root {} is not a directory", root.display());
        }
        let mut files = FxHashMap::default();
        let mut dirs = FxHashSet::default();
        dirs.insert("/".to_string());
        let mut totals = Totals::default();
        let mut found: Vec<(String, PathBuf)> = Vec::new();
        for entry in walkdir::WalkDir::new(&root).follow_links(true) {
            let entry = entry.map_err(|e| anyhow::anyhow!("reading {}: {e}", root.display()))?;
            if !entry.file_type().is_file() {
                continue;
            }
            let relative = entry.path().strip_prefix(&root).unwrap_or(entry.path());
            let Some(key) = key_of(relative) else {
                tracing::warn!(path = %entry.path().display(), "skipping a file whose name is not UTF-8");
                continue;
            };
            found.push((key, entry.into_path()));
        }
        let loaded = on_every_cpu(&found, |(_, path)| {
            std::fs::read(path).map(|bytes| Prepared::new(bytes, lz4_min_saving))
        });
        let mut prepared = Vec::with_capacity(found.len());
        for ((key, path), file) in found.into_iter().zip(loaded) {
            let file = file.map_err(|e| anyhow::anyhow!("reading {}: {e}", path.display()))?;
            let size = file.stored.len() as u64;
            if size > *budget {
                anyhow::bail!(
                    "the site files do not fit in memory (WEB_MAX_MEMORY): {} needs {size} more bytes",
                    path.display()
                );
            }
            *budget -= size;
            prepared.push((key, file));
        }
        let mut arena = Vec::with_capacity(prepared.iter().map(|(_, p)| p.stored.len()).sum());
        for (_, file) in &prepared {
            arena.extend_from_slice(&file.stored);
        }
        let arena: &'static [u8] = Box::leak(arena.into_boxed_slice());
        let mut offset = 0;
        for (key, prepared) in prepared {
            let stored = &arena[offset..offset + prepared.stored.len()];
            offset += stored.len();
            let file = FileEntry::placed(&key, &prepared, stored);
            drop(prepared);
            let size = file.stored_len() as u64;
            totals.files += 1;
            totals.bytes += file.len() as u64;
            totals.stored += size;
            totals.lz4 += usize::from(file.is_lz4());
            let mut dir = key.as_str();
            while let Some(i) = dir[..dir.len().saturating_sub(1)].rfind('/') {
                dir = &dir[..=i];
                if !dirs.insert(dir.to_string()) {
                    break;
                }
            }
            files.insert(key, Arc::new(file));
        }
        Ok(FileStore {
            root,
            files,
            dirs,
            totals,
        })
    }
}

/// `work` on each item, spread over threads, one per CPU at most; the results in the items'
/// order. Keep what lasts out of the threads' own allocations (build it on the calling thread):
/// their memory is then all free when they end, and `release_free_memory` gives it back.
pub fn on_every_cpu<T: Sync, R: Send>(items: &[T], work: impl Fn(&T) -> R + Sync) -> Vec<R> {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let threads = std::thread::available_parallelism()
        .map_or(1, |n| n.get())
        .min(items.len());
    let next = AtomicUsize::new(0);
    let mut done: Vec<(usize, R)> = std::thread::scope(|scope| {
        let workers: Vec<_> = (0..threads)
            .map(|_| {
                scope.spawn(|| {
                    let mut mine = Vec::new();
                    loop {
                        let i = next.fetch_add(1, Ordering::Relaxed);
                        let Some(item) = items.get(i) else { break };
                        mine.push((i, work(item)));
                    }
                    mine
                })
            })
            .collect();
        workers
            .into_iter()
            .flat_map(|w| w.join().expect("a loading thread panicked"))
            .collect()
    });
    done.sort_unstable_by_key(|(i, _)| *i);
    done.into_iter().map(|(_, r)| r).collect()
}

/// "/a/b.txt" from a relative path, `None` if not UTF-8.
fn key_of(relative: &Path) -> Option<String> {
    let mut key = String::new();
    for part in relative.components() {
        key.push('/');
        key.push_str(part.as_os_str().to_str()?);
    }
    Some(key)
}

/// Strong ETag from the content: 80 bits of BLAKE3 in hex.
pub fn etag_of(body: &[u8]) -> String {
    let hash = blake3::hash(body);
    format!("\"{}\"", &hash.to_hex()[..20])
}

/// Content type by file extension; `None` (no header, as in Caddy) when unknown.
pub fn content_type(path: &str) -> Option<&'static str> {
    let name = path.rsplit('/').next().unwrap_or(path);
    let ext = name.rsplit_once('.')?.1.to_ascii_lowercase();
    Some(match ext.as_str() {
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "json" | "map" => "application/json",
        "xml" => "text/xml; charset=utf-8",
        "txt" => "text/plain; charset=utf-8",
        "md" => "text/markdown; charset=utf-8",
        "csv" => "text/csv; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "avif" => "image/avif",
        "ico" => "image/vnd.microsoft.icon",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        "otf" => "font/otf",
        "webmanifest" => "application/manifest+json",
        "wasm" => "application/wasm",
        "pdf" => "application/pdf",
        "mp4" => "video/mp4",
        "webm" => "video/webm",
        "mp3" => "audio/mpeg",
        "zip" => "application/zip",
        "gz" => "application/gzip",
        "zst" => "application/zstd",
        _ => return None,
    })
}

/// Every site root used by the configuration, loaded once.
pub struct Loader {
    stores: HashMap<PathBuf, Arc<FileStore>>,
    budget: u64,
    lz4_min_saving: Option<u8>,
}

impl Loader {
    /// Over every root.
    pub fn totals(&self) -> Totals {
        self.stores.values().fold(Totals::default(), |sum, store| Totals {
            files: sum.files + store.totals.files,
            bytes: sum.bytes + store.totals.bytes,
            stored: sum.stored + store.totals.stored,
            lz4: sum.lz4 + store.totals.lz4,
        })
    }

    /// Files kept in LZ4 when that saves the default share.
    pub fn new(max_bytes: u64) -> Loader {
        Loader::with_lz4(max_bytes, Some(DEFAULT_LZ4_MIN_SAVING))
    }

    pub fn with_lz4(max_bytes: u64, lz4_min_saving: Option<u8>) -> Loader {
        Loader {
            stores: HashMap::new(),
            budget: max_bytes,
            lz4_min_saving,
        }
    }

    pub fn store(&mut self, root: &str) -> anyhow::Result<Arc<FileStore>> {
        let path = PathBuf::from(root);
        let canonical = path
            .canonicalize()
            .map_err(|e| anyhow::anyhow!("site root {root}: {e}"))?;
        if let Some(store) = self.stores.get(&canonical) {
            return Ok(store.clone());
        }
        let started = std::time::Instant::now();
        let store = Arc::new(FileStore::load(&canonical, &mut self.budget, self.lz4_min_saving)?);
        let totals = store.totals;
        tracing::info!(
            root = %canonical.display(),
            files = totals.files,
            bytes = totals.bytes,
            in_memory = totals.stored,
            lz4_files = totals.lz4,
            ms = started.elapsed().as_millis() as u64,
            "site files loaded"
        );
        self.stores.insert(canonical, store.clone());
        Ok(store)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_files_dirs_and_etags() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("en/blog")).unwrap();
        std::fs::write(dir.path().join("en/blog/index.html"), "a").unwrap();
        std::fs::write(dir.path().join("en/x.html"), "a").unwrap();
        std::fs::write(dir.path().join("top.txt"), "b").unwrap();
        let mut budget = 1 << 20;
        let store = FileStore::load(dir.path(), &mut budget, Some(DEFAULT_LZ4_MIN_SAVING)).unwrap();
        assert_eq!(store.len(), 3);
        assert!(store.is_dir("/") && store.is_dir("/en/") && store.is_dir("/en/blog/"));
        assert!(!store.is_dir("/en/blog"));
        let a = store.file("/en/blog/index.html").unwrap();
        let b = store.file("/en/x.html").unwrap();
        assert_eq!(a.etag, b.etag, "same content, same ETag");
        assert_ne!(a.etag, store.file("/top.txt").unwrap().etag);
        assert_eq!(budget, (1 << 20) - 3);
    }

    #[test]
    fn budget_is_enforced() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("big.bin"), vec![0u8; 100]).unwrap();
        let mut budget = 10;
        assert!(
            FileStore::load(dir.path(), &mut budget, None)
                .unwrap_err()
                .to_string()
                .contains("WEB_MAX_MEMORY")
        );
    }

    #[test]
    fn compressible_files_are_kept_in_lz4_and_come_back_whole() {
        let text: Vec<u8> = "<p>the same paragraph, again and again</p>\n".repeat(200).into_bytes();
        // Bytes that do not repeat: LZ4 cannot shrink them.
        let mut noise = Vec::with_capacity(8192);
        let mut x: u32 = 2_463_534_242;
        for _ in 0..8192 {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            noise.push(x as u8);
        }
        let page = FileEntry::new("/a.html", text.clone(), Some(25));
        assert!(page.is_lz4());
        assert!(page.stored_len() * 4 < text.len());
        assert_eq!(page.len(), text.len());
        assert_eq!(&page.body()[..], &text[..]);
        assert_eq!(
            page.etag,
            etag_of(&text).as_str(),
            "the ETag is the file's, not the block's"
        );
        assert_eq!(page.length, text.len().to_string().as_str());

        let image = FileEntry::new("/a.png", noise.clone(), Some(25));
        assert!(!image.is_lz4());
        assert_eq!(&image.body()[..], &noise[..]);
        assert!(
            !FileEntry::new("/small.html", b"<p>x</p>".repeat(10), Some(0)).is_lz4(),
            "too small"
        );
        assert!(!FileEntry::new("/a.html", text, None).is_lz4(), "off");
        let huge = "<p>the same paragraph, again and again</p>\n"
            .repeat(LZ4_MAX_SIZE / 40 + 1)
            .into_bytes();
        assert!(huge.len() > LZ4_MAX_SIZE);
        assert!(
            !FileEntry::new("/huge.html", huge, Some(0)).is_lz4(),
            "too large: one request would decompress it whole"
        );
    }

    #[test]
    fn work_spread_over_cpus_comes_back_in_order() {
        let items: Vec<u64> = (0..1000).collect();
        let squares = on_every_cpu(&items, |x| x * x);
        assert_eq!(squares, items.iter().map(|x| x * x).collect::<Vec<_>>());
        assert!(on_every_cpu(&[] as &[u8], |x| *x).is_empty());
    }

    #[test]
    fn content_types() {
        assert_eq!(content_type("/a/index.html"), Some("text/html; charset=utf-8"));
        assert_eq!(content_type("/a.JS"), Some("text/javascript; charset=utf-8"));
        assert_eq!(content_type("/noext"), None);
        assert_eq!(content_type("/x.unknownext"), None);
    }
}
