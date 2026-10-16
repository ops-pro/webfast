//! Site files held in memory: read at startup, each with an ETag that is the hash of its content,
//! so the ETag changes exactly when the file does (and is the same on every replica). Precompressed
//! `.br` / `.zst` / `.gz` siblings are ordinary entries with their own ETags. The header values a
//! response needs (ETag, Content-Length, Content-Type) are built when a file is read.
//!
//! A store holds its files as a snapshot (`Files`) that a rescan replaces whole when files change on
//! disk (src/watch.rs): unchanged files are taken over as they are, only new and changed ones are
//! read, and a request keeps the snapshot it found. Files that may be replaced each have a buffer of
//! their own, freed with the last snapshot and response that hold it; when nothing is watched
//! (WEB_FILES_WATCH=off) they all lie in one buffer kept for the life of the process, and a
//! response's copy of a body counts no references.
//!
//! To save memory a file of up to `LZ4_MAX_SIZE` (1 MiB) is kept as an LZ4 block when that saves
//! at least `WEB_LZ4_MIN_SAVING` percent (25 by default) — text, typically; images, fonts and the
//! precompressed siblings do not shrink and stay as they are. A response that sends such a file's
//! bytes as they are decompresses them (some GB/s: tens of microseconds for a page); 304s, HEAD and
//! the precompressed siblings that browsers get cost nothing.

use arc_swap::ArcSwap;
use bytes::Bytes;
use http::HeaderValue;
use rustc_hash::{FxHashMap, FxHashSet};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex, PoisonError};
use std::time::{Instant, SystemTime};

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

/// `text` for good, as the same `&'static str` whenever it comes again: header values that
/// responses copy without counting references. Each distinct value stays for the life of the
/// process — for a file, about 30 bytes per version (its ETag and length); src/memo.rs keeps the
/// ready answers' header values here too.
pub fn intern(text: &str) -> &'static str {
    static STRINGS: LazyLock<Mutex<FxHashSet<&'static str>>> = LazyLock::new(Default::default);
    let mut strings = STRINGS.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some(kept) = strings.get(text) {
        return kept;
    }
    let kept: &'static str = Box::leak(Box::from(text));
    strings.insert(kept);
    kept
}

/// A file's version on disk, told without reading it: size, modification time and — on Unix — the
/// inode and status-change time (a rewrite that keeps the modification time, or a new file renamed
/// into place, still changes them).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Meta {
    len: u64,
    modified: Option<SystemTime>,
    #[cfg(unix)]
    inode: u64,
    #[cfg(unix)]
    changed: (i64, i64),
}

impl Meta {
    fn of(metadata: &std::fs::Metadata) -> Meta {
        #[cfg(unix)]
        use std::os::unix::fs::MetadataExt;
        Meta {
            len: metadata.len(),
            modified: metadata.modified().ok(),
            #[cfg(unix)]
            inode: metadata.ino(),
            #[cfg(unix)]
            changed: (metadata.ctime(), metadata.ctime_nsec()),
        }
    }
}

/// How a file's bytes are kept.
#[derive(Debug)]
enum Stored {
    Plain(Bytes),
    /// An LZ4 block of the file, `len` bytes once decompressed.
    Lz4 {
        block: Bytes,
        len: usize,
    },
}

/// Files read together are copied into shared buffers of about this size: few allocations — a
/// thousand files of every size, each in its own, took 16 MiB more of the heap than their bytes —
/// and a buffer goes once no snapshot or response holds any of its files.
const CHUNK: usize = 1 << 20;

/// A shared buffer of files (for the accounting of what replaced files leave in it).
#[derive(Debug)]
struct Chunk {
    len: usize,
}

#[derive(Debug)]
pub struct FileEntry {
    stored: Stored,
    pub etag: HeaderValue,
    /// Content-Length of the whole file.
    pub length: HeaderValue,
    /// By the extension (`None`: unknown, no header, as in Caddy).
    pub content_type: Option<HeaderValue>,
    /// The file's version on disk when it was read (`None`: not read from a file).
    meta: Option<Meta>,
    /// The shared buffer its bytes are in (`None`: kept for good, or a buffer of its own).
    chunk: Option<Arc<Chunk>>,
}

impl FileEntry {
    fn stored_bytes(&self) -> &Bytes {
        match &self.stored {
            Stored::Plain(bytes) => bytes,
            Stored::Lz4 { block, .. } => block,
        }
    }

    /// The same file with its bytes at `stored`, in `chunk`.
    fn repacked(&self, stored: Bytes, chunk: Arc<Chunk>) -> FileEntry {
        FileEntry {
            stored: match &self.stored {
                Stored::Plain(_) => Stored::Plain(stored),
                Stored::Lz4 { len, .. } => Stored::Lz4 {
                    block: stored,
                    len: *len,
                },
            },
            etag: self.etag.clone(),
            length: self.length.clone(),
            content_type: self.content_type.clone(),
            meta: self.meta,
            chunk: Some(chunk),
        }
    }

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
        let stored = Bytes::from(std::mem::take(&mut prepared.stored));
        FileEntry::placed(path, &prepared, stored, None, None)
    }

    /// From a prepared file whose stored bytes are `stored`. The header values are interned, so a
    /// response's copy of them counts no references.
    fn placed(
        path: &str,
        prepared: &Prepared,
        stored: Bytes,
        meta: Option<Meta>,
        chunk: Option<Arc<Chunk>>,
    ) -> FileEntry {
        let etag = HeaderValue::from_static(intern(&prepared.etag));
        let length = HeaderValue::from_static(intern(&prepared.len.to_string()));
        let content_type = content_type(path).map(HeaderValue::from_static);
        let stored = if prepared.lz4 {
            Stored::Lz4 {
                block: stored,
                len: prepared.len,
            }
        } else {
            Stored::Plain(stored)
        };
        FileEntry {
            stored,
            etag,
            length,
            content_type,
            meta,
            chunk,
        }
    }
}

/// `parts` copied, in order, into shared buffers of about `CHUNK` bytes (a larger part in one of
/// its own), allocated by the calling thread: each part's bytes and the buffer they are in.
fn pack(parts: &[&[u8]]) -> Vec<(Bytes, Arc<Chunk>)> {
    let mut out = Vec::with_capacity(parts.len());
    let mut i = 0;
    while i < parts.len() {
        let mut len = parts[i].len();
        let mut j = i + 1;
        while j < parts.len() && len + parts[j].len() <= CHUNK {
            len += parts[j].len();
            j += 1;
        }
        let mut buffer = Vec::with_capacity(len);
        for part in &parts[i..j] {
            buffer.extend_from_slice(part);
        }
        let buffer = Bytes::from(buffer);
        let chunk = Arc::new(Chunk { len });
        let mut offset = 0;
        for part in &parts[i..j] {
            out.push((buffer.slice(offset..offset + part.len()), chunk.clone()));
            offset += part.len();
        }
        i = j;
    }
    out
}

/// What the buffers `files` are in hold besides them: bytes of replaced files, not yet freed.
fn chunk_waste(files: &FxHashMap<String, Arc<FileEntry>>) -> (usize, usize) {
    let mut chunks: FxHashMap<*const Chunk, (usize, usize)> = FxHashMap::default();
    for file in files.values() {
        if let Some(chunk) = &file.chunk {
            chunks.entry(Arc::as_ptr(chunk)).or_insert((chunk.len, 0)).1 += file.stored_len();
        }
    }
    let live: usize = chunks.values().map(|(_, live)| live).sum();
    let held: usize = chunks.values().map(|(len, _)| len).sum();
    (held - live, live)
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

impl Totals {
    fn add(&mut self, file: &FileEntry) {
        self.files += 1;
        self.bytes += file.len() as u64;
        self.stored += file.stored_len() as u64;
        self.lz4 += usize::from(file.is_lz4());
    }
}

/// A store's files at one moment.
#[derive(Debug, Default)]
pub struct Files {
    /// "/dir/name.ext" → file. FxHash: the keys are our own paths, so a fast non-keyed hash is
    /// safe here (requests only look up, they never insert).
    files: FxHashMap<String, Arc<FileEntry>>,
    /// "/", "/dir/", "/dir/sub/": every directory that holds a file.
    dirs: FxHashSet<String>,
    pub totals: Totals,
}

impl Files {
    fn new(files: FxHashMap<String, Arc<FileEntry>>) -> Files {
        let mut dirs = FxHashSet::default();
        dirs.insert("/".to_string());
        let mut totals = Totals::default();
        for (key, file) in &files {
            totals.add(file);
            let mut dir = key.as_str();
            while let Some(i) = dir[..dir.len().saturating_sub(1)].rfind('/') {
                dir = &dir[..=i];
                if !dirs.insert(dir.to_string()) {
                    break;
                }
            }
        }
        Files { files, dirs, totals }
    }

    pub fn file(&self, path: &str) -> Option<&Arc<FileEntry>> {
        self.files.get(path)
    }

    pub fn contains(&self, path: &str) -> bool {
        self.files.contains_key(path)
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
}

/// What a rescan found.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Rescan {
    /// New files, changed ones, and ones gone; all 0: nothing changed and nothing was replaced.
    pub added: usize,
    pub changed: usize,
    pub removed: usize,
    /// Files that changed while being read, or went before they could be: kept as they were (or
    /// left out), to be looked at again soon.
    pub unsettled: usize,
    pub totals: Totals,
    pub millis: u64,
}

impl Rescan {
    pub fn replaced(&self) -> bool {
        self.added + self.changed + self.removed > 0
    }
}

#[derive(Debug)]
pub struct FileStore {
    /// The root as loaded at startup, symlinks resolved.
    pub root: PathBuf,
    /// The root as configured: rescans start here, so a root that is a symlink switched to another
    /// directory is followed.
    configured: PathBuf,
    current: ArcSwap<Files>,
    lz4_min_saving: Option<u8>,
    /// One rescan at a time (after a reload, the watcher that ends and the one that starts may
    /// overlap).
    rescanning: Mutex<()>,
}

impl FileStore {
    /// The files as they are now. A guard, not a reference count: load it where it is used, and
    /// not across an `.await`.
    pub fn files(&self) -> arc_swap::Guard<Arc<Files>> {
        self.current.load()
    }

    pub fn file(&self, path: &str) -> Option<Arc<FileEntry>> {
        self.files().file(path).cloned()
    }

    pub fn is_dir(&self, path: &str) -> bool {
        self.files().is_dir(path)
    }

    pub fn totals(&self) -> Totals {
        self.files().totals
    }

    pub fn len(&self) -> usize {
        self.files().len()
    }

    pub fn is_empty(&self) -> bool {
        self.files().is_empty()
    }

    pub fn configured(&self) -> &Path {
        &self.configured
    }

    /// Reads every regular file under `root` (symlinks followed), charging `budget` with what they
    /// take in memory; `lz4_min_saving`: see `FileEntry::new`. The files are read, hashed and
    /// compressed on every CPU; the budget is checked in path order, as one by one would. What is
    /// kept goes into one buffer allocated here, for good: the files lie together, and the loading
    /// threads' memory is all given back.
    pub fn load(root: &Path, budget: &mut u64, lz4_min_saving: Option<u8>) -> anyhow::Result<FileStore> {
        FileStore::load_with(root, budget, lz4_min_saving, false)
    }

    /// `reloadable`: each file in a buffer of its own allocated here, so that a rescan can replace
    /// it and its memory goes when the last snapshot and response that hold it do.
    pub fn load_with(
        root: &Path,
        budget: &mut u64,
        lz4_min_saving: Option<u8>,
        reloadable: bool,
    ) -> anyhow::Result<FileStore> {
        let canonical = root
            .canonicalize()
            .map_err(|e| anyhow::anyhow!("site root {}: {e}", root.display()))?;
        if !canonical.is_dir() {
            anyhow::bail!("site root {} is not a directory", root.display());
        }
        let (found, _) = scan(root, false)?;
        let loaded = on_every_cpu(&found, |(_, path, _)| {
            std::fs::read(path).map(|bytes| Prepared::new(bytes, lz4_min_saving))
        });
        let mut prepared = Vec::with_capacity(found.len());
        for ((key, path, meta), file) in found.into_iter().zip(loaded) {
            let file = file.map_err(|e| anyhow::anyhow!("reading {}: {e}", path.display()))?;
            let size = file.stored.len() as u64;
            if size > *budget {
                anyhow::bail!(
                    "the site files do not fit in memory (WEB_MAX_MEMORY): {} needs {size} more bytes",
                    path.display()
                );
            }
            *budget -= size;
            prepared.push((key, file, meta));
        }
        let mut files = FxHashMap::default();
        if reloadable {
            let parts: Vec<&[u8]> = prepared.iter().map(|(_, p, _)| p.stored.as_slice()).collect();
            let packed = pack(&parts);
            for ((key, prepared, meta), (stored, chunk)) in prepared.iter().zip(packed) {
                let file = FileEntry::placed(key, prepared, stored, Some(*meta), Some(chunk));
                files.insert(key.clone(), Arc::new(file));
            }
        } else {
            let mut arena = Vec::with_capacity(prepared.iter().map(|(_, p, _)| p.stored.len()).sum());
            for (_, file, _) in &prepared {
                arena.extend_from_slice(&file.stored);
            }
            let arena: &'static [u8] = Box::leak(arena.into_boxed_slice());
            let mut offset = 0;
            for (key, prepared, meta) in prepared {
                let stored = &arena[offset..offset + prepared.stored.len()];
                offset += stored.len();
                let file = FileEntry::placed(&key, &prepared, Bytes::from_static(stored), Some(meta), None);
                files.insert(key, Arc::new(file));
            }
        }
        Ok(FileStore {
            root: canonical,
            configured: root.to_path_buf(),
            current: ArcSwap::from_pointee(Files::new(files)),
            lz4_min_saving,
            rescanning: Mutex::new(()),
        })
    }

    /// Looks at the files on disk again and, when any is new, changed or gone, replaces the
    /// snapshot: unchanged files (same size, modification time, inode) are taken over, the others
    /// read on every CPU. `budget`: what the new snapshot may take in memory — over it, nothing is
    /// replaced. Requests keep using the snapshot they found; the store must have been loaded
    /// `reloadable` (otherwise replaced files would stay in memory for good).
    pub fn rescan(&self, budget: u64) -> anyhow::Result<Rescan> {
        let _one = self.rescanning.lock().unwrap_or_else(PoisonError::into_inner);
        let started = Instant::now();
        if !self.configured.is_dir() {
            anyhow::bail!("site root {} is not a directory (any more)", self.configured.display());
        }
        let (found, vanished) = scan(&self.configured, true)?;
        let old = self.current.load_full();
        let mut out = Rescan {
            unsettled: vanished,
            ..Rescan::default()
        };
        let mut files: FxHashMap<String, Arc<FileEntry>> = FxHashMap::default();
        let mut to_read = Vec::new();
        for (key, path, meta) in found {
            match old.files.get(&key) {
                Some(file) if file.meta == Some(meta) => {
                    files.insert(key, file.clone());
                }
                _ => to_read.push((key, path, meta)),
            }
        }
        out.removed = old.files.keys().filter(|key| !files.contains_key(*key)).count();
        out.removed -= to_read.iter().filter(|(key, _, _)| old.files.contains_key(key)).count();
        if to_read.is_empty() && out.removed == 0 {
            out.totals = old.totals;
            out.millis = started.elapsed().as_millis() as u64;
            return Ok(out);
        }
        let lz4_min_saving = self.lz4_min_saving;
        let loaded = on_every_cpu(&to_read, |(_, path, meta)| read_settled(path, *meta, lz4_min_saving));
        let parts: Vec<&[u8]> = loaded
            .iter()
            .filter_map(|file| file.as_ref().ok()?.as_ref())
            .map(|prepared| prepared.stored.as_slice())
            .collect();
        let mut packed = pack(&parts).into_iter();
        for ((key, path, meta), file) in to_read.iter().zip(&loaded) {
            let previous = old.files.get(key);
            match file {
                Ok(Some(prepared)) => {
                    let (stored, chunk) = packed.next().expect("a buffer for each file read");
                    let file = FileEntry::placed(key, prepared, stored, Some(*meta), Some(chunk));
                    if previous.is_some() {
                        out.changed += 1;
                    } else {
                        out.added += 1;
                    }
                    files.insert(key.clone(), Arc::new(file));
                }
                Ok(None) => {
                    // Changed while being read, or gone: as it was until the next look.
                    out.unsettled += 1;
                    if let Some(previous) = previous {
                        files.insert(key.clone(), previous.clone());
                    }
                }
                Err(e) => {
                    tracing::warn!(path = %path.display(), error = %e, "cannot read a site file; it stays as it was");
                    if let Some(previous) = previous {
                        files.insert(key.clone(), previous.clone());
                    }
                }
            }
        }
        drop(loaded);
        // Buffers kept for a few unchanged files while most of theirs were replaced: when they hold
        // more than a quarter again of what is live, every file is copied into new ones.
        let (waste, live) = chunk_waste(&files);
        if waste > live / 4 && waste > CHUNK {
            let entries: Vec<(&String, &Arc<FileEntry>)> = files.iter().collect();
            let parts: Vec<&[u8]> = entries.iter().map(|(_, file)| &file.stored_bytes()[..]).collect();
            let repacked: FxHashMap<String, Arc<FileEntry>> = entries
                .iter()
                .zip(pack(&parts))
                .map(|((key, file), (stored, chunk))| ((*key).clone(), Arc::new(file.repacked(stored, chunk))))
                .collect();
            tracing::debug!(root = %self.configured.display(), waste, live, "site files copied into new buffers");
            files = repacked;
        }
        let files = Files::new(files);
        if files.totals.stored > budget {
            anyhow::bail!(
                "the site files do not fit in memory (WEB_MAX_MEMORY): {} bytes, {budget} free",
                files.totals.stored
            );
        }
        out.totals = files.totals;
        if out.replaced() {
            self.current.store(Arc::new(files));
        }
        out.millis = started.elapsed().as_millis() as u64;
        Ok(out)
    }
}

/// The file read and prepared, if it is still the version `meta` describes once read (`None`:
/// changed meanwhile, or gone).
fn read_settled(path: &Path, meta: Meta, lz4_min_saving: Option<u8>) -> std::io::Result<Option<Prepared>> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    match std::fs::metadata(path) {
        Ok(after) if Meta::of(&after) == meta && bytes.len() as u64 == meta.len => {
            Ok(Some(Prepared::new(bytes, lz4_min_saving)))
        }
        Ok(_) => Ok(None),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Files found on disk: key ("/dir/name.ext"), path, version.
type Found = Vec<(String, PathBuf, Meta)>;

/// Every regular file under `root` (symlinks followed). With `lenient`, entries that went while the
/// directory was being walked are left out and counted.
fn scan(root: &Path, lenient: bool) -> anyhow::Result<(Found, usize)> {
    let mut found = Vec::new();
    let mut vanished = 0;
    for entry in walkdir::WalkDir::new(root).follow_links(true) {
        let entry = match entry {
            Ok(entry) => entry,
            Err(e) if lenient && e.io_error().is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound) => {
                vanished += 1;
                continue;
            }
            Err(e) => return Err(anyhow::anyhow!("reading {}: {e}", root.display())),
        };
        if !entry.file_type().is_file() {
            continue;
        }
        let relative = entry.path().strip_prefix(root).unwrap_or(entry.path());
        let Some(key) = key_of(relative) else {
            tracing::warn!(path = %entry.path().display(), "skipping a file whose name is not UTF-8");
            continue;
        };
        let meta = match entry.metadata() {
            Ok(metadata) => Meta::of(&metadata),
            Err(e) if lenient && e.io_error().is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound) => {
                vanished += 1;
                continue;
            }
            Err(e) => return Err(anyhow::anyhow!("reading {}: {e}", entry.path().display())),
        };
        found.push((key, entry.into_path(), meta));
    }
    Ok((found, vanished))
}

/// Every directory under `root` (symlinks followed), `root` first.
pub fn directories(root: &Path) -> Vec<PathBuf> {
    walkdir::WalkDir::new(root)
        .follow_links(true)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_dir())
        .map(walkdir::DirEntry::into_path)
        .collect()
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
    /// Roots the running server already holds (a reload): taken over instead of read again.
    previous: HashMap<PathBuf, Arc<FileStore>>,
    max_bytes: u64,
    budget: u64,
    lz4_min_saving: Option<u8>,
    reloadable: bool,
}

impl Loader {
    /// Over every root.
    pub fn totals(&self) -> Totals {
        self.stores.values().fold(Totals::default(), |sum, store| {
            let totals = store.totals();
            Totals {
                files: sum.files + totals.files,
                bytes: sum.bytes + totals.bytes,
                stored: sum.stored + totals.stored,
                lz4: sum.lz4 + totals.lz4,
            }
        })
    }

    /// Every root loaded.
    pub fn stores(&self) -> Vec<Arc<FileStore>> {
        self.stores.values().cloned().collect()
    }

    /// What all the stores together may take (WEB_MAX_MEMORY).
    pub fn max_bytes(&self) -> u64 {
        self.max_bytes
    }

    /// Files kept in LZ4 when that saves the default share.
    pub fn new(max_bytes: u64) -> Loader {
        Loader::with_lz4(max_bytes, Some(DEFAULT_LZ4_MIN_SAVING))
    }

    pub fn with_lz4(max_bytes: u64, lz4_min_saving: Option<u8>) -> Loader {
        Loader {
            stores: HashMap::new(),
            previous: HashMap::new(),
            max_bytes,
            budget: max_bytes,
            lz4_min_saving,
            reloadable: false,
        }
    }

    /// Stores whose files a rescan may replace (`FileStore::load_with`).
    pub fn reloadable(mut self, reloadable: bool) -> Loader {
        self.reloadable = reloadable;
        self
    }

    /// For a reload: a root among `stores` (the running server's) is taken over as it is — kept
    /// current by the watcher, or as loaded at startup with WEB_FILES_WATCH=off — instead of being
    /// read again.
    pub fn reusing(mut self, stores: &[Arc<FileStore>]) -> Loader {
        self.previous = stores.iter().map(|s| (s.root.clone(), s.clone())).collect();
        self
    }

    pub fn store(&mut self, root: &str) -> anyhow::Result<Arc<FileStore>> {
        let path = PathBuf::from(root);
        let canonical = path
            .canonicalize()
            .map_err(|e| anyhow::anyhow!("site root {root}: {e}"))?;
        if let Some(store) = self.stores.get(&canonical) {
            return Ok(store.clone());
        }
        if let Some(store) = self.previous.remove(&canonical) {
            let totals = store.totals();
            if totals.stored > self.budget {
                anyhow::bail!(
                    "the site files do not fit in memory (WEB_MAX_MEMORY): {root} takes {} bytes",
                    totals.stored
                );
            }
            self.budget -= totals.stored;
            tracing::info!(
                root = %canonical.display(),
                files = totals.files,
                in_memory = totals.stored,
                "site files kept"
            );
            self.stores.insert(canonical, store.clone());
            return Ok(store);
        }
        let started = std::time::Instant::now();
        let store = Arc::new(FileStore::load_with(
            &path,
            &mut self.budget,
            self.lz4_min_saving,
            self.reloadable,
        )?);
        let totals = store.totals();
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
    fn a_rescan_replaces_what_changed_and_keeps_the_rest() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("en")).unwrap();
        std::fs::write(dir.path().join("en/a.html"), "one").unwrap();
        std::fs::write(dir.path().join("keep.txt"), "kept").unwrap();
        std::fs::write(dir.path().join("gone.txt"), "gone").unwrap();
        let mut budget = 1 << 20;
        let store = FileStore::load_with(dir.path(), &mut budget, None, true).unwrap();
        let kept = store.file("/keep.txt").unwrap();
        let before = store.files();

        assert!(!store.rescan(1 << 20).unwrap().replaced(), "nothing changed");
        assert!(Arc::ptr_eq(&before, &store.files()), "nothing replaced");

        std::fs::write(dir.path().join("en/a.html"), "two!").unwrap();
        std::fs::create_dir_all(dir.path().join("new")).unwrap();
        std::fs::write(dir.path().join("new/b.txt"), "b").unwrap();
        std::fs::remove_file(dir.path().join("gone.txt")).unwrap();
        let rescan = store.rescan(1 << 20).unwrap();
        assert_eq!(
            (rescan.added, rescan.changed, rescan.removed, rescan.unsettled),
            (1, 1, 1, 0)
        );
        assert_eq!(&store.file("/en/a.html").unwrap().body()[..], b"two!");
        assert_eq!(store.file("/en/a.html").unwrap().length, "4");
        assert!(store.file("/gone.txt").is_none());
        assert!(store.is_dir("/new/"));
        assert!(
            Arc::ptr_eq(&kept, &store.file("/keep.txt").unwrap()),
            "unchanged: taken over"
        );
        // A request that found the old snapshot still has it whole.
        assert_eq!(&before.file("/en/a.html").unwrap().body()[..], b"one");
        assert!(before.file("/gone.txt").is_some());
        assert_eq!(store.totals().files, 3);

        // Over the budget: nothing is replaced.
        std::fs::write(dir.path().join("big.bin"), vec![1u8; 4096]).unwrap();
        assert!(store.rescan(100).unwrap_err().to_string().contains("WEB_MAX_MEMORY"));
        assert!(store.file("/big.bin").is_none());
    }

    #[test]
    fn buffers_mostly_of_replaced_files_are_copied_into_new_ones() {
        let dir = tempfile::tempdir().unwrap();
        let file = |i: usize, version: u8| vec![version; 64 * 1024 + i];
        for i in 0..40 {
            std::fs::write(dir.path().join(format!("{i}.bin")), file(i, 0)).unwrap();
        }
        let mut budget = 1 << 30;
        let store = FileStore::load_with(dir.path(), &mut budget, None, true).unwrap();
        assert_eq!(chunk_waste(&store.files().files).0, 0);
        assert!(store.files().files.len() > CHUNK / (64 * 1024), "several buffers");

        // A few changed: their old copies stay in the shared buffers for now.
        for i in 0..4 {
            std::fs::write(dir.path().join(format!("{i}.bin")), file(i, 1)).unwrap();
        }
        assert_eq!(store.rescan(1 << 30).unwrap().changed, 4);
        let (waste, _) = chunk_waste(&store.files().files);
        assert!(waste > 0 && waste < CHUNK, "{waste}");

        // Most changed: everything goes into new buffers, nothing held besides the live files.
        for i in 0..30 {
            std::fs::write(dir.path().join(format!("{i}.bin")), file(i, 2)).unwrap();
        }
        assert_eq!(store.rescan(1 << 30).unwrap().changed, 30);
        let (waste, live) = chunk_waste(&store.files().files);
        assert_eq!(waste, 0);
        assert_eq!(live as u64, store.totals().stored);
        for i in [0, 29, 30, 39] {
            let want = file(i, if i < 30 { 2 } else { 0 });
            assert_eq!(&store.file(&format!("/{i}.bin")).unwrap().body()[..], &want[..], "{i}");
        }
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
