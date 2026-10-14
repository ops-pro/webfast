//! Site files held in memory: read once at startup, each with an ETag that is the hash of its
//! content, so the ETag changes exactly when the file does (and is the same on every replica).
//! Precompressed `.br` / `.zst` / `.gz` siblings are ordinary entries with their own ETags. The
//! header values a response needs (ETag, Content-Length, Content-Type) are built at load time.

use bytes::Bytes;
use http::HeaderValue;
use rustc_hash::{FxHashMap, FxHashSet};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Debug)]
pub struct FileEntry {
    pub body: Bytes,
    pub etag: HeaderValue,
    /// Content-Length of the whole file.
    pub length: HeaderValue,
    /// By the extension (`None`: unknown, no header, as in Caddy).
    pub content_type: Option<HeaderValue>,
}

#[derive(Debug)]
pub struct FileStore {
    pub root: PathBuf,
    /// "/dir/name.ext" → file. FxHash: the keys are our own paths, so a fast non-keyed hash is
    /// safe here (requests only look up, they never insert).
    files: FxHashMap<String, Arc<FileEntry>>,
    /// "/", "/dir/", "/dir/sub/": every directory that holds a file.
    dirs: FxHashSet<String>,
    pub bytes: u64,
}

impl FileStore {
    pub fn file(&self, path: &str) -> Option<&Arc<FileEntry>> {
        self.files.get(path)
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

    /// Reads every regular file under `root` (symlinks followed), charging `budget` bytes.
    pub fn load(root: &Path, budget: &mut u64) -> anyhow::Result<FileStore> {
        let root = root
            .canonicalize()
            .map_err(|e| anyhow::anyhow!("site root {}: {e}", root.display()))?;
        if !root.is_dir() {
            anyhow::bail!("site root {} is not a directory", root.display());
        }
        let mut files = FxHashMap::default();
        let mut dirs = FxHashSet::default();
        dirs.insert("/".to_string());
        let mut bytes = 0u64;
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
            let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
            if size > *budget {
                anyhow::bail!(
                    "the site files do not fit in memory (WEB_MAX_MEMORY): {} needs {size} more bytes",
                    entry.path().display()
                );
            }
            let body = Bytes::from(std::fs::read(entry.path())?);
            *budget -= body.len() as u64;
            bytes += body.len() as u64;
            let mut dir = key.as_str();
            while let Some(i) = dir[..dir.len().saturating_sub(1)].rfind('/') {
                dir = &dir[..=i];
                if !dirs.insert(dir.to_string()) {
                    break;
                }
            }
            let etag = HeaderValue::from_str(&etag_of(&body)).expect("hex is a valid header value");
            let length = HeaderValue::from(body.len() as u64);
            let content_type = content_type(&key).map(HeaderValue::from_static);
            files.insert(
                key,
                Arc::new(FileEntry {
                    body,
                    etag,
                    length,
                    content_type,
                }),
            );
        }
        Ok(FileStore {
            root,
            files,
            dirs,
            bytes,
        })
    }
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
}

impl Loader {
    pub fn new(max_bytes: u64) -> Loader {
        Loader {
            stores: HashMap::new(),
            budget: max_bytes,
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
        let store = Arc::new(FileStore::load(&canonical, &mut self.budget)?);
        tracing::info!(root = %canonical.display(), files = store.len(), bytes = store.bytes, "site files loaded");
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
        let store = FileStore::load(dir.path(), &mut budget).unwrap();
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
            FileStore::load(dir.path(), &mut budget)
                .unwrap_err()
                .to_string()
                .contains("WEB_MAX_MEMORY")
        );
    }

    #[test]
    fn content_types() {
        assert_eq!(content_type("/a/index.html"), Some("text/html; charset=utf-8"));
        assert_eq!(content_type("/a.JS"), Some("text/javascript; charset=utf-8"));
        assert_eq!(content_type("/noext"), None);
        assert_eq!(content_type("/x.unknownext"), None);
    }
}
