//! webfast: a static-first web server. It serves sites from memory and proxies the dynamic parts,
//! configured with a strict subset of the Caddyfile so the same file also runs in Caddy (README.md,
//! docs/).

pub mod accesslog;
#[cfg(feature = "api-firewall")]
pub mod apifw;
pub mod body;
#[cfg(feature = "proxy-cache")]
pub mod cache;
pub mod caddyfile;
pub mod config;
pub mod date;
pub mod encode;
#[cfg(any(feature = "jwt", feature = "api-firewall"))]
pub mod eventlog;
#[cfg(any(feature = "jwt", feature = "api-firewall"))]
pub mod fetch;
pub mod files;
pub mod guard;
pub mod h3;
pub mod h3limit;
pub mod handler;
#[cfg(feature = "jwt")]
pub mod jwt;
pub mod matcher;
pub mod memo;
pub mod placeholder;
pub mod proxy;
#[cfg(feature = "rate-limit")]
pub mod ratelimit;
pub mod server;
pub mod sockets;
pub mod static_files;
pub mod tls;
#[cfg(feature = "compress-files")]
pub mod variants;
pub mod watch;

use std::path::Path;
use std::time::Duration;

/// Default limit for the site files held in memory.
pub const DEFAULT_MAX_MEMORY: u64 = 512 * 1024 * 1024;

/// Reads and compiles a Caddyfile, loading every site root into memory.
pub fn load_config(path: &Path, max_memory: u64) -> anyhow::Result<config::Config> {
    let file = caddyfile::parse_file(path)?;
    load_parsed(&file, max_memory)
}

pub fn load_parsed(file: &caddyfile::Caddyfile, max_memory: u64) -> anyhow::Result<config::Config> {
    load_parsed_with(file, max_memory, Some(files::DEFAULT_LZ4_MIN_SAVING))
}

/// `lz4_min_saving`: files are kept in LZ4 when that saves at least this many percent (`None`:
/// never; src/files.rs).
pub fn load_parsed_with(
    file: &caddyfile::Caddyfile,
    max_memory: u64,
    lz4_min_saving: Option<u8>,
) -> anyhow::Result<config::Config> {
    load_parsed_watching(file, max_memory, lz4_min_saving, watch::Watch::default())
}

/// With `watch` on, the files are loaded so that they can be replaced, and the started server
/// picks up changes to them (src/watch.rs).
pub fn load_parsed_watching(
    file: &caddyfile::Caddyfile,
    max_memory: u64,
    lz4_min_saving: Option<u8>,
    watch: watch::Watch,
) -> anyhow::Result<config::Config> {
    let max_in_memory = Some(files::DEFAULT_MAX_FILE_IN_MEMORY);
    load_parsed_reusing(file, max_memory, lz4_min_saving, max_in_memory, watch, &[])
}

/// For a reload (`server::Running::reload`): site roots among `stores` — the running server's,
/// `Running::stores` — are taken over as they are instead of being read again; the others are
/// loaded. `max_in_memory`: larger files are served from disk (WEB_MAX_FILE_IN_MEMORY; `None`:
/// every file in memory).
pub fn load_parsed_reusing(
    file: &caddyfile::Caddyfile,
    max_memory: u64,
    lz4_min_saving: Option<u8>,
    max_in_memory: Option<u64>,
    watch: watch::Watch,
    stores: &[std::sync::Arc<files::FileStore>],
) -> anyhow::Result<config::Config> {
    let mut loader = files::Loader::with_lz4(max_memory, lz4_min_saving)
        .reloadable(watch.is_on())
        .max_in_memory(max_in_memory)
        .reusing(stores);
    let client = proxy::client(Duration::from_secs(3), Some(Duration::from_secs(120)));
    let mut config = config::compile(file, &mut loader, client)?;
    config.files = loader.totals();
    config.stores = loader.stores();
    config.max_memory = loader.max_bytes();
    config.watch = watch;
    Ok(config)
}

/// Gives freed memory back to the system: this thread's, and what threads that have ended left
/// behind. mimalloc keeps freed memory for reuse, so the threads that loaded the files and prepared
/// the answers at startup would otherwise leave theirs resident and unused; called once startup is
/// done (src/main.rs). Without mimalloc: nothing.
pub fn release_free_memory() {
    #[cfg(feature = "mimalloc")]
    // SAFETY: mi_collect only walks and trims mimalloc's own heaps.
    unsafe {
        libmimalloc_sys::mi_collect(true)
    }
}

/// The process's resident memory (Linux: VmRSS), for the startup report.
pub fn resident_bytes() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find(|l| l.starts_with("VmRSS:"))?;
    let kib: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
    Some(kib * 1024)
}

/// `512MiB`, `1G`, `300000000`.
pub fn parse_size(text: &str) -> Option<u64> {
    let text = text.trim();
    let split = text.find(|c: char| !c.is_ascii_digit()).unwrap_or(text.len());
    let (number, unit) = text.split_at(split);
    let number: u64 = number.parse().ok()?;
    let factor = match unit.trim().to_ascii_lowercase().as_str() {
        "" | "b" => 1,
        "k" | "kb" | "kib" => 1 << 10,
        "m" | "mb" | "mib" => 1 << 20,
        "g" | "gb" | "gib" => 1 << 30,
        _ => return None,
    };
    number.checked_mul(factor)
}

#[cfg(test)]
mod tests {
    #[test]
    fn sizes() {
        assert_eq!(super::parse_size("512MiB"), Some(512 << 20));
        assert_eq!(super::parse_size("1G"), Some(1 << 30));
        assert_eq!(super::parse_size("100"), Some(100));
        assert_eq!(super::parse_size("x"), None);
    }
}
