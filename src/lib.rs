//! Web server: serves the site from memory and proxies the dynamic parts, configured with a
//! strict subset of the Caddyfile so the same file also runs in Caddy (see README.md).

pub mod accesslog;
pub mod body;
pub mod caddyfile;
pub mod config;
pub mod encode;
pub mod files;
pub mod h3;
pub mod handler;
pub mod matcher;
pub mod placeholder;
pub mod proxy;
pub mod server;
pub mod static_files;
pub mod tls;

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
    let mut loader = files::Loader::new(max_memory);
    let client = proxy::client(Duration::from_secs(3), Some(Duration::from_secs(120)));
    config::compile(file, &mut loader, client)
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
