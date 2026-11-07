//! The webfast binary: the core (`webfast_core::run`, which has the commands, the environment and
//! the reload loop) composed with this crate's modules (src/compose.rs).

use std::process::ExitCode;

/// mimalloc: the requests' many small, short-lived allocations are cheaper than with glibc malloc.
#[cfg(feature = "mimalloc")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

/// clock_gettime through the vDSO for the static musl build (musl misses the arm64 vDSO).
#[cfg(target_os = "linux")]
#[cfg_attr(not(target_env = "musl"), allow(dead_code))]
mod vdso;

fn main() -> ExitCode {
    webfast_core::run::main(webfast::compose::composition())
}
