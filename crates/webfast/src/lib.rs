//! webfast, the binary's crate: the composition (`compose`) of the core with the modules the
//! binary is built with, which the binary (main.rs) runs and the integration tests (tests/) boot
//! servers with. The modules come as crates of their own, written against `webfast_core`'s public
//! API alone (docs/modules.md), from https://github.com/ops-pro/webfast-modules; for now none is
//! composed.

pub mod compose;
