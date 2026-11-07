//! The composition: which modules this binary is built with, and in what order their hooks run
//! (`webfast_core::module`, docs/modules.md). The sets are types — nested pairs, `()` for a module
//! that is not built — so the order is fixed here at compile time and the core calls each set
//! through one `&'static dyn`.
//!
//! The modules' crates are added here: a dependency in Cargo.toml, its `MODULE` in `MODULES`, its
//! checks and inspectors in their slots of `Checks` and `Inspectors`, and `hooks` filling them from
//! the loaded configuration. They live in https://github.com/ops-pro/webfast-modules (the request
//! filter `webfast-ngfw`, the browser challenge `webfast-challenge`); this composition is empty,
//! the next commit wires them in. The core's own checks run regardless: the ACME answer before the
//! modules' checks, the JWT and API firewall after them, the cache's observer after the modules'
//! inspectors.

use webfast_core::config::Config;
use webfast_core::module::{Composition, Module};

/// The modules' request checks, in order.
pub type Checks = ();
/// The modules' inspectors of proxied responses, in order.
pub type Inspectors = ();

/// The modules, built or not: a module whose feature is off is an `Unbuilt`, so that a variable of
/// its environment stops the start instead of being ignored.
pub static MODULES: &[&dyn Module] = &[];

/// The hooks from the loaded configuration: a module's instance, when its environment named a file
/// (`Module::load` put it in `config.modules`), in its slot.
fn hooks(config: &Config) -> (Checks, Inspectors) {
    let _ = config;
    ((), ())
}

/// What the binary runs and the tests boot servers with.
pub fn composition() -> Composition<Checks, Inspectors> {
    Composition {
        modules: MODULES,
        hooks,
    }
}

/// Registers the composition with the core (once per process; the tests of this crate call it
/// before they parse a Caddyfile with a module's directive).
pub fn install() {
    webfast_core::module::install(composition()).expect("the modules' directives are the core's to add");
}
