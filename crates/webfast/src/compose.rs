//! The composition: which modules this binary is built with, and in what order their hooks run
//! (`webfast_core::module`, docs/modules.md). The sets are types — nested pairs, `()` for a module
//! that is not built — so the order is fixed here at compile time and the core calls each set
//! through one `&'static dyn`.
//!
//! The modules are crates of https://github.com/ops-pro/webfast-modules, each behind a cargo
//! feature of this crate: the request filter `webfast-ngfw` (`ngfw`) and the browser challenge
//! `webfast-challenge` (`challenge`). A module is added here with a dependency in Cargo.toml, its
//! `MODULE` in `MODULES`, its checks and inspectors in their slots of `Checks` and `Inspectors`,
//! and `hooks` filling them from the loaded configuration.
//!
//! The request checks, in order: the browser challenge's answer endpoint (a POST of a nonce and
//! its answer, on every site), then the request filter (the mass of noise goes no further); the
//! core's ACME answer runs before them and its JWT and API firewall after. The inspectors of
//! proxied responses: the request filter's response phase (a leaking response is replaced before
//! the core's cache keeps it).

use webfast_core::config::Config;
use webfast_core::module::{Composition, Module};

#[cfg(feature = "challenge")]
type ChallengeEndpoint = webfast_challenge::ChallengeEndpoint;
#[cfg(not(feature = "challenge"))]
type ChallengeEndpoint = ();

#[cfg(feature = "ngfw")]
type Ngfw = Option<std::sync::Arc<webfast_ngfw::Ngfw>>;
#[cfg(not(feature = "ngfw"))]
type Ngfw = ();

#[cfg(feature = "ngfw")]
type NgfwResponses = webfast_ngfw::response::NgfwResponses;
#[cfg(not(feature = "ngfw"))]
type NgfwResponses = ();

/// The modules' request checks, in order.
pub type Checks = (ChallengeEndpoint, (Ngfw, ()));
/// The modules' inspectors of proxied responses, in order.
pub type Inspectors = (NgfwResponses, ());

/// The modules, built or not: a module whose feature is off is an `Unbuilt`, so that a variable of
/// its environment stops the start instead of being ignored.
pub static MODULES: &[&dyn Module] = &[
    #[cfg(feature = "challenge")]
    &webfast_challenge::MODULE,
    #[cfg(not(feature = "challenge"))]
    &webfast_core::module::Unbuilt {
        what: "the browser challenge",
        feature: "challenge",
        variables: &["WEB_CHALLENGE_PASSED"],
    },
    #[cfg(feature = "ngfw")]
    &webfast_ngfw::MODULE,
    #[cfg(not(feature = "ngfw"))]
    &webfast_core::module::Unbuilt {
        what: "the request filter",
        feature: "ngfw",
        variables: &["WEB_NGFW_CONFIG"],
    },
];

/// The hooks from the loaded configuration: the request filter's instance, when WEB_NGFW_CONFIG
/// named a file (`Module::load` put it in `config.modules`), in its slot.
fn hooks(config: &Config) -> (Checks, Inspectors) {
    let _ = config;
    (
        (
            #[cfg(feature = "challenge")]
            webfast_challenge::ChallengeEndpoint,
            #[cfg(not(feature = "challenge"))]
            (),
            (
                #[cfg(feature = "ngfw")]
                config.modules.get::<webfast_ngfw::Ngfw>(),
                #[cfg(not(feature = "ngfw"))]
                (),
                (),
            ),
        ),
        (
            #[cfg(feature = "ngfw")]
            webfast_ngfw::response::NgfwResponses,
            #[cfg(not(feature = "ngfw"))]
            (),
            (),
        ),
    )
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
