//! A request check read from its own file — the JWT check (`WEB_JWT_CONFIG`), the API firewall
//! (`WEB_API_FIREWALL_CONFIG`) — that a reload (SIGHUP) reads again, as the modules' files are.
//!
//! The hooks are `&'static` and keep the check (`Reloadable`) for the life of the process; what
//! it holds is swapped. A reload goes in two steps around the Caddyfile's (src/run.rs
//! `reload_config`): the file is read and **staged** first (one that does not load fails the
//! reload, and the running check stays), so the new Caddyfile is checked against the staged
//! check's bindings to upstreams (`UpstreamCheck::upstreams` reports them while staged); once the
//! server has taken the Caddyfile the staged check is **committed** — started (its keys or specs
//! read in the background) and put in place for the next request — or, when the reload failed,
//! dropped. A request under way keeps the check it began with.
//!
//! The old check's background work ends by itself: its tasks hold it weakly and stop once it is
//! gone (src/jwt/jwks.rs `refresh`, src/apifw `refresh`).

use crate::body::Body;
use crate::extensions::{Checked, Client, RequestCheck, UpstreamCheck};
use anyhow::Result;
use arc_swap::{ArcSwap, ArcSwapOption};
use http::Response;
use http::uri::Authority;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// What starts a check's background work, once it is in place (the JWT's key reads, the API
/// firewall's spec reads through this server's routes).
type Starter<T> = Box<dyn Fn(&T) -> Result<()> + Send + Sync>;

/// A check and the file it was read from.
pub struct Reloadable<T> {
    /// `None`: given as it is (tests, tools); a reload leaves it.
    path: Option<PathBuf>,
    current: ArcSwap<T>,
    staged: ArcSwapOption<T>,
    starter: Mutex<Option<Starter<T>>>,
}

impl<T> Reloadable<T> {
    /// A check without a file: a reload leaves it as it is.
    pub fn new(check: T) -> Reloadable<T> {
        Reloadable {
            path: None,
            current: ArcSwap::from_pointee(check),
            staged: ArcSwapOption::empty(),
            starter: Mutex::new(None),
        }
    }

    /// A check read from `path`, which a reload reads again.
    pub fn from_file(path: &Path, check: T) -> Reloadable<T> {
        Reloadable {
            path: Some(path.to_path_buf()),
            ..Reloadable::new(check)
        }
    }

    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// The check in place now.
    pub fn current(&self) -> Arc<T> {
        self.current.load_full()
    }

    /// The staged check, else the one in place: what the bindings are checked against.
    pub fn latest(&self) -> Arc<T> {
        self.staged.load_full().unwrap_or_else(|| self.current.load_full())
    }

    /// Starts `check`'s background work, and that of every check committed from now on.
    pub fn start_with(&self, check: &T, start: impl Fn(&T) -> Result<()> + Send + Sync + 'static) -> Result<()> {
        start(check)?;
        *self.starter.lock().unwrap_or_else(|e| e.into_inner()) = Some(Box::new(start));
        Ok(())
    }

    /// Reads the file again with `load` and stages what it gives (nothing for a check without a
    /// file); the staged check, for the log.
    pub fn stage(&self, load: impl FnOnce(&Path) -> Result<T>) -> Result<Option<Arc<T>>> {
        let Some(path) = &self.path else {
            return Ok(None);
        };
        let check = Arc::new(load(path)?);
        self.staged.store(Some(Arc::clone(&check)));
        Ok(Some(check))
    }

    /// The staged check put in place, its background work started; `Ok(false)` when nothing was
    /// staged.
    pub fn commit(&self) -> Result<bool> {
        let Some(check) = self.staged.swap(None) else {
            return Ok(false);
        };
        if let Some(start) = &*self.starter.lock().unwrap_or_else(|e| e.into_inner()) {
            start(&check)?;
        }
        self.current.store(check);
        Ok(true)
    }

    /// The staged check dropped (the reload failed): the running one stays.
    pub fn discard(&self) {
        self.staged.store(None);
    }
}

impl<T: RequestCheck> RequestCheck for Reloadable<T> {
    async fn check(&self, req: &mut http::request::Parts, body: Body, client: Client<'_>) -> Checked {
        let check = self.current.load_full();
        check.check(req, body, client).await
    }
}

impl<T: UpstreamCheck> UpstreamCheck for Reloadable<T> {
    type Held = T::Held;

    async fn check(
        &self,
        req: &mut http::request::Parts,
        body: Body,
        client: Client<'_>,
        upstreams: &[Authority],
    ) -> std::result::Result<(Body, T::Held), Response<Body>> {
        let check = self.current.load_full();
        check.check(req, body, client, upstreams).await
    }

    /// A check from a file may be bound after a reload even when it is not now: the proxies call
    /// it (the hooks are composed once, at startup).
    fn bound(&self) -> bool {
        self.path.is_some() || self.current.load().bound()
    }

    fn upstreams(&self, out: &mut Vec<(Authority, &'static str)>) {
        self.latest().upstreams(out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn staged_then_committed_or_discarded() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("check.txt");
        std::fs::write(&path, "two").unwrap();
        let read = |p: &Path| -> Result<String> { Ok(std::fs::read_to_string(p)?) };
        let check = Reloadable::from_file(&path, "one".to_string());
        let started = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&started);
        check
            .start_with(&check.current(), move |_| {
                counter.fetch_add(1, Ordering::Relaxed);
                Ok(())
            })
            .unwrap();
        assert_eq!(started.load(Ordering::Relaxed), 1);

        // Staged: not in place yet, but what the bindings see.
        check.stage(read).unwrap();
        assert_eq!(*check.current(), "one");
        assert_eq!(*check.latest(), "two");
        assert!(check.commit().unwrap());
        assert_eq!(*check.current(), "two");
        assert_eq!(started.load(Ordering::Relaxed), 2, "the new one started");
        assert!(!check.commit().unwrap(), "nothing staged");

        // A failed reload: the staged check goes, the running one stays.
        std::fs::write(&path, "three").unwrap();
        check.stage(read).unwrap();
        check.discard();
        assert_eq!(*check.latest(), "two");
        assert!(!check.commit().unwrap());

        // A file that does not load: an error, nothing staged.
        std::fs::remove_file(&path).unwrap();
        assert!(check.stage(read).is_err());
        assert_eq!(*check.latest(), "two");

        // Without a file: nothing to read again.
        let fixed = Reloadable::new("x".to_string());
        assert!(fixed.stage(read).unwrap().is_none());
    }
}
