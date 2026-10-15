//! Changes to the site files picked up while the server runs (WEB_FILES_WATCH). Where the kernel
//! tells of every change — a local filesystem — a thread waits for inotify events and looks at a
//! root only when one comes, once the burst a deploy makes has passed. Elsewhere — NFS, SMB, FUSE,
//! 9p (WSL's /mnt/*, Docker Desktop's bind mounts), where changes made by another system raise no
//! event, or without inotify — the roots are looked at every WEB_FILES_POLL. A look compares each
//! file's size, modification time and inode with what was read and reads only what differs
//! (src/files.rs `FileStore::rescan`); when something did, the sites that read that root take the
//! chain until their ready answers are worked out again (src/memo.rs).

use crate::files::FileStore;
use crate::server::ServerState;
use rustc_hash::FxHashSet;
use std::path::Path;
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// The files as loaded at startup, for the life of the process.
    Off,
    /// inotify where the filesystem reports every change, polling elsewhere.
    Auto,
    Inotify,
    Poll,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Watch {
    pub mode: Mode,
    /// How often a polled root is looked at.
    pub poll: Duration,
}

pub const DEFAULT_POLL: Duration = Duration::from_secs(30);

/// After an event, more are waited for until none came for this long…
const QUIET: Duration = Duration::from_millis(200);
/// …but not longer than this after the first.
const BURST: Duration = Duration::from_secs(2);
/// Files that changed while being read, and new directories, are looked at again after this.
const AGAIN: Duration = Duration::from_millis(500);
/// How often the thread checks that the server still runs: it ends with it.
const ALIVE: Duration = Duration::from_secs(5);

impl Default for Watch {
    /// Off: what the library gives (tests, benchmarks) unless asked; the server's own default comes
    /// from the environment (`from_env`: auto).
    fn default() -> Watch {
        Watch {
            mode: Mode::Off,
            poll: DEFAULT_POLL,
        }
    }
}

impl Watch {
    pub fn is_on(&self) -> bool {
        self.mode != Mode::Off
    }

    /// WEB_FILES_WATCH (`auto`, the default; `inotify`, `poll`, `off`) and WEB_FILES_POLL (30s).
    pub fn from_env() -> Result<Watch, String> {
        let mode = match std::env::var("WEB_FILES_WATCH") {
            Err(_) => Mode::Auto,
            Ok(value) => match value.trim().to_ascii_lowercase().as_str() {
                "auto" => Mode::Auto,
                "inotify" => Mode::Inotify,
                "poll" => Mode::Poll,
                "off" => Mode::Off,
                _ => return Err(format!("WEB_FILES_WATCH: auto, inotify, poll or off, not {value:?}")),
            },
        };
        let poll = match std::env::var("WEB_FILES_POLL") {
            Err(_) => DEFAULT_POLL,
            Ok(value) => match crate::config::parse_duration(&value) {
                Ok(d) if !d.is_zero() => d,
                _ => return Err(format!("WEB_FILES_POLL: a duration (e.g. 30s), not {value:?}")),
            },
        };
        Ok(Watch { mode, poll })
    }
}

/// Starts the thread that keeps `stores` up to date for the servers' sites; it ends when the
/// servers are gone. `max_memory`: what all the stores may take together.
pub(crate) fn start(watch: Watch, stores: &[Arc<FileStore>], states: &[Arc<ServerState>], max_memory: u64) {
    if !watch.is_on() || stores.is_empty() {
        return;
    }
    let stores: Vec<Weak<FileStore>> = stores.iter().map(Arc::downgrade).collect();
    let states: Vec<Weak<ServerState>> = states.iter().map(Arc::downgrade).collect();
    let spawned = std::thread::Builder::new()
        .name("web-watch".into())
        .spawn(move || run(watch, &stores, &states, max_memory));
    if let Err(e) = spawned {
        tracing::error!(error = %e, "cannot start watching the site files; they stay as loaded");
    }
}

fn run(watch: Watch, stores: &[Weak<FileStore>], states: &[Weak<ServerState>], max_memory: u64) {
    let mut inotify: Option<Inotify> = None;
    let mut polled: Vec<usize> = Vec::new();
    for (i, store) in stores.iter().enumerate() {
        let Some(store) = store.upgrade() else { return };
        let root = store.configured();
        match inotify_or_why(watch.mode, root).and_then(|()| watch_root(&mut inotify, stores.len(), i, root)) {
            Ok(directories) => {
                tracing::info!(root = %root.display(), watch = "inotify", directories, "watching the site files")
            }
            Err(reason) => {
                tracing::info!(
                    root = %root.display(),
                    watch = "poll",
                    every_ms = watch.poll.as_millis() as u64,
                    reason = %reason,
                    "watching the site files"
                );
                polled.push(i);
            }
        }
    }

    let mut next_poll = Instant::now() + watch.poll;
    // What changed between loading the files and watching them raised no event: one look now.
    let mut again: Option<Instant> = Some(Instant::now());
    let mut again_stores: FxHashSet<usize> = (0..stores.len()).collect();
    loop {
        let mut deadline = Instant::now() + ALIVE;
        if !polled.is_empty() {
            deadline = deadline.min(next_poll);
        }
        if let Some(at) = again {
            deadline = deadline.min(at);
        }
        let mut due: FxHashSet<usize> = FxHashSet::default();
        match &mut inotify {
            Some(notify) => notify.wait(deadline, &mut due),
            None => std::thread::sleep(deadline.saturating_duration_since(Instant::now())),
        }
        let now = Instant::now();
        if !polled.is_empty() && now >= next_poll {
            due.extend(polled.iter().copied());
            next_poll = now + watch.poll;
        }
        if again.is_some_and(|at| now >= at) {
            due.extend(again_stores.drain());
            again = None;
        }
        if states.iter().all(|state| state.strong_count() == 0) {
            return;
        }
        if due.is_empty() {
            continue;
        }
        let live: Vec<Option<Arc<FileStore>>> = stores.iter().map(Weak::upgrade).collect();
        let mut due: Vec<usize> = due.into_iter().collect();
        due.sort_unstable();
        let mut changed: Vec<Arc<FileStore>> = Vec::new();
        for i in due {
            let Some(store) = &live[i] else { continue };
            let root = store.configured();
            let others: u64 = live
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .filter_map(|(_, other)| other.as_ref())
                .map(|other| other.totals().stored)
                .sum();
            match store.rescan(max_memory.saturating_sub(others)) {
                Ok(found) => {
                    if found.unsettled > 0 {
                        again_stores.insert(i);
                        again = Some(now + AGAIN);
                    }
                    if found.replaced() {
                        tracing::info!(
                            root = %root.display(),
                            added = found.added,
                            changed = found.changed,
                            removed = found.removed,
                            files = found.totals.files,
                            in_memory = found.totals.stored,
                            ms = found.millis,
                            "site files changed"
                        );
                        // Until they are worked out again, the ready answers would be the old files'.
                        forget_answers(states, store);
                        changed.push(store.clone());
                    }
                }
                Err(e) => {
                    tracing::warn!(root = %root.display(), error = %e, "site files not read again; the loaded ones stay");
                }
            }
            if let Some(notify) = &mut inotify
                && notify.watches(i)
            {
                match notify.watch_tree(i, root) {
                    // What was made in a new directory before it was watched raised no event.
                    Ok(new) if new > 0 => {
                        again_stores.insert(i);
                        again = Some(now + AGAIN);
                    }
                    Ok(_) => {}
                    Err(e) => {
                        tracing::warn!(root = %root.display(), error = %e, "cannot watch it with inotify any more; polling");
                        notify.forget(i);
                        polled.push(i);
                    }
                }
            }
        }
        if !changed.is_empty() {
            prepare_answers(states, &changed);
            crate::release_free_memory();
        }
    }
}

/// Whether `root` is to be watched with inotify (`Err`: why it is polled instead).
fn inotify_or_why(mode: Mode, root: &Path) -> Result<(), String> {
    match mode {
        Mode::Poll => Err("WEB_FILES_WATCH=poll".to_string()),
        Mode::Inotify => Ok(()),
        Mode::Auto | Mode::Off => match filesystem(root) {
            Some((name, true)) => {
                tracing::debug!(root = %root.display(), filesystem = name, "a local filesystem");
                Ok(())
            }
            Some((name, false)) => Err(format!("{name}: changes made elsewhere raise no inotify event")),
            None => Err("a filesystem not known to report every change".to_string()),
        },
    }
}

/// `root` (store `i` of `roots`) watched with inotify; how many directories.
fn watch_root(inotify: &mut Option<Inotify>, roots: usize, i: usize, root: &Path) -> Result<usize, String> {
    if inotify.is_none() {
        *inotify = Some(Inotify::new(roots).map_err(|e| format!("no inotify: {e}"))?);
    }
    let notify = inotify.as_mut().expect("made just above");
    notify.watch_tree(i, root).map_err(|e| {
        notify.forget(i);
        format!("cannot watch it with inotify: {e}")
    })
}

/// The sites that read any of `changed`, on every server still running.
fn sites_reading(
    states: &[Weak<ServerState>],
    changed: &[Arc<FileStore>],
    mut each: impl FnMut(&ServerState, &crate::config::Site),
) {
    for state in states.iter().filter_map(Weak::upgrade) {
        for site in state.sites() {
            let mut stores = Vec::new();
            crate::memo::collect_stores(&site.routes, &mut stores);
            if stores.iter().any(|s| changed.iter().any(|c| Arc::ptr_eq(s, c))) {
                each(&state, site);
            }
        }
    }
}

fn forget_answers(states: &[Weak<ServerState>], store: &Arc<FileStore>) {
    sites_reading(states, std::slice::from_ref(store), |_, site| site.answers.store(None));
}

fn prepare_answers(states: &[Weak<ServerState>], changed: &[Arc<FileStore>]) {
    sites_reading(states, changed, |state, site| {
        let started = Instant::now();
        let answers = crate::memo::Answers::prepare(&site.routes, state.tls());
        if let Some(answers) = &answers {
            tracing::info!(
                hosts = ?site.hosts,
                paths = answers.paths(),
                answers = answers.answers(),
                memory_kib = answers.bytes() / 1024,
                ms = started.elapsed().as_millis() as u64,
                "ready answers worked out again"
            );
        }
        site.answers.store(answers.map(Arc::new));
    });
}

/// The filesystem `path` is on, and whether it reports every change (local); `None`: unknown.
#[cfg(target_os = "linux")]
fn filesystem(path: &Path) -> Option<(&'static str, bool)> {
    use std::os::unix::ffi::OsStrExt;
    const KNOWN: &[(u32, &str, bool)] = &[
        (0xEF53, "ext4", true),
        (0x5846_5342, "xfs", true),
        (0x9123_683E, "btrfs", true),
        (0x0102_1994, "tmpfs", true),
        (0x794C_7630, "overlay", true),
        (0x2FC1_2FC1, "zfs", true),
        (0xF2F5_2010, "f2fs", true),
        (0xCA45_1A4E, "bcachefs", true),
        (0x7371_7368, "squashfs", true),
        (0x8584_58F6, "ramfs", true),
        (0x5265_4973, "reiserfs", true),
        (0x3153_464A, "jfs", true),
        (0x5346_544E, "ntfs", true),
        (0x2011_BAB0, "exfat", true),
        (0x4D44, "vfat", true),
        (0x6969, "nfs", false),
        (0xFF53_4D42, "cifs", false),
        (0xFE53_4D42, "smb2", false),
        (0x517B, "smb", false),
        (0x6573_5546, "fuse", false),
        (0x0102_1997, "9p", false),
        (0x00C3_6400, "ceph", false),
        (0x0BD0_0BD0, "lustre", false),
        (0x4750_4653, "gpfs", false),
        (0x5346_414F, "afs", false),
    ];
    let path = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    // SAFETY: statfs fills the struct it is given (zeroed, a plain C struct) for a NUL-terminated
    // path; nothing is kept.
    let mut fs: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statfs(path.as_ptr(), &mut fs) } != 0 {
        return None;
    }
    let magic = fs.f_type as u64 as u32;
    KNOWN
        .iter()
        .find(|(m, _, _)| *m == magic)
        .map(|(_, name, local)| (*name, *local))
}

#[cfg(not(target_os = "linux"))]
fn filesystem(_path: &Path) -> Option<(&'static str, bool)> {
    None
}

#[cfg(target_os = "linux")]
use linux::Inotify;

#[cfg(target_os = "linux")]
mod linux {
    use super::{BURST, QUIET};
    use rustc_hash::{FxHashMap, FxHashSet};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;
    use std::path::{Path, PathBuf};
    use std::time::Instant;

    /// What a directory's watch reports: entries written and closed, created, moved in or out,
    /// deleted, changed (attributes too); the directory itself deleted or moved.
    const MASK: u32 = libc::IN_CLOSE_WRITE
        | libc::IN_MODIFY
        | libc::IN_ATTRIB
        | libc::IN_CREATE
        | libc::IN_DELETE
        | libc::IN_MOVED_FROM
        | libc::IN_MOVED_TO
        | libc::IN_DELETE_SELF
        | libc::IN_MOVE_SELF
        | libc::IN_ONLYDIR
        | libc::IN_EXCL_UNLINK;

    /// One inotify instance for every watched root: a watch per directory.
    pub struct Inotify {
        fd: OwnedFd,
        /// Watch → its root (store index) and directory.
        watches: FxHashMap<i32, (usize, PathBuf)>,
        /// Per root: the directories watched, and the root's real directory when they were.
        trees: Vec<Option<(PathBuf, FxHashSet<PathBuf>)>>,
    }

    impl Inotify {
        pub fn new(roots: usize) -> std::io::Result<Inotify> {
            // SAFETY: a plain syscall; the descriptor it returns is owned from here on.
            let fd = unsafe { libc::inotify_init1(libc::IN_CLOEXEC | libc::IN_NONBLOCK) };
            if fd < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(Inotify {
                // SAFETY: a new descriptor that nothing else owns.
                fd: unsafe { OwnedFd::from_raw_fd(fd) },
                watches: FxHashMap::default(),
                trees: (0..roots).map(|_| None).collect(),
            })
        }

        pub fn watches(&self, root: usize) -> bool {
            self.trees[root].is_some()
        }

        /// No more watching of `root` (its events, if any still come, are left alone).
        pub fn forget(&mut self, root: usize) {
            self.trees[root] = None;
            self.watches.retain(|_, (r, _)| *r != root);
        }

        /// Watches every directory under `root` not watched yet — and, when `root` is a symlink, the
        /// directory that holds it, so a switch to another directory is seen; how many are new.
        pub fn watch_tree(&mut self, root: usize, path: &Path) -> std::io::Result<usize> {
            let real = path.canonicalize()?;
            let mut tree = match self.trees[root].take() {
                // A root switched to another directory: the old tree's watches are no use.
                Some((was, dirs)) if was == real => dirs,
                _ => FxHashSet::default(),
            };
            let mut new = 0;
            if path.symlink_metadata()?.file_type().is_symlink()
                && let Some(parent) = path.parent()
                && tree.insert(parent.to_path_buf())
            {
                self.add(root, parent)?;
                new += 1;
            }
            for dir in crate::files::directories(path) {
                if tree.insert(dir.clone()) {
                    if let Err(e) = self.add(root, &dir) {
                        self.trees[root] = Some((real, tree));
                        return Err(e);
                    }
                    new += 1;
                }
            }
            self.trees[root] = Some((real, tree));
            Ok(new)
        }

        fn add(&mut self, root: usize, dir: &Path) -> std::io::Result<()> {
            let path = std::ffi::CString::new(dir.as_os_str().as_bytes())?;
            // SAFETY: a NUL-terminated path and our own descriptor.
            let wd = unsafe { libc::inotify_add_watch(self.fd.as_raw_fd(), path.as_ptr(), MASK) };
            if wd < 0 {
                return Err(std::io::Error::last_os_error());
            }
            self.watches.insert(wd, (root, dir.to_path_buf()));
            Ok(())
        }

        /// Waits until `deadline` for events; after the first, until none came for `QUIET` (at most
        /// `BURST` after the first). The roots they concern go into `due` — all of them when the
        /// kernel's queue overflowed.
        pub fn wait(&mut self, deadline: Instant, due: &mut FxHashSet<usize>) {
            let mut first: Option<Instant> = None;
            loop {
                let now = Instant::now();
                let until = match first {
                    None => deadline,
                    Some(at) => (now + QUIET).min(at + BURST),
                };
                if until <= now || !self.readable(until - now) {
                    return;
                }
                if self.drain(due) {
                    first.get_or_insert_with(Instant::now);
                }
            }
        }

        fn readable(&self, timeout: std::time::Duration) -> bool {
            let mut poll = libc::pollfd {
                fd: self.fd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            let millis = timeout.as_micros().div_ceil(1000).min(i32::MAX as u128) as i32;
            // SAFETY: one pollfd of our own.
            unsafe { libc::poll(&mut poll, 1, millis) > 0 }
        }

        /// Reads the queued events; whether any concerned a watched root.
        fn drain(&mut self, due: &mut FxHashSet<usize>) -> bool {
            const HEADER: usize = std::mem::size_of::<libc::inotify_event>();
            let mut any = false;
            // Aligned for the events' header.
            let mut buffer = [0u64; 1024];
            loop {
                // SAFETY: reads into our own buffer, at most its size.
                let n = unsafe {
                    libc::read(
                        self.fd.as_raw_fd(),
                        buffer.as_mut_ptr().cast(),
                        std::mem::size_of_val(&buffer),
                    )
                };
                if n <= 0 {
                    return any;
                }
                let n = n as usize;
                // SAFETY: the first n bytes were just written by the kernel.
                let bytes = unsafe { std::slice::from_raw_parts(buffer.as_ptr().cast::<u8>(), n) };
                let mut offset = 0;
                while offset + HEADER <= n {
                    // SAFETY: a whole header lies at offset (the kernel writes whole events).
                    let event: libc::inotify_event =
                        unsafe { std::ptr::read_unaligned(bytes[offset..].as_ptr().cast()) };
                    offset += HEADER + event.len as usize;
                    if event.mask & libc::IN_Q_OVERFLOW != 0 {
                        due.extend((0..self.trees.len()).filter(|r| self.trees[*r].is_some()));
                        any = true;
                    } else if event.mask & libc::IN_IGNORED != 0 {
                        // The directory went: watched again if it comes back.
                        if let Some((root, dir)) = self.watches.remove(&event.wd)
                            && let Some((_, tree)) = &mut self.trees[root]
                        {
                            tree.remove(&dir);
                        }
                    } else if let Some((root, _)) = self.watches.get(&event.wd)
                        && self.trees[*root].is_some()
                    {
                        due.insert(*root);
                        any = true;
                    }
                }
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
struct Inotify;

#[cfg(not(target_os = "linux"))]
impl Inotify {
    fn new(_roots: usize) -> std::io::Result<Inotify> {
        Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "Linux only"))
    }
    fn watches(&self, _root: usize) -> bool {
        false
    }
    fn forget(&mut self, _root: usize) {}
    fn watch_tree(&mut self, _root: usize, _path: &Path) -> std::io::Result<usize> {
        Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "Linux only"))
    }
    fn wait(&mut self, deadline: Instant, _due: &mut FxHashSet<usize>) {
        std::thread::sleep(deadline.saturating_duration_since(Instant::now()));
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn inotify_tells_of_changes_in_new_directories_too() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.txt"), "a").unwrap();
        let mut notify = Inotify::new(1).unwrap();
        assert_eq!(notify.watch_tree(0, dir.path()).unwrap(), 1);
        let mut due = FxHashSet::default();
        notify.wait(Instant::now() + Duration::from_millis(50), &mut due);
        assert!(due.is_empty(), "nothing happened");

        std::fs::write(dir.path().join("a.txt"), "b").unwrap();
        notify.wait(Instant::now() + Duration::from_secs(5), &mut due);
        assert!(due.contains(&0), "a write");

        due.clear();
        std::fs::create_dir(dir.path().join("sub")).unwrap();
        notify.wait(Instant::now() + Duration::from_secs(5), &mut due);
        assert!(due.contains(&0), "a new directory");
        assert_eq!(notify.watch_tree(0, dir.path()).unwrap(), 1, "watched from now on");
        due.clear();
        std::fs::write(dir.path().join("sub/b.txt"), "b").unwrap();
        notify.wait(Instant::now() + Duration::from_secs(5), &mut due);
        assert!(due.contains(&0), "a file in it");
    }

    #[test]
    fn the_temporary_directory_is_on_a_local_filesystem() {
        // tmpfs, overlay (in a container) or a disk.
        let (name, local) = filesystem(&std::env::temp_dir()).expect("a known filesystem");
        assert!(local, "{name}");
    }
}
