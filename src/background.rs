//! What the extensions' background work shares (docs/extensions.md): a `Worker`, one thread with
//! a bounded queue of jobs and a periodic tick, and a `Budget`, memory bounded by CLOCK eviction.
//! Both are generic over what they carry, so each use is monomorphised: no dynamic dispatch, and
//! nothing of them on the request path but a `try_send` and an atomic mark.

use std::collections::VecDeque;
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// A thread of its own with a current-thread runtime: `run` on each job as it comes, `tick`
/// every `every` with the jobs not taken since the last. The queue holds `queue` jobs; a job that
/// finds it full is given back
/// (`submit`) and counted, so a burst slows nothing but what the worker does.
pub struct Worker<J> {
    jobs: tokio::sync::mpsc::Sender<J>,
    dropped: Arc<AtomicU64>,
}

impl<J: Send + 'static> Worker<J> {
    /// `nice`: how far below the requests' threads the worker runs (Linux; 0: the same).
    pub fn start<R, F, T>(name: &'static str, queue: usize, nice: i32, every: Duration, mut run: R, mut tick: T) -> Worker<J>
    where
        R: FnMut(J) -> F + Send + 'static,
        F: Future<Output = ()>,
        T: FnMut(u64) + Send + 'static,
    {
        let (jobs, mut taken) = tokio::sync::mpsc::channel::<J>(queue.max(1));
        let dropped = Arc::new(AtomicU64::new(0));
        let counted = dropped.clone();
        let spawned = std::thread::Builder::new().name(name.into()).spawn(move || {
            lower_priority(nice);
            let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
                Ok(runtime) => runtime,
                Err(e) => {
                    tracing::error!(thread = name, error = %e, "the background thread cannot start its runtime: its work is not done");
                    return;
                }
            };
            runtime.block_on(async move {
                let mut ticks = tokio::time::interval(every);
                ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                ticks.tick().await;
                loop {
                    tokio::select! {
                        job = taken.recv() => match job {
                            Some(job) => run(job).await,
                            None => return,
                        },
                        _ = ticks.tick() => tick(counted.swap(0, Ordering::Relaxed)),
                    }
                }
            });
        });
        if let Err(e) = spawned {
            // The receiver is gone with the thread: every `submit` fails and is counted.
            tracing::error!(thread = name, error = %e, "the background thread cannot start: its work is not done");
        }
        Worker {
            jobs,
            dropped,
        }
    }

    /// Queues `job`; a full queue (or a worker that could not start) gives it back and counts it.
    pub fn submit(&self, job: J) -> Result<(), J> {
        self.jobs.try_send(job).map_err(|e| {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            match e {
                tokio::sync::mpsc::error::TrySendError::Full(job) | tokio::sync::mpsc::error::TrySendError::Closed(job) => job,
            }
        })
    }
}

/// The calling thread's priority lowered by `nice` (Linux: setpriority on the thread; nothing
/// elsewhere, and nothing for 0).
fn lower_priority(nice: i32) {
    #[cfg(target_os = "linux")]
    if nice != 0 {
        // SAFETY: setpriority on the calling thread (who = 0 names it on Linux) changes only its nice.
        unsafe {
            libc::setpriority(libc::PRIO_PROCESS, 0, nice);
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = nice;
}

/// Memory bounded by CLOCK eviction: the entries in the order they came, their sizes summed; past
/// the budget the first entry not asked for since the eviction last passed it goes, and one that
/// was gets another round. The owner keeps the entries themselves (and their marks) however its
/// readers need them; the budget keeps the order and the sum.
pub struct Budget<K> {
    order: VecDeque<K>,
    used: usize,
}

/// What the owner says of an entry when its turn comes in a pass.
pub enum Seen {
    /// Already gone (removed elsewhere): forgotten.
    Gone,
    /// Asked for since the last pass: another round.
    Marked,
    /// Evicted by the owner, this many bytes.
    Evicted(usize),
}

impl<K> Default for Budget<K> {
    fn default() -> Self {
        Budget::new()
    }
}

impl<K> Budget<K> {
    pub const fn new() -> Budget<K> {
        Budget {
            order: VecDeque::new(),
            used: 0,
        }
    }

    pub fn used(&self) -> usize {
        self.used
    }

    pub fn len(&self) -> usize {
        self.order.len()
    }

    pub fn is_empty(&self) -> bool {
        self.order.is_empty()
    }

    /// An entry put in place: last in the order, its size counted.
    pub fn add(&mut self, key: K, size: usize) {
        self.used += size;
        self.order.push_back(key);
    }

    /// Bytes of entries the owner removed on its own (replaced, swept); their keys are forgotten
    /// when their turn comes (`Seen::Gone`) or on `retain`.
    pub fn release(&mut self, size: usize) {
        self.used = self.used.saturating_sub(size);
    }

    /// A CLOCK pass while `used` is over `max`: the owner is asked about each entry in turn, at
    /// most twice around, so a store whose every entry is marked still ends.
    pub fn evict(&mut self, max: usize, mut look: impl FnMut(&K) -> Seen) {
        let mut passes = self.order.len() * 2;
        while self.used > max && passes > 0 {
            passes -= 1;
            let Some(key) = self.order.pop_front() else { break };
            match look(&key) {
                Seen::Gone => {}
                Seen::Marked => self.order.push_back(key),
                Seen::Evicted(size) => self.used = self.used.saturating_sub(size),
            }
        }
    }

    /// Forgets the keys `keep` refuses (entries the owner swept).
    pub fn retain(&mut self, keep: impl FnMut(&K) -> bool) {
        self.order.retain(keep);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn the_entries_not_asked_for_go_first_and_a_mark_buys_one_round() {
        let mut entries: HashMap<u32, (usize, bool)> = (0..4).map(|i| (i, (100, i % 2 == 1))).collect();
        let mut budget = Budget::new();
        for i in 0..4 {
            budget.add(i, 100);
        }
        assert_eq!(budget.used(), 400);
        let pass = |budget: &mut Budget<u32>, max: usize, entries: &mut HashMap<u32, (usize, bool)>| {
            budget.evict(max, |key| {
                let Some((size, marked)) = entries.get_mut(key) else {
                    return Seen::Gone;
                };
                if std::mem::take(marked) {
                    return Seen::Marked;
                }
                let size = *size;
                entries.remove(key);
                Seen::Evicted(size)
            });
        };
        pass(&mut budget, 250, &mut entries);
        let mut kept: Vec<u32> = entries.keys().copied().collect();
        kept.sort_unstable();
        assert_eq!(kept, [1, 3], "the marked ones stay");
        assert_eq!(budget.used(), 200);
        // Their marks are spent: the next pass may take them.
        pass(&mut budget, 100, &mut entries);
        assert_eq!(entries.len(), 1);
        assert_eq!(budget.used(), 100);
        // An entry the owner removed on its own: its bytes released, its key forgotten on retain.
        entries.clear();
        budget.release(100);
        budget.retain(|key| entries.contains_key(key));
        assert!(budget.is_empty() && budget.used() == 0);
    }

    #[test]
    fn a_worker_runs_its_jobs_and_ticks_and_gives_back_what_it_cannot_take() {
        use std::sync::Arc;
        use std::sync::atomic::AtomicUsize;
        let ran = Arc::new(AtomicUsize::new(0));
        let ticked = Arc::new(AtomicUsize::new(0));
        let worker = {
            let (ran, ticked) = (ran.clone(), ticked.clone());
            Worker::start(
                "test-worker",
                2,
                0,
                Duration::from_millis(5),
                move |n: usize| {
                    let ran = ran.clone();
                    async move {
                        ran.fetch_add(n, Ordering::Relaxed);
                    }
                },
                move |_| {
                    ticked.fetch_add(1, Ordering::Relaxed);
                },
            )
        };
        assert!(worker.submit(1).is_ok());
        let started = std::time::Instant::now();
        while ran.load(Ordering::Relaxed) < 1 || ticked.load(Ordering::Relaxed) < 2 {
            assert!(started.elapsed() < Duration::from_secs(5));
            std::thread::sleep(Duration::from_millis(5));
        }
        // More than the queue holds at once: the rest come back.
        let given_back = (0..50).filter(|_| worker.submit(1).is_err()).count();
        assert!(given_back > 0);
    }
}
