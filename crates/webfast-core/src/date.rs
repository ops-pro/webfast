//! The `Date` response header, one value for all threads: a background thread formats it just after
//! every second starts, and responses take it without reading the clock. HTTP dates have a
//! resolution of one second, so the value is exact for the whole second it was made in.
//!
//! Each thread keeps its own copy of the bytes, refreshed when the second changes: taking the value
//! is a clone of that copy, which never contends with other threads.

use http::HeaderValue;
use std::cell::RefCell;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

struct Shared {
    /// The Unix second `value` was formatted for.
    second: AtomicU64,
    value: Mutex<HeaderValue>,
}

static SHARED: OnceLock<Shared> = OnceLock::new();

thread_local! {
    static LOCAL: RefCell<Option<(u64, HeaderValue)>> = const { RefCell::new(None) };
}

/// Starts the updating thread (also done by the first [`now`]).
pub fn start() {
    shared();
}

/// The current value of the `Date` header (IMF-fixdate, RFC 9110 §5.6.7).
pub fn now() -> HeaderValue {
    let shared = shared();
    let second = shared.second.load(Ordering::Acquire);
    LOCAL.with(|local| {
        let mut local = local.borrow_mut();
        if let Some((cached, value)) = &*local
            && *cached == second
        {
            return value.clone();
        }
        let value = shared.value.lock().unwrap_or_else(PoisonError::into_inner);
        // This thread's own bytes: its clones count references on them, not on a shared copy.
        let copy = HeaderValue::from_bytes(value.as_bytes()).expect("a valid header value");
        drop(value);
        *local = Some((second, copy.clone()));
        copy
    })
}

fn shared() -> &'static Shared {
    SHARED.get_or_init(|| {
        let (second, value) = format(SystemTime::now());
        std::thread::Builder::new()
            .name("web-date".into())
            .spawn(update_every_second)
            .expect("cannot start the thread that keeps the Date header");
        Shared {
            second: AtomicU64::new(second),
            value: Mutex::new(value),
        }
    })
}

fn update_every_second() {
    // Waits here until `shared()` has finished initialising.
    let shared = shared();
    loop {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
        std::thread::sleep(Duration::from_nanos(1_000_000_000 - u64::from(now.subsec_nanos())));
        let (second, value) = format(SystemTime::now());
        if second != shared.second.load(Ordering::Relaxed) {
            *shared.value.lock().unwrap_or_else(PoisonError::into_inner) = value;
            shared.second.store(second, Ordering::Release);
        }
    }
}

fn format(now: SystemTime) -> (u64, HeaderValue) {
    let second = now.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
    let value = HeaderValue::from_str(&httpdate::fmt_http_date(now)).expect("an HTTP date is ASCII");
    (second, value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_date_is_current_and_follows_the_clock() {
        let parse = |v: HeaderValue| httpdate::parse_http_date(v.to_str().unwrap()).unwrap();
        let before = SystemTime::now() - Duration::from_secs(1);
        let first = parse(now());
        assert!(first >= before && first <= SystemTime::now());
        // The updating thread moves it on with the clock.
        std::thread::sleep(Duration::from_millis(2100));
        let later = parse(now());
        assert!(later.duration_since(first).unwrap() >= Duration::from_secs(2));
        assert!(later <= SystemTime::now());
    }

    #[test]
    fn threads_see_the_same_value() {
        let here = now();
        let there = std::thread::spawn(now).join().unwrap();
        // Unless the second changed in between.
        let again = now();
        assert!(there == here || there == again);
    }
}
