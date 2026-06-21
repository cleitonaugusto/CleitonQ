// Copyright (c) 2026 Cleiton Augusto Correa Bezerra. Licensed under MIT OR Apache-2.0.

//! Thread-safe nonce generation and tracking for concurrent control loops.
//!
//! [`crate::channel::AuthChannel::sign`] and [`crate::dsa::SigningKey::sign`]
//! take a caller-supplied `u64` nonce — correct, but unsafe to share across
//! threads without external synchronization: two threads computing "last
//! nonce + 1" from a plain `u64` can race and emit the same nonce twice,
//! which the receiver would then treat as a replay (or worse, if the first
//! copy is dropped due to packet loss, silently lose a command).
//!
//! [`AtomicNonce`] (sender side) and [`NonceTracker`] (receiver side) make
//! both operations safe to call from multiple threads on platforms with
//! 64-bit atomic support (`target_has_atomic = "64"`). On Cortex-M4 and
//! other 32-bit-only platforms, use [`SimpleNonce`] and [`SimpleNonceTracker`]
//! instead — they are not thread-safe but carry no platform constraints.

// ── Atomic implementation (x86-64, ARM64, Cortex-M33 with atomics) ────────────

#[cfg(target_has_atomic = "64")]
use core::sync::atomic::{AtomicU64, Ordering};

/// Generates strictly increasing nonces, safe to share across threads.
///
/// Available on platforms with 64-bit atomic support. For Cortex-M4 and
/// other 32-bit-only targets, use [`SimpleNonce`] instead.
#[cfg(target_has_atomic = "64")]
pub struct AtomicNonce(AtomicU64);

#[cfg(target_has_atomic = "64")]
impl AtomicNonce {
    /// Starts the sequence at `start`. The first call to [`Self::next`]
    /// returns `start`, not `start + 1` — `start` itself is a valid nonce.
    pub fn new(start: u64) -> Self {
        Self(AtomicU64::new(start))
    }

    /// Seeds from nanoseconds since the Unix epoch.
    ///
    /// Seeding from wall-clock time — rather than 0 — means a process restart
    /// produces nonces higher than anything emitted before the restart in the
    /// overwhelmingly common case.
    #[cfg(feature = "std")]
    pub fn from_time() -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        Self::new(nanos as u64)
    }

    /// Atomically returns the next nonce. Safe to call from multiple threads.
    pub fn next(&self) -> u64 {
        self.0.fetch_add(1, Ordering::Relaxed)
    }
}

/// Tracks the last accepted nonce for anti-replay checks, safe to share
/// across threads receiving on the same channel concurrently.
///
/// Available on platforms with 64-bit atomic support. For Cortex-M4 and
/// other 32-bit-only targets, use [`SimpleNonceTracker`] instead.
#[cfg(target_has_atomic = "64")]
pub struct NonceTracker(AtomicU64);

#[cfg(target_has_atomic = "64")]
impl NonceTracker {
    /// Starts tracking from `last_accepted` (use `0` if nothing has been accepted yet).
    pub fn new(last_accepted: u64) -> Self {
        Self(AtomicU64::new(last_accepted))
    }

    /// Atomically accepts `nonce` iff it is strictly greater than the last accepted value.
    pub fn accept(&self, nonce: u64) -> bool {
        let mut current = self.0.load(Ordering::Acquire);
        loop {
            if nonce <= current {
                return false;
            }
            match self.0.compare_exchange(current, nonce, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => return true,
                Err(observed) => current = observed,
            }
        }
    }

    /// Returns the current last-accepted nonce.
    pub fn last_accepted(&self) -> u64 {
        self.0.load(Ordering::Acquire)
    }
}

// ── Single-threaded implementation (Cortex-M4, embedded without 64-bit atomics) ─

/// Generates strictly increasing nonces for single-threaded embedded use.
///
/// Not thread-safe. For multi-threaded use, use [`AtomicNonce`] on platforms
/// that support 64-bit atomics.
pub struct SimpleNonce(u64);

impl SimpleNonce {
    pub fn new(start: u64) -> Self {
        Self(start)
    }

    pub fn next(&mut self) -> u64 {
        let v = self.0;
        self.0 = self.0.wrapping_add(1);
        v
    }
}

/// Tracks the last accepted nonce for single-threaded embedded use.
///
/// Not thread-safe. For multi-threaded use, use [`NonceTracker`] on platforms
/// that support 64-bit atomics.
pub struct SimpleNonceTracker(u64);

impl SimpleNonceTracker {
    pub fn new(last_accepted: u64) -> Self {
        Self(last_accepted)
    }

    pub fn accept(&mut self, nonce: u64) -> bool {
        if nonce <= self.0 {
            return false;
        }
        self.0 = nonce;
        true
    }

    pub fn last_accepted(&self) -> u64 {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_has_atomic = "64")]
    #[test]
    fn atomic_nonce_strictly_increasing() {
        let n = AtomicNonce::new(0);
        let a = n.next();
        let b = n.next();
        let c = n.next();
        assert!(a < b && b < c);
    }

    #[cfg(target_has_atomic = "64")]
    #[test]
    fn atomic_nonce_first_call_returns_start() {
        let n = AtomicNonce::new(42);
        assert_eq!(n.next(), 42);
        assert_eq!(n.next(), 43);
    }

    #[cfg(all(target_has_atomic = "64", feature = "std"))]
    #[test]
    fn atomic_nonce_from_time_is_nonzero_and_increasing() {
        let n = AtomicNonce::from_time();
        let a = n.next();
        let b = n.next();
        assert!(a > 0);
        assert!(b > a);
    }

    #[cfg(all(target_has_atomic = "64", feature = "std"))]
    #[test]
    fn atomic_nonce_no_duplicates_under_concurrency() {
        use std::collections::HashSet;
        use std::sync::Arc;
        use std::thread;

        let n = Arc::new(AtomicNonce::new(0));
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let n = Arc::clone(&n);
                thread::spawn(move || (0..1000).map(|_| n.next()).collect::<Vec<_>>())
            })
            .collect();

        let mut all = HashSet::new();
        for t in threads {
            for nonce in t.join().unwrap() {
                assert!(all.insert(nonce), "nonce {nonce} emitted twice — race in AtomicNonce::next");
            }
        }
        assert_eq!(all.len(), 8000);
    }

    #[cfg(target_has_atomic = "64")]
    #[test]
    fn nonce_tracker_rejects_replay_and_regression() {
        let t = NonceTracker::new(0);
        assert!(t.accept(5));
        assert!(!t.accept(5), "exact replay must be rejected");
        assert!(!t.accept(3), "regression below last-accepted must be rejected");
        assert!(t.accept(6));
        assert_eq!(t.last_accepted(), 6);
    }

    #[cfg(all(target_has_atomic = "64", feature = "std"))]
    #[test]
    fn nonce_tracker_no_double_accept_under_concurrency() {
        use std::sync::Arc;
        use std::thread;

        let tracker = Arc::new(NonceTracker::new(0));
        let nonces: Vec<u64> = (1..=500).collect();

        let threads: Vec<_> = (0..4)
            .map(|_| {
                let tracker = Arc::clone(&tracker);
                let nonces = nonces.clone();
                thread::spawn(move || {
                    nonces.iter().filter(|&&n| tracker.accept(n)).count()
                })
            })
            .collect();

        let total_accepted: usize = threads.into_iter().map(|t| t.join().unwrap()).sum();
        assert_eq!(total_accepted, 500, "each nonce must be accepted exactly once across all threads");
        assert_eq!(tracker.last_accepted(), 500);
    }

    #[test]
    fn simple_nonce_strictly_increasing() {
        let mut n = SimpleNonce::new(0);
        let a = n.next();
        let b = n.next();
        let c = n.next();
        assert!(a < b && b < c);
    }

    #[test]
    fn simple_nonce_tracker_rejects_replay() {
        let mut t = SimpleNonceTracker::new(0);
        assert!(t.accept(5));
        assert!(!t.accept(5));
        assert!(!t.accept(3));
        assert!(t.accept(6));
        assert_eq!(t.last_accepted(), 6);
    }
}
