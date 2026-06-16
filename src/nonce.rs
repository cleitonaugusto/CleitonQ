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
//! both operations safe to call from multiple threads — e.g. a vehicle with
//! independent control loops for attitude, navigation, and telemetry all
//! signing on the same channel.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Generates strictly increasing nonces, safe to share across threads.
///
/// Construct with [`AtomicNonce::from_time`] when there's no persisted
/// last-nonce state to resume from (e.g. first boot, or storage wiped).
/// Seeding from wall-clock time — rather than 0 — means a process restart
/// produces nonces higher than anything emitted before the restart in the
/// overwhelmingly common case, narrowing (but not eliminating) the replay
/// window described in `tests/mitm_active.rs::mitm_cross_session_replay_rejected_by_nonce`.
/// Persisting and resuming the exact last nonce remains the only complete
/// fix; this is a pragmatic default when that isn't implemented yet.
pub struct AtomicNonce(AtomicU64);

impl AtomicNonce {
    /// Starts the sequence at `start`. The first call to [`Self::next`]
    /// returns `start`, not `start + 1` — `start` itself is a valid nonce.
    pub fn new(start: u64) -> Self {
        Self(AtomicU64::new(start))
    }

    /// Seeds from nanoseconds since the Unix epoch, truncated to fit `u64`
    /// (wraps roughly every 584 years — not a practical concern).
    pub fn from_time() -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        Self::new(nanos as u64)
    }

    /// Atomically returns the next nonce in the sequence. Safe to call
    /// concurrently from any number of threads — every call returns a
    /// distinct, strictly increasing value.
    pub fn next(&self) -> u64 {
        self.0.fetch_add(1, Ordering::Relaxed)
    }
}

/// Tracks the last accepted nonce for anti-replay checks, safe to share
/// across threads receiving on the same channel concurrently.
///
/// Plain `if nonce > last_nonce { last_nonce = nonce }` races: two threads
/// can both read the old value, both decide to accept, and both write —
/// the second write clobbers the first with no error, silently widening
/// the replay window. [`Self::accept`] does the compare-and-update
/// atomically so concurrent receivers can't both accept the same nonce
/// or regress `last_nonce` backwards.
pub struct NonceTracker(AtomicU64);

impl NonceTracker {
    /// Starts tracking from `last_accepted` (use `0` if nothing has been
    /// accepted yet — matches the convention used by `verify(..., 0)`
    /// throughout `channel.rs`/`dsa.rs`).
    pub fn new(last_accepted: u64) -> Self {
        Self(AtomicU64::new(last_accepted))
    }

    /// Atomically checks whether `nonce` is newer than the last accepted
    /// nonce, and if so, records it as the new last-accepted value.
    /// Returns `true` iff `nonce` should be treated as valid (not a
    /// replay). Call this instead of `verify(packet, my_last_nonce)`'s
    /// nonce check when multiple threads verify packets on the same
    /// channel concurrently.
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn atomic_nonce_strictly_increasing() {
        let n = AtomicNonce::new(0);
        let a = n.next();
        let b = n.next();
        let c = n.next();
        assert!(a < b && b < c);
    }

    #[test]
    fn atomic_nonce_first_call_returns_start() {
        let n = AtomicNonce::new(42);
        assert_eq!(n.next(), 42);
        assert_eq!(n.next(), 43);
    }

    #[test]
    fn atomic_nonce_from_time_is_nonzero_and_increasing() {
        let n = AtomicNonce::from_time();
        let a = n.next();
        let b = n.next();
        assert!(a > 0);
        assert!(b > a);
    }

    #[test]
    fn atomic_nonce_no_duplicates_under_concurrency() {
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

    #[test]
    fn nonce_tracker_rejects_replay_and_regression() {
        let t = NonceTracker::new(0);
        assert!(t.accept(5));
        assert!(!t.accept(5), "exact replay must be rejected");
        assert!(!t.accept(3), "regression below last-accepted must be rejected");
        assert!(t.accept(6));
        assert_eq!(t.last_accepted(), 6);
    }

    #[test]
    fn nonce_tracker_no_double_accept_under_concurrency() {
        // Many threads race to accept the same small set of nonces; exactly
        // one thread per distinct nonce value must win.
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
}
