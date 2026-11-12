//! In-process fixed-window rate limiter.
//!
//! Deliberately simple and dependency free: good enough to blunt credential
//! stuffing on a single node. For a multi-node deployment swap this for Redis
//! (`INCR` + `EXPIRE`) behind the same `check` signature.

use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};

#[derive(Debug)]
struct Window {
    started: Instant,
    count: u32,
}

#[derive(Debug, Default)]
pub struct RateLimiter {
    windows: Mutex<HashMap<String, Window>>,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a hit for `scope:identity` and returns `Err(retry_after_secs)`
    /// when the caller exceeded `limit` inside `window`.
    pub fn check(
        &self,
        scope: &str,
        identity: &str,
        limit: u32,
        window: Duration,
    ) -> Result<(), u64> {
        if limit == 0 || window.is_zero() {
            return Ok(());
        }
        let key = format!("{scope}:{identity}");
        let now = Instant::now();
        let mut windows = self.windows.lock().expect("rate limiter poisoned");

        if windows.len() > 20_000 {
            windows.retain(|_, w| now.duration_since(w.started) < Duration::from_secs(3600));
        }

        let entry = windows.entry(key).or_insert(Window {
            started: now,
            count: 0,
        });

        if now.duration_since(entry.started) >= window {
            entry.started = now;
            entry.count = 0;
        }

        entry.count += 1;
        if entry.count > limit {
            let elapsed = now.duration_since(entry.started).as_secs_f64();
            let retry_after = (window.as_secs_f64() - elapsed).max(1.0).ceil() as u64;
            Err(retry_after)
        } else {
            Ok(())
        }
    }

    /// Clears a bucket, e.g. after a successful login.
    pub fn reset(&self, scope: &str, identity: &str) {
        let key = format!("{scope}:{identity}");
        if let Ok(mut windows) = self.windows.lock() {
            windows.remove(&key);
        }
    }

    pub fn tracked_keys(&self) -> usize {
        self.windows.lock().map(|w| w.len()).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_after_limit() {
        let limiter = RateLimiter::new();
        let window = Duration::from_secs(60);
        for _ in 0..3 {
            assert!(limiter.check("login", "1.2.3.4", 3, window).is_ok());
        }
        let err = limiter.check("login", "1.2.3.4", 3, window).unwrap_err();
        assert!(err >= 1);
        // A different identity has its own bucket.
        assert!(limiter.check("login", "5.6.7.8", 3, window).is_ok());
    }
}
