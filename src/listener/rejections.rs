//! Counts of DoH and DoH3 requests refused before reaching the handler (a
//! wrong path, missing or wrong Basic Auth credentials, an unsupported
//! method), so a misconfiguration that turns every client away shows up in
//! the logs and stats instead of passing silently.
//!
//! Each rejection is logged at `debug`; a background thread logs a summary
//! at `warn` at most once every [`REPORT_EVERY`], and only when something
//! was rejected, so scanners can't flood the journal.
//!
//! The counters only grow. Readers (the warn summary, the stats records)
//! each keep their own [`RejectionCounts`] snapshot and report the
//! difference, so neither resets what the other sees.

use std::fmt;
use std::net::SocketAddr;
use std::sync::Once;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// How often the warn summary may be logged.
const REPORT_EVERY: Duration = Duration::from_secs(60);

/// The listener that refused a request, named as in the stats `proto` key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Listener {
    /// DoH over HTTP/1.1 or HTTP/2.
    Https,
    /// DoH over HTTP/3.
    H3,
}

impl Listener {
    const ALL: [Self; 2] = [Self::Https, Self::H3];

    /// The name used in stats keys and logs.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Https => "https",
            Self::H3 => "h3",
        }
    }
}

/// Why a request was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rejection {
    /// The path isn't one of the configured routes (404).
    NotFound,
    /// Basic Auth is required and the request didn't pass it (401).
    Unauthorized,
    /// Neither GET nor POST (405).
    MethodNotAllowed,
}

impl Rejection {
    const ALL: [Self; 3] = [Self::NotFound, Self::Unauthorized, Self::MethodNotAllowed];

    /// The HTTP status the request was answered with.
    pub fn status(self) -> u16 {
        match self {
            Self::NotFound => 404,
            Self::Unauthorized => 401,
            Self::MethodNotAllowed => 405,
        }
    }
}

const SLOTS: usize = Listener::ALL.len() * Rejection::ALL.len();

static COUNTS: [AtomicU64; SLOTS] = [const { AtomicU64::new(0) }; SLOTS];

static REPORTER: Once = Once::new();

fn slot(listener: Listener, why: Rejection) -> usize {
    let l = Listener::ALL.iter().position(|&x| x == listener);
    let r = Rejection::ALL.iter().position(|&x| x == why);
    l.zip(r)
        .map(|(l, r)| l * Rejection::ALL.len() + r)
        .expect("ALL lists every variant")
}

/// Counts and logs one request `listener` refused from `peer`.
pub(crate) fn note(listener: Listener, why: Rejection, peer: SocketAddr) {
    COUNTS[slot(listener, why)].fetch_add(1, Ordering::Relaxed);
    let proto = listener.as_str();
    let status = why.status();
    tracing::debug!(%peer, proto, status, "rejected doh request");
    REPORTER.call_once(spawn_reporter);
}

/// Starts the thread behind the warn summary. A plain thread rather than a
/// task, so it doesn't depend on which runtime saw the first rejection. Its
/// first summary comes right away, covering that first rejection.
fn spawn_reporter() {
    let spawned = std::thread::Builder::new()
        .name("doh-rejections".to_owned())
        .spawn(|| {
            let secs = REPORT_EVERY.as_secs();
            let mut last = RejectionCounts::default();
            loop {
                let now = RejectionCounts::now();
                let delta = now.since(&last);
                if !delta.is_empty() {
                    tracing::warn!("rejected doh requests in the last {secs}s: {delta}");
                }
                last = now;
                std::thread::sleep(REPORT_EVERY);
            }
        });
    if let Err(e) = spawned {
        tracing::warn!(error = %e, "starting the rejected-request reporter failed");
    }
}

/// A snapshot of the rejection counters, or the difference of two.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RejectionCounts([u64; SLOTS]);

impl RejectionCounts {
    /// The counts since the process started.
    pub fn now() -> Self {
        Self(std::array::from_fn(|i| COUNTS[i].load(Ordering::Relaxed)))
    }

    /// The counts added between `earlier` and `self`.
    pub fn since(&self, earlier: &Self) -> Self {
        Self(std::array::from_fn(|i| {
            self.0[i].saturating_sub(earlier.0[i])
        }))
    }

    /// Whether every count is zero.
    pub fn is_empty(&self) -> bool {
        self.0.iter().all(|&n| n == 0)
    }

    /// The count for one listener and reason.
    pub fn get(&self, listener: Listener, why: Rejection) -> u64 {
        self.0[slot(listener, why)]
    }

    /// The nonzero counts.
    pub fn iter(&self) -> impl Iterator<Item = (Listener, Rejection, u64)> + '_ {
        Listener::ALL
            .into_iter()
            .flat_map(|l| Rejection::ALL.into_iter().map(move |r| (l, r)))
            .map(|(l, r)| (l, r, self.get(l, r)))
            .filter(|&(_, _, n)| n > 0)
    }
}

/// `https_401=312 h3_404=3`.
impl fmt::Display for RejectionCounts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, (listener, why, n)) in self.iter().enumerate() {
            let sep = if i == 0 { "" } else { " " };
            let proto = listener.as_str();
            let status = why.status();
            write!(f, "{sep}{proto}_{status}={n}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slots_are_distinct() {
        let mut seen = [false; SLOTS];
        for l in Listener::ALL {
            for r in Rejection::ALL {
                let i = slot(l, r);
                assert!(!seen[i], "{l:?} {r:?}");
                seen[i] = true;
            }
        }
        assert!(seen.iter().all(|&s| s));
    }

    #[test]
    fn diffs_and_formats_nonzero_counts() {
        let mut earlier = RejectionCounts::default();
        earlier.0[slot(Listener::Https, Rejection::Unauthorized)] = 2;
        let mut later = earlier;
        later.0[slot(Listener::Https, Rejection::Unauthorized)] = 314;
        later.0[slot(Listener::H3, Rejection::NotFound)] = 3;

        let delta = later.since(&earlier);
        assert_eq!(delta.get(Listener::Https, Rejection::Unauthorized), 312);
        assert_eq!(delta.to_string(), "https_401=312 h3_404=3");
        assert!(later.since(&later).is_empty());
        assert_eq!(later.since(&later).to_string(), "");
    }
}
