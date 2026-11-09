//! Graceful shutdown: waiting for SIGINT/SIGTERM and for in-flight queries
//! to finish before the process exits.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use hickory_proto::op::Message;
use tokio::sync::Notify;

use crate::listener::io::Handler;

/// Counts queries being handled, so shutdown can wait for them.
#[derive(Default)]
pub struct InFlight {
    count: AtomicUsize,
    idle: Notify,
}

impl InFlight {
    /// Wraps `handler` so every query it handles is counted until its
    /// response is ready. Wrap outermost (outside the stats wrapper),
    /// so a query's stats are recorded before it stops counting.
    pub fn wrap(self: &Arc<Self>, handler: Handler) -> Handler {
        let in_flight = Arc::clone(self);
        Arc::new(move |req: Message| {
            let handler = Arc::clone(&handler);
            in_flight.count.fetch_add(1, Ordering::SeqCst);
            let guard = Guard(Arc::clone(&in_flight));
            Box::pin(async move {
                let _guard = guard;
                handler(req).await
            })
        })
    }

    /// The number of queries being handled.
    pub fn count(&self) -> usize {
        self.count.load(Ordering::SeqCst)
    }

    /// Waits until no query is being handled, for at most `timeout`.
    /// Returns whether that happened in time.
    pub async fn wait_idle(&self, timeout: Duration) -> bool {
        tokio::time::timeout(timeout, async {
            loop {
                // Created before the check, so a wakeup between the check
                // and the await isn't missed.
                let idle = self.idle.notified();
                if self.count() == 0 {
                    return;
                }
                idle.await;
            }
        })
        .await
        .is_ok()
    }
}

/// Decrements the count when a query's future completes or is dropped.
struct Guard(Arc<InFlight>);

impl Drop for Guard {
    fn drop(&mut self) {
        if self.0.count.fetch_sub(1, Ordering::SeqCst) == 1 {
            self.0.idle.notify_waiters();
        }
    }
}

/// Waits for SIGINT or SIGTERM (Ctrl-C elsewhere), returning its name.
#[cfg(unix)]
pub async fn wait_for_signal() -> std::io::Result<&'static str> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut terminate = signal(SignalKind::terminate())?;
    tokio::select! {
        _ = interrupt.recv() => Ok("SIGINT"),
        _ = terminate.recv() => Ok("SIGTERM"),
    }
}

/// Waits for SIGINT or SIGTERM (Ctrl-C elsewhere), returning its name.
#[cfg(not(unix))]
pub async fn wait_for_signal() -> std::io::Result<&'static str> {
    tokio::signal::ctrl_c().await.map(|()| "ctrl-c")
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{MessageType, OpCode};

    fn slow_handler(delay: Duration) -> Handler {
        Arc::new(move |req: Message| {
            Box::pin(async move {
                tokio::time::sleep(delay).await;
                Ok(req)
            })
        })
    }

    #[tokio::test]
    async fn waits_for_in_flight_queries() {
        let in_flight = Arc::new(InFlight::default());
        let handler = in_flight.wrap(slow_handler(Duration::from_millis(100)));
        let query = tokio::spawn(handler(Message::new(1, MessageType::Query, OpCode::Query)));
        tokio::task::yield_now().await;
        assert_eq!(in_flight.count(), 1);

        assert!(in_flight.wait_idle(Duration::from_secs(2)).await);
        assert_eq!(in_flight.count(), 0);
        query.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn gives_up_after_the_timeout() {
        let in_flight = Arc::new(InFlight::default());
        let handler = in_flight.wrap(slow_handler(Duration::from_secs(60)));
        let _query = tokio::spawn(handler(Message::new(1, MessageType::Query, OpCode::Query)));
        tokio::task::yield_now().await;

        assert!(!in_flight.wait_idle(Duration::from_millis(50)).await);
        assert_eq!(in_flight.count(), 1);
    }

    #[tokio::test]
    async fn idle_returns_at_once_with_nothing_in_flight() {
        let in_flight = InFlight::default();
        assert!(in_flight.wait_idle(Duration::from_millis(1)).await);
    }
}
