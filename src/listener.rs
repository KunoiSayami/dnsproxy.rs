//! DNS server/listener implementations: accepting incoming queries over
//! plain DNS-over-UDP/TCP, DoT, DoQ, DoH, and DoH3.

#[cfg(feature = "dnscrypt-server")]
pub mod dnscrypt;
#[cfg(feature = "doh-server")]
pub mod doh;
#[cfg(feature = "http3-server")]
pub mod doh3;
#[cfg(feature = "doh-server")]
pub mod doh_auth;
#[cfg(feature = "doh-server")]
pub mod doh_routes;
#[cfg(feature = "doq-server")]
pub mod doq;
#[cfg(feature = "dot-server")]
pub mod dot;
pub mod io;
#[cfg(any(feature = "doq-server", feature = "dot-server", feature = "doh-server"))]
pub mod tls_config;

#[cfg(feature = "doh-server")]
pub use doh_auth::Credentials;
#[cfg(feature = "doh-server")]
pub use doh_routes::DohRoutes;
pub use io::{Handler, serve, serve_all, serve_all_split, with_matching_edns, with_servfail};

use std::future::Future;
use std::sync::{Mutex, PoisonError};

use tokio::task::AbortHandle;

/// Every listener's accept/receive loop, so [`stop_accepting`] can end them.
static ACCEPT_LOOPS: Mutex<Vec<AbortHandle>> = Mutex::new(Vec::new());

/// Spawns a listener's accept (or, for UDP, receive) loop, registering it
/// for [`stop_accepting`].
pub(crate) fn spawn_accept_loop(accept_loop: impl Future<Output = ()> + Send + 'static) {
    let handle = tokio::spawn(accept_loop);
    ACCEPT_LOOPS
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(handle.abort_handle());
}

/// Stops every listener started so far from taking new queries or
/// connections, for a graceful shutdown: their accept and receive loops end
/// and drop their sockets. Queries already being handled, and connections
/// already accepted, carry on.
pub fn stop_accepting() {
    let loops = std::mem::take(&mut *ACCEPT_LOOPS.lock().unwrap_or_else(PoisonError::into_inner));
    for accept_loop in loops {
        accept_loop.abort();
    }
}
