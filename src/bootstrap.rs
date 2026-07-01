//! Resolves upstream hostnames to IP addresses and dials the resolved
//! addresses, mirroring `internal/bootstrap` from the Go implementation.

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::{lookup_host, TcpStream, UdpSocket};

use crate::error::DohError;

/// Network type used when dialing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    Tcp,
    Udp,
}

/// A dial function bound to a fixed set of addresses, ignoring whatever
/// address is passed to it (matching `bootstrap.DialHandler`'s contract of
/// connecting only to addresses resolved at construction time).
pub type DialHandler = Arc<
    dyn Fn(Network) -> Pin<Box<dyn Future<Output = Result<Conn, DohError>> + Send>> + Send + Sync,
>;

/// A connected transport-layer socket, unified over TCP/UDP.
pub enum Conn {
    Tcp(TcpStream),
    Udp(UdpSocket, SocketAddr),
}

/// Resolves hostnames to IP addresses. `tokio`'s system resolver satisfies
/// this by default; a bootstrap DNS server can be substituted.
#[async_trait::async_trait]
pub trait Resolver: Send + Sync {
    async fn lookup(&self, host: &str) -> Result<Vec<IpAddr>, DohError>;
}

/// Resolves via the OS resolver (`getaddrinfo`), the same fallback the Go
/// code uses when no bootstrap is configured.
pub struct SystemResolver;

#[async_trait::async_trait]
impl Resolver for SystemResolver {
    async fn lookup(&self, host: &str) -> Result<Vec<IpAddr>, DohError> {
        let addrs = lookup_host((host, 0))
            .await
            .map_err(|e| DohError::Bootstrap(e.to_string()))?;
        Ok(addrs.map(|a| a.ip()).collect())
    }
}

/// Always resolves to a fixed set of addresses, used for `sdns://` stamps
/// that embed a literal server IP.
pub struct StaticResolver(pub Vec<IpAddr>);

#[async_trait::async_trait]
impl Resolver for StaticResolver {
    async fn lookup(&self, _host: &str) -> Result<Vec<IpAddr>, DohError> {
        Ok(self.0.clone())
    }
}

/// Queries all resolvers concurrently and returns the first successful,
/// non-empty result.
pub struct ParallelResolver(pub Vec<Arc<dyn Resolver>>);

#[async_trait::async_trait]
impl Resolver for ParallelResolver {
    async fn lookup(&self, host: &str) -> Result<Vec<IpAddr>, DohError> {
        if self.0.is_empty() {
            return Err(DohError::Bootstrap("no resolvers configured".into()));
        }

        let mut futs: Vec<Pin<Box<dyn Future<Output = Result<Vec<IpAddr>, DohError>> + Send>>> =
            self.0
                .iter()
                .map(|r| {
                    let r = Arc::clone(r);
                    let host = host.to_owned();
                    Box::pin(async move { r.lookup(&host).await })
                        as Pin<Box<dyn Future<Output = Result<Vec<IpAddr>, DohError>> + Send>>
                })
                .collect();

        let mut errs = Vec::new();
        while !futs.is_empty() {
            let (result, _idx, rest) = futures_util::future::select_all(futs).await;
            futs = rest;
            match result {
                Ok(addrs) if !addrs.is_empty() => return Ok(addrs),
                Ok(_) => continue,
                Err(e) => errs.push(e),
            }
        }

        Err(DohError::Bootstrap(format!(
            "all resolvers failed: {errs:?}"
        )))
    }
}

/// Builds a [`DialHandler`] that connects only to `addrs`, trying each in
/// order and returning the first successful connection (mirrors
/// `bootstrap.NewDialContext`).
pub fn new_dial_context(timeout: Option<Duration>, addrs: Vec<SocketAddr>) -> DialHandler {
    Arc::new(move |network| {
        let addrs = addrs.clone();
        Box::pin(async move {
            if addrs.is_empty() {
                return Err(DohError::Bootstrap("no addresses to dial".into()));
            }

            let mut last_err = None;
            for addr in &addrs {
                let start = Instant::now();
                let attempt = dial_one(*addr, network, timeout);
                match attempt.await {
                    Ok(conn) => {
                        let _ = start.elapsed();
                        return Ok(conn);
                    }
                    Err(e) => last_err = Some(e),
                }
            }

            Err(last_err.unwrap_or_else(|| DohError::Bootstrap("no addresses".into())))
        })
    })
}

async fn dial_one(
    addr: SocketAddr,
    network: Network,
    timeout: Option<Duration>,
) -> Result<Conn, DohError> {
    let fut = async move {
        match network {
            Network::Tcp => TcpStream::connect(addr)
                .await
                .map(Conn::Tcp)
                .map_err(|e| DohError::Bootstrap(e.to_string())),
            Network::Udp => {
                let local = if addr.is_ipv4() {
                    "0.0.0.0:0"
                } else {
                    "[::]:0"
                };
                let sock = UdpSocket::bind(local)
                    .await
                    .map_err(|e| DohError::Bootstrap(e.to_string()))?;
                sock.connect(addr)
                    .await
                    .map_err(|e| DohError::Bootstrap(e.to_string()))?;
                Ok(Conn::Udp(sock, addr))
            }
        }
    };

    match timeout {
        Some(d) => tokio::time::timeout(d, fut)
            .await
            .map_err(|_| DohError::Bootstrap(format!("dialing {addr}: timed out")))?,
        None => fut.await,
    }
}

/// Resolves `host` (the DoH server's hostname) via `resolver`, then returns a
/// [`DialHandler`] bound to those resolved addresses, sorted to prefer IPv4
/// or IPv6 per `prefer_v6`. Mirrors `bootstrap.ResolveDialContext`.
pub async fn resolve_dial_context(
    host: &str,
    port: u16,
    timeout: Option<Duration>,
    resolver: &dyn Resolver,
    prefer_v6: bool,
) -> Result<DialHandler, DohError> {
    let lookup = resolver.lookup(host);
    let ips = match timeout {
        Some(d) => tokio::time::timeout(d, lookup)
            .await
            .map_err(|_| DohError::Bootstrap(format!("resolving {host}: timed out")))??,
        None => lookup.await?,
    };

    if ips.is_empty() {
        return Err(DohError::Bootstrap(format!("no addresses for {host}")));
    }

    let mut ips = ips;
    ips.sort_by_key(|ip| {
        let is_v6 = ip.is_ipv6();
        if prefer_v6 {
            !is_v6
        } else {
            is_v6
        }
    });

    let addrs = ips
        .into_iter()
        .map(|ip| SocketAddr::new(ip, port))
        .collect();

    Ok(new_dial_context(timeout, addrs))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn static_resolver_returns_fixed_addrs() {
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        let resolver = StaticResolver(vec![ip]);
        let addrs = resolver.lookup("ignored.example.").await.unwrap();
        assert_eq!(addrs, vec![ip]);
    }

    #[tokio::test]
    async fn parallel_resolver_returns_first_success() {
        struct Failing;
        #[async_trait::async_trait]
        impl Resolver for Failing {
            async fn lookup(&self, _host: &str) -> Result<Vec<IpAddr>, DohError> {
                Err(DohError::Bootstrap("nope".into()))
            }
        }

        let ip: IpAddr = "192.0.2.2".parse().unwrap();
        let resolver =
            ParallelResolver(vec![Arc::new(Failing), Arc::new(StaticResolver(vec![ip]))]);

        let addrs = resolver.lookup("example.").await.unwrap();
        assert_eq!(addrs, vec![ip]);
    }

    #[tokio::test]
    async fn parallel_resolver_fails_when_all_fail() {
        struct Failing;
        #[async_trait::async_trait]
        impl Resolver for Failing {
            async fn lookup(&self, _host: &str) -> Result<Vec<IpAddr>, DohError> {
                Err(DohError::Bootstrap("nope".into()))
            }
        }

        let resolver = ParallelResolver(vec![Arc::new(Failing), Arc::new(Failing)]);
        assert!(resolver.lookup("example.").await.is_err());
    }

    #[tokio::test]
    async fn dial_context_tries_addrs_in_order_until_success() {
        // Bind a real listener so the second address in the list succeeds.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let good_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        // First address (unroutable/closed port) should fail, falling through
        // to the second, mirroring `NewDialContext`'s "first success wins".
        let bad_addr: SocketAddr = "127.0.0.1:1".parse().unwrap();

        let handler = new_dial_context(Some(Duration::from_millis(500)), vec![bad_addr, good_addr]);

        let conn = (handler)(Network::Tcp).await;
        assert!(conn.is_ok());
    }

    #[tokio::test]
    async fn dial_context_fails_with_no_addrs() {
        let handler = new_dial_context(None, vec![]);
        assert!((handler)(Network::Tcp).await.is_err());
    }
}
