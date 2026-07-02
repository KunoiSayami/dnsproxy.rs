use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use hyper::Uri;

use doh_upstream::{DohUpstream, HttpVersion, Options};

/// A minimal standalone DNS-over-HTTPS forwarding proxy.
#[derive(Parser)]
struct Args {
    /// Address to listen on for plain DNS (UDP and TCP).
    #[arg(long, default_value = "127.0.0.1:53")]
    listen: SocketAddr,

    /// Upstream DoH server, e.g. https://dns.google/dns-query.
    #[arg(long)]
    upstream: Uri,

    /// Overall timeout for exchanges, bootstrap lookups, and H3 probes, in seconds.
    #[arg(long, default_value_t = 10)]
    timeout: u64,

    /// Disable TLS certificate verification. Dangerous.
    #[arg(long)]
    insecure: bool,

    /// Prefer IPv6 addresses when the bootstrap resolves multiple families.
    #[arg(long)]
    prefer_ipv6: bool,

    /// Allow HTTP/3, in addition to HTTP/1.1 and HTTP/2.
    #[cfg(feature = "http3")]
    #[arg(long)]
    http3: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // rustls needs a process-wide CryptoProvider installed before any TLS
    // connection is made; the lib crate leaves this to its consumer.
    tokio_rustls::rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("no CryptoProvider installed yet");

    let args = Args::parse();

    let host = args
        .upstream
        .host()
        .ok_or("--upstream must include a host")?
        .to_owned();
    let path = args.upstream.path().to_owned();

    #[cfg_attr(not(feature = "http3"), allow(unused_mut))]
    let mut http_versions = vec![HttpVersion::Http11, HttpVersion::Http2];
    #[cfg(feature = "http3")]
    if args.http3 {
        http_versions.push(HttpVersion::Http3);
    }

    let opts = Options {
        http_versions,
        timeout: Some(Duration::from_secs(args.timeout)),
        insecure_skip_verify: args.insecure,
        prefer_ipv6: args.prefer_ipv6,
        ..Default::default()
    };

    let upstream = Arc::new(DohUpstream::new(
        &host,
        args.upstream.port_u16(),
        &path,
        opts,
    ));
    println!("forwarding {} -> {}", args.listen, upstream.address());

    let handler = upstream.into_handler();
    doh_upstream::serve(args.listen, handler).await?;

    // `serve` spawns its listeners and returns once bound; block forever so
    // the process keeps running them.
    std::future::pending::<()>().await;
    Ok(())
}
