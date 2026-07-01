# doh-upstream

A DNS-over-HTTPS ([RFC 8484](https://www.rfc-editor.org/rfc/rfc8484)) upstream
client for Rust, ported from [AdGuard dnsproxy](https://github.com/AdguardTeam/dnsproxy)'s
Go implementation (`upstream/doh.go`).

HTTP/1.1 and HTTP/2 are supported unconditionally; HTTP/3 is available behind
the `http3` feature and races a QUIC handshake against TLS to decide whether
to prefer it, matching the Go client's probing behavior.

## Features

- DNS message exchange over DoH using `hyper` (HTTP/1.1 / HTTP/2) and
  optionally `quinn`/`h3` (HTTP/3)
- Configurable bootstrap resolver for resolving the DoH server's hostname
- Automatic retry with a fresh client on retryable errors (timeouts, QUIC
  0-RTT rejection)
- A minimal plain-DNS server (`serve`) that forwards UDP/TCP queries to any
  async handler, so a `DohUpstream` can be turned into a local DNS-to-DoH
  proxy with `into_handler`

## Usage

```rust
use doh_upstream::{DohUpstream, Options};

let upstream = DohUpstream::new("dns.google", None, "/dns-query", Options::default());
let response = upstream.exchange(&query_message).await?;
```

To run it as a local plain-DNS proxy:

```rust
use std::sync::Arc;
use doh_upstream::{serve, DohUpstream, Options};

let upstream = Arc::new(DohUpstream::new("dns.google", None, "/dns-query", Options::default()));
serve("127.0.0.1:5353".parse()?, upstream.into_handler()).await?;
```

## Cargo features

| Feature | Default | Description |
|---|---|---|
| `http3` | yes | Enables HTTP/3 support via `quinn`, `h3`, and `h3-quinn` |

## Building

```sh
cargo check
cargo test
```

## License

AGPL-3.0-only. See the `license` field in [Cargo.toml](Cargo.toml).
