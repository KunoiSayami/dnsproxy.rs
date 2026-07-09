//! A DNS-over-TLS (RFC 7858) listener: accepts TCP connections, wraps them
//! in TLS, and reads length-prefixed queries off the resulting stream,
//! mirroring `proxy/servertls.go`. Framing is identical to plain
//! DNS-over-TCP, just over a TLS connection instead of a raw one.

use std::net::SocketAddr;
use std::sync::Arc;

use hickory_proto::op::Message;
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::error::DohError;
use crate::server::{Handler, bind_tcp, read_prefixed, write_prefixed};

/// Runs a DoT listener on every address in `addrs`, dispatching every
/// decoded query to `handler`. Returns once every listener is bound; the
/// accept loops keep running in spawned tasks.
pub async fn serve_all(
    addrs: &[SocketAddr],
    tls_config: Arc<tokio_rustls::rustls::ServerConfig>,
    handler: Handler,
) -> Result<(), DohError> {
    for &addr in addrs {
        serve(addr, Arc::clone(&tls_config), Arc::clone(&handler)).await?;
    }
    Ok(())
}

/// Runs a DoT listener on `addr`, returning the address it actually bound to
/// (useful when `addr`'s port is `0`).
pub async fn serve(
    addr: SocketAddr,
    tls_config: Arc<tokio_rustls::rustls::ServerConfig>,
    handler: Handler,
) -> Result<SocketAddr, DohError> {
    let listener = bind_tcp(addr)?;
    let bound_addr = listener.local_addr()?;
    let acceptor = TlsAcceptor::from(tls_config);

    tracing::info!(addr = %bound_addr, "listening for dot queries");

    tokio::spawn(async move {
        accept_loop(listener, acceptor, handler).await;
    });

    Ok(bound_addr)
}

async fn accept_loop(listener: TcpListener, acceptor: TlsAcceptor, handler: Handler) {
    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "dot accept failed");
                continue;
            }
        };
        let acceptor = acceptor.clone();
        let handler = Arc::clone(&handler);
        tokio::spawn(async move {
            if let Err(e) = handle_connection(tcp, acceptor, handler).await {
                tracing::warn!(%peer, error = %e, "dot connection failed");
            }
        });
    }
}

async fn handle_connection(
    tcp: tokio::net::TcpStream,
    acceptor: TlsAcceptor,
    handler: Handler,
) -> Result<(), DohError> {
    let mut tls = acceptor
        .accept(tcp)
        .await
        .map_err(|e| DohError::Http(format!("tls handshake failed: {e}")))?;

    loop {
        let packet = match read_prefixed(&mut tls).await {
            Ok(p) => p,
            Err(_) => return Ok(()),
        };

        let req = Message::from_bytes(&packet)
            .map_err(|e| DohError::InvalidResponse(format!("unpacking dot message: {e}")))?;

        let resp = handler(req).await?;
        let bytes = resp.to_bytes()?;
        write_prefixed(&mut tls, &bytes).await?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DotUpstream;
    use hickory_proto::op::{MessageType, OpCode, Query};
    use hickory_proto::rr::{Name, RecordType};
    use std::str::FromStr;
    use std::time::Duration;

    fn make_query(id: u16, name: &str) -> Message {
        let mut msg = Message::new(id, MessageType::Query, OpCode::Query);
        msg.add_query(Query::query(Name::from_str(name).unwrap(), RecordType::A));
        msg
    }

    fn server_tls_config() -> tokio_rustls::rustls::ServerConfig {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_der = cert.cert.der().clone();
        let key_der = tokio_rustls::rustls::pki_types::PrivateKeyDer::Pkcs8(
            cert.signing_key.serialize_der().into(),
        );
        tokio_rustls::rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .unwrap()
    }

    fn echo_handler() -> Handler {
        Arc::new(|req: Message| {
            Box::pin(async move {
                let mut resp = req.clone();
                resp.metadata.message_type = MessageType::Response;
                Ok(resp)
            })
        })
    }

    #[tokio::test]
    async fn roundtrips_through_dot_upstream_client() {
        let addr = serve(
            "127.0.0.1:0".parse().unwrap(),
            Arc::new(server_tls_config()),
            echo_handler(),
        )
        .await
        .unwrap();

        let upstream = DotUpstream::new(
            "localhost",
            Some(addr.port()),
            crate::options::Options {
                bootstrap: Some(Arc::new(crate::bootstrap::StaticResolver(vec![addr.ip()]))),
                timeout: Some(Duration::from_secs(5)),
                insecure_skip_verify: true,
                ..Default::default()
            },
        );

        let req = make_query(42, "example.com.");
        let resp = upstream.exchange(&req).await.unwrap();
        assert_eq!(resp.metadata.id, 42);
        assert_eq!(resp.metadata.message_type, MessageType::Response);
    }
}
