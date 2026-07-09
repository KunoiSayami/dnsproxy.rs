//! A DNS-over-QUIC (RFC 9250) listener: accepts incoming QUIC connections,
//! reads length-prefixed queries off each bidirectional stream, and hands
//! them to a caller-supplied handler, mirroring `proxy/serverquic.go`.

use std::sync::Arc;

use hickory_proto::op::Message;
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use std::net::SocketAddr;

use crate::error::DohError;
use crate::listener::io::Handler;

const MAX_MSG_SIZE: usize = 65535;
pub const DOQ_ALPN: &[u8] = b"doq";

/// Runs a DoQ listener on every address in `addrs`, dispatching every
/// decoded query to `handler`. Returns once every endpoint is bound; the
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

/// Runs a DoQ listener on `addr`, returning the address it actually bound to
/// (useful when `addr`'s port is `0`).
pub async fn serve(
    addr: SocketAddr,
    tls_config: Arc<tokio_rustls::rustls::ServerConfig>,
    handler: Handler,
) -> Result<SocketAddr, DohError> {
    let quic_config = quinn::crypto::rustls::QuicServerConfig::try_from((*tls_config).clone())
        .map_err(|e| DohError::Quic(e.to_string()))?;
    let server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_config));
    let endpoint =
        quinn::Endpoint::server(server_config, addr).map_err(|e| DohError::Quic(e.to_string()))?;
    let bound_addr = endpoint
        .local_addr()
        .map_err(|e| DohError::Quic(e.to_string()))?;

    tracing::info!(addr = %bound_addr, "listening for doq queries");

    tokio::spawn(async move {
        accept_loop(endpoint, handler).await;
    });

    Ok(bound_addr)
}

async fn accept_loop(endpoint: quinn::Endpoint, handler: Handler) {
    loop {
        let Some(incoming) = endpoint.accept().await else {
            return;
        };
        let handler = Arc::clone(&handler);
        tokio::spawn(async move {
            match incoming.await {
                Ok(conn) => connection_loop(conn, handler).await,
                Err(e) => tracing::warn!(error = %e, "doq handshake failed"),
            }
        });
    }
}

async fn connection_loop(conn: quinn::Connection, handler: Handler) {
    loop {
        let (send, recv) = match conn.accept_bi().await {
            Ok(v) => v,
            Err(e) => {
                tracing::debug!(error = %e, "doq connection closed");
                return;
            }
        };
        let handler = Arc::clone(&handler);
        tokio::spawn(async move {
            if let Err(e) = handle_stream(send, recv, handler).await {
                tracing::warn!(error = %e, "doq stream failed");
            }
        });
    }
}

async fn handle_stream(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    handler: Handler,
) -> Result<(), DohError> {
    let mut len_buf = [0u8; 2];
    recv.read_exact(&mut len_buf)
        .await
        .map_err(|e| DohError::Quic(e.to_string()))?;
    let len = u16::from_be_bytes(len_buf) as usize;
    if len > MAX_MSG_SIZE {
        return Err(DohError::InvalidResponse("request too large".into()));
    }

    let mut buf = vec![0u8; len];
    recv.read_exact(&mut buf)
        .await
        .map_err(|e| DohError::Quic(e.to_string()))?;

    let req = Message::from_bytes(&buf)
        .map_err(|e| DohError::InvalidResponse(format!("unpacking doq request: {e}")))?;
    if req.metadata.id != 0 {
        return Err(DohError::NonZeroId(req.metadata.id));
    }

    let mut resp = handler(req).await?;
    resp.metadata.id = 0;
    let bytes = resp.to_bytes()?;
    if bytes.len() > u16::MAX as usize {
        return Err(DohError::Pack(hickory_proto::ProtoError::from(
            "response too large for doq framing",
        )));
    }

    send.write_all(&(bytes.len() as u16).to_be_bytes())
        .await
        .map_err(|e| DohError::Quic(e.to_string()))?;
    send.write_all(&bytes)
        .await
        .map_err(|e| DohError::Quic(e.to_string()))?;
    send.finish().map_err(|e| DohError::Quic(e.to_string()))?;
    // Wait for the peer to finish reading before dropping the stream;
    // otherwise dropping it here races an implicit close against the
    // client's read (same concern noted in doq.rs's client-side test).
    let _ = send.stopped().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DoqUpstream;
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
        let mut config = tokio_rustls::rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .unwrap();
        config.alpn_protocols = vec![DOQ_ALPN.to_vec()];
        config
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
    async fn roundtrips_through_doq_upstream_client() {
        let addr = serve(
            "127.0.0.1:0".parse().unwrap(),
            Arc::new(server_tls_config()),
            echo_handler(),
        )
        .await
        .unwrap();

        let upstream = DoqUpstream::new(
            "localhost",
            Some(addr.port()),
            crate::options::Options {
                bootstrap: Some(Arc::new(crate::client::bootstrap::StaticResolver(vec![
                    addr.ip(),
                ]))),
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

    #[tokio::test]
    async fn rejects_non_zero_id_request_without_crashing() {
        // Not directly reachable through DoqUpstream, which always zeroes
        // the id per RFC 9250 before sending; this exercises handle_stream
        // directly against a raw quinn connection to confirm a malformed
        // request just drops the stream rather than panicking or hanging.
        let tls_config = Arc::new(server_tls_config());
        let addr = serve(
            "127.0.0.1:0".parse().unwrap(),
            Arc::clone(&tls_config),
            echo_handler(),
        )
        .await
        .unwrap();

        let mut client_tls =
            crate::client::doh::build_tls_config("localhost", true, vec![DOQ_ALPN.to_vec()]);
        client_tls.alpn_protocols = vec![DOQ_ALPN.to_vec()];
        let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        let client_config = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(client_tls).unwrap(),
        ));
        endpoint.set_default_client_config(client_config);
        let conn = endpoint.connect(addr, "localhost").unwrap().await.unwrap();

        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        let req = make_query(7, "example.com.");
        let bytes = req.to_bytes().unwrap(); // non-zero id, on purpose
        send.write_all(&(bytes.len() as u16).to_be_bytes())
            .await
            .unwrap();
        send.write_all(&bytes).await.unwrap();
        send.finish().unwrap();

        let mut len_buf = [0u8; 2];
        let result =
            tokio::time::timeout(Duration::from_millis(500), recv.read_exact(&mut len_buf)).await;
        assert!(result.is_err() || result.unwrap().is_err());
    }
}
