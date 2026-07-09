//! An HTTP/3 listener for DoH (RFC 8484 over QUIC): accepts QUIC
//! connections, drives them with `h3::server`, and serves the same GET/POST
//! request forms as the HTTP/1.1-or-2 DoH listener, mirroring the HTTP/3
//! half of `proxy/serverhttp.go`.

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::{Buf, Bytes};
use h3::server::RequestStream;
use http::{Method, Request, Response, StatusCode};

use crate::doh_auth::Credentials;
use crate::error::DohError;
use crate::server::Handler;
use crate::serverhttps::find_dns_param;
use crate::wire::{decode_request, encode_response};

const MAX_MSG_SIZE: usize = 65535;

/// Runs a DoH3 listener on every address in `addrs`, dispatching every
/// decoded query to `handler`. Returns once every endpoint is bound; the
/// accept loops keep running in spawned tasks. `credentials`, if non-empty,
/// requires every request to present one of its configured `user:password`
/// pairs via HTTP Basic Auth.
pub async fn serve_all(
    addrs: &[SocketAddr],
    tls_config: Arc<tokio_rustls::rustls::ServerConfig>,
    handler: Handler,
    credentials: Arc<Credentials>,
) -> Result<(), DohError> {
    for &addr in addrs {
        serve(
            addr,
            Arc::clone(&tls_config),
            Arc::clone(&handler),
            Arc::clone(&credentials),
        )
        .await?;
    }
    Ok(())
}

/// Runs a DoH3 listener on `addr`, returning the address it actually bound
/// to (useful when `addr`'s port is `0`).
pub async fn serve(
    addr: SocketAddr,
    tls_config: Arc<tokio_rustls::rustls::ServerConfig>,
    handler: Handler,
    credentials: Arc<Credentials>,
) -> Result<SocketAddr, DohError> {
    let quic_config = quinn::crypto::rustls::QuicServerConfig::try_from((*tls_config).clone())
        .map_err(|e| DohError::Quic(e.to_string()))?;
    let server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_config));
    let endpoint =
        quinn::Endpoint::server(server_config, addr).map_err(|e| DohError::Quic(e.to_string()))?;
    let bound_addr = endpoint
        .local_addr()
        .map_err(|e| DohError::Quic(e.to_string()))?;

    tracing::info!(addr = %bound_addr, "listening for doh3 queries");

    tokio::spawn(async move {
        accept_loop(endpoint, handler, credentials).await;
    });

    Ok(bound_addr)
}

async fn accept_loop(endpoint: quinn::Endpoint, handler: Handler, credentials: Arc<Credentials>) {
    loop {
        let Some(incoming) = endpoint.accept().await else {
            return;
        };
        let handler = Arc::clone(&handler);
        let credentials = Arc::clone(&credentials);
        tokio::spawn(async move {
            match incoming.await {
                Ok(conn) => connection_loop(conn, handler, credentials).await,
                Err(e) => tracing::warn!(error = %e, "doh3 handshake failed"),
            }
        });
    }
}

async fn connection_loop(conn: quinn::Connection, handler: Handler, credentials: Arc<Credentials>) {
    let quinn_conn = h3_quinn::Connection::new(conn);
    let mut h3_conn = match h3::server::Connection::new(quinn_conn).await {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, "doh3 connection setup failed");
            return;
        }
    };

    loop {
        let resolver = match h3_conn.accept().await {
            Ok(Some(r)) => r,
            Ok(None) => return,
            Err(e) => {
                tracing::debug!(error = %e, "doh3 connection closed");
                return;
            }
        };
        let handler = Arc::clone(&handler);
        let credentials = Arc::clone(&credentials);
        tokio::spawn(async move {
            let (req, stream) = match resolver.resolve_request().await {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(error = %e, "doh3 request resolution failed");
                    return;
                }
            };
            if let Err(e) = handle_request(req, stream, handler, credentials).await {
                tracing::warn!(error = %e, "doh3 request failed");
            }
        });
    }
}

async fn handle_request(
    req: Request<()>,
    mut stream: RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    handler: Handler,
    credentials: Arc<Credentials>,
) -> Result<(), DohError> {
    if !credentials.is_empty() {
        let authorized = req
            .headers()
            .get(http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| credentials.is_authorized(Some(v)));
        if !authorized {
            return send_unauthorized(&mut stream).await;
        }
    }

    let dns_param = req.uri().query().and_then(find_dns_param);

    let body = match *req.method() {
        Method::GET => Vec::new(),
        Method::POST => {
            let mut body = Vec::new();
            while let Some(mut chunk) = stream
                .recv_data()
                .await
                .map_err(|e| DohError::Quic(e.to_string()))?
            {
                body.extend_from_slice(chunk.copy_to_bytes(chunk.remaining()).as_ref());
                if body.len() > MAX_MSG_SIZE {
                    return Err(DohError::Http("request body too large".into()));
                }
            }
            body
        }
        _ => {
            return send_response(&mut stream, StatusCode::METHOD_NOT_ALLOWED, Bytes::new()).await;
        }
    };

    let query = match decode_request(dns_param.as_deref(), &body) {
        Ok(q) => q,
        Err(e) => {
            tracing::warn!(error = %e, "doh3 decoding request failed");
            return send_response(&mut stream, StatusCode::BAD_REQUEST, Bytes::new()).await;
        }
    };

    let resp = handler(query).await?;
    let bytes = encode_response(&resp)?;
    send_response(&mut stream, StatusCode::OK, Bytes::from(bytes)).await
}

async fn send_response(
    stream: &mut RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    status: StatusCode,
    body: Bytes,
) -> Result<(), DohError> {
    let response = Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "application/dns-message")
        .body(())
        .map_err(|e| DohError::Http(format!("building response: {e}")))?;

    stream
        .send_response(response)
        .await
        .map_err(|e| DohError::Quic(e.to_string()))?;
    if !body.is_empty() {
        stream
            .send_data(body)
            .await
            .map_err(|e| DohError::Quic(e.to_string()))?;
    }
    stream
        .finish()
        .await
        .map_err(|e| DohError::Quic(e.to_string()))
}

async fn send_unauthorized(
    stream: &mut RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
) -> Result<(), DohError> {
    let response = Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header(http::header::WWW_AUTHENTICATE, "Basic")
        .body(())
        .map_err(|e| DohError::Http(format!("building response: {e}")))?;

    stream
        .send_response(response)
        .await
        .map_err(|e| DohError::Quic(e.to_string()))?;
    stream
        .finish()
        .await
        .map_err(|e| DohError::Quic(e.to_string()))
}

/// The ALPN protocol list DoH3 listeners should offer: `h3` alongside
/// `serverhttps::DOH_ALPN`'s `h2`/`http/1.1`, so a single cert can back both
/// a QUIC-based DoH3 listener and a separate TCP+TLS DoH listener.
pub const DOH3_ALPN: &[&[u8]] = &[b"h3"];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DohUpstream;
    use crate::options::HttpVersion;
    use hickory_proto::op::{Message, MessageType, OpCode, Query};
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
        config.alpn_protocols = DOH3_ALPN.iter().map(|p| p.to_vec()).collect();
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

    fn no_credentials() -> Arc<Credentials> {
        Arc::new(Credentials::new([]))
    }

    #[tokio::test]
    async fn roundtrips_through_doh_upstream_client_over_http3() {
        let addr = serve(
            "127.0.0.1:0".parse().unwrap(),
            Arc::new(server_tls_config()),
            echo_handler(),
            no_credentials(),
        )
        .await
        .unwrap();

        // Force HTTP/3-only so the DoH client's h3-vs-TLS race doesn't fall
        // back to a (nonexistent, for this test) TCP+TLS listener.
        let upstream = DohUpstream::new(
            "localhost",
            Some(addr.port()),
            "/dns-query",
            crate::options::Options {
                bootstrap: Some(Arc::new(crate::bootstrap::StaticResolver(vec![addr.ip()]))),
                http_versions: vec![HttpVersion::Http3],
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
    async fn rejects_request_missing_credentials() {
        let addr = serve(
            "127.0.0.1:0".parse().unwrap(),
            Arc::new(server_tls_config()),
            echo_handler(),
            Arc::new(Credentials::new([(
                "alice".to_owned(),
                "secret".to_owned(),
            )])),
        )
        .await
        .unwrap();

        let upstream = DohUpstream::new(
            "localhost",
            Some(addr.port()),
            "/dns-query",
            crate::options::Options {
                bootstrap: Some(Arc::new(crate::bootstrap::StaticResolver(vec![addr.ip()]))),
                http_versions: vec![HttpVersion::Http3],
                timeout: Some(Duration::from_secs(5)),
                insecure_skip_verify: true,
                ..Default::default()
            },
        );

        let req = make_query(42, "example.com.");
        let result = upstream.exchange(&req).await;
        assert!(matches!(
            result,
            Err(DohError::UnexpectedStatus { status: 401, .. })
        ));
    }
}
