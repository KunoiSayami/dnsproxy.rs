//! A DNS-over-HTTPS (RFC 8484) listener: accepts TCP+TLS connections and
//! serves GET (`?dns=<base64url>`) and POST (raw `application/dns-message`
//! body) requests over HTTP/1.1 or HTTP/2, mirroring `proxy/serverhttp.go`.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::header::CONTENT_TYPE;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use tokio_rustls::TlsAcceptor;

use crate::error::DohError;
use crate::server::{Handler, bind_tcp};
use crate::wire::{decode_request, encode_response};

const MAX_MSG_SIZE: usize = 65535;
pub const DOH_ALPN: &[&[u8]] = &[b"h2", b"http/1.1"];

/// Runs a DoH listener on every address in `addrs`, dispatching every
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

/// Runs a DoH listener on `addr`, returning the address it actually bound to
/// (useful when `addr`'s port is `0`).
pub async fn serve(
    addr: SocketAddr,
    tls_config: Arc<tokio_rustls::rustls::ServerConfig>,
    handler: Handler,
) -> Result<SocketAddr, DohError> {
    let listener = bind_tcp(addr)?;
    let bound_addr = listener.local_addr()?;
    let acceptor = TlsAcceptor::from(tls_config);

    tracing::info!(addr = %bound_addr, "listening for doh queries");

    tokio::spawn(async move {
        accept_loop(listener, acceptor, handler).await;
    });

    Ok(bound_addr)
}

async fn accept_loop(listener: tokio::net::TcpListener, acceptor: TlsAcceptor, handler: Handler) {
    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "doh accept failed");
                continue;
            }
        };
        let acceptor = acceptor.clone();
        let handler = Arc::clone(&handler);
        tokio::spawn(async move {
            if let Err(e) = handle_connection(tcp, acceptor, handler).await {
                tracing::warn!(%peer, error = %e, "doh connection failed");
            }
        });
    }
}

async fn handle_connection(
    tcp: tokio::net::TcpStream,
    acceptor: TlsAcceptor,
    handler: Handler,
) -> Result<(), DohError> {
    let tls = acceptor
        .accept(tcp)
        .await
        .map_err(|e| DohError::Http(format!("tls handshake failed: {e}")))?;

    let service = service_fn(move |req| handle_request(req, Arc::clone(&handler)));
    auto::Builder::new(TokioExecutor::new())
        .serve_connection(TokioIo::new(tls), service)
        .await
        .map_err(|e| DohError::Http(format!("serving connection: {e}")))
}

async fn handle_request(
    req: Request<Incoming>,
    handler: Handler,
) -> Result<Response<Full<Bytes>>, Infallible> {
    Ok(match handle_request_inner(req, handler).await {
        Ok(resp) => resp,
        Err(e) => {
            tracing::warn!(error = %e, "doh query failed");
            error_response(StatusCode::BAD_REQUEST)
        }
    })
}

async fn handle_request_inner(
    req: Request<Incoming>,
    handler: Handler,
) -> Result<Response<Full<Bytes>>, DohError> {
    let dns_param = req.uri().query().and_then(find_dns_param);

    let body = match *req.method() {
        Method::GET => Vec::new(),
        Method::POST => {
            let body = req
                .into_body()
                .collect()
                .await
                .map_err(|e| DohError::Http(format!("reading body: {e}")))?
                .to_bytes();
            if body.len() > MAX_MSG_SIZE {
                return Err(DohError::Http("request body too large".into()));
            }
            body.to_vec()
        }
        _ => return Ok(error_response(StatusCode::METHOD_NOT_ALLOWED)),
    };

    let query = decode_request(dns_param.as_deref(), &body)?;
    let resp = handler(query).await?;
    let bytes = encode_response(&resp)?;

    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/dns-message")
        .body(Full::new(Bytes::from(bytes)))
        .map_err(|e| DohError::Http(format!("building response: {e}")))
}

/// Finds the `dns` parameter in a URI's raw (still percent-encoded) query
/// string. The base64url alphabet RFC 8484 mandates for this parameter has
/// no characters that need percent-decoding, so no decoding step is needed.
/// Shared with the DoH3 listener, which parses the same query-string form.
pub(crate) fn find_dns_param(query: &str) -> Option<String> {
    query
        .split('&')
        .find_map(|pair| pair.strip_prefix("dns="))
        .map(str::to_owned)
}

fn error_response(status: StatusCode) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .body(Full::new(Bytes::new()))
        .expect("static response is valid")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DohUpstream;
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
        config.alpn_protocols = DOH_ALPN.iter().map(|p| p.to_vec()).collect();
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
    async fn roundtrips_through_doh_upstream_client() {
        let addr = serve(
            "127.0.0.1:0".parse().unwrap(),
            Arc::new(server_tls_config()),
            echo_handler(),
        )
        .await
        .unwrap();

        let upstream = DohUpstream::new(
            "localhost",
            Some(addr.port()),
            "/dns-query",
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
