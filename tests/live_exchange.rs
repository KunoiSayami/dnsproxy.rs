//! End-to-end test running a local, in-process DoH echo server over
//! HTTP/2-over-TLS and exercising the full `DohUpstream::exchange` path
//! against it, with no external network access required.

use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bytes::Bytes;
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RData, Record, RecordType, rdata::A};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as ServerBuilder;
use tokio::net::TcpListener;
use tokio_rustls::rustls;

use doh_upstream::{DohUpstream, Options, options::HttpVersion};

/// Generates a self-signed cert for `localhost`, mirroring the ephemeral
/// certs the Go tests spin up via `httptest`.
fn generate_self_signed() -> (
    rustls::pki_types::CertificateDer<'static>,
    rustls::pki_types::PrivateKeyDer<'static>,
) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = cert.cert.der().clone();
    let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into());
    (cert_der, key_der)
}

async fn handle(req: Request<Incoming>) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let query = req.uri().query().unwrap_or_default();
    let dns_param = query
        .split('&')
        .find_map(|kv| kv.strip_prefix("dns="))
        .unwrap_or_default();

    let raw = URL_SAFE_NO_PAD.decode(dns_param).expect("valid base64url");
    let query_msg = Message::from_bytes(&raw).expect("valid dns message");
    assert_eq!(
        query_msg.metadata.id, 0,
        "RFC 8484 requires a zeroed id in the request"
    );

    let mut resp = Message::new(0, MessageType::Response, OpCode::Query);
    resp.add_query(query_msg.queries[0].clone());

    let name = query_msg.queries[0].name().clone();
    let record = Record::from_rdata(name, 60, RData::A(A::new(93, 184, 216, 34)));
    resp.add_answer(record);

    let body = resp.to_bytes().unwrap();
    Ok(Response::builder()
        .status(200)
        .header("content-type", "application/dns-message")
        .body(Full::new(Bytes::from(body)))
        .unwrap())
}

async fn start_server() -> SocketAddr {
    #[cfg(feature = "crypto-ring")]
    let _ = rustls::crypto::ring::default_provider().install_default();
    #[cfg(feature = "crypto-aws-lc-rs")]
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let (cert_der, key_der) = generate_self_signed();

    let mut server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .unwrap();
    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(s) => s,
                Err(_) => continue,
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let tls_stream = match acceptor.accept(stream).await {
                    Ok(s) => s,
                    Err(_) => return,
                };
                let io = TokioIo::new(tls_stream);
                let _ = ServerBuilder::new(TokioExecutor::new())
                    .serve_connection(io, service_fn(handle))
                    .await;
            });
        }
    });

    addr
}

#[tokio::test]
async fn exchange_roundtrips_over_local_https_server() {
    let addr = start_server().await;

    let opts = Options {
        http_versions: vec![HttpVersion::Http11, HttpVersion::Http2],
        insecure_skip_verify: true,
        ..Default::default()
    };

    let upstream = DohUpstream::new("localhost", Some(addr.port()), "/dns-query", opts);

    let mut msg = Message::new(0xBEEF, MessageType::Query, OpCode::Query);
    msg.add_query(Query::query(
        Name::from_str("example.com.").unwrap(),
        RecordType::A,
    ));

    let resp = upstream
        .exchange(&msg)
        .await
        .expect("exchange should succeed");

    assert_eq!(
        resp.metadata.id, 0xBEEF,
        "original request id must be restored"
    );
    assert_eq!(resp.answers.len(), 1);
}
