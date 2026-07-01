//! End-to-end test: a local, in-process DoH echo server (over HTTP/2-TLS)
//! sits behind a plain-DNS `server::serve` listener, and we verify that
//! real UDP and TCP DNS queries sent to the plain listener are forwarded to
//! the DoH server and answered correctly. No external network access
//! required.

use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use bytes::Bytes;
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{rdata::A, Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as ServerBuilder;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio_rustls::rustls;

use doh_upstream::{options::HttpVersion, DohUpstream, Options};

fn generate_self_signed() -> (
    rustls::pki_types::CertificateDer<'static>,
    rustls::pki_types::PrivateKeyDer<'static>,
) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = cert.cert.der().clone();
    let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into());
    (cert_der, key_der)
}

async fn handle_doh(req: Request<Incoming>) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let query = req.uri().query().unwrap_or_default();
    let dns_param = query
        .split('&')
        .find_map(|kv| kv.strip_prefix("dns="))
        .unwrap_or_default();

    let raw = URL_SAFE_NO_PAD.decode(dns_param).expect("valid base64url");
    let query_msg = Message::from_bytes(&raw).expect("valid dns message");

    let mut resp = Message::new();
    resp.set_id(0);
    resp.set_message_type(MessageType::Response);
    resp.set_op_code(OpCode::Query);
    resp.add_query(query_msg.queries()[0].clone());

    let name = query_msg.queries()[0].name().clone();
    let mut record = Record::with(name, RecordType::A, 60);
    record.set_data(Some(RData::A(A::new(93, 184, 216, 34))));
    resp.add_answer(record);

    let body = resp.to_bytes().unwrap();
    Ok(Response::builder()
        .status(200)
        .header("content-type", "application/dns-message")
        .body(Full::new(Bytes::from(body)))
        .unwrap())
}

async fn start_doh_server() -> SocketAddr {
    let _ = rustls::crypto::ring::default_provider().install_default();

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
                    .serve_connection(io, service_fn(handle_doh))
                    .await;
            });
        }
    });

    addr
}

fn make_query(id: u16, name: &str) -> Message {
    let mut msg = Message::new();
    msg.set_id(id);
    msg.set_message_type(MessageType::Query);
    msg.set_op_code(OpCode::Query);
    msg.set_recursion_desired(true);
    msg.add_query(Query::query(Name::from_str(name).unwrap(), RecordType::A));
    msg
}

async fn start_plain_proxy(doh_addr: SocketAddr) -> SocketAddr {
    let opts = Options {
        http_versions: vec![HttpVersion::Http11, HttpVersion::Http2],
        insecure_skip_verify: true,
        ..Default::default()
    };
    let upstream = Arc::new(DohUpstream::new(
        "localhost",
        Some(doh_addr.port()),
        "/dns-query",
        opts,
    ));
    let handler = upstream.into_handler();

    let listen_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

    // `server::serve` binds its own sockets internally; grab an ephemeral
    // port by binding a throwaway socket first to learn a free port, then
    // let `serve` bind that same port for both UDP and TCP.
    let probe = UdpSocket::bind(listen_addr).await.unwrap();
    let port = probe.local_addr().unwrap().port();
    drop(probe);

    let bind_addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    doh_upstream::serve(bind_addr, handler).await.unwrap();

    // Give the listeners a moment to be ready to accept.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    bind_addr
}

#[tokio::test]
async fn udp_query_is_forwarded_and_answered() {
    let doh_addr = start_doh_server().await;
    let proxy_addr = start_plain_proxy(doh_addr).await;

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let req = make_query(0x1234, "example.com.");
    let req_bytes = req.to_bytes().unwrap();

    client.send_to(&req_bytes, proxy_addr).await.unwrap();

    let mut buf = vec![0u8; 4096];
    let (n, _) = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        client.recv_from(&mut buf),
    )
    .await
    .expect("timed out waiting for udp response")
    .unwrap();

    let resp = Message::from_bytes(&buf[..n]).unwrap();
    assert_eq!(resp.id(), 0x1234);
    assert_eq!(resp.answers().len(), 1);
}

#[tokio::test]
async fn tcp_query_is_forwarded_and_answered() {
    let doh_addr = start_doh_server().await;
    let proxy_addr = start_plain_proxy(doh_addr).await;

    let mut stream = TcpStream::connect(proxy_addr).await.unwrap();
    let req = make_query(0x5678, "example.com.");
    let req_bytes = req.to_bytes().unwrap();

    stream.write_u16(req_bytes.len() as u16).await.unwrap();
    stream.write_all(&req_bytes).await.unwrap();

    let len = tokio::time::timeout(std::time::Duration::from_secs(5), stream.read_u16())
        .await
        .expect("timed out waiting for tcp response length")
        .unwrap();
    let mut buf = vec![0u8; len as usize];
    stream.read_exact(&mut buf).await.unwrap();

    let resp = Message::from_bytes(&buf).unwrap();
    assert_eq!(resp.id(), 0x5678);
    assert_eq!(resp.answers().len(), 1);
}
