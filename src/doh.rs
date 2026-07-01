use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper::header::{ACCEPT, USER_AGENT};
use hyper::{Request, Uri};
use hyper_util::client::legacy::connect::{Connected, Connection};
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls_pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

use hickory_proto::op::Message;

use crate::bootstrap::{resolve_dial_context, Resolver, SystemResolver};
use crate::error::DohError;
use crate::options::{HttpVersion, Options};
use crate::wire::{decode_response, encode_request};

const DEFAULT_PORT_DOH: u16 = 443;
const MAX_MSG_SIZE: usize = 65535;

/// A DNS-over-HTTPS upstream client (RFC 8484), supporting HTTP/1.1 and
/// HTTP/2 transports. Analogous to Go's `dnsOverHTTPS` minus the HTTP/3
/// racing logic, which lives in [`crate::doh3`] behind the `http3` feature.
pub struct DohUpstream {
    host: String,
    port: u16,
    path: String,
    addr_redacted: String,
    http_versions: Vec<HttpVersion>,
    resolver: Arc<dyn Resolver>,
    prefer_ipv6: bool,
    timeout: Option<Duration>,
    insecure_skip_verify: bool,

    client: Mutex<Option<Client<HttpsConnector, Empty<Bytes>>>>,
}

impl DohUpstream {
    /// Builds a new upstream for `https://host[:port]/path`. `host` must not
    /// include a scheme.
    pub fn new(host: &str, port: Option<u16>, path: &str, opts: Options) -> Self {
        let port = port.unwrap_or(DEFAULT_PORT_DOH);
        let addr_redacted = format!("https://{host}:{port}{path}");

        Self {
            host: host.to_owned(),
            port,
            path: path.to_owned(),
            addr_redacted,
            http_versions: opts.resolved_http_versions(),
            resolver: opts.bootstrap.unwrap_or_else(|| Arc::new(SystemResolver)),
            prefer_ipv6: opts.prefer_ipv6,
            timeout: opts.timeout,
            insecure_skip_verify: opts.insecure_skip_verify,
            client: Mutex::new(None),
        }
    }

    pub fn address(&self) -> &str {
        &self.addr_redacted
    }

    /// Builds a [`crate::server::Handler`] that forwards every query it
    /// receives to `self` and returns the upstream's response, turning a
    /// [`crate::server::serve`] listener into a minimal DNS-to-DoH proxy.
    pub fn into_handler(self: Arc<Self>) -> crate::server::Handler {
        Arc::new(move |req: Message| {
            let upstream = Arc::clone(&self);
            Box::pin(async move { upstream.exchange(&req).await })
        })
    }

    /// Sends `req` to this upstream, retrying once with a freshly created
    /// client if the first attempt fails with a retryable error (mirrors
    /// `dnsOverHTTPS.Exchange`).
    pub async fn exchange(&self, req: &Message) -> Result<Message, DohError> {
        let (client, was_cached) = self.get_client().await?;

        match self.exchange_https(&client, req).await {
            Ok(resp) => Ok(resp),
            Err(e) if was_cached && e.should_retry() => {
                let client = self.reset_client().await?;
                self.exchange_https(&client, req).await
            }
            Err(e) => {
                self.reset_client_ignore_err().await;
                Err(e)
            }
        }
    }

    async fn get_client(&self) -> Result<(Client<HttpsConnector, Empty<Bytes>>, bool), DohError> {
        let mut guard = self.client.lock().await;
        if let Some(c) = guard.as_ref() {
            return Ok((c.clone(), true));
        }

        let start = Instant::now();
        let client = self.create_client().await?;
        if let Some(t) = self.timeout {
            if start.elapsed() > t {
                return Err(DohError::Timeout(start.elapsed()));
            }
        }

        *guard = Some(client.clone());
        Ok((client, false))
    }

    async fn reset_client(&self) -> Result<Client<HttpsConnector, Empty<Bytes>>, DohError> {
        let mut guard = self.client.lock().await;
        let client = self.create_client().await?;
        *guard = Some(client.clone());
        Ok(client)
    }

    async fn reset_client_ignore_err(&self) {
        let mut guard = self.client.lock().await;
        *guard = None;
    }

    async fn create_client(&self) -> Result<Client<HttpsConnector, Empty<Bytes>>, DohError> {
        let dial = resolve_dial_context(
            &self.host,
            self.port,
            self.timeout,
            self.resolver.as_ref(),
            self.prefer_ipv6,
        )
        .await?;

        let alpns: Vec<Vec<u8>> = self
            .http_versions
            .iter()
            .filter(|v| **v != HttpVersion::Http3)
            .map(|v| v.alpn().as_bytes().to_vec())
            .collect();
        if alpns.is_empty() {
            return Err(DohError::NoSupportedVersions);
        }

        let tls_config = build_tls_config(&self.host, self.insecure_skip_verify, alpns);

        let connector = HttpsConnector {
            dial,
            tls_config: Arc::new(tls_config),
            server_name: self.host.clone(),
        };

        let client = Client::builder(TokioExecutor::new())
            .pool_max_idle_per_host(2)
            .build(connector);

        Ok(client)
    }

    async fn exchange_https(
        &self,
        client: &Client<HttpsConnector, Empty<Bytes>>,
        req: &Message,
    ) -> Result<Message, DohError> {
        let (encoded, original_id) = encode_request(req)?;

        let uri: Uri = format!(
            "https://{}:{}{}?dns={}",
            self.host, self.port, self.path, encoded
        )
        .parse()
        .map_err(|e| DohError::Http(format!("building request uri: {e}")))?;

        let http_req = Request::get(uri)
            .header(USER_AGENT, "")
            .header(ACCEPT, "application/dns-message")
            .body(Empty::<Bytes>::new())
            .map_err(|e| DohError::Http(format!("building request: {e}")))?;

        let fut = client.request(http_req);
        let resp = match self.timeout {
            Some(t) => tokio::time::timeout(t, fut)
                .await
                .map_err(|_| DohError::Timeout(t))?
                .map_err(|e| DohError::Http(error_chain(&e)))?,
            None => fut.await.map_err(|e| DohError::Http(error_chain(&e)))?,
        };

        let status = resp.status();
        let body = resp
            .into_body()
            .collect()
            .await
            .map_err(|e| DohError::Http(format!("reading body: {e}")))?
            .to_bytes();

        if !status.is_success() {
            return Err(DohError::UnexpectedStatus {
                status: status.as_u16(),
                addr: self.addr_redacted.clone(),
            });
        }

        if body.len() > MAX_MSG_SIZE {
            return Err(DohError::Http(format!(
                "response body too large: {} bytes",
                body.len()
            )));
        }

        decode_response(&body, req, original_id)
    }
}

fn error_chain(e: &(dyn std::error::Error + 'static)) -> String {
    let mut parts = vec![e.to_string()];
    let mut source = e.source();
    while let Some(s) = source {
        parts.push(s.to_string());
        source = s.source();
    }
    parts.join(" -> ")
}

fn build_tls_config(
    server_name: &str,
    insecure_skip_verify: bool,
    alpn: Vec<Vec<u8>>,
) -> tokio_rustls::rustls::ClientConfig {
    let mut roots = tokio_rustls::rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let builder = tokio_rustls::rustls::ClientConfig::builder();

    let mut config = if insecure_skip_verify {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(danger::NoVerifier))
            .with_no_client_auth()
    } else {
        builder.with_root_certificates(roots).with_no_client_auth()
    };

    config.alpn_protocols = alpn;
    let _ = server_name;
    config
}

#[cfg(test)]
mod danger_test_helper {}

mod danger {
    use tokio_rustls::rustls::client::danger::{
        HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
    };
    use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use tokio_rustls::rustls::{DigitallySignedStruct, Error, SignatureScheme};

    #[derive(Debug)]
    pub struct NoVerifier;

    impl ServerCertVerifier for NoVerifier {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![
                SignatureScheme::RSA_PKCS1_SHA256,
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::RSA_PSS_SHA256,
                SignatureScheme::ED25519,
            ]
        }
    }
}

/// A `hyper` connector that dials only the addresses resolved at
/// bootstrap-time (via [`crate::bootstrap::DialHandler`]) and wraps the
/// connection in TLS, negotiating HTTP/2 or HTTP/1.1 based on ALPN.
#[derive(Clone)]
struct HttpsConnector {
    dial: crate::bootstrap::DialHandler,
    tls_config: Arc<tokio_rustls::rustls::ClientConfig>,
    server_name: String,
}

impl tower_service::Service<Uri> for HttpsConnector {
    type Response = TokioIo<TlsStream>;
    type Error = DohError;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
    >;

    fn poll_ready(
        &mut self,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, _uri: Uri) -> Self::Future {
        let dial = self.dial.clone();
        let tls_config = Arc::clone(&self.tls_config);
        let server_name = self.server_name.clone();

        Box::pin(async move {
            let conn = (dial)(crate::bootstrap::Network::Tcp).await?;
            let tcp = match conn {
                crate::bootstrap::Conn::Tcp(s) => s,
                crate::bootstrap::Conn::Udp(..) => {
                    return Err(DohError::Http("expected tcp connection".into()))
                }
            };

            let connector = tokio_rustls::TlsConnector::from(tls_config);
            let name = ServerName::try_from(server_name.clone())
                .map_err(|e| DohError::Http(format!("invalid server name: {e}")))?;

            let tls_stream = connector
                .connect(name, tcp)
                .await
                .map_err(|e| DohError::Http(format!("tls handshake failed: {e}")))?;

            Ok(TokioIo::new(TlsStream(tls_stream)))
        })
    }
}

struct TlsStream(tokio_rustls::client::TlsStream<TcpStream>);

impl AsyncRead for TlsStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl AsyncWrite for TlsStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

impl Connection for TlsStream {
    fn connected(&self) -> Connected {
        let (_, conn) = self.0.get_ref();
        let connected = Connected::new();
        if conn.alpn_protocol() == Some(b"h2") {
            connected.negotiated_h2()
        } else {
            connected
        }
    }
}
