use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine;
use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper::header::{ACCEPT, AUTHORIZATION, USER_AGENT};
use hyper::{Request, Uri};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::{Connected, Connection};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls_pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

use hickory_proto::op::Message;

#[cfg(feature = "http3")]
use crate::client::bootstrap::resolve_addrs;
use crate::client::bootstrap::{Resolver, SystemResolver, resolve_dial_context};
use crate::client::wire::{decode_response, encode_request};
use crate::error::DohError;
use crate::options::{HttpVersion, Options};

const DEFAULT_PORT_DOH: u16 = 443;
const MAX_MSG_SIZE: usize = 65535;

/// A DNS-over-HTTPS upstream client (RFC 8484), supporting HTTP/1.1 and
/// HTTP/2 always, and HTTP/3 behind the `http3` feature: mirrors Go's
/// `dnsOverHTTPS`, racing a QUIC handshake against TLS (via
/// [`crate::client::doh3::probe_h3`]) to decide which to use, unless the upstream
/// only advertises HTTP/3.
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
    basic_auth_header: Option<String>,

    client: Mutex<Option<Client<HttpsConnector, Empty<Bytes>>>>,
    #[cfg(feature = "http3")]
    h3: Mutex<Option<Arc<crate::client::doh3::Http3Transport>>>,
    /// Cached result of racing HTTP/3 against HTTP/2 (mirrors Go caching
    /// `probeH3`'s outcome on the upstream). `None` until the first
    /// exchange; irrelevant when [`Self::http_versions`] names only one of
    /// the two.
    #[cfg(feature = "http3")]
    prefer_h3: Mutex<Option<bool>>,
}

impl DohUpstream {
    /// Builds a new upstream for `https://host[:port]/path`. `host` must not
    /// include a scheme.
    pub fn new(host: &str, port: Option<u16>, path: &str, opts: Options) -> Self {
        let port = port.unwrap_or(DEFAULT_PORT_DOH);
        let addr_redacted = format!("https://{host}:{port}{path}");
        let http_versions = opts.resolved_http_versions();
        let basic_auth_header = opts.basic_auth.map(|(user, pass)| {
            let credentials =
                base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}"));
            format!("Basic {credentials}")
        });

        Self {
            host: host.to_owned(),
            port,
            path: path.to_owned(),
            addr_redacted,
            http_versions,
            resolver: opts.bootstrap.unwrap_or_else(|| Arc::new(SystemResolver)),
            prefer_ipv6: opts.prefer_ipv6,
            timeout: opts.timeout,
            insecure_skip_verify: opts.insecure_skip_verify,
            basic_auth_header,
            client: Mutex::new(None),
            #[cfg(feature = "http3")]
            h3: Mutex::new(None),
            #[cfg(feature = "http3")]
            prefer_h3: Mutex::new(None),
        }
    }

    /// The upstream's host, as given to [`Self::new`] (no scheme, port, or
    /// path).
    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn address(&self) -> &str {
        &self.addr_redacted
    }

    /// Builds a [`crate::listener::io::Handler`] that forwards every query it
    /// receives to `self` and returns the upstream's response, turning a
    /// [`crate::listener::io::serve`] listener into a minimal DNS-to-DoH proxy.
    pub fn into_handler(self: Arc<Self>) -> crate::listener::io::Handler {
        Arc::new(move |req: Message| {
            let upstream = Arc::clone(&self);
            Box::pin(async move { upstream.exchange(&req).await })
        })
    }

    /// Sends `req` to this upstream, retrying once with a freshly created
    /// client if the first attempt fails with a retryable error (mirrors
    /// `dnsOverHTTPS.Exchange`).
    pub async fn exchange(&self, req: &Message) -> Result<Message, DohError> {
        #[cfg(feature = "http3")]
        if self.should_use_http3().await? {
            return self.exchange_h3(req).await;
        }

        let (client, was_cached) = self.get_client().await?;

        match self.exchange_https(&client, req).await {
            Ok(resp) => Ok(resp),
            Err(e) if was_cached && e.should_retry() => {
                tracing::debug!(addr = %self.addr_redacted, error = %e, "retrying with a fresh client");
                let client = self.reset_client().await?;
                self.exchange_https(&client, req).await
            }
            Err(e) => {
                tracing::warn!(addr = %self.addr_redacted, error = %e, "exchange failed");
                self.reset_client_ignore_err().await;
                Err(e)
            }
        }
    }

    /// Whether HTTP/2 (or 1.1) is among this upstream's allowed versions,
    /// i.e. whether the racing probe against HTTP/3 is meaningful at all.
    #[cfg(feature = "http3")]
    fn http2_supported(&self) -> bool {
        self.http_versions.iter().any(|v| *v != HttpVersion::Http3)
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

    #[cfg(feature = "http3")]
    /// Decides whether to use HTTP/3 for this exchange: always true if it's
    /// the only version this upstream allows, always false if it isn't
    /// allowed at all, otherwise the cached (or freshly probed) result of
    /// racing a QUIC handshake against TLS, mirroring `dnsOverHTTPS.exchangeHTTPSClient`.
    async fn should_use_http3(&self) -> Result<bool, DohError> {
        let allows_http3 = self.http_versions.contains(&HttpVersion::Http3);
        if !allows_http3 {
            return Ok(false);
        }
        if !self.http2_supported() {
            return Ok(true);
        }

        if let Some(prefer) = *self.prefer_h3.lock().await {
            return Ok(prefer);
        }

        let addrs = resolve_addrs(
            &self.host,
            self.port,
            self.timeout,
            self.resolver.as_ref(),
            self.prefer_ipv6,
        )
        .await?;
        let addr = *addrs
            .first()
            .ok_or_else(|| DohError::Bootstrap(format!("no addresses for {}", self.host)))?;

        let tls_config =
            build_tls_config(&self.host, self.insecure_skip_verify, vec![b"h2".to_vec()]);
        let prefer = crate::client::doh3::probe_h3(
            addr,
            &self.host,
            Arc::new(tls_config),
            self.timeout,
            true,
        )
        .await;

        *self.prefer_h3.lock().await = Some(prefer);
        Ok(prefer)
    }

    #[cfg(feature = "http3")]
    async fn exchange_h3(&self, req: &Message) -> Result<Message, DohError> {
        let (transport, was_cached) = self.get_h3_transport().await?;

        match transport.exchange(req).await {
            Ok(resp) => Ok(resp),
            Err(e) if was_cached && e.should_retry() => {
                tracing::debug!(addr = %self.addr_redacted, error = %e, "retrying http/3 with a fresh transport");
                transport.reset().await?;
                transport.exchange(req).await
            }
            Err(e) => {
                tracing::warn!(addr = %self.addr_redacted, error = %e, "http/3 exchange failed");
                *self.h3.lock().await = None;
                Err(e)
            }
        }
    }

    #[cfg(feature = "http3")]
    async fn get_h3_transport(
        &self,
    ) -> Result<(Arc<crate::client::doh3::Http3Transport>, bool), DohError> {
        let mut guard = self.h3.lock().await;
        if let Some(t) = guard.as_ref() {
            return Ok((Arc::clone(t), true));
        }

        let addrs = resolve_addrs(
            &self.host,
            self.port,
            self.timeout,
            self.resolver.as_ref(),
            self.prefer_ipv6,
        )
        .await?;
        let addr = *addrs
            .first()
            .ok_or_else(|| DohError::Bootstrap(format!("no addresses for {}", self.host)))?;

        let tls_config =
            build_tls_config(&self.host, self.insecure_skip_verify, vec![b"h3".to_vec()]);
        let transport = Arc::new(crate::client::doh3::Http3Transport::new(
            addr,
            self.host.clone(),
            Arc::new(tls_config),
            self.timeout,
            self.path.clone(),
            self.basic_auth_header.clone(),
        ));

        *guard = Some(Arc::clone(&transport));
        Ok((transport, false))
    }

    async fn create_client(&self) -> Result<Client<HttpsConnector, Empty<Bytes>>, DohError> {
        tracing::debug!(host = %self.host, port = self.port, "creating http client");
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

        let mut builder = Request::get(uri)
            .header(USER_AGENT, "")
            .header(ACCEPT, "application/dns-message");
        if let Some(auth) = &self.basic_auth_header {
            builder = builder.header(AUTHORIZATION, auth);
        }
        let http_req = builder
            .body(Empty::<Bytes>::new())
            .map_err(|e| DohError::Http(format!("building request: {e}")))?;

        tracing::debug!(
            addr = %self.addr_redacted,
            id = original_id,
            questions = ?req.queries,
            "sending doh request"
        );

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

pub(crate) fn build_tls_config(
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
/// bootstrap-time (via [`crate::client::bootstrap::DialHandler`]) and wraps the
/// connection in TLS, negotiating HTTP/2 or HTTP/1.1 based on ALPN.
#[derive(Clone)]
struct HttpsConnector {
    dial: crate::client::bootstrap::DialHandler,
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
            let conn = (dial)(crate::client::bootstrap::Network::Tcp).await?;
            let tcp = match conn {
                crate::client::bootstrap::Conn::Tcp(s) => s,
                crate::client::bootstrap::Conn::Udp(..) => {
                    return Err(DohError::Http("expected tcp connection".into()));
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
