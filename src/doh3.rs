//! HTTP/3 support for the DoH client: races a QUIC handshake against a plain
//! TLS handshake to decide whether HTTP/3 is actually faster over this path
//! (mirrors `probeH3`/`probeQUIC`/`probeTLS` in `upstream/doh.go`), then
//! drives the exchange over `h3` if QUIC wins.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use h3::client::SendRequest;
use h3_quinn::quinn;
use hickory_proto::op::Message;
use http::Request;
use tokio::sync::Mutex;

use crate::error::DohError;
use crate::wire::{decode_response, encode_request};

const MAX_MSG_SIZE: usize = 65535;

/// An HTTP/3 transport for a single DoH upstream. Holds a lazily-created
/// QUIC connection and h3 request-sender, recreated on failure the same way
/// the Go client recreates its `*http.Client`.
pub struct Http3Transport {
    server_addr: SocketAddr,
    server_name: String,
    tls_config: Arc<rustls::ClientConfig>,
    timeout: Option<Duration>,
    path: String,

    inner: Mutex<Option<SendRequest<h3_quinn::OpenStreams, Bytes>>>,
}

impl Http3Transport {
    pub fn new(
        server_addr: SocketAddr,
        server_name: String,
        tls_config: Arc<rustls::ClientConfig>,
        timeout: Option<Duration>,
        path: String,
    ) -> Self {
        Self {
            server_addr,
            server_name,
            tls_config,
            timeout,
            path,
            inner: Mutex::new(None),
        }
    }

    async fn connect(&self) -> Result<SendRequest<h3_quinn::OpenStreams, Bytes>, DohError> {
        tracing::debug!(addr = %self.server_addr, server_name = %self.server_name, "opening http/3 connection");
        let quic_conn = dial_quic(
            self.server_addr,
            &self.server_name,
            Arc::clone(&self.tls_config),
        )
        .await?;

        let quinn_conn = h3_quinn::Connection::new(quic_conn);
        let (mut driver, send_request) = h3::client::new(quinn_conn)
            .await
            .map_err(|e| DohError::Quic(e.to_string()))?;

        tokio::spawn(async move {
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });

        Ok(send_request)
    }

    async fn get_sender(&self) -> Result<SendRequest<h3_quinn::OpenStreams, Bytes>, DohError> {
        let mut guard = self.inner.lock().await;
        if let Some(s) = guard.as_ref() {
            return Ok(s.clone());
        }
        let s = self.connect().await?;
        *guard = Some(s.clone());
        Ok(s)
    }

    pub async fn reset(&self) -> Result<SendRequest<h3_quinn::OpenStreams, Bytes>, DohError> {
        let mut guard = self.inner.lock().await;
        let s = self.connect().await?;
        *guard = Some(s.clone());
        Ok(s)
    }

    /// Sends `req` using HTTP/3's `GET` (0-RTT where the server allows it),
    /// mirroring `exchangeHTTPSClient`'s http3 path.
    pub async fn exchange(&self, req: &Message) -> Result<Message, DohError> {
        let mut sender = self.get_sender().await?;

        let (encoded, original_id) = encode_request(req)?;
        let uri: http::Uri = format!("https://{}{}?dns={}", self.server_name, self.path, encoded)
            .parse()
            .map_err(|e| DohError::Http(format!("building request uri: {e}")))?;

        let http_req = Request::get(uri)
            .header(http::header::USER_AGENT, "")
            .header(http::header::ACCEPT, "application/dns-message")
            .body(())
            .map_err(|e| DohError::Http(format!("building request: {e}")))?;

        tracing::debug!(
            server_name = %self.server_name,
            id = original_id,
            questions = ?req.queries(),
            "sending doh request over http/3"
        );

        let fut = async {
            let mut stream = sender
                .send_request(http_req)
                .await
                .map_err(|e| DohError::Quic(e.to_string()))?;
            stream
                .finish()
                .await
                .map_err(|e| DohError::Quic(e.to_string()))?;

            let resp = stream
                .recv_response()
                .await
                .map_err(|e| DohError::Quic(e.to_string()))?;

            if !resp.status().is_success() {
                return Err(DohError::UnexpectedStatus {
                    status: resp.status().as_u16(),
                    addr: self.server_name.clone(),
                });
            }

            let mut body = Vec::new();
            while let Some(chunk) = stream
                .recv_data()
                .await
                .map_err(|e| DohError::Quic(e.to_string()))?
            {
                use bytes::Buf;
                let mut chunk = chunk;
                body.extend_from_slice(chunk.copy_to_bytes(chunk.remaining()).as_ref());
                if body.len() > MAX_MSG_SIZE {
                    return Err(DohError::Http("response body too large".into()));
                }
            }

            Ok(body)
        };

        let body = match self.timeout {
            Some(t) => tokio::time::timeout(t, fut)
                .await
                .map_err(|_| DohError::Timeout(t))??,
            None => fut.await?,
        };

        decode_response(&body, req, original_id)
    }
}

async fn dial_quic(
    addr: SocketAddr,
    server_name: &str,
    tls_config: Arc<rustls::ClientConfig>,
) -> Result<quinn::Connection, DohError> {
    let mut endpoint = quinn::Endpoint::client(if addr.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    })
    .map_err(|e| DohError::Quic(e.to_string()))?;

    let client_config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from((*tls_config).clone())
            .map_err(|e| DohError::Quic(e.to_string()))?,
    ));
    endpoint.set_default_client_config(client_config);

    let connecting = endpoint
        .connect(addr, server_name)
        .map_err(|e| DohError::Quic(e.to_string()))?;

    connecting.await.map_err(|e| DohError::Quic(e.to_string()))
}

/// Races a QUIC handshake against a TLS handshake to `addr` and returns
/// `true` if QUIC established a connection at least as fast as TLS,
/// mirroring `dnsOverHTTPS.probeH3`. `http_supported` should be `false` when
/// this upstream only advertises HTTP/3 (skips the race entirely).
pub async fn probe_h3(
    addr: SocketAddr,
    server_name: &str,
    tls_config: Arc<rustls::ClientConfig>,
    timeout: Option<Duration>,
    http_supported: bool,
) -> bool {
    if !http_supported {
        return true;
    }

    let quic_probe = {
        let tls_config = Arc::clone(&tls_config);
        let server_name = server_name.to_owned();
        async move {
            let start = Instant::now();
            let result = dial_quic(addr, &server_name, tls_config).await;
            (result.is_ok(), start.elapsed())
        }
    };

    let tls_probe = {
        let server_name = server_name.to_owned();
        async move {
            let start = Instant::now();
            let result = probe_tls(addr, &server_name).await;
            (result.is_ok(), start.elapsed())
        }
    };

    let race = async {
        tokio::select! {
            (quic_ok, elapsed) = quic_probe => {
                tracing::debug!(%addr, server_name, quic_ok, ?elapsed, "quic probe won the race");
                quic_ok
            }
            (tls_ok, elapsed) = tls_probe => {
                tracing::debug!(%addr, server_name, tls_ok, ?elapsed, "tls probe won the race");
                !tls_ok
            }
        }
    };

    let prefer_h3 = match timeout {
        Some(t) => tokio::time::timeout(t, race).await.unwrap_or(false),
        None => race.await,
    };
    tracing::debug!(%addr, server_name, prefer_h3, "http/3 probe result");
    prefer_h3
}

async fn probe_tls(addr: SocketAddr, server_name: &str) -> Result<(), DohError> {
    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .map_err(|e| DohError::Io(e))?;

    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();

    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let name = rustls_pki_types::ServerName::try_from(server_name.to_owned())
        .map_err(|e| DohError::Http(format!("invalid server name: {e}")))?;

    connector
        .connect(name, tcp)
        .await
        .map_err(|e| DohError::Http(e.to_string()))?;

    Ok(())
}
