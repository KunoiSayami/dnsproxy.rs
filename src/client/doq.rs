//! A DNS-over-QUIC (RFC 9250) upstream client, mirroring Go's `dnsOverQUIC`
//! in `upstream/quic.go`: each exchange opens a fresh bidirectional QUIC
//! stream, writes a 2-byte length-prefixed query with a zeroed DNS ID (per
//! RFC 9250 section 4.2.1), and reads a length-prefixed response.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use hickory_proto::op::Message;
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use tokio::sync::Mutex;

use crate::client::bootstrap::{Resolver, SystemResolver, resolve_addrs};
use crate::client::wire::{format_host_port, validate_response};
use crate::error::DohError;

const DEFAULT_PORT_DOQ: u16 = 853;
const MAX_MSG_SIZE: usize = 65535;
const DOQ_ALPN: &[u8] = b"doq";

/// A DNS-over-QUIC upstream, holding a lazily-created QUIC connection that's
/// reused across exchanges (each exchange opens its own bidirectional
/// stream on it), and recreated on failure.
pub struct DoqUpstream {
    host: String,
    port: u16,
    addr_redacted: String,
    resolver: Arc<dyn Resolver>,
    prefer_ipv6: bool,
    timeout: Option<Duration>,
    insecure_skip_verify: bool,

    conn: Mutex<Option<quinn::Connection>>,
}

impl DoqUpstream {
    pub fn new(host: &str, port: Option<u16>, opts: crate::options::Options) -> Self {
        let port = port.unwrap_or(DEFAULT_PORT_DOQ);
        Self {
            host: host.to_owned(),
            port,
            addr_redacted: format!("quic://{}", format_host_port(host, port)),
            resolver: opts.bootstrap.unwrap_or_else(|| Arc::new(SystemResolver)),
            prefer_ipv6: opts.prefer_ipv6,
            timeout: opts.timeout,
            insecure_skip_verify: opts.insecure_skip_verify,
            conn: Mutex::new(None),
        }
    }

    pub fn address(&self) -> &str {
        &self.addr_redacted
    }

    /// Sends `req` to this upstream over QUIC, retrying once with a fresh
    /// connection if the first attempt fails with a retryable error.
    pub async fn exchange(&self, req: &Message) -> Result<Message, DohError> {
        let (conn, was_cached) = self.get_conn().await?;

        match self.exchange_on(&conn, req).await {
            Ok(resp) => Ok(resp),
            Err(e) if was_cached && e.should_retry() => {
                tracing::debug!(addr = %self.addr_redacted, error = %e, "retrying doq with a fresh connection");
                let conn = self.reset_conn().await?;
                self.exchange_on(&conn, req).await
            }
            Err(e) => {
                tracing::warn!(addr = %self.addr_redacted, error = %e, "doq exchange failed");
                *self.conn.lock().await = None;
                Err(e)
            }
        }
    }

    async fn exchange_on(
        &self,
        conn: &quinn::Connection,
        req: &Message,
    ) -> Result<Message, DohError> {
        let original_id = req.metadata.id;
        // RFC 9250 section 4.2.1 requires the DNS ID to be 0 on the wire.
        let mut zeroed = req.clone();
        zeroed.metadata.id = 0;
        let req_bytes = zeroed.to_bytes()?;

        if req_bytes.len() > u16::MAX as usize {
            return Err(DohError::Pack(hickory_proto::ProtoError::from(
                "message too large for doq framing",
            )));
        }

        let fut = async {
            let (mut send, mut recv) = conn
                .open_bi()
                .await
                .map_err(|e| DohError::Quic(e.to_string()))?;

            let len = (req_bytes.len() as u16).to_be_bytes();
            send.write_all(&len)
                .await
                .map_err(|e| DohError::Quic(e.to_string()))?;
            send.write_all(&req_bytes)
                .await
                .map_err(|e| DohError::Quic(e.to_string()))?;
            send.finish().map_err(|e| DohError::Quic(e.to_string()))?;

            let mut len_buf = [0u8; 2];
            recv.read_exact(&mut len_buf)
                .await
                .map_err(|e| DohError::Quic(e.to_string()))?;
            let resp_len = u16::from_be_bytes(len_buf) as usize;
            if resp_len > MAX_MSG_SIZE {
                return Err(DohError::InvalidResponse("response too large".into()));
            }

            let mut resp_buf = vec![0u8; resp_len];
            recv.read_exact(&mut resp_buf)
                .await
                .map_err(|e| DohError::Quic(e.to_string()))?;

            let mut resp = Message::from_bytes(&resp_buf)
                .map_err(|e| DohError::InvalidResponse(format!("unpacking response: {e}")))?;
            if resp.metadata.id != 0 {
                return Err(DohError::NonZeroId(resp.metadata.id));
            }
            resp.metadata.id = original_id;

            validate_response(req, &resp)?;
            Ok(resp)
        };

        match self.timeout {
            Some(d) => tokio::time::timeout(d, fut)
                .await
                .map_err(|_| DohError::Timeout(d))?,
            None => fut.await,
        }
    }

    async fn get_conn(&self) -> Result<(quinn::Connection, bool), DohError> {
        let mut guard = self.conn.lock().await;
        if let Some(c) = guard.as_ref() {
            return Ok((c.clone(), true));
        }
        let c = self.dial().await?;
        *guard = Some(c.clone());
        Ok((c, false))
    }

    async fn reset_conn(&self) -> Result<quinn::Connection, DohError> {
        let mut guard = self.conn.lock().await;
        let c = self.dial().await?;
        *guard = Some(c.clone());
        Ok(c)
    }

    async fn dial(&self) -> Result<quinn::Connection, DohError> {
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

        let tls_config = crate::client::doh::build_tls_config(
            &self.host,
            self.insecure_skip_verify,
            vec![DOQ_ALPN.to_vec()],
        );

        dial_quic(addr, &self.host, Arc::new(tls_config)).await
    }
}

async fn dial_quic(
    addr: SocketAddr,
    server_name: &str,
    tls_config: Arc<tokio_rustls::rustls::ClientConfig>,
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

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{MessageType, OpCode, Query};
    use hickory_proto::rr::{Name, RecordType};
    use std::str::FromStr;

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

    #[tokio::test]
    async fn exchange_roundtrips_over_quic() {
        let server_config = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(server_tls_config()).unwrap(),
        ));
        let endpoint =
            quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = endpoint.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let incoming = endpoint.accept().await.unwrap();
            let conn = incoming.await.unwrap();
            let (mut send, mut recv) = conn.accept_bi().await.unwrap();

            let mut len_buf = [0u8; 2];
            recv.read_exact(&mut len_buf).await.unwrap();
            let len = u16::from_be_bytes(len_buf) as usize;
            let mut req_buf = vec![0u8; len];
            recv.read_exact(&mut req_buf).await.unwrap();
            let req = Message::from_bytes(&req_buf).unwrap();
            assert_eq!(req.metadata.id, 0);

            let mut resp = req.clone();
            resp.metadata.message_type = MessageType::Response;
            let bytes = resp.to_bytes().unwrap();
            send.write_all(&(bytes.len() as u16).to_be_bytes())
                .await
                .unwrap();
            send.write_all(&bytes).await.unwrap();
            send.finish().unwrap();
            // Keep the connection alive until the peer has actually read the
            // response; otherwise dropping `conn` here races an implicit
            // close against the client's read.
            let _ = send.stopped().await;
        });

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
        server_task.await.unwrap();
    }
}
