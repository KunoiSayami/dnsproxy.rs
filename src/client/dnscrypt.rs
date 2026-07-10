//! A DNSCrypt upstream client, mirroring Go's `dnsCrypt` in
//! `upstream/dnscrypt.go`: fetches and caches the resolver's certificate via
//! a plain TXT query, then exchanges DNS messages encrypted per the
//! DNSCrypt v2 wire protocol (`dnscrypt::crypto`) over UDP, falling back to
//! TCP when the UDP response is truncated.

#[cfg(feature = "dnscrypt-server")]
pub mod config;
pub(crate) mod crypto;
#[cfg(feature = "dnscrypt-server")]
pub mod keygen;
pub(crate) mod stamp;

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RData, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::RwLock;

use crate::client::wire::validate_response;
use crate::error::DohError;
use crate::options::Options;

use crypto::{Certificate, ClientKeyPair};
use stamp::{DnsCryptStamp, parse_dnscrypt_stamp};

const MAX_UDP_MSG_SIZE: usize = 65535;

/// A DNSCrypt upstream, identified by an `sdns://` stamp.
pub struct DnsCryptUpstream {
    stamp: DnsCryptStamp,
    addr_redacted: String,
    timeout: Option<Duration>,
    cert: RwLock<Option<Certificate>>,
}

impl DnsCryptUpstream {
    /// Parses `stamp_url` (an `sdns://...` string) and builds a new
    /// [`DnsCryptUpstream`]. The resolver certificate isn't fetched until
    /// the first [`Self::exchange`] call.
    pub fn new(stamp_url: &str, opts: Options) -> Result<Self, String> {
        let stamp = parse_dnscrypt_stamp(stamp_url)?;
        Ok(Self {
            stamp,
            addr_redacted: stamp_url.to_owned(),
            timeout: opts.timeout,
            cert: RwLock::new(None),
        })
    }

    pub fn address(&self) -> &str {
        &self.addr_redacted
    }

    /// Sends `req` to this upstream, encrypting it per the DNSCrypt
    /// protocol, and validates the response against it. Fetches (and
    /// caches) the resolver certificate on first use or after it expires;
    /// retries once with a freshly fetched certificate on timeout, since
    /// that likely means the resolver rotated its key.
    pub async fn exchange(&self, req: &Message) -> Result<Message, DohError> {
        let fut = async {
            let cert = self.current_cert().await?;
            match self.exchange_with_cert(&cert, req).await {
                Ok(resp) => Ok(resp),
                Err(e) if matches!(e, DohError::Timeout(_) | DohError::Io(_)) => {
                    let cert = self.refresh_cert().await?;
                    self.exchange_with_cert(&cert, req).await
                }
                Err(e) => Err(e),
            }
        };

        match self.timeout {
            Some(d) => tokio::time::timeout(d, fut)
                .await
                .map_err(|_| DohError::Timeout(d))?,
            None => fut.await,
        }
    }

    async fn exchange_with_cert(
        &self,
        cert: &Certificate,
        req: &Message,
    ) -> Result<Message, DohError> {
        let req_bytes = req.to_bytes()?;
        let client = ClientKeyPair::generate();
        let (framed, client_nonce) = crypto::encrypt_query(cert, &client, &req_bytes)?;

        let enc_resp = self.exchange_udp(&framed).await?;
        let resp_bytes = crypto::decrypt_response(cert, &client, &client_nonce, &enc_resp)?;
        let resp = Message::from_bytes(&resp_bytes)
            .map_err(|e| DohError::InvalidResponse(format!("unpacking response: {e}")))?;

        if resp.metadata.truncation {
            let enc_resp = self.exchange_tcp(&framed).await?;
            let resp_bytes = crypto::decrypt_response(cert, &client, &client_nonce, &enc_resp)?;
            let resp = Message::from_bytes(&resp_bytes)
                .map_err(|e| DohError::InvalidResponse(format!("unpacking response: {e}")))?;
            validate_response(req, &resp)?;
            return Ok(resp);
        }

        validate_response(req, &resp)?;
        Ok(resp)
    }

    async fn exchange_udp(&self, framed: &[u8]) -> Result<Vec<u8>, DohError> {
        let local = if self.stamp.addr.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let sock = UdpSocket::bind(local).await?;
        sock.connect(self.stamp.addr).await?;
        sock.send(framed).await?;

        let mut buf = [0u8; MAX_UDP_MSG_SIZE];
        let n = sock.recv(&mut buf).await?;
        Ok(buf[..n].to_vec())
    }

    async fn exchange_tcp(&self, framed: &[u8]) -> Result<Vec<u8>, DohError> {
        if framed.len() > u16::MAX as usize {
            return Err(DohError::DnsCrypt(
                "encrypted query too large for tcp framing".into(),
            ));
        }

        let mut tcp = TcpStream::connect(self.stamp.addr).await?;
        tcp.write_all(&(framed.len() as u16).to_be_bytes()).await?;
        tcp.write_all(framed).await?;

        let mut len_buf = [0u8; 2];
        tcp.read_exact(&mut len_buf).await?;
        let resp_len = u16::from_be_bytes(len_buf) as usize;

        let mut resp_buf = vec![0u8; resp_len];
        tcp.read_exact(&mut resp_buf).await?;
        Ok(resp_buf)
    }

    /// Returns the cached certificate if present and still valid, otherwise
    /// fetches (and caches) a fresh one.
    async fn current_cert(&self) -> Result<Certificate, DohError> {
        {
            let guard = self.cert.read().await;
            if let Some(cert) = guard.as_ref()
                && cert.is_valid_at(now_unix())
            {
                return Ok(cert.clone());
            }
        }
        self.refresh_cert().await
    }

    async fn refresh_cert(&self) -> Result<Certificate, DohError> {
        let txt_records = self.fetch_provider_txt().await?;
        let mut certs = crypto::parse_certificates(&txt_records, &self.stamp.provider_public_key)?;

        let now = now_unix();
        certs.retain(|c| c.is_valid_at(now));

        let cert = certs.into_iter().next().ok_or_else(|| {
            DohError::DnsCrypt(format!(
                "no valid certificate found for provider {:?}",
                self.stamp.provider_name
            ))
        })?;

        *self.cert.write().await = Some(cert.clone());
        Ok(cert)
    }

    /// Queries the resolver directly (plain DNS-over-UDP) for the provider
    /// name's TXT records, which carry the resolver certificate(s). Returns
    /// raw bytes rather than `String`s, since certificates are binary data
    /// that a lossy UTF-8 conversion would corrupt.
    async fn fetch_provider_txt(&self) -> Result<Vec<Vec<u8>>, DohError> {
        let name = Name::from_ascii(&self.stamp.provider_name)
            .map_err(|e| DohError::DnsCrypt(format!("invalid provider name: {e}")))?;
        let mut msg = Message::new(rand::random(), MessageType::Query, OpCode::Query);
        msg.metadata.recursion_desired = true;
        msg.add_query(Query::query(name, RecordType::TXT));

        let req_bytes = msg.to_bytes()?;

        let local = if self.stamp.addr.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let sock = UdpSocket::bind(local).await?;
        sock.connect(self.stamp.addr).await?;
        sock.send(&req_bytes).await?;

        let mut buf = [0u8; MAX_UDP_MSG_SIZE];
        let n = sock.recv(&mut buf).await?;

        let resp = Message::from_bytes(&buf[..n])
            .map_err(|e| DohError::InvalidResponse(format!("unpacking cert response: {e}")))?;

        Ok(resp
            .answers
            .iter()
            .filter_map(|rec| match &rec.data {
                RData::TXT(txt) => Some(txt),
                _ => None,
            })
            .flat_map(|txt| txt.txt_data.iter())
            .map(|bytes| bytes.to_vec())
            .collect())
    }
}

fn now_unix() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::ClientKeyPair as ServerKeyPair;
    use ed25519_dalek::{Signer, SigningKey};
    use hickory_proto::op::{MessageType, OpCode, Query};
    use hickory_proto::rr::{Name, RData, Record, RecordType, rdata::TXT};
    use std::net::SocketAddr;
    use std::str::FromStr;
    use tokio::net::TcpListener;

    const CERT_MAGIC: &[u8; 4] = b"DNSC";
    const RESOLVER_MAGIC: &[u8; 8] = b"r6fnvWj8";

    fn make_query(id: u16, name: &str) -> Message {
        let mut msg = Message::new(id, MessageType::Query, OpCode::Query);
        msg.add_query(Query::query(Name::from_str(name).unwrap(), RecordType::A));
        msg
    }

    /// Builds a signed certificate TXT payload for a fresh resolver keypair,
    /// returning the raw cert bytes alongside the provider's long-term
    /// signing key and the resolver's short-term keypair.
    fn make_cert(
        provider_signing_key: &SigningKey,
        client_magic: [u8; 8],
    ) -> (Vec<u8>, ServerKeyPair) {
        let resolver_kp = ServerKeyPair::generate();

        let mut signed = Vec::new();
        signed.extend_from_slice(resolver_kp.public_key());
        signed.extend_from_slice(&client_magic);
        signed.extend_from_slice(&1u32.to_be_bytes()); // serial
        signed.extend_from_slice(&0u32.to_be_bytes()); // ts_start
        signed.extend_from_slice(&u32::MAX.to_be_bytes()); // ts_end

        let signature = provider_signing_key.sign(&signed);

        let mut cert = Vec::new();
        cert.extend_from_slice(CERT_MAGIC);
        cert.extend_from_slice(&1u16.to_be_bytes()); // es-version: XSalsa20Poly1305
        cert.extend_from_slice(&[0x00, 0x00]); // minor version
        cert.extend_from_slice(&signature.to_bytes());
        cert.extend_from_slice(&signed);

        (cert, resolver_kp)
    }

    fn cert_response(req: &Message, cert_bytes: &[u8]) -> Message {
        let mut resp = Message::new(req.metadata.id, MessageType::Response, OpCode::Query);
        resp.metadata.message_type = MessageType::Response;
        resp.add_query(req.queries[0].clone());
        resp.add_answer(Record::from_rdata(
            req.queries[0].name().clone(),
            60,
            RData::TXT(TXT::from_bytes(vec![cert_bytes])),
        ));
        resp
    }

    fn decrypt_client_query<'a>(
        resolver_kp: &ServerKeyPair,
        client_magic: &[u8; 8],
        framed: &'a [u8],
    ) -> (Vec<u8>, [u8; 32], [u8; 12]) {
        assert_eq!(&framed[0..8], client_magic);
        let client_pk: [u8; 32] = framed[8..40].try_into().unwrap();
        let client_nonce: [u8; 12] = framed[40..52].try_into().unwrap();

        let salsa_box = crypto_box::SalsaBox::new(
            &crypto_box::PublicKey::from(client_pk),
            resolver_kp.secret_key_for_test(),
        );
        let mut full_nonce = [0u8; 24];
        full_nonce[..12].copy_from_slice(&client_nonce);
        use crypto_box::aead::Aead;
        let padded = salsa_box
            .decrypt(
                crypto_box::aead::generic_array::GenericArray::from_slice(&full_nonce),
                &framed[52..],
            )
            .unwrap();
        let idx = padded.iter().rposition(|&b| b != 0).unwrap();
        assert_eq!(padded[idx], 0x80);
        (padded[..idx].to_vec(), client_pk, client_nonce)
    }

    fn encrypt_server_response(
        resolver_kp: &ServerKeyPair,
        client_pk: [u8; 32],
        client_nonce: [u8; 12],
        msg: &[u8],
    ) -> Vec<u8> {
        use crypto_box::aead::Aead;
        let salsa_box = crypto_box::SalsaBox::new(
            &crypto_box::PublicKey::from(client_pk),
            resolver_kp.secret_key_for_test(),
        );

        let mut resolver_nonce = [0u8; 12];
        crypto_box::aead::rand_core::RngCore::fill_bytes(
            &mut crypto_box::aead::rand_core::OsRng,
            &mut resolver_nonce,
        );
        let mut full_nonce = [0u8; 24];
        full_nonce[..12].copy_from_slice(&client_nonce);
        full_nonce[12..].copy_from_slice(&resolver_nonce);

        let mut padded = msg.to_vec();
        padded.push(0x80);
        let rem = padded.len() % 64;
        if rem != 0 {
            padded.resize(padded.len() + (64 - rem), 0);
        }

        let ciphertext = salsa_box
            .encrypt(
                crypto_box::aead::generic_array::GenericArray::from_slice(&full_nonce),
                padded.as_slice(),
            )
            .unwrap();

        let mut resp = Vec::new();
        resp.extend_from_slice(RESOLVER_MAGIC);
        resp.extend_from_slice(&client_nonce);
        resp.extend_from_slice(&resolver_nonce);
        resp.extend_from_slice(&ciphertext);
        resp
    }

    #[tokio::test]
    async fn exchange_roundtrips_over_udp() {
        let provider_signing_key = SigningKey::generate(&mut crypto_box::aead::rand_core::OsRng);
        let provider_pk = provider_signing_key.verifying_key().to_bytes();
        let client_magic = *b"TESTMAGC";
        let (cert_bytes, resolver_kp) = make_cert(&provider_signing_key, client_magic);

        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let mut buf = [0u8; 65535];

            // First exchange: certificate fetch (a TXT query).
            let (n, peer) = server.recv_from(&mut buf).await.unwrap();
            let req = Message::from_bytes(&buf[..n]).unwrap();
            let resp = cert_response(&req, &cert_bytes);
            server
                .send_to(&resp.to_bytes().unwrap(), peer)
                .await
                .unwrap();

            // Second exchange: the encrypted DNS query.
            let (n, peer) = server.recv_from(&mut buf).await.unwrap();
            let (inner_bytes, client_pk, client_nonce) =
                decrypt_client_query(&resolver_kp, &client_magic, &buf[..n]);
            let inner_req = Message::from_bytes(&inner_bytes).unwrap();

            let mut inner_resp = inner_req.clone();
            inner_resp.metadata.message_type = MessageType::Response;
            let inner_resp_bytes = inner_resp.to_bytes().unwrap();

            let framed_resp =
                encrypt_server_response(&resolver_kp, client_pk, client_nonce, &inner_resp_bytes);
            server.send_to(&framed_resp, peer).await.unwrap();
        });

        let stamp = build_stamp_url(server_addr, &provider_pk, "test-provider");
        let upstream = DnsCryptUpstream::new(
            &stamp,
            Options {
                timeout: Some(Duration::from_secs(5)),
                ..Default::default()
            },
        )
        .unwrap();

        let req = make_query(42, "example.com.");
        let resp = upstream.exchange(&req).await.unwrap();
        assert_eq!(resp.metadata.id, 42);

        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn exchange_falls_back_to_tcp_on_truncation() {
        let provider_signing_key = SigningKey::generate(&mut crypto_box::aead::rand_core::OsRng);
        let provider_pk = provider_signing_key.verifying_key().to_bytes();
        let client_magic = *b"TESTMAGC";
        let (cert_bytes, resolver_kp) = make_cert(&provider_signing_key, client_magic);

        let udp_server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = udp_server.local_addr().unwrap();
        let tcp_listener = TcpListener::bind(server_addr).await.unwrap();

        let server_task = tokio::spawn(async move {
            let mut buf = [0u8; 65535];

            // Certificate fetch over UDP.
            let (n, peer) = udp_server.recv_from(&mut buf).await.unwrap();
            let req = Message::from_bytes(&buf[..n]).unwrap();
            let resp = cert_response(&req, &cert_bytes);
            udp_server
                .send_to(&resp.to_bytes().unwrap(), peer)
                .await
                .unwrap();

            // Encrypted query over UDP: respond with TC=1 and empty answer.
            let (n, peer) = udp_server.recv_from(&mut buf).await.unwrap();
            let (inner_bytes, client_pk, client_nonce) =
                decrypt_client_query(&resolver_kp, &client_magic, &buf[..n]);
            let inner_req = Message::from_bytes(&inner_bytes).unwrap();

            let mut truncated_resp = inner_req.clone();
            truncated_resp.metadata.message_type = MessageType::Response;
            truncated_resp.metadata.truncation = true;
            let truncated_bytes = truncated_resp.to_bytes().unwrap();
            let framed_truncated =
                encrypt_server_response(&resolver_kp, client_pk, client_nonce, &truncated_bytes);
            udp_server.send_to(&framed_truncated, peer).await.unwrap();

            // Client should now retry over TCP with the same encrypted query.
            let (mut tcp, _) = tcp_listener.accept().await.unwrap();
            let mut len_buf = [0u8; 2];
            tcp.read_exact(&mut len_buf).await.unwrap();
            let len = u16::from_be_bytes(len_buf) as usize;
            let mut framed = vec![0u8; len];
            tcp.read_exact(&mut framed).await.unwrap();

            let (inner_bytes, client_pk, client_nonce) =
                decrypt_client_query(&resolver_kp, &client_magic, &framed);
            let inner_req = Message::from_bytes(&inner_bytes).unwrap();

            let mut final_resp = inner_req.clone();
            final_resp.metadata.message_type = MessageType::Response;
            let final_bytes = final_resp.to_bytes().unwrap();
            let framed_final =
                encrypt_server_response(&resolver_kp, client_pk, client_nonce, &final_bytes);

            tcp.write_all(&(framed_final.len() as u16).to_be_bytes())
                .await
                .unwrap();
            tcp.write_all(&framed_final).await.unwrap();
        });

        let stamp = build_stamp_url(server_addr, &provider_pk, "test-provider");
        let upstream = DnsCryptUpstream::new(
            &stamp,
            Options {
                timeout: Some(Duration::from_secs(5)),
                ..Default::default()
            },
        )
        .unwrap();

        let req = make_query(7, "example.com.");
        let resp = upstream.exchange(&req).await.unwrap();
        assert_eq!(resp.metadata.id, 7);
        assert!(!resp.metadata.truncation);

        server_task.await.unwrap();
    }

    /// Builds an `sdns://` stamp string for `addr`/`provider_pk`/`provider_name`.
    fn build_stamp_url(addr: SocketAddr, provider_pk: &[u8; 32], provider_name: &str) -> String {
        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;

        let mut bytes = Vec::new();
        bytes.push(0x01u8); // DNSCrypt protocol type
        bytes.extend_from_slice(&[0u8; 8]); // properties

        let addr_str = addr.to_string();
        bytes.push(addr_str.len() as u8);
        bytes.extend_from_slice(addr_str.as_bytes());

        bytes.push(provider_pk.len() as u8);
        bytes.extend_from_slice(provider_pk);

        bytes.push(provider_name.len() as u8);
        bytes.extend_from_slice(provider_name.as_bytes());

        format!("sdns://{}", URL_SAFE_NO_PAD.encode(bytes))
    }
}
