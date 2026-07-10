//! The DNSCrypt v2 wire protocol: resolver certificate parsing/verification
//! and query/response encryption, per the spec at
//! <https://dnscrypt.info/protocol/> (DNSCrypt-V2-protocol.txt).
//!
//! Only the `X25519-XSalsa20Poly1305` cipher suite is implemented, matching
//! this crate's `crypto_box` dependency (`salsa20` feature); certificates
//! advertising `X25519-XChaCha20Poly1305` are rejected as unsupported.

use crypto_box::aead::rand_core::{OsRng, RngCore};
use crypto_box::aead::{Aead, generic_array::GenericArray};
use crypto_box::{PublicKey, SalsaBox, SecretKey};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

use crate::error::DohError;

/// `DNSC`, the fixed magic prefixing every resolver certificate.
pub(crate) const CERT_MAGIC: &[u8; 4] = b"DNSC";

/// es-version for the `X25519-XSalsa20Poly1305` cipher suite.
pub(crate) const ES_VERSION_XSALSA20POLY1305: u16 = 0x0001;

/// The fixed 8-byte magic prefixing every resolver response.
const RESOLVER_MAGIC: &[u8; 8] = b"r6fnvWj8";

/// Certificates are padded/aligned to a multiple of this many bytes, per the
/// spec's recommendation to cushion against length-based fingerprinting.
const PAD_BLOCK_SIZE: usize = 64;

/// A verified DNSCrypt resolver certificate, embedding the resolver's
/// short-term X25519 public key used to encrypt queries until it expires.
#[derive(Debug, Clone)]
pub struct Certificate {
    pub resolver_public_key: [u8; 32],
    pub client_magic: [u8; 8],
    pub serial: u32,
    pub ts_start: u32,
    pub ts_end: u32,
}

impl Certificate {
    /// Whether this certificate is valid at `now` (a Unix timestamp).
    pub fn is_valid_at(&self, now: u32) -> bool {
        self.ts_start <= now && now < self.ts_end
    }
}

/// Parses and verifies every certificate found in `txt_records` (the raw
/// bytes of each TXT record returned by a query for the provider name;
/// certificates are binary data, not text, so this must not be lossily
/// converted through UTF-8), keeping only those whose Ed25519 signature
/// checks out against `provider_public_key`. Returns them sorted by
/// descending serial, matching the resolver's own precedence rules.
pub fn parse_certificates(
    txt_records: &[Vec<u8>],
    provider_public_key: &[u8; 32],
) -> Result<Vec<Certificate>, DohError> {
    let verifying_key = VerifyingKey::from_bytes(provider_public_key)
        .map_err(|e| DohError::DnsCrypt(format!("invalid provider public key: {e}")))?;

    let mut certs: Vec<Certificate> = txt_records
        .iter()
        .filter_map(|txt| parse_one_certificate(txt, &verifying_key))
        .collect();

    certs.sort_by_key(|c| std::cmp::Reverse(c.serial));
    Ok(certs)
}

/// Parses and verifies a single certificate's raw bytes, returning `None` if
/// it's malformed, uses an unsupported cipher suite, or fails signature
/// verification (logging the reason at debug level rather than failing the
/// whole batch, since a provider may publish certs for suites we don't
/// support alongside ones we do).
fn parse_one_certificate(bytes: &[u8], verifying_key: &VerifyingKey) -> Option<Certificate> {
    // magic(4) + es-version(2) + minor-version(2) + signature(64) +
    // resolver-pk(32) + client-magic(8) + serial(4) + ts-start(4) + ts-end(4)
    const HEADER_LEN: usize = 4 + 2 + 2;
    const SIGNED_LEN: usize = 32 + 8 + 4 + 4 + 4;
    const MIN_LEN: usize = HEADER_LEN + 64 + SIGNED_LEN;

    if bytes.len() < MIN_LEN {
        tracing::debug!(len = bytes.len(), "dnscrypt cert too short, skipping");
        return None;
    }
    if &bytes[0..4] != CERT_MAGIC {
        tracing::debug!("dnscrypt cert has wrong magic, skipping");
        return None;
    }
    let es_version = u16::from_be_bytes([bytes[4], bytes[5]]);
    if es_version != ES_VERSION_XSALSA20POLY1305 {
        tracing::debug!(
            es_version,
            "dnscrypt cert has unsupported cipher suite, skipping"
        );
        return None;
    }

    let signature_bytes = &bytes[HEADER_LEN..HEADER_LEN + 64];
    let signed = &bytes[HEADER_LEN + 64..HEADER_LEN + 64 + SIGNED_LEN];

    let signature = Signature::from_slice(signature_bytes).ok()?;
    verifying_key.verify(signed, &signature).ok()?;

    let resolver_public_key: [u8; 32] = signed[0..32].try_into().ok()?;
    let client_magic: [u8; 8] = signed[32..40].try_into().ok()?;
    let serial = u32::from_be_bytes(signed[40..44].try_into().ok()?);
    let ts_start = u32::from_be_bytes(signed[44..48].try_into().ok()?);
    let ts_end = u32::from_be_bytes(signed[48..52].try_into().ok()?);

    Some(Certificate {
        resolver_public_key,
        client_magic,
        serial,
        ts_start,
        ts_end,
    })
}

/// Builds and signs a resolver certificate's raw bytes, the mirror image of
/// [`parse_one_certificate`]: `provider_signing_key` signs over
/// `resolver_public_key || client_magic || serial || ts_start || ts_end`,
/// and the result is prefixed with the magic/es-version/minor-version
/// header. Always uses the `X25519-XSalsa20Poly1305` cipher suite, matching
/// this crate's only supported suite.
pub fn sign_certificate(
    provider_signing_key: &SigningKey,
    resolver_public_key: &[u8; 32],
    client_magic: &[u8; 8],
    serial: u32,
    ts_start: u32,
    ts_end: u32,
) -> Vec<u8> {
    let mut signed = Vec::new();
    signed.extend_from_slice(resolver_public_key);
    signed.extend_from_slice(client_magic);
    signed.extend_from_slice(&serial.to_be_bytes());
    signed.extend_from_slice(&ts_start.to_be_bytes());
    signed.extend_from_slice(&ts_end.to_be_bytes());

    let signature = provider_signing_key.sign(&signed);

    let mut cert = Vec::with_capacity(8 + 64 + signed.len());
    cert.extend_from_slice(CERT_MAGIC);
    cert.extend_from_slice(&ES_VERSION_XSALSA20POLY1305.to_be_bytes());
    cert.extend_from_slice(&[0x00, 0x00]); // minor version
    cert.extend_from_slice(&signature.to_bytes());
    cert.extend_from_slice(&signed);
    cert
}

/// An ephemeral client keypair, generated fresh per exchange per the spec
/// (unlike the resolver's short-term key, which is reused until its
/// certificate expires).
pub struct ClientKeyPair {
    secret_key: SecretKey,
    public_key: [u8; 32],
}

impl ClientKeyPair {
    pub fn generate() -> Self {
        let secret_key = SecretKey::generate(&mut OsRng);
        let public_key = *secret_key.public_key().as_bytes();
        Self {
            secret_key,
            public_key,
        }
    }

    pub fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }

    /// Exposes the secret key for tests that simulate the resolver side of
    /// an exchange (which needs it to derive the same shared `SalsaBox` the
    /// client used).
    #[cfg(test)]
    pub(crate) fn secret_key_for_test(&self) -> &SecretKey {
        &self.secret_key
    }
}

/// Pads `msg` with a `0x80` byte followed by zeros up to the next multiple
/// of [`PAD_BLOCK_SIZE`], per the spec's `<client-query>` padding rule.
fn pad(msg: &[u8]) -> Vec<u8> {
    let mut padded = Vec::with_capacity(msg.len() + PAD_BLOCK_SIZE);
    padded.extend_from_slice(msg);
    padded.push(0x80);
    let rem = padded.len() % PAD_BLOCK_SIZE;
    if rem != 0 {
        padded.resize(padded.len() + (PAD_BLOCK_SIZE - rem), 0);
    }
    padded
}

/// Strips the `0x80`-then-zeros padding [`pad`] added, returning an error if
/// the padding is malformed (no `0x80` marker found).
fn unpad(padded: &[u8]) -> Result<&[u8], DohError> {
    match padded.iter().rposition(|&b| b != 0) {
        Some(idx) if padded[idx] == 0x80 => Ok(&padded[..idx]),
        _ => Err(DohError::DnsCrypt("invalid padding in response".into())),
    }
}

/// Builds the `SalsaBox` shared between one side's secret key and the other
/// side's public key. Symmetric: the same box results whether called as
/// `shared_box(client_secret, resolver_pk)` or
/// `shared_box(resolver_secret, client_pk)`, since both derive the same
/// X25519 Diffie-Hellman shared secret.
fn shared_box(secret_key: &SecretKey, peer_public_key: &[u8; 32]) -> SalsaBox {
    SalsaBox::new(&PublicKey::from(*peer_public_key), secret_key)
}

/// Encrypts `msg` (a raw DNS wireformat query) for `cert`, returning the
/// full framed query (`client-magic || client-pk || client-nonce ||
/// encrypted-padded-msg`) ready to send on the wire, along with the 12-byte
/// client nonce half needed to decrypt the matching response.
pub fn encrypt_query(
    cert: &Certificate,
    client: &ClientKeyPair,
    msg: &[u8],
) -> Result<(Vec<u8>, [u8; 12]), DohError> {
    let mut client_nonce = [0u8; 12];
    OsRng.fill_bytes(&mut client_nonce);

    let mut full_nonce = [0u8; 24];
    full_nonce[..12].copy_from_slice(&client_nonce);

    let salsa_box = shared_box(&client.secret_key, &cert.resolver_public_key);
    let padded = pad(msg);
    let ciphertext = salsa_box
        .encrypt(GenericArray::from_slice(&full_nonce), padded.as_slice())
        .map_err(|e| DohError::DnsCrypt(format!("encrypting query: {e}")))?;

    let mut framed = Vec::with_capacity(8 + 32 + 12 + ciphertext.len());
    framed.extend_from_slice(&cert.client_magic);
    framed.extend_from_slice(client.public_key());
    framed.extend_from_slice(&client_nonce);
    framed.extend_from_slice(&ciphertext);

    Ok((framed, client_nonce))
}

/// Decrypts a resolver response previously produced for a query encrypted
/// with [`encrypt_query`], validating the resolver magic and reusing
/// `client_nonce` (the half returned by [`encrypt_query`]) to reconstruct
/// the full nonce.
pub fn decrypt_response(
    cert: &Certificate,
    client: &ClientKeyPair,
    client_nonce: &[u8; 12],
    resp: &[u8],
) -> Result<Vec<u8>, DohError> {
    if resp.len() < RESOLVER_MAGIC.len() + 24 {
        return Err(DohError::DnsCrypt("response too short".into()));
    }
    if &resp[0..8] != RESOLVER_MAGIC {
        return Err(DohError::DnsCrypt(
            "response has wrong resolver magic".into(),
        ));
    }

    let resp_client_nonce = &resp[8..20];
    if resp_client_nonce != client_nonce {
        return Err(DohError::DnsCrypt(
            "response echoes a different client nonce".into(),
        ));
    }
    let resolver_nonce = &resp[20..32];

    let mut full_nonce = [0u8; 24];
    full_nonce[..12].copy_from_slice(client_nonce);
    full_nonce[12..].copy_from_slice(resolver_nonce);

    let ciphertext = &resp[32..];
    let salsa_box = shared_box(&client.secret_key, &cert.resolver_public_key);
    let padded = salsa_box
        .decrypt(GenericArray::from_slice(&full_nonce), ciphertext)
        .map_err(|e| DohError::DnsCrypt(format!("decrypting response: {e}")))?;

    Ok(unpad(&padded)?.to_vec())
}

/// Parses the `<client-magic><client-pk><client-nonce><ciphertext>` framing
/// of an incoming encrypted query and decrypts it with the resolver's secret
/// key, the mirror image of [`encrypt_query`]. Returns the decrypted,
/// unpadded query bytes along with the client's public key and nonce half
/// (both needed to encrypt the matching response via
/// [`encrypt_server_response`]).
pub fn decrypt_query(
    resolver_secret: &SecretKey,
    expected_client_magic: &[u8; 8],
    framed: &[u8],
) -> Result<(Vec<u8>, [u8; 32], [u8; 12]), DohError> {
    const HEADER_LEN: usize = 8 + 32 + 12;
    if framed.len() < HEADER_LEN {
        return Err(DohError::DnsCrypt("query too short".into()));
    }
    if &framed[0..8] != expected_client_magic {
        return Err(DohError::DnsCrypt("query has wrong client magic".into()));
    }

    let client_public_key: [u8; 32] = framed[8..40].try_into().unwrap();
    let client_nonce: [u8; 12] = framed[40..52].try_into().unwrap();

    let mut full_nonce = [0u8; 24];
    full_nonce[..12].copy_from_slice(&client_nonce);

    let salsa_box = shared_box(resolver_secret, &client_public_key);
    let padded = salsa_box
        .decrypt(GenericArray::from_slice(&full_nonce), &framed[HEADER_LEN..])
        .map_err(|e| DohError::DnsCrypt(format!("decrypting query: {e}")))?;

    Ok((unpad(&padded)?.to_vec(), client_public_key, client_nonce))
}

/// Encrypts `msg` (a raw DNS wireformat response) for the client identified
/// by `client_public_key`/`client_nonce` (as returned by [`decrypt_query`]),
/// framing it as `<resolver-magic><client-nonce><resolver-nonce><ciphertext>`,
/// the mirror image of [`decrypt_response`].
pub fn encrypt_server_response(
    resolver_secret: &SecretKey,
    client_public_key: &[u8; 32],
    client_nonce: &[u8; 12],
    msg: &[u8],
) -> Result<Vec<u8>, DohError> {
    let mut resolver_nonce = [0u8; 12];
    OsRng.fill_bytes(&mut resolver_nonce);

    let mut full_nonce = [0u8; 24];
    full_nonce[..12].copy_from_slice(client_nonce);
    full_nonce[12..].copy_from_slice(&resolver_nonce);

    let salsa_box = shared_box(resolver_secret, client_public_key);
    let padded = pad(msg);
    let ciphertext = salsa_box
        .encrypt(GenericArray::from_slice(&full_nonce), padded.as_slice())
        .map_err(|e| DohError::DnsCrypt(format!("encrypting response: {e}")))?;

    let mut framed = Vec::with_capacity(8 + 12 + 12 + ciphertext.len());
    framed.extend_from_slice(RESOLVER_MAGIC);
    framed.extend_from_slice(client_nonce);
    framed.extend_from_slice(&resolver_nonce);
    framed.extend_from_slice(&ciphertext);

    Ok(framed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn make_signed_cert(
        signing_key: &SigningKey,
        resolver_public_key: [u8; 32],
        client_magic: [u8; 8],
        serial: u32,
        ts_start: u32,
        ts_end: u32,
    ) -> Vec<u8> {
        let mut signed = Vec::new();
        signed.extend_from_slice(&resolver_public_key);
        signed.extend_from_slice(&client_magic);
        signed.extend_from_slice(&serial.to_be_bytes());
        signed.extend_from_slice(&ts_start.to_be_bytes());
        signed.extend_from_slice(&ts_end.to_be_bytes());

        let signature = signing_key.sign(&signed);

        let mut cert = Vec::new();
        cert.extend_from_slice(CERT_MAGIC);
        cert.extend_from_slice(&ES_VERSION_XSALSA20POLY1305.to_be_bytes());
        cert.extend_from_slice(&[0x00, 0x00]); // minor version
        cert.extend_from_slice(&signature.to_bytes());
        cert.extend_from_slice(&signed);
        cert
    }

    #[test]
    fn parses_valid_signed_certificate() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let provider_pk = signing_key.verifying_key().to_bytes();
        let resolver_pk = [7u8; 32];
        let client_magic = *b"DNSC\0\0\0\0";

        let cert_bytes = make_signed_cert(&signing_key, resolver_pk, client_magic, 2, 100, 200);

        let cert = parse_one_certificate(
            &cert_bytes,
            &VerifyingKey::from_bytes(&provider_pk).unwrap(),
        );
        assert!(cert.is_some(), "cert should parse and verify");
        let cert = cert.unwrap();
        assert_eq!(cert.resolver_public_key, resolver_pk);
        assert_eq!(cert.client_magic, client_magic);
        assert_eq!(cert.serial, 2);
        assert_eq!(cert.ts_start, 100);
        assert_eq!(cert.ts_end, 200);
    }

    #[test]
    fn rejects_tampered_certificate() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let provider_pk = signing_key.verifying_key().to_bytes();
        let mut cert_bytes =
            make_signed_cert(&signing_key, [7u8; 32], *b"DNSC\0\0\0\0", 2, 100, 200);

        // Flip a byte in the signed portion so the signature no longer matches.
        let last = cert_bytes.len() - 1;
        cert_bytes[last] ^= 0xff;

        let cert = parse_one_certificate(
            &cert_bytes,
            &VerifyingKey::from_bytes(&provider_pk).unwrap(),
        );
        assert!(cert.is_none());
    }

    #[test]
    fn rejects_wrong_magic() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let provider_pk = signing_key.verifying_key().to_bytes();
        let mut cert_bytes =
            make_signed_cert(&signing_key, [7u8; 32], *b"DNSC\0\0\0\0", 2, 100, 200);
        cert_bytes[0] = b'X';

        let cert = parse_one_certificate(
            &cert_bytes,
            &VerifyingKey::from_bytes(&provider_pk).unwrap(),
        );
        assert!(cert.is_none());
    }

    #[test]
    fn parse_certificates_sorts_by_serial_desc() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let provider_pk = signing_key.verifying_key().to_bytes();

        let cert1 = make_signed_cert(&signing_key, [1u8; 32], *b"DNSC\0\0\0\0", 1, 100, 200);
        let cert2 = make_signed_cert(&signing_key, [2u8; 32], *b"DNSC\0\0\0\0", 5, 100, 200);
        let cert3 = make_signed_cert(&signing_key, [3u8; 32], *b"DNSC\0\0\0\0", 3, 100, 200);

        let txts = vec![cert1, cert2, cert3];

        let certs = parse_certificates(&txts, &provider_pk).unwrap();
        assert_eq!(certs.len(), 3);
        assert_eq!(certs[0].serial, 5);
        assert_eq!(certs[1].serial, 3);
        assert_eq!(certs[2].serial, 1);
    }

    #[test]
    fn is_valid_at_checks_window() {
        let cert = Certificate {
            resolver_public_key: [0u8; 32],
            client_magic: [0u8; 8],
            serial: 1,
            ts_start: 100,
            ts_end: 200,
        };
        assert!(!cert.is_valid_at(99));
        assert!(cert.is_valid_at(100));
        assert!(cert.is_valid_at(150));
        assert!(!cert.is_valid_at(200));
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let resolver_secret = SecretKey::generate(&mut OsRng);
        let resolver_public_key = *resolver_secret.public_key().as_bytes();

        let cert = Certificate {
            resolver_public_key,
            client_magic: *b"DNSC\0\0\0\0",
            serial: 1,
            ts_start: 0,
            ts_end: u32::MAX,
        };

        let client = ClientKeyPair::generate();
        let msg = b"hello dnscrypt";

        let (framed, client_nonce) = encrypt_query(&cert, &client, msg).unwrap();

        // Simulate the resolver side: parse the framed query, decrypt with
        // its own secret key, then build+encrypt a response.
        assert_eq!(&framed[0..8], &cert.client_magic);
        let sent_client_pk: [u8; 32] = framed[8..40].try_into().unwrap();
        let sent_nonce: [u8; 12] = framed[40..52].try_into().unwrap();
        assert_eq!(sent_nonce, client_nonce);

        let resolver_box = SalsaBox::new(&PublicKey::from(sent_client_pk), &resolver_secret);
        let mut full_nonce = [0u8; 24];
        full_nonce[..12].copy_from_slice(&sent_nonce);
        let decrypted_on_server = resolver_box
            .decrypt(GenericArray::from_slice(&full_nonce), &framed[52..])
            .unwrap();
        assert_eq!(unpad(&decrypted_on_server).unwrap(), msg);

        // Build a response the way a resolver would: magic + client-nonce +
        // resolver-nonce + encrypt(padded response).
        let mut resolver_nonce = [0u8; 12];
        OsRng.fill_bytes(&mut resolver_nonce);
        let mut resp_full_nonce = [0u8; 24];
        resp_full_nonce[..12].copy_from_slice(&sent_nonce);
        resp_full_nonce[12..].copy_from_slice(&resolver_nonce);

        let resp_msg = b"hello back";
        let resp_ciphertext = resolver_box
            .encrypt(
                GenericArray::from_slice(&resp_full_nonce),
                pad(resp_msg).as_slice(),
            )
            .unwrap();

        let mut resp = Vec::new();
        resp.extend_from_slice(RESOLVER_MAGIC);
        resp.extend_from_slice(&sent_nonce);
        resp.extend_from_slice(&resolver_nonce);
        resp.extend_from_slice(&resp_ciphertext);

        let decrypted = decrypt_response(&cert, &client, &client_nonce, &resp).unwrap();
        assert_eq!(decrypted, resp_msg);
    }

    #[test]
    fn decrypt_response_rejects_wrong_magic() {
        let cert = Certificate {
            resolver_public_key: [0u8; 32],
            client_magic: [0u8; 8],
            serial: 1,
            ts_start: 0,
            ts_end: u32::MAX,
        };
        let client = ClientKeyPair::generate();
        let bad_resp = vec![0u8; 64];
        let err = decrypt_response(&cert, &client, &[0u8; 12], &bad_resp).unwrap_err();
        assert!(matches!(err, DohError::DnsCrypt(_)));
    }

    #[test]
    fn decrypt_response_rejects_mismatched_nonce() {
        let resolver_secret = SecretKey::generate(&mut OsRng);
        let cert = Certificate {
            resolver_public_key: *resolver_secret.public_key().as_bytes(),
            client_magic: *b"DNSC\0\0\0\0",
            serial: 1,
            ts_start: 0,
            ts_end: u32::MAX,
        };
        let client = ClientKeyPair::generate();

        let mut resp = Vec::new();
        resp.extend_from_slice(RESOLVER_MAGIC);
        resp.extend_from_slice(&[9u8; 12]); // different nonce than expected
        resp.extend_from_slice(&[0u8; 12]);
        resp.extend_from_slice(&[0u8; 16]);

        let err = decrypt_response(&cert, &client, &[1u8; 12], &resp).unwrap_err();
        assert!(matches!(err, DohError::DnsCrypt(_)));
    }

    #[test]
    fn pad_unpad_roundtrip() {
        let msg = b"some dns message bytes";
        let padded = pad(msg);
        assert_eq!(padded.len() % PAD_BLOCK_SIZE, 0);
        assert_eq!(unpad(&padded).unwrap(), msg);
    }

    #[test]
    fn unpad_rejects_all_zero() {
        let bytes = vec![0u8; 64];
        assert!(unpad(&bytes).is_err());
    }
}
