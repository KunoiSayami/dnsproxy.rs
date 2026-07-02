//! RFC 8484 message framing: packing requests for the `dns=` query parameter
//! and validating/unpacking responses.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hickory_proto::op::Message;
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};

use crate::error::DohError;

/// Packs `req` into the base64url-encoded form used in the DoH GET request's
/// `dns` query parameter. Per RFC 8484, the DNS ID is zeroed for cache
/// friendliness; the original ID is restored on the response by
/// [`unpack_response`].
pub fn encode_request(req: &Message) -> Result<(String, u16), DohError> {
    let original_id = req.id();

    let mut zeroed = req.clone();
    zeroed.set_id(0);

    let bytes = zeroed.to_bytes()?;
    Ok((URL_SAFE_NO_PAD.encode(bytes), original_id))
}

/// Unpacks `body` as a DNS message, checks that its ID was zeroed as
/// required by RFC 8484, then restores `original_id` and validates the
/// response's question section against `req`.
pub fn decode_response(body: &[u8], req: &Message, original_id: u16) -> Result<Message, DohError> {
    let mut resp = Message::from_bytes(body)
        .map_err(|e| DohError::InvalidResponse(format!("unpacking response: {e}")))?;

    if resp.id() != 0 {
        return Err(DohError::NonZeroId(resp.id()));
    }
    resp.set_id(original_id);

    validate_response(req, &resp)?;

    Ok(resp)
}

/// Mirrors `validateResponse` in `upstream/upstream.go`: exactly one
/// question, matching type, and case-insensitively matching name.
fn validate_response(req: &Message, resp: &Message) -> Result<(), DohError> {
    if resp.queries().len() != 1 {
        return Err(DohError::InvalidResponse(format!(
            "only 1 question allowed; got {}",
            resp.queries().len()
        )));
    }

    let req_q = &req.queries()[0];
    let resp_q = &resp.queries()[0];

    if req_q.query_type() != resp_q.query_type() {
        return Err(DohError::InvalidResponse(format!(
            "mismatched type {:?}",
            resp_q.query_type()
        )));
    }

    if !req_q
        .name()
        .to_ascii()
        .eq_ignore_ascii_case(&resp_q.name().to_ascii())
    {
        return Err(DohError::InvalidResponse(format!(
            "mismatched name {:?}",
            resp_q.name()
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{Message, MessageType, OpCode, Query};
    use hickory_proto::rr::{Name, RecordType};
    use hickory_proto::serialize::binary::BinEncodable;
    use std::str::FromStr;

    fn make_query(id: u16, name: &str) -> Message {
        let mut msg = Message::new();
        msg.set_id(id);
        msg.set_message_type(MessageType::Query);
        msg.set_op_code(OpCode::Query);
        msg.add_query(Query::query(Name::from_str(name).unwrap(), RecordType::A));
        msg
    }

    #[test]
    fn encode_request_zeroes_id_and_preserves_original() {
        let req = make_query(1234, "example.com.");
        let (encoded, original_id) = encode_request(&req).unwrap();
        assert_eq!(original_id, 1234);

        // Decoding the base64url payload should show a zeroed ID, per RFC 8484.
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&encoded)
            .unwrap();
        let msg = Message::from_bytes(&decoded).unwrap();
        assert_eq!(msg.id(), 0);
    }

    #[test]
    fn decode_response_restores_original_id() {
        let req = make_query(4321, "example.com.");
        let (_, original_id) = encode_request(&req).unwrap();

        let mut resp = req.clone();
        resp.set_id(0);
        resp.set_message_type(MessageType::Response);
        let body = resp.to_bytes().unwrap();

        let decoded = decode_response(&body, &req, original_id).unwrap();
        assert_eq!(decoded.id(), 4321);
    }

    #[test]
    fn decode_response_rejects_non_zero_id() {
        let req = make_query(1, "example.com.");
        let mut resp = req.clone();
        resp.set_id(42);
        let body = resp.to_bytes().unwrap();

        let err = decode_response(&body, &req, 1).unwrap_err();
        assert!(matches!(err, DohError::NonZeroId(42)));
    }

    #[test]
    fn decode_response_rejects_mismatched_qtype() {
        let req = make_query(1, "example.com.");
        let mut resp = Message::new();
        resp.set_id(0);
        resp.set_message_type(MessageType::Response);
        resp.add_query(Query::query(
            Name::from_str("example.com.").unwrap(),
            RecordType::AAAA,
        ));
        let body = resp.to_bytes().unwrap();

        let err = decode_response(&body, &req, 1).unwrap_err();
        assert!(matches!(err, DohError::InvalidResponse(_)));
    }

    #[test]
    fn decode_response_accepts_case_insensitive_name() {
        let req = make_query(1, "Example.COM.");
        let mut resp = Message::new();
        resp.set_id(0);
        resp.set_message_type(MessageType::Response);
        resp.add_query(Query::query(
            Name::from_str("example.com.").unwrap(),
            RecordType::A,
        ));
        let body = resp.to_bytes().unwrap();

        let decoded = decode_response(&body, &req, 1).unwrap();
        assert_eq!(decoded.id(), 1);
    }

    #[test]
    fn decode_response_rejects_multiple_questions() {
        let req = make_query(1, "example.com.");
        let mut resp = Message::new();
        resp.set_id(0);
        resp.set_message_type(MessageType::Response);
        resp.add_query(Query::query(
            Name::from_str("example.com.").unwrap(),
            RecordType::A,
        ));
        resp.add_query(Query::query(
            Name::from_str("other.com.").unwrap(),
            RecordType::A,
        ));
        let body = resp.to_bytes().unwrap();

        let err = decode_response(&body, &req, 1).unwrap_err();
        assert!(matches!(err, DohError::InvalidResponse(_)));
    }
}
