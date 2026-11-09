//! RFC 8484 message framing: packing requests for the `dns=` query parameter
//! and validating/unpacking responses.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hickory_proto::op::{Edns, Message, OpCode, ResponseCode};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};

use crate::error::DohError;

/// Packs `req` into the base64url-encoded form used in the DoH GET request's
/// `dns` query parameter. Per RFC 8484, the DNS ID is zeroed for cache
/// friendliness; the original ID is restored on the response by
/// [`unpack_response`].
pub fn encode_request(req: &Message) -> Result<(String, u16), DohError> {
    let original_id = req.metadata.id;

    let mut zeroed = req.clone();
    zeroed.metadata.id = 0;

    let bytes = zeroed.to_bytes()?;
    Ok((URL_SAFE_NO_PAD.encode(bytes), original_id))
}

/// Unpacks `body` as a DNS message, checks that its ID was zeroed as
/// required by RFC 8484, then restores `original_id` and validates the
/// response's question section against `req`.
pub fn decode_response(body: &[u8], req: &Message, original_id: u16) -> Result<Message, DohError> {
    let mut resp = Message::from_bytes(body)
        .map_err(|e| DohError::InvalidResponse(format!("unpacking response: {e}")))?;

    if resp.metadata.id != 0 {
        return Err(DohError::NonZeroId(resp.metadata.id));
    }
    resp.metadata.id = original_id;

    validate_response(req, &resp)?;

    Ok(resp)
}

/// Decodes a DoH request body: raw DNS wireformat bytes (the RFC 8484 POST
/// form) or, if `dns_param` is given instead (the GET form's `dns` query
/// parameter), its base64url decoding. Used by DoH/DoH3 listeners; the
/// mirror image of [`encode_request`], which the DoH client uses instead.
pub fn decode_request(dns_param: Option<&str>, body: &[u8]) -> Result<Message, DohError> {
    let bytes = match dns_param {
        Some(param) => URL_SAFE_NO_PAD
            .decode(param)
            .map_err(|e| DohError::InvalidResponse(format!("decoding dns param: {e}")))?,
        None => body.to_vec(),
    };
    Message::from_bytes(&bytes)
        .map_err(|e| DohError::InvalidResponse(format!("unpacking doh request: {e}")))
}

/// Encodes a DoH response as raw DNS wireformat bytes, for the
/// `application/dns-message` response body. The mirror image of
/// [`decode_response`], which the DoH client uses instead.
pub fn encode_response(resp: &Message) -> Result<Vec<u8>, DohError> {
    Ok(resp.to_bytes()?)
}

/// Builds a SERVFAIL reply to `req`, for when it couldn't be resolved.
/// Mirrors `genServerFailure` in `proxy/proxy.go`, i.e. miekg/dns's
/// `Msg.SetRcode`: copies the ID and opcode, the RD and CD bits (for
/// standard queries only), and the first question, and sets RA.
///
/// Unlike the Go version, it answers an EDNS request with an OPT record, as
/// RFC 6891 section 7 requires of an EDNS-aware responder: version 0, the
/// request's UDP payload size, and the DO bit copied per RFC 3225. The
/// request's EDNS options (cookies, client subnet, ...) aren't echoed.
pub fn servfail(req: &Message) -> Message {
    let mut resp = Message::error_msg(
        req.metadata.id,
        req.metadata.op_code,
        ResponseCode::ServFail,
    );
    if req.metadata.op_code == OpCode::Query {
        resp.metadata.recursion_desired = req.metadata.recursion_desired;
        resp.metadata.checking_disabled = req.metadata.checking_disabled;
    }
    resp.metadata.recursion_available = true;
    if let Some(query) = req.queries.first() {
        resp.add_query(query.clone());
    }
    if let Some(req_edns) = &req.edns {
        let mut edns = Edns::new();
        edns.set_version(0)
            .set_max_payload(req_edns.max_payload())
            .set_dnssec_ok(req_edns.flags().dnssec_ok);
        resp.set_edns(edns);
    }
    resp
}

/// Formats a `host:port` authority for display, bracketing `host` if it's a
/// literal IPv6 address (e.g. `[::1]:53` rather than the ambiguous
/// `::1:53`).
pub fn format_host_port(host: &str, port: u16) -> String {
    if host.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// Mirrors `validateResponse` in `upstream/upstream.go`: exactly one
/// question, matching type, and case-insensitively matching name.
pub fn validate_response(req: &Message, resp: &Message) -> Result<(), DohError> {
    if resp.queries.len() != 1 {
        return Err(DohError::InvalidResponse(format!(
            "only 1 question allowed; got {}",
            resp.queries.len()
        )));
    }

    let req_q = &req.queries[0];
    let resp_q = &resp.queries[0];

    if req_q.query_type() != resp_q.query_type() {
        return Err(DohError::InvalidResponse(format!(
            "mismatched type {:?}",
            resp_q.query_type()
        )));
    }

    if !req_q.name().eq_ignore_root(resp_q.name()) {
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
        let mut msg = Message::new(id, MessageType::Query, OpCode::Query);
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
        assert_eq!(msg.metadata.id, 0);
    }

    #[test]
    fn decode_response_restores_original_id() {
        let req = make_query(4321, "example.com.");
        let (_, original_id) = encode_request(&req).unwrap();

        let mut resp = req.clone();
        resp.metadata.id = 0;
        resp.metadata.message_type = MessageType::Response;
        let body = resp.to_bytes().unwrap();

        let decoded = decode_response(&body, &req, original_id).unwrap();
        assert_eq!(decoded.metadata.id, 4321);
    }

    #[test]
    fn decode_response_rejects_non_zero_id() {
        let req = make_query(1, "example.com.");
        let mut resp = req.clone();
        resp.metadata.id = 42;
        let body = resp.to_bytes().unwrap();

        let err = decode_response(&body, &req, 1).unwrap_err();
        assert!(matches!(err, DohError::NonZeroId(42)));
    }

    #[test]
    fn decode_response_rejects_mismatched_qtype() {
        let req = make_query(1, "example.com.");
        let mut resp = Message::new(0, MessageType::Response, OpCode::Query);
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
        let mut resp = Message::new(0, MessageType::Response, OpCode::Query);
        resp.add_query(Query::query(
            Name::from_str("example.com.").unwrap(),
            RecordType::A,
        ));
        let body = resp.to_bytes().unwrap();

        let decoded = decode_response(&body, &req, 1).unwrap();
        assert_eq!(decoded.metadata.id, 1);
    }

    #[test]
    fn decode_response_rejects_multiple_questions() {
        let req = make_query(1, "example.com.");
        let mut resp = Message::new(0, MessageType::Response, OpCode::Query);
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

    #[test]
    fn servfail_copies_id_flags_and_first_question() {
        let mut req = make_query(0x1234, "example.com.");
        req.metadata.recursion_desired = true;
        req.metadata.checking_disabled = true;
        req.add_query(Query::query(
            Name::from_str("second.example.").unwrap(),
            RecordType::AAAA,
        ));

        let resp = servfail(&req);
        assert_eq!(resp.metadata.id, 0x1234);
        assert_eq!(resp.metadata.message_type, MessageType::Response);
        assert_eq!(resp.metadata.op_code, OpCode::Query);
        assert_eq!(resp.metadata.response_code, ResponseCode::ServFail);
        assert!(resp.metadata.recursion_desired);
        assert!(resp.metadata.checking_disabled);
        assert!(resp.metadata.recursion_available);
        assert_eq!(resp.queries, vec![req.queries[0].clone()]);
        assert!(resp.answers.is_empty());
        assert!(resp.edns.is_none());
    }

    #[test]
    fn servfail_answers_edns_request_with_opt_record() {
        let mut req = make_query(1, "example.com.");
        let mut req_edns = Edns::new();
        req_edns.set_max_payload(1232).set_dnssec_ok(true);
        req_edns
            .options_mut()
            .insert(hickory_proto::rr::rdata::opt::EdnsOption::Unknown(
                10,
                vec![0; 8],
            ));
        req.set_edns(req_edns);

        let resp = servfail(&req);
        let edns = resp.edns.as_ref().expect("EDNS request gets an OPT record");
        assert_eq!(edns.version(), 0);
        assert_eq!(edns.max_payload(), 1232);
        assert!(edns.flags().dnssec_ok);
        assert!(edns.options().as_ref().is_empty());

        // And it survives the wire roundtrip.
        let decoded = Message::from_bytes(&resp.to_bytes().unwrap()).unwrap();
        assert_eq!(decoded.metadata.response_code, ResponseCode::ServFail);
        assert_eq!(decoded.edns.unwrap().max_payload(), 1232);
    }
}
