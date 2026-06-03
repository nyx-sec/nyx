//! Minimal BER (ASN.1) reader/writer for LDAPv3 bind + search messages.
//!
//! The Phase 06 LDAP stub at [`super::ldap_server`] speaks a custom
//! plaintext `SEARCH <filter>\n` / `COUNT <n>\n` framed-line protocol so
//! per-language harnesses can drive it without linking a real LDAP
//! client.  The deferred work for that phase tracks "tier (b)" — a
//! real LDAPv3 ASN.1 BER wire round-trip so a harness using
//! `javax.naming.directory.InitialDirContext` (or any other stock LDAP
//! client) can talk to the stub directly.
//!
//! This module is the unblocking primitive: a zero-dependency BER
//! reader+writer that covers exactly the tags LDAPv3 bind +
//! search-request +  search-result-entry + search-result-done messages
//! need.  It deliberately rejects everything else so a malformed
//! payload cannot exfiltrate state through the parser; rejection falls
//! through to `None` and the caller short-circuits to the plaintext
//! fallback path.
//!
//! # Scope
//!
//! Universal tags: `INTEGER` (0x02), `OCTET STRING` (0x04),
//! `ENUMERATED` (0x0A), `SEQUENCE` (0x30).
//!
//! Application tags (LDAP RFC 4511 §4.1):
//! `BindRequest` (0x60), `BindResponse` (0x61), `SearchRequest` (0x63),
//! `SearchResultEntry` (0x64), `SearchResultDone` (0x65).
//!
//! Context-specific tags inside `Filter` (RFC 4511 §4.5.1):
//! and \[0\], or \[1\], not \[2\], equalityMatch \[3\], substrings \[4\],
//! greaterOrEqual \[5\], lessOrEqual \[6\], present \[7\], approxMatch \[8\].
//! Plus simple-auth \[0\] inside `AuthenticationChoice`.
//!
//! Length encoding: short-form (single byte 0x00-0x7F) and long-form
//! (0x81-0x84 length-of-length, value up to 32 bits).  Indefinite
//! length (0x80) is rejected — LDAP DER never uses it.
//!
//! Integer encoding: two's-complement, big-endian, minimum-byte form
//! (LDAP integers are non-negative `MessageID` / version / result-code
//! values, but the decoder accepts the full two's-complement range so
//! a hand-rolled client that emits leading zero bytes still parses).
//!
//! # Filter rendering
//!
//! The decoded `SearchRequest` filter is re-rendered into the
//! RFC 4515 string syntax (`(uid=alice)`, `(|(uid=alice)(uid=*))`) so
//! the existing [`super::ldap_server::LdapStub::evaluate`] subset
//! matcher consumes it without a parallel evaluator.  Only the four
//! filter shapes the matcher already covers are rendered; anything
//! richer (`>=`, `<=`, `~=`, `not`) collapses to `*` so an exotic
//! adversarial payload over-matches rather than zero-matches.

#![cfg(feature = "dynamic")]

/// LDAPv3 BER tag bytes the stub recognises.
pub mod tags {
    /// Universal primitive integer (RFC 4511 §5).
    pub const INTEGER: u8 = 0x02;
    /// Universal primitive octet string.
    pub const OCTET_STRING: u8 = 0x04;
    /// Universal primitive enumerated.
    pub const ENUMERATED: u8 = 0x0A;
    /// Universal constructed sequence.
    pub const SEQUENCE: u8 = 0x30;

    /// `BindRequest` `[APPLICATION 0]` constructed (RFC 4511 §4.2).
    pub const BIND_REQUEST: u8 = 0x60;
    /// `BindResponse` `[APPLICATION 1]` constructed.
    pub const BIND_RESPONSE: u8 = 0x61;
    /// `SearchRequest` `[APPLICATION 3]` constructed.
    pub const SEARCH_REQUEST: u8 = 0x63;
    /// `SearchResultEntry` `[APPLICATION 4]` constructed.
    pub const SEARCH_RESULT_ENTRY: u8 = 0x64;
    /// `SearchResultDone` `[APPLICATION 5]` constructed.
    pub const SEARCH_RESULT_DONE: u8 = 0x65;

    /// `simple` `[0]` primitive OCTET STRING inside
    /// `AuthenticationChoice`.
    pub const AUTH_SIMPLE: u8 = 0x80;

    /// Filter `and` `[0]` constructed SET.
    pub const FILTER_AND: u8 = 0xA0;
    /// Filter `or` `[1]` constructed SET.
    pub const FILTER_OR: u8 = 0xA1;
    /// Filter `not` `[2]` constructed wrapper.
    pub const FILTER_NOT: u8 = 0xA2;
    /// Filter `equalityMatch` `[3]` constructed
    /// `AttributeValueAssertion`.
    pub const FILTER_EQUALITY: u8 = 0xA3;
    /// Filter `substrings` `[4]` constructed.
    pub const FILTER_SUBSTRINGS: u8 = 0xA4;
    /// Filter `present` `[7]` primitive `AttributeDescription`.
    pub const FILTER_PRESENT: u8 = 0x87;

    /// Substring `initial` `[0]` primitive.
    pub const SUBSTR_INITIAL: u8 = 0x80;
    /// Substring `any` `[1]` primitive.
    pub const SUBSTR_ANY: u8 = 0x81;
    /// Substring `final` `[2]` primitive.
    pub const SUBSTR_FINAL: u8 = 0x82;
}

/// Decoded TLV view.  `body` is borrowed from the source buffer; the
/// caller never has to allocate during parsing.
#[derive(Debug, Clone, Copy)]
pub struct Tlv<'a> {
    /// Raw tag byte.  Match against [`tags`] constants.
    pub tag: u8,
    /// The value-octets slice (length-prefix already stripped).
    pub body: &'a [u8],
    /// Offset into the source buffer immediately after this TLV.
    pub end: usize,
}

/// Read a single TLV starting at `offset` in `buf`.  Returns `None`
/// when the buffer is too short, the length is indefinite (0x80), or
/// the long-form length-of-length exceeds 4 bytes (>4 GiB messages are
/// out of scope for the in-process stub).
pub fn read_tlv(buf: &[u8], offset: usize) -> Option<Tlv<'_>> {
    if offset >= buf.len() {
        return None;
    }
    let tag = buf[offset];
    let first_len = *buf.get(offset + 1)?;
    let (length, length_consumed) = if first_len & 0x80 == 0 {
        (first_len as usize, 1usize)
    } else {
        let length_of_length = (first_len & 0x7F) as usize;
        if length_of_length == 0 || length_of_length > 4 {
            // 0x80 is indefinite length; >4 bytes is too long for the
            // in-process stub.
            return None;
        }
        let len_start = offset + 2;
        let len_end = len_start + length_of_length;
        if len_end > buf.len() {
            return None;
        }
        let mut acc: usize = 0;
        for &b in &buf[len_start..len_end] {
            acc = (acc << 8) | (b as usize);
        }
        (acc, 1 + length_of_length)
    };
    let body_start = offset + 1 + length_consumed;
    let body_end = body_start.checked_add(length)?;
    if body_end > buf.len() {
        return None;
    }
    Some(Tlv {
        tag,
        body: &buf[body_start..body_end],
        end: body_end,
    })
}

/// Decode an `INTEGER` value-octets slice into an `i64`.  Rejects
/// inputs longer than 8 bytes — LDAP versions, message IDs, and result
/// codes all fit in 32 bits.
pub fn decode_integer(body: &[u8]) -> Option<i64> {
    if body.is_empty() || body.len() > 8 {
        return None;
    }
    let sign_extend: i64 = if body[0] & 0x80 != 0 { -1 } else { 0 };
    let mut acc: i64 = sign_extend;
    for &b in body {
        acc = (acc << 8) | (b as i64 & 0xFF);
    }
    Some(acc)
}

/// Append an `INTEGER` TLV to `out`.  Minimum-byte two's-complement
/// encoding.
pub fn write_integer(out: &mut Vec<u8>, n: i64) {
    let mut bytes = n.to_be_bytes().to_vec();
    while bytes.len() > 1
        && ((bytes[0] == 0x00 && bytes[1] & 0x80 == 0)
            || (bytes[0] == 0xFF && bytes[1] & 0x80 != 0))
    {
        bytes.remove(0);
    }
    write_tlv(out, tags::INTEGER, &bytes);
}

/// Append an `ENUMERATED` TLV to `out`.  Single-byte encoding (LDAP
/// scope / result-code values all fit in one byte).
pub fn write_enumerated(out: &mut Vec<u8>, n: u8) {
    write_tlv(out, tags::ENUMERATED, &[n]);
}

/// Append an `OCTET STRING` TLV to `out`.
pub fn write_octet_string(out: &mut Vec<u8>, s: &[u8]) {
    write_tlv(out, tags::OCTET_STRING, s);
}

/// Append a TLV with arbitrary tag + body to `out`.  Encodes length in
/// short-form when `body.len() < 128`; long-form otherwise.
pub fn write_tlv(out: &mut Vec<u8>, tag: u8, body: &[u8]) {
    out.push(tag);
    write_length(out, body.len());
    out.extend_from_slice(body);
}

fn write_length(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        out.push(len as u8);
        return;
    }
    let mut bytes: Vec<u8> = Vec::with_capacity(5);
    let mut n = len;
    while n != 0 {
        bytes.push((n & 0xFF) as u8);
        n >>= 8;
    }
    bytes.reverse();
    out.push(0x80 | bytes.len() as u8);
    out.extend_from_slice(&bytes);
}

/// Wrap `body` as a `SEQUENCE` TLV.  Convenience helper for assembling
/// LDAP messages.
pub fn wrap_sequence(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 4);
    write_tlv(&mut out, tags::SEQUENCE, body);
    out
}

/// Decoded LDAPMessage header — protocol operation TLV's tag plus
/// body, ready to dispatch on.
#[derive(Debug, Clone, Copy)]
pub struct LdapMessageHeader<'a> {
    /// The LDAP message ID the client picked.  Echoed verbatim on the
    /// matching response.
    pub message_id: i64,
    /// The protocol op application tag (e.g. [`tags::BIND_REQUEST`]).
    pub op_tag: u8,
    /// The protocol op value-octets.  Pass into [`decode_bind_request`]
    /// / [`decode_search_request`] depending on `op_tag`.
    pub op_body: &'a [u8],
}

/// Decode an LDAP message header.  The outer `SEQUENCE` must already
/// be the top-level TLV in `buf`.  Returns `None` for malformed input,
/// missing fields, or unrecognised protocol-op classes.
pub fn decode_ldap_message(buf: &[u8]) -> Option<LdapMessageHeader<'_>> {
    let outer = read_tlv(buf, 0)?;
    if outer.tag != tags::SEQUENCE {
        return None;
    }
    let msg_id_tlv = read_tlv(outer.body, 0)?;
    if msg_id_tlv.tag != tags::INTEGER {
        return None;
    }
    let message_id = decode_integer(msg_id_tlv.body)?;
    let op_tlv = read_tlv(outer.body, msg_id_tlv.end)?;
    Some(LdapMessageHeader {
        message_id,
        op_tag: op_tlv.tag,
        op_body: op_tlv.body,
    })
}

/// Decoded `BindRequest` (RFC 4511 §4.2).
#[derive(Debug, Clone)]
pub struct BindRequest<'a> {
    /// Protocol version (always 3 for LDAPv3).
    pub version: i64,
    /// The bind DN ("" for anonymous bind).
    pub name: &'a [u8],
    /// `simple` authentication credential bytes, if present.  Other
    /// `AuthenticationChoice` variants (SASL) collapse to `None`.
    pub simple_password: Option<&'a [u8]>,
}

/// Decode the value-octets of a `BindRequest`.
pub fn decode_bind_request(body: &[u8]) -> Option<BindRequest<'_>> {
    let version_tlv = read_tlv(body, 0)?;
    if version_tlv.tag != tags::INTEGER {
        return None;
    }
    let version = decode_integer(version_tlv.body)?;
    let name_tlv = read_tlv(body, version_tlv.end)?;
    if name_tlv.tag != tags::OCTET_STRING {
        return None;
    }
    let auth_tlv = read_tlv(body, name_tlv.end)?;
    let simple_password = if auth_tlv.tag == tags::AUTH_SIMPLE {
        Some(auth_tlv.body)
    } else {
        None
    };
    Some(BindRequest {
        version,
        name: name_tlv.body,
        simple_password,
    })
}

/// Decoded `SearchRequest` (RFC 4511 §4.5.1).
#[derive(Debug, Clone)]
pub struct SearchRequest<'a> {
    /// Base object DN the search is anchored at.
    pub base_object: &'a [u8],
    /// Scope enum value (0=baseObject, 1=singleLevel, 2=wholeSubtree).
    pub scope: u8,
    /// Filter rendered into the RFC 4515 string subset the existing
    /// [`super::ldap_server::LdapStub::evaluate`] matcher consumes.
    pub filter: String,
}

/// Decode the value-octets of a `SearchRequest`.
pub fn decode_search_request(body: &[u8]) -> Option<SearchRequest<'_>> {
    let base_tlv = read_tlv(body, 0)?;
    if base_tlv.tag != tags::OCTET_STRING {
        return None;
    }
    let scope_tlv = read_tlv(body, base_tlv.end)?;
    if scope_tlv.tag != tags::ENUMERATED || scope_tlv.body.len() != 1 {
        return None;
    }
    let scope = scope_tlv.body[0];
    let deref_tlv = read_tlv(body, scope_tlv.end)?;
    let size_tlv = read_tlv(body, deref_tlv.end)?;
    let time_tlv = read_tlv(body, size_tlv.end)?;
    let typesonly_tlv = read_tlv(body, time_tlv.end)?;
    let filter_tlv = read_tlv(body, typesonly_tlv.end)?;
    let filter = render_filter(filter_tlv.tag, filter_tlv.body);
    Some(SearchRequest {
        base_object: base_tlv.body,
        scope,
        filter,
    })
}

/// Render a decoded filter TLV into the RFC 4515 subset
/// [`super::ldap_server::LdapStub::evaluate`] accepts.  Unrecognised
/// shapes collapse to bare `*` so adversarial payloads over-match.
pub fn render_filter(tag: u8, body: &[u8]) -> String {
    match tag {
        tags::FILTER_AND => render_set("&", body),
        tags::FILTER_OR => render_set("|", body),
        tags::FILTER_EQUALITY => render_equality(body),
        tags::FILTER_PRESENT => {
            let attr = String::from_utf8_lossy(body);
            format!("({attr}=*)")
        }
        tags::FILTER_SUBSTRINGS => render_substrings(body),
        _ => "*".to_string(),
    }
}

fn render_set(operator: &str, body: &[u8]) -> String {
    let mut out = String::from("(");
    out.push_str(operator);
    let mut cur = 0usize;
    while cur < body.len() {
        let Some(child) = read_tlv(body, cur) else {
            // Truncated SET — break out and let the outer caller fall
            // through to over-match.
            out.push('*');
            break;
        };
        out.push_str(&render_filter(child.tag, child.body));
        cur = child.end;
    }
    out.push(')');
    out
}

fn render_equality(body: &[u8]) -> String {
    let Some(attr_tlv) = read_tlv(body, 0) else {
        return "*".to_string();
    };
    if attr_tlv.tag != tags::OCTET_STRING {
        return "*".to_string();
    }
    let Some(value_tlv) = read_tlv(body, attr_tlv.end) else {
        return "*".to_string();
    };
    if value_tlv.tag != tags::OCTET_STRING {
        return "*".to_string();
    }
    let attr = String::from_utf8_lossy(attr_tlv.body);
    let value = String::from_utf8_lossy(value_tlv.body);
    format!("({attr}={value})")
}

fn render_substrings(body: &[u8]) -> String {
    let Some(attr_tlv) = read_tlv(body, 0) else {
        return "*".to_string();
    };
    if attr_tlv.tag != tags::OCTET_STRING {
        return "*".to_string();
    }
    let Some(seq_tlv) = read_tlv(body, attr_tlv.end) else {
        return "*".to_string();
    };
    if seq_tlv.tag != tags::SEQUENCE {
        return "*".to_string();
    }
    let attr = String::from_utf8_lossy(attr_tlv.body);
    let mut initial = String::new();
    let mut any_parts: Vec<String> = Vec::new();
    let mut tail = String::new();
    let mut cur = 0usize;
    while cur < seq_tlv.body.len() {
        let Some(piece) = read_tlv(seq_tlv.body, cur) else {
            break;
        };
        let text = String::from_utf8_lossy(piece.body).into_owned();
        match piece.tag {
            tags::SUBSTR_INITIAL => initial = text,
            tags::SUBSTR_ANY => any_parts.push(text),
            tags::SUBSTR_FINAL => tail = text,
            _ => {}
        }
        cur = piece.end;
    }
    let mut joined = initial;
    if !any_parts.is_empty() {
        joined.push('*');
        joined.push_str(&any_parts.join("*"));
    }
    joined.push('*');
    joined.push_str(&tail);
    format!("({attr}={joined})")
}

/// Encode a complete `LDAPMessage` carrying `op_tag` + `op_body` as
/// the protocol op.  Wraps everything in the outer `SEQUENCE`.
pub fn encode_ldap_message(message_id: i64, op_tag: u8, op_body: &[u8]) -> Vec<u8> {
    let mut inner = Vec::with_capacity(op_body.len() + 8);
    write_integer(&mut inner, message_id);
    write_tlv(&mut inner, op_tag, op_body);
    wrap_sequence(&inner)
}

/// LDAP result codes the stub uses (RFC 4511 §4.1.9).
pub mod result_codes {
    /// Operation completed successfully.
    pub const SUCCESS: u8 = 0;
    /// Operation rejected — used here for unrecognised request shapes.
    pub const UNWILLING_TO_PERFORM: u8 = 53;
}

/// Encode a minimal `BindResponse` (success, empty matchedDN, empty
/// diagnosticMessage).
pub fn encode_bind_response(message_id: i64, result_code: u8) -> Vec<u8> {
    let mut body = Vec::with_capacity(8);
    write_enumerated(&mut body, result_code);
    write_octet_string(&mut body, b"");
    write_octet_string(&mut body, b"");
    encode_ldap_message(message_id, tags::BIND_RESPONSE, &body)
}

/// Encode a `SearchResultEntry` carrying `dn` with no attributes.  The
/// Phase 06 LDAP stub's directory model only ever publishes the DN —
/// callers that need attributes can extend this once a fixture surfaces
/// the need.
pub fn encode_search_result_entry(message_id: i64, dn: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(dn.len() + 8);
    write_octet_string(&mut body, dn);
    // PartialAttributeList ::= SEQUENCE OF partial Attribute — empty.
    write_tlv(&mut body, tags::SEQUENCE, &[]);
    encode_ldap_message(message_id, tags::SEARCH_RESULT_ENTRY, &body)
}

/// Encode a `SearchResultDone` (RFC 4511 §4.5.2).
pub fn encode_search_result_done(message_id: i64, result_code: u8) -> Vec<u8> {
    let mut body = Vec::with_capacity(8);
    write_enumerated(&mut body, result_code);
    write_octet_string(&mut body, b"");
    write_octet_string(&mut body, b"");
    encode_ldap_message(message_id, tags::SEARCH_RESULT_DONE, &body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_tlv_short_form_length() {
        // tag=0x04, len=0x03, body="abc"
        let buf = b"\x04\x03abc";
        let tlv = read_tlv(buf, 0).expect("tlv");
        assert_eq!(tlv.tag, 0x04);
        assert_eq!(tlv.body, b"abc");
        assert_eq!(tlv.end, 5);
    }

    #[test]
    fn read_tlv_long_form_length() {
        // 200-byte body → length 0x81 0xC8
        let mut buf = vec![0x04, 0x81, 200];
        buf.extend(std::iter::repeat_n(b'a', 200));
        let tlv = read_tlv(&buf, 0).expect("tlv");
        assert_eq!(tlv.body.len(), 200);
    }

    #[test]
    fn read_tlv_rejects_indefinite_length() {
        let buf = [0x30u8, 0x80, 0x00, 0x00];
        assert!(read_tlv(&buf, 0).is_none());
    }

    #[test]
    fn read_tlv_rejects_truncated_body() {
        let buf = [0x04u8, 0x05, b'a', b'b'];
        assert!(read_tlv(&buf, 0).is_none());
    }

    #[test]
    fn decode_integer_handles_single_byte() {
        assert_eq!(decode_integer(&[3]), Some(3));
        assert_eq!(decode_integer(&[0]), Some(0));
    }

    #[test]
    fn decode_integer_handles_negative_via_sign_extension() {
        // 0xFF is -1 in two's complement
        assert_eq!(decode_integer(&[0xFF]), Some(-1));
    }

    #[test]
    fn decode_integer_rejects_empty_and_oversized() {
        assert!(decode_integer(&[]).is_none());
        assert!(decode_integer(&[0u8; 9]).is_none());
    }

    #[test]
    fn write_integer_minimum_byte_form() {
        let mut out = Vec::new();
        write_integer(&mut out, 0);
        assert_eq!(out, vec![0x02, 0x01, 0x00]);

        let mut out = Vec::new();
        write_integer(&mut out, 127);
        assert_eq!(out, vec![0x02, 0x01, 0x7F]);

        let mut out = Vec::new();
        write_integer(&mut out, 128);
        // Need leading zero byte because high bit of 0x80 would make
        // the value negative under two's-complement.
        assert_eq!(out, vec![0x02, 0x02, 0x00, 0x80]);
    }

    #[test]
    fn integer_round_trips() {
        for n in [0i64, 1, 3, 127, 128, 255, 256, 65535, 65536, -1, -128, -129] {
            let mut buf = Vec::new();
            write_integer(&mut buf, n);
            let tlv = read_tlv(&buf, 0).expect("tlv");
            assert_eq!(tlv.tag, tags::INTEGER);
            assert_eq!(decode_integer(tlv.body), Some(n));
        }
    }

    #[test]
    fn long_form_length_round_trip() {
        let mut buf = Vec::new();
        let body = vec![0xABu8; 1024];
        write_tlv(&mut buf, tags::OCTET_STRING, &body);
        let tlv = read_tlv(&buf, 0).expect("tlv");
        assert_eq!(tlv.body, &body[..]);
    }

    #[test]
    fn bind_request_round_trip() {
        // version=3, name="cn=admin", simple_password="secret"
        let mut body = Vec::new();
        write_integer(&mut body, 3);
        write_octet_string(&mut body, b"cn=admin");
        write_tlv(&mut body, tags::AUTH_SIMPLE, b"secret");
        let msg = encode_ldap_message(/*id=*/ 7, tags::BIND_REQUEST, &body);
        let hdr = decode_ldap_message(&msg).expect("header");
        assert_eq!(hdr.message_id, 7);
        assert_eq!(hdr.op_tag, tags::BIND_REQUEST);
        let req = decode_bind_request(hdr.op_body).expect("bind body");
        assert_eq!(req.version, 3);
        assert_eq!(req.name, b"cn=admin");
        assert_eq!(req.simple_password, Some(b"secret".as_slice()));
    }

    #[test]
    fn bind_response_round_trip_decodes_via_header() {
        let msg = encode_bind_response(/*id=*/ 7, result_codes::SUCCESS);
        let hdr = decode_ldap_message(&msg).expect("header");
        assert_eq!(hdr.message_id, 7);
        assert_eq!(hdr.op_tag, tags::BIND_RESPONSE);
        // BindResponse body: ENUMERATED + 2x OCTET STRING
        let tlv = read_tlv(hdr.op_body, 0).expect("rc");
        assert_eq!(tlv.tag, tags::ENUMERATED);
        assert_eq!(tlv.body, &[0]);
    }

    fn build_search_msg(message_id: i64, filter_tag: u8, filter_body: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        write_octet_string(&mut body, b"ou=people,dc=nyx,dc=test");
        write_enumerated(&mut body, 2); // wholeSubtree
        write_enumerated(&mut body, 0); // derefAliases neverDerefAliases
        write_integer(&mut body, 0); // sizeLimit
        write_integer(&mut body, 0); // timeLimit
        // typesOnly BOOLEAN false; encoded as 0x01 0x01 0x00
        write_tlv(&mut body, 0x01, &[0x00]);
        write_tlv(&mut body, filter_tag, filter_body);
        // attributes: empty SEQUENCE
        write_tlv(&mut body, tags::SEQUENCE, &[]);
        encode_ldap_message(message_id, tags::SEARCH_REQUEST, &body)
    }

    fn equality_body(attr: &[u8], value: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        write_octet_string(&mut body, attr);
        write_octet_string(&mut body, value);
        body
    }

    #[test]
    fn search_request_equality_filter_renders_to_rfc4515() {
        let eq = equality_body(b"uid", b"alice");
        let msg = build_search_msg(11, tags::FILTER_EQUALITY, &eq);
        let hdr = decode_ldap_message(&msg).expect("header");
        let req = decode_search_request(hdr.op_body).expect("search");
        assert_eq!(req.base_object, b"ou=people,dc=nyx,dc=test");
        assert_eq!(req.scope, 2);
        assert_eq!(req.filter, "(uid=alice)");
    }

    #[test]
    fn search_request_present_filter_renders_with_wildcard() {
        let msg = build_search_msg(11, tags::FILTER_PRESENT, b"uid");
        let hdr = decode_ldap_message(&msg).expect("header");
        let req = decode_search_request(hdr.op_body).expect("search");
        assert_eq!(req.filter, "(uid=*)");
    }

    #[test]
    fn search_request_or_filter_nests_equalities() {
        let mut set_body = Vec::new();
        let eq_a = equality_body(b"uid", b"alice");
        let eq_b = equality_body(b"uid", b"bob");
        write_tlv(&mut set_body, tags::FILTER_EQUALITY, &eq_a);
        write_tlv(&mut set_body, tags::FILTER_EQUALITY, &eq_b);
        let msg = build_search_msg(11, tags::FILTER_OR, &set_body);
        let hdr = decode_ldap_message(&msg).expect("header");
        let req = decode_search_request(hdr.op_body).expect("search");
        assert_eq!(req.filter, "(|(uid=alice)(uid=bob))");
    }

    #[test]
    fn search_request_and_filter_nests_equalities() {
        let mut set_body = Vec::new();
        let eq_a = equality_body(b"uid", b"alice");
        let eq_b = equality_body(b"cn", b"admin");
        write_tlv(&mut set_body, tags::FILTER_EQUALITY, &eq_a);
        write_tlv(&mut set_body, tags::FILTER_EQUALITY, &eq_b);
        let msg = build_search_msg(11, tags::FILTER_AND, &set_body);
        let hdr = decode_ldap_message(&msg).expect("header");
        let req = decode_search_request(hdr.op_body).expect("search");
        assert_eq!(req.filter, "(&(uid=alice)(cn=admin))");
    }

    #[test]
    fn search_request_substrings_filter_renders_prefix_star_suffix() {
        let mut sub_body = Vec::new();
        write_octet_string(&mut sub_body, b"uid");
        let mut inner = Vec::new();
        write_tlv(&mut inner, tags::SUBSTR_INITIAL, b"al");
        write_tlv(&mut inner, tags::SUBSTR_FINAL, b"ce");
        write_tlv(&mut sub_body, tags::SEQUENCE, &inner);
        let msg = build_search_msg(11, tags::FILTER_SUBSTRINGS, &sub_body);
        let hdr = decode_ldap_message(&msg).expect("header");
        let req = decode_search_request(hdr.op_body).expect("search");
        assert_eq!(req.filter, "(uid=al*ce)");
    }

    #[test]
    fn search_request_unknown_filter_collapses_to_wildcard() {
        // 0xA5 = greaterOrEqual — not rendered, falls through to "*".
        let body = equality_body(b"uid", b"alice");
        let msg = build_search_msg(11, 0xA5, &body);
        let hdr = decode_ldap_message(&msg).expect("header");
        let req = decode_search_request(hdr.op_body).expect("search");
        assert_eq!(req.filter, "*");
    }

    #[test]
    fn encode_search_result_entry_round_trip() {
        let msg = encode_search_result_entry(/*id=*/ 11, b"uid=alice,ou=people");
        let hdr = decode_ldap_message(&msg).expect("header");
        assert_eq!(hdr.message_id, 11);
        assert_eq!(hdr.op_tag, tags::SEARCH_RESULT_ENTRY);
        let dn_tlv = read_tlv(hdr.op_body, 0).expect("dn");
        assert_eq!(dn_tlv.tag, tags::OCTET_STRING);
        assert_eq!(dn_tlv.body, b"uid=alice,ou=people");
    }

    #[test]
    fn encode_search_result_done_round_trip() {
        let msg = encode_search_result_done(/*id=*/ 11, result_codes::SUCCESS);
        let hdr = decode_ldap_message(&msg).expect("header");
        assert_eq!(hdr.op_tag, tags::SEARCH_RESULT_DONE);
        let rc = read_tlv(hdr.op_body, 0).expect("rc");
        assert_eq!(rc.tag, tags::ENUMERATED);
        assert_eq!(rc.body, &[0]);
    }
}
