//! Link request/response primitive — RPC-style communication over established links.
//!
//! Implements `link.request(path, data)` and `link.response()` from Python RNS.
//!
//! # Request wire format (msgpack)
//! ```text
//! fixarray(3) = 0x93
//! float64     = 0xcb + 8 bytes BE (timestamp)
//! bin8/bin16  = path_hash (16 bytes, SHA-256(path.encode("utf-8"))[0:16])
//! any msgpack value = data (`nil` for no request data)
//! ```
//!
//! # Response wire format (msgpack)
//! ```text
//! fixarray(2) = 0x92
//! bin8        = request_id (16 bytes, truncated packet hash for single-packet requests)
//! bin8/bin16/bin32 = response data
//! ```

extern crate alloc;

use alloc::vec::Vec;
use rete_core::msgpack::{self, MsgpackError};
use rete_core::{PathHash, RequestId, TRUNCATED_HASH_LEN};
use sha2::{Digest, Sha256};

/// Length of a path hash (truncated SHA-256, same as `Identity.truncated_hash` in Python RNS).
pub const PATH_HASH_LEN: usize = TRUNCATED_HASH_LEN;

/// Length of a request ID (truncated hash of the packet's hashable part for single-packet requests,
/// or truncated hash of the packed request data for resource-based requests).
pub const REQUEST_ID_LEN: usize = TRUNCATED_HASH_LEN;

/// Errors from request/response parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestError {
    /// Data too short or truncated.
    TooShort,
    /// Msgpack decoding failed.
    Msgpack(MsgpackError),
    /// Wrong array length (expected 3 for request, 2 for response).
    InvalidArrayLen,
    /// Path hash has wrong length (expected 16 bytes).
    BadPathHashLen,
    /// Request ID has wrong length (expected 16 bytes).
    BadRequestIdLen,
    /// Bytes remained after the one expected MessagePack value.
    TrailingData,
}

impl From<MsgpackError> for RequestError {
    fn from(e: MsgpackError) -> Self {
        RequestError::Msgpack(e)
    }
}

/// Compute path hash: `SHA-256(path.as_bytes())[..16]`.
pub fn path_hash(path: &str) -> PathHash {
    let digest = Sha256::digest(path.as_bytes());
    let mut out = [0u8; PATH_HASH_LEN];
    out.copy_from_slice(&digest[..PATH_HASH_LEN]);
    PathHash::from(out)
}

/// Compute request_id from packed request bytes: `SHA-256(packed)[..16]`.
///
/// Note: This is only correct for resource-based (multi-packet) requests.
/// For single-packet requests, Python RNS uses the packet's truncated hash instead.
pub fn request_id(packed_request: &[u8]) -> RequestId {
    let digest = Sha256::digest(packed_request);
    let mut out = [0u8; REQUEST_ID_LEN];
    out.copy_from_slice(&digest[..REQUEST_ID_LEN]);
    RequestId::from(out)
}

fn build_request_prefix(path: &str, now_secs_f64: f64, value_len: usize) -> Vec<u8> {
    let ph = path_hash(path);
    let mut buf = Vec::with_capacity(1 + 9 + (2 + PATH_HASH_LEN) + value_len);
    buf.push(0x93);
    msgpack::write_float64(&mut buf, now_secs_f64);
    msgpack::write_bin(&mut buf, ph.as_ref());
    buf
}

fn validate_packed_value(value: &[u8]) -> Result<(), RequestError> {
    let mut pos = 0;
    msgpack::skip_value(value, &mut pos)?;
    if pos != value.len() {
        return Err(RequestError::TrailingData);
    }
    Ok(())
}

/// Build a Python-compatible packed request whose data is one already-encoded
/// MessagePack value.
///
/// `None` writes MessagePack `nil`, matching `Link.request(path, data=None)`.
/// `Some` is accepted only when the supplied bytes contain exactly one complete
/// MessagePack value. The value is embedded without decoding or re-encoding,
/// so map, array, scalar, binary and extension values retain their exact wire
/// representation.
pub fn build_request_value(
    path: &str,
    data: Option<&[u8]>,
    now_secs_f64: f64,
) -> Result<Vec<u8>, RequestError> {
    if let Some(value) = data {
        validate_packed_value(value)?;
    }
    let value_len = data.map_or(1, <[u8]>::len);
    let mut buf = build_request_prefix(path, now_secs_f64, value_len);
    match data {
        Some(value) => buf.extend_from_slice(value),
        None => msgpack::write_nil(&mut buf),
    }
    Ok(buf)
}

/// Build a packed request with a binary data value.
///
/// This preserves the original byte-oriented convenience API. Call
/// [`build_request_value`] for `nil`, maps, arrays or other pre-encoded
/// MessagePack request values.
pub fn build_request(path: &str, data: &[u8], now_secs_f64: f64) -> Vec<u8> {
    let mut buf = build_request_prefix(path, now_secs_f64, 3 + data.len());
    msgpack::write_bin(&mut buf, data);
    buf
}

/// Parse a request while preserving its one encoded MessagePack data value.
///
/// The returned slice borrows the exact value bytes from `packed`, including
/// the `0xc0` marker for `nil`.
pub fn parse_request_value(packed: &[u8]) -> Result<(f64, PathHash, &[u8]), RequestError> {
    let mut pos = 0;
    let arr_len = msgpack::read_array_len(packed, &mut pos)?;
    if arr_len != 3 {
        return Err(RequestError::InvalidArrayLen);
    }
    let timestamp = msgpack::read_float64(packed, &mut pos)?;
    let ph_bytes = msgpack::read_bin_or_str(packed, &mut pos)?;
    if ph_bytes.len() != PATH_HASH_LEN {
        return Err(RequestError::BadPathHashLen);
    }
    let mut ph = [0u8; PATH_HASH_LEN];
    ph.copy_from_slice(ph_bytes);

    let value_start = pos;
    msgpack::skip_value(packed, &mut pos)?;
    if pos != packed.len() {
        return Err(RequestError::TrailingData);
    }
    Ok((timestamp, PathHash::from(ph), &packed[value_start..pos]))
}

/// Validated inbound request data without changing the legacy byte-oriented
/// interpretation of MessagePack binary and string values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestData<'a> {
    /// Decoded contents of one MessagePack binary or string value.
    Bytes(&'a [u8]),
    /// Exact encoded bytes of any other complete MessagePack value.
    ///
    /// Canonical anonymous requests are represented by `EncodedValue(&[0xc0])`.
    /// This is deliberately distinct from `Bytes(&[])`, which represents an
    /// empty MessagePack binary or string value.
    EncodedValue(&'a [u8]),
}

/// Parse one request and classify its validated data value without losing its
/// encoded MessagePack representation.
///
/// Binary and string values retain the historical decoded-byte behavior.
/// Every other MessagePack family is returned unchanged as
/// [`RequestData::EncodedValue`].
pub fn parse_request_data(packed: &[u8]) -> Result<(f64, PathHash, RequestData<'_>), RequestError> {
    let (timestamp, path_hash, value) = parse_request_value(packed)?;
    let marker = value[0];
    let is_bytes =
        marker & 0xe0 == 0xa0 || matches!(marker, 0xc4 | 0xc5 | 0xc6 | 0xd9 | 0xda | 0xdb);
    let data = if is_bytes {
        let mut pos = 0;
        let bytes = msgpack::read_bin_or_str(value, &mut pos)?;
        debug_assert_eq!(pos, value.len());
        RequestData::Bytes(bytes)
    } else {
        RequestData::EncodedValue(value)
    };
    Ok((timestamp, path_hash, data))
}

/// Parse a packed request, returning `(timestamp_f64, path_hash, data)`.
///
/// This is the byte-oriented convenience counterpart to
/// [`parse_request_value`] and accepts only binary or string request data.
pub fn parse_request(packed: &[u8]) -> Result<(f64, PathHash, Vec<u8>), RequestError> {
    let (timestamp, path_hash, value) = parse_request_value(packed)?;
    let mut pos = 0;
    let data = msgpack::read_bin_or_str(value, &mut pos)?.to_vec();
    debug_assert_eq!(pos, value.len());
    Ok((timestamp, path_hash, data))
}

/// Build a packed response: `msgpack([request_id_bytes, response_data_bytes])`.
pub fn build_response(req_id: &RequestId, data: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1 + 12 + 3 + data.len());

    // fixarray(2)
    buf.push(0x92);

    // request_id as bin8 (always 16 bytes)
    msgpack::write_bin(&mut buf, req_id.as_ref());

    // response data as bin
    msgpack::write_bin(&mut buf, data);

    buf
}

/// Parse a packed response, returning `(request_id, data)`.
pub fn parse_response(packed: &[u8]) -> Result<(RequestId, Vec<u8>), RequestError> {
    let mut pos = 0;

    // Read fixarray(2) header
    let arr_len = msgpack::read_array_len(packed, &mut pos)?;
    if arr_len != 2 {
        return Err(RequestError::InvalidArrayLen);
    }

    // Read request_id (bin, expect 16 bytes)
    let rid_bytes = msgpack::read_bin_or_str(packed, &mut pos)?;
    if rid_bytes.len() != REQUEST_ID_LEN {
        return Err(RequestError::BadRequestIdLen);
    }
    let mut rid = [0u8; REQUEST_ID_LEN];
    rid.copy_from_slice(rid_bytes);

    // Read data (bin)
    let data = msgpack::read_bin_or_str(packed, &mut pos)?.to_vec();
    if pos != packed.len() {
        return Err(RequestError::TrailingData);
    }

    Ok((RequestId::from(rid), data))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    extern crate alloc;
    use alloc::vec;

    use super::*;

    #[test]
    fn test_path_hash_computation() {
        let ph = path_hash("lxmf.delivery");
        // SHA-256("lxmf.delivery") truncated to 10 bytes — verify deterministic
        let ph2 = path_hash("lxmf.delivery");
        assert_eq!(ph, ph2);
        assert_eq!(ph.as_ref().len(), PATH_HASH_LEN);

        // Verify it's actually SHA-256 truncated
        let digest = Sha256::digest("lxmf.delivery".as_bytes());
        assert_eq!(ph.as_ref(), &digest[..PATH_HASH_LEN]);
    }

    #[test]
    fn test_build_parse_request_roundtrip() {
        let path = "test.echo";
        let data = b"hello, world!";
        let ts = 1700000000.5_f64;

        let packed = build_request(path, data, ts);
        let (parsed_ts, parsed_ph, parsed_data) = parse_request(&packed).unwrap();

        assert!((parsed_ts - ts).abs() < 1e-10);
        assert_eq!(parsed_ph, path_hash(path));
        assert_eq!(parsed_data, data);
    }

    #[test]
    fn anonymous_request_matches_python_messagepack_wire() {
        let packed = build_request_value("/page/index.mu", None, 1_700_000_000.0).unwrap();
        let expected = [
            0x93, 0xcb, 0x41, 0xd9, 0x54, 0xfc, 0x40, 0x00, 0x00, 0x00, 0xc4, 0x10, 0xfb, 0x40,
            0xab, 0xf3, 0x59, 0xb3, 0xf2, 0x5f, 0xa0, 0x08, 0x61, 0x07, 0xc5, 0xee, 0xe5, 0x16,
            0xc0,
        ];
        assert_eq!(packed, expected);

        let (timestamp, parsed_path, value) = parse_request_value(&packed).unwrap();
        assert_eq!(timestamp, 1_700_000_000.0);
        assert_eq!(parsed_path, path_hash("/page/index.mu"));
        assert_eq!(value, [0xc0]);
    }

    #[test]
    fn request_data_distinguishes_nil_and_raw_values_from_legacy_bytes() {
        let nil = build_request_value("/page/index.mu", None, 42.0).unwrap();
        assert_eq!(
            parse_request_data(&nil).unwrap().2,
            RequestData::EncodedValue(&[0xc0])
        );

        let empty_binary = build_request("/page/index.mu", &[], 42.0);
        assert_eq!(
            parse_request_data(&empty_binary).unwrap().2,
            RequestData::Bytes(&[])
        );

        let string = build_request_value("/page/string", Some(&[0xa2, b'o', b'k']), 42.0).unwrap();
        assert_eq!(
            parse_request_data(&string).unwrap().2,
            RequestData::Bytes(b"ok")
        );

        let map = [0x81, 0xa1, b'k', 0x01];
        let mapped = build_request_value("/page/form.mu", Some(&map), 42.0).unwrap();
        assert_eq!(
            parse_request_data(&mapped).unwrap().2,
            RequestData::EncodedValue(&map)
        );
    }

    #[test]
    fn request_data_rejects_malformed_or_trailing_values() {
        let mut missing_value = build_request_value("/page/index.mu", None, 42.0).unwrap();
        missing_value.pop();
        assert_eq!(
            parse_request_data(&missing_value),
            Err(RequestError::Msgpack(MsgpackError::Truncated))
        );

        let mut trailing = build_request_value("/page/index.mu", None, 42.0).unwrap();
        trailing.push(0xc0);
        assert_eq!(
            parse_request_data(&trailing),
            Err(RequestError::TrailingData)
        );
    }

    #[test]
    fn packed_request_value_is_preserved_and_must_be_exactly_one_value() {
        let value = [
            0x81, 0xa8, b'v', b'a', b'r', b'_', b'n', b'a', b'm', b'e', 0xa4, b'R', b'u', b's',
            b't',
        ];
        let packed = build_request_value("/page/form.mu", Some(&value), 42.0).unwrap();
        let (_, parsed_path, parsed_value) = parse_request_value(&packed).unwrap();
        assert_eq!(parsed_path, path_hash("/page/form.mu"));
        assert_eq!(parsed_value, value);

        assert_eq!(
            build_request_value("/page/form.mu", Some(&[]), 42.0),
            Err(RequestError::Msgpack(MsgpackError::Truncated))
        );
        assert_eq!(
            build_request_value("/page/form.mu", Some(&[0xc0, 0xc0]), 42.0),
            Err(RequestError::TrailingData)
        );
    }

    #[test]
    fn test_request_id_deterministic() {
        let packed = build_request("test.echo", b"data1", 1700000000.0);
        let id1 = request_id(&packed);
        let id2 = request_id(&packed);
        assert_eq!(id1, id2);
        assert_eq!(id1.as_ref().len(), REQUEST_ID_LEN);

        // Different input produces different id
        let packed2 = build_request("test.echo", b"data2", 1700000000.0);
        let id3 = request_id(&packed2);
        assert_ne!(id1, id3);
    }

    #[test]
    fn test_build_parse_response_roundtrip() {
        let req_id = RequestId::from([
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10,
        ]);
        let resp_data = b"response payload";

        let packed = build_response(&req_id, resp_data);
        let (parsed_rid, parsed_data) = parse_response(&packed).unwrap();

        assert_eq!(parsed_rid, req_id);
        assert_eq!(parsed_data, resp_data);
    }

    #[test]
    fn test_parse_request_empty_data() {
        let packed = build_request("test.path", &[], 1700000001.0);
        let (ts, ph, data) = parse_request(&packed).unwrap();

        assert!((ts - 1700000001.0).abs() < 1e-10);
        assert_eq!(ph, path_hash("test.path"));
        assert!(data.is_empty());
    }

    #[test]
    fn test_parse_request_garbage_fails() {
        // Complete garbage
        assert!(parse_request(&[0xFF, 0x00, 0x01]).is_err());
        // Empty input
        assert!(parse_request(&[]).is_err());
        // Wrong array length
        assert!(parse_request(&[0x92]).is_err()); // fixarray(2) instead of 3
    }

    #[test]
    fn test_parse_response_garbage_fails() {
        // Complete garbage
        assert!(parse_response(&[0xFF, 0x00, 0x01]).is_err());
        // Empty input
        assert!(parse_response(&[]).is_err());
        // Wrong array length
        assert!(parse_response(&[0x93]).is_err()); // fixarray(3) instead of 2
    }

    #[test]
    fn test_parse_response_rejects_trailing_data() {
        let request_id = RequestId::from([0x42; REQUEST_ID_LEN]);
        let mut packed = build_response(&request_id, b"page");
        packed.push(0xc0);
        assert_eq!(parse_response(&packed), Err(RequestError::TrailingData));
    }

    #[test]
    fn test_request_with_large_data() {
        let data = vec![0xAA; 400];
        let packed = build_request("test.large", &data, 1700000002.0);
        let (ts, ph, parsed_data) = parse_request(&packed).unwrap();

        assert!((ts - 1700000002.0).abs() < 1e-10);
        assert_eq!(ph, path_hash("test.large"));
        assert_eq!(parsed_data, data);
    }

    #[test]
    fn test_response_with_empty_data() {
        let req_id = RequestId::from([0xAA; REQUEST_ID_LEN]);
        let packed = build_response(&req_id, &[]);
        let (parsed_rid, parsed_data) = parse_response(&packed).unwrap();

        assert_eq!(parsed_rid, req_id);
        assert!(parsed_data.is_empty());
    }

    #[test]
    fn path_hash_different_paths() {
        let ph1 = path_hash("lxmf.delivery");
        let ph2 = path_hash("lxmf.propagation");
        assert_ne!(ph1, ph2);
    }
}
