//! QUIC variable-length integers (RFC 9000 Section 16).
//!
//! Encodes and decodes varints through the public nghttp3 APIs
//! (`nghttp3_put_uvarint` / `nghttp3_get_uvarint`).

use nghttp3_sys;

/// Error returned when a varint output buffer is too short.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncodeError {
    /// Required encoded length in bytes.
    pub required: usize,
    /// Provided buffer length in bytes.
    pub actual: usize,
}

/// Returns the number of bytes needed to encode the value.
pub fn encoded_len(n: u64) -> usize {
    unsafe { nghttp3_sys::nghttp3_put_uvarintlen(n) }
}

/// Encodes a variable-length integer into `buf`.
///
/// `buf` must be at least `encoded_len(n)` bytes long. Returns the number of
/// bytes written.
pub fn encode(buf: &mut [u8], n: u64) -> Result<usize, EncodeError> {
    let len = encoded_len(n);
    if buf.len() < len {
        return Err(EncodeError {
            required: len,
            actual: buf.len(),
        });
    }

    unsafe {
        nghttp3_sys::nghttp3_put_uvarint(buf.as_mut_ptr(), n);
    }
    Ok(len)
}

/// Appends a variable-length integer to a `Vec<u8>`.
pub fn encode_to_vec(n: u64, buf: &mut Vec<u8>) {
    let len = encoded_len(n);
    let start = buf.len();
    buf.resize(start + len, 0);
    let _ = encode(&mut buf[start..], n);
}

/// Decodes a variable-length integer.
///
/// On success, returns `(value, consumed_bytes)`. Returns `None` when `buf` is
/// empty or truncated.
pub fn decode(buf: &[u8]) -> Option<(u64, usize)> {
    if buf.is_empty() {
        return None;
    }
    let len = unsafe { nghttp3_sys::nghttp3_get_uvarintlen(buf.as_ptr()) };
    if buf.len() < len {
        return None;
    }
    let mut dest = 0u64;
    unsafe {
        nghttp3_sys::nghttp3_get_uvarint(&mut dest, buf.as_ptr());
    }
    Some((dest, len))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_varint_roundtrip() {
        for value in [0u64, 1, 63, 64, 16383, 16384, 1073741823, 1073741824] {
            let mut buf = Vec::new();
            encode_to_vec(value, &mut buf);
            let (decoded, consumed) = decode(&buf).unwrap();
            assert_eq!(decoded, value);
            assert_eq!(consumed, buf.len());
        }
    }

    #[test]
    fn test_varint_encoded_len() {
        assert_eq!(encoded_len(0), 1);
        assert_eq!(encoded_len(63), 1);
        assert_eq!(encoded_len(64), 2);
        assert_eq!(encoded_len(16383), 2);
        assert_eq!(encoded_len(16384), 4);
        assert_eq!(encoded_len(1073741823), 4);
        assert_eq!(encoded_len(1073741824), 8);
    }

    #[test]
    fn test_varint_decode_empty() {
        assert!(decode(&[]).is_none());
    }

    #[test]
    fn test_varint_decode_truncated() {
        // This encoding needs 2 bytes, but only 1 byte is present.
        assert!(decode(&[0x40]).is_none());
    }

    #[test]
    fn test_varint_encode_short_buffer() {
        let err = encode(&mut [0], 64).unwrap_err();
        assert_eq!(err.required, 2);
        assert_eq!(err.actual, 1);
    }
}
