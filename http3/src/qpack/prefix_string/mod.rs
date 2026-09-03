mod bitwin;
mod decode;
mod encode;

use std::{convert::TryInto, fmt, num::TryFromIntError};

use bytes::{Buf, BufMut};

pub use self::{
    bitwin::BitWindow,
    decode::{Error as HuffmanDecodingError, HpackStringDecode},
    encode::{Error as HuffmanEncodingError, HpackStringEncode},
};
use crate::{
    proto::coding::BufMutExt,
    qpack::prefix_int::{self, Error as IntegerError},
};

#[derive(Debug, PartialEq)]
pub enum Error {
    UnexpectedEnd,
    EncodedStringTooLong { len: u64, limit: usize },
    Integer(IntegerError),
    HuffmanDecoding(HuffmanDecodingError),
    HuffmanEncoding(HuffmanEncodingError),
    BufSize(TryFromIntError),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::UnexpectedEnd => write!(f, "unexpected end"),
            Error::EncodedStringTooLong { len, limit } => {
                write!(f, "encoded string length {len} exceeds limit {limit}")
            }
            Error::Integer(e) => write!(f, "could not parse integer: {}", e),
            Error::HuffmanDecoding(e) => write!(f, "Huffman decode failed: {:?}", e),
            Error::HuffmanEncoding(e) => write!(f, "Huffman encode failed: {:?}", e),
            Error::BufSize(_) => write!(f, "number in buffer wrong size"),
        }
    }
}

pub fn decode<B: Buf>(size: u8, buf: &mut B) -> Result<Vec<u8>, Error> {
    decode_limited(size, buf, usize::MAX)
}

pub(crate) fn decode_limited<B: Buf>(
    size: u8,
    buf: &mut B,
    max_encoded_len: usize,
) -> Result<Vec<u8>, Error> {
    let (flags, len) = prefix_int::decode(size - 1, buf)?;
    let limit = u64::try_from(max_encoded_len).unwrap_or(u64::MAX);
    if len > limit {
        return Err(Error::EncodedStringTooLong {
            len,
            limit: max_encoded_len,
        });
    }
    let len: usize = len.try_into()?;
    if buf.remaining() < len {
        return Err(Error::UnexpectedEnd);
    }

    let payload = buf.copy_to_bytes(len);
    let value = if flags & 1 == 0 {
        payload.into_iter().collect()
    } else {
        let mut decoded = Vec::new();
        for byte in payload.as_ref().hpack_decode() {
            decoded.push(byte?);
        }
        decoded
    };
    Ok(value)
}

pub fn encode<B: BufMut>(size: u8, flags: u8, value: &[u8], buf: &mut B) -> Result<(), Error> {
    let encoded = value.hpack_encode()?;
    prefix_int::encode(size - 1, flags << 1 | 1, encoded.len().try_into()?, buf);
    for byte in encoded {
        buf.write(byte);
    }
    Ok(())
}

impl From<HuffmanEncodingError> for Error {
    fn from(error: HuffmanEncodingError) -> Self {
        Error::HuffmanEncoding(error)
    }
}

impl From<IntegerError> for Error {
    fn from(error: IntegerError) -> Self {
        match error {
            IntegerError::UnexpectedEnd => Error::UnexpectedEnd,
            e => Error::Integer(e),
        }
    }
}

impl From<HuffmanDecodingError> for Error {
    fn from(error: HuffmanDecodingError) -> Self {
        Error::HuffmanDecoding(error)
    }
}

impl From<TryFromIntError> for Error {
    fn from(error: TryFromIntError) -> Self {
        Error::BufSize(error)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use assert_matches::assert_matches;

    use super::*;

    #[test]
    fn codec_6() {
        let mut buf = Vec::new();
        encode(6, 0b01, b"name without ref", &mut buf).unwrap();
        let mut read = Cursor::new(&buf);
        assert_eq!(
            &buf,
            &[
                0b0110_1100,
                168,
                116,
                149,
                79,
                6,
                76,
                231,
                181,
                42,
                88,
                89,
                127
            ]
        );
        assert_eq!(decode(6, &mut read).unwrap(), b"name without ref");
    }

    #[test]
    fn codec_8() {
        let mut buf = Vec::new();
        encode(8, 0b01, b"name with ref", &mut buf).unwrap();
        let mut read = Cursor::new(&buf);
        assert_eq!(
            &buf,
            &[0b1000_1010, 168, 116, 149, 79, 6, 76, 234, 88, 89, 127]
        );
        assert_eq!(decode(8, &mut read).unwrap(), b"name with ref");
    }

    #[test]
    fn codec_8_empty() {
        let mut buf = Vec::new();
        encode(8, 0b01, b"", &mut buf).unwrap();
        let mut read = Cursor::new(&buf);
        assert_eq!(&buf, &[0b1000_0000]);
        assert_eq!(decode(8, &mut read).unwrap(), b"");
    }

    #[test]
    fn decode_non_huffman() {
        let buf = vec![0b0100_0011, b'b', b'a', b'r'];
        let mut read = Cursor::new(&buf);
        assert_eq!(decode(6, &mut read).unwrap(), b"bar");
    }

    #[test]
    fn decode_too_short() {
        let buf = vec![0b0100_0011, b'b', b'a'];
        let mut read = Cursor::new(&buf);
        assert_matches!(decode(6, &mut read), Err(Error::UnexpectedEnd));
    }

    #[test]
    fn encoded_length_limit_is_checked_before_payload() {
        let mut buf = Vec::new();
        prefix_int::encode(7, 0, 5, &mut buf);
        let prefix_len = buf.len();
        let mut read = Cursor::new(buf);

        assert_eq!(
            decode_limited(8, &mut read, 4),
            Err(Error::EncodedStringTooLong { len: 5, limit: 4 })
        );
        assert_eq!(usize::try_from(read.position()).unwrap(), prefix_len);
        assert_eq!(read.remaining(), 0);
    }

    #[test]
    fn huffman_payload_decodes_from_borrowed_bytes() {
        // RFC 7541 Appendix C.4.1 encodes "www.example.com" as these
        // twelve Huffman octets.
        // https://www.rfc-editor.org/rfc/rfc7541.html#appendix-C.4.1
        let mut encoded = Cursor::new(vec![
            0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
        ]);

        let decoded = decode(8, &mut encoded).unwrap();

        assert_eq!(decoded, b"www.example.com");
    }
}
