use bytes::{Buf, BufMut};

use super::{parse_error::ParseError, prefix_int, prefix_string};

// 4.5. Field Line Representations
// Single header field line. These representations reference the static table or
// the dynamic table in a particular state, but do not modify that state.
pub enum HeaderBlockField {
    // 4.5.2. Indexed Field Line
    // Entry in the static table, or in the dynamic table with an absolute index
    // less than the value of the Base.
    //   0   1   2   3   4   5   6   7
    // +---+---+---+---+---+---+---+---+
    // | 1 | T |      Index (6+)       |
    // +---+---+-----------------------+
    Indexed,
    // 4.5.3. Indexed Field Line With Post-Base Index
    // Entry in the dynamic table with an absolute index greater than or equal
    // to the value of the Base.
    //   0   1   2   3   4   5   6   7
    // +---+---+---+---+---+---+---+---+
    // | 0 | 0 | 0 | 1 |  Index (4+)   |
    // +---+---+---+---+---------------+
    IndexedWithPostBase,
    // 4.5.4. Literal Field Line With Name Reference
    // Entry in the dynamic table with an absolute index greater than or equal
    // to the value of the Base.
    //   0   1   2   3   4   5   6   7
    // +---+---+---+---+---+---+---+---+
    // | 0 | 1 | N | T |Name Index (4+)|
    // +---+---+---+---+---------------+
    // | H |     Value Length (7+)     |
    // +---+---------------------------+
    // |  Value String (Length bytes)  |
    // +-------------------------------+
    LiteralWithNameRef,
    // 4.5.5. Literal Field Line With Post-Base Name Reference
    // The field name matches a name of an entry in the static table, or in the
    // dynamic table with an absolute index less than the value of the Base.
    //   0   1   2   3   4   5   6   7
    // +---+---+---+---+---+---+---+---+
    // | 0 | 0 | 0 | 0 | N |NameIdx(3+)|
    // +---+---+---+---+---+-----------+
    // | H |     Value Length (7+)     |
    // +---+---------------------------+
    // |  Value String (Length bytes)  |
    // +-------------------------------+
    LiteralWithPostBaseNameRef,
    // 4.5.6. Literal Field Line With Literal Name
    // Field name and field value are encoded as string literals.
    //   0   1   2   3   4   5   6   7
    // +---+---+---+---+---+---+---+---+
    // | 0 | 0 | 1 | N | H |NameLen(3+)|
    // +---+---+---+---+---+-----------+
    // |  Name String (Length bytes)   |
    // +---+---------------------------+
    // | H |     Value Length (7+)     |
    // +---+---------------------------+
    // |  Value String (Length bytes)  |
    // +-------------------------------+
    Literal,
    Unknown,
}

impl HeaderBlockField {
    // Check how the next field is encoded according its first byte
    pub fn decode(first: u8) -> Self {
        if first & 0b1000_0000 != 0 {
            HeaderBlockField::Indexed
        } else if first & 0b1111_0000 == 0b0001_0000 {
            HeaderBlockField::IndexedWithPostBase
        } else if first & 0b1100_0000 == 0b0100_0000 {
            HeaderBlockField::LiteralWithNameRef
        } else if first & 0b1111_0000 == 0 {
            HeaderBlockField::LiteralWithPostBaseNameRef
        } else if first & 0b1110_0000 == 0b0010_0000 {
            HeaderBlockField::Literal
        } else {
            HeaderBlockField::Unknown
        }
    }
}

// 4.5.1. Encoded Field Section Prefix
#[derive(Debug, PartialEq)]
pub struct HeaderPrefix {
    encoded_insert_count: usize,
    sign_negative: bool,
    delta_base: usize,
}

impl HeaderPrefix {
    pub fn new(required: usize, base: usize, total_inserted: usize, max_table_size: usize) -> Self {
        if max_table_size == 0 {
            return Self {
                encoded_insert_count: 0,
                sign_negative: false,
                delta_base: 0,
            };
        }

        if required == 0 {
            return Self {
                encoded_insert_count: 0,
                delta_base: 0,
                sign_negative: false,
            };
        }

        assert!(required <= total_inserted);
        let (sign_negative, delta_base) = if required > base {
            (true, required - base - 1)
        } else {
            (false, base - required)
        };

        let max_entries = max_table_size / 32;

        Self {
            encoded_insert_count: required % (2 * max_entries) + 1,
            sign_negative,
            delta_base,
        }
    }

    pub fn get(
        self,
        total_inserted: usize,
        max_table_size: usize,
    ) -> Result<(usize, usize), ParseError> {
        // Required Insert Count reconstruction uses the advertised maximum
        // capacity, not the table's current capacity.
        // https://www.rfc-editor.org/rfc/rfc9204.html#section-4.5.1.1
        let required = if self.encoded_insert_count == 0 {
            0
        } else {
            let max_entries = max_table_size / 32;
            let full_range = 2 * max_entries;
            if max_entries == 0 || self.encoded_insert_count > full_range {
                return Err(ParseError::InvalidRequiredInsertCount(
                    self.encoded_insert_count,
                ));
            }

            // Choose the largest candidate no more than MaxEntries ahead of the
            // decoder's current Insert Count.
            let max_value = total_inserted.checked_add(max_entries).ok_or(
                ParseError::InvalidRequiredInsertCount(self.encoded_insert_count),
            )?;
            let max_wrapped = (max_value / full_range) * full_range;
            let mut required = max_wrapped
                .checked_add(self.encoded_insert_count)
                .and_then(|value| value.checked_sub(1))
                .ok_or(ParseError::InvalidRequiredInsertCount(
                    self.encoded_insert_count,
                ))?;

            if required > max_value {
                if required <= full_range {
                    return Err(ParseError::InvalidRequiredInsertCount(
                        self.encoded_insert_count,
                    ));
                }
                required -= full_range;
            }

            if required == 0 {
                return Err(ParseError::InvalidRequiredInsertCount(
                    self.encoded_insert_count,
                ));
            }
            required
        };

        let invalid_base = || ParseError::InvalidBase {
            required_insert_count: required,
            sign_negative: self.sign_negative,
            delta_base: self.delta_base,
        };

        // Delta Base is peer-controlled. Checked arithmetic rejects a Base that
        // cannot be represented as `usize`.
        // https://www.rfc-editor.org/rfc/rfc9204.html#section-4.5.1
        let base = if !self.sign_negative {
            // With no dynamic references, RIC 0 can still use any Base.
            // https://www.rfc-editor.org/rfc/rfc9204.html#section-4.5.1.2
            required
                .checked_add(self.delta_base)
                .ok_or_else(invalid_base)?
        } else {
            // A negative sign is invalid when Required Insert Count is no
            // greater than Delta Base, including when both values are zero.
            // https://www.rfc-editor.org/rfc/rfc9204.html#section-4.5.1.2
            required
                .checked_sub(self.delta_base)
                .and_then(|base| base.checked_sub(1))
                .ok_or_else(invalid_base)?
        };

        Ok((required, base))
    }

    // 4.5.1. Encoded Field Section Prefix
    //   0   1   2   3   4   5   6   7
    // +---+---+---+---+---+---+---+---+
    // |   Required Insert Count (8+)  |
    // +---+---------------------------+
    // | S |      Delta Base (7+)      |
    // +---+---------------------------+
    // |      Encoded Field Lines    ...
    // +-------------------------------+
    pub fn decode<R: Buf>(buf: &mut R) -> Result<Self, ParseError> {
        let (_, encoded_insert_count) = prefix_int::decode(8, buf)?;
        let (sign_negative, delta_base) = prefix_int::decode(7, buf)?;

        if encoded_insert_count > (usize::MAX as u64) {
            return Err(ParseError::Integer(
                crate::qpack::prefix_int::Error::Overflow,
            ));
        }

        if delta_base > (usize::MAX as u64) {
            return Err(ParseError::Integer(
                crate::qpack::prefix_int::Error::Overflow,
            ));
        }

        Ok(Self {
            encoded_insert_count: encoded_insert_count as usize,
            delta_base: delta_base as usize,
            sign_negative: sign_negative == 1,
        })
    }

    pub fn encode<W: BufMut>(&self, buf: &mut W) {
        let sign_bit = if self.sign_negative { 1 } else { 0 };
        prefix_int::encode(8, 0, self.encoded_insert_count as u64, buf);
        prefix_int::encode(7, sign_bit, self.delta_base as u64, buf);
    }
}

#[derive(Debug, PartialEq)]
pub enum Indexed {
    Static(usize),
    Dynamic(usize),
}

impl Indexed {
    pub fn decode<R: Buf>(buf: &mut R) -> Result<Self, ParseError> {
        match prefix_int::decode(6, buf)? {
            (0b11, i) => {
                if i > (usize::MAX as u64) {
                    return Err(ParseError::Integer(
                        crate::qpack::prefix_int::Error::Overflow,
                    ));
                }

                Ok(Indexed::Static(i as usize))
            }
            (0b10, i) => {
                if i > (usize::MAX as u64) {
                    return Err(ParseError::Integer(
                        crate::qpack::prefix_int::Error::Overflow,
                    ));
                }

                Ok(Indexed::Dynamic(i as usize))
            }
            (f, _) => Err(ParseError::InvalidPrefix(f)),
        }
    }

    pub fn encode<W: BufMut>(&self, buf: &mut W) {
        match self {
            Indexed::Static(i) => prefix_int::encode(6, 0b11, *i as u64, buf),
            Indexed::Dynamic(i) => prefix_int::encode(6, 0b10, *i as u64, buf),
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct IndexedWithPostBase(pub usize);

impl IndexedWithPostBase {
    pub fn decode<R: Buf>(buf: &mut R) -> Result<Self, ParseError> {
        match prefix_int::decode(4, buf)? {
            (0b0001, i) => {
                if i > (usize::MAX as u64) {
                    return Err(ParseError::Integer(
                        crate::qpack::prefix_int::Error::Overflow,
                    ));
                }

                Ok(IndexedWithPostBase(i as usize))
            }
            (f, _) => Err(ParseError::InvalidPrefix(f)),
        }
    }

    pub fn encode<W: BufMut>(&self, buf: &mut W) {
        prefix_int::encode(4, 0b0001, self.0 as u64, buf)
    }
}

#[derive(Debug, PartialEq)]
pub enum LiteralWithNameRef {
    Static { index: usize, value: Vec<u8> },
    Dynamic { index: usize, value: Vec<u8> },
}

impl LiteralWithNameRef {
    pub fn new_static<T: Into<Vec<u8>>>(index: usize, value: T) -> Self {
        LiteralWithNameRef::Static {
            index,
            value: value.into(),
        }
    }

    pub fn new_dynamic<T: Into<Vec<u8>>>(index: usize, value: T) -> Self {
        LiteralWithNameRef::Dynamic {
            index,
            value: value.into(),
        }
    }

    pub fn decode<R: Buf>(buf: &mut R) -> Result<Self, ParseError> {
        Self::decode_limited(buf, usize::MAX)
    }

    pub(crate) fn decode_limited<R: Buf>(
        buf: &mut R,
        max_encoded_string_size: usize,
    ) -> Result<Self, ParseError> {
        match prefix_int::decode(4, buf)? {
            (f, i) if f & 0b0101 == 0b0101 => {
                if i > (usize::MAX as u64) {
                    return Err(ParseError::Integer(
                        crate::qpack::prefix_int::Error::Overflow,
                    ));
                }

                Ok(LiteralWithNameRef::new_static(
                    i as usize,
                    prefix_string::decode_limited(8, buf, max_encoded_string_size)?,
                ))
            }
            (f, i) if f & 0b0101 == 0b0100 => {
                if i > (usize::MAX as u64) {
                    return Err(ParseError::Integer(
                        crate::qpack::prefix_int::Error::Overflow,
                    ));
                }

                Ok(LiteralWithNameRef::new_dynamic(
                    i as usize,
                    prefix_string::decode_limited(8, buf, max_encoded_string_size)?,
                ))
            }
            (f, _) => Err(ParseError::InvalidPrefix(f)),
        }
    }

    pub fn encode<W: BufMut>(&self, buf: &mut W) -> Result<(), prefix_string::Error> {
        match self {
            LiteralWithNameRef::Static { index, value } => {
                prefix_int::encode(4, 0b0101, *index as u64, buf);
                prefix_string::encode(8, 0, value, buf)?;
            }
            LiteralWithNameRef::Dynamic { index, value } => {
                prefix_int::encode(4, 0b0100, *index as u64, buf);
                prefix_string::encode(8, 0, value, buf)?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, PartialEq)]
pub struct LiteralWithPostBaseNameRef {
    pub index: usize,
    pub value: Vec<u8>,
}

impl LiteralWithPostBaseNameRef {
    pub fn new<T: Into<Vec<u8>>>(index: usize, value: T) -> Self {
        LiteralWithPostBaseNameRef {
            index,
            value: value.into(),
        }
    }

    pub fn decode<R: Buf>(buf: &mut R) -> Result<Self, ParseError> {
        Self::decode_limited(buf, usize::MAX)
    }

    pub(crate) fn decode_limited<R: Buf>(
        buf: &mut R,
        max_encoded_string_size: usize,
    ) -> Result<Self, ParseError> {
        match prefix_int::decode(3, buf)? {
            (f, i) if f & 0b1111_0000 == 0 => {
                if i > (usize::MAX as u64) {
                    return Err(ParseError::Integer(
                        crate::qpack::prefix_int::Error::Overflow,
                    ));
                }

                Ok(LiteralWithPostBaseNameRef::new(
                    i as usize,
                    prefix_string::decode_limited(8, buf, max_encoded_string_size)?,
                ))
            }
            (f, _) => Err(ParseError::InvalidPrefix(f)),
        }
    }

    pub fn encode<W: BufMut>(&self, buf: &mut W) -> Result<(), prefix_string::Error> {
        prefix_int::encode(3, 0b0000, self.index as u64, buf);
        prefix_string::encode(8, 0, &self.value, buf)?;
        Ok(())
    }
}

#[derive(Debug, PartialEq)]
pub struct Literal {
    pub name: Vec<u8>,
    pub value: Vec<u8>,
}

impl Literal {
    pub fn new<T: Into<Vec<u8>>>(name: T, value: T) -> Self {
        Literal {
            name: name.into(),
            value: value.into(),
        }
    }

    pub fn decode<R: Buf>(buf: &mut R) -> Result<Self, ParseError> {
        Self::decode_limited(buf, usize::MAX)
    }

    pub(crate) fn decode_limited<R: Buf>(
        buf: &mut R,
        max_encoded_string_size: usize,
    ) -> Result<Self, ParseError> {
        if buf.remaining() < 1 {
            return Err(ParseError::Integer(prefix_int::Error::UnexpectedEnd));
        } else if buf.chunk()[0] & 0b1110_0000 != 0b0010_0000 {
            return Err(ParseError::InvalidPrefix(buf.chunk()[0]));
        }
        Ok(Literal::new(
            prefix_string::decode_limited(4, buf, max_encoded_string_size)?,
            prefix_string::decode_limited(8, buf, max_encoded_string_size)?,
        ))
    }

    pub fn encode<W: BufMut>(&self, buf: &mut W) -> Result<(), prefix_string::Error> {
        prefix_string::encode(4, 0b0010, &self.name, buf)?;
        prefix_string::encode(8, 0, &self.value, buf)?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use std::{convert::TryInto, io::Cursor};

    use super::*;

    const TABLE_SIZE: usize = 4096;

    #[test]
    fn indexed_static() {
        let field = Indexed::Static(42);
        let mut buf = vec![];
        field.encode(&mut buf);
        let mut read = Cursor::new(&buf);
        assert_eq!(Indexed::decode(&mut read), Ok(field));
    }

    #[test]
    fn indexed_dynamic() {
        let field = Indexed::Dynamic(42);
        let mut buf = vec![];
        field.encode(&mut buf);
        let mut read = Cursor::new(&buf);
        assert_eq!(Indexed::decode(&mut read), Ok(field));
    }

    #[test]
    fn indexed_with_postbase() {
        let field = IndexedWithPostBase(42);
        let mut buf = vec![];
        field.encode(&mut buf);
        let mut read = Cursor::new(&buf);
        assert_eq!(IndexedWithPostBase::decode(&mut read), Ok(field));
    }

    #[test]
    fn literal_with_name_ref() {
        let field = LiteralWithNameRef::new_static(42, "foo");
        let mut buf = vec![];
        field.encode(&mut buf).unwrap();
        let mut read = Cursor::new(&buf);
        assert_eq!(LiteralWithNameRef::decode(&mut read), Ok(field));
    }

    #[test]
    fn literal_with_post_base_name_ref() {
        let field = LiteralWithPostBaseNameRef::new(42, "foo");
        let mut buf = vec![];
        field.encode(&mut buf).unwrap();
        let mut read = Cursor::new(&buf);
        assert_eq!(LiteralWithPostBaseNameRef::decode(&mut read), Ok(field));
    }

    #[test]
    fn literal() {
        let field = Literal::new("foo", "bar");
        let mut buf = vec![];
        field.encode(&mut buf).unwrap();
        let mut read = Cursor::new(&buf);
        assert_eq!(Literal::decode(&mut read), Ok(field));
    }

    #[test]
    fn header_prefix() {
        let prefix = HeaderPrefix::new(10, 5, 12, TABLE_SIZE);
        let mut buf = vec![];
        prefix.encode(&mut buf);
        let mut read = Cursor::new(&buf);
        let decoded = HeaderPrefix::decode(&mut read);
        assert_eq!(decoded, Ok(prefix));
        assert_eq!(decoded.unwrap().get(13, 3332).unwrap(), (10, 5));
    }

    #[test]
    fn header_prefix_table_size_0() {
        assert_eq!(HeaderPrefix::new(10, 5, 12, 0).get(1, 0).unwrap(), (0, 0));
    }

    #[test]
    fn nonzero_insert_count_requires_at_least_one_table_entry() {
        let prefix = HeaderPrefix {
            encoded_insert_count: 1,
            sign_negative: false,
            delta_base: 0,
        };

        assert_eq!(
            prefix.get(0, 31),
            Err(ParseError::InvalidRequiredInsertCount(1))
        );
    }

    #[test]
    fn encoded_insert_count_cannot_exceed_full_range() {
        let prefix = HeaderPrefix {
            encoded_insert_count: 3,
            sign_negative: false,
            delta_base: 0,
        };

        assert_eq!(
            prefix.get(0, 32),
            Err(ParseError::InvalidRequiredInsertCount(3))
        );
    }

    #[test]
    fn required_insert_count_reconstruction_rejects_overflow() {
        let prefix = HeaderPrefix {
            encoded_insert_count: 2,
            sign_negative: false,
            delta_base: 0,
        };

        assert_eq!(
            prefix.get(usize::MAX - 1, 32),
            Err(ParseError::InvalidRequiredInsertCount(2))
        );
    }

    #[test]
    fn base_index_too_small() {
        let mut buf = vec![];
        let encoded_largest_ref: u64 = ((2 % (2 * TABLE_SIZE / 32)) + 1).try_into().unwrap();
        prefix_int::encode(8, 0, encoded_largest_ref, &mut buf);
        prefix_int::encode(7, 1, 2, &mut buf); // base index negative = 0

        let mut read = Cursor::new(&buf);
        assert_eq!(
            HeaderPrefix::decode(&mut read).unwrap().get(2, TABLE_SIZE),
            Err(ParseError::InvalidBase {
                required_insert_count: 2,
                sign_negative: true,
                delta_base: 2,
            })
        );
    }

    #[test]
    fn negative_delta_base_with_zero_required_insert_count_is_rejected() {
        let prefix = HeaderPrefix {
            encoded_insert_count: 0,
            sign_negative: true,
            delta_base: 0,
        };

        assert_eq!(
            prefix.get(0, TABLE_SIZE),
            Err(ParseError::InvalidBase {
                required_insert_count: 0,
                sign_negative: true,
                delta_base: 0,
            })
        );
    }

    #[test]
    fn positive_delta_base_with_zero_required_insert_count_is_allowed() {
        let prefix = HeaderPrefix {
            encoded_insert_count: 0,
            sign_negative: false,
            delta_base: 1,
        };

        // A field section without dynamic references can use any Base. RIC 0
        // therefore does not require Delta Base to be zero when the sign is positive.
        // https://www.rfc-editor.org/rfc/rfc9204.html#section-4.5.1.2
        assert_eq!(prefix.get(0, TABLE_SIZE), Ok((0, 1)));
    }

    #[test]
    fn positive_delta_base_overflow_is_rejected() {
        let mut field_section = vec![];
        prefix_int::encode(8, 0, 1, &mut field_section);
        prefix_int::encode(7, 0, 2, &mut field_section);

        let prefix = HeaderPrefix::decode(&mut Cursor::new(field_section)).unwrap();
        // With MaxEntries set to one, EIC 1 reconstructs Required Insert Count
        // `usize::MAX - 1`. Adding the wire Delta Base must fail.
        assert_eq!(
            prefix.get(usize::MAX - 1, 32),
            Err(ParseError::InvalidBase {
                required_insert_count: usize::MAX - 1,
                sign_negative: false,
                delta_base: 2,
            })
        );
    }

    #[test]
    fn negative_delta_base_arithmetic_overflow_is_rejected() {
        // This value is wire-representable on 32-bit targets, so the test covers
        // the arithmetic boundary on every supported architecture.
        let prefix = HeaderPrefix {
            encoded_insert_count: 2,
            sign_negative: true,
            delta_base: usize::MAX,
        };
        assert_eq!(
            prefix.get(0, 32),
            Err(ParseError::InvalidBase {
                required_insert_count: 1,
                sign_negative: true,
                delta_base: usize::MAX,
            })
        );
    }
}
