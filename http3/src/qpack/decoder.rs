use std::{convert::TryInto, fmt, io::Cursor, num::TryFromIntError};

use bytes::{Buf, BufMut};
#[cfg(feature = "tracing")]
use tracing::trace;

use super::{
    block::{
        HeaderBlockField, HeaderPrefix, Indexed, IndexedWithPostBase, Literal, LiteralWithNameRef,
        LiteralWithPostBaseNameRef,
    },
    dynamic::{DynamicTable, DynamicTableDecoder, Error as DynamicTableError},
    field::HeaderField,
    parse_error::ParseError,
    prefix_int, prefix_string,
    static_::{Error as StaticError, StaticTable},
    stream::{
        Duplicate, DynamicTableSizeUpdate, EncoderInstruction, HeaderAck, InsertCountIncrement,
        InsertWithNameRef, InsertWithoutNameRef, StreamCancel,
    },
    vas,
};

#[derive(Debug, PartialEq)]
pub enum DecoderError {
    InvalidInteger(prefix_int::Error),
    InvalidString(prefix_string::Error),
    InvalidIndex(vas::Error),
    DynamicTable(DynamicTableError),
    InvalidStaticIndex(usize),
    UnknownPrefix(u8),
    MissingRefs(usize),
    BadBaseIndex {
        required_insert_count: usize,
        sign_negative: bool,
        delta_base: usize,
    },
    InvalidRequiredInsertCount(usize),
    TooManyBlockedStreams,
    UnexpectedEnd,
    HeaderTooLong(u64),
    BufSize(TryFromIntError),
}

impl std::error::Error for DecoderError {}

impl std::fmt::Display for DecoderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecoderError::InvalidInteger(e) => write!(f, "invalid integer: {}", e),
            DecoderError::InvalidString(e) => write!(f, "invalid string: {:?}", e),
            DecoderError::InvalidIndex(e) => write!(f, "invalid dynamic index: {:?}", e),
            DecoderError::DynamicTable(e) => write!(f, "dynamic table error: {:?}", e),
            DecoderError::InvalidStaticIndex(i) => write!(f, "unknown static index: {}", i),
            DecoderError::UnknownPrefix(p) => write!(f, "unknown instruction code: 0x{}", p),
            DecoderError::MissingRefs(required_insert_count) => write!(
                f,
                "field section requires insert count {}",
                required_insert_count
            ),
            DecoderError::BadBaseIndex {
                required_insert_count,
                sign_negative,
                delta_base,
            } => write!(
                f,
                "invalid base from required insert count {}, sign {}, and delta base {}",
                required_insert_count,
                if *sign_negative {
                    "negative"
                } else {
                    "positive"
                },
                delta_base
            ),
            DecoderError::InvalidRequiredInsertCount(i) => {
                write!(f, "invalid required insert count: {}", i)
            }
            DecoderError::TooManyBlockedStreams => write!(f, "too many blocked streams"),
            DecoderError::UnexpectedEnd => write!(f, "unexpected end"),
            DecoderError::HeaderTooLong(_) => write!(f, "header too long"),
            DecoderError::BufSize(_) => write!(f, "number in buffer wrong size"),
        }
    }
}

pub fn ack_header<W: BufMut>(stream_id: u64, decoder: &mut W) {
    HeaderAck(stream_id).encode(decoder);
}

pub fn stream_canceled<W: BufMut>(stream_id: u64, decoder: &mut W) {
    StreamCancel(stream_id).encode(decoder);
}

#[derive(PartialEq, Debug)]
pub struct Decoded {
    /// The decoded fields
    pub fields: Vec<HeaderField<'static>>,
    /// Whether the field section's Required Insert Count is non-zero.
    ///
    /// A successfully decoded field section with a non-zero Required Insert
    /// Count requires a Section Acknowledgment.
    ///
    /// See [RFC 9204 Section 4.4.1](https://www.rfc-editor.org/rfc/rfc9204.html#section-4.4.1).
    pub dyn_ref: bool,
    /// Uncompressed field section size, including the 32-byte overhead per field.
    ///
    /// See [RFC 9114 Section 4.2.2](https://www.rfc-editor.org/rfc/rfc9114.html#section-4.2.2).
    pub mem_size: u64,
}

/// Prefix state retained while a field section is blocked on dynamic entries.
///
/// Required Insert Count reconstruction depends on the decoder insert count at
/// the time the prefix is first processed. Reconstructing it after the table has
/// advanced can bind the same encoded prefix to a different insertion.
///
/// See [RFC 9204, Section 4.5.1.1](https://www.rfc-editor.org/rfc/rfc9204.html#section-4.5.1.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FieldSectionPrefix {
    required_ref: usize,
    base: usize,
}

pub struct Decoder {
    table: DynamicTable,
    // SETTINGS_QPACK_MAX_TABLE_CAPACITY is a fixed decoding limit. The table's
    // current capacity is separate and starts at zero.
    // https://www.rfc-editor.org/rfc/rfc9204.html#section-3.2.3
    max_table_capacity: usize,
    max_blocked_streams: u64,
    max_encoded_string_size: usize,
    // Preserve a decoded literal name while its value is still arriving on the
    // encoder stream. This avoids decoding and allocating the name on each retry.
    // https://www.rfc-editor.org/rfc/rfc9204.html#section-4.3.3
    pending_literal_name: Option<Vec<u8>>,
}

impl Decoder {
    pub(crate) fn new(
        max_table_capacity: u64,
        max_blocked_streams: u64,
    ) -> Result<Self, DecoderError> {
        let max_table_capacity = max_table_capacity.try_into()?;
        // The peer encoder raises the current capacity with a Set Dynamic Table
        // Capacity instruction before inserting entries.
        // https://www.rfc-editor.org/rfc/rfc9204.html#section-4.3.1
        let table = DynamicTable::new();
        Ok(Self {
            table,
            max_table_capacity,
            max_blocked_streams,
            max_encoded_string_size: crate::config::DEFAULT_QPACK_DECODE_BUFFER_SIZE,
            pending_literal_name: None,
        })
    }

    /// Sets the local limit for one encoded QPACK string.
    ///
    /// The length is checked as soon as its prefix is complete, before the
    /// decoder waits for or copies the payload.
    ///
    /// See [RFC 9204, Section 7.4](https://www.rfc-editor.org/rfc/rfc9204.html#section-7.4).
    pub(crate) fn set_max_encoded_string_size(&mut self, max_encoded_string_size: usize) {
        self.max_encoded_string_size = max_encoded_string_size;
    }

    /// Returns the local encoded-string limit copied into shared decoder state.
    pub(crate) fn max_encoded_string_size(&self) -> usize {
        self.max_encoded_string_size
    }

    /// Returns whether the configured maximum dynamic table capacity is non-zero.
    ///
    /// The endpoint advertises this limit to bound the memory the peer encoder may
    /// use. A zero limit forbids dynamic table entries, allowing field sections to
    /// use the stateless decoding path.
    ///
    /// See [RFC 9204, Section 3.2.3](https://www.rfc-editor.org/rfc/rfc9204.html#section-3.2.3).
    pub(crate) fn dynamic_table_enabled(&self) -> bool {
        self.max_table_capacity > 0
    }

    /// Returns the advertised limit on concurrently blocked request or push streams.
    ///
    /// This is the `SETTINGS_QPACK_BLOCKED_STREAMS` value. A value of zero means
    /// every field section must be decodable from the current table state.
    ///
    /// See [RFC 9204, Section 2.1.2](https://www.rfc-editor.org/rfc/rfc9204.html#section-2.1.2),
    /// [Section 5](https://www.rfc-editor.org/rfc/rfc9204.html#section-5), and
    /// [RFC 9114, Section 7.2.4](https://www.rfc-editor.org/rfc/rfc9114.html#section-7.2.4).
    pub(crate) fn max_blocked_streams(&self) -> u64 {
        self.max_blocked_streams
    }

    // Decode field lines received on a request or push stream.
    // https://www.rfc-editor.org/rfc/rfc9204.html#section-4.5
    #[inline(always)]
    pub fn decode_header<T: Buf>(&self, buf: &mut T) -> Result<Decoded, DecoderError> {
        self.decode_header_limited(buf, u64::MAX, &mut None)
    }

    pub(crate) fn decode_header_limited<T: Buf>(
        &self,
        buf: &mut T,
        max_size: u64,
        prefix: &mut Option<FieldSectionPrefix>,
    ) -> Result<Decoded, DecoderError> {
        let FieldSectionPrefix { required_ref, base } = match *prefix {
            Some(prefix) => prefix,
            None => {
                let (required_ref, base) = HeaderPrefix::decode(buf)?
                    .get(self.table.total_inserted(), self.max_table_capacity)?;
                let decoded = FieldSectionPrefix { required_ref, base };
                *prefix = Some(decoded);
                decoded
            }
        };

        if required_ref > self.table.total_inserted() {
            return Err(DecoderError::MissingRefs(required_ref));
        }

        let decoder_table = self.table.decoder(base, required_ref);

        let mut mem_size = 0;
        let mut fields = Vec::new();
        while buf.has_remaining() {
            let field =
                Self::parse_header_field(&decoder_table, buf, self.max_encoded_string_size)?;
            mem_size += field.mem_size() as u64;
            if mem_size > max_size {
                return Err(DecoderError::HeaderTooLong(mem_size));
            }
            fields.push(field);
        }

        Ok(Decoded {
            fields,
            mem_size,
            dyn_ref: required_ref > 0,
        })
    }

    // The receiving side of encoder stream
    pub fn on_encoder_recv<R: Buf, W: BufMut>(
        &mut self,
        read: &mut R,
        write: &mut W,
    ) -> Result<usize, DecoderError> {
        self.on_encoder_recv_with(read, write, Self::parse_instruction)
    }

    /// Processes encoder instructions from a checkpointable receive cursor.
    ///
    /// Complete parts of an instruction can be consumed before the entire
    /// instruction arrives. The decoder keeps that parsed state and leaves the
    /// incomplete part available for the next receive chunk.
    ///
    /// See [RFC 9204, Section 4.3](https://www.rfc-editor.org/rfc/rfc9204.html#section-4.3).
    pub(crate) fn on_encoder_recv_buffered<R: Buf + Clone, W: BufMut>(
        &mut self,
        read: &mut R,
        write: &mut W,
    ) -> Result<usize, DecoderError> {
        self.on_encoder_recv_with(read, write, Self::parse_instruction_buffered)
    }

    fn on_encoder_recv_with<R: Buf, W: BufMut>(
        &mut self,
        read: &mut R,
        write: &mut W,
        parse_instruction: fn(&mut Self, &mut R) -> Result<Option<Instruction>, DecoderError>,
    ) -> Result<usize, DecoderError> {
        let inserted_on_start = self.table.total_inserted();

        while let Some(instruction) = parse_instruction(self, read)? {
            #[cfg(feature = "tracing")]
            trace!("instruction {:?}", instruction);

            match instruction {
                // Peer insertions must update the decoder table. They cannot use
                // the local encoder's literal fallback.
                Instruction::Insert(field) => self.table.put_decoder(field)?,
                Instruction::TableSizeUpdate(size) => {
                    // The encoder may change the current capacity within the
                    // limit advertised in our SETTINGS.
                    // https://www.rfc-editor.org/rfc/rfc9204.html#section-4.3.1
                    if size > self.max_table_capacity {
                        return Err(DynamicTableError::MaximumTableSizeTooLarge.into());
                    }
                    self.table.set_max_size(size)?;
                }
            }
        }

        if self.table.total_inserted() != inserted_on_start {
            // Six bits form the integer prefix. Values above 63 continue in the
            // following bytes.
            // https://www.rfc-editor.org/rfc/rfc9204.html#section-4.4.3
            InsertCountIncrement(self.table.total_inserted() - inserted_on_start).encode(write);
        }

        Ok(self.table.total_inserted())
    }

    fn parse_instruction<R: Buf>(
        &mut self,
        read: &mut R,
    ) -> Result<Option<Instruction>, DecoderError> {
        if read.remaining() < 1 {
            return Ok(None);
        }

        let mut buf = Cursor::new(read.chunk());
        let instruction = self.decode_instruction(&mut buf)?;
        if instruction.is_some() {
            read.advance(buf.position() as usize);
        }
        Ok(instruction)
    }

    fn parse_instruction_buffered<R: Buf + Clone>(
        &mut self,
        read: &mut R,
    ) -> Result<Option<Instruction>, DecoderError> {
        if self.pending_literal_name.is_some() {
            return self.parse_pending_literal_value(read);
        }

        if read.remaining() < 1 {
            return Ok(None);
        }

        if matches!(
            EncoderInstruction::decode(read.chunk()[0]),
            EncoderInstruction::InsertWithoutNameRef
        ) {
            // Consume a complete literal name immediately. If the value is
            // fragmented, the next poll resumes from its prefix instead of
            // decoding the name again.
            // https://www.rfc-editor.org/rfc/rfc9204.html#section-4.3.3
            let before = read.remaining();
            let mut buf = read.clone();
            let name =
                match prefix_string::decode_limited(6, &mut buf, self.max_encoded_string_size) {
                    Ok(name) => name,
                    Err(prefix_string::Error::UnexpectedEnd) => return Ok(None),
                    Err(error) => return Err(error.into()),
                };
            read.advance(before - buf.remaining());
            self.pending_literal_name = Some(name);
            return self.parse_pending_literal_value(read);
        }

        // Parse from a cloned cursor and advance the real cursor only after a
        // complete instruction is available.
        // https://www.rfc-editor.org/rfc/rfc9204.html#section-4.3
        let before = read.remaining();
        let mut buf = read.clone();
        let instruction = self.decode_instruction(&mut buf)?;
        if instruction.is_some() {
            read.advance(before - buf.remaining());
        }
        Ok(instruction)
    }

    fn parse_pending_literal_value<R: Buf + Clone>(
        &mut self,
        read: &mut R,
    ) -> Result<Option<Instruction>, DecoderError> {
        let before = read.remaining();
        let mut buf = read.clone();
        let value = match prefix_string::decode_limited(8, &mut buf, self.max_encoded_string_size) {
            Ok(value) => value,
            Err(prefix_string::Error::UnexpectedEnd) => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let Some(name) = self.pending_literal_name.take() else {
            return Err(DecoderError::UnexpectedEnd);
        };

        read.advance(before - buf.remaining());
        Ok(Some(Instruction::Insert(HeaderField::new(name, value))))
    }

    fn decode_instruction<R: Buf>(&self, buf: &mut R) -> Result<Option<Instruction>, DecoderError> {
        let first = buf.chunk()[0];
        let instruction = match EncoderInstruction::decode(first) {
            EncoderInstruction::Unknown => return Err(DecoderError::UnknownPrefix(first)),
            EncoderInstruction::DynamicTableSizeUpdate => {
                DynamicTableSizeUpdate::decode(&mut *buf)?
                    .map(|x| Instruction::TableSizeUpdate(x.0))
            }
            EncoderInstruction::InsertWithoutNameRef => {
                InsertWithoutNameRef::decode_limited(&mut *buf, self.max_encoded_string_size)?
                    .map(|x| Instruction::Insert(HeaderField::new(x.name, x.value)))
            }
            EncoderInstruction::Duplicate => match Duplicate::decode(&mut *buf)? {
                Some(Duplicate(index)) => {
                    Some(Instruction::Insert(self.table.get_relative(index)?.clone()))
                }
                None => None,
            },
            EncoderInstruction::InsertWithNameRef => {
                match InsertWithNameRef::decode_limited(&mut *buf, self.max_encoded_string_size)? {
                    Some(InsertWithNameRef::Static { index, value }) => Some(Instruction::Insert(
                        StaticTable::get(index)?.with_value(value),
                    )),
                    Some(InsertWithNameRef::Dynamic { index, value }) => Some(Instruction::Insert(
                        self.table.get_relative(index)?.with_value(value),
                    )),
                    None => None,
                }
            }
        };

        Ok(instruction)
    }

    fn parse_header_field<R: Buf>(
        table: &DynamicTableDecoder,
        buf: &mut R,
        max_encoded_string_size: usize,
    ) -> Result<HeaderField<'static>, DecoderError> {
        let first = buf.chunk()[0];
        let field = match HeaderBlockField::decode(first) {
            HeaderBlockField::Indexed => match Indexed::decode(buf)? {
                Indexed::Static(index) => StaticTable::get(index)?.clone(),
                Indexed::Dynamic(index) => table.get_relative(index)?.clone(),
            },
            HeaderBlockField::IndexedWithPostBase => {
                let index = IndexedWithPostBase::decode(buf)?.0;
                table.get_postbase(index)?.clone()
            }
            HeaderBlockField::LiteralWithNameRef => {
                match LiteralWithNameRef::decode_limited(buf, max_encoded_string_size)? {
                    LiteralWithNameRef::Static {
                        index,
                        value,
                        never_indexed,
                    } => StaticTable::get(index)?
                        .with_value(value)
                        .with_sensitive(never_indexed),
                    LiteralWithNameRef::Dynamic {
                        index,
                        value,
                        never_indexed,
                    } => table
                        .get_relative(index)?
                        .with_value(value)
                        .with_sensitive(never_indexed),
                }
            }
            HeaderBlockField::LiteralWithPostBaseNameRef => {
                let literal =
                    LiteralWithPostBaseNameRef::decode_limited(buf, max_encoded_string_size)?;
                table
                    .get_postbase(literal.index)?
                    .with_value(literal.value)
                    .with_sensitive(literal.never_indexed)
            }
            HeaderBlockField::Literal => {
                let literal = Literal::decode_limited(buf, max_encoded_string_size)?;
                HeaderField::new(literal.name, literal.value).with_sensitive(literal.never_indexed)
            }
            _ => return Err(DecoderError::UnknownPrefix(first)),
        };
        Ok(field)
    }
}

// Decode field lines received on a request or push stream.
// https://www.rfc-editor.org/rfc/rfc9204.html#section-4.5
pub fn decode_stateless<T: Buf>(buf: &mut T, max_size: u64) -> Result<Decoded, DecoderError> {
    decode_stateless_limited(buf, max_size, usize::MAX)
}

pub(crate) fn decode_stateless_limited<T: Buf>(
    buf: &mut T,
    max_size: u64,
    max_encoded_string_size: usize,
) -> Result<Decoded, DecoderError> {
    let (required_ref, _base) = HeaderPrefix::decode(buf)?.get(0, 0)?;

    if required_ref > 0 {
        return Err(DecoderError::MissingRefs(required_ref));
    }

    let mut mem_size = 0;
    let mut fields = Vec::new();
    while buf.has_remaining() {
        let field = match HeaderBlockField::decode(buf.chunk()[0]) {
            HeaderBlockField::IndexedWithPostBase => return Err(DecoderError::MissingRefs(0)),
            HeaderBlockField::LiteralWithPostBaseNameRef => {
                return Err(DecoderError::MissingRefs(0));
            }
            HeaderBlockField::Indexed => match Indexed::decode(buf)? {
                Indexed::Static(index) => StaticTable::get(index)?.clone(),
                Indexed::Dynamic(_) => return Err(DecoderError::MissingRefs(0)),
            },
            HeaderBlockField::LiteralWithNameRef => {
                match LiteralWithNameRef::decode_limited(buf, max_encoded_string_size)? {
                    LiteralWithNameRef::Dynamic { .. } => return Err(DecoderError::MissingRefs(0)),
                    LiteralWithNameRef::Static {
                        index,
                        value,
                        never_indexed,
                    } => StaticTable::get(index)?
                        .with_value(value)
                        .with_sensitive(never_indexed),
                }
            }
            HeaderBlockField::Literal => {
                let literal = Literal::decode_limited(buf, max_encoded_string_size)?;
                HeaderField::new(literal.name, literal.value).with_sensitive(literal.never_indexed)
            }
            _ => return Err(DecoderError::UnknownPrefix(buf.chunk()[0])),
        };
        mem_size += field.mem_size() as u64;
        // Cancel decoding if the header is considered too big
        if mem_size > max_size {
            return Err(DecoderError::HeaderTooLong(mem_size));
        }
        fields.push(field);
    }

    Ok(Decoded {
        fields,
        mem_size,
        dyn_ref: false,
    })
}

#[cfg(test)]
impl From<DynamicTable> for Decoder {
    fn from(table: DynamicTable) -> Self {
        let max_table_capacity = table.max_mem_size();
        Self {
            table,
            max_table_capacity,
            max_blocked_streams: 0,
            max_encoded_string_size: crate::config::DEFAULT_QPACK_DECODE_BUFFER_SIZE,
            pending_literal_name: None,
        }
    }
}

#[derive(PartialEq)]
enum Instruction {
    Insert(HeaderField<'static>),
    TableSizeUpdate(usize),
}

impl fmt::Debug for Instruction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Instruction::Insert(h) => write!(f, "Instruction::Insert {{ {} }}", h),
            Instruction::TableSizeUpdate(n) => {
                write!(f, "Instruction::TableSizeUpdate {{ {} }}", n)
            }
        }
    }
}

impl From<prefix_int::Error> for DecoderError {
    fn from(e: prefix_int::Error) -> Self {
        match e {
            prefix_int::Error::UnexpectedEnd => DecoderError::UnexpectedEnd,
            e => DecoderError::InvalidInteger(e),
        }
    }
}

impl From<prefix_string::Error> for DecoderError {
    fn from(e: prefix_string::Error) -> Self {
        match e {
            prefix_string::Error::UnexpectedEnd => DecoderError::UnexpectedEnd,
            e => DecoderError::InvalidString(e),
        }
    }
}

impl From<vas::Error> for DecoderError {
    fn from(e: vas::Error) -> Self {
        DecoderError::InvalidIndex(e)
    }
}

impl From<StaticError> for DecoderError {
    fn from(e: StaticError) -> Self {
        match e {
            StaticError::Unknown(i) => DecoderError::InvalidStaticIndex(i),
        }
    }
}

impl From<DynamicTableError> for DecoderError {
    fn from(e: DynamicTableError) -> Self {
        DecoderError::DynamicTable(e)
    }
}

impl From<ParseError> for DecoderError {
    fn from(e: ParseError) -> Self {
        match e {
            ParseError::Integer(x) => DecoderError::InvalidInteger(x),
            ParseError::String(x) => DecoderError::InvalidString(x),
            ParseError::InvalidPrefix(p) => DecoderError::UnknownPrefix(p),
            ParseError::InvalidBase {
                required_insert_count,
                sign_negative,
                delta_base,
            } => DecoderError::BadBaseIndex {
                required_insert_count,
                sign_negative,
                delta_base,
            },
            ParseError::InvalidRequiredInsertCount(i) => {
                DecoderError::InvalidRequiredInsertCount(i)
            }
        }
    }
}

impl From<TryFromIntError> for DecoderError {
    fn from(error: TryFromIntError) -> Self {
        DecoderError::BufSize(error)
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::*;
    use crate::{
        buf::BufList,
        qpack::tests::helpers::{TABLE_SIZE, build_table_with_size},
    };

    #[test]
    fn missing_refs_display_reports_required_insert_count() {
        assert_eq!(
            DecoderError::MissingRefs(100).to_string(),
            "field section requires insert count 100"
        );
    }

    #[test]
    fn test_header_too_long() {
        let mut trailers = http::HeaderMap::new();
        trailers.insert("trailer", "value".parse().unwrap());
        trailers.insert("trailer2", "value2".parse().unwrap());
        let mut buf = bytes::BytesMut::new();
        let _ = crate::qpack::encode_stateless(
            &mut buf,
            crate::proto::headers::Header::trailer(trailers),
        );
        let result = decode_stateless(&mut buf, 2);
        assert_eq!(result, Err(DecoderError::HeaderTooLong(44)));
    }

    #[test]
    fn dynamic_table_capacity_starts_at_zero() {
        let decoder = Decoder::new(128, 0).unwrap();

        assert!(decoder.dynamic_table_enabled());
        assert_eq!(decoder.table.max_mem_size(), 0);
    }

    #[cfg(target_pointer_width = "32")]
    #[test]
    fn decoder_rejects_capacity_larger_than_the_address_space() {
        let capacity = u64::from(u32::MAX) + 1;

        assert!(matches!(
            Decoder::new(capacity, 0),
            Err(DecoderError::BufSize(_))
        ));
    }

    #[test]
    fn blocked_stream_limit_accepts_full_settings_range() {
        let max = crate::proto::varint::VarInt::MAX.into_inner();
        let decoder = Decoder::new(0, max).unwrap();

        assert_eq!(decoder.max_blocked_streams(), max);
    }

    #[test]
    fn insert_before_capacity_update_is_rejected() {
        let mut encoder_stream = Vec::new();
        InsertWithoutNameRef::new("key", "value")
            .encode(&mut encoder_stream)
            .unwrap();
        let mut decoder = Decoder::new(128, 0).unwrap();

        assert_eq!(
            decoder.on_encoder_recv(&mut Cursor::new(encoder_stream), &mut Vec::new()),
            Err(DecoderError::DynamicTable(
                DynamicTableError::MaxTableSizeReached
            ))
        );
    }

    #[test]
    fn capacity_update_cannot_exceed_advertised_maximum() {
        let mut encoder_stream = Vec::new();
        DynamicTableSizeUpdate(129).encode(&mut encoder_stream);
        let mut decoder = Decoder::new(128, 0).unwrap();

        assert_eq!(
            decoder.on_encoder_recv(&mut Cursor::new(encoder_stream), &mut Vec::new()),
            Err(DecoderError::DynamicTable(
                DynamicTableError::MaximumTableSizeTooLarge
            ))
        );
    }

    #[test]
    fn cumulative_insert_limit_rejects_encoder_instruction_without_mutation() {
        let mut table = DynamicTable::new();
        table.set_max_size(64).unwrap();
        table.set_empty_insert_count_for_test(usize::MAX);
        let mut decoder = Decoder::from(table);
        let mut encoder_stream = Vec::new();
        InsertWithoutNameRef::new("name", "value")
            .encode(&mut encoder_stream)
            .unwrap();

        assert_eq!(
            decoder.on_encoder_recv(&mut Cursor::new(encoder_stream), &mut Vec::new()),
            Err(DecoderError::DynamicTable(
                DynamicTableError::AddressSpaceOverflow
            ))
        );
        assert_eq!(decoder.table.total_inserted(), usize::MAX);
    }

    #[test]
    fn zero_capacity_update_is_tolerated_when_advertised_maximum_is_zero() {
        let mut encoder_stream = Vec::new();
        DynamicTableSizeUpdate(0).encode(&mut encoder_stream);
        let mut decoder = Decoder::new(0, 0).unwrap();
        let mut decoder_stream = Vec::new();

        // Section 3.2.3 says an encoder must send no instructions when the
        // advertised maximum is zero. A zero-capacity update is valid syntax and
        // leaves the table at zero, so the decoder accepts it for interoperability.
        // https://www.rfc-editor.org/rfc/rfc9204.html#section-3.2.3
        // https://www.rfc-editor.org/rfc/rfc9204.html#section-4.3.1
        assert_eq!(
            decoder.on_encoder_recv(&mut Cursor::new(encoder_stream), &mut decoder_stream),
            Ok(0)
        );
        assert_eq!(decoder.table.max_mem_size(), 0);
        assert!(decoder_stream.is_empty());
    }

    #[test]
    fn encoder_instruction_can_span_receive_chunks() {
        let mut encoder_stream = Vec::new();
        DynamicTableSizeUpdate(128).encode(&mut encoder_stream);
        InsertWithoutNameRef::new("key", "value")
            .encode(&mut encoder_stream)
            .unwrap();
        let encoded_len = encoder_stream.len();

        let mut fragments = BufList::new();
        for byte in encoder_stream {
            fragments.push(Bytes::from(vec![byte]));
        }

        let mut read = fragments.cursor();
        let mut decoder = Decoder::new(128, 0).unwrap();
        let mut decoder_stream = Vec::new();

        assert_eq!(
            decoder.on_encoder_recv_buffered(&mut read, &mut decoder_stream),
            Ok(1)
        );
        assert_eq!(read.position(), encoded_len);
        assert_eq!(
            InsertCountIncrement::decode(&mut Cursor::new(decoder_stream)),
            Ok(Some(InsertCountIncrement(1)))
        );
    }

    #[test]
    fn incomplete_literal_value_preserves_decoded_name() {
        let mut capacity_update = Vec::new();
        DynamicTableSizeUpdate(128).encode(&mut capacity_update);
        let capacity_update_len = capacity_update.len();

        let mut insertion = Vec::new();
        InsertWithoutNameRef::new("key", "value")
            .encode(&mut insertion)
            .unwrap();
        let encoded_name_len = {
            let mut read = Cursor::new(&insertion);
            let _ = prefix_string::decode(6, &mut read).unwrap();
            usize::try_from(read.position()).unwrap()
        };
        let final_byte = insertion.pop().unwrap();

        let mut fragments = BufList::new();
        for byte in capacity_update.into_iter().chain(insertion) {
            fragments.push(Bytes::from(vec![byte]));
        }

        let mut decoder = Decoder::new(128, 0).unwrap();
        let mut decoder_stream = Vec::new();
        let consumed = {
            let mut read = fragments.cursor();
            assert_eq!(
                decoder.on_encoder_recv_buffered(&mut read, &mut decoder_stream),
                Ok(0)
            );
            read.position()
        };
        assert_eq!(consumed, capacity_update_len + encoded_name_len);
        assert_eq!(decoder.pending_literal_name.as_deref(), Some(&b"key"[..]));

        // The name bytes can be released immediately. The decoder keeps the
        // decoded name until the final value byte arrives.
        // https://www.rfc-editor.org/rfc/rfc9204.html#section-4.3.3
        fragments.advance(consumed);
        fragments.push(Bytes::from(vec![final_byte]));
        let remaining = fragments.remaining();
        let mut read = fragments.cursor();
        assert_eq!(
            decoder.on_encoder_recv_buffered(&mut read, &mut decoder_stream),
            Ok(1)
        );
        assert_eq!(read.position(), remaining);
        assert!(decoder.pending_literal_name.is_none());
        assert_eq!(decoder.table.max_mem_size(), 128);
    }

    #[test]
    fn decoder_reports_large_insert_count_increment() {
        const INSERTIONS: usize = 256;
        const ENTRY_SIZE: usize = 32;

        let mut encoder_stream = Vec::new();
        DynamicTableSizeUpdate(INSERTIONS * ENTRY_SIZE).encode(&mut encoder_stream);
        for _ in 0..INSERTIONS {
            InsertWithoutNameRef::new("", "")
                .encode(&mut encoder_stream)
                .unwrap();
        }

        let mut decoder = Decoder::new((INSERTIONS * ENTRY_SIZE) as u64, 0).unwrap();
        let mut decoder_stream = Vec::new();

        assert_eq!(
            decoder.on_encoder_recv(&mut Cursor::new(encoder_stream), &mut decoder_stream),
            Ok(INSERTIONS)
        );
        let mut decoder_stream = Cursor::new(decoder_stream);
        assert_eq!(
            InsertCountIncrement::decode(&mut decoder_stream),
            Ok(Some(InsertCountIncrement(INSERTIONS)))
        );
        assert!(!decoder_stream.has_remaining());
    }

    #[test]
    fn required_insert_count_uses_advertised_capacity() {
        let mut field_section = Vec::new();
        HeaderPrefix::new(8, 8, 10, TABLE_SIZE).encode(&mut field_section);
        let decoder = Decoder::new(TABLE_SIZE as u64, 0).unwrap();

        assert_eq!(
            decoder.decode_header(&mut Cursor::new(field_section)),
            Err(DecoderError::MissingRefs(8))
        );
    }

    #[test]
    fn dynamic_reference_cannot_exceed_required_insert_count() {
        let mut field_section = Vec::new();
        HeaderPrefix::new(2, 4, 4, TABLE_SIZE).encode(&mut field_section);
        Indexed::Dynamic(0).encode(&mut field_section);
        let decoder = Decoder::from(build_table_with_size(4));

        assert_eq!(
            decoder.decode_header(&mut Cursor::new(field_section)),
            Err(DecoderError::DynamicTable(
                DynamicTableError::BadRelativeIndex(0)
            ))
        );
    }

    /**
     * https://www.rfc-editor.org/rfc/rfc9204.html#section-4.3.2
     * 4.3.2.  Insert With Name Reference
     */
    #[test]
    fn test_insert_field_with_name_ref_into_dynamic_table() {
        let mut buf = vec![];
        InsertWithNameRef::new_static(1, "serial value")
            .encode(&mut buf)
            .unwrap();
        let mut decoder = Decoder::from(build_table_with_size(0));
        let mut enc = Cursor::new(&buf);
        let mut dec = vec![];
        assert!(decoder.on_encoder_recv(&mut enc, &mut dec).is_ok());

        assert_eq!(
            decoder.table.decoder(1, 1).get_relative(0),
            Ok(&StaticTable::get(1).unwrap().with_value("serial value"))
        );

        let mut dec_cursor = Cursor::new(&dec);
        assert_eq!(
            InsertCountIncrement::decode(&mut dec_cursor),
            Ok(Some(InsertCountIncrement(1)))
        );
    }

    /**
     * https://www.rfc-editor.org/rfc/rfc9204.html#section-4.3.2
     * 4.3.2.  Insert With Name Reference
     */
    #[test]
    fn test_insert_field_with_wrong_name_index_from_static_table() {
        let mut buf = vec![];
        InsertWithNameRef::new_static(3000, "")
            .encode(&mut buf)
            .unwrap();
        let mut enc = Cursor::new(&buf);
        let mut decoder = Decoder::from(build_table_with_size(0));
        let res = decoder.on_encoder_recv(&mut enc, &mut vec![]);
        assert_eq!(res, Err(DecoderError::InvalidStaticIndex(3000)));
    }

    /**
     * https://www.rfc-editor.org/rfc/rfc9204.html#section-4.3.2
     * 4.3.2.  Insert With Name Reference
     */
    #[test]
    fn test_insert_field_with_wrong_name_index_from_dynamic_table() {
        let mut buf = vec![];
        InsertWithNameRef::new_dynamic(3000, "")
            .encode(&mut buf)
            .unwrap();
        let mut enc = Cursor::new(&buf);
        let mut dec = vec![];
        let mut decoder = Decoder::from(build_table_with_size(0));
        let res = decoder.on_encoder_recv(&mut enc, &mut dec);
        assert_eq!(
            res,
            Err(DecoderError::DynamicTable(
                DynamicTableError::BadRelativeIndex(3000)
            ))
        );

        assert!(dec.is_empty());
    }

    /**
     * https://www.rfc-editor.org/rfc/rfc9204.html#section-4.3.3
     * 4.3.3.  Insert with Literal Name
     */
    #[test]
    fn test_insert_field_without_name_ref() {
        let mut buf = vec![];
        InsertWithoutNameRef::new("key", "value")
            .encode(&mut buf)
            .unwrap();

        let mut decoder = Decoder::from(build_table_with_size(0));
        let mut enc = Cursor::new(&buf);
        let mut dec = vec![];
        assert!(decoder.on_encoder_recv(&mut enc, &mut dec).is_ok());

        assert_eq!(
            decoder.table.decoder(1, 1).get_relative(0),
            Ok(&HeaderField::new("key", "value"))
        );

        let mut dec_cursor = Cursor::new(&dec);
        assert_eq!(
            InsertCountIncrement::decode(&mut dec_cursor),
            Ok(Some(InsertCountIncrement(1)))
        );
    }

    fn insert_fields(table: &mut DynamicTable, fields: Vec<HeaderField<'static>>) {
        for field in fields {
            table.put(field).unwrap();
        }
    }

    /**
     * https://www.rfc-editor.org/rfc/rfc9204.html#section-4.3.4
     * 4.3.4.  Duplicate
     */
    #[test]
    fn test_duplicate_field() {
        // let mut table = build_table_with_size(0);
        let mut table = build_table_with_size(0);
        insert_fields(
            &mut table,
            vec![HeaderField::new("", ""), HeaderField::new("", "")],
        );
        let mut decoder = Decoder::from(table);

        let mut buf = vec![];
        Duplicate(1).encode(&mut buf);

        let mut enc = Cursor::new(&buf);
        let mut dec = vec![];
        let res = decoder.on_encoder_recv(&mut enc, &mut dec);
        assert_eq!(res, Ok(3));

        let mut dec_cursor = Cursor::new(&dec);
        assert_eq!(
            InsertCountIncrement::decode(&mut dec_cursor),
            Ok(Some(InsertCountIncrement(1)))
        );
    }

    /**
     * https://www.rfc-editor.org/rfc/rfc9204.html#section-4.3.1
     * 4.3.1.  Set Dynamic Table Capacity
     */
    #[test]
    fn test_dynamic_table_size_update() {
        let mut buf = vec![];
        DynamicTableSizeUpdate(25).encode(&mut buf);

        let mut enc = Cursor::new(&buf);
        let mut dec = vec![];
        let mut decoder = Decoder::from(build_table_with_size(0));
        let res = decoder.on_encoder_recv(&mut enc, &mut dec);
        assert_eq!(res, Ok(0));

        let actual_max_size = decoder.table.max_mem_size();
        assert_eq!(actual_max_size, 25);
        assert!(dec.is_empty());
    }

    #[test]
    fn enc_recv_buf_too_short() {
        let mut decoder = Decoder::from(build_table_with_size(0));
        let mut buf = vec![];
        {
            let mut enc = Cursor::new(&buf);
            assert_eq!(decoder.parse_instruction(&mut enc), Ok(None));
        }

        buf.push(0b1000_0000);
        let mut enc = Cursor::new(&buf);
        assert_eq!(decoder.parse_instruction(&mut enc), Ok(None));
    }

    #[test]
    fn enc_recv_accepts_truncated_messages() {
        let mut buf = vec![];
        InsertWithoutNameRef::new("keyfoobarbaz", "value")
            .encode(&mut buf)
            .unwrap();

        let mut decoder = Decoder::from(build_table_with_size(0));
        // cut in middle of the first int
        let mut enc = Cursor::new(&buf[..2]);
        let mut dec = vec![];
        assert!(decoder.on_encoder_recv(&mut enc, &mut dec).is_ok());
        assert_eq!(enc.position(), 0);

        // cut the last byte of the 2nd string
        let mut enc = Cursor::new(&buf[..buf.len() - 1]);
        let mut dec = vec![];
        assert!(decoder.on_encoder_recv(&mut enc, &mut dec).is_ok());
        assert_eq!(enc.position(), 0);

        InsertWithoutNameRef::new("keyfoobarbaz2", "value")
            .encode(&mut buf)
            .unwrap();

        // the first valid field is inserted and buf is left at the first byte of incomplete string
        let mut enc = Cursor::new(&buf[..buf.len() - 1]);
        let mut dec = vec![];
        assert!(decoder.on_encoder_recv(&mut enc, &mut dec).is_ok());
        assert_eq!(enc.position(), 15);

        let mut dec_cursor = Cursor::new(&dec);
        assert_eq!(
            InsertCountIncrement::decode(&mut dec_cursor),
            Ok(Some(InsertCountIncrement(1)))
        );
    }

    #[test]
    fn largest_ref_too_big() {
        let decoder = Decoder::from(build_table_with_size(0));
        let mut buf = vec![];
        HeaderPrefix::new(8, 8, 10, TABLE_SIZE).encode(&mut buf);

        let mut read = Cursor::new(&buf);
        assert_eq!(
            decoder.decode_header(&mut read),
            Err(DecoderError::MissingRefs(8))
        );
    }

    #[test]
    fn static_field_section_has_no_dynamic_reference() {
        let mut buf = vec![];
        HeaderPrefix::new(0, 0, 0, TABLE_SIZE).encode(&mut buf);
        Indexed::Static(18).encode(&mut buf);

        let decoder = Decoder::from(build_table_with_size(0));
        let decoded = decoder.decode_header(&mut Cursor::new(buf)).unwrap();

        assert!(!decoded.dyn_ref);
    }

    fn field(n: usize) -> HeaderField<'static> {
        HeaderField::new(format!("foo{}", n), "bar")
    }

    // Required Insert Count and Base are both 2. Relative indices 0 and 1
    // select foo2 (absolute index 1) and foo1 (absolute index 0), respectively.
    // https://www.rfc-editor.org/rfc/rfc9204.html#section-3.2.5

    #[test]
    fn decode_indexed_header_field() {
        let mut buf = vec![];
        HeaderPrefix::new(2, 2, 2, TABLE_SIZE).encode(&mut buf);
        Indexed::Dynamic(0).encode(&mut buf);
        Indexed::Dynamic(1).encode(&mut buf);
        Indexed::Static(18).encode(&mut buf);

        let mut read = Cursor::new(&buf);
        let decoder = Decoder::from(build_table_with_size(2));
        let Decoded {
            fields, dyn_ref, ..
        } = decoder.decode_header(&mut read).unwrap();
        assert!(dyn_ref);
        assert_eq!(
            fields,
            &[field(2), field(1), StaticTable::get(18).unwrap().clone()]
        )
    }

    // With Base 2, relative index 0 selects foo2 (absolute index 1), while
    // post-base indices 0 and 1 select foo3 and foo4 (absolute indices 2 and 3).
    // https://www.rfc-editor.org/rfc/rfc9204.html#section-3.2.5
    // https://www.rfc-editor.org/rfc/rfc9204.html#section-3.2.6

    #[test]
    fn decode_post_base_indexed() {
        let mut buf = vec![];
        HeaderPrefix::new(4, 2, 4, TABLE_SIZE).encode(&mut buf);
        Indexed::Dynamic(0).encode(&mut buf);
        IndexedWithPostBase(0).encode(&mut buf);
        IndexedWithPostBase(1).encode(&mut buf);

        let mut read = Cursor::new(&buf);
        let decoder = Decoder::from(build_table_with_size(4));
        let Decoded {
            fields, dyn_ref, ..
        } = decoder.decode_header(&mut read).unwrap();
        assert!(dyn_ref);
        assert_eq!(fields, &[field(2), field(3), field(4)])
    }

    #[test]
    fn decode_name_ref_header_field() {
        let mut buf = vec![];
        HeaderPrefix::new(2, 2, 4, TABLE_SIZE).encode(&mut buf);
        LiteralWithNameRef::new_dynamic(1, "new bar1")
            .encode(&mut buf)
            .unwrap();
        LiteralWithNameRef::new_static(18, "PUT")
            .encode(&mut buf)
            .unwrap();

        let mut read = Cursor::new(&buf);
        let decoder = Decoder::from(build_table_with_size(4));
        let Decoded {
            fields, dyn_ref, ..
        } = decoder.decode_header(&mut read).unwrap();
        assert!(dyn_ref);
        assert_eq!(
            fields,
            &[
                field(1).with_value("new bar1"),
                StaticTable::get(18).unwrap().with_value("PUT")
            ]
        )
    }

    #[test]
    fn decode_post_base_name_ref_header_field() {
        let mut buf = vec![];
        // Base 2 and post-base index 0 refer to the third insertion, whose
        // absolute index is 2. The Required Insert Count must cover it.
        // https://www.rfc-editor.org/rfc/rfc9204.html#section-4.5.1.1
        // https://www.rfc-editor.org/rfc/rfc9204.html#section-4.5.5
        HeaderPrefix::new(3, 2, 4, TABLE_SIZE).encode(&mut buf);
        LiteralWithPostBaseNameRef::new(0, "new bar3")
            .encode(&mut buf)
            .unwrap();

        let mut read = Cursor::new(&buf);
        let decoder = Decoder::from(build_table_with_size(4));
        let Decoded { fields, .. } = decoder.decode_header(&mut read).unwrap();
        assert_eq!(fields, &[field(3).with_value("new bar3")]);
    }

    #[test]
    fn reject_post_base_name_ref_past_required_insert_count() {
        let mut buf = vec![];
        // Required Insert Count 2 does not cover the third insertion (absolute
        // index 2), which post-base index 0 selects from Base 2.
        // https://www.rfc-editor.org/rfc/rfc9204.html#section-4.5.1.1
        // https://www.rfc-editor.org/rfc/rfc9204.html#section-4.5.5
        HeaderPrefix::new(2, 2, 4, TABLE_SIZE).encode(&mut buf);
        LiteralWithPostBaseNameRef::new(0, "new bar3")
            .encode(&mut buf)
            .unwrap();

        let mut read = Cursor::new(&buf);
        let decoder = Decoder::from(build_table_with_size(4));
        assert_eq!(
            decoder.decode_header(&mut read),
            Err(DecoderError::DynamicTable(
                DynamicTableError::BadPostbaseIndex(0)
            ))
        );
    }

    #[test]
    fn decode_without_name_ref_header_field() {
        let mut buf = vec![];
        HeaderPrefix::new(0, 0, 0, TABLE_SIZE).encode(&mut buf);
        Literal::new("foo", "bar").encode(&mut buf).unwrap();

        let mut read = Cursor::new(&buf);
        let decoder = Decoder::from(build_table_with_size(0));
        let Decoded { fields, .. } = decoder.decode_header(&mut read).unwrap();
        assert_eq!(
            fields,
            &[HeaderField::new(b"foo".to_vec(), b"bar".to_vec())]
        );
    }

    #[test]
    fn field_section_rejects_oversized_encoded_string_from_length_prefix() {
        let mut field_section = Vec::new();
        HeaderPrefix::new(0, 0, 0, 0).encode(&mut field_section);
        field_section.extend_from_slice(&[0b0101_0000, 5]);

        let mut decoder = Decoder::new(0, 0).unwrap();
        decoder.set_max_encoded_string_size(4);
        assert_eq!(
            decoder.decode_header(&mut Cursor::new(field_section)),
            Err(DecoderError::InvalidString(
                prefix_string::Error::EncodedStringTooLong { len: 5, limit: 4 }
            ))
        );
    }

    #[test]
    fn malformed_huffman_maps_to_each_qpack_input_error_path() {
        let mut field_section = Vec::new();
        HeaderPrefix::new(0, 0, 0, 0).encode(&mut field_section);
        field_section.extend_from_slice(&[0b0101_0000, 0b1000_0100, 0xff, 0xff, 0xff, 0xff]);
        assert_eq!(
            Decoder::new(0, 0)
                .unwrap()
                .decode_header(&mut Cursor::new(field_section)),
            Err(DecoderError::InvalidString(
                prefix_string::Error::HuffmanDecoding(prefix_string::HuffmanDecodingError::Eos)
            ))
        );

        let encoder_stream = [0b1100_0000, 0b1000_0100, 0xff, 0xff, 0xff, 0xff];
        assert_eq!(
            Decoder::new(0, 0)
                .unwrap()
                .on_encoder_recv(&mut Cursor::new(encoder_stream), &mut Vec::new(),),
            Err(DecoderError::InvalidString(
                prefix_string::Error::HuffmanDecoding(prefix_string::HuffmanDecodingError::Eos)
            ))
        );
    }

    #[test]
    fn encoder_stream_rejects_oversized_string_from_length_prefix() {
        let mut decoder = Decoder::new(0, 0).unwrap();
        decoder.set_max_encoded_string_size(1);

        assert_eq!(
            decoder.on_encoder_recv_buffered(&mut Cursor::new([0b0100_0010]), &mut Vec::new(),),
            Err(DecoderError::InvalidString(
                prefix_string::Error::EncodedStringTooLong { len: 2, limit: 1 }
            ))
        );
    }

    // With Base 0, post-base indices 0 through 3 select foo1 through foo4,
    // whose absolute indices are 0 through 3.
    // https://www.rfc-editor.org/rfc/rfc9204.html#section-3.2.6

    #[test]
    fn decode_single_pass_encoded() {
        let mut buf = vec![];
        HeaderPrefix::new(4, 0, 4, TABLE_SIZE).encode(&mut buf);
        IndexedWithPostBase(0).encode(&mut buf);
        IndexedWithPostBase(1).encode(&mut buf);
        IndexedWithPostBase(2).encode(&mut buf);
        IndexedWithPostBase(3).encode(&mut buf);

        let mut read = Cursor::new(&buf);
        let decoder = Decoder::from(build_table_with_size(4));
        let Decoded { fields, .. } = decoder.decode_header(&mut read).unwrap();
        assert_eq!(fields, &[field(1), field(2), field(3), field(4)]);
    }

    #[test]
    fn largest_ref_greater_than_max_entries() {
        let max_entries = TABLE_SIZE / 32;
        // some fields evicted
        let table = build_table_with_size(max_entries + 10);
        let mut buf = vec![];

        // Pre-base relative reference
        HeaderPrefix::new(
            max_entries + 5,
            max_entries + 5,
            max_entries + 10,
            TABLE_SIZE,
        )
        .encode(&mut buf);
        Indexed::Dynamic(10).encode(&mut buf);

        let mut read = Cursor::new(&buf);
        let decoder = Decoder::from(build_table_with_size(max_entries + 10));
        let Decoded { fields, .. } = decoder.decode_header(&mut read).expect("decode");
        assert_eq!(fields, &[field(max_entries - 5)]);

        let mut buf = vec![];

        // Post-base reference
        HeaderPrefix::new(
            max_entries + 10,
            max_entries + 5,
            max_entries + 10,
            TABLE_SIZE,
        )
        .encode(&mut buf);
        IndexedWithPostBase(0).encode(&mut buf);
        IndexedWithPostBase(4).encode(&mut buf);

        let mut read = Cursor::new(&buf);
        let decoder = Decoder::from(table);
        let Decoded { fields, .. } = decoder.decode_header(&mut read).unwrap();
        assert_eq!(fields, &[field(max_entries + 6), field(max_entries + 10)]);
    }
}
