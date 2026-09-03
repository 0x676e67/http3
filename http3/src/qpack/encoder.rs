use std::{cmp, io::Cursor};

use bytes::{Buf, BufMut};

use super::{
    HeaderField,
    block::{
        HeaderPrefix, Indexed, IndexedWithPostBase, Literal, LiteralWithNameRef,
        LiteralWithPostBaseNameRef,
    },
    dynamic::{
        DynamicInsertionResult, DynamicLookupResult, DynamicTable, DynamicTableEncoder,
        Error as DynamicTableError,
    },
    parse_error::ParseError,
    prefix_int::Error as IntError,
    prefix_string::Error as StringError,
    static_::StaticTable,
    stream::{
        DecoderInstruction, Duplicate, DynamicTableSizeUpdate, HeaderAck, InsertCountIncrement,
        InsertWithNameRef, InsertWithoutNameRef, StreamCancel,
    },
};
use crate::quic::StreamId;

#[derive(Debug, PartialEq)]
pub enum EncoderError {
    Insertion(DynamicTableError),
    InvalidString(StringError),
    InvalidInteger(IntError),
    InvalidStreamId(u64),
    MalformedDecoderInstruction,
    UnknownDecoderInstruction(u8),
}

impl std::error::Error for EncoderError {}

impl std::fmt::Display for EncoderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EncoderError::Insertion(e) => write!(f, "dynamic table insertion: {:?}", e),
            EncoderError::InvalidString(e) => write!(f, "could not parse string: {}", e),
            EncoderError::InvalidInteger(e) => write!(f, "could not parse integer: {}", e),
            EncoderError::InvalidStreamId(stream_id) => {
                write!(f, "invalid stream ID in decoder instruction: {stream_id}")
            }
            EncoderError::MalformedDecoderInstruction => {
                write!(f, "malformed decoder instruction")
            }
            EncoderError::UnknownDecoderInstruction(e) => {
                write!(f, "got unknown decoder instruction: {}", e)
            }
        }
    }
}

pub struct Encoder {
    table: DynamicTable,
}

impl Encoder {
    pub fn encode<W, T, H>(
        &mut self,
        stream_id: u64,
        block: &mut W,
        encoder_buf: &mut W,
        fields: T,
    ) -> Result<usize, EncoderError>
    where
        W: BufMut,
        T: IntoIterator<Item = H>,
        H: AsRef<HeaderField<'static>>,
    {
        let mut required_ref = 0;
        let mut block_buf = Vec::new();
        let mut encoder = self.table.encoder(stream_id);

        for field in fields {
            if let Some(reference) =
                Self::encode_field(&mut encoder, &mut block_buf, encoder_buf, field.as_ref())?
            {
                required_ref = cmp::max(required_ref, reference);
            }
        }

        HeaderPrefix::new(
            required_ref,
            encoder.base(),
            encoder.total_inserted(),
            encoder.max_size(),
        )
        .encode(block);
        block.put(block_buf.as_slice());

        encoder.commit(required_ref);

        Ok(required_ref)
    }

    /// Applies instructions received on the peer's QPACK decoder stream.
    ///
    /// A trailing incomplete instruction remains unread for the next call.
    ///
    /// See [RFC 9204, Section 4.4](https://www.rfc-editor.org/rfc/rfc9204.html#section-4.4).
    pub fn on_decoder_recv<R: Buf>(&mut self, read: &mut R) -> Result<(), EncoderError> {
        self.on_decoder_recv_with(read, Action::parse)
    }

    /// Applies decoder instructions through a checkpointable receive cursor.
    ///
    /// This path allows one instruction to span transport buffers without
    /// coalescing them. Input advances only after a complete instruction has
    /// been parsed.
    ///
    /// See [RFC 9204, Section 4.4](https://www.rfc-editor.org/rfc/rfc9204.html#section-4.4).
    pub(crate) fn on_decoder_recv_buffered<R: Buf + Clone>(
        &mut self,
        read: &mut R,
    ) -> Result<(), EncoderError> {
        self.on_decoder_recv_with(read, Action::parse_buffered)
    }

    fn on_decoder_recv_with<R: Buf>(
        &mut self,
        read: &mut R,
        parse: impl Fn(&mut R) -> Result<Option<Action>, EncoderError>,
    ) -> Result<(), EncoderError> {
        while let Some(instruction) = parse(read)? {
            match instruction {
                Action::Untrack(stream_id) => {
                    self.table.acknowledge_section(stream_id.into_inner())?
                }
                Action::StreamCancel(stream_id) => {
                    self.table.cancel_stream(stream_id.into_inner())?;
                }
                Action::ReceivedRefIncrement(increment) => {
                    self.table.update_largest_received(increment)?
                }
            }
        }
        Ok(())
    }

    fn encode_field<W: BufMut>(
        table: &mut DynamicTableEncoder,
        block: &mut Vec<u8>,
        encoder: &mut W,
        field: &HeaderField<'static>,
    ) -> Result<Option<usize>, EncoderError> {
        if field.is_sensitive() {
            return Self::encode_sensitive_field(table, block, field);
        }

        if let Some(index) = StaticTable::find(field) {
            Indexed::Static(index).encode(block);
            return Ok(None);
        }

        if let DynamicLookupResult::Relative { index, absolute } = table.find(field) {
            Indexed::Dynamic(index).encode(block);
            return Ok(Some(absolute));
        }

        let reference = match table.insert(field)? {
            DynamicInsertionResult::Duplicated {
                relative,
                postbase,
                absolute,
            } => {
                Duplicate(relative).encode(encoder);
                IndexedWithPostBase(postbase).encode(block);
                Some(absolute)
            }
            DynamicInsertionResult::Inserted { postbase, absolute } => {
                InsertWithoutNameRef::new(field.name.clone(), field.value.clone())
                    .encode(encoder)?;
                IndexedWithPostBase(postbase).encode(block);
                Some(absolute)
            }
            DynamicInsertionResult::InsertedWithStaticNameRef {
                postbase,
                index,
                absolute,
            } => {
                InsertWithNameRef::new_static(index, field.value.clone()).encode(encoder)?;
                IndexedWithPostBase(postbase).encode(block);
                Some(absolute)
            }
            DynamicInsertionResult::InsertedWithNameRef {
                postbase,
                relative,
                absolute,
            } => {
                InsertWithNameRef::new_dynamic(relative, field.value.clone()).encode(encoder)?;
                IndexedWithPostBase(postbase).encode(block);
                Some(absolute)
            }
            DynamicInsertionResult::NotInserted(lookup_result) => match lookup_result {
                DynamicLookupResult::Static(index) => {
                    LiteralWithNameRef::new_static(index, field.value.clone()).encode(block)?;
                    None
                }
                DynamicLookupResult::Relative { index, absolute } => {
                    LiteralWithNameRef::new_dynamic(index, field.value.clone()).encode(block)?;
                    Some(absolute)
                }
                DynamicLookupResult::PostBase { index, absolute } => {
                    LiteralWithPostBaseNameRef::new(index, field.value.clone()).encode(block)?;
                    Some(absolute)
                }
                DynamicLookupResult::NotFound => {
                    Literal::new(field.name.clone(), field.value.clone()).encode(block)?;
                    None
                }
            },
        };
        Ok(reference)
    }

    fn encode_sensitive_field(
        table: &mut DynamicTableEncoder,
        block: &mut Vec<u8>,
        field: &HeaderField<'static>,
    ) -> Result<Option<usize>, EncoderError> {
        // The N bit forbids an indexed field line and dynamic-table insertion.
        // A name reference is still a literal representation and can be used.
        // https://www.rfc-editor.org/rfc/rfc9204.html#section-4.5.4
        let reference = match table.find_name(&field.name) {
            DynamicLookupResult::Static(index) => {
                LiteralWithNameRef::new_static(index, field.value.clone())
                    .with_never_indexed()
                    .encode(block)?;
                None
            }
            DynamicLookupResult::Relative { index, absolute } => {
                LiteralWithNameRef::new_dynamic(index, field.value.clone())
                    .with_never_indexed()
                    .encode(block)?;
                Some(absolute)
            }
            DynamicLookupResult::PostBase { index, absolute } => {
                LiteralWithPostBaseNameRef::new(index, field.value.clone())
                    .with_never_indexed()
                    .encode(block)?;
                Some(absolute)
            }
            DynamicLookupResult::NotFound => {
                Literal::new(field.name.clone(), field.value.clone())
                    .with_never_indexed()
                    .encode(block)?;
                None
            }
        };
        Ok(reference)
    }
}

impl Default for Encoder {
    fn default() -> Self {
        Self {
            table: DynamicTable::new(),
        }
    }
}

/// Encodes a field section without dynamic-table references.
///
/// The returned value is the uncompressed field section size, including the
/// 32-byte overhead defined for each field by
/// [HTTP/3](https://www.rfc-editor.org/rfc/rfc9114.html#section-4.1.1).
///
/// # Errors
///
/// Returns an error if a field cannot be represented by the QPACK encoder.
pub fn encode_stateless<'a, W, T, H>(block: &mut W, fields: T) -> Result<u64, EncoderError>
where
    W: BufMut,
    T: IntoIterator<Item = H>,
    H: AsRef<HeaderField<'a>>,
{
    let mut size = 0;

    HeaderPrefix::new(0, 0, 0, 0).encode(block);
    for field in fields {
        let field = field.as_ref();
        encode_stateless_parts(block, &field.name, &field.value, field.is_sensitive())?;
        size += field.mem_size() as u64;
    }
    Ok(size)
}

#[inline]
fn encode_stateless_parts<W: BufMut>(
    block: &mut W,
    name: &[u8],
    value: &[u8],
    sensitive: bool,
) -> Result<(), EncoderError> {
    if sensitive {
        if let Some(index) = StaticTable::find_name(name) {
            LiteralWithNameRef::encode_parts(index, value, true, true, block)?;
        } else {
            Literal::encode_parts(name, value, true, block)?;
        }
    } else if let Some(index) = StaticTable::find_parts(name, value) {
        Indexed::Static(index).encode(block);
    } else if let Some(index) = StaticTable::find_name(name) {
        LiteralWithNameRef::encode_parts(index, value, false, true, block)?;
    } else {
        Literal::encode_parts(name, value, false, block)?;
    }
    Ok(())
}

#[cfg(test)]
impl From<DynamicTable> for Encoder {
    fn from(table: DynamicTable) -> Encoder {
        Encoder { table }
    }
}

// Action to apply to the encoder table, given an instruction received from the decoder.
#[derive(Debug, PartialEq)]
enum Action {
    ReceivedRefIncrement(usize),
    Untrack(StreamId),
    StreamCancel(StreamId),
}

impl Action {
    fn stream_id(value: u64) -> Result<StreamId, EncoderError> {
        // Section Acknowledgment and Stream Cancellation carry a QUIC Stream
        // ID, whose wire range is limited to 62 bits.
        // https://www.rfc-editor.org/rfc/rfc9204.html#section-4.4.1
        // https://www.rfc-editor.org/rfc/rfc9204.html#section-4.4.2
        // https://www.rfc-editor.org/rfc/rfc9000.html#section-2.1
        StreamId::try_from(value).map_err(|_| EncoderError::InvalidStreamId(value))
    }

    fn parse<R: Buf>(read: &mut R) -> Result<Option<Action>, EncoderError> {
        if read.remaining() < 1 {
            return Ok(None);
        }

        let mut buf = Cursor::new(read.chunk());
        let instruction = Self::decode(&mut buf)?;

        if instruction.is_some() {
            read.advance(buf.position() as usize);
        }

        Ok(instruction)
    }

    fn parse_buffered<R: Buf + Clone>(read: &mut R) -> Result<Option<Action>, EncoderError> {
        if read.remaining() < 1 {
            return Ok(None);
        }

        let before = read.remaining();
        let mut buf = read.clone();
        let instruction = Self::decode(&mut buf)?;

        if instruction.is_some() {
            read.advance(before - buf.remaining());
        }

        Ok(instruction)
    }

    fn decode<R: Buf>(buf: &mut R) -> Result<Option<Action>, EncoderError> {
        let first = buf.chunk()[0];
        let instruction = match DecoderInstruction::decode(first) {
            DecoderInstruction::Unknown => {
                return Err(EncoderError::UnknownDecoderInstruction(first));
            }
            DecoderInstruction::InsertCountIncrement => {
                InsertCountIncrement::decode(&mut *buf)?.map(|x| Action::ReceivedRefIncrement(x.0))
            }
            DecoderInstruction::HeaderAck => match HeaderAck::decode(&mut *buf)? {
                Some(instruction) => Some(Action::Untrack(Self::stream_id(instruction.0)?)),
                None => None,
            },
            DecoderInstruction::StreamCancel => match StreamCancel::decode(&mut *buf)? {
                Some(instruction) => Some(Action::StreamCancel(Self::stream_id(instruction.0)?)),
                None => None,
            },
        };
        Ok(instruction)
    }
}

pub fn set_dynamic_table_size<W: BufMut>(
    table: &mut DynamicTable,
    encoder: &mut W,
    size: usize,
) -> Result<(), EncoderError> {
    table.set_max_size(size)?;
    DynamicTableSizeUpdate(size).encode(encoder);
    Ok(())
}

impl From<DynamicTableError> for EncoderError {
    fn from(e: DynamicTableError) -> Self {
        EncoderError::Insertion(e)
    }
}

impl From<StringError> for EncoderError {
    fn from(e: StringError) -> Self {
        EncoderError::InvalidString(e)
    }
}

impl From<ParseError> for EncoderError {
    fn from(e: ParseError) -> Self {
        match e {
            ParseError::Integer(x) => EncoderError::InvalidInteger(x),
            ParseError::String(x) => EncoderError::InvalidString(x),
            ParseError::InvalidPrefix(x) => EncoderError::UnknownDecoderInstruction(x),
            ParseError::InvalidBase { .. } | ParseError::InvalidRequiredInsertCount(_) => {
                EncoderError::MalformedDecoderInstruction
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::*;
    use crate::{
        buf::BufList,
        qpack::tests::helpers::{TABLE_SIZE, build_table, build_table_with_size},
    };

    #[allow(clippy::type_complexity)]
    fn check_encode_field(
        init_fields: &[HeaderField<'static>],
        field: &[HeaderField<'static>],
        check: &dyn Fn(&mut Cursor<&mut Vec<u8>>, &mut Cursor<&mut Vec<u8>>),
    ) {
        let mut table = build_table();
        table.set_max_size(TABLE_SIZE).unwrap();
        check_encode_field_table(&mut table, init_fields, field, 1, check);
    }

    #[allow(clippy::type_complexity)]
    fn check_encode_field_table(
        table: &mut DynamicTable,
        init_fields: &[HeaderField<'static>],
        field: &[HeaderField<'static>],
        stream_id: u64,
        check: &dyn Fn(&mut Cursor<&mut Vec<u8>>, &mut Cursor<&mut Vec<u8>>),
    ) {
        for field in init_fields {
            table.put(field.clone()).unwrap();
        }

        let mut encoder = Vec::new();
        let mut block = Vec::new();
        let mut enc_table = table.encoder(stream_id);
        let mut required_insert_count = 0;

        for field in field {
            if let Some(reference) =
                Encoder::encode_field(&mut enc_table, &mut block, &mut encoder, field).unwrap()
            {
                required_insert_count = required_insert_count.max(reference);
            }
        }

        enc_table.commit(required_insert_count);

        let mut read_block = Cursor::new(&mut block);
        let mut read_encoder = Cursor::new(&mut encoder);
        check(&mut read_block, &mut read_encoder);
    }

    #[test]
    fn encode_static() {
        let field = HeaderField::new(":method", "GET");
        check_encode_field(&[], &[field], &|mut b, e| {
            assert_eq!(Indexed::decode(&mut b), Ok(Indexed::Static(17)));
            assert_eq!(e.get_ref().len(), 0);
        });
    }

    #[test]
    fn dynamic_encoder_keeps_sensitive_static_field_literal() {
        let mut encoder = Encoder::default();
        let field = HeaderField::new(":method", "GET").with_sensitive(true);
        let mut block = Vec::new();
        let mut encoder_stream = Vec::new();

        assert_eq!(
            encoder.encode(0, &mut block, &mut encoder_stream, [field]),
            Ok(0)
        );
        assert!(encoder_stream.is_empty());

        let mut block = Cursor::new(block);
        HeaderPrefix::decode(&mut block).unwrap();
        assert_eq!(
            LiteralWithNameRef::decode(&mut block),
            Ok(LiteralWithNameRef::new_static(15, "GET").with_never_indexed())
        );
    }

    #[test]
    fn dynamic_encoder_uses_sensitive_dynamic_name_without_inserting() {
        let mut table = build_table();
        table.put(HeaderField::new("x-private", "old")).unwrap();
        let mut encoder = Encoder::from(table);
        let field = HeaderField::new("x-private", "secret").with_sensitive(true);
        let mut block = Vec::new();
        let mut encoder_stream = Vec::new();

        assert_eq!(
            encoder.encode(0, &mut block, &mut encoder_stream, [field]),
            Ok(1)
        );
        assert!(encoder_stream.is_empty());

        let mut block = Cursor::new(block);
        HeaderPrefix::decode(&mut block).unwrap();
        assert_eq!(
            LiteralWithNameRef::decode(&mut block),
            Ok(LiteralWithNameRef::new_dynamic(0, "secret").with_never_indexed())
        );
    }

    #[test]
    fn dynamic_encoder_uses_sensitive_post_base_name_without_inserting() {
        let mut table = DynamicTable::new();
        table.set_max_size(TABLE_SIZE).unwrap();
        table.set_max_blocked(1).unwrap();
        let mut encoder = Encoder::from(table);
        let mut block = Vec::new();
        let mut encoder_stream = Vec::new();

        assert_eq!(
            encoder.encode(
                0,
                &mut block,
                &mut encoder_stream,
                [
                    HeaderField::new("x-private", "old"),
                    HeaderField::new("x-private", "secret").with_sensitive(true),
                ],
            ),
            Ok(1)
        );

        let mut block = Cursor::new(block);
        HeaderPrefix::decode(&mut block).unwrap();
        IndexedWithPostBase::decode(&mut block).unwrap();
        assert_eq!(
            LiteralWithPostBaseNameRef::decode(&mut block),
            Ok(LiteralWithPostBaseNameRef::new(0, "secret").with_never_indexed())
        );
    }

    #[test]
    fn encode_static_nameref() {
        let field = HeaderField::new("location", "/bar");
        check_encode_field(&[], &[field], &|mut b, mut e| {
            assert_eq!(
                IndexedWithPostBase::decode(&mut b),
                Ok(IndexedWithPostBase(0))
            );
            assert_eq!(
                InsertWithNameRef::decode(&mut e),
                Ok(Some(InsertWithNameRef::new_static(12, "/bar")))
            );
        });
    }

    #[test]
    fn encode_static_nameref_indexed_in_dynamic() {
        let field = HeaderField::new("location", "/bar");
        check_encode_field(
            std::slice::from_ref(&field),
            std::slice::from_ref(&field),
            &|mut b, e| {
                assert_eq!(Indexed::decode(&mut b), Ok(Indexed::Dynamic(0)));
                assert_eq!(e.get_ref().len(), 0);
            },
        );
    }

    #[test]
    fn encode_dynamic_insert() {
        let field = HeaderField::new("foo", "bar");
        check_encode_field(&[], &[field], &|mut b, mut e| {
            assert_eq!(
                IndexedWithPostBase::decode(&mut b),
                Ok(IndexedWithPostBase(0))
            );
            assert_eq!(
                InsertWithoutNameRef::decode(&mut e),
                Ok(Some(InsertWithoutNameRef::new("foo", "bar")))
            );
        });
    }

    #[test]
    fn encode_dynamic_insert_nameref() {
        let field = HeaderField::new("foo", "bar");
        check_encode_field(
            &[field.clone(), HeaderField::new("baz", "bar")],
            &[field.with_value("quxx")],
            &|mut b, mut e| {
                assert_eq!(
                    IndexedWithPostBase::decode(&mut b),
                    Ok(IndexedWithPostBase(0))
                );
                assert_eq!(
                    InsertWithNameRef::decode(&mut e),
                    Ok(Some(InsertWithNameRef::new_dynamic(1, "quxx")))
                );
            },
        );
    }

    #[test]
    fn encode_literal() {
        let mut table = build_table();
        table.set_max_size(0).unwrap();
        let field = HeaderField::new("foo", "bar");
        check_encode_field_table(&mut table, &[], &[field], 1, &|mut b, e| {
            assert_eq!(Literal::decode(&mut b), Ok(Literal::new("foo", "bar")));
            assert_eq!(e.get_ref().len(), 0);
        });
    }

    #[test]
    fn encode_literal_nameref() {
        let mut table = build_table();
        table.set_max_size(63).unwrap();
        let field = HeaderField::new("foo", "bar");

        check_encode_field_table(
            &mut table,
            &[],
            std::slice::from_ref(&field),
            1,
            &|mut b, _| {
                assert_eq!(
                    IndexedWithPostBase::decode(&mut b),
                    Ok(IndexedWithPostBase(0))
                );
            },
        );
        check_encode_field_table(
            &mut table,
            std::slice::from_ref(&field),
            &[field.with_value("quxx")],
            2,
            &|mut b, e| {
                assert_eq!(
                    LiteralWithNameRef::decode(&mut b),
                    Ok(LiteralWithNameRef::new_dynamic(0, "quxx"))
                );
                assert_eq!(e.get_ref().len(), 0);
            },
        );
    }

    #[test]
    fn encode_literal_postbase_nameref() {
        let mut table = build_table();
        table.set_max_size(63).unwrap();
        let field = HeaderField::new("foo", "bar");
        check_encode_field_table(
            &mut table,
            &[],
            &[field.clone(), field.with_value("quxx")],
            1,
            &|mut b, mut e| {
                assert_eq!(
                    IndexedWithPostBase::decode(&mut b),
                    Ok(IndexedWithPostBase(0))
                );
                assert_eq!(
                    LiteralWithPostBaseNameRef::decode(&mut b),
                    Ok(LiteralWithPostBaseNameRef::new(0, "quxx"))
                );
                assert_eq!(
                    InsertWithoutNameRef::decode(&mut e),
                    Ok(Some(InsertWithoutNameRef::new("foo", "bar")))
                );
            },
        );
    }

    #[test]
    fn encode_with_header_block() {
        let mut table = build_table();

        for idx in 1..5 {
            table
                .put(HeaderField::new(
                    format!("foo{}", idx),
                    format!("bar{}", idx),
                ))
                .unwrap();
        }

        let mut encoder_buf = Vec::new();
        let mut block = Vec::new();
        let mut encoder = Encoder::from(table);

        let fields = vec![
            HeaderField::new(":method", "GET"),
            HeaderField::new("foo1", "bar1"),
            HeaderField::new("foo3", "new bar3"),
            HeaderField::new(":method", "staticnameref"),
            HeaderField::new("newfoo", "newbar"),
        ]
        .into_iter();

        assert_eq!(
            encoder.encode(1, &mut block, &mut encoder_buf, fields),
            Ok(7)
        );

        let mut read_block = Cursor::new(&mut block);
        let mut read_encoder = Cursor::new(&mut encoder_buf);

        assert_eq!(
            InsertWithNameRef::decode(&mut read_encoder),
            Ok(Some(InsertWithNameRef::new_dynamic(1, "new bar3")))
        );
        assert_eq!(
            InsertWithNameRef::decode(&mut read_encoder),
            Ok(Some(InsertWithNameRef::new_static(
                StaticTable::find_name(&b":method"[..]).unwrap(),
                "staticnameref"
            )))
        );
        assert_eq!(
            InsertWithoutNameRef::decode(&mut read_encoder),
            Ok(Some(InsertWithoutNameRef::new("newfoo", "newbar")))
        );

        assert_eq!(
            HeaderPrefix::decode(&mut read_block)
                .unwrap()
                .get(7, TABLE_SIZE),
            Ok((7, 4))
        );
        assert_eq!(Indexed::decode(&mut read_block), Ok(Indexed::Static(17)));
        assert_eq!(Indexed::decode(&mut read_block), Ok(Indexed::Dynamic(3)));
        assert_eq!(
            IndexedWithPostBase::decode(&mut read_block),
            Ok(IndexedWithPostBase(0))
        );
        assert_eq!(
            IndexedWithPostBase::decode(&mut read_block),
            Ok(IndexedWithPostBase(1))
        );
        assert_eq!(
            IndexedWithPostBase::decode(&mut read_block),
            Ok(IndexedWithPostBase(2))
        );
        assert_eq!(read_block.get_ref().len() as u64, read_block.position());
    }

    #[test]
    fn decoder_block_ack() {
        let mut table = build_table();

        let field = HeaderField::new("foo", "bar");
        check_encode_field_table(
            &mut table,
            &[],
            &[field.clone(), field.with_value("quxx")],
            2,
            &|_, _| {},
        );

        let mut buf = vec![];
        let mut encoder = Encoder::from(table);

        HeaderAck(2).encode(&mut buf);
        let mut cur = Cursor::new(&buf);
        assert_eq!(
            Action::parse(&mut cur),
            Ok(Some(Action::Untrack(StreamId(2))))
        );

        let mut cur = Cursor::new(&buf);
        assert_eq!(encoder.on_decoder_recv(&mut cur), Ok(()),);

        let mut cur = Cursor::new(&buf);
        assert_eq!(
            encoder.on_decoder_recv(&mut cur),
            Err(EncoderError::Insertion(DynamicTableError::UnknownStreamId(
                2
            )))
        );
    }

    #[test]
    fn section_acknowledgment_advances_known_received_count() {
        let mut table = build_table();
        table.set_max_blocked(1).unwrap();
        let mut encoder = Encoder::from(table);

        assert_eq!(
            encoder.encode(
                2,
                &mut Vec::new(),
                &mut Vec::new(),
                &[HeaderField::new("first", "value")],
            ),
            Ok(1)
        );
        assert_eq!(
            encoder.encode(
                4,
                &mut Vec::new(),
                &mut Vec::new(),
                &[HeaderField::new("blocked", "value")],
            ),
            Ok(0)
        );

        let mut acknowledgment = Vec::new();
        HeaderAck(2).encode(&mut acknowledgment);
        encoder
            .on_decoder_recv(&mut Cursor::new(acknowledgment))
            .unwrap();

        // The acknowledgment proves that insertion 1 arrived and releases the
        // only blocked-stream slot for a new dynamic field section.
        // https://www.rfc-editor.org/rfc/rfc9204.html#section-2.1.4
        assert_eq!(
            encoder.encode(
                6,
                &mut Vec::new(),
                &mut Vec::new(),
                &[HeaderField::new("second", "value")],
            ),
            Ok(2)
        );
    }

    #[test]
    fn section_acknowledgment_skips_static_field_sections() {
        let mut encoder = Encoder::from(build_table());

        assert_eq!(
            encoder.encode(
                2,
                &mut Vec::new(),
                &mut Vec::new(),
                &[HeaderField::new(":method", "GET")],
            ),
            Ok(0)
        );
        assert_eq!(
            encoder.encode(
                2,
                &mut Vec::new(),
                &mut Vec::new(),
                &[HeaderField::new("dynamic", "value")],
            ),
            Ok(1)
        );

        let mut acknowledgment = Vec::new();
        HeaderAck(2).encode(&mut acknowledgment);
        assert_eq!(
            encoder.on_decoder_recv(&mut Cursor::new(&acknowledgment)),
            Ok(())
        );
        assert_eq!(
            encoder.on_decoder_recv(&mut Cursor::new(acknowledgment)),
            Err(EncoderError::Insertion(DynamicTableError::UnknownStreamId(
                2
            )))
        );
    }

    #[test]
    fn decoder_stream_cancellation_releases_all_field_sections() {
        let mut table = build_table();
        table.set_max_blocked(1).unwrap();
        let mut encoder = Encoder::from(table);

        for index in 1..=3 {
            assert_eq!(
                encoder.encode(
                    2,
                    &mut Vec::new(),
                    &mut Vec::new(),
                    &[HeaderField::new(format!("field{index}"), "value")],
                ),
                Ok(index)
            );
        }

        let mut instruction = Vec::new();
        StreamCancel(2).encode(&mut instruction);
        let mut cur = Cursor::new(&instruction);
        assert_eq!(
            Action::parse(&mut cur),
            Ok(Some(Action::StreamCancel(StreamId(2))))
        );

        encoder
            .on_decoder_recv(&mut Cursor::new(instruction))
            .unwrap();
        assert_eq!(
            encoder.encode(
                4,
                &mut Vec::new(),
                &mut Vec::new(),
                &[HeaderField::new("replacement", "value")],
            ),
            Ok(4)
        );
    }

    #[test]
    fn decoder_accept_truncated() {
        let mut buf = vec![];
        StreamCancel(2321).encode(&mut buf);

        let mut cur = Cursor::new(&buf[..2]); // trucated prefix_int
        assert_eq!(Action::parse(&mut cur), Ok(None));

        let mut cur = Cursor::new(&buf);
        assert_eq!(
            Action::parse(&mut cur),
            Ok(Some(Action::StreamCancel(StreamId(2321))))
        );
    }

    #[test]
    fn decoder_instruction_can_span_receive_chunks() {
        let mut encoded = vec![];
        StreamCancel(2321).encode(&mut encoded);

        let mut received = BufList::new();
        received.push(Bytes::copy_from_slice(&encoded[..1]));
        let mut encoder = Encoder::default();

        {
            let mut cursor = received.cursor();
            assert_eq!(encoder.on_decoder_recv_buffered(&mut cursor), Ok(()));
            assert_eq!(cursor.position(), 0);
        }

        received.push(Bytes::copy_from_slice(&encoded[1..]));
        let mut cursor = received.cursor();
        assert_eq!(encoder.on_decoder_recv_buffered(&mut cursor), Ok(()));
        assert_eq!(cursor.position(), encoded.len());
    }

    #[test]
    fn decoder_instruction_stream_id_uses_quic_varint_range() {
        let max_stream_id = crate::proto::varint::VarInt::MAX.into_inner();

        let mut acknowledgment = Vec::new();
        HeaderAck(max_stream_id).encode(&mut acknowledgment);
        assert_eq!(
            Action::parse(&mut Cursor::new(acknowledgment)),
            Ok(Some(Action::Untrack(StreamId(max_stream_id))))
        );

        let mut cancellation = Vec::new();
        StreamCancel(max_stream_id).encode(&mut cancellation);
        assert_eq!(
            Action::parse(&mut Cursor::new(cancellation)),
            Ok(Some(Action::StreamCancel(StreamId(max_stream_id))))
        );

        for encoded in [
            {
                let mut encoded = Vec::new();
                HeaderAck(max_stream_id + 1).encode(&mut encoded);
                encoded
            },
            {
                let mut encoded = Vec::new();
                StreamCancel(max_stream_id + 1).encode(&mut encoded);
                encoded
            },
        ] {
            let mut cursor = Cursor::new(encoded);
            assert_eq!(
                Action::parse(&mut cursor),
                Err(EncoderError::InvalidStreamId(max_stream_id + 1))
            );
            assert_eq!(cursor.position(), 0);
        }

        let mut encoded = Vec::new();
        StreamCancel(max_stream_id + 1).encode(&mut encoded);
        let mut received = BufList::new();
        received.push(Bytes::from(encoded));
        let mut cursor = received.cursor();
        assert_eq!(
            Encoder::default().on_decoder_recv_buffered(&mut cursor),
            Err(EncoderError::InvalidStreamId(max_stream_id + 1))
        );
        assert_eq!(cursor.position(), 0);
    }

    #[test]
    fn decoder_unknown_stream() {
        let mut table = build_table();

        check_encode_field_table(
            &mut table,
            &[],
            &[HeaderField::new("foo", "bar")],
            2,
            &|_, _| {},
        );
        let mut encoder = Encoder::from(table);

        let mut buf = vec![];
        HeaderAck(4).encode(&mut buf);

        let mut cur = Cursor::new(&buf);
        assert_eq!(
            encoder.on_decoder_recv(&mut cur),
            Err(EncoderError::Insertion(DynamicTableError::UnknownStreamId(
                4
            )))
        );
    }

    #[test]
    fn insert_count() {
        let mut buf = vec![];
        InsertCountIncrement(4).encode(&mut buf);

        let mut cur = Cursor::new(&buf);
        assert_eq!(
            Action::parse(&mut cur),
            Ok(Some(Action::ReceivedRefIncrement(4)))
        );

        let mut encoder = Encoder {
            table: build_table_with_size(4),
        };

        let mut cur = Cursor::new(&buf);
        assert_eq!(encoder.on_decoder_recv(&mut cur), Ok(()));
    }

    #[test]
    fn invalid_insert_count_increments_are_rejected() {
        // Zero and counts beyond the insertions sent by the encoder are
        // QPACK_DECODER_STREAM_ERROR conditions.
        // https://www.rfc-editor.org/rfc/rfc9204.html#section-4.4.3
        for increment in [0, 2] {
            let mut buf = vec![];
            InsertCountIncrement(increment).encode(&mut buf);
            let mut encoder = Encoder {
                table: build_table_with_size(1),
            };

            assert_eq!(
                encoder.on_decoder_recv(&mut Cursor::new(buf)),
                Err(EncoderError::Insertion(
                    DynamicTableError::InvalidInsertCountIncrement
                ))
            );
        }
    }
}
