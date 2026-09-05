use std::{
    io::Cursor,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
};

use crate::{
    proto::headers::Header,
    qpack::{
        BlockedStreamRegistry, Decoded, DecoderError, HeaderField, QpackDecoder, QpackEvent,
        block::{HeaderPrefix, Indexed, Literal, LiteralWithNameRef, LiteralWithPostBaseNameRef},
        decoder::{Decoder, DecoderState, decode_stateless},
        dynamic::{DynamicTable, Error as DynamicTableError},
        encoder::{Encoder, encode_stateless, set_dynamic_table_size},
        stream::{DynamicTableSizeUpdate, InsertWithoutNameRef},
    },
    quic::StreamId,
};

struct WakeCounter(AtomicUsize);

impl futures_util::task::ArcWake for WakeCounter {
    fn wake_by_ref(counter: &Arc<Self>) {
        counter.0.fetch_add(1, Ordering::Relaxed);
    }
}

pub mod helpers {
    use crate::qpack::{HeaderField, dynamic::DynamicTable};

    pub const TABLE_SIZE: usize = 4096;

    pub fn build_table() -> DynamicTable {
        let mut table = DynamicTable::new();
        table.set_max_size(TABLE_SIZE).unwrap();
        table.set_max_blocked(100).unwrap();
        table
    }

    pub fn build_table_with_size(n_field: usize) -> DynamicTable {
        let mut table = DynamicTable::new();
        table.set_max_size(TABLE_SIZE).unwrap();
        table.set_max_blocked(100).unwrap();

        for i in 0..n_field {
            table
                .put(HeaderField::new(format!("foo{}", i + 1), "bar"))
                .unwrap();
        }

        table
    }
}

#[test]
fn codec_basic_get() {
    let mut encoder = Encoder::default();
    let mut decoder = Decoder::from(DynamicTable::new());

    let mut block_buf = vec![];
    let mut enc_buf = vec![];
    let mut dec_buf = vec![];

    let header = vec![
        HeaderField::new(":method", "GET"),
        HeaderField::new(":path", "/"),
        HeaderField::new("foo", "bar"),
    ];

    encoder
        .encode(42, &mut block_buf, &mut enc_buf, header.clone())
        .unwrap();

    let mut enc_cur = Cursor::new(&mut enc_buf);
    decoder.on_encoder_recv(&mut enc_cur, &mut dec_buf).unwrap();

    let mut block_cur = Cursor::new(&mut block_buf);
    let Decoded { fields, .. } = decoder.decode_header(&mut block_cur).unwrap();
    assert_eq!(fields, header);

    let mut dec_cur = Cursor::new(&mut dec_buf);
    encoder.on_decoder_recv(&mut dec_cur).unwrap();
}

const TABLE_SIZE: usize = 4096;
#[test]
fn blocked_header() {
    let mut enc_table = DynamicTable::new();
    enc_table.set_max_size(TABLE_SIZE).unwrap();
    enc_table.set_max_blocked(100).unwrap();
    let mut encoder = Encoder::from(enc_table);
    let mut dec_table = DynamicTable::new();
    dec_table.set_max_size(TABLE_SIZE).unwrap();
    dec_table.set_max_blocked(100).unwrap();
    let decoder = Decoder::from(dec_table);

    let mut block_buf = vec![];
    let mut enc_buf = vec![];

    encoder
        .encode(
            42,
            &mut block_buf,
            &mut enc_buf,
            &[HeaderField::new("foo", "bar")],
        )
        .unwrap();

    let mut block_cur = Cursor::new(&mut block_buf);
    assert_eq!(
        decoder.decode_header(&mut block_cur),
        Err(DecoderError::MissingRefs(1))
    );
}

#[test]
fn blocked_field_section_keeps_reconstructed_prefix() {
    const ENTRY_SIZE: usize = 34;

    let mut field_section = Vec::new();
    HeaderPrefix::new(1, 1, 1, ENTRY_SIZE).encode(&mut field_section);
    Indexed::Dynamic(0).encode(&mut field_section);

    let mut decoder = Decoder::new(ENTRY_SIZE as u64, 1).unwrap();
    let mut prefix = None;
    let mut incremental = DecoderState::new();
    incremental
        .extend(&mut Cursor::new(&field_section), ENTRY_SIZE)
        .unwrap();
    assert_eq!(
        decoder.decode_header_incremental(&mut incremental, true, u64::MAX),
        Err(DecoderError::MissingRefs(1))
    );
    let mut read = Cursor::new(field_section);
    assert_eq!(
        decoder.decode_header_limited(&mut read, u64::MAX, &mut prefix),
        Err(DecoderError::MissingRefs(1))
    );
    assert!(prefix.is_some());

    let mut encoder_stream = Vec::new();
    DynamicTableSizeUpdate(ENTRY_SIZE).encode(&mut encoder_stream);
    for value in ["1", "2", "3"] {
        InsertWithoutNameRef::new("a", value)
            .encode(&mut encoder_stream)
            .unwrap();
    }
    decoder
        .on_encoder_recv(&mut Cursor::new(encoder_stream), &mut Vec::new())
        .unwrap();

    // Required Insert Count is reconstructed when the prefix first arrives.
    // Reconstructing it against Insert Count 3 would turn RIC 1 into RIC 3 and
    // silently bind this field line to a different dynamic-table entry.
    // https://www.rfc-editor.org/rfc/rfc9204.html#section-4.5.1.1
    let result = decoder.decode_header_limited(&mut read, u64::MAX, &mut prefix);
    assert_eq!(
        decoder
            .decode_header_incremental(&mut incremental, true, u64::MAX)
            .unwrap_err(),
        DecoderError::DynamicTable(DynamicTableError::BadRelativeIndex(0))
    );
    assert!(
        matches!(
            result,
            Err(DecoderError::DynamicTable(
                DynamicTableError::BadRelativeIndex(0)
            ))
        ),
        "unexpected retry result: {result:?}"
    );
}

#[test]
fn shared_decoder_queues_blocked_header_for_connection_driver() {
    let mut enc_table = DynamicTable::new();
    enc_table.set_max_size(TABLE_SIZE).unwrap();
    enc_table.set_max_blocked(100).unwrap();
    let mut encoder = Encoder::from(enc_table);

    let mut block_buf = vec![];
    let mut enc_buf = vec![];
    encoder
        .encode(
            42,
            &mut block_buf,
            &mut enc_buf,
            &[HeaderField::new("foo", "bar")],
        )
        .unwrap();

    let (decoder_waker, mut decoder_wakers) = tokio::sync::mpsc::unbounded_channel();
    let decoder = QpackDecoder::new(Decoder::new(TABLE_SIZE as u64, 100).unwrap(), decoder_waker);
    let mut block_cur = Cursor::new(&mut block_buf);
    let mut cx = Context::from_waker(futures_util::task::noop_waker_ref());

    assert_eq!(
        decoder.poll_decode_field_section(&mut cx, &mut block_cur, u64::MAX, &mut None),
        Poll::Ready(Err(DecoderError::MissingRefs(1)))
    );
    assert!(decoder_wakers.try_recv().is_err());

    decoder
        .queue_blocked_stream(StreamId(0), 1, cx.waker())
        .unwrap();
    assert!(matches!(
        decoder_wakers.try_recv(),
        Ok(QpackEvent::RegisterBlocked {
            stream_id: StreamId(0),
            required_ref: 1,
            ..
        })
    ));
}

#[test]
fn shared_decoder_rejects_blocking_when_the_advertised_limit_is_zero() {
    let (events_send, mut events_recv) = tokio::sync::mpsc::unbounded_channel();
    let decoder = QpackDecoder::new(Decoder::new(TABLE_SIZE as u64, 0).unwrap(), events_send);

    assert!(matches!(
        decoder.queue_blocked_stream(StreamId(0), 1, futures_util::task::noop_waker_ref()),
        Err(DecoderError::TooManyBlockedStreams)
    ));
    assert!(events_recv.try_recv().is_err());
}

#[test]
fn decoder_update_releases_blocked_stream_budget_before_request_repoll() {
    let mut encoder_table = DynamicTable::new();
    encoder_table.set_max_blocked(1).unwrap();
    let mut first_encoder_stream = Vec::new();
    set_dynamic_table_size(&mut encoder_table, &mut first_encoder_stream, TABLE_SIZE).unwrap();
    let mut encoder = Encoder::from(encoder_table);

    let mut first_field_section = Vec::new();
    assert_eq!(
        encoder.encode(
            0,
            &mut first_field_section,
            &mut first_encoder_stream,
            &[HeaderField::new("first", "value")],
        ),
        Ok(1)
    );

    let (events_send, _events_recv) = tokio::sync::mpsc::unbounded_channel();
    let decoder = QpackDecoder::new(Decoder::new(TABLE_SIZE as u64, 1).unwrap(), events_send);
    let mut cx = Context::from_waker(futures_util::task::noop_waker_ref());
    assert_eq!(
        decoder.poll_decode_field_section(
            &mut cx,
            &mut Cursor::new(first_field_section),
            u64::MAX,
            &mut None,
        ),
        Poll::Ready(Err(DecoderError::MissingRefs(1)))
    );
    let mut blocked_streams = BlockedStreamRegistry::new(1);
    let wake_count = Arc::new(WakeCounter(AtomicUsize::new(0)));
    let blocked_waker = futures_util::task::waker(wake_count.clone());
    assert!(
        blocked_streams
            .register(StreamId(0), 1, blocked_waker)
            .is_ok()
    );

    let mut decoder_stream = Vec::new();
    let Poll::Ready(Ok(insert_count)) = decoder.poll_on_recv_encoder(
        &mut cx,
        &mut Cursor::new(first_encoder_stream),
        &mut decoder_stream,
    ) else {
        panic!("first encoder-stream insertion was not processed");
    };
    assert_eq!(insert_count, 1);
    blocked_streams.update_insert_count(insert_count);
    assert_eq!(wake_count.0.load(Ordering::Relaxed), 1);
    encoder
        .on_decoder_recv(&mut Cursor::new(decoder_stream))
        .unwrap();

    let mut second_field_section = Vec::new();
    let mut second_encoder_stream = Vec::new();
    assert_eq!(
        encoder.encode(
            4,
            &mut second_field_section,
            &mut second_encoder_stream,
            &[HeaderField::new("second", "value")],
        ),
        Ok(2)
    );
    assert_eq!(
        decoder.poll_decode_field_section(
            &mut cx,
            &mut Cursor::new(second_field_section),
            u64::MAX,
            &mut None,
        ),
        Poll::Ready(Err(DecoderError::MissingRefs(2)))
    );

    // Insert Count one released the first stream before its request task polled
    // the field section again.
    // https://www.rfc-editor.org/rfc/rfc9204.html#section-2.2.1
    assert!(
        blocked_streams
            .register(StreamId(4), 2, cx.waker().clone())
            .is_ok()
    );
}

#[test]
fn blocked_registration_after_decoder_update_wakes_immediately() {
    let mut blocked_streams = BlockedStreamRegistry::new(1);
    blocked_streams.update_insert_count(1);

    let wake_count = Arc::new(WakeCounter(AtomicUsize::new(0)));
    let waker = futures_util::task::waker(wake_count.clone());

    // The update arrived before registration. The registry sees that the field
    // section is already decodable, wakes it, and uses no blocked-stream slot.
    // https://www.rfc-editor.org/rfc/rfc9204.html#section-2.2.1
    assert!(blocked_streams.register(StreamId(0), 1, waker).is_ok());
    assert_eq!(wake_count.0.load(Ordering::Relaxed), 1);
    assert!(
        blocked_streams
            .register(StreamId(4), 2, futures_util::task::noop_waker().clone(),)
            .is_ok()
    );
}

#[test]
fn codec_table_size_0() {
    let mut enc_table = DynamicTable::new();
    let mut dec_table = DynamicTable::new();

    let mut block_buf = vec![];
    let mut enc_buf = vec![];
    let mut dec_buf = vec![];

    let header = vec![
        HeaderField::new(":method", "GET"),
        HeaderField::new(":path", "/"),
        HeaderField::new("foo", "bar"),
    ];

    dec_table.set_max_size(0).unwrap();
    enc_table.set_max_size(0).unwrap();

    let mut encoder = Encoder::from(enc_table);
    let mut decoder = Decoder::from(dec_table);

    encoder
        .encode(42, &mut block_buf, &mut enc_buf, header.clone())
        .unwrap();

    let mut enc_cur = Cursor::new(&mut enc_buf);
    decoder.on_encoder_recv(&mut enc_cur, &mut dec_buf).unwrap();

    let mut block_cur = Cursor::new(&mut block_buf);
    let Decoded { fields, .. } = decoder.decode_header(&mut block_cur).unwrap();
    assert_eq!(fields, header);

    let mut dec_cur = Cursor::new(&mut dec_buf);
    encoder.on_decoder_recv(&mut dec_cur).unwrap();
}

#[test]
fn codec_table_full() {
    let mut enc_table = DynamicTable::new();
    let mut dec_table = DynamicTable::new();

    let mut block_buf = vec![];
    let mut enc_buf = vec![];
    let mut dec_buf = vec![];

    let header = vec![
        HeaderField::new("foo", "bar"),
        HeaderField::new("foo1", "bar1"),
    ];

    dec_table.set_max_size(42).unwrap();
    enc_table.set_max_size(42).unwrap();

    let mut encoder = Encoder::from(enc_table);
    let mut decoder = Decoder::from(dec_table);

    encoder
        .encode(42, &mut block_buf, &mut enc_buf, header.clone())
        .unwrap();

    let mut enc_cur = Cursor::new(&mut enc_buf);
    let mut block_cur = Cursor::new(&mut block_buf);

    decoder.on_encoder_recv(&mut enc_cur, &mut dec_buf).unwrap();
    let Decoded { fields, .. } = decoder.decode_header(&mut block_cur).unwrap();
    assert_eq!(fields, header);

    let mut dec_cur = Cursor::new(&mut dec_buf);
    encoder.on_decoder_recv(&mut dec_cur).unwrap();
}

fn forward_stateless(fields: Vec<HeaderField<'static>>) -> Cursor<Vec<u8>> {
    let headers = Header::try_from(fields).unwrap();
    let mut encoded = Vec::new();
    encode_stateless(&mut encoded, &headers).unwrap();
    let mut encoded = Cursor::new(encoded);
    HeaderPrefix::decode(&mut encoded).unwrap();
    encoded
}

#[test]
fn forwarded_never_indexed_static_name_reference_remains_literal() {
    let mut encoded = Vec::new();
    HeaderPrefix::new(0, 0, 0, 0).encode(&mut encoded);
    LiteralWithNameRef::new_static(17, "GET")
        .with_never_indexed()
        .encode(&mut encoded)
        .unwrap();

    let decoded = decode_stateless(&mut Cursor::new(encoded), u64::MAX).unwrap();
    assert!(decoded.fields[0].is_sensitive());

    assert_eq!(
        LiteralWithNameRef::decode(&mut forward_stateless(decoded.fields)),
        Ok(LiteralWithNameRef::new_static(15, "GET").with_never_indexed())
    );
}

#[test]
fn forwarded_never_indexed_dynamic_name_reference_remains_literal() {
    let mut table = DynamicTable::new();
    table.set_max_size(TABLE_SIZE).unwrap();
    table.put(HeaderField::new("x-private", "old")).unwrap();
    let decoder = Decoder::from(table);
    let mut encoded = Vec::new();
    HeaderPrefix::new(1, 1, 1, TABLE_SIZE).encode(&mut encoded);
    LiteralWithNameRef::new_dynamic(0, "secret")
        .with_never_indexed()
        .encode(&mut encoded)
        .unwrap();

    let decoded = decoder.decode_header(&mut Cursor::new(encoded)).unwrap();
    assert!(decoded.fields[0].is_sensitive());

    assert_eq!(
        Literal::decode(&mut forward_stateless(decoded.fields)),
        Ok(Literal::new("x-private", "secret").with_never_indexed())
    );
}

#[test]
fn forwarded_never_indexed_literal_name_remains_literal() {
    let mut encoded = Vec::new();
    HeaderPrefix::new(0, 0, 0, 0).encode(&mut encoded);
    Literal::new("x-private", "secret")
        .with_never_indexed()
        .encode(&mut encoded)
        .unwrap();

    let decoded = decode_stateless(&mut Cursor::new(encoded), u64::MAX).unwrap();
    assert!(decoded.fields[0].is_sensitive());

    assert_eq!(
        Literal::decode(&mut forward_stateless(decoded.fields)),
        Ok(Literal::new("x-private", "secret").with_never_indexed())
    );
}

#[test]
fn forwarded_never_indexed_post_base_name_reference_remains_literal() {
    let mut table = DynamicTable::new();
    table.set_max_size(TABLE_SIZE).unwrap();
    table.put(HeaderField::new("x-private", "old")).unwrap();
    let decoder = Decoder::from(table);
    let mut encoded = Vec::new();
    HeaderPrefix::new(1, 0, 1, TABLE_SIZE).encode(&mut encoded);
    LiteralWithPostBaseNameRef::new(0, "secret")
        .with_never_indexed()
        .encode(&mut encoded)
        .unwrap();

    let decoded = decoder.decode_header(&mut Cursor::new(encoded)).unwrap();
    assert!(decoded.fields[0].is_sensitive());

    assert_eq!(
        Literal::decode(&mut forward_stateless(decoded.fields)),
        Ok(Literal::new("x-private", "secret").with_never_indexed())
    );
}
