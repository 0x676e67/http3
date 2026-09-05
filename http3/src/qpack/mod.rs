use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex, MutexGuard, RwLock, RwLockReadGuard, TryLockError},
    task::{Context, Poll, Waker},
};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use futures_util::task::AtomicWaker;
use tokio::sync::mpsc;

#[cfg(feature = "unstable")]
pub use self::decoder::decode_stateless;
#[cfg(test)]
pub(crate) use self::stream::{DynamicTableSizeUpdate, InsertCountIncrement, InsertWithoutNameRef};
pub use self::{
    decoder::{Decoded, Decoder, DecoderError, ack_header, stream_canceled},
    encoder::{EncoderError, encode_stateless},
    field::HeaderField,
};
pub(crate) use self::{
    decoder::{FieldSectionPrefix, decode_stateless_limited},
    encoder::Encoder,
};
use crate::quic::StreamId;

mod block;
mod dynamic;
mod field;
mod parse_error;
mod static_;
mod stream;
mod vas;

mod decoder;
mod encoder;

mod prefix_int;
mod prefix_string;

#[cfg(test)]
mod tests;

#[derive(Debug)]
pub enum Error {
    Encoder(EncoderError),
    Decoder(DecoderError),
}

#[derive(Default)]
struct QpackEncoderState {
    encoder: Encoder,
    // Committed QPACK encoder-stream output. Encoding starts only while this
    // queue is empty; a successful encode never retracts its instructions.
    // This is the local outq boundary for the Insert Count Increment check.
    // https://www.rfc-editor.org/rfc/rfc9204.html#section-4.4.3
    pending: BytesMut,
    enabled: bool,
}

/// Connection-shared request encoder with an opt-in dynamic table.
#[derive(Clone, Default)]
pub(crate) struct QpackEncoder {
    state: Arc<Mutex<QpackEncoderState>>,
}

#[derive(Debug)]
pub(crate) enum QpackEncoderError {
    Encoder(EncoderError),
    Poisoned,
}

impl std::fmt::Display for QpackEncoderError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Encoder(error) => error.fmt(formatter),
            Self::Poisoned => formatter.write_str("QPACK encoder state is poisoned"),
        }
    }
}

impl From<EncoderError> for QpackEncoderError {
    fn from(error: EncoderError) -> Self {
        Self::Encoder(error)
    }
}

impl QpackEncoder {
    fn lock(&self) -> Result<MutexGuard<'_, QpackEncoderState>, QpackEncoderError> {
        self.state.lock().map_err(|_| QpackEncoderError::Poisoned)
    }

    pub(crate) fn dynamic_ready(&self) -> Result<bool, QpackEncoderError> {
        let state = self.lock()?;
        Ok(state.enabled && state.pending.is_empty())
    }

    pub(crate) fn configure(
        &self,
        max_table_capacity: usize,
        capacity: usize,
    ) -> Result<(), QpackEncoderError> {
        if capacity == 0 {
            return Ok(());
        }

        let mut state = self.lock()?;
        let QpackEncoderState {
            encoder,
            pending,
            enabled,
        } = &mut *state;
        // Generate speculative insertions with one private slot, but transmit
        // only field sections whose Required Insert Count is already known by
        // the peer. The peer's blocked-stream allowance is therefore never
        // consumed, including when it is zero.
        encoder.configure(pending, max_table_capacity, capacity, 1)?;
        *enabled = true;
        Ok(())
    }

    /// Encodes one request field section and commits any encoder-stream output.
    /// An error is terminal for this encoder state and the caller must close the
    /// connection with a local error.
    pub(crate) fn encode<'a, T, H>(
        &self,
        stream_id: StreamId,
        block: &mut BytesMut,
        fields: T,
    ) -> Result<bool, QpackEncoderError>
    where
        T: IntoIterator<Item = H> + Clone,
        H: AsRef<HeaderField<'a>>,
    {
        let mut state = self.lock()?;
        if !state.enabled || !state.pending.is_empty() {
            drop(state);
            encode_stateless(block, fields)?;
            return Ok(false);
        }

        let QpackEncoderState {
            encoder,
            pending,
            enabled,
        } = &mut *state;
        let block_start = block.len();
        let required_insert_count =
            match encoder.encode(stream_id.into_inner(), block, pending, fields.clone()) {
                Ok(encoded) => encoded,
                Err(error) => {
                    // Encoding can mutate the local table before a later string
                    // conversion fails. Discard the uncommitted instruction
                    // batch; the caller must terminate the connection because
                    // this encoder state is no longer reusable.
                    pending.clear();
                    *enabled = false;
                    return Err(error.into());
                }
            };
        if encoder.field_section_is_blocked(required_insert_count) {
            if let Err(error) = encoder.cancel_stream(stream_id.into_inner()) {
                block.truncate(block_start);
                pending.clear();
                *enabled = false;
                return Err(error.into());
            }
            block.truncate(block_start);
            if let Err(error) = encode_stateless(block, fields) {
                pending.clear();
                *enabled = false;
                return Err(error.into());
            }
        }
        Ok(!pending.is_empty())
    }

    /// Takes the next instruction batch. The caller must completely write a
    /// previously taken batch before taking another so stream order is kept.
    /// The returned bytes remain part of the committed, non-retractable local
    /// encoder-stream output queue while the transport consumes them.
    pub(crate) fn take_pending_instructions(&self) -> Result<Bytes, QpackEncoderError> {
        let mut state = self.lock()?;
        Ok(state.pending.split().freeze())
    }

    pub(crate) fn on_decoder_recv_buffered<R: Buf + Clone>(
        &self,
        read: &mut R,
    ) -> Result<(), QpackEncoderError> {
        self.lock()?.encoder.on_decoder_recv_buffered(read)?;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn has_acknowledged_all_insertions(&self) -> Result<bool, QpackEncoderError> {
        Ok(self.lock()?.encoder.has_acknowledged_all_insertions())
    }
}

impl std::error::Error for Error {}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Encoder(e) => write!(f, "Encoder {}", e),
            Error::Decoder(e) => write!(f, "Decoder {}", e),
        }
    }
}

/// Event emitted by request streams for QPACK decoder work.
#[derive(Debug)]
pub(crate) enum QpackEvent {
    HeaderAck(StreamId),
    StreamCancel(StreamId),
    RegisterBlocked {
        stream_id: StreamId,
        required_ref: usize,
        waker: Waker,
    },
    ReleaseBlocked {
        stream_id: StreamId,
        required_ref: usize,
    },
    DecoderAccessWaker(Waker),
}

/// Tracks blocked field sections in the connection driver.
///
/// Entries are ordered by Required Insert Count, allowing an encoder-stream
/// update to wake only newly decodable streams. Driver ownership avoids a shared
/// registry lock in request polling and drop paths.
pub(crate) struct BlockedStreamRegistry {
    max_blocked_streams: u64,
    insert_count: usize,
    streams: BTreeMap<(usize, StreamId), Waker>,
}

impl BlockedStreamRegistry {
    pub(crate) fn new(max_blocked_streams: u64) -> Self {
        Self {
            max_blocked_streams,
            insert_count: 0,
            streams: BTreeMap::new(),
        }
    }

    /// Registers a field section that is waiting for dynamic table entries.
    ///
    /// Repeated polls update the stored waker without using another slot. If the
    /// encoder update arrives first, registration sees the current Insert Count
    /// and wakes the task immediately.
    ///
    /// When the peer exceeds the advertised limit, the unregistered waker is
    /// returned so the connection driver can publish the error before waking it.
    ///
    /// See [RFC 9204, Section 2.1.2](https://www.rfc-editor.org/rfc/rfc9204.html#section-2.1.2)
    /// and [Section 2.2.1](https://www.rfc-editor.org/rfc/rfc9204.html#section-2.2.1).
    pub(crate) fn register(
        &mut self,
        stream_id: StreamId,
        required_ref: usize,
        waker: Waker,
    ) -> Result<(), Waker> {
        if required_ref <= self.insert_count {
            waker.wake();
            return Ok(());
        }

        let key = (required_ref, stream_id);
        if let Some(registered) = self.streams.get_mut(&key) {
            if !registered.will_wake(&waker) {
                *registered = waker;
            }
            return Ok(());
        }

        let limit_reached = match u64::try_from(self.streams.len()) {
            Ok(blocked_streams) => blocked_streams >= self.max_blocked_streams,
            Err(_) => true,
        };
        if limit_reached {
            // The driver publishes the connection error before waking this
            // task. Waking here would let it observe an unfinished error state.
            return Err(waker);
        }

        self.streams.insert(key, waker);
        Ok(())
    }

    /// Removes a field section after it decodes or its stream is abandoned.
    ///
    /// See [RFC 9204, Section 2.2.1](https://www.rfc-editor.org/rfc/rfc9204.html#section-2.2.1).
    pub(crate) fn release(&mut self, stream_id: StreamId, required_ref: usize) {
        self.streams.remove(&(required_ref, stream_id));
    }

    /// Advances the decoder Insert Count and wakes every newly decodable stream.
    ///
    /// A stream stops counting as blocked as soon as the decoder has all its
    /// referenced entries. The request task does not need to poll first.
    ///
    /// See [RFC 9204, Section 2.2.1](https://www.rfc-editor.org/rfc/rfc9204.html#section-2.2.1).
    pub(crate) fn update_insert_count(&mut self, insert_count: usize) {
        if insert_count <= self.insert_count {
            return;
        }
        self.insert_count = insert_count;

        while self
            .streams
            .first_key_value()
            .is_some_and(|(&(required_ref, _), _)| required_ref <= insert_count)
        {
            if let Some((_, waker)) = self.streams.pop_first() {
                waker.wake();
            }
        }
    }

    /// Wakes and removes all blocked streams after a connection-level error.
    pub(crate) fn wake_all(&mut self) {
        while let Some((_, waker)) = self.streams.pop_first() {
            waker.wake();
        }
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.streams.len()
    }
}

struct QpackDecoderInner {
    decoder: RwLock<Decoder>,
    decoder_dynamic_table: bool,
    allows_blocking: bool,
    max_encoded_string_size: usize,
    decoder_events_send: mpsc::UnboundedSender<QpackEvent>,
    /// Connection-driver waker used while a request holds a read guard.
    write_waker: AtomicWaker,
}

/// Shared QPACK decoder state for a single HTTP/3 connection.
///
/// Request tasks use read guards to decode field sections. The connection driver
/// takes a write guard for dynamic table updates and resumes when active readers
/// release their guards.
#[derive(Clone)]
pub(crate) struct QpackDecoder(Arc<QpackDecoderInner>);

impl QpackDecoder {
    /// Creates the connection's shared decoder.
    ///
    /// `decoder_events_send` carries decoder-stream work and request wakers to
    /// the connection driver.
    #[inline(always)]
    pub(crate) fn new(
        decoder: Decoder,
        decoder_events_send: mpsc::UnboundedSender<QpackEvent>,
    ) -> Self {
        QpackDecoder(Arc::new(QpackDecoderInner {
            decoder_dynamic_table: decoder.dynamic_table_enabled(),
            allows_blocking: decoder.max_blocked_streams() != 0,
            max_encoded_string_size: decoder.max_encoded_string_size(),
            decoder: RwLock::new(decoder),
            decoder_events_send,
            write_waker: AtomicWaker::new(),
        }))
    }

    /// Returns whether the peer is permitted to use dynamic table references.
    ///
    /// This is fixed from the advertised maximum table capacity when the
    /// connection is created. It does not indicate whether the table currently
    /// contains entries or whether its current capacity was later reduced to zero.
    ///
    /// See [RFC 9204, Section 3.2.3](https://www.rfc-editor.org/rfc/rfc9204.html#section-3.2.3).
    pub(crate) fn dynamic_table_enabled(&self) -> bool {
        self.0.decoder_dynamic_table
    }

    /// Queues a blocked field section for the connection driver.
    ///
    /// The driver owns blocked-stream accounting and wakes the request when its
    /// Required Insert Count is available. A delayed registration is compared
    /// with the current Insert Count, so an earlier encoder update cannot leave
    /// the request asleep.
    ///
    /// See [RFC 9204, Section 2.1.2](https://www.rfc-editor.org/rfc/rfc9204.html#section-2.1.2)
    /// and [Section 2.2.1](https://www.rfc-editor.org/rfc/rfc9204.html#section-2.2.1).
    pub(crate) fn queue_blocked_stream(
        &self,
        stream_id: StreamId,
        required_ref: usize,
        waker: &Waker,
    ) -> Result<(), DecoderError> {
        // A zero advertised limit leaves no legal blocked field section to
        // register. Reject it synchronously; this also avoids waiting for a
        // connection driver while a sequential server resolves the request.
        if !self.0.allows_blocking {
            return Err(DecoderError::TooManyBlockedStreams);
        }

        self.0
            .decoder_events_send
            .send(QpackEvent::RegisterBlocked {
                stream_id,
                required_ref,
                waker: waker.clone(),
            })
            .map_err(|_| DecoderError::Internal("QPACK decoder event channel is closed"))?;
        #[cfg(feature = "tracing")]
        tracing::debug!(
            stream_id = ?stream_id,
            required_ref,
            "queued blocked QPACK field section"
        );
        Ok(())
    }

    /// Queues removal of a blocked field section from the driver registry.
    ///
    /// An encoder-stream update may release the entry before the request runs
    /// again, so removal is idempotent.
    ///
    /// See [RFC 9204, Section 2.2.1](https://www.rfc-editor.org/rfc/rfc9204.html#section-2.2.1).
    pub(crate) fn release_blocked_stream(&self, stream_id: StreamId, required_ref: usize) -> bool {
        let queued = self
            .0
            .decoder_events_send
            .send(QpackEvent::ReleaseBlocked {
                stream_id,
                required_ref,
            })
            .is_ok();
        #[cfg(feature = "tracing")]
        if queued {
            tracing::debug!(
                stream_id = ?stream_id,
                required_ref,
                "queued blocked QPACK field section release"
            );
        }
        queued
    }

    /// Queues a Section Acknowledgment for the connection driver to send.
    ///
    /// The caller uses this after successfully processing a field section whose
    /// Required Insert Count is non-zero. The driver serializes the instruction
    /// onto the connection's QPACK decoder stream.
    ///
    /// See [RFC 9204, Section 4.4.1](https://www.rfc-editor.org/rfc/rfc9204.html#section-4.4.1).
    pub(crate) fn queue_section_acknowledgment(
        &self,
        stream_id: StreamId,
    ) -> Result<(), DecoderError> {
        self.0
            .decoder_events_send
            .send(QpackEvent::HeaderAck(stream_id))
            .map_err(|_| DecoderError::Internal("QPACK decoder event channel is closed"))?;
        #[cfg(feature = "tracing")]
        tracing::debug!(
            stream_id = ?stream_id,
            "queued QPACK section acknowledgment"
        );
        Ok(())
    }

    /// Queues a Stream Cancellation for the connection driver to send.
    ///
    /// This is used when a request stream is reset or its remaining field
    /// sections are no longer being read. Returns `true` when the event was
    /// accepted by the driver channel.
    ///
    /// See [RFC 9204, Section 4.4.2](https://www.rfc-editor.org/rfc/rfc9204.html#section-4.4.2).
    pub(crate) fn queue_stream_cancellation(&self, stream_id: StreamId) -> bool {
        let queued = self
            .0
            .decoder_events_send
            .send(QpackEvent::StreamCancel(stream_id))
            .is_ok();
        #[cfg(feature = "tracing")]
        if queued {
            tracing::debug!(
                stream_id = ?stream_id,
                "queued QPACK stream cancellation"
            );
        }
        queued
    }

    /// Applies instructions received on the peer QPACK encoder stream.
    ///
    /// Updating the dynamic table requires exclusive decoder access. If a request
    /// holds a read guard, the connection driver registers its waker and returns
    /// [`Poll::Pending`]. It retries the lock after registration in case the last
    /// reader finished in between.
    pub(crate) fn poll_on_recv_encoder<R: Buf + Clone, W: BufMut>(
        &self,
        cx: &mut Context<'_>,
        read: &mut R,
        write: &mut W,
    ) -> Poll<Result<usize, DecoderError>> {
        match self.0.decoder.try_write() {
            Ok(mut decoder) => return Poll::Ready(decoder.on_encoder_recv_buffered(read, write)),
            Err(TryLockError::WouldBlock) => {}
            _ => {
                return Poll::Ready(Err(DecoderError::Internal(
                    "QPACK decoder lock is poisoned",
                )));
            }
        }

        // The last reader may finish between the first attempt and registration.
        self.0.write_waker.register(cx.waker());

        match self.0.decoder.try_write() {
            Ok(mut decoder) => Poll::Ready(decoder.on_encoder_recv_buffered(read, write)),
            Err(TryLockError::WouldBlock) => Poll::Pending,
            _ => Poll::Ready(Err(DecoderError::Internal(
                "QPACK decoder lock is poisoned",
            ))),
        }
    }

    /// Releases a decode guard and wakes a driver waiting to update the table.
    fn finish_decode(
        &self,
        decoder: RwLockReadGuard<'_, Decoder>,
        decoded: Result<Decoded, DecoderError>,
    ) -> Poll<Result<Decoded, DecoderError>> {
        // A driver blocked in poll_on_recv_encoder can continue after the guard drops.
        drop(decoder);
        self.0.write_waker.wake();
        Poll::Ready(decoded)
    }

    /// Decodes one QPACK field section.
    ///
    /// When dynamic table support is disabled, decoding needs no shared table or
    /// lock. Otherwise, request tasks take read guards and may decode concurrently.
    ///
    /// [`DecoderError::MissingRefs`] contains the Required Insert Count used to
    /// register the request with the connection driver. A direct [`Poll::Pending`]
    /// means that the driver currently holds the write lock.
    ///
    /// See [RFC 9204, Section 2.2.1](https://www.rfc-editor.org/rfc/rfc9204.html#section-2.2.1).
    pub(crate) fn poll_decode_field_section<T: Buf>(
        &self,
        cx: &mut Context<'_>,
        field_section: &mut T,
        max_field_section_size: u64,
        prefix: &mut Option<FieldSectionPrefix>,
    ) -> Poll<Result<Decoded, DecoderError>> {
        if !self.0.decoder_dynamic_table {
            return Poll::Ready(decode_stateless_limited(
                field_section,
                max_field_section_size,
                self.0.max_encoded_string_size,
            ));
        }

        match self.0.decoder.try_read() {
            Ok(decoder) => {
                let decoded =
                    decoder.decode_header_limited(field_section, max_field_section_size, prefix);
                return self.finish_decode(decoder, decoded);
            }
            Err(TryLockError::WouldBlock) => {}
            _ => {
                return Poll::Ready(Err(DecoderError::Internal(
                    "QPACK decoder lock is poisoned",
                )));
            }
        }

        // Register before retrying; the writer drains this queue after its update.
        if self
            .0
            .decoder_events_send
            .send(QpackEvent::DecoderAccessWaker(cx.waker().clone()))
            .is_err()
        {
            return Poll::Ready(Err(DecoderError::Internal(
                "QPACK decoder event channel is closed",
            )));
        }
        #[cfg(feature = "tracing")]
        tracing::debug!("queued QPACK decoder waiter for decoder write lock");

        match self.0.decoder.try_read() {
            Ok(decoder) => {
                let decoded =
                    decoder.decode_header_limited(field_section, max_field_section_size, prefix);
                self.finish_decode(decoder, decoded)
            }
            Err(TryLockError::WouldBlock) => Poll::Pending,
            _ => Poll::Ready(Err(DecoderError::Internal(
                "QPACK decoder lock is poisoned",
            ))),
        }
    }
}

#[cfg(test)]
mod shared_encoder_tests {
    use std::io::Cursor;

    use bytes::BytesMut;

    use super::{
        HeaderField, QpackEncoder,
        block::HeaderPrefix,
        stream::{DynamicTableSizeUpdate, InsertCountIncrement},
    };
    use crate::quic::StreamId;

    #[test]
    fn dynamic_encoder_waits_for_settings_instructions_to_drain() {
        let encoder = QpackEncoder::default();
        encoder.configure(256, 256).unwrap();

        let mut stateless = BytesMut::new();
        encoder
            .encode(
                StreamId(0),
                &mut stateless,
                [HeaderField::borrowed(b"custom", b"value", false)],
            )
            .unwrap();
        assert_eq!(
            HeaderPrefix::decode(&mut Cursor::new(stateless.freeze()))
                .unwrap()
                .get(0, 0),
            Ok((0, 0))
        );

        let mut instructions = Cursor::new(encoder.take_pending_instructions().unwrap());
        assert_eq!(
            DynamicTableSizeUpdate::decode(&mut instructions),
            Ok(Some(DynamicTableSizeUpdate(256)))
        );

        let mut prewarm = BytesMut::new();
        let encoder_instructions_queued = encoder
            .encode(
                StreamId(0),
                &mut prewarm,
                [HeaderField::borrowed(b"custom", b"value", false)],
            )
            .unwrap();
        assert!(encoder_instructions_queued);
        assert_eq!(
            HeaderPrefix::decode(&mut Cursor::new(prewarm.freeze()))
                .unwrap()
                .get(0, 256),
            Ok((0, 0))
        );

        let _instructions = encoder.take_pending_instructions().unwrap();
        let mut increment = Vec::new();
        InsertCountIncrement(1).encode(&mut increment);
        encoder
            .on_decoder_recv_buffered(&mut Cursor::new(increment))
            .unwrap();

        let mut dynamic = BytesMut::new();
        let encoder_instructions_queued = encoder
            .encode(
                StreamId(4),
                &mut dynamic,
                [HeaderField::borrowed(b"custom", b"value", false)],
            )
            .unwrap();
        assert!(!encoder_instructions_queued);
        assert_eq!(
            HeaderPrefix::decode(&mut Cursor::new(dynamic.freeze()))
                .unwrap()
                .get(1, 256),
            Ok((1, 1))
        );
    }
}
