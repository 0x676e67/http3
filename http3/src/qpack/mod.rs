use std::{
    collections::BTreeMap,
    sync::{Arc, RwLock, RwLockReadGuard, TryLockError},
    task::{Context, Poll, Waker},
};

use bytes::{Buf, BufMut};
use futures_util::task::AtomicWaker;
use tokio::sync::mpsc;

pub(crate) use self::encoder::Encoder;
pub use self::{
    decoder::{Decoded, Decoder, DecoderError, ack_header, decode_stateless, stream_canceled},
    encoder::{EncoderError, encode_stateless},
    field::HeaderField,
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
    /// See [RFC 9204, Section 2.1.2](https://www.rfc-editor.org/rfc/rfc9204.html#section-2.1.2)
    /// and [Section 2.2.1](https://www.rfc-editor.org/rfc/rfc9204.html#section-2.2.1).
    pub(crate) fn register(
        &mut self,
        stream_id: StreamId,
        required_ref: usize,
        waker: Waker,
    ) -> Result<(), DecoderError> {
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
            waker.wake();
            return Err(DecoderError::TooManyBlockedStreams);
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
}

struct QpackDecoderInner {
    decoder: RwLock<Decoder>,
    decoder_dynamic_table: bool,
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
        self.0
            .decoder_events_send
            .send(QpackEvent::RegisterBlocked {
                stream_id,
                required_ref,
                waker: waker.clone(),
            })
            .map_err(|_| DecoderError::UnexpectedEnd)?;
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
            .map_err(|_| DecoderError::UnexpectedEnd)?;
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
            _ => return Poll::Ready(Err(DecoderError::UnexpectedEnd)),
        }

        // The last reader may finish between the first attempt and registration.
        self.0.write_waker.register(cx.waker());

        match self.0.decoder.try_write() {
            Ok(mut decoder) => Poll::Ready(decoder.on_encoder_recv_buffered(read, write)),
            Err(TryLockError::WouldBlock) => Poll::Pending,
            _ => Poll::Ready(Err(DecoderError::UnexpectedEnd)),
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
    pub(crate) fn poll_decode_header<T: Buf>(
        &self,
        cx: &mut Context<'_>,
        encoded: &mut T,
        max_size: u64,
    ) -> Poll<Result<Decoded, DecoderError>> {
        if !self.0.decoder_dynamic_table {
            return Poll::Ready(decode_stateless(encoded, max_size));
        }

        match self.0.decoder.try_read() {
            Ok(decoder) => {
                let decoded = decoder.decode_header_limited(encoded, max_size);
                return self.finish_decode(decoder, decoded);
            }
            Err(TryLockError::WouldBlock) => {}
            _ => return Poll::Ready(Err(DecoderError::UnexpectedEnd)),
        }

        // Register before retrying; the writer drains this queue after its update.
        if self
            .0
            .decoder_events_send
            .send(QpackEvent::DecoderAccessWaker(cx.waker().clone()))
            .is_err()
        {
            return Poll::Ready(Err(DecoderError::UnexpectedEnd));
        }
        #[cfg(feature = "tracing")]
        tracing::debug!("queued QPACK decoder waiter for decoder write lock");

        match self.0.decoder.try_read() {
            Ok(decoder) => {
                let decoded = decoder.decode_header_limited(encoded, max_size);
                self.finish_decode(decoder, decoded)
            }
            Err(TryLockError::WouldBlock) => Poll::Pending,
            _ => Poll::Ready(Err(DecoderError::UnexpectedEnd)),
        }
    }
}
