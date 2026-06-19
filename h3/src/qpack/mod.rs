use crate::quic::StreamId;

pub use self::{
    decoder::{ack_header, decode_stateless, stream_canceled, Decoded, Decoder, DecoderError},
    encoder::{encode_stateless, EncoderError},
    field::HeaderField,
};

use std::{
    sync::{RwLock, RwLockReadGuard, TryLockError},
    task::{Context, Poll, Waker},
};

use bytes::{Buf, BufMut};
use futures_util::task::AtomicWaker;
use tokio::sync::mpsc;

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

/// Event emitted by request streams for QPACK decoder stream instructions.
#[derive(Debug)]
pub(crate) enum QpackEvent {
    HeaderAck(StreamId),
    StreamCancel(StreamId),
    Waker(Waker),
}

/// Shared QPACK decoder state for a single HTTP/3 connection.
///
/// The decoder is read-mostly: header blocks decode through read guards, while the
/// connection driver updates the dynamic table through a write guard. Request wakers
/// wait for dynamic-table updates; the writer waker lets the driver resume after active
/// decodes release their read guards.
pub(crate) struct QpackDecoder {
    decoder: RwLock<Decoder>,
    /// Request wakers consumed by the connection driver after an encoder update.
    events_send: mpsc::UnboundedSender<QpackEvent>,
    /// Connection-driver waker used while a request holds a read guard.
    write_waker: AtomicWaker,
}

impl QpackDecoder {
    /// Creates the connection's shared decoder.
    ///
    /// `decoder_waker` sends blocked request wakers to the connection driver. The
    /// receiving side is kept with the connection's QPACK streams.
    #[inline(always)]
    pub(crate) fn new(decoder: Decoder, events_send: mpsc::UnboundedSender<QpackEvent>) -> Self {
        QpackDecoder {
            decoder: RwLock::new(decoder),
            events_send,
            write_waker: AtomicWaker::new(),
        }
    }

    /// Applies instructions received on the peer QPACK encoder stream.
    ///
    /// Updating the dynamic table requires exclusive access to the decoder. If a
    /// request is decoding a field section, this registers the connection driver
    /// and returns [`Poll::Pending`]. The second lock attempt closes the gap between
    /// the failed first attempt and waker registration.
    pub(crate) fn poll_on_recv_encoder<R: Buf, W: BufMut>(
        &self,
        cx: &mut Context<'_>,
        read: &mut R,
        write: &mut W,
    ) -> Poll<Result<usize, DecoderError>> {
        match self.decoder.try_write() {
            Ok(mut decoder) => return Poll::Ready(decoder.on_encoder_recv(read, write)),
            Err(TryLockError::WouldBlock) => {}
            _ => return Poll::Ready(Err(DecoderError::UnexpectedEnd)),
        }

        // A reader may finish between the first attempt and registration.
        self.write_waker.register(cx.waker());

        match self.decoder.try_write() {
            Ok(mut decoder) => Poll::Ready(decoder.on_encoder_recv(read, write)),
            Err(TryLockError::WouldBlock) => Poll::Pending,
            _ => Poll::Ready(Err(DecoderError::UnexpectedEnd)),
        }
    }

    /// Releases a decode guard and wakes a driver waiting to update the table.
    ///
    /// A field section with missing references must also register its request task.
    /// `waiter_registered` is true when registration already happened while waiting
    /// for the read lock.
    fn finish_decode(
        &self,
        cx: &Context<'_>,
        decoder: RwLockReadGuard<'_, Decoder>,
        decoded: Result<Decoded, DecoderError>,
        waiter_registered: bool,
    ) -> Poll<Result<Decoded, DecoderError>> {
        if matches!(&decoded, Err(DecoderError::MissingRefs(_))) && !waiter_registered {
            // Register while the read guard still prevents an encoder update. This
            // keeps the driver from updating the table before the waiter is visible.
            if self
                .events_send
                .send(QpackEvent::Waker(cx.waker().clone()))
                .is_err()
            {
                return Poll::Ready(Err(DecoderError::UnexpectedEnd));
            }
        }

        // A writer blocked in poll_on_recv_encoder can continue once the guard drops.
        drop(decoder);
        self.write_waker.wake();
        Poll::Ready(decoded)
    }

    /// Decodes one QPACK field section.
    ///
    /// Stateless decoding is used when dynamic-table support is disabled. Otherwise
    /// the decoder is read-locked so request tasks can decode concurrently while the
    /// connection driver is idle.
    ///
    /// [`DecoderError::MissingRefs`] is returned after the request waker has been
    /// queued. The caller turns that result into [`Poll::Pending`] and restores the
    /// encoded input, since decoding may advance it before reporting the missing
    /// references. A direct [`Poll::Pending`] means the encoder stream currently owns
    /// the write lock.
    pub(crate) fn poll_decode_header<T: Buf>(
        &self,
        cx: &mut Context<'_>,
        encoded: &mut T,
        max_size: u64,
        use_dynamic_table: bool,
    ) -> Poll<Result<Decoded, DecoderError>> {
        if !use_dynamic_table {
            return Poll::Ready(decode_stateless(encoded, max_size));
        }

        match self.decoder.try_read() {
            Ok(decoder) => {
                let decoded = decoder.decode_header_limited(encoded, max_size);
                return self.finish_decode(cx, decoder, decoded, false);
            }
            Err(TryLockError::WouldBlock) => {}
            _ => return Poll::Ready(Err(DecoderError::UnexpectedEnd)),
        }

        // Register before retrying; the writer drains this queue after its update.
        if self
            .events_send
            .send(QpackEvent::Waker(cx.waker().clone()))
            .is_err()
        {
            return Poll::Ready(Err(DecoderError::UnexpectedEnd));
        }

        match self.decoder.try_read() {
            Ok(decoder) => {
                let decoded = decoder.decode_header_limited(encoded, max_size);
                self.finish_decode(cx, decoder, decoded, true)
            }
            Err(TryLockError::WouldBlock) => Poll::Pending,
            _ => Poll::Ready(Err(DecoderError::UnexpectedEnd)),
        }
    }
}
