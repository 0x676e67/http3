pub use self::{
    decoder::{Decoded, Decoder, DecoderError, ack_header, decode_stateless, stream_canceled},
    encoder::{EncoderError, encode_stateless},
    field::HeaderField,
};

use std::{
    sync::{Arc, RwLock, TryLockError},
    task::{Context, Poll},
};

use bytes::{Buf, BufMut};
use futures_util::task::AtomicWaker;
use tokio::sync::mpsc;

use crate::shared_state::{ConnectionState, SharedState};

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
pub(crate) enum QpackDecoderEvent {
    HeaderAck(u64),
    StreamCancel(u64),
}

struct QpackDecoderInner {
    decoder: RwLock<Decoder>,
    decoder_events: mpsc::UnboundedSender<QpackDecoderEvent>,
    read_waker: AtomicWaker,
    write_waker: AtomicWaker,
}

/// Shared QPACK decoder state for a single HTTP/3 connection.
///
/// The decoder is read-mostly: header blocks decode through read guards, while the
/// peer encoder stream updates the dynamic table through a write guard.
pub(crate) struct QpackDecoder {
    inner: Arc<QpackDecoderInner>,
    stream_state: Option<QpackDecoderStreamState>,
}

/// Per-stream QPACK decoder state used to emit decoder stream instructions.
struct QpackDecoderStreamState {
    stream_id: u64,
    shared: Arc<SharedState>,
    cancel_on_drop: bool,
}

impl Clone for QpackDecoder {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            stream_state: None,
        }
    }
}

impl Drop for QpackDecoder {
    fn drop(&mut self) {
        if let Some(stream_state) = &self.stream_state {
            if stream_state.cancel_on_drop
                && self
                    .inner
                    .decoder_events
                    .send(QpackDecoderEvent::StreamCancel(stream_state.stream_id))
                    .is_ok()
            {
                stream_state.shared.waker().wake();
            }
        }
    }
}

impl QpackDecoder {
    /// Creates a new [`QpackDecoder`] instance.
    #[inline(always)]
    pub(crate) fn new(
        decoder: Decoder,
        decoder_events: mpsc::UnboundedSender<QpackDecoderEvent>,
    ) -> Self {
        Self {
            inner: Arc::new(QpackDecoderInner {
                decoder: RwLock::new(decoder),
                decoder_events,
                read_waker: AtomicWaker::new(),
                write_waker: AtomicWaker::new(),
            }),
            stream_state: None,
        }
    }

    /// Returns a stream-scoped decoder handle that tracks decoder stream instructions.
    #[inline(always)]
    pub(crate) fn track_stream(mut self, stream_id: u64, shared: Arc<SharedState>) -> Self {
        self.stream_state = Some(QpackDecoderStreamState {
            stream_id,
            shared,
            // Until the header block is successfully decoded, dropping the tracked
            // stream abandons it and must notify the peer encoder.
            cancel_on_drop: true,
        });
        self
    }

    /// Processes bytes received from the peer QPACK encoder stream.
    ///
    /// Returns `Poll::Pending` when a header decode currently holds a read lock;
    /// the provided waker is registered and will be woken once a write may make progress.
    pub(crate) fn poll_on_recv_encoder<R: Buf, W: BufMut>(
        &self,
        cx: &mut Context<'_>,
        read: &mut R,
        write: &mut W,
    ) -> Poll<Result<usize, DecoderError>> {
        match self.inner.decoder.try_write() {
            Ok(mut decoder) => {
                let result = decoder.on_encoder_recv(read, write);
                drop(decoder);
                self.inner.read_waker.wake();
                Poll::Ready(result)
            }
            Err(TryLockError::WouldBlock) => {
                // A header decode is holding a read lock. Register before retrying
                // so a read-lock release cannot be missed between attempts.
                self.inner.write_waker.register(cx.waker());
                match self.inner.decoder.try_write() {
                    Ok(mut decoder) => {
                        // The read lock was released after registration; process now
                        // instead of returning Pending and waiting for another wake.
                        let result = decoder.on_encoder_recv(read, write);
                        drop(decoder);
                        self.inner.read_waker.wake();
                        Poll::Ready(result)
                    }
                    Err(TryLockError::WouldBlock) => {
                        // Still blocked. The registered waker will be notified when
                        // the current readers release the decoder.
                        Poll::Pending
                    }
                    Err(TryLockError::Poisoned(_)) => Poll::Ready(Err(DecoderError::UnexpectedEnd)),
                }
            }
            Err(TryLockError::Poisoned(_)) => Poll::Ready(Err(DecoderError::UnexpectedEnd)),
        }
    }

    /// Decodes a header block and tracks decoder stream instructions for it.
    ///
    /// When `use_dynamic_table` is `false`, no lock is acquired and dynamic table
    /// references are rejected by `decode_stateless`.
    pub(crate) fn poll_decode_header<T: Buf>(
        &mut self,
        cx: &mut Context<'_>,
        encoded: &mut T,
        max_size: u64,
        use_dynamic_table: bool,
    ) -> Poll<Result<Decoded, DecoderError>> {
        if !use_dynamic_table {
            return Poll::Ready(decode_stateless(encoded, max_size));
        }

        let decoded = match self.inner.decoder.try_read() {
            Ok(decoder) => {
                let decoded = decoder.decode_header_limited(encoded, max_size);
                drop(decoder);
                self.inner.write_waker.wake();
                decoded
            }
            Err(TryLockError::WouldBlock) => {
                // The encoder stream is updating the dynamic table. Register before
                // retrying so a write-lock release cannot be missed between attempts.
                self.inner.read_waker.register(cx.waker());
                match self.inner.decoder.try_read() {
                    Ok(decoder) => {
                        // The write lock was released after registration; decode now
                        // instead of returning Pending and waiting for another wake.
                        let decoded = decoder.decode_header_limited(encoded, max_size);
                        drop(decoder);
                        self.inner.write_waker.wake();
                        decoded
                    }
                    Err(TryLockError::WouldBlock) => {
                        // Still blocked. The registered waker will be notified when
                        // the writer releases the decoder.
                        return Poll::Pending;
                    }
                    Err(TryLockError::Poisoned(_)) => {
                        return Poll::Ready(Err(DecoderError::UnexpectedEnd));
                    }
                }
            }
            Err(TryLockError::Poisoned(_)) => return Poll::Ready(Err(DecoderError::UnexpectedEnd)),
        };

        let decoded = match decoded {
            Ok(decoded) => decoded,
            Err(error @ DecoderError::MissingRefs(required_ref)) => {
                if required_ref > 0 {
                    if let Some(stream_state) = &mut self.stream_state {
                        stream_state.cancel_on_drop = true;
                    }
                }
                return Poll::Ready(Err(error));
            }
            Err(error) => return Poll::Ready(Err(error)),
        };

        if let Some(stream_state) = &mut self.stream_state {
            stream_state.cancel_on_drop = false;
            if decoded.dyn_ref {
                if self
                    .inner
                    .decoder_events
                    .send(QpackDecoderEvent::HeaderAck(stream_state.stream_id))
                    .is_err()
                {
                    return Poll::Ready(Err(DecoderError::UnexpectedEnd));
                }
                stream_state.shared.waker().wake();
            }
        }

        Poll::Ready(Ok(decoded))
    }
}
