pub use self::{
    decoder::{ack_header, decode_stateless, stream_canceled, Decoded, Decoder, DecoderError},
    encoder::{encode_stateless, EncoderError},
    field::HeaderField,
};

use std::{
    sync::{Arc, RwLock, TryLockError},
    task::{ready, Context, Poll},
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
            if stream_state.cancel_on_drop {
                if self
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
            cancel_on_drop: false,
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
        let mut decoder = match self.inner.decoder.try_write() {
            Ok(guard) => guard,
            Err(TryLockError::WouldBlock) => {
                self.inner.write_waker.register(cx.waker());
                match self.inner.decoder.try_write() {
                    Ok(guard) => guard,
                    Err(TryLockError::WouldBlock) => return Poll::Pending,
                    Err(TryLockError::Poisoned(_)) => {
                        return Poll::Ready(Err(DecoderError::UnexpectedEnd))
                    }
                }
            }
            Err(TryLockError::Poisoned(_)) => return Poll::Ready(Err(DecoderError::UnexpectedEnd)),
        };

        let result = decoder.on_encoder_recv(read, write);
        drop(decoder);
        self.inner.read_waker.wake();

        Poll::Ready(result)
    }

    /// Decodes a header block using either stateless QPACK or the dynamic table.
    ///
    /// When `use_dynamic_table` is `false`, no lock is acquired and dynamic table
    /// references are rejected by `decode_stateless`.
    pub(crate) fn poll_decode_header_limited<T: Buf>(
        &self,
        cx: &mut Context<'_>,
        encoded: &mut T,
        max_size: u64,
        use_dynamic_table: bool,
    ) -> Poll<Result<Decoded, DecoderError>> {
        if !use_dynamic_table {
            return Poll::Ready(decode_stateless(encoded, max_size));
        }

        let decoder = match self.inner.decoder.try_read() {
            Ok(guard) => guard,
            Err(TryLockError::WouldBlock) => {
                self.inner.read_waker.register(cx.waker());
                match self.inner.decoder.try_read() {
                    Ok(guard) => guard,
                    Err(TryLockError::WouldBlock) => return Poll::Pending,
                    Err(TryLockError::Poisoned(_)) => {
                        return Poll::Ready(Err(DecoderError::UnexpectedEnd))
                    }
                }
            }
            Err(TryLockError::Poisoned(_)) => return Poll::Ready(Err(DecoderError::UnexpectedEnd)),
        };

        let decoded = decoder.decode_header_limited(encoded, max_size);
        drop(decoder);
        self.inner.write_waker.wake();

        Poll::Ready(decoded)
    }

    /// Decodes a header block and tracks decoder stream instructions for it.
    pub(crate) fn poll_decode_header_limited_tracked<T: Buf>(
        &mut self,
        cx: &mut Context<'_>,
        encoded: &mut T,
        max_size: u64,
        use_dynamic_table: bool,
    ) -> Poll<Result<Decoded, DecoderError>> {
        let decoded = match ready!(self.poll_decode_header_limited(
            cx,
            encoded,
            max_size,
            use_dynamic_table,
        )) {
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
