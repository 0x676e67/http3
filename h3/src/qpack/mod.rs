pub use self::{
    decoder::{ack_header, decode_stateless, stream_canceled, Decoded, Decoder, DecoderError},
    encoder::{encode_stateless, EncoderError},
    field::HeaderField,
};

use std::{
    sync::{RwLock, TryLockError},
    task::{Context, Poll, Waker},
};

use bytes::{Buf, BufMut};
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
pub(crate) enum QpackDecoderEvent {
    HeaderAck(u64),
    StreamCancel(u64),
}

/// Shared QPACK decoder state for a single HTTP/3 connection.
///
/// The decoder is read-mostly: header blocks decode through read guards, while the
/// peer encoder stream updates the dynamic table through a write guard.
pub(crate) struct QpackDecoder {
    decoder: RwLock<Decoder>,
    decoder_waker: mpsc::UnboundedSender<Waker>,
}

impl QpackDecoder {
    /// Creates a new [`QpackDecoder`] instance.
    #[inline(always)]
    pub(crate) fn new(decoder: Decoder, decoder_waker: mpsc::UnboundedSender<Waker>) -> Self {
        QpackDecoder {
            decoder: RwLock::new(decoder),
            decoder_waker,
        }
    }

    /// Processes bytes received from the peer QPACK encoder stream.
    ///
    /// Returns `Poll::Pending` when a header decode currently holds a read lock;
    /// the provided waker is registered and will be woken once a write may make progress.
    pub(crate) fn poll_on_recv_encoder<R: Buf, W: BufMut>(
        &self,
        read: &mut R,
        write: &mut W,
    ) -> Poll<Result<usize, DecoderError>> {
        match self.decoder.try_write() {
            Ok(mut decoder) => Poll::Ready(decoder.on_encoder_recv(read, write)),
            Err(TryLockError::WouldBlock) => Poll::Pending,
            Err(TryLockError::Poisoned(_)) => Poll::Ready(Err(DecoderError::UnexpectedEnd)),
        }
    }

    /// Decodes a header block and tracks decoder stream instructions for it.
    ///
    /// When `use_dynamic_table` is `false`, no lock is acquired and dynamic table
    /// references are rejected by `decode_stateless`.
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

        // 1. First attempt: Try to acquire the read lock immediately.
        match self.decoder.try_read() {
            Ok(decoder) => {
                match decoder.decode_header_limited(encoded, max_size) {
                    // The read lock was acquired, but decoding requires dynamic table entries
                    // that have not yet been received from the peer encoder stream.
                    Err(DecoderError::MissingRefs(_)) => {
                        // Enqueue the cloned waker into the mpsc channel so the connection driver
                        // can wake this task once the dynamic table is updated.
                        let _ = self.decoder_waker.send(cx.waker().clone());

                        // Double-check: The driver might have released the write lock and updated
                        // the dynamic table right between the decoding failure and waker registration.
                        match self.decoder.try_read() {
                            Ok(retry_decoder) => {
                                match retry_decoder.decode_header_limited(encoded, max_size) {
                                    // If it still results in missing references even though the lock is now available,
                                    // we can safely yield Pending since our waker is already queued in the channel.
                                    Err(DecoderError::MissingRefs(_)) => {
                                        // Still missing references. Yield Pending safely.
                                        Poll::Pending
                                    }
                                    other => Poll::Ready(other),
                                }
                            }
                            Err(_) => Poll::Pending,
                        }
                    }
                    // Return successfully decoded headers or unrecoverable hard errors immediately.
                    other => Poll::Ready(other),
                }
            }
            Err(TryLockError::WouldBlock) => {
                // 2. Lock contention: The encoder stream is currently updating the dynamic table
                // and holding the write lock. Register before retrying so a write-lock release
                // cannot be missed between attempts.
                let _ = self.decoder_waker.send(cx.waker().clone());

                // 3. Double-check under lock contention scenario.
                match self.decoder.try_read() {
                    Ok(decoder) => {
                        match decoder.decode_header_limited(encoded, max_size) {
                            // If it still results in missing references even though the lock is now available,
                            // we can safely yield Pending since our waker is already queued in the channel.
                            Err(DecoderError::MissingRefs(_)) => Poll::Pending,
                            other => Poll::Ready(other),
                        }
                    }
                    Err(TryLockError::WouldBlock) => {
                        // Still blocked by the write lock. The registered waker will be notified
                        // when the connection driver releases the write lock and flushes the channel.
                        Poll::Pending
                    }
                    Err(TryLockError::Poisoned(_)) => Poll::Ready(Err(DecoderError::UnexpectedEnd)),
                }
            }
            Err(TryLockError::Poisoned(_)) => return Poll::Ready(Err(DecoderError::UnexpectedEnd)),
        }
    }
}
