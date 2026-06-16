pub use self::{
    decoder::{ack_header, decode_stateless, stream_canceled, Decoded, Decoder, DecoderError},
    encoder::{encode_stateless, EncoderError},
    field::HeaderField,
};

use std::{
    ops::{Deref, DerefMut},
    sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard, TryLockError},
    task::Context,
};

use futures_util::task::AtomicWaker;

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

struct DecoderState {
    decoder: RwLock<Decoder>,
    read_waker: AtomicWaker,
    write_waker: AtomicWaker,
}

/// Shared QPACK decoder state for a single HTTP/3 connection.
///
/// The decoder is read-mostly: header blocks decode through read guards, while the
/// peer encoder stream updates the dynamic table through a write guard.
#[derive(Clone)]
pub(crate) struct QpackDecoder(Arc<DecoderState>);

/// Read guard for QPACK header block decoding.
///
/// Dropping the guard wakes any task waiting to process encoder stream updates.
pub(crate) struct QpackDecoderReadGuard<'a> {
    guard: Option<RwLockReadGuard<'a, Decoder>>,
    state: Arc<DecoderState>,
}

/// Write guard for QPACK encoder stream processing.
///
/// Dropping the guard wakes any task waiting to decode header blocks.
pub(crate) struct QpackDecoderWriteGuard<'a> {
    guard: RwLockWriteGuard<'a, Decoder>,
    state: Arc<DecoderState>,
}

impl Deref for QpackDecoderReadGuard<'_> {
    type Target = Decoder;

    #[inline(always)]
    fn deref(&self) -> &Self::Target {
        self.guard
            .as_deref()
            .expect("QPACK decoder read guard is present")
    }
}

impl Drop for QpackDecoderReadGuard<'_> {
    fn drop(&mut self) {
        let _ = self.guard.take();
        self.state.write_waker.wake();
    }
}

impl Deref for QpackDecoderWriteGuard<'_> {
    type Target = Decoder;

    #[inline(always)]
    fn deref(&self) -> &Self::Target {
        &self.guard
    }
}

impl DerefMut for QpackDecoderWriteGuard<'_> {
    #[inline(always)]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.guard
    }
}

impl Drop for QpackDecoderWriteGuard<'_> {
    fn drop(&mut self) {
        self.state.read_waker.wake();
    }
}

impl QpackDecoder {
    /// Wraps a connection-owned QPACK decoder in shared read/write state.
    #[inline(always)]
    pub(crate) fn new(decoder: Decoder) -> Self {
        Self(Arc::new(DecoderState {
            decoder: RwLock::new(decoder),
            read_waker: AtomicWaker::new(),
            write_waker: AtomicWaker::new(),
        }))
    }

    /// Attempts to acquire a read guard without blocking the current task.
    ///
    /// If a writer currently holds the decoder, the provided waker is registered
    /// and `Ok(None)` is returned.
    #[inline(always)]
    pub(crate) fn try_read(
        &self,
        cx: &mut Context<'_>,
    ) -> Result<Option<QpackDecoderReadGuard<'_>>, DecoderError> {
        match self.0.decoder.try_read() {
            Ok(guard) => Ok(Some(QpackDecoderReadGuard {
                guard: Some(guard),
                state: self.0.clone(),
            })),
            Err(TryLockError::WouldBlock) => {
                self.0.read_waker.register(cx.waker());
                match self.0.decoder.try_read() {
                    Ok(guard) => Ok(Some(QpackDecoderReadGuard {
                        guard: Some(guard),
                        state: self.0.clone(),
                    })),
                    Err(TryLockError::WouldBlock) => Ok(None),
                    Err(TryLockError::Poisoned(_)) => Err(DecoderError::UnexpectedEnd),
                }
            }
            Err(TryLockError::Poisoned(_)) => Err(DecoderError::UnexpectedEnd),
        }
    }

    /// Attempts to acquire a write guard without blocking the current task.
    ///
    /// If readers currently hold the decoder, the provided waker is registered
    /// and `Ok(None)` is returned.
    #[inline(always)]
    pub(crate) fn try_write(
        &self,
        cx: &mut Context<'_>,
    ) -> Result<Option<QpackDecoderWriteGuard<'_>>, DecoderError> {
        match self.0.decoder.try_write() {
            Ok(guard) => Ok(Some(QpackDecoderWriteGuard {
                guard,
                state: self.0.clone(),
            })),
            Err(TryLockError::WouldBlock) => {
                self.0.write_waker.register(cx.waker());
                match self.0.decoder.try_write() {
                    Ok(guard) => Ok(Some(QpackDecoderWriteGuard {
                        guard,
                        state: self.0.clone(),
                    })),
                    Err(TryLockError::WouldBlock) => Ok(None),
                    Err(TryLockError::Poisoned(_)) => Err(DecoderError::UnexpectedEnd),
                }
            }
            Err(TryLockError::Poisoned(_)) => Err(DecoderError::UnexpectedEnd),
        }
    }
}
