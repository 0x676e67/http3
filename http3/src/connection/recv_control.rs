use std::{
    sync::{Arc, Mutex, OnceLock},
    task::{Context, Poll},
};

use futures_util::task::AtomicWaker;

use crate::{
    error::{Code, StreamError},
    qpack::{DecoderError, QpackDecoder},
    quic::{StopRecv, StreamId},
};

/// Independent control of a client's receive direction.
///
/// The response reader retains its frame buffers and decoding state. This handle
/// shares only cancellation and QPACK registration metadata with it. Dropping
/// the handle has no cancellation effect; dropping the reader still cancels an
/// unfinished receive direction. The send direction is unaffected.
///
/// Created by [`crate::client::RequestStream::recv_control`]. The first call adds
/// one shared metadata allocation, plus any allocation required by the backend.
/// Cloning is available when the backend handle is Clone and only shares state.
pub struct RecvControl<T> {
    pub(crate) stop: T,
    pub(crate) state: Arc<ReceiveState>,
}

impl<T: Clone> Clone for RecvControl<T> {
    fn clone(&self) -> Self {
        Self {
            stop: self.stop.clone(),
            state: self.state.clone(),
        }
    }
}

impl<T: StopRecv> RecvControl<T> {
    /// Stops receiving with the first cancellation code and releases QPACK work.
    ///
    /// This works even when the reader is not polled, and wakes a pending receive
    /// operation with a local [`StreamError::StreamError`]. Repeated calls retain
    /// the first code; calls after observed receive completion do nothing.
    /// Buffered HTTP bytes remain owned by the reader until it is dropped;
    /// previously returned bytes cannot be revoked. The connection driver must
    /// keep running to transmit STOP_SENDING and QPACK cancellation instructions.
    /// See [RFC 9114, Section 4.1.1](https://www.rfc-editor.org/rfc/rfc9114.html#section-4.1.1).
    pub fn stop_sending(&self, code: Code) {
        if let Some(code) = self.state.cancel(code) {
            // Never call transport code while holding the metadata lock. A
            // racing reader Drop also submits this same selected code before
            // dropping its native receive object.
            self.stop.stop_sending(code.value());
            self.state.wake();
        }
    }
}

/// Connection-level decoder access for this request's QPACK feedback.
///
/// This contains no field-section bytes or parsing cursor. Those remain owned
/// by the receive stream; the control handle only queues registration and
/// feedback events through the shared decoder.
pub(crate) struct QpackReceive {
    /// Request stream identified by blocked registrations and decoder feedback.
    pub stream_id: StreamId,
    /// Shared decoder and event sender used to release references on cancellation.
    pub decoder: QpackDecoder,
}

/// Receive transitions that must be serialized with QPACK event submission.
///
/// Keeping these decisions under one lock prevents a late registration or ACK
/// from being queued after cancellation. QPACK can finish before buffered HTTP
/// data is delivered, so its cancellation obligation has a separate flag.
struct Lifecycle {
    /// HTTP receive completion won the race against local cancellation.
    finished: bool,
    /// Abandoning the reader still requires one QPACK Stream Cancellation.
    cancel_qpack: bool,
    /// Required Insert Count of the current blocked registration, if any.
    blocked: Option<usize>,
}

/// Lazily shared receive metadata for the reader, Drop guard, and control handles.
///
/// Frame buffers and parsing state remain exclusively owned by the reader.
/// Cancellation and completion compete under `lifecycle`; the selected code is
/// also published through `canceled` so ordinary DATA polls need no metadata
/// lock. Transport stop and reader wakeups run after releasing that lock.
pub(crate) struct ReceiveState {
    /// Serializes completion, cancellation, and QPACK feedback ordering.
    lifecycle: Mutex<Lifecycle>,
    /// First local cancellation code; immutable once selected, including on Drop.
    canceled: OnceLock<Code>,
    /// The sole receive task, including waits blocked on QPACK rather than QUIC.
    reader: AtomicWaker,
    /// Present only when this request uses connection-level dynamic decoding.
    qpack: Option<QpackReceive>,
}

impl ReceiveState {
    pub(crate) fn new(
        qpack: Option<QpackReceive>,
        cancel_qpack: bool,
        blocked: Option<usize>,
        finished: bool,
        code: Option<Code>,
    ) -> Self {
        Self {
            lifecycle: Mutex::new(Lifecycle {
                finished,
                cancel_qpack,
                blocked,
            }),
            canceled: code.map_or_else(OnceLock::new, OnceLock::from),
            reader: AtomicWaker::new(),
            qpack,
        }
    }

    pub(crate) fn cancel(&self, code: Code) -> Option<Code> {
        let mut state = self.lifecycle.lock().unwrap_or_else(|e| e.into_inner());
        if state.finished {
            return None;
        }
        let code = *self.canceled.get_or_init(|| code);
        self.cancel_qpack_locked(&mut state);
        Some(code)
    }

    pub(crate) fn wake(&self) {
        self.reader.wake();
    }

    pub(crate) fn finish(&self) -> bool {
        let mut state = self.lifecycle.lock().unwrap_or_else(|e| e.into_inner());
        if self.canceled.get().is_some() {
            return false;
        }
        self.unblock_locked(&mut state);
        state.cancel_qpack = false;
        state.finished = true;
        true
    }

    // QPACK completion can precede delivery of buffered DATA. It must not
    // disable HTTP receive cancellation or turn a transport error into a local stop.
    pub(crate) fn finish_qpack(&self) {
        let mut state = self.lifecycle.lock().unwrap_or_else(|e| e.into_inner());
        self.unblock_locked(&mut state);
        state.cancel_qpack = false;
    }

    pub(crate) fn cancel_qpack(&self) {
        let mut state = self.lifecycle.lock().unwrap_or_else(|e| e.into_inner());
        self.cancel_qpack_locked(&mut state);
    }

    fn cancel_qpack_locked(&self, state: &mut Lifecycle) {
        self.unblock_locked(state);
        if std::mem::take(&mut state.cancel_qpack)
            && let Some(qpack) = &self.qpack
        {
            qpack.decoder.queue_stream_cancellation(qpack.stream_id);
        }
    }

    pub(crate) fn register(&self, waker: &std::task::Waker) {
        self.reader.register(waker);
    }

    pub(crate) fn clear_waiter(&self) {
        self.reader.take();
    }

    pub(crate) fn block(
        &self,
        required: usize,
        waker: &std::task::Waker,
    ) -> Result<(), DecoderError> {
        let mut state = self.lifecycle.lock().unwrap_or_else(|e| e.into_inner());
        if state.finished || self.canceled.get().is_some() {
            return Ok(());
        }
        if state.blocked.is_some_and(|old| old != required) {
            self.unblock_locked(&mut state);
        }
        if let Some(qpack) = &self.qpack {
            qpack
                .decoder
                .queue_blocked_stream(qpack.stream_id, required, waker)?;
            state.blocked = Some(required);
        }
        Ok(())
    }

    pub(crate) fn unblock(&self) {
        let mut state = self.lifecycle.lock().unwrap_or_else(|e| e.into_inner());
        self.unblock_locked(&mut state);
    }

    fn unblock_locked(&self, state: &mut Lifecycle) {
        if let Some(required) = state.blocked.take()
            && let Some(qpack) = &self.qpack
        {
            qpack
                .decoder
                .release_blocked_stream(qpack.stream_id, required);
        }
    }

    pub(crate) fn acknowledge(&self, dynamic: bool) -> Result<(), DecoderError> {
        let state = self.lifecycle.lock().unwrap_or_else(|e| e.into_inner());
        if dynamic
            && !state.finished
            && self.canceled.get().is_none()
            && let Some(qpack) = &self.qpack
        {
            qpack
                .decoder
                .queue_section_acknowledgment(qpack.stream_id)?;
        }
        Ok(())
    }

    fn error(&self) -> Option<StreamError> {
        self.canceled.get().map(|&code| StreamError::StreamError {
            code,
            reason: "receive direction canceled locally".into(),
        })
    }

    pub(crate) fn poll<T>(
        state: Option<&Self>,
        cx: &mut Context<'_>,
        operation: impl FnOnce(&mut Context<'_>) -> Poll<Result<T, StreamError>>,
    ) -> Poll<Result<T, StreamError>> {
        let Some(state) = state else {
            return operation(cx);
        };
        if let Some(error) = state.error() {
            state.clear_waiter();
            return Poll::Ready(Err(error));
        }
        let result = operation(cx);
        if result.is_pending() {
            state.register(cx.waker());
        } else {
            state.clear_waiter();
        }
        // Preserve protocol diagnostics produced by the operation (for example
        // HeaderTooBig after its own stop). Only a backend's local ClosedStream
        // needs replacement with our recorded cancellation code.
        if matches!(&result, Poll::Ready(Err(error)) if !matches!(error, StreamError::Undefined(_)))
        {
            return result;
        }
        // Covers a stop during the operation, QPACK blocking, or registration.
        if let Some(error) = state.error() {
            state.clear_waiter();
            return Poll::Ready(Err(error));
        }
        result
    }
}
