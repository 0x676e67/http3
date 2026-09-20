use std::{
    future::Future,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
};

use bytes::Bytes;
use http3::quic::StreamErrorIncoming;

use crate::{VarInt, convert_read_error_to_stream_error, quic};

/// Independent stop handle for an HTTP/3 QUIC receive stream.
///
/// Creating the first handle allocates shared storage for the native receiver.
/// Subsequent native reads take one short mutex; no lock is held across Pending.
/// Clones share that allocation. Dropping this handle does not stop receiving.
#[derive(Clone)]
pub struct RecvStop(pub(crate) Arc<SharedRecv>);

impl http3::quic::StopRecv for RecvStop {
    fn stop_sending(&self, code: u64) {
        self.0.stop(code);
    }
}

/// Native receive storage shared by one reader and its independent stop handles.
///
/// The mutex serializes individual read polls, stop calls, and reader teardown.
/// It is never held across an await; a pending reader is woken after the lock is
/// released. The native stop API requires exclusive access to the receiver, so
/// an atomic cancellation flag alone cannot replace this lock. HTTP frame
/// buffers and QPACK state are not stored here.
pub(crate) struct SharedRecv(Mutex<Receive>);

/// Mutable receiver ownership and notification state protected by `SharedRecv`.
///
/// QUIC retains responsibility for FIN, reset, and stop idempotence; this adapter
/// only keeps the receiver accessible to external stop handles.
struct Receive {
    stream: Option<quic::RecvStream>,
    waker: Option<Waker>,
}

impl SharedRecv {
    /// Takes the reader's native stream and any waiter registered before sharing.
    pub(crate) fn new(stream: Option<quic::RecvStream>, waker: Option<Waker>) -> Self {
        Self(Mutex::new(Receive { stream, waker }))
    }

    /// Polls one native read, retaining its waiter only while the read is pending.
    /// Native read errors are mapped through the adapter's existing conversion.
    pub(crate) fn poll_data(
        &self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Bytes>, StreamErrorIncoming>> {
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let Some(stream) = &mut state.stream else {
            return Poll::Ready(Ok(None));
        };
        let result = std::pin::pin!(stream.read_chunk(usize::MAX, true))
            .as_mut()
            .poll(cx)
            .map(|result| {
                result
                    .map(|chunk| chunk.map(|chunk| chunk.bytes))
                    .map_err(convert_read_error_to_stream_error)
            });
        if result.is_pending() {
            if let Some(waker) = &mut state.waker {
                waker.clone_from(cx.waker());
            } else {
                state.waker = Some(cx.waker().clone());
            }
        } else {
            state.waker = None;
        }
        result
    }

    /// Submits a native stop and wakes the pending reader after releasing locks.
    /// Invalid QUIC codes are ignored; the native stream preserves the first
    /// stop code. A handle outliving the reader has no stream left to stop.
    pub(crate) fn stop(&self, code: u64) {
        let Ok(code) = VarInt::from_u64(code) else {
            return;
        };
        let waker = {
            let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
            // Native stop owns FIN/reset/0-RTT handling and repeat calls.
            // QUIC also owns STOP_SENDING retransmission (RFC 9000, Section 3.5).
            if let Some(stream) = &mut state.stream {
                let _ = stream.stop(code);
            }
            state.waker.take()
        };
        // Native stop removes its blocked reader without waking it. Preserve
        // the reader's waker here and invoke it after both locks are released.
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    /// Releases the native reader even if independent stop handles remain alive.
    /// Native Drop stops unfinished receive work with code zero and preserves an
    /// earlier explicit stop. A pending reader is woken after releasing the lock.
    pub(crate) fn drop_reader(&self) {
        let waker = {
            let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
            // Keep native Drop serialized with stop calls. It already performs
            // the fallback stop, so calling stop(0) first would be redundant.
            drop(state.stream.take());
            state.waker.take()
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}
