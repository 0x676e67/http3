//! The local control stream, shared by the connection driver and request senders.
//!
//! quinn keeps one blocked-writer waker per stream, so every poll here passes a waker that
//! wakes the connection driver and any pending control write. A request sender therefore
//! never parks on the control stream, and the driver finishes what a sender left behind.

use std::{
    collections::VecDeque,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
    task::{Context, Poll},
};

use bytes::Buf;
use futures_util::{
    future, ready,
    task::{ArcWake, AtomicWaker, waker_ref},
};

use crate::{
    proto::frame::RequestPriorityUpdate,
    quic::{SendStream, StreamErrorIncoming},
    shared_state::{ConnectionState, SharedState},
    stream::WriteBuf,
};

/// Bound for initial PRIORITY_UPDATE frames waiting for a busy control stream.
const MAX_QUEUED_PRIORITY_UPDATES: usize = 256;

/// Writer for the local control stream: SETTINGS, GOAWAY, and initial PRIORITY_UPDATE frames.
pub(crate) struct ControlSend<S> {
    inner: Mutex<Inner<S>>,
    wake: Arc<Wake>,
}

struct Inner<S> {
    stream: S,
    /// Initial PRIORITY_UPDATE frames the driver writes once the stream is ready.
    queue: VecDeque<RequestPriorityUpdate>,
}

/// Wakes the connection driver and a pending SETTINGS or GOAWAY write.
///
/// quinn wakes it while holding its connection lock, and a sender may hold `inner` while
/// waiting for that lock in `poll_write`, so waking must never take `inner`.
struct Wake {
    shared: Arc<SharedState>,
    writer: AtomicWaker,
}

// ===== impl ControlSend =====

impl<S> ControlSend<S> {
    pub(crate) fn new(stream: S, shared: Arc<SharedState>) -> Self {
        Self {
            inner: Mutex::new(Inner {
                stream,
                queue: VecDeque::new(),
            }),
            wake: Arc::new(Wake {
                shared,
                writer: AtomicWaker::new(),
            }),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Inner<S>> {
        // The stream and queue stay valid across a panic in the QUIC layer, so poison is ignored.
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Writes one frame from the task that owns the driver.
    ///
    /// Bytes left by a cancelled write are finished first, and bytes of this frame left by a
    /// cancellation are finished by the next flush, so the stream never sees two writes.
    pub(crate) async fn write<B, D>(&self, data: D) -> Result<(), StreamErrorIncoming>
    where
        S: SendStream<B>,
        B: Buf,
        D: Into<WriteBuf<B>>,
    {
        let mut data = Some(data);
        let result = future::poll_fn(|cx| {
            self.wake.writer.register(cx.waker());
            let waker = waker_ref(&self.wake);
            let mut cx = Context::from_waker(&waker);
            let stream = &mut self.lock().stream;
            if let Some(frame) = data.take() {
                if stream.poll_ready(&mut cx)?.is_pending() {
                    data = Some(frame);
                    return Poll::Pending;
                }
                stream.send_data(frame)?;
            }
            stream.poll_ready(&mut cx)
        })
        .await;
        // The write is over; stop waking the task that awaited it.
        self.wake.writer.take();
        result
    }

    /// Sends a request's initial priority without waiting.
    ///
    /// An idle stream takes the frame before the request writes its HEADERS; wire order and
    /// packing are then up to the QUIC layer. A busy stream queues it for the driver, so it
    /// may follow the HEADERS, or drops it when the queue is full; RFC 9218 allows both.
    /// See [RFC 9218, Section 7](https://www.rfc-editor.org/rfc/rfc9218.html#section-7).
    pub(crate) fn send_now<B>(
        &self,
        update: RequestPriorityUpdate,
    ) -> Result<(), StreamErrorIncoming>
    where
        S: SendStream<B>,
        B: Buf,
    {
        let waker = waker_ref(&self.wake);
        let mut cx = Context::from_waker(&waker);
        let mut inner = self.lock();
        match inner.stream.poll_ready(&mut cx)? {
            Poll::Ready(()) => {
                inner.stream.send_data(update)?;
                // Unaccepted bytes stay buffered; quinn wakes the driver to finish them.
                if let Poll::Ready(Err(error)) = inner.stream.poll_ready(&mut cx) {
                    return Err(error);
                }
            }
            Poll::Pending if inner.queue.len() < MAX_QUEUED_PRIORITY_UPDATES => {
                inner.queue.push_back(update);
                drop(inner);
                self.wake.shared.waker().wake();
            }
            Poll::Pending => {}
        }
        Ok(())
    }

    /// Finishes buffered bytes and writes queued PRIORITY_UPDATE frames.
    pub(crate) fn poll_flush<B>(
        &self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), StreamErrorIncoming>>
    where
        S: SendStream<B>,
        B: Buf,
    {
        self.wake.shared.waker().register(cx.waker());
        let waker = waker_ref(&self.wake);
        let mut cx = Context::from_waker(&waker);
        let mut inner = self.lock();
        loop {
            ready!(inner.stream.poll_ready(&mut cx))?;
            let Some(update) = inner.queue.pop_front() else {
                return Poll::Ready(Ok(()));
            };
            inner.stream.send_data(update)?;
        }
    }
}

// ===== impl Wake =====

impl ArcWake for Wake {
    fn wake_by_ref(arc_self: &Arc<Self>) {
        arc_self.shared.waker().wake();
        arc_self.writer.wake();
    }
}
