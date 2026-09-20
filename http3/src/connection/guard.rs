use std::{
    ops::Deref,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::Buf;

use super::ReceiveState;
use crate::{
    error::Code,
    frame::{FrameStream, FrameStreamError},
    proto::frame::{Frame, PayloadLen},
    quic::{self, SendStream, StreamErrorIncoming},
    stream::WriteBuf,
};

type Cancel<S, B> = fn(&mut FrameStream<S, B>, Code);

/// Cancels a client's open stream directions when their owner is dropped.
///
/// Callbacks retain each direction's trait capability after splitting, without
/// requiring receive-only streams to implement `SendStream` (or vice versa).
/// Server streams start disarmed and retain their transport's drop behavior.
/// See <https://www.rfc-editor.org/rfc/rfc9114.html#section-4.1.1>.
pub(crate) struct StreamGuard<S, B> {
    inner: Option<FrameStream<S, B>>,
    reset_on_drop: Option<Cancel<S, B>>,
    stop_sending_on_drop: Option<Cancel<S, B>>,
    pub(super) control: Option<Arc<ReceiveState>>,
    pub(super) recv_stop_code: Option<Code>,
}

impl<S, B> StreamGuard<S, B> {
    /// Wraps a stream with both cancellation callbacks disabled.
    /// Used for server streams and halves whose callbacks are transferred by split.
    pub(super) fn without_cancellation(stream: FrameStream<S, B>) -> Self {
        Self {
            inner: Some(stream),
            reset_on_drop: None,
            stop_sending_on_drop: None,
            control: None,
            recv_stop_code: None,
        }
    }

    /// Disables receive cancellation after EOF and any buffered trailers are processed.
    /// The send direction keeps its current state.
    pub(super) fn finish_reading(&mut self) {
        if let Some(control) = &self.control
            && !control.finish()
        {
            // A selected external cancellation may still be waiting to stop
            // QUIC. Keep Drop armed so native Drop cannot win with its own code.
            return;
        }
        self.stop_sending_on_drop = None;
    }

    /// The inner stream. `None` only while `split` is consuming this guard,
    /// which drops it without borrowing.
    fn stream_mut(&mut self) -> &mut FrameStream<S, B> {
        self.inner.as_mut().expect("stream is present")
    }
}

impl<S, B> Deref for StreamGuard<S, B> {
    type Target = FrameStream<S, B>;

    fn deref(&self) -> &Self::Target {
        self.inner.as_ref().expect("stream is present")
    }
}

impl<S, B> Drop for StreamGuard<S, B> {
    fn drop(&mut self) {
        self.cancel_remaining();
        if let Some(control) = &self.control {
            control.clear_waiter();
        }
    }
}

impl<S: quic::RecvStream, B> StreamGuard<S, B> {
    /// Stops receiving with the caller's code and prevents Drop from replacing it.
    /// This does not reset the send direction. When enabled, receive control
    /// coordinates QPACK cleanup with the external cancellation handle.
    pub(super) fn stop_sending(&mut self, code: Code) {
        let code = if let Some(control) = &self.control {
            let Some(code) = control.cancel(code) else {
                return;
            };
            code
        } else {
            *self.recv_stop_code.get_or_insert(code)
        };
        self.recv_stop_code = Some(code);
        self.stop_sending_on_drop = None;
        self.stream_mut().stop_sending(code);
        if let Some(control) = &self.control {
            control.wake();
        }
    }
}

impl<S: quic::SendStream<B> + quic::RecvStream, B: Buf> StreamGuard<S, B> {
    /// Wraps a new client stream with cancellation armed for both directions.
    /// See <https://www.rfc-editor.org/rfc/rfc9114.html#section-4.1.1>.
    pub(super) fn new(stream: FrameStream<S, B>) -> Self {
        Self {
            inner: Some(stream),
            reset_on_drop: Some(|stream, code| stream.reset(code.into())),
            stop_sending_on_drop: Some(|stream, code| stream.stop_sending(code)),
            control: None,
            recv_stop_code: None,
        }
    }
}

impl<S: quic::BidiStream<B>, B: Buf> StreamGuard<S, B> {
    /// Transfers each open direction to its half without cancelling either one.
    /// A direction already finished or explicitly stopped stays disarmed.
    pub(super) fn split(
        mut self,
    ) -> (StreamGuard<S::SendStream, B>, StreamGuard<S::RecvStream, B>) {
        let (send, recv) = self.inner.take().expect("stream is present").split();
        let mut send = StreamGuard::without_cancellation(send);
        let mut recv = StreamGuard::without_cancellation(recv);
        recv.control = self.control.take();
        recv.recv_stop_code = self.recv_stop_code;

        if self.reset_on_drop.take().is_some() {
            send.reset_on_drop = Some(|stream, code| stream.reset(code.into()));
        }

        if self.stop_sending_on_drop.take().is_some() {
            recv.stop_sending_on_drop = Some(|stream, code| stream.stop_sending(code));
        }

        (send, recv)
    }
}

impl<S: quic::RecvStream, B> StreamGuard<S, B> {
    /// Reads the next frame. Receiving does not complete either direction,
    /// so this leaves both cancellation callbacks as they are.
    pub(crate) fn poll_next(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Frame<PayloadLen>>, FrameStreamError>> {
        self.stream_mut().poll_next(cx)
    }

    /// Reads the current frame's payload, leaving cancellation as it is.
    pub(crate) fn poll_data(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<impl Buf + use<S, B>>, FrameStreamError>> {
        self.stream_mut().poll_data(cx)
    }
}

impl<S, B> SendStream<B> for StreamGuard<S, B>
where
    S: SendStream<B>,
    B: Buf,
{
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        self.stream_mut().poll_ready(cx)
    }

    fn send_data<D: Into<WriteBuf<B>>>(&mut self, data: D) -> Result<(), StreamErrorIncoming> {
        self.stream_mut().send_data(data)
    }

    fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        let result = self.stream_mut().poll_finish(cx);
        // Pending or failed FIN does not complete the send direction. If the
        // request is then dropped, its cancellation callback must still run.
        if matches!(result, Poll::Ready(Ok(()))) {
            self.reset_on_drop = None;
        }
        result
    }

    fn reset(&mut self, reset_code: u64) {
        self.reset_on_drop = None;
        self.stream_mut().reset(reset_code);
    }

    fn send_id(&self) -> quic::StreamId {
        self.deref().send_id()
    }
}

impl<S, B> StreamGuard<S, B> {
    /// Cancels only directions still owned by this handle. Taking callbacks
    /// makes explicit rejection followed by Drop idempotent.
    pub(super) fn cancel_remaining(&mut self) {
        let Some(stream) = self.inner.as_mut() else {
            return;
        };
        if let Some(reset) = self.reset_on_drop.take() {
            reset(stream, Code::H3_REQUEST_CANCELLED);
        }
        if let Some(stop_sending) = self.stop_sending_on_drop.take() {
            let code = if let Some(control) = &self.control {
                control.cancel(Code::H3_REQUEST_CANCELLED)
            } else {
                Some(self.recv_stop_code.unwrap_or(Code::H3_REQUEST_CANCELLED))
            };
            if let Some(code) = code {
                stop_sending(stream, code);
            }
            if let Some(control) = &self.control {
                control.wake();
            }
        }
    }

    pub(super) fn receive_finished(&self) -> bool {
        self.stop_sending_on_drop.is_none() && self.recv_stop_code.is_none()
    }
}

impl<S: quic::RecvStreamControl, B> StreamGuard<S, B> {
    pub(super) fn stop_handle(&mut self) -> S::Stop {
        self.stream_mut().stream.stop_handle()
    }
}
