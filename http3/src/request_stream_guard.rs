// Adapted from http3 PR #5, commit 617e579343d6bfcc2d66f318f4fe355690a8f57d.
// https://github.com/0x676e67/http3/pull/5
//
// Copyright (c) 2020 h3 authors
//
// Permission is hereby granted, free of charge, to any
// person obtaining a copy of this software and associated
// documentation files (the "Software"), to deal in the
// Software without restriction, including without
// limitation the rights to use, copy, modify, merge,
// publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software
// is furnished to do so, subject to the following
// conditions:
//
// The above copyright notice and this permission notice
// shall be included in all copies or substantial portions
// of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF
// ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
// TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
// PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT
// SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
// CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR
// IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

use std::{
    ops::{Deref, DerefMut},
    task::{Context, Poll},
};

use bytes::Buf;

use crate::{
    error::Code,
    frame::FrameStream,
    quic::{self, SendStream, StreamErrorIncoming},
    stream::WriteBuf,
};

// The framed stream is taken only by into_inner, which disarms Drop first.
// All other access therefore observes Some, including after split.
// Cancellation aborts only unfinished directions (RFC 9114, section 4.1.1).
pub(super) type ResetOnDrop<S, B> = fn(&mut FrameStream<S, B>, Code);
pub(super) type StopSendingOnDrop<S, B> = fn(&mut FrameStream<S, B>, Code);

pub(crate) struct RequestStreamGuard<S, B> {
    inner: Option<FrameStream<S, B>>,
    pub(super) reset_on_drop: Option<ResetOnDrop<S, B>>,
    pub(super) stop_sending_on_drop: Option<StopSendingOnDrop<S, B>>,
}

impl<S, B> RequestStreamGuard<S, B> {
    pub(super) fn new(
        stream: FrameStream<S, B>,
        reset_on_drop: Option<ResetOnDrop<S, B>>,
        stop_sending_on_drop: Option<StopSendingOnDrop<S, B>>,
    ) -> Self {
        Self {
            inner: Some(stream),
            reset_on_drop,
            stop_sending_on_drop,
        }
    }

    pub(super) fn into_inner(mut self) -> FrameStream<S, B> {
        self.reset_on_drop = None;
        self.stop_sending_on_drop = None;
        self.inner.take().expect("stream is present")
    }

    pub(super) fn disarm_reset(&mut self) {
        self.reset_on_drop = None;
    }

    pub(super) fn disarm_stop_sending(&mut self) {
        self.stop_sending_on_drop = None;
    }
}

impl<S, B> Deref for RequestStreamGuard<S, B> {
    type Target = FrameStream<S, B>;

    fn deref(&self) -> &Self::Target {
        self.inner.as_ref().expect("stream is present")
    }
}

impl<S, B> DerefMut for RequestStreamGuard<S, B> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.inner.as_mut().expect("stream is present")
    }
}

impl<S, B> Drop for RequestStreamGuard<S, B> {
    fn drop(&mut self) {
        let Some(stream) = self.inner.as_mut() else {
            return;
        };

        if let Some(reset) = self.reset_on_drop {
            reset(stream, Code::H3_REQUEST_CANCELLED);
        }
        if let Some(stop_sending) = self.stop_sending_on_drop {
            stop_sending(stream, Code::H3_REQUEST_CANCELLED);
        }
    }
}

impl<S, B> SendStream<B> for RequestStreamGuard<S, B>
where
    S: SendStream<B>,
    B: Buf,
{
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        self.deref_mut().poll_ready(cx)
    }

    fn send_data<D: Into<WriteBuf<B>>>(&mut self, data: D) -> Result<(), StreamErrorIncoming> {
        self.deref_mut().send_data(data)
    }

    fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        self.deref_mut().poll_finish(cx)
    }

    fn reset(&mut self, reset_code: u64) {
        self.deref_mut().reset(reset_code);
    }

    fn send_id(&self) -> quic::StreamId {
        self.deref().send_id()
    }
}

pub(super) fn reset_on_drop<S, B>(stream: &mut FrameStream<S, B>, code: Code)
where
    S: quic::SendStream<B>,
    B: Buf,
{
    stream.reset(code.into());
}

pub(super) fn stop_sending_on_drop<S, B>(stream: &mut FrameStream<S, B>, code: Code)
where
    S: quic::RecvStream,
{
    stream.stop_sending(code);
}
