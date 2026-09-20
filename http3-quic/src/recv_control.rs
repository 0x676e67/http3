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

pub(crate) struct SharedRecv(Mutex<Receive>);

struct Receive {
    stream: Option<quic::RecvStream>,
    waker: Option<Waker>,
}

impl SharedRecv {
    pub(crate) fn new(stream: Option<quic::RecvStream>, waker: Option<Waker>) -> Self {
        Self(Mutex::new(Receive { stream, waker }))
    }

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

    pub(crate) fn stop(&self, code: u64) {
        let Ok(code) = VarInt::from_u64(code) else {
            return;
        };
        let waker = {
            let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
            // Native stop owns FIN/reset/0-RTT handling and preserves the first
            // code. Repeated calls return ClosedStream without another STOP.
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

    pub(crate) fn drop_reader(&self) {
        self.stop(0);
        let stream = self
            .0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .stream
            .take();
        drop(stream);
    }
}
