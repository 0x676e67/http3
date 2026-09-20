use std::{
    convert::TryFrom,
    future::{Future, poll_fn},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::Buf;
use http::{HeaderMap, Response};
use quic::StreamId;
#[cfg(feature = "tracing")]
use tracing::instrument;

use crate::{
    connection::{self},
    error::{
        Code, StreamError, connection_error_creators::CloseStream,
        internal_error::InternalConnectionError,
    },
    proto::{frame::Frame, headers::Header},
    qpack,
    quic::{self},
    shared_state::{ConnectionState, SharedState},
};

/// Manage request bodies transfer, response and trailers.
///
/// Once a request has been sent via [`crate::client::SendRequest::send_request()`], a response can
/// be awaited by calling [`RequestStream::recv_response()`]. A body for this request can be sent
/// with [`RequestStream::send_data()`], followed by optional [`RequestStream::send_trailers()`].
/// Call [`RequestStream::finish()`] to complete the send direction.
///
/// After receiving the response's headers, it's body can be read by [`RequestStream::recv_data()`]
/// until it returns `None`. Then the trailers will eventually be available via
/// [`RequestStream::recv_trailers()`].
///
/// TODO: If data is polled before the response has been received, an error will be thrown.
///
/// TODO: If trailers are polled but the body hasn't been fully received, an UNEXPECT_FRAME error
/// will be thrown
///
/// Dropping an unfinished stream cancels its open directions with `H3_REQUEST_CANCELLED`.
/// After [`split()`](Self::split), each half cancels only its own direction. Explicit
/// [`stop_sending()`](Self::stop_sending) stops receiving; [`stop_stream()`](Self::stop_stream)
/// stops sending.
/// See [RFC 9114, Section 4.1.1](https://www.rfc-editor.org/rfc/rfc9114.html#section-4.1.1).
///
/// While the connection driver runs, pending operations are woken if the server's
/// GOAWAY excludes this request. They return [`StreamError::GoawayRejected`] and
/// cancel the directions owned by this handle. After [`Self::split()`], each half
/// observes rejection independently. Requests below the GOAWAY boundary continue.
/// The caller decides whether to retry; this type never retries automatically.
///
/// Receive operations check for published GOAWAY rejection and connection errors
/// before polling the receive stream, including its buffered data. Consequently,
/// a published error can prevent delivery of already-buffered response bytes;
/// callers must not rely on draining those bytes after a connection failure.
/// Bytes returned to the caller before the error are unaffected.
///
/// # Examples
///
/// ```rust
/// # use http3::{quic, client::*};
/// # use http::{Request, Response};
/// # use bytes::Buf;
/// # use tokio::io::AsyncWriteExt;
/// # async fn doc<T,B>(mut req_stream: RequestStream<T, B>) -> Result<(), Box<dyn std::error::Error>>
/// # where
/// #     T: quic::RecvStream,
/// # {
/// // Prepare the HTTP request to send to the server
/// let request = Request::get("https://www.example.com/").body(())?;
///
/// // Receive the response
/// let response = req_stream.recv_response().await?;
/// // Receive the body
/// while let Some(mut chunk) = req_stream.recv_data().await? {
///     let mut out = tokio::io::stdout();
///     out.write_all_buf(&mut chunk).await?;
///     out.flush().await?;
/// }
/// # Ok(())
/// # }
/// # pub fn main() {}
/// ```
///
/// [`send_request()`]: struct.SendRequest.html#method.send_request
/// [`recv_response()`]: #method.recv_response
/// [`recv_data()`]: #method.recv_data
/// [`send_data()`]: #method.send_data
/// [`send_trailers()`]: #method.send_trailers
/// [`recv_trailers()`]: #method.recv_trailers
/// [`finish()`]: #method.finish
/// [`stop_sending()`]: #method.stop_sending
pub struct RequestStream<S, B> {
    pub(super) inner: connection::RequestStream<S, B>,
    rejection: RequestRejection,
}

impl<S, B> ConnectionState for RequestStream<S, B> {
    fn shared_state(&self) -> &SharedState {
        &self.inner.conn_state
    }
}

impl<S, B> CloseStream for RequestStream<S, B> {}

impl<S, B> RequestStream<S, B>
where
    S: quic::RecvStream,
{
    /// Receive the HTTP/3 response
    ///
    /// This should be called before trying to receive any data with [`recv_data()`].
    ///
    /// [`recv_data()`]: #method.recv_data
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub async fn recv_response(&mut self) -> Result<Response<()>, StreamError> {
        let result = self
            .rejection
            .run(Self::recv_response_inner(&mut self.inner))
            .await;
        self.handle_result(result)
    }

    /// Receives response body data.
    ///
    /// Published request errors take precedence over buffered data; see
    /// [`RequestStream`]'s error handling contract.
    // TODO what if called before recv_response ?
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub async fn recv_data(&mut self) -> Result<Option<impl Buf + use<S, B>>, StreamError> {
        let result = self
            .rejection
            .run(poll_fn(|cx| self.inner.poll_recv_data(cx)))
            .await;
        self.handle_result(result)
    }

    /// Polls for response body data with the same error precedence as
    /// [`Self::recv_data`].
    pub fn poll_recv_data(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<impl Buf + use<S, B>>, StreamError>> {
        let result = self.rejection.poll(cx, |cx| self.inner.poll_recv_data(cx));
        result.map(|result| self.handle_result(result))
    }

    /// Receive an optional set of trailers for the response.
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub async fn recv_trailers(&mut self) -> Result<Option<HeaderMap>, StreamError> {
        let result = self
            .rejection
            .run(poll_fn(|cx| self.inner.poll_recv_trailers(cx)))
            .await;
        if let Err(StreamError::HeaderTooBig { .. }) = &result {
            self.inner.stop_sending(Code::H3_REQUEST_CANCELLED);
        }
        self.handle_result(result)
    }

    /// Poll receive an optional set of trailers for the response.
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub fn poll_recv_trailers(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<HeaderMap>, StreamError>> {
        let res = self
            .rejection
            .poll(cx, |cx| self.inner.poll_recv_trailers(cx));
        if let Poll::Ready(Err(StreamError::HeaderTooBig { .. })) = &res {
            self.inner.stop_sending(Code::H3_REQUEST_CANCELLED);
        }
        res.map(|result| self.handle_result(result))
    }

    /// Stops receiving the response with `error_code` and releases its QPACK state.
    ///
    /// The request's send direction remains open. Dropping the stream afterwards
    /// does not replace this receive-side code with `H3_REQUEST_CANCELLED`.
    /// Clients must not use `H3_REQUEST_REJECTED` unless the server requested
    /// closure of this request with that code.
    /// See [RFC 9114, Section 4.1.1](https://www.rfc-editor.org/rfc/rfc9114.html#section-4.1.1).
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub fn stop_sending(&mut self, error_code: Code) {
        self.inner.stop_sending(error_code)
    }

    /// Returns the underlying stream id
    pub fn id(&self) -> StreamId {
        self.inner.stream.id()
    }

    async fn recv_response_inner(
        inner: &mut connection::RequestStream<S, B>,
    ) -> Result<Response<()>, StreamError> {
        let frame = poll_fn(|cx| inner.stream.poll_next(cx))
            .await
            .map_err(|e| inner.handle_receive_stream_error(e))?
            .ok_or_else(|| {
                //= https://www.rfc-editor.org/rfc/rfc9114#section-4.1
                //# Receipt of an invalid sequence of frames MUST be treated as a
                //# connection error of type H3_FRAME_UNEXPECTED.
                inner.handle_connection_error_on_stream(InternalConnectionError::new(
                    Code::H3_FRAME_UNEXPECTED,
                    "Stream finished without receiving response headers".to_string(),
                ))
            })?;

        //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.5
        //= type=TODO
        //# A client MUST treat
        //# receipt of a PUSH_PROMISE frame that contains a larger push ID than
        //# the client has advertised as a connection error of H3_ID_ERROR.

        //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.5
        //= type=TODO
        //# If a client
        //# receives a push ID that has already been promised and detects a
        //# mismatch, it MUST respond with a connection error of type
        //# H3_GENERAL_PROTOCOL_ERROR.

        let mut encoded = match frame {
            Frame::Headers(encoded) => encoded,
            _ => {
                //= https://www.rfc-editor.org/rfc/rfc9114#section-4.1
                //# Receipt of an invalid sequence of frames MUST be treated as a
                //# connection error of type H3_FRAME_UNEXPECTED.
                return Err(
                    inner.handle_connection_error_on_stream(InternalConnectionError::new(
                        Code::H3_FRAME_UNEXPECTED,
                        "First response frame is not headers".to_string(),
                    )),
                );
            }
        };

        let decoded = match poll_fn(|cx| inner.poll_decode_field_section(cx, &mut encoded)).await {
            //= https://www.rfc-editor.org/rfc/rfc9114#section-4.2.2
            //# An HTTP/3 implementation MAY impose a limit on the maximum size of
            //# the message header it will accept on an individual HTTP message.
            Err(qpack::DecoderError::HeaderTooLong(cancel_size)) => {
                inner.stop_sending(Code::H3_REQUEST_CANCELLED);
                return Err(StreamError::HeaderTooBig {
                    actual_size: cancel_size,
                    max_size: inner.max_field_section_size,
                });
            }
            Ok(decoded) => decoded,
            Err(error) => {
                let code = if error.is_internal() {
                    Code::H3_INTERNAL_ERROR
                } else {
                    Code::QPACK_DECOMPRESSION_FAILED
                };
                return Err(
                    inner.handle_connection_error_on_stream(InternalConnectionError::new(
                        code,
                        format!("failed to decode response headers: {error}"),
                    )),
                );
            }
        };

        let qpack::Decoded { fields, .. } = decoded;

        let (status, headers, pseudo_sensitivity) = Header::try_from(fields)
            .and_then(Header::into_response_parts)
            .map_err(|error| {
                let code = error.code();
                inner.stop_sending(code);
                StreamError::StreamError {
                    code,
                    reason: format!("rejected response headers: {error}"),
                }
            })?;

        let mut resp = Response::new(());
        *resp.status_mut() = status;
        *resp.headers_mut() = headers;
        if !pseudo_sensitivity.is_empty() {
            resp.extensions_mut().insert(pseudo_sensitivity);
        }
        *resp.version_mut() = http::Version::HTTP_3;

        Ok(resp)
    }
}

impl<S, B> RequestStream<S, B>
where
    S: quic::SendStream<B>,
    B: Buf,
{
    /// Send some data on the request body.
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub async fn send_data(&mut self, buf: B) -> Result<(), StreamError> {
        let result = self.rejection.run(self.inner.send_data(buf)).await;
        self.handle_result(result)
    }

    /// Resets the request's send direction with `error_code`.
    ///
    /// Receiving the response is unaffected. Dropping the stream afterwards does
    /// not replace this code with `H3_REQUEST_CANCELLED`. The code can be
    /// [`Code::H3_NO_ERROR`], for example when the peer has declined the upload.
    /// Clients must not use `H3_REQUEST_REJECTED` unless the server requested
    /// closure of this request with that code.
    /// See [RFC 9114, Section 4.1.1](https://www.rfc-editor.org/rfc/rfc9114.html#section-4.1.1).
    pub fn stop_stream(&mut self, error_code: Code) {
        self.inner.stop_stream(error_code);
    }

    /// Send a set of trailers to end the request.
    ///
    /// [`RequestStream::finish()`] must be called to finalize a request.
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub async fn send_trailers(&mut self, trailers: HeaderMap) -> Result<(), StreamError> {
        let result = self.rejection.run(self.inner.send_trailers(trailers)).await;
        self.handle_result(result)
    }

    /// Flushes pending request output and closes the send direction with FIN.
    ///
    /// Call this after sending the body and any trailers. Once it succeeds,
    /// dropping the stream does not reset the upload; an unread response is still
    /// cancelled. Transport failures are returned as [`StreamError`].
    ///
    /// Cancelling this future before it returns success leaves reset on Drop
    /// armed. Retry `finish`, or drop the stream to cancel its open directions.
    /// See [RFC 9114, Section 4.1](https://www.rfc-editor.org/rfc/rfc9114.html#section-4.1).
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub async fn finish(&mut self) -> Result<(), StreamError> {
        let result = self.rejection.run(self.inner.finish()).await;
        self.handle_result(result)
    }

    /// Polls for the server stopping or acknowledging the request's send direction.
    ///
    /// Resolves to `Some(code)` after `STOP_SENDING` and to `None` once the whole
    /// upload, including the FIN sent by [`finish()`](Self::finish), is acknowledged.
    /// Polling never changes the stream's state, so this works before and after
    /// `finish()` and on a split send half. A GOAWAY excluding this request is
    /// reported as [`StreamError::GoawayRejected`], like any other operation.
    pub fn poll_stopped(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Code>, StreamError>> {
        let result = self.rejection.poll(cx, |cx| self.inner.poll_stopped(cx));
        result.map(|result| self.handle_result(result))
    }
}

impl<S, B> RequestStream<S, B>
where
    S: quic::BidiStream<B>,
    B: Buf,
{
    /// Split this stream into two halves that can be driven independently.
    ///
    /// Dropping an unfinished send half resets only the upload; dropping an
    /// unfinished receive half stops only the response and cancels its QPACK
    /// decoding. Directions already finished or explicitly stopped remain so.
    /// See [RFC 9114, Section 4.1.1](https://www.rfc-editor.org/rfc/rfc9114.html#section-4.1.1).
    pub fn split(
        self,
    ) -> (
        RequestStream<S::SendStream, B>,
        RequestStream<S::RecvStream, B>,
    ) {
        let Self {
            inner,
            mut rejection,
        } = self;
        rejection.notified = None;
        let (send, recv) = inner.split();
        (
            RequestStream {
                inner: send,
                rejection: RequestRejection::new(rejection.state.clone(), rejection.stream_id),
            },
            RequestStream {
                inner: recv,
                rejection,
            },
        )
    }
}

impl<S, B> RequestStream<S, B>
where
    S: quic::SendStream<B> + quic::RecvStream,
    B: Buf,
{
    pub(super) fn new(inner: connection::RequestStream<S, B>) -> Self {
        let rejection = RequestRejection::new(inner.conn_state.clone(), inner.stream.id());
        Self { inner, rejection }
    }
}

// A poll API must retain its waiter across calls. Recreating and dropping a
// Notified on each Pending would lose the connection driver's wakeup.
struct RequestRejection {
    state: Arc<SharedState>,
    stream_id: StreamId,
    notified: Option<Pin<Box<tokio::sync::futures::OwnedNotified>>>,
}

impl RequestRejection {
    fn new(state: Arc<SharedState>, stream_id: StreamId) -> Self {
        Self {
            state,
            stream_id,
            notified: None,
        }
    }

    fn poll<T>(
        &mut self,
        cx: &mut Context<'_>,
        operation: impl FnOnce(&mut Context<'_>) -> Poll<Result<T, StreamError>>,
    ) -> Poll<Result<T, StreamError>> {
        if let Some(error) = self.state.request_error(self.stream_id) {
            self.notified = None;
            return Poll::Ready(Err(error));
        }
        let result = operation(cx);
        if result.is_ready() {
            self.notified = None;
            return result;
        }
        loop {
            let notified = self
                .notified
                .get_or_insert_with(|| Box::pin(self.state.notified()));
            let changed = notified.as_mut().poll(cx);
            // Register before rechecking: GOAWAY can arrive during operation's
            // poll or while the notification is being installed.
            if let Some(error) = self.state.request_error(self.stream_id) {
                self.notified = None;
                return Poll::Ready(Err(error));
            }
            if changed.is_pending() {
                return Poll::Pending;
            }
            notified.set(self.state.notified());
        }
    }

    async fn run<T>(
        &mut self,
        operation: impl Future<Output = Result<T, StreamError>>,
    ) -> Result<T, StreamError> {
        let mut operation = std::pin::pin!(operation);
        let waiter = RejectionWait(self);
        poll_fn(|cx| waiter.0.poll(cx, |cx| operation.as_mut().poll(cx))).await
    }
}

// Canceling an async operation unregisters its task even if the stream is kept.
struct RejectionWait<'a>(&'a mut RequestRejection);

impl Drop for RejectionWait<'_> {
    fn drop(&mut self) {
        self.0.notified = None;
    }
}

impl<S, B> RequestStream<S, B> {
    fn handle_result<T>(&mut self, result: Result<T, StreamError>) -> Result<T, StreamError> {
        if matches!(&result, Err(StreamError::GoawayRejected { .. })) {
            // Use the Drop guard's ownership state so completed or explicitly
            // stopped directions keep their result, including after split.
            self.inner.cancel_request();
        }
        result
    }
}
