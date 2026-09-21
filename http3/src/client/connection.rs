//! Client implementation of the HTTP/3 protocol

use std::{
    marker::PhantomData,
    mem,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::{Buf, Bytes, BytesMut};
use futures_util::future;
use http::request;
#[cfg(feature = "tracing")]
use tracing::{info, instrument, trace};

use super::stream::RequestStream;
use crate::{
    connection::{self, ConnectionInner},
    error::{
        Code, ConnectionError, StreamError, connection_error_creators::CloseStream,
        internal_error::InternalConnectionError,
    },
    frame::FrameStream,
    proto::{frame::Frame, headers::Header, push::PushId},
    qpack::{self, QpackDecoder, QpackEncoder},
    quic::{self, SendStream, StreamId},
    shared_state::{ConnectionState, SharedState},
    stream::{self, BufRecvStream},
};

// Retain enough storage to amortize ordinary request headers without letting a
// single large field section pin memory for the lifetime of a sender.
const MAX_RETAINED_QPACK_ENCODE_CAPACITY: usize = 4 * 1024;

fn clear_qpack_encode_buffer(buffer: &mut BytesMut) {
    if buffer.capacity() > MAX_RETAINED_QPACK_ENCODE_CAPACITY {
        *buffer = BytesMut::new();
    } else {
        buffer.clear();
    }
}

fn take_qpack_encode_buffer(buffer: &mut BytesMut) -> Bytes {
    if buffer.capacity() > MAX_RETAINED_QPACK_ENCODE_CAPACITY {
        mem::take(buffer).freeze()
    } else {
        buffer.split().freeze()
    }
}

/// HTTP/3 request sender
///
/// [`send_request()`] initiates a new request and will resolve when it is ready to be sent
/// to the server. Then a [`RequestStream`] will be returned to send a request body (for
/// POST, PUT methods) and receive a response. After the whole body is sent, it is necessary
/// to call [`RequestStream::finish()`] to let the server know the request transfer is complete.
/// This includes the cases where no body is sent at all.
///
/// This struct is cloneable so multiple requests can be sent concurrently.
///
/// Dropping a sender, including the last clone, does not close the connection.
/// Keep driving the [`Connection`] while requests are active. Dropping the
/// connection driver terminates the connection and its outstanding requests.
///
/// # Examples
///
/// ## Sending a request with no body
///
/// ```rust
/// # use http3::{quic, client::*};
/// # use http::{Request, Response};
/// # use bytes::Buf;
/// # async fn doc<T,B>(mut send_request: SendRequest<T, B>) -> Result<(), Box<dyn std::error::Error>>
/// # where
/// #     T: quic::OpenStreams<B>,
/// #     B: Buf,
/// # {
/// // Prepare the HTTP request to send to the server
/// let request = Request::get("https://www.example.com/").body(())?;
///
/// // Send the request to the server
/// let mut req_stream: RequestStream<_, _> = send_request.send_request(request).await?;
/// // Don't forget to end up the request by finishing the send stream.
/// req_stream.finish().await?;
/// // Receive the response
/// let response: Response<()> = req_stream.recv_response().await?;
/// // Process the response...
/// # Ok(())
/// # }
/// # pub fn main() {}
/// ```
///
/// ## Sending a request with a body and trailers
///
/// ```rust
/// # use http3::{quic, client::*};
/// # use http::{Request, Response, HeaderMap};
/// # use bytes::{Buf, Bytes};
/// # async fn doc<T,B>(mut send_request: SendRequest<T, Bytes>) -> Result<(), Box<dyn std::error::Error>>
/// # where
/// #     T: quic::OpenStreams<Bytes>,
/// # {
/// // Prepare the HTTP request to send to the server
/// let request = Request::get("https://www.example.com/").body(())?;
///
/// // Send the request to the server
/// let mut req_stream = send_request.send_request(request).await?;
/// // Send some data
/// req_stream.send_data("body".into()).await?;
/// // Prepare the trailers
/// let mut trailers = HeaderMap::new();
/// trailers.insert("trailer", "value".parse()?);
/// // Send them and finish the send stream
/// req_stream.send_trailers(trailers).await?;
/// req_stream.finish().await?;
///
/// // Receive the response.
/// let response = req_stream.recv_response().await?;
/// // Process the response...
/// # Ok(())
/// # }
/// # pub fn main() {}
/// ```
///
/// [`send_request()`]: struct.SendRequest.html#method.send_request
/// [`RequestStream`]: struct.RequestStream.html
/// [`RequestStream::finish()`]: struct.RequestStream.html#method.finish
pub struct SendRequest<T, B>
where
    T: quic::OpenStreams<B>,
    B: Buf,
{
    pub(super) open: T,
    pub(super) conn_state: Arc<SharedState>,
    pub(super) decoder: Option<QpackDecoder>,
    pub(super) encoder: Option<QpackEncoder>,
    pub(super) max_field_section_size: u64, // largest field section we accept
    pub(super) max_qpack_decode_buffer_size: usize,
    pub(super) _buf: PhantomData<fn(B)>,
    pub(super) send_grease_frame: bool,
    pub(super) qpack_encode_buffer: BytesMut,
}

impl<T, B> ConnectionState for SendRequest<T, B>
where
    T: quic::OpenStreams<B>,
    B: Buf,
{
    fn shared_state(&self) -> &SharedState {
        &self.conn_state
    }
}

impl<T, B> CloseStream for SendRequest<T, B>
where
    T: quic::OpenStreams<B>,
    B: Buf,
{
}

impl<T, B> SendRequest<T, B>
where
    T: quic::OpenStreams<B>,
    B: Buf,
{
    /// Send an HTTP/3 request to the server
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub async fn send_request(
        &mut self,
        req: http::Request<()>,
    ) -> Result<RequestStream<T::BidiStream, B>, StreamError> {
        if let Some(error) = self.check_peer_connection_closing() {
            return Err(error);
        };

        let (parts, _) = req.into_parts();
        let request::Parts {
            method,
            uri,
            headers,
            extensions,
            ..
        } = parts;
        let headers = Header::request(method, uri, headers, extensions).map_err(|error| {
            StreamError::InvalidRequest {
                reason: error.to_string().into_boxed_str(),
            }
        })?;

        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.2
        //= type=TODO
        //# Characters in field names MUST be
        //# converted to lowercase prior to their encoding.

        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.2.1
        //= type=TODO
        //# To allow for better compression efficiency, the Cookie header field
        //# ([COOKIES]) MAY be split into separate field lines, each with one or
        //# more cookie-pairs, before compression.

        let dynamic_encoder = match self.encoder.as_ref() {
            Some(encoder) => match encoder.ready() {
                Ok(true) => Some(encoder),
                Ok(false) => None,
                Err(error) => {
                    return Err(self.handle_connection_error_on_stream(
                        InternalConnectionError::new(
                            Code::H3_INTERNAL_ERROR,
                            format!("failed to access QPACK encoder: {error}"),
                        ),
                    ));
                }
            },
            None => None,
        };

        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.2.2
        //# An implementation that has received this parameter SHOULD NOT send
        //# an HTTP message header that exceeds the indicated size, as the peer
        //# will likely refuse to process it.
        //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.4.2
        //# An HTTP implementation MUST NOT send frames or requests that would be
        //# invalid based on its current understanding of the peer's settings.
        let peer_max_field_section_size = self.settings().max_field_section_size;

        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.1
        //= type=implication
        //# A
        //# client MUST send only a single request on a given stream.
        let mut stream;
        if let Some(encoder) = dynamic_encoder {
            // Dynamic references are tracked by the actual QUIC request stream
            // ID. Check the peer's limit before mutating the encoder table.
            let mem_size = headers
                .into_iter()
                .try_fold(0_u64, |size, field| {
                    size.checked_add(field.mem_size() as u64)
                })
                .ok_or_else(|| {
                    self.handle_connection_error_on_stream(InternalConnectionError::new(
                        Code::H3_INTERNAL_ERROR,
                        "request field section size overflowed".to_string(),
                    ))
                })?;
            if mem_size > peer_max_field_section_size {
                return Err(StreamError::HeaderTooBig {
                    actual_size: mem_size,
                    max_size: peer_max_field_section_size,
                });
            }
            stream = Self::open_request_stream_with_state(&mut self.open, &self.conn_state).await?;
            let mut guard =
                OpeningStream::<_, B>::new(&mut stream, self.decoder.as_ref(), &self.conn_state);

            let encoder_instructions_queued = match encoder.encode(
                guard.stream.send_id(),
                &mut self.qpack_encode_buffer,
                &headers,
            ) {
                Ok(encoded) => encoded,
                Err(error) => {
                    clear_qpack_encode_buffer(&mut self.qpack_encode_buffer);
                    return Err(self.handle_connection_error_on_stream(
                        InternalConnectionError::new(
                            Code::H3_INTERNAL_ERROR,
                            format!("failed to encode request headers: {error}"),
                        ),
                    ));
                }
            };

            drop(headers);
            let block = take_qpack_encode_buffer(&mut self.qpack_encode_buffer);
            if encoder_instructions_queued {
                self.waker().wake();
            }

            // Keep dynamic references tracked once encoding commits. A canceled
            // write may already be peer-visible and can still produce a Section
            // Acknowledgment or Stream Cancellation.
            Self::write_headers(guard.stream, block, &self.conn_state).await?;
            guard.complete = true;
        } else {
            let mem_size = match qpack::encode_stateless(&mut self.qpack_encode_buffer, &headers) {
                Ok(mem_size) => mem_size,
                Err(_error) => {
                    clear_qpack_encode_buffer(&mut self.qpack_encode_buffer);
                    return Err(self.handle_connection_error_on_stream(
                        InternalConnectionError::new(
                            Code::H3_INTERNAL_ERROR,
                            "failed to encode request headers".to_string(),
                        ),
                    ));
                }
            };

            // Keep the default path encoded before waiting for stream credit.
            drop(headers);
            let block = take_qpack_encode_buffer(&mut self.qpack_encode_buffer);
            if mem_size > peer_max_field_section_size {
                return Err(StreamError::HeaderTooBig {
                    actual_size: mem_size,
                    max_size: peer_max_field_section_size,
                });
            }
            stream = Self::open_request_stream_with_state(&mut self.open, &self.conn_state).await?;
            let mut guard =
                OpeningStream::<_, B>::new(&mut stream, self.decoder.as_ref(), &self.conn_state);
            Self::write_headers(guard.stream, block, &self.conn_state).await?;
            guard.complete = true;
        }

        let request_stream = RequestStream::new(connection::RequestStream::new(
            FrameStream::new(BufRecvStream::new(stream)),
            self.max_field_section_size,
            self.max_qpack_decode_buffer_size,
            self.send_grease_frame,
            self.conn_state.clone(),
            self.decoder.clone(),
        ));
        // send the grease frame only once
        self.send_grease_frame = false;
        Ok(request_stream)
    }

    async fn write_headers(
        stream: &mut T::BidiStream,
        block: Bytes,
        state: &SharedState,
    ) -> Result<(), StreamError> {
        stream::write(stream, Frame::Headers(block))
            .await
            .map_err(|e| state.handle_quic_stream_error(e))?;
        // GOAWAY can arrive while the headers are in flight.
        match state.request_error(stream.send_id()) {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    async fn open_request_stream_with_state(
        open: &mut T,
        state: &SharedState,
    ) -> Result<T::BidiStream, StreamError> {
        let mut stream = future::poll_fn(|cx| open.poll_open_bidi(cx))
            .await
            .map_err(|e| state.handle_quic_stream_error(e))?;
        if let Some(error) = state.check_peer_connection_closing() {
            // GOAWAY can race the transport's successful open.
            let _guard = OpeningStream::<_, B>::new(&mut stream, None, state);
            return Err(error);
        }
        Ok(stream)
    }
}

impl<T, B> Clone for SendRequest<T, B>
where
    T: quic::OpenStreams<B> + Clone,
    B: Buf,
{
    fn clone(&self) -> Self {
        Self {
            conn_state: self.conn_state.clone(),
            decoder: self.decoder.clone(),
            encoder: self.encoder.clone(),
            open: self.open.clone(),
            max_field_section_size: self.max_field_section_size,
            max_qpack_decode_buffer_size: self.max_qpack_decode_buffer_size,
            _buf: PhantomData,
            send_grease_frame: self.send_grease_frame,
            // Encoding buffers are worker-local mutable state. Sharing their
            // allocation would add synchronization to the request hot path.
            qpack_encode_buffer: BytesMut::new(),
        }
    }
}

/// Client connection driver
///
/// Owns the HTTP/3 connection lifetime, including control streams and QPACK.
/// Dropping it closes the connection with `H3_NO_ERROR` unless an earlier error
/// already determined the outcome. Dropping request senders does not stop it.
///
/// Dropping the driver is immediate closure, not graceful shutdown: finish any
/// required transfers and transport acknowledgments first. See
/// [RFC 9114 Section 5.3](https://www.rfc-editor.org/rfc/rfc9114.html#section-5.3).
///
/// It needs to be polled continuously via [`poll_close()`]. On connection closure,
/// this returns a [`ConnectionError`]; use [`ConnectionError::is_h3_no_error()`]
/// to distinguish a normal close from an error.
///
/// [`shutdown()`] initiates a graceful shutdown of this connection. After calling it, no request
/// initiation will be further allowed. Continue driving the connection while
/// existing requests finish. This method sends GOAWAY; it does not itself wait
/// for requests to finish or close the QUIC connection.
///
/// # Examples
///
/// ## Drive a connection concurrently
///
/// ```rust
/// # use bytes::Buf;
/// # use futures_util::future;
/// # use http3::{client::*, quic};
/// # use tokio::task::JoinHandle;
/// # async fn doc<C, B>(mut connection: Connection<C, B>)
/// #    -> JoinHandle<Result<(), Box<dyn std::error::Error + Send + Sync>>>
/// # where
/// #    C: quic::Connection<B> + Send + 'static,
/// #    C::SendStream: quic::SendStreamUnframed<B>,
/// #    C::SendStream: Send + 'static,
/// #    C::RecvStream: Send + 'static,
/// #    B: Buf + Send + 'static,
/// # {
/// // Run the driver on a different task
/// tokio::spawn(async move {
///     future::poll_fn(|cx| connection.poll_close(cx)).await;
///     Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
/// })
/// # }
/// ```
///
/// ## Shutdown a connection gracefully
///
/// ```rust
/// # use bytes::Buf;
/// # use futures_util::future;
/// # use http3::quic;
/// # use http3::client::Connection;
/// # use http3::client::SendRequest;
/// # use tokio::{self, sync::oneshot, task::JoinHandle};
/// # async fn doc<C, B>(mut connection: Connection<C, B>)
/// #    -> Result<(), Box<dyn std::error::Error + Send + Sync>>
/// # where
/// #    C: quic::Connection<B> + Send + 'static,
/// #    C::SendStream: quic::SendStreamUnframed<B>,
/// #    C::SendStream: Send + 'static,
/// #    C::RecvStream: Send + 'static,
/// #    B: Buf + Send + 'static,
/// # {
/// // Prepare a channel to stop the driver thread
/// let (shutdown_tx, shutdown_rx) = oneshot::channel();
///
/// // Run the driver on a different task
/// let driver = tokio::spawn(async move {
///     tokio::select! {
///         // Drive the connection
///         closed = future::poll_fn(|cx| connection.poll_close(cx)) => closed,
///         // Listen for shutdown condition
///         max_streams = shutdown_rx => {
///             // Initiate shutdown
///             connection.shutdown(max_streams?).await?;
///             // Wait for peer closure; applications may instead finish their
///             // outstanding requests and then drop the driver.
///             future::poll_fn(|cx| connection.poll_close(cx)).await
///         }
///     };
///
///     Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
/// });
///
/// // Do client things, wait for close condition...
///
/// // Initiate shutdown
/// shutdown_tx.send(2);
/// // Wait for the connection to be closed
/// driver.await?
/// # }
/// ```
/// [`poll_close()`]: struct.Connection.html#method.poll_close
/// [`shutdown()`]: struct.Connection.html#method.shutdown
pub struct Connection<C, B>
where
    C: quic::Connection<B>,
    B: Buf,
{
    /// TODO: breaking encapsulation for RFC9298.
    pub inner: ConnectionInner<C, B>,
    // Has a GOAWAY frame been sent? If so, this PushId is the last we are willing to accept.
    pub(super) sent_closing: Option<PushId>,
    // Has a GOAWAY frame been received? If so, this is StreamId the last the remote will accept.
    pub(super) recv_closing: Option<StreamId>,
}

impl<C, B> ConnectionState for Connection<C, B>
where
    C: quic::Connection<B>,
    B: Buf,
{
    fn shared_state(&self) -> &SharedState {
        &self.inner.shared
    }
}

impl<C, B> Connection<C, B>
where
    C: quic::Connection<B>,
    C::SendStream: quic::SendStreamUnframed<B>,
    B: Buf,
{
    /// Initiate a graceful shutdown, accepting `max_push` potentially in-flight server pushes
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub async fn shutdown(&mut self, _max_push: usize) -> Result<(), ConnectionError> {
        // TODO: Calculate remaining pushes once server push is implemented.
        self.inner.shutdown(&mut self.sent_closing, PushId(0)).await
    }

    /// Wait until the connection is closed
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub async fn wait_idle(&mut self) -> ConnectionError {
        future::poll_fn(|cx| self.poll_close(cx)).await
    }

    /// Maintain the connection state until it is closed
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub fn poll_close(&mut self, cx: &mut Context<'_>) -> Poll<ConnectionError> {
        if let Err(err) = self.inner.poll_accept_recv(cx) {
            return Poll::Ready(err);
        }

        if let Err(err) = self.inner.poll_qpack(cx) {
            return Poll::Ready(err);
        }

        while let Poll::Ready(result) = self.inner.poll_accepted_control(cx) {
            match result {
                //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.4.2
                //= type=TODO
                //# When a 0-RTT QUIC connection is being used, the initial value of each
                //# server setting is the value used in the previous session.  Clients
                //# SHOULD store the settings the server provided in the HTTP/3
                //# connection where resumption information was provided, but they MAY
                //# opt not to store settings in certain cases (e.g., if the session
                //# ticket is received before the SETTINGS frame).

                //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.4.2
                //= type=TODO
                //# A client MUST comply
                //# with stored settings -- or default values if no values are stored --
                //# when attempting 0-RTT.

                //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.4.2
                //= type=TODO
                //# Once a server has provided new settings,
                //# clients MUST comply with those values.
                Ok(Frame::Settings(_)) => {
                    #[cfg(feature = "tracing")]
                    trace!("Got settings");
                }

                Ok(Frame::Goaway(id)) => {
                    //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.6
                    //# The GOAWAY frame is always sent on the control stream.  In the
                    //# server-to-client direction, it carries a QUIC stream ID for a client-
                    //# initiated bidirectional stream encoded as a variable-length integer.
                    //# A client MUST treat receipt of a GOAWAY frame containing a stream ID
                    //# of any other type as a connection error of type H3_ID_ERROR.
                    if !StreamId::from(id).is_request() {
                        return Poll::Ready(self.inner.handle_connection_error(
                            InternalConnectionError::new(
                                Code::H3_ID_ERROR,
                                format!("non-request StreamId in a GoAway frame: {}", id),
                            ),
                        ));
                    }
                    if let Err(err) = self.inner.process_goaway(&mut self.recv_closing, id) {
                        return Poll::Ready(err);
                    }
                    self.inner.shared.set_peer_goaway(StreamId::from(id));

                    #[cfg(feature = "tracing")]
                    info!("Server initiated graceful shutdown, last: StreamId({})", id);
                }

                //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.5
                //# If a PUSH_PROMISE frame is received on the control stream, the client
                //# MUST respond with a connection error of type H3_FRAME_UNEXPECTED.

                //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.7
                //# A client MUST treat the
                //# receipt of a MAX_PUSH_ID frame as a connection error of type
                //# H3_FRAME_UNEXPECTED.
                Ok(frame) => {
                    return Poll::Ready(self.inner.handle_connection_error(
                        InternalConnectionError::new(
                            Code::H3_FRAME_UNEXPECTED,
                            format!("on client control stream: {:?}", frame),
                        ),
                    ));
                }
                Err(connection_error) => {
                    return Poll::Ready(connection_error);
                }
            }
        }

        //= https://www.rfc-editor.org/rfc/rfc9114#section-6.1
        //# Clients MUST treat
        //# receipt of a server-initiated bidirectional stream as a connection
        //# error of type H3_STREAM_CREATION_ERROR unless such an extension has
        //# been negotiated.
        if self.inner.poll_accept_bi(cx).is_ready() {
            return Poll::Ready(
                self.inner
                    .handle_connection_error(InternalConnectionError::new(
                        Code::H3_STREAM_CREATION_ERROR,
                        "client received a server-initiated bidirectional stream".to_string(),
                    )),
            );
        }

        Poll::Pending
    }
}

impl<C, B> Drop for Connection<C, B>
where
    C: quic::Connection<B>,
    B: Buf,
{
    fn drop(&mut self) {
        // Publish the cause and wake QPACK waiters before closing the transport.
        self.inner
            .handle_connection_error(InternalConnectionError::new(
                Code::H3_NO_ERROR,
                "Connection driver dropped".to_string(),
            ));
    }
}

// Protect the open stream before its public RequestStream owner exists.
// https://www.rfc-editor.org/rfc/rfc9114.html#section-4.1.1
struct OpeningStream<'a, S: quic::SendStream<B> + quic::RecvStream, B: Buf> {
    stream: &'a mut S,
    complete: bool,
    buffer: PhantomData<fn(B)>,
    decoder: Option<&'a QpackDecoder>,
    shared: &'a SharedState,
}

impl<'a, S: quic::SendStream<B> + quic::RecvStream, B: Buf> OpeningStream<'a, S, B> {
    fn new(stream: &'a mut S, decoder: Option<&'a QpackDecoder>, shared: &'a SharedState) -> Self {
        Self {
            stream,
            complete: false,
            buffer: PhantomData,
            decoder,
            shared,
        }
    }
}

impl<S: quic::SendStream<B> + quic::RecvStream, B: Buf> Drop for OpeningStream<'_, S, B> {
    fn drop(&mut self) {
        if !self.complete {
            self.stream.reset(Code::H3_REQUEST_CANCELLED.value());
            self.stream.stop_sending(Code::H3_REQUEST_CANCELLED.value());
            // Abandoning the response also releases the peer encoder's
            // references; our request encoder still waits for peer feedback.
            // https://www.rfc-editor.org/rfc/rfc9204.html#section-2.2.2.2
            if let Some(decoder) = self.decoder
                && decoder.queue_stream_cancellation(self.stream.recv_id())
            {
                self.shared.waker().wake();
            }
        }
    }
}

#[cfg(test)]
mod integration_tests {
    use std::{
        future::{Future, poll_fn},
        sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    };

    use futures_util::task::{ArcWake, waker};

    use super::*;
    use crate::quic::{OpenStreams, RecvStream, StreamErrorIncoming, WriteBuf};

    #[derive(Default)]
    struct State {
        block_open: AtomicBool,
        block_write: AtomicBool,
        block_finish: AtomicBool,
        read: std::sync::Mutex<Option<Bytes>>,
        reject_on_read: std::sync::OnceLock<Arc<SharedState>>,
        opened: AtomicUsize,
        written: AtomicBool,
        reset: AtomicU64,
        stopped: AtomicU64,
        reset_calls: AtomicUsize,
        stop_calls: AtomicUsize,
        wakes: AtomicUsize,
        close_on_open: std::sync::OnceLock<Arc<SharedState>>,
    }

    impl ArcWake for State {
        fn wake_by_ref(state: &Arc<Self>) {
            state.wakes.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[derive(Clone)]
    struct Mock(Arc<State>);

    impl OpenStreams<Bytes> for Mock {
        type BidiStream = Self;
        type SendStream = Self;
        fn poll_open_bidi(
            &mut self,
            _: &mut Context<'_>,
        ) -> Poll<Result<Self, StreamErrorIncoming>> {
            if self.0.block_open.load(Ordering::Relaxed) {
                return Poll::Pending;
            }
            self.0.opened.fetch_add(1, Ordering::Relaxed);
            if let Some(shared) = self.0.close_on_open.get() {
                shared.set_closing();
            }
            Poll::Ready(Ok(self.clone()))
        }

        fn poll_open_send(
            &mut self,
            _: &mut Context<'_>,
        ) -> Poll<Result<Self, StreamErrorIncoming>> {
            unreachable!()
        }

        fn close(&mut self, _: Code, _: &[u8]) {}
    }

    impl SendStream<Bytes> for Mock {
        fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
            if self.0.block_write.load(Ordering::Relaxed) {
                Poll::Pending
            } else {
                Poll::Ready(Ok(()))
            }
        }

        fn send_data<D: Into<WriteBuf<Bytes>>>(&mut self, _: D) -> Result<(), StreamErrorIncoming> {
            self.0.written.store(true, Ordering::Relaxed);
            Ok(())
        }

        fn poll_finish(&mut self, _: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
            if self.0.block_finish.load(Ordering::Relaxed) {
                Poll::Pending
            } else {
                Poll::Ready(Ok(()))
            }
        }

        fn poll_stopped(
            &mut self,
            _: &mut Context<'_>,
        ) -> Poll<Result<Option<u64>, StreamErrorIncoming>> {
            Poll::Pending
        }

        fn reset(&mut self, code: u64) {
            self.0.reset.store(code, Ordering::Relaxed);
            self.0.reset_calls.fetch_add(1, Ordering::Relaxed);
        }

        fn send_id(&self) -> StreamId {
            StreamId::try_from(0).unwrap()
        }
    }

    impl RecvStream for Mock {
        type Buf = Bytes;
        fn poll_data(
            &mut self,
            _: &mut Context<'_>,
        ) -> Poll<Result<Option<Bytes>, StreamErrorIncoming>> {
            if let Some(shared) = self.0.reject_on_read.get() {
                shared.set_peer_goaway(StreamId::try_from(0).unwrap());
            }
            if let Some(bytes) = self.0.read.lock().unwrap().take() {
                return Poll::Ready(Ok(Some(bytes)));
            }
            Poll::Pending
        }
        fn stop_sending(&mut self, code: u64) {
            self.0.stopped.store(code, Ordering::Relaxed);
            self.0.stop_calls.fetch_add(1, Ordering::Relaxed);
        }
        fn recv_id(&self) -> StreamId {
            self.send_id()
        }
    }

    impl quic::BidiStream<Bytes> for Mock {
        type SendStream = Self;
        type RecvStream = Self;
        fn split(self) -> (Self, Self) {
            (self.clone(), self)
        }
    }

    fn sender(state: &Arc<State>, dynamic: bool) -> SendRequest<Mock, Bytes> {
        let encoder = dynamic.then(|| {
            let encoder = QpackEncoder::default();
            encoder.configure(4096, 4096).unwrap();
            encoder.take_pending_instructions().unwrap();
            assert!(encoder.ready().unwrap());
            encoder
        });
        SendRequest {
            open: Mock(state.clone()),
            conn_state: Arc::default(),
            decoder: None,
            encoder,
            max_field_section_size: 65536,
            max_qpack_decode_buffer_size: 262144,
            _buf: PhantomData,
            send_grease_frame: false,
            qpack_encode_buffer: BytesMut::new(),
        }
    }

    fn request() -> http::Request<()> {
        http::Request::get("https://localhost/").body(()).unwrap()
    }

    fn returned(sender: &mut SendRequest<Mock, Bytes>) -> RequestStream<Mock, Bytes> {
        match std::pin::pin!(sender.send_request(request())).poll(&mut Context::from_waker(
            futures_util::task::noop_waker_ref(),
        )) {
            Poll::Ready(Ok(stream)) => stream,
            _ => panic!("request did not open"),
        }
    }

    fn request_operation(
        stream: &mut RequestStream<Mock, Bytes>,
        operation: usize,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<(), StreamError>> + '_>> {
        Box::pin(async move {
            match operation {
                0 => stream.recv_response().await.map(|_| ()),
                1 => stream.recv_data().await.map(|_| ()),
                2 => stream.recv_trailers().await.map(|_| ()),
                3 => stream.send_data(Bytes::from_static(b"body")).await,
                4 => stream.send_trailers(http::HeaderMap::new()).await,
                5 => stream.finish().await,
                6 => poll_fn(|cx| stream.poll_stopped(cx)).await.map(|_| ()),
                _ => unreachable!(),
            }
        })
    }

    fn prepare_response_body(
        stream: &mut RequestStream<Mock, Bytes>,
        state: &State,
        operation: usize,
    ) {
        if matches!(operation, 1 | 2) {
            *state.read.lock().unwrap() = Some(Bytes::from_static(&[1, 3, 0, 0, 0xd9]));
            assert!(matches!(
                std::pin::pin!(stream.recv_response()).poll(&mut Context::from_waker(futures_util::task::noop_waker_ref())),
                Poll::Ready(Ok(response)) if response.status() == 200
            ));
        }
    }

    #[test]
    fn goaway_rejects_returned_request_operations_on_next_poll_and_cancels_directions() {
        for terminal_error in [false, true] {
            for operation in 0..7 {
                let state = Arc::new(State::default());
                let mut sender = sender(&state, false);
                let mut stream = returned(&mut sender);
                prepare_response_body(&mut stream, &state, operation);
                state.block_write.store(true, Ordering::Relaxed);
                state.block_finish.store(true, Ordering::Relaxed);
                let waker = waker(state.clone());
                let mut cx = Context::from_waker(&waker);
                let mut waiting = request_operation(&mut stream, operation);
                assert!(waiting.as_mut().poll(&mut cx).is_pending());
                if terminal_error {
                    sender
                        .conn_state
                        .set_conn_error(quic::ConnectionErrorIncoming::Timeout.into());
                } else {
                    sender
                        .conn_state
                        .set_peer_goaway(StreamId::try_from(0).unwrap());
                }
                assert_eq!(
                    state.wakes.load(Ordering::Relaxed),
                    0,
                    "operation {operation}"
                );
                match waiting.as_mut().poll(&mut cx) {
                    Poll::Ready(Err(StreamError::ConnectionError(ConnectionError::Timeout)))
                        if terminal_error => {}
                    Poll::Ready(Err(StreamError::GoawayRejected {
                        stream_id,
                        boundary,
                    })) if !terminal_error => {
                        assert_eq!(stream_id, boundary);
                    }
                    _ => panic!("operation {operation} did not receive its error"),
                }
                drop(waiting);
                let code = if terminal_error {
                    0
                } else {
                    Code::H3_REQUEST_CANCELLED.value()
                };
                assert_eq!(state.reset.load(Ordering::Relaxed), code);
                assert_eq!(state.stopped.load(Ordering::Relaxed), code);
            }
        }
    }

    #[test]
    fn goaway_rejects_both_split_halves_independently() {
        for send_operation in 3..7 {
            for recv_operation in 0..3 {
                let state = Arc::new(State::default());
                let mut sender = sender(&state, false);
                let (mut send, mut recv) = returned(&mut sender).split();
                prepare_response_body(&mut recv, &state, recv_operation);
                state.block_write.store(true, Ordering::Relaxed);
                state.block_finish.store(true, Ordering::Relaxed);
                let send_wakes = Arc::new(State::default());
                let recv_wakes = Arc::new(State::default());
                let send_waker = waker(send_wakes.clone());
                let recv_waker = waker(recv_wakes.clone());
                let mut send_cx = Context::from_waker(&send_waker);
                let mut recv_cx = Context::from_waker(&recv_waker);
                let mut sending = request_operation(&mut send, send_operation);
                let mut receiving = request_operation(&mut recv, recv_operation);
                assert!(sending.as_mut().poll(&mut send_cx).is_pending());
                assert!(receiving.as_mut().poll(&mut recv_cx).is_pending());
                sender
                    .conn_state
                    .set_peer_goaway(StreamId::try_from(0).unwrap());
                assert_eq!(send_wakes.wakes.load(Ordering::Relaxed), 0);
                assert_eq!(recv_wakes.wakes.load(Ordering::Relaxed), 0);
                assert!(matches!(
                    receiving.as_mut().poll(&mut recv_cx),
                    Poll::Ready(Err(StreamError::GoawayRejected { .. }))
                ));
                assert_eq!(
                    state.stopped.load(Ordering::Relaxed),
                    Code::H3_REQUEST_CANCELLED.value()
                );
                assert_eq!(state.reset.load(Ordering::Relaxed), 0);
                assert!(matches!(
                    sending.as_mut().poll(&mut send_cx),
                    Poll::Ready(Err(StreamError::GoawayRejected { .. }))
                ));
                assert_eq!(
                    state.reset.load(Ordering::Relaxed),
                    Code::H3_REQUEST_CANCELLED.value()
                );
            }
        }
    }

    #[test]
    fn goaway_during_transport_poll_is_not_lost() {
        let state = Arc::new(State::default());
        let mut sender = sender(&state, false);
        let mut stream = returned(&mut sender);
        state.reject_on_read.set(sender.conn_state.clone()).unwrap();
        let mut cx = Context::from_waker(futures_util::task::noop_waker_ref());
        assert!(matches!(
            std::pin::pin!(stream.recv_response()).poll(&mut cx),
            Poll::Ready(Err(StreamError::GoawayRejected { .. }))
        ));
    }

    #[test]
    fn goaway_is_checked_before_ready_writes() {
        let state = Arc::new(State::default());
        let mut sender = sender(&state, false);
        let mut stream = returned(&mut sender);
        state.written.store(false, Ordering::Relaxed);
        sender
            .conn_state
            .set_peer_goaway(StreamId::try_from(0).unwrap());
        let mut cx = Context::from_waker(futures_util::task::noop_waker_ref());
        assert!(matches!(
            std::pin::pin!(stream.send_data(Bytes::from_static(b"body"))).poll(&mut cx),
            Poll::Ready(Err(StreamError::GoawayRejected { .. }))
        ));
        assert!(!state.written.load(Ordering::Relaxed));
    }

    #[test]
    fn goaway_preserves_completed_directions_and_cancels_remaining_once() {
        for split in [false, true] {
            // Open upload, completed upload, explicitly reset upload.
            for send_state in 0..3 {
                for stopped_receive in [false, true] {
                    let state = Arc::new(State::default());
                    let mut sender = sender(&state, false);
                    let mut stream = returned(&mut sender);
                    let mut cx = Context::from_waker(futures_util::task::noop_waker_ref());
                    if send_state == 1 {
                        assert!(matches!(
                            std::pin::pin!(stream.finish()).poll(&mut cx),
                            Poll::Ready(Ok(()))
                        ));
                    } else if send_state == 2 {
                        stream.stop_stream(Code::H3_NO_ERROR);
                    }
                    if stopped_receive {
                        stream.stop_sending(Code::H3_MESSAGE_ERROR);
                    }
                    sender
                        .conn_state
                        .set_peer_goaway(StreamId::try_from(0).unwrap());
                    if split {
                        let (mut send, mut recv) = stream.split();
                        for _ in 0..2 {
                            assert!(matches!(
                                std::pin::pin!(send.finish()).poll(&mut cx),
                                Poll::Ready(Err(StreamError::GoawayRejected { .. }))
                            ));
                            assert!(matches!(
                                recv.poll_recv_data(&mut cx),
                                Poll::Ready(Err(StreamError::GoawayRejected { .. }))
                            ));
                        }
                        drop((send, recv));
                    } else {
                        for _ in 0..2 {
                            assert!(matches!(
                                stream.poll_recv_data(&mut cx),
                                Poll::Ready(Err(StreamError::GoawayRejected { .. }))
                            ));
                        }
                        drop(stream);
                    }
                    assert_eq!(
                        state.reset_calls.load(Ordering::Relaxed),
                        usize::from(send_state != 1)
                    );
                    assert_eq!(
                        state.reset.load(Ordering::Relaxed),
                        match send_state {
                            0 => Code::H3_REQUEST_CANCELLED.value(),
                            1 => 0,
                            _ => Code::H3_NO_ERROR.value(),
                        }
                    );
                    assert_eq!(state.stop_calls.load(Ordering::Relaxed), 1);
                    assert_eq!(
                        state.stopped.load(Ordering::Relaxed),
                        if stopped_receive {
                            Code::H3_MESSAGE_ERROR.value()
                        } else {
                            Code::H3_REQUEST_CANCELLED.value()
                        }
                    );
                }
            }
        }
    }

    #[test]
    fn goaway_rejection_cancels_qpack_blocked_response_on_next_poll() {
        let state = Arc::new(State::default());
        let mut sender = sender(&state, false);
        let (events_tx, mut events_rx) = tokio::sync::mpsc::unbounded_channel();
        sender.decoder = Some(QpackDecoder::new(
            qpack::Decoder::new(256, 1).unwrap(),
            events_tx,
        ));
        let mut stream = returned(&mut sender);
        // HEADERS with Required Insert Count 1, but the insertion has not arrived.
        *state.read.lock().unwrap() = Some(Bytes::from_static(&[1, 3, 2, 0, 0x80]));
        let task_waker = waker(state.clone());
        let mut cx = Context::from_waker(&task_waker);
        let mut waiting = Box::pin(stream.recv_response());
        assert!(waiting.as_mut().poll(&mut cx).is_pending());
        assert!(matches!(
            events_rx.try_recv(),
            Ok(qpack::QpackEvent::RegisterBlocked {
                required_ref: 1,
                ..
            })
        ));
        sender
            .conn_state
            .set_peer_goaway(StreamId::try_from(0).unwrap());
        assert_eq!(state.wakes.load(Ordering::Relaxed), 0);
        assert!(matches!(
            waiting.as_mut().poll(&mut cx),
            Poll::Ready(Err(StreamError::GoawayRejected { .. }))
        ));
        drop(waiting);
        drop(stream);
        assert!(matches!(
            events_rx.try_recv(),
            Ok(qpack::QpackEvent::ReleaseBlocked {
                required_ref: 1,
                ..
            })
        ));
        assert!(matches!(
            events_rx.try_recv(),
            Ok(qpack::QpackEvent::StreamCancel(id)) if id.into_inner() == 0
        ));
        assert!(events_rx.try_recv().is_err());
    }

    #[test]
    fn goaway_rejects_poll_receivers_only_at_or_below_their_stream() {
        for trailers in [false, true] {
            let state = Arc::new(State::default());
            let mut sender = sender(&state, false);
            let mut stream = returned(&mut sender);
            prepare_response_body(&mut stream, &state, if trailers { 2 } else { 1 });
            let first_wakes = Arc::new(State::default());
            let second_wakes = Arc::new(State::default());
            let first_waker = waker(first_wakes.clone());
            let second_waker = waker(second_wakes.clone());
            let mut first_cx = Context::from_waker(&first_waker);
            let mut second_cx = Context::from_waker(&second_waker);
            let mut poll = |cx: &mut Context<'_>| {
                if trailers {
                    stream.poll_recv_trailers(cx).map_ok(|_| ())
                } else {
                    stream.poll_recv_data(cx).map_ok(|_| ())
                }
            };
            assert!(poll(&mut first_cx).is_pending());
            // A boundary above this request changes nothing for it.
            sender
                .conn_state
                .set_peer_goaway(StreamId::try_from(4).unwrap());
            assert_eq!(first_wakes.wakes.load(Ordering::Relaxed), 0);
            assert!(poll(&mut second_cx).is_pending());
            sender
                .conn_state
                .set_peer_goaway(StreamId::try_from(0).unwrap());
            assert_eq!(second_wakes.wakes.load(Ordering::Relaxed), 0);
            assert_eq!(first_wakes.wakes.load(Ordering::Relaxed), 0);
            assert!(matches!(
                poll(&mut second_cx),
                Poll::Ready(Err(StreamError::GoawayRejected { .. }))
            ));
        }
    }

    #[test]
    fn pending_headers_cancel_both_directions_in_both_encoders() {
        for dynamic in [false, true] {
            let state = Arc::new(State::default());
            state.block_write.store(true, Ordering::Relaxed);
            let mut sender = sender(&state, dynamic);
            let (events_tx, mut events_rx) = tokio::sync::mpsc::unbounded_channel();
            sender.decoder = Some(QpackDecoder::new(
                qpack::Decoder::new(4096, 16).unwrap(),
                events_tx,
            ));
            let mut sending = Box::pin(sender.send_request(request()));
            assert!(
                sending
                    .as_mut()
                    .poll(&mut Context::from_waker(
                        futures_util::task::noop_waker_ref()
                    ))
                    .is_pending()
            );
            assert!(state.written.load(Ordering::Relaxed));
            drop(sending);
            assert!(matches!(
                events_rx.try_recv(),
                Ok(qpack::QpackEvent::StreamCancel(id)) if id.into_inner() == 0
            ));
            assert!(events_rx.try_recv().is_err());
            assert_eq!(
                state.reset.load(Ordering::Relaxed),
                Code::H3_REQUEST_CANCELLED.value()
            );
            assert_eq!(
                state.stopped.load(Ordering::Relaxed),
                Code::H3_REQUEST_CANCELLED.value()
            );
        }
    }

    #[test]
    fn closing_rejects_blocked_opens_once_the_transport_completes_them() {
        let state = Arc::new(State::default());
        state.block_open.store(true, Ordering::Relaxed);
        let mut first = sender(&state, false);
        let mut second = first.clone();
        let shared = first.conn_state.clone();
        let waker = waker(state.clone());
        let mut cx = Context::from_waker(&waker);
        let mut a = Box::pin(first.send_request(request()));
        let mut b = Box::pin(second.send_request(request()));
        assert!(a.as_mut().poll(&mut cx).is_pending());
        assert!(b.as_mut().poll(&mut cx).is_pending());
        // Closing wakes nothing; the open is rejected once the transport
        // completes it, and the unusable stream is cancelled.
        shared.set_closing();
        assert_eq!(state.wakes.load(Ordering::Relaxed), 0);
        assert!(a.as_mut().poll(&mut cx).is_pending());
        state.block_open.store(false, Ordering::Relaxed);
        assert!(matches!(
            a.as_mut().poll(&mut cx),
            Poll::Ready(Err(StreamError::ConnectionClosing))
        ));
        assert!(matches!(
            b.as_mut().poll(&mut cx),
            Poll::Ready(Err(StreamError::ConnectionClosing))
        ));
        assert_eq!(state.opened.load(Ordering::Relaxed), 2);
        assert!(!state.written.load(Ordering::Relaxed));
        assert_eq!(
            state.reset.load(Ordering::Relaxed),
            Code::H3_REQUEST_CANCELLED.value()
        );
        assert_eq!(
            state.stopped.load(Ordering::Relaxed),
            Code::H3_REQUEST_CANCELLED.value()
        );

        let state = Arc::new(State::default());
        let mut sender = sender(&state, false);
        state.close_on_open.set(sender.conn_state.clone()).unwrap();
        assert!(matches!(
            std::pin::pin!(sender.send_request(request()))
                .as_mut()
                .poll(&mut cx),
            Poll::Ready(Err(StreamError::ConnectionClosing))
        ));
        assert!(!state.written.load(Ordering::Relaxed));
        assert_eq!(
            state.reset.load(Ordering::Relaxed),
            Code::H3_REQUEST_CANCELLED.value()
        );
        assert_eq!(
            state.stopped.load(Ordering::Relaxed),
            Code::H3_REQUEST_CANCELLED.value()
        );
    }

    #[test]
    fn decreasing_goaway_rejects_written_headers_only_at_boundary() {
        for dynamic in [false, true] {
            for (boundary, rejected) in [(4, false), (0, true)] {
                let state = Arc::new(State::default());
                state.block_write.store(true, Ordering::Relaxed);
                let mut sender = sender(&state, dynamic);
                let shared = sender.conn_state.clone();
                let waker = waker(state.clone());
                let mut cx = Context::from_waker(&waker);
                let mut sending = Box::pin(sender.send_request(request()));
                assert!(sending.as_mut().poll(&mut cx).is_pending());
                shared.set_peer_goaway(StreamId::try_from(boundary).unwrap());
                shared.set_closing();
                // The blocked write is not interrupted; the boundary is checked
                // once the headers are written.
                assert_eq!(state.wakes.load(Ordering::Relaxed), 0);
                assert!(sending.as_mut().poll(&mut cx).is_pending());
                state.block_write.store(false, Ordering::Relaxed);
                let result = sending.as_mut().poll(&mut cx);
                if rejected {
                    assert!(matches!(
                        result,
                        Poll::Ready(Err(StreamError::GoawayRejected { stream_id, boundary }))
                            if stream_id == boundary
                    ));
                    drop(sending);
                    assert_eq!(
                        state.reset.load(Ordering::Relaxed),
                        Code::H3_REQUEST_CANCELLED.value()
                    );
                    assert_eq!(
                        state.stopped.load(Ordering::Relaxed),
                        Code::H3_REQUEST_CANCELLED.value()
                    );
                } else {
                    assert!(matches!(result, Poll::Ready(Ok(_))));
                    assert_eq!(state.reset.load(Ordering::Relaxed), 0);
                    assert_eq!(state.stopped.load(Ordering::Relaxed), 0);
                }
            }
        }
    }

    #[test]
    fn successful_headers_disarm_guard_and_invalid_requests_preserve_connection() {
        for dynamic in [false, true] {
            let state = Arc::new(State::default());
            let mut sender = sender(&state, dynamic);
            let mut cx = Context::from_waker(futures_util::task::noop_waker_ref());
            for invalid in [
                http::Request::get("/").body(()).unwrap(),
                http::Request::get("https://localhost/")
                    .header("host", "other")
                    .body(())
                    .unwrap(),
            ] {
                assert!(matches!(
                    std::pin::pin!(sender.send_request(invalid))
                        .as_mut()
                        .poll(&mut cx),
                    Poll::Ready(Err(StreamError::InvalidRequest { .. }))
                ));
                assert!(sender.get_conn_error().is_none());
                assert_eq!(state.opened.load(Ordering::Relaxed), 0);
            }
            let stream = returned(&mut sender);
            assert_eq!(state.reset.load(Ordering::Relaxed), 0);
            assert_eq!(state.stopped.load(Ordering::Relaxed), 0);
            // HEADERS completion transfers cancellation to the returned owner.
            drop(stream);
            assert_eq!(
                state.reset.load(Ordering::Relaxed),
                Code::H3_REQUEST_CANCELLED.value()
            );
            assert_eq!(
                state.stopped.load(Ordering::Relaxed),
                Code::H3_REQUEST_CANCELLED.value()
            );
        }
    }
}

#[cfg(test)]
mod qpack_encode_buffer_tests {
    use super::*;

    #[test]
    fn taken_blocks_remain_independent_and_large_storage_is_not_retained() {
        let mut buffer = BytesMut::with_capacity(64);
        buffer.extend_from_slice(b"first");
        let first = take_qpack_encode_buffer(&mut buffer);

        buffer.extend_from_slice(b"second");
        let second = take_qpack_encode_buffer(&mut buffer);

        assert_eq!(first, b"first"[..]);
        assert_eq!(second, b"second"[..]);

        let mut large = BytesMut::with_capacity(MAX_RETAINED_QPACK_ENCODE_CAPACITY + 1);
        large.extend_from_slice(b"large");
        assert_eq!(take_qpack_encode_buffer(&mut large), b"large"[..]);
        assert_eq!(large.capacity(), 0);
    }

    #[test]
    fn clearing_drops_only_oversized_storage() {
        let mut small = BytesMut::with_capacity(64);
        small.extend_from_slice(b"partial");
        clear_qpack_encode_buffer(&mut small);
        assert!(small.is_empty());
        assert!(small.capacity() >= 64);

        let mut large = BytesMut::with_capacity(MAX_RETAINED_QPACK_ENCODE_CAPACITY + 1);
        large.extend_from_slice(b"partial");
        clear_qpack_encode_buffer(&mut large);
        assert!(large.is_empty());
        assert_eq!(large.capacity(), 0);
    }
}
