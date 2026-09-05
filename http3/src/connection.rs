use std::{
    convert::TryFrom,
    marker::PhantomData,
    sync::Arc,
    task::{Context, Poll, Waker},
};

use bytes::{Buf, Bytes, BytesMut};
use futures_util::{future, ready};
use http::HeaderMap;
use stream::WriteBuf;
use tokio::sync::mpsc;
#[cfg(feature = "tracing")]
use tracing::{instrument, warn};

use crate::{
    config::Config,
    error::{
        Code, ConnectionError, StreamError,
        connection_error_creators::{
            CloseRawQuicConnection, CloseStream, HandleFrameStreamErrorOnRequestStream,
        },
        internal_error::InternalConnectionError,
    },
    frame::{FrameStream, FrameStreamError},
    proto::{
        frame::{self, Frame, PayloadLen},
        headers::Header,
        stream::StreamType,
        varint::VarInt,
    },
    qpack::{self, QpackDecoder, QpackEvent},
    quic::{self, RecvStream, SendStream, SendStreamUnframed, StreamErrorIncoming, StreamId},
    shared_state::{ConnectionState, SharedState},
    stream::{self, AcceptRecvStream, AcceptedRecvStream, BufRecvStream, UniStreamHeader},
    webtransport::SessionId,
};

#[allow(missing_docs)]
pub struct AcceptedStreams<C, B>
where
    C: quic::Connection<B>,
    B: Buf,
{
    #[allow(missing_docs)]
    pub wt_uni_streams: Vec<(SessionId, BufRecvStream<C::RecvStream, B>)>,
}

impl<B, C> Default for AcceptedStreams<C, B>
where
    C: quic::Connection<B>,
    B: Buf,
{
    fn default() -> Self {
        Self {
            wt_uni_streams: Default::default(),
        }
    }
}

pub(crate) struct QpackStreams<C, B>
where
    C: quic::Connection<B>,
    B: Buf,
{
    decoder_send_buf: BytesMut,
    decoder_send: Option<C::SendStream>,
    decoder_recv: Option<AcceptedRecvStream<C::RecvStream, B>>,
    encoder: qpack::QpackEncoder,
    // Active prefix of the same committed encoder-stream output queue held by
    // `QpackEncoder`; moving a batch here does not make it retractable.
    encoder_send_buf: Bytes,
    encoder_send: Option<C::SendStream>,
    encoder_recv: Option<AcceptedRecvStream<C::RecvStream, B>>,
    decoder: QpackDecoder,
    blocked_streams: qpack::BlockedStreamRegistry,
    decoder_events_recv: mpsc::UnboundedReceiver<QpackEvent>,
}

fn invalid_qpack_decoder_configuration(error: qpack::DecoderError) -> InternalConnectionError {
    // This failure comes from a local setting that cannot be represented on
    // the current target, not from a field section received from the peer.
    // https://www.rfc-editor.org/rfc/rfc9204.html#section-6
    InternalConnectionError::new(
        Code::H3_INTERNAL_ERROR,
        format!("invalid QPACK decoder configuration: {error}"),
    )
}

fn local_settings(config: &Config) -> Result<frame::Settings, frame::SettingsError> {
    #[cfg(test)]
    if !config.send_settings {
        return Ok(frame::Settings::default());
    }

    frame::Settings::try_from(config.clone())
}

fn open_critical_send_stream<C, B>(
    conn: &mut C,
    result: Result<C::SendStream, StreamErrorIncoming>,
    stream_name: &str,
) -> Result<C::SendStream, ConnectionError>
where
    C: quic::Connection<B>,
    B: Buf,
{
    match result {
        Ok(stream) => Ok(stream),
        Err(StreamErrorIncoming::ConnectionErrorIncoming { connection_error }) => {
            Err(conn.handle_quic_error_raw(connection_error))
        }
        Err(StreamErrorIncoming::StreamTerminated { error_code }) => Err(conn
            .close_raw_connection_with_h3_error(InternalConnectionError::new(
                Code::H3_CLOSED_CRITICAL_STREAM,
                format!("{stream_name} stream was terminated with error code {error_code}"),
            ))),
        Err(StreamErrorIncoming::Unknown(error)) => Err(conn.close_raw_connection_with_h3_error(
            // No critical stream exists yet, so this local transport failure
            // cannot be reported as a stream closed by the peer.
            // https://www.rfc-editor.org/rfc/rfc9114.html#section-8.1
            InternalConnectionError::new(
                Code::H3_INTERNAL_ERROR,
                format!("failed to open {stream_name} stream: {error}"),
            ),
        )),
    }
}

fn wake_qpack_waiters_on_connection_error(
    blocked_streams: &mut qpack::BlockedStreamRegistry,
    decoder_events_recv: &mut mpsc::UnboundedReceiver<QpackEvent>,
) {
    blocked_streams.wake_all();

    // Once the connection fails, no QPACK event can make progress. Close the
    // channel and drain it so wakers not yet registered by the driver are also
    // released. Normal polling uses `poll_recv`; `try_recv` is limited to this
    // closed path.
    decoder_events_recv.close();
    while let Ok(event) = decoder_events_recv.try_recv() {
        match event {
            QpackEvent::RegisterBlocked { waker, .. } | QpackEvent::DecoderAccessWaker(waker) => {
                waker.wake()
            }
            QpackEvent::HeaderAck(_)
            | QpackEvent::StreamCancel(_)
            | QpackEvent::ReleaseBlocked { .. } => {}
        }
    }
}

#[allow(missing_docs)]
pub struct ConnectionInner<C, B>
where
    C: quic::Connection<B>,
    B: Buf,
{
    pub shared: Arc<SharedState>,
    /// TODO: breaking encapsulation just to see if we can get this to work, will fix before
    /// merging
    pub conn: C,
    control_send: C::SendStream,
    control_recv: Option<FrameStream<C::RecvStream, B>>,
    pub(crate) qpack_streams: QpackStreams<C, B>,
    /// Buffers incoming uni/recv streams which have yet to be claimed.
    ///
    /// This is opposed to discarding them by returning in `poll_accept_recv`, which may cause them
    /// to be missed by something else polling.
    ///
    /// See: <https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http3/#section-4.5>
    ///
    /// In WebTransport over HTTP/3, the client MAY send its SETTINGS frame, as well as
    /// multiple WebTransport CONNECT requests, WebTransport data streams and WebTransport
    /// datagrams, all within a single flight. As those can arrive out of order, a WebTransport
    /// server could be put into a situation where it receives a stream or a datagram without a
    /// corresponding session. Similarly, a client may receive a server-initiated stream or a
    /// datagram before receiving the CONNECT response headers from the server.To handle this
    /// case, WebTransport endpoints SHOULD buffer streams and datagrams until those can be
    /// associated with an established session. To avoid resource exhaustion, the endpoints
    /// MUST limit the number of buffered streams and datagrams. When the number of buffered
    /// streams is exceeded, a stream SHALL be closed by sending a RESET_STREAM and/or
    /// STOP_SENDING with the H3_WEBTRANSPORT_BUFFERED_STREAM_REJECTED error code. When the
    /// number of buffered datagrams is exceeded, a datagram SHALL be dropped. It is up to an
    /// implementation to choose what stream or datagram to discard.
    accepted_streams: AcceptedStreams<C, B>,
    pending_recv_streams: Vec<Option<AcceptRecvStream<C::RecvStream, B>>>,
    got_peer_settings: bool,
    pub(crate) handled_connection_error: Option<ConnectionError>,
    pub send_grease_frame: bool,
    // tells if the grease steam should be sent
    send_grease_stream_flag: bool,
    // step of the grease sending poll fn
    grease_step: GreaseStatus<C::SendStream, B>,
    pub config: Config,
}

impl<B, C> ConnectionState for ConnectionInner<C, B>
where
    C: quic::Connection<B>,
    B: Buf,
{
    fn shared_state(&self) -> &SharedState {
        &self.shared
    }
}

enum GreaseStatus<S, B>
where
    S: SendStream<B>,
    B: Buf,
{
    /// Grease stream is not started
    NotStarted(PhantomData<B>),
    /// Grease steam is started without data
    Started(Option<S>),
    /// Grease stream is started with data
    DataPrepared(Option<S>),
    /// Data is sent on grease stream
    DataSent(S),
    /// Grease stream is finished
    Finished,
}

impl<B, C> ConnectionInner<C, B>
where
    C: quic::Connection<B>,
    B: Buf,
{
    fn handle_critical_send_stream_result(
        &mut self,
        result: Result<(), StreamErrorIncoming>,
        stream_name: &str,
    ) -> Result<(), ConnectionError> {
        match result {
            Ok(()) => Ok(()),
            Err(StreamErrorIncoming::ConnectionErrorIncoming { connection_error }) => {
                Err(self.handle_connection_error(connection_error))
            }
            Err(StreamErrorIncoming::StreamTerminated { error_code }) => Err(self
                .handle_connection_error(InternalConnectionError::new(
                    Code::H3_CLOSED_CRITICAL_STREAM,
                    format!("{stream_name} stream was terminated with error code {error_code}"),
                ))),
            Err(StreamErrorIncoming::Unknown(error)) => {
                Err(self.handle_connection_error(InternalConnectionError::new(
                    Code::H3_CLOSED_CRITICAL_STREAM,
                    format!("failed to write {stream_name} stream header: {error}"),
                )))
            }
        }
    }

    /// Wakes every request task waiting for QPACK progress.
    ///
    /// The driver cannot provide decoder access or missing table entries after
    /// a connection error, so no request may remain pending on it.
    pub(crate) fn wake_qpack_waiters_on_connection_error(&mut self) {
        let qpack = &mut self.qpack_streams;
        wake_qpack_waiters_on_connection_error(
            &mut qpack.blocked_streams,
            &mut qpack.decoder_events_recv,
        );
    }

    /// Sends the configured settings and initializes the control streams.
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub async fn send_control_stream_headers(&mut self) -> Result<(), ConnectionError> {
        let settings = local_settings(&self.config).map_err(|error| {
            self.handle_connection_error(InternalConnectionError::new(
                Code::H3_INTERNAL_ERROR,
                format!("invalid local SETTINGS configuration: {error}"),
            ))
        })?;
        self.send_control_stream_headers_with_settings(settings)
            .await
    }

    async fn send_control_stream_headers_with_settings(
        &mut self,
        settings: frame::Settings,
    ) -> Result<(), ConnectionError> {
        #[cfg(test)]
        if !self.config.send_settings {
            return Ok(());
        }

        #[cfg(feature = "tracing")]
        tracing::debug!("Sending server settings: {:#x?}", settings);

        //= https://www.rfc-editor.org/rfc/rfc9114#section-3.2
        //# After the QUIC connection is
        //# established, a SETTINGS frame MUST be sent by each endpoint as the
        //# initial frame of their respective HTTP control stream.

        //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2.1
        //# Each side MUST initiate a single control stream at the beginning of
        //# the connection and send its SETTINGS frame as the first frame on this
        //# stream.

        //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.4
        //# A SETTINGS frame MUST be sent as the first frame of
        //# each control stream (see Section 6.2.1) by each peer, and it MUST NOT
        //# be sent subsequently.

        //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.4
        //= type=implication
        //# SETTINGS frames MUST NOT be sent on any stream other than the control
        //# stream.

        //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.4.2
        //= type=implication
        //# Endpoints MUST NOT require any data to be received from
        //# the peer prior to sending the SETTINGS frame; settings MUST be sent
        //# as soon as the transport is ready to send data.

        //= https://www.rfc-editor.org/rfc/rfc9204.html#section-4.2
        //# Each endpoint
        //# MUST initiate, at most, one encoder stream and, at most, one decoder
        //# stream.

        let control = stream::write(
            &mut self.control_send,
            WriteBuf::from(UniStreamHeader::Control(settings)),
        )
        .await;
        self.handle_critical_send_stream_result(control, "control")?;

        // QPACK encoder and decoder streams are critical streams. A peer must
        // not close either direction once the stream has been created.
        // https://www.rfc-editor.org/rfc/rfc9204.html#section-4.2
        let mut decoder_send = match self.qpack_streams.decoder_send.take() {
            Some(stream) => stream,
            None => {
                return Err(self.handle_connection_error(InternalConnectionError::new(
                    Code::H3_INTERNAL_ERROR,
                    "QPACK decoder stream was not initialized".to_string(),
                )));
            }
        };
        let decoder =
            stream::write(&mut decoder_send, WriteBuf::from(UniStreamHeader::Decoder)).await;
        self.qpack_streams.decoder_send = Some(decoder_send);
        self.handle_critical_send_stream_result(decoder, "QPACK decoder")?;

        let mut encoder_send = match self.qpack_streams.encoder_send.take() {
            Some(stream) => stream,
            None => {
                return Err(self.handle_connection_error(InternalConnectionError::new(
                    Code::H3_INTERNAL_ERROR,
                    "QPACK encoder stream was not initialized".to_string(),
                )));
            }
        };
        let encoder =
            stream::write(&mut encoder_send, WriteBuf::from(UniStreamHeader::Encoder)).await;
        self.qpack_streams.encoder_send = Some(encoder_send);
        self.handle_critical_send_stream_result(encoder, "QPACK encoder")
    }

    /// Initiates the connection and opens a control stream
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub async fn new(mut conn: C, config: Config) -> Result<Self, ConnectionError> {
        let settings = local_settings(&config).map_err(|error| {
            conn.close_raw_connection_with_h3_error(InternalConnectionError::new(
                Code::H3_INTERNAL_ERROR,
                format!("invalid local SETTINGS configuration: {error}"),
            ))
        })?;
        let advertised_settings: crate::config::Settings = (&settings).into();
        let mut decoder = qpack::Decoder::new(
            advertised_settings.qpack_max_table_capacity.unwrap_or(0),
            advertised_settings.qpack_blocked_streams.unwrap_or(0),
        )
        .map_err(|error| {
            conn.close_raw_connection_with_h3_error(invalid_qpack_decoder_configuration(error))
        })?;
        decoder.set_max_encoded_string_size(config.qpack_decode_buffer_size);

        //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2
        //# Endpoints SHOULD create the HTTP control stream as well as the
        //# unidirectional streams required by mandatory extensions (such as the
        //# QPACK encoder and decoder streams) first, and then create additional

        // start streams
        let control_send = future::poll_fn(|cx| conn.poll_open_send(cx)).await;
        let control_send = open_critical_send_stream(&mut conn, control_send, "control")?;
        let encoder_send = future::poll_fn(|cx| conn.poll_open_send(cx)).await;
        let encoder_send = open_critical_send_stream(&mut conn, encoder_send, "QPACK encoder")?;
        let decoder_send = future::poll_fn(|cx| conn.poll_open_send(cx)).await;
        let decoder_send = open_critical_send_stream(&mut conn, decoder_send, "QPACK decoder")?;

        let (decoder_events_send, decoder_events_recv) = mpsc::unbounded_channel();

        //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2.1
        //= type=implication
        //# The
        //# sender MUST NOT close the control stream, and the receiver MUST NOT
        //# request that the sender close the control stream.
        let blocked_streams = qpack::BlockedStreamRegistry::new(decoder.max_blocked_streams());
        let decoder = QpackDecoder::new(decoder, decoder_events_send);

        let qpack_streams = QpackStreams {
            decoder_send: Some(decoder_send),
            decoder_send_buf: BytesMut::new(),
            decoder,
            encoder: qpack::QpackEncoder::default(),
            encoder_send_buf: Bytes::new(),
            blocked_streams,
            decoder_events_recv,
            decoder_recv: None,
            encoder_send: Some(encoder_send),
            encoder_recv: None,
        };

        let mut conn_inner = Self {
            shared: Arc::new(SharedState::default()),
            conn,
            control_send,
            control_recv: None,
            qpack_streams,
            handled_connection_error: None,
            pending_recv_streams: Vec::with_capacity(3),
            got_peer_settings: false,
            send_grease_frame: config.send_grease,
            // send grease stream if configured
            send_grease_stream_flag: config.send_grease,
            config,
            accepted_streams: Default::default(),
            // start at first step
            grease_step: GreaseStatus::NotStarted(PhantomData),
        };
        conn_inner
            .send_control_stream_headers_with_settings(settings)
            .await?;

        Ok(conn_inner)
    }

    /// Send GOAWAY with specified max_id, iff max_id is smaller than the previous one.
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub async fn shutdown<T>(
        &mut self,
        sent_closing: &mut Option<T>,
        max_id: T,
    ) -> Result<(), ConnectionError>
    where
        T: From<VarInt> + PartialOrd<T> + Copy,
        VarInt: From<T>,
    {
        if let Some(sent_id) = sent_closing {
            if *sent_id <= max_id {
                return Ok(());
            }
        }

        *sent_closing = Some(max_id);
        self.set_closing();

        //= https://www.rfc-editor.org/rfc/rfc9114#section-3.3
        //# When either endpoint chooses to close the HTTP/3
        //# connection, the terminating endpoint SHOULD first send a GOAWAY frame
        //# (Section 5.2) so that both endpoints can reliably determine whether
        //# previously sent frames have been processed and gracefully complete or
        //# terminate any necessary remaining tasks.
        match stream::write(&mut self.control_send, Frame::Goaway(max_id.into())).await {
            Ok(()) => Ok(()),
            Err(StreamErrorIncoming::ConnectionErrorIncoming { connection_error }) => {
                Err(self.handle_connection_error(connection_error))
            }
            Err(StreamErrorIncoming::StreamTerminated { error_code: err }) => Err(self
                //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2.1
                //# If either control
                //# stream is closed at any point, this MUST be treated as a connection
                //# error of type H3_CLOSED_CRITICAL_STREAM.
                .handle_connection_error(InternalConnectionError::new(
                    Code::H3_CLOSED_CRITICAL_STREAM,
                    format!(
                        "control stream was requested to stop sending with error code {}",
                        err
                    ),
                ))),
            Err(StreamErrorIncoming::Unknown(error)) => {
                Err(self.handle_connection_error(InternalConnectionError::new(
                    Code::H3_CLOSED_CRITICAL_STREAM,
                    format!("an error occurred on the control stream {}", error),
                )))
            }
        }
    }

    #[allow(missing_docs)]
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub fn poll_accept_bi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<C::BidiStream, ConnectionError>> {
        let _ = self.poll_connection_error(cx)?;

        // Accept the request by accepting the next bidirectional stream
        // .into().into() converts the impl QuicError into crate::error::Error.
        // The `?` operator doesn't work here for some reason.
        self.conn
            .poll_accept_bidi(cx)
            .map_err(|e| self.handle_connection_error(e))
    }

    /// Polls incoming streams
    ///
    /// Accepted streams which are not control, decoder, or encoder streams are buffer in
    /// `accepted_recv_streams`
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub fn poll_accept_recv(&mut self, cx: &mut Context<'_>) -> Result<(), ConnectionError> {
        let _ = self.poll_connection_error(cx)?;

        // Get all currently pending streams
        while let Poll::Ready(stream) = self
            .conn
            .poll_accept_recv(cx)
            .map_err(|e| self.handle_connection_error(e))?
        {
            self.pending_recv_streams
                .push(Some(AcceptRecvStream::new(stream)));
        }

        for stream in self.pending_recv_streams.iter_mut().filter(|s| s.is_some()) {
            let resolved = match stream.as_mut().expect("this cannot be None").poll_type(cx) {
                Poll::Ready(Err(stream::PollTypeError::IncomingError(e))) => {
                    return Err(self.handle_connection_error(e));
                }
                Poll::Ready(Err(stream::PollTypeError::InternalError(e))) => {
                    return Err(self.handle_connection_error(e));
                }
                Poll::Ready(Err(stream::PollTypeError::EndOfStream)) =>
                //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2
                //# A receiver MUST tolerate unidirectional streams being
                //# closed or reset prior to the reception of the unidirectional stream
                //# header.
                {
                    // remove the stream if it was closed before the header was received
                    let _ = stream.take();
                    continue;
                }
                Poll::Ready(Ok(())) => stream.take().expect("this cannot be None"),
                Poll::Pending => continue,
            };

            match resolved.into_stream() {
                //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2.1
                //# Only one control stream per peer is permitted;
                //# receipt of a second stream claiming to be a control stream MUST be
                //# treated as a connection error of type H3_STREAM_CREATION_ERROR.
                AcceptedRecvStream::Control(s) => {
                    if self.control_recv.is_some() {
                        return Err(self.handle_connection_error(InternalConnectionError::new(
                            Code::H3_STREAM_CREATION_ERROR,
                            "got two control streams".to_string(),
                        )));
                    }
                    self.control_recv = Some(s);
                }
                enc @ AcceptedRecvStream::Encoder(_) => {
                    if let Some(_prev) = self.qpack_streams.encoder_recv.replace(enc) {
                        //= https://www.rfc-editor.org/rfc/rfc9204.html#section-4.2
                        //# Receipt of a second instance of either stream type MUST be
                        //# treated as a connection error of type H3_STREAM_CREATION_ERROR.

                        //= https://www.rfc-editor.org/rfc/rfc9204.html#section-4.2
                        //# An endpoint MUST allow its peer to create an encoder stream and a
                        //# decoder stream even if the connection's settings prevent their use.

                        return Err(self.handle_connection_error(InternalConnectionError::new(
                            Code::H3_STREAM_CREATION_ERROR,
                            "got two encoder streams".to_string(),
                        )));
                    }
                }
                dec @ AcceptedRecvStream::Decoder(_) => {
                    if let Some(_prev) = self.qpack_streams.decoder_recv.replace(dec) {
                        //= https://www.rfc-editor.org/rfc/rfc9204.html#section-4.2
                        //# Receipt of a second instance of either stream type MUST be
                        //# treated as a connection error of type H3_STREAM_CREATION_ERROR.

                        //= https://www.rfc-editor.org/rfc/rfc9204.html#section-4.2
                        //# An endpoint MUST allow its peer to create an encoder stream and a
                        //# decoder stream even if the connection's settings prevent their use.

                        return Err(self.handle_connection_error(InternalConnectionError::new(
                            Code::H3_STREAM_CREATION_ERROR,
                            "got two decoder streams".to_string(),
                        )));
                    }
                }
                AcceptedRecvStream::WebTransportUni(id, s)
                    if self.config.settings.enable_webtransport =>
                {
                    // Store until someone else picks it up, like a webtransport session which is
                    // not yet established.
                    self.accepted_streams.wt_uni_streams.push((id, s))
                }

                //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2.3
                //= type=implication
                //# Endpoints MUST NOT consider these streams to have any meaning upon
                //# receipt.
                AcceptedRecvStream::Unknown(mut stream) => {
                    //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2
                    //# Recipients of unknown stream types MUST
                    //# either abort reading of the stream or discard incoming data without
                    //# further processing.

                    //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2
                    //# If reading is aborted, the recipient SHOULD use
                    //# the H3_STREAM_CREATION_ERROR error code or a reserved error code
                    //# (Section 8.1).

                    //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2
                    //= type=implication
                    //# The recipient MUST NOT consider unknown stream types
                    //# to be a connection error of any kind.

                    stream.stop_sending(Code::H3_STREAM_CREATION_ERROR.value());
                }
                _ => (),
            };
        }

        // Remove all None values
        self.pending_recv_streams.retain(|s| s.is_some());

        Ok(())
    }

    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub fn poll_qpack_encoder_stream(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), ConnectionError>>
    where
        C::SendStream: quic::SendStreamUnframed<B>,
    {
        let _ = self.poll_connection_error(cx)?;

        self.poll_qpack_encoder_stream_inner(cx)
    }

    fn poll_qpack_encoder_stream_inner(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), ConnectionError>>
    where
        C::SendStream: quic::SendStreamUnframed<B>,
    {
        // Do not accumulate decoder instructions while the decoder stream is
        // flow-control blocked. RFC 9204 allows implementations to limit
        // unsent decoder-stream data as part of their memory policy.
        // https://www.rfc-editor.org/rfc/rfc9204.html#section-7.3
        match self.poll_flush_qpack_decoder(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            Poll::Pending => return Poll::Pending,
        }

        let Some(accepted) = self.qpack_streams.encoder_recv.take() else {
            return Poll::Pending;
        };

        let mut encoder_recv = match accepted {
            AcceptedRecvStream::Encoder(stream) => stream,
            other => {
                self.qpack_streams.encoder_recv = Some(other);
                return Poll::Pending;
            }
        };

        loop {
            if encoder_recv.has_remaining() {
                // Parse across receive buffers without coalescing them. Advance
                // only through complete instructions so trailing bytes remain
                // buffered for the next read.
                // https://www.rfc-editor.org/rfc/rfc9204.html#section-4.3
                let (result, consumed) = {
                    let mut read = encoder_recv.buf().cursor();
                    let result = self.qpack_streams.decoder.poll_on_recv_encoder(
                        cx,
                        &mut read,
                        &mut self.qpack_streams.decoder_send_buf,
                    );
                    (result, read.position())
                };
                encoder_recv.buf_mut().advance(consumed);

                match result {
                    Poll::Ready(Ok(insert_count)) => {
                        self.qpack_streams
                            .blocked_streams
                            .update_insert_count(insert_count);
                    }
                    Poll::Ready(Err(err)) => {
                        // Do not drain QPACK events before publishing the error.
                        // A woken request can run on another executor thread and
                        // must observe the connection error before it is polled.
                        let (code, message) = if err.is_internal() {
                            (
                                Code::H3_INTERNAL_ERROR,
                                format!(
                                    "local QPACK decoder failed while processing the encoder stream: {err}"
                                ),
                            )
                        } else {
                            (
                                Code::QPACK_ENCODER_STREAM_ERROR,
                                format!("invalid QPACK encoder stream instruction: {err}"),
                            )
                        };
                        return Poll::Ready(Err(self.handle_connection_error(
                            InternalConnectionError::new(code, message),
                        )));
                    }
                    Poll::Pending => {
                        self.qpack_streams.encoder_recv =
                            Some(AcceptedRecvStream::Encoder(encoder_recv));
                        return Poll::Pending;
                    }
                };
            }

            match self.poll_flush_qpack_decoder(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => {
                    self.qpack_streams.encoder_recv =
                        Some(AcceptedRecvStream::Encoder(encoder_recv));
                    return Poll::Pending;
                }
            }

            match encoder_recv.poll_read(cx) {
                Poll::Ready(Ok(false)) => continue,
                Poll::Ready(Ok(true)) => {
                    return Poll::Ready(Err(self.handle_connection_error(
                        InternalConnectionError::new(
                            Code::H3_CLOSED_CRITICAL_STREAM,
                            "QPACK encoder stream closed".to_string(),
                        ),
                    )));
                }
                Poll::Ready(Err(StreamErrorIncoming::ConnectionErrorIncoming {
                    connection_error,
                })) => return Poll::Ready(Err(self.handle_connection_error(connection_error))),
                Poll::Ready(Err(StreamErrorIncoming::StreamTerminated { error_code })) => {
                    return Poll::Ready(Err(self.handle_connection_error(
                        InternalConnectionError::new(
                            Code::H3_CLOSED_CRITICAL_STREAM,
                            format!("QPACK encoder stream reset with error code {}", error_code),
                        ),
                    )));
                }
                Poll::Ready(Err(StreamErrorIncoming::Unknown(error))) => {
                    return Poll::Ready(Err(self.handle_connection_error(
                        InternalConnectionError::new(
                            Code::H3_CLOSED_CRITICAL_STREAM,
                            format!("QPACK encoder stream error: {}", error),
                        ),
                    )));
                }
                Poll::Pending => {
                    self.qpack_streams.encoder_recv =
                        Some(AcceptedRecvStream::Encoder(encoder_recv));
                    return Poll::Pending;
                }
            }
        }
    }

    /// Drives instructions received on the peer's QPACK decoder stream.
    ///
    /// Decoder instruction failures are reported by this endpoint's encoder as
    /// `QPACK_DECODER_STREAM_ERROR`. Closing or resetting the stream is instead
    /// a critical-stream failure.
    ///
    /// See [RFC 9204, Section 4.2](https://www.rfc-editor.org/rfc/rfc9204.html#section-4.2)
    /// and [Section 6](https://www.rfc-editor.org/rfc/rfc9204.html#section-6).
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub fn poll_qpack_decoder_stream(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), ConnectionError>> {
        let _ = self.poll_connection_error(cx)?;

        self.poll_qpack_decoder_stream_inner(cx)
    }

    fn poll_qpack_decoder_stream_inner(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), ConnectionError>> {
        let Some(accepted) = self.qpack_streams.decoder_recv.take() else {
            return Poll::Pending;
        };

        let mut decoder_recv = match accepted {
            AcceptedRecvStream::Decoder(stream) => stream,
            other => {
                self.qpack_streams.decoder_recv = Some(other);
                return Poll::Pending;
            }
        };

        loop {
            if decoder_recv.has_remaining() {
                // Decoder instructions are unframed and can span QUIC receive
                // buffers. Parse through a cursor and advance only complete
                // instructions.
                // https://www.rfc-editor.org/rfc/rfc9204.html#section-4.4
                let (result, consumed) = {
                    let mut read = decoder_recv.buf().cursor();
                    let result = self
                        .qpack_streams
                        .encoder
                        .on_decoder_recv_buffered(&mut read);
                    (result, read.position())
                };
                decoder_recv.buf_mut().advance(consumed);

                if let Err(error) = result {
                    let (code, message) = match error {
                        qpack::QpackEncoderError::Encoder(error) => (
                            Code::QPACK_DECODER_STREAM_ERROR,
                            format!("invalid QPACK decoder stream instruction: {error}"),
                        ),
                        qpack::QpackEncoderError::Poisoned => (
                            Code::H3_INTERNAL_ERROR,
                            "QPACK encoder state is poisoned".to_string(),
                        ),
                    };
                    return Poll::Ready(Err(
                        self.handle_connection_error(InternalConnectionError::new(code, message))
                    ));
                }
            }

            match decoder_recv.poll_read(cx) {
                Poll::Ready(Ok(false)) => continue,
                Poll::Ready(Ok(true)) => {
                    return Poll::Ready(Err(self.handle_connection_error(
                        InternalConnectionError::new(
                            Code::H3_CLOSED_CRITICAL_STREAM,
                            "QPACK decoder stream closed".to_string(),
                        ),
                    )));
                }
                Poll::Ready(Err(StreamErrorIncoming::ConnectionErrorIncoming {
                    connection_error,
                })) => return Poll::Ready(Err(self.handle_connection_error(connection_error))),
                Poll::Ready(Err(StreamErrorIncoming::StreamTerminated { error_code })) => {
                    return Poll::Ready(Err(self.handle_connection_error(
                        InternalConnectionError::new(
                            Code::H3_CLOSED_CRITICAL_STREAM,
                            format!("QPACK decoder stream reset with error code {error_code}"),
                        ),
                    )));
                }
                Poll::Ready(Err(StreamErrorIncoming::Unknown(error))) => {
                    return Poll::Ready(Err(self.handle_connection_error(
                        InternalConnectionError::new(
                            Code::H3_CLOSED_CRITICAL_STREAM,
                            format!("QPACK decoder stream error: {error}"),
                        ),
                    )));
                }
                Poll::Pending => {
                    self.qpack_streams.decoder_recv =
                        Some(AcceptedRecvStream::Decoder(decoder_recv));
                    return Poll::Pending;
                }
            }
        }
    }

    /// Drives both peer QPACK streams and flushes locally generated instructions.
    ///
    /// Each direction remains an independent critical-stream state machine. A
    /// pending direction registers its own wakeup and does not prevent the other
    /// directions from making progress.
    ///
    /// See [RFC 9204, Sections 4.2-4.4](https://www.rfc-editor.org/rfc/rfc9204.html#section-4.2).
    pub(crate) fn poll_qpack(&mut self, cx: &mut Context<'_>) -> Result<(), ConnectionError>
    where
        C::SendStream: quic::SendStreamUnframed<B>,
    {
        let _ = self.poll_connection_error(cx)?;

        if self.config.qpack_encoder_table_capacity != 0 {
            if let Poll::Ready(Err(error)) = self.poll_flush_qpack_encoder(cx) {
                return Err(error);
            }
        } else {
            debug_assert!(!self.qpack_streams.encoder_send_buf.has_remaining());
        }

        if self.qpack_streams.decoder_recv.is_some() {
            if let Poll::Ready(Err(error)) = self.poll_qpack_decoder_stream_inner(cx) {
                return Err(error);
            }
        }

        if self.qpack_streams.encoder_recv.is_some()
            || self.qpack_streams.decoder.dynamic_table_enabled()
        {
            if let Poll::Ready(Err(error)) = self.poll_qpack_encoder_stream_inner(cx) {
                return Err(error);
            }
        }
        Ok(())
    }

    /// Flushes instructions generated by this endpoint's QPACK encoder.
    fn poll_flush_qpack_encoder(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), ConnectionError>>
    where
        C::SendStream: quic::SendStreamUnframed<B>,
    {
        loop {
            if !self.qpack_streams.encoder_send_buf.has_remaining() {
                self.qpack_streams.encoder_send_buf =
                    match self.qpack_streams.encoder.take_pending_instructions() {
                        Ok(instructions) => instructions,
                        Err(error) => {
                            return Poll::Ready(Err(self.handle_connection_error(
                                InternalConnectionError::new(
                                    Code::H3_INTERNAL_ERROR,
                                    format!("failed to access QPACK encoder instructions: {error}"),
                                ),
                            )));
                        }
                    };
                if !self.qpack_streams.encoder_send_buf.has_remaining() {
                    return Poll::Ready(Ok(()));
                }
            }

            let Some(encoder_send) = self.qpack_streams.encoder_send.as_mut() else {
                return Poll::Ready(Err(self.handle_connection_error(
                    InternalConnectionError::new(
                        Code::H3_CLOSED_CRITICAL_STREAM,
                        "QPACK encoder stream is unavailable".to_string(),
                    ),
                )));
            };

            match encoder_send.poll_send(cx, &mut self.qpack_streams.encoder_send_buf) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(self.handle_connection_error(
                        InternalConnectionError::new(
                            Code::H3_INTERNAL_ERROR,
                            "QPACK encoder stream made no write progress".to_string(),
                        ),
                    )));
                }
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(_)) => {}
                Poll::Ready(Err(StreamErrorIncoming::ConnectionErrorIncoming {
                    connection_error,
                })) => return Poll::Ready(Err(self.handle_connection_error(connection_error))),
                Poll::Ready(Err(StreamErrorIncoming::StreamTerminated { error_code })) => {
                    return Poll::Ready(Err(self.handle_connection_error(
                        InternalConnectionError::new(
                            Code::H3_CLOSED_CRITICAL_STREAM,
                            format!("QPACK encoder stream reset with error code {error_code}"),
                        ),
                    )));
                }
                Poll::Ready(Err(StreamErrorIncoming::Unknown(error))) => {
                    return Poll::Ready(Err(self.handle_connection_error(
                        InternalConnectionError::new(
                            Code::H3_CLOSED_CRITICAL_STREAM,
                            format!("QPACK encoder stream error: {error}"),
                        ),
                    )));
                }
            }
        }
    }

    fn poll_flush_qpack_decoder(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), ConnectionError>>
    where
        C::SendStream: quic::SendStreamUnframed<B>,
    {
        if !self.qpack_streams.decoder.dynamic_table_enabled() {
            debug_assert!(!self.qpack_streams.decoder_send_buf.has_remaining());
            return Poll::Ready(Ok(()));
        }

        // Losing the QPACK decoder stream is H3_CLOSED_CRITICAL_STREAM. QPACK
        // instruction errors apply to the peer's encoder stream instead.
        // https://www.rfc-editor.org/rfc/rfc9204.html#section-4.2
        if let Err(err) = self.poll_qpack_decoder_events(cx) {
            return Poll::Ready(Err(err));
        }

        let Some(decoder_send) = self.qpack_streams.decoder_send.as_mut() else {
            if !self.qpack_streams.decoder_send_buf.has_remaining() {
                return Poll::Ready(Ok(()));
            }
            return Poll::Ready(Err(self.handle_connection_error(
                InternalConnectionError::new(
                    Code::H3_CLOSED_CRITICAL_STREAM,
                    "QPACK decoder stream is unavailable".to_string(),
                ),
            )));
        };

        while self.qpack_streams.decoder_send_buf.has_remaining() {
            match decoder_send.poll_send(cx, &mut self.qpack_streams.decoder_send_buf) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(self.handle_connection_error(
                        InternalConnectionError::new(
                            Code::H3_INTERNAL_ERROR,
                            "QPACK decoder stream made no write progress".to_string(),
                        ),
                    )));
                }
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(_)) => {}
                Poll::Ready(Err(StreamErrorIncoming::ConnectionErrorIncoming {
                    connection_error,
                })) => return Poll::Ready(Err(self.handle_connection_error(connection_error))),
                Poll::Ready(Err(StreamErrorIncoming::StreamTerminated { error_code })) => {
                    return Poll::Ready(Err(self.handle_connection_error(
                        InternalConnectionError::new(
                            Code::H3_CLOSED_CRITICAL_STREAM,
                            format!("QPACK decoder stream reset with error code {}", error_code),
                        ),
                    )));
                }
                Poll::Ready(Err(StreamErrorIncoming::Unknown(error))) => {
                    return Poll::Ready(Err(self.handle_connection_error(
                        InternalConnectionError::new(
                            Code::H3_CLOSED_CRITICAL_STREAM,
                            format!("QPACK decoder stream error: {}", error),
                        ),
                    )));
                }
            }
        }

        Poll::Ready(Ok(()))
    }

    /// Waits for the control stream to be received and reads subsequent frames.
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub fn poll_control(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Frame<PayloadLen>, ConnectionError>> {
        // check if a connection error occurred on a stream
        let _ = self.poll_connection_error(cx)?;

        let recv = {
            // TODO
            self.poll_accept_recv(cx)?;
            if let Some(v) = &mut self.control_recv {
                v
            } else {
                // Try later
                return Poll::Pending;
            }
        };

        let res = match ready!(recv.poll_next(cx)) {
            Err(FrameStreamError::Quic(StreamErrorIncoming::ConnectionErrorIncoming {
                connection_error,
            })) => return Poll::Ready(Err(self.handle_connection_error(connection_error))),
            Err(FrameStreamError::Quic(StreamErrorIncoming::StreamTerminated {
                error_code: err,
            })) => {
                return Poll::Ready(Err(self.handle_connection_error(
                    InternalConnectionError::new(
                        Code::H3_CLOSED_CRITICAL_STREAM,
                        format!("control stream was reset with error code {}", err),
                    ),
                )));
            }
            Err(FrameStreamError::Quic(StreamErrorIncoming::Unknown(error))) => {
                return Poll::Ready(Err(self.handle_connection_error(
                    InternalConnectionError::new(
                        Code::H3_CLOSED_CRITICAL_STREAM,
                        format!("an error occurred on the control stream {}", error),
                    ),
                )));
            }
            Err(FrameStreamError::UnexpectedEnd) => {
                return Poll::Ready(Err(self.handle_connection_error(
                    InternalConnectionError::new(
                        Code::H3_FRAME_ERROR,
                        "received incomplete frame".to_string(),
                    ),
                )));
            }
            Err(FrameStreamError::Proto(frame_error)) => {
                return Poll::Ready(Err(self.handle_connection_error(
                    InternalConnectionError::got_frame_error(frame_error),
                )));
            }
            Ok(None) =>
            //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2.1
            //# If either control
            //# stream is closed at any point, this MUST be treated as a connection
            //# error of type H3_CLOSED_CRITICAL_STREAM.
            {
                return Poll::Ready(Err(self.handle_connection_error(
                    InternalConnectionError::new(
                        Code::H3_CLOSED_CRITICAL_STREAM,
                        "control stream was closed".to_string(),
                    ),
                )));
            }
            Ok(Some(Frame::Settings(settings))) => {
                if !self.got_peer_settings {
                    // Received settings frame
                    let peer_settings: crate::config::Settings = (&settings).into();
                    self.got_peer_settings = true;
                    self.set_settings(peer_settings);

                    // If the advertised maximum cannot fit this platform's
                    // address space, conservatively keep requests stateless.
                    // Clamping it would use the wrong Required Insert Count
                    // modulus (RFC 9204 Section 4.5.1.1).
                    let peer_capacity = peer_settings
                        .qpack_max_table_capacity
                        .and_then(|value| usize::try_from(value).ok())
                        .unwrap_or(0);
                    let capacity = self.config.qpack_encoder_table_capacity.min(peer_capacity);
                    if let Err(error) = self
                        .qpack_streams
                        .encoder
                        .configure(peer_capacity, capacity)
                    {
                        return Poll::Ready(Err(self.handle_connection_error(
                            InternalConnectionError::new(
                                Code::H3_INTERNAL_ERROR,
                                format!("failed to configure QPACK encoder: {error}"),
                            ),
                        )));
                    }
                    if capacity != 0 {
                        self.waker().wake();
                    }

                    Frame::Settings(settings)
                } else {
                    //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.4
                    //# If an endpoint receives a second SETTINGS
                    //# frame on the control stream, the endpoint MUST respond with a
                    //# connection error of type H3_FRAME_UNEXPECTED.
                    return Poll::Ready(Err(self.handle_connection_error(
                        InternalConnectionError::new(
                            Code::H3_FRAME_UNEXPECTED,
                            "second settings frame received".to_string(),
                        ),
                    )));
                }
            }
            Ok(Some(frame)) if !self.got_peer_settings => {
                // We received a frame before the settings frame
                //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2.1
                //# If the first frame of the control stream is any other frame
                //# type, this MUST be treated as a connection error of type
                //# H3_MISSING_SETTINGS.
                return Poll::Ready(Err(self.handle_connection_error(
                    InternalConnectionError::new(
                        Code::H3_MISSING_SETTINGS,
                        format!("received frame {:?} before settings", frame),
                    ),
                )));
            }
            Ok(Some(
                frame @ Frame::Goaway(_)
                | frame @ Frame::CancelPush(_)
                | frame @ Frame::MaxPushId(_),
            )) => {
                // handle these frames in client/server imples
                frame
            }
            Ok(Some(frame)) => {
                // All other frames are not allowed on the control stream
                // Unknown frames are not covered by the Frame enum and poll_next will just ignore
                // them
                //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.1
                //= type=implication
                //# DATA frames MUST be associated with an HTTP request or response.

                //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.1
                //# If
                //# a DATA frame is received on a control stream, the recipient MUST
                //# respond with a connection error of type H3_FRAME_UNEXPECTED.

                //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.2
                //# If a HEADERS frame is received on a control stream, the recipient
                //# MUST respond with a connection error of type H3_FRAME_UNEXPECTED.
                return Poll::Ready(Err(self.handle_connection_error(
                    InternalConnectionError::new(
                        Code::H3_FRAME_UNEXPECTED,
                        format!("received unexpected frame {:?} on control stream", frame),
                    ),
                )));
            }
        };

        if self.send_grease_stream_flag {
            //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2.3
            //# They MAY also be
            //# sent on connections where no data is currently being transferred.
            ready!(self.poll_grease_stream(cx));
        }

        Poll::Ready(Ok(res))
    }

    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub(crate) fn process_goaway<T>(
        &mut self,
        recv_closing: &mut Option<T>,
        id: VarInt,
    ) -> Result<(), ConnectionError>
    where
        T: From<VarInt> + Copy,
        VarInt: From<T>,
    {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-5.2
        //# An endpoint MAY send multiple GOAWAY frames indicating different
        //# identifiers, but the identifier in each frame MUST NOT be greater
        //# than the identifier in any previous frame, since clients might
        //# already have retried unprocessed requests on another HTTP connection.

        //= https://www.rfc-editor.org/rfc/rfc9114#section-5.2
        //# Like the server,
        //# the client MAY send subsequent GOAWAY frames so long as the specified
        //# push ID is no greater than any previously sent value.
        if let Some(prev_id) = recv_closing.map(VarInt::from) {
            if prev_id < id {
                //= https://www.rfc-editor.org/rfc/rfc9114#section-5.2
                //# Receiving a GOAWAY containing a larger identifier than previously
                //# received MUST be treated as a connection error of type H3_ID_ERROR.
                return Err(self.handle_connection_error(InternalConnectionError::new(
                    Code::H3_ID_ERROR,
                    format!(
                        "received a GoAway ({}) greater than the former one ({})",
                        id, prev_id
                    ),
                )));
            }
        }
        *recv_closing = Some(id.into());
        self.set_closing();
        Ok(())
    }

    // start grease stream and send data
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    fn poll_grease_stream(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        if matches!(self.grease_step, GreaseStatus::NotStarted(_)) {
            self.grease_step = match self.conn.poll_open_send(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(_)) => {
                    // could not create grease stream
                    // don't try again
                    self.send_grease_stream_flag = false;

                    #[cfg(feature = "tracing")]
                    warn!("grease stream creation failed with");

                    return Poll::Ready(());
                }
                Poll::Ready(Ok(stream)) => GreaseStatus::Started(Some(stream)),
            };
        };
        //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2.3
        //# Stream types of the format 0x1f * N + 0x21 for non-negative integer
        //# values of N are reserved to exercise the requirement that unknown
        //# types be ignored.  These streams have no semantics, and they can be
        //# sent when application-layer padding is desired.  They MAY also be
        //# sent on connections where no data is currently being transferred.
        if let GreaseStatus::Started(stream) = &mut self.grease_step {
            if let Some(stream) = stream {
                if stream
                    .send_data((StreamType::grease(), Frame::Grease))
                    .is_err()
                {
                    self.send_grease_stream_flag = false;

                    #[cfg(feature = "tracing")]
                    warn!("write data on grease stream failed with");

                    return Poll::Ready(());
                };
            }
            self.grease_step = GreaseStatus::DataPrepared(stream.take());
        };

        if let GreaseStatus::DataPrepared(stream) = &mut self.grease_step {
            if let Some(stream) = stream {
                match stream.poll_ready(cx) {
                    Poll::Ready(Ok(_)) => (),
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(_)) => {
                        // could not write grease frame
                        // don't try again
                        self.send_grease_stream_flag = false;

                        #[cfg(feature = "tracing")]
                        warn!("write data on grease stream failed with");

                        return Poll::Ready(());
                    }
                };
            }
            self.grease_step = GreaseStatus::DataSent(match stream.take() {
                Some(stream) => stream,
                None => {
                    // this should never happen
                    self.send_grease_stream_flag = false;
                    return Poll::Ready(());
                }
            });
        };

        //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2.3
        //= type=implication
        //# When sending a reserved stream type,
        //# the implementation MAY either terminate the stream cleanly or reset
        //# it.
        if let GreaseStatus::DataSent(stream) = &mut self.grease_step {
            //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2.3
            //= type=exception
            //# When resetting the stream, either the H3_NO_ERROR error code or
            //# a reserved error code (Section 8.1) SHOULD be used.
            // We terminate the stream cleanly so no H3_NO_ERROR is needed
            match stream.poll_finish(cx) {
                Poll::Ready(Ok(_)) => (),
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(_)) => {
                    // could not finish grease stream
                    // don't try again
                    self.send_grease_stream_flag = false;

                    #[cfg(feature = "tracing")]
                    warn!("finish grease stream failed with");

                    return Poll::Ready(());
                }
            };
            self.grease_step = GreaseStatus::Finished;
        };

        // grease stream is closed
        // don't do another one
        self.send_grease_stream_flag = false;
        Poll::Ready(())
    }

    #[allow(missing_docs)]
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub fn accepted_streams_mut(&mut self) -> &mut AcceptedStreams<C, B> {
        &mut self.accepted_streams
    }

    #[inline(always)]
    pub(super) fn dynamic_qpack_decoder(&self) -> Option<QpackDecoder> {
        self.qpack_streams
            .decoder
            .dynamic_table_enabled()
            .then(|| self.qpack_streams.decoder.clone())
    }

    #[inline(always)]
    pub(super) fn dynamic_qpack_encoder(&self) -> Option<qpack::QpackEncoder> {
        (self.config.qpack_encoder_table_capacity != 0).then(|| self.qpack_streams.encoder.clone())
    }

    #[cfg(test)]
    pub(crate) fn qpack_blocked_stream_count(&self) -> usize {
        self.qpack_streams.blocked_streams.len()
    }

    fn poll_qpack_decoder_events(&mut self, cx: &mut Context<'_>) -> Result<(), ConnectionError> {
        while let Poll::Ready(Some(event)) = self.qpack_streams.decoder_events_recv.poll_recv(cx) {
            match event {
                QpackEvent::HeaderAck(stream_id) => qpack::ack_header(
                    stream_id.into_inner(),
                    &mut self.qpack_streams.decoder_send_buf,
                ),
                QpackEvent::StreamCancel(stream_id) => qpack::stream_canceled(
                    stream_id.into_inner(),
                    &mut self.qpack_streams.decoder_send_buf,
                ),
                QpackEvent::RegisterBlocked {
                    stream_id,
                    required_ref,
                    waker,
                } => {
                    if let Err(waker) =
                        self.qpack_streams
                            .blocked_streams
                            .register(stream_id, required_ref, waker)
                    {
                        // The encoder must stay within the blocked-stream limit
                        // advertised by the decoder. Exceeding it is a connection
                        // error, not a request-stream error.
                        // https://www.rfc-editor.org/rfc/rfc9204.html#section-2.1.2
                        let error = self.handle_connection_error(InternalConnectionError::new(
                            Code::QPACK_DECOMPRESSION_FAILED,
                            format!(
                                "QPACK blocked-stream limit exceeded: {}",
                                qpack::DecoderError::TooManyBlockedStreams
                            ),
                        ));
                        waker.wake();
                        return Err(error);
                    }
                }
                QpackEvent::ReleaseBlocked {
                    stream_id,
                    required_ref,
                } => self
                    .qpack_streams
                    .blocked_streams
                    .release(stream_id, required_ref),
                // Missing references use `RegisterBlocked`. This event only
                // waits for a write guard scoped to `poll_on_recv_encoder`, which
                // has been released before the driver can consume the event.
                QpackEvent::DecoderAccessWaker(waker) => waker.wake(),
            }
        }
        Ok(())
    }
}

pub(crate) struct DecoderGuard {
    stream_id: StreamId,
    shared: Arc<SharedState>,
    cancel_on_drop: bool,
    blocked: Option<usize>,
    decoder: QpackDecoder,
    prefix: Option<qpack::FieldSectionPrefix>,
}

impl DecoderGuard {
    /// Registers this stream after decoding reports missing dynamic table entries.
    ///
    /// Repeated polls update the waker for the same Required Insert Count. If the
    /// count changes, the previous driver registration is released first.
    ///
    /// See [RFC 9204, Section 2.1.2](https://www.rfc-editor.org/rfc/rfc9204.html#section-2.1.2).
    fn block(&mut self, required_ref: usize, waker: &Waker) -> Result<(), qpack::DecoderError> {
        if self.blocked.is_some_and(|blocked| blocked != required_ref) {
            self.unblock();
        }

        self.decoder
            .queue_blocked_stream(self.stream_id, required_ref, waker)?;
        self.blocked = Some(required_ref);
        Ok(())
    }

    /// Removes this stream's active blocked-field registration.
    ///
    /// An encoder-stream update may already have removed the entry, so release
    /// is idempotent.
    ///
    /// See [RFC 9204, Section 2.1.2](https://www.rfc-editor.org/rfc/rfc9204.html#section-2.1.2).
    fn unblock(&mut self) {
        if let Some(required_ref) = self.blocked.take() {
            self.decoder
                .release_blocked_stream(self.stream_id, required_ref);
        }
    }

    /// Queues a Section Acknowledgment for a decoded dynamic field section.
    ///
    /// Only a non-zero Required Insert Count needs acknowledgment. Static-table
    /// and literal-only field sections have a count of zero.
    ///
    /// See [RFC 9204, Section 4.4.1](https://www.rfc-editor.org/rfc/rfc9204.html#section-4.4.1).
    fn acknowledge(&mut self, dyn_ref: bool) -> Result<(), qpack::DecoderError> {
        if dyn_ref {
            self.decoder.queue_section_acknowledgment(self.stream_id)?;
            self.shared.waker().wake();
        }

        Ok(())
    }

    /// Marks the receive side complete without sending Stream Cancellation.
    ///
    /// End of stream is normal completion and does not abandon any field section.
    ///
    /// See [RFC 9204, Section 4.4.2](https://www.rfc-editor.org/rfc/rfc9204.html#section-4.4.2).
    fn finish_reading(&mut self) {
        self.unblock();
        self.cancel_on_drop = false;
    }

    /// Cancels outstanding field sections when the receive side is abandoned.
    ///
    /// STOP_SENDING and `Drop` can both reach this path, so cancellation is
    /// queued at most once.
    ///
    /// See [RFC 9204, Section 4.4.2](https://www.rfc-editor.org/rfc/rfc9204.html#section-4.4.2).
    fn cancel_reading(&mut self) {
        self.unblock();
        if std::mem::take(&mut self.cancel_on_drop)
            && self.decoder.queue_stream_cancellation(self.stream_id)
        {
            self.shared.waker().wake();
        }
    }
}

impl Drop for DecoderGuard {
    fn drop(&mut self) {
        self.cancel_reading();
    }
}

pub(crate) enum RequestDecodeState {
    Stateless { max_encoded_string_size: usize },
    Dynamic(Box<DecoderGuard>),
    SendOnly,
}

impl RequestDecodeState {
    pub(crate) fn new(
        stream_id: StreamId,
        shared: &Arc<SharedState>,
        max_encoded_string_size: usize,
        decoder: Option<QpackDecoder>,
    ) -> Self {
        match decoder {
            Some(decoder) => Self::Dynamic(Box::new(DecoderGuard {
                stream_id,
                shared: shared.clone(),
                // Dropping before end of stream abandons any remaining field section
                // and requires Stream Cancellation.
                cancel_on_drop: true,
                blocked: None,
                decoder,
                prefix: None,
            })),
            None => Self::Stateless {
                max_encoded_string_size,
            },
        }
    }

    fn cancel_reading(&mut self) {
        if let Self::Dynamic(state) = self {
            state.cancel_reading();
        }
    }

    fn finish_reading(&mut self) {
        if let Self::Dynamic(state) = self {
            state.finish_reading();
        }
    }
}

#[allow(missing_docs)]
pub struct RequestStream<S, B> {
    pub(super) stream: FrameStream<S, B>,
    pub(super) trailers: Option<Bytes>,
    pub(super) conn_state: Arc<SharedState>,
    pub(super) max_field_section_size: u64,
    send_grease_frame: bool,
    decode_state: RequestDecodeState,
}

impl<S, B> RequestStream<S, B>
where
    S: quic::RecvStream,
{
    #[allow(missing_docs)]
    pub(crate) fn new(
        mut stream: FrameStream<S, B>,
        max_field_section_size: u64,
        max_qpack_decode_buffer_size: usize,
        conn_state: Arc<SharedState>,
        grease: bool,
        decoder: Option<QpackDecoder>,
    ) -> Self {
        stream.set_max_field_section_size(max_qpack_decode_buffer_size);
        let decode_state = RequestDecodeState::new(
            stream.id(),
            &conn_state,
            max_qpack_decode_buffer_size,
            decoder,
        );

        Self::with_decode_state(
            stream,
            max_field_section_size,
            conn_state,
            grease,
            decode_state,
        )
    }

    pub(crate) fn with_decode_state(
        stream: FrameStream<S, B>,
        max_field_section_size: u64,
        conn_state: Arc<SharedState>,
        grease: bool,
        decode_state: RequestDecodeState,
    ) -> Self {
        Self {
            stream,
            conn_state,
            max_field_section_size,
            trailers: None,
            send_grease_frame: grease,
            decode_state,
        }
    }
}

impl<S, B> ConnectionState for RequestStream<S, B> {
    fn shared_state(&self) -> &SharedState {
        &self.conn_state
    }
}

impl<S, B> CloseStream for RequestStream<S, B> {}

impl<S, B> RequestStream<S, B>
where
    S: quic::RecvStream,
{
    /// Cancels QPACK state when the receive side is reset or abandoned.
    ///
    /// See [RFC 9204, Section 4.4.2](https://www.rfc-editor.org/rfc/rfc9204.html#section-4.4.2).
    pub(crate) fn cancel_qpack_reading(&mut self) {
        self.decode_state.cancel_reading();
    }

    /// Cancels outstanding QPACK work before converting a receive error.
    ///
    /// See [RFC 9204, Section 4.4.2](https://www.rfc-editor.org/rfc/rfc9204.html#section-4.4.2).
    pub(crate) fn handle_receive_stream_error(&mut self, error: FrameStreamError) -> StreamError {
        self.cancel_qpack_reading();
        self.handle_frame_stream_error_on_request_stream(error)
    }

    /// Receive some of the request body.
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub fn poll_recv_data(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<impl Buf + use<S, B>>, StreamError>> {
        if !self.stream.has_data() {
            match ready!(self.stream.poll_next(cx)) {
                Err(frame_stream_error) => {
                    return Poll::Ready(Err(self.handle_receive_stream_error(frame_stream_error)));
                }
                Ok(None) => {
                    self.decode_state.finish_reading();
                    return Poll::Ready(Ok(None));
                }
                Ok(Some(Frame::Headers(encoded))) => {
                    self.trailers = Some(encoded);
                    // Received trailers, no more data expected
                    return Poll::Ready(Ok(None));
                }
                Ok(Some(Frame::Data { .. })) => (),
                Ok(Some(other_frame)) => {
                    //= https://www.rfc-editor.org/rfc/rfc9114#section-4.1
                    //# Receipt of an invalid sequence of frames MUST be treated as a
                    //# connection error of type H3_FRAME_UNEXPECTED.

                    //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.3
                    //# Receiving a
                    //# CANCEL_PUSH frame on a stream other than the control stream MUST be
                    //# treated as a connection error of type H3_FRAME_UNEXPECTED.

                    //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.4
                    //# If an endpoint receives a SETTINGS frame on a different
                    //# stream, the endpoint MUST respond with a connection error of type
                    //# H3_FRAME_UNEXPECTED.

                    //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.6
                    //# A client MUST treat a GOAWAY frame on a stream other than
                    //# the control stream as a connection error of type H3_FRAME_UNEXPECTED.

                    //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.7
                    //# The MAX_PUSH_ID frame is always sent on the control stream.  Receipt
                    //# of a MAX_PUSH_ID frame on any other stream MUST be treated as a
                    //# connection error of type H3_FRAME_UNEXPECTED.

                    return Poll::Ready(Err(self.handle_connection_error_on_stream(
                        InternalConnectionError::new(
                            Code::H3_FRAME_UNEXPECTED,
                            format!("unexpected frame: {:?}", other_frame),
                        ),
                    )));
                }
            };
        }

        self.stream
            .poll_data(cx)
            .map_err(|error| self.handle_receive_stream_error(error))
    }

    /// Poll receive trailers.
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub fn poll_recv_trailers(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<HeaderMap>, StreamError>> {
        let mut trailers = if let Some(encoded) = self.trailers.take() {
            encoded
        } else {
            match ready!(self.stream.poll_next(cx)) {
                Err(frame_stream_error) => {
                    return Poll::Ready(Err(self.handle_receive_stream_error(frame_stream_error)));
                }
                Ok(None) => {
                    self.decode_state.finish_reading();
                    return Poll::Ready(Ok(None));
                }
                Ok(Some(Frame::Headers(encoded))) => encoded,
                Ok(Some(other_frame)) => {
                    //= https://www.rfc-editor.org/rfc/rfc9114#section-4.1
                    //# Receipt of an invalid sequence of frames MUST be treated as a
                    //# connection error of type H3_FRAME_UNEXPECTED.

                    //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.3
                    //# Receiving a
                    //# CANCEL_PUSH frame on a stream other than the control stream MUST be
                    //# treated as a connection error of type H3_FRAME_UNEXPECTED.

                    //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.4
                    //# If an endpoint receives a SETTINGS frame on a different
                    //# stream, the endpoint MUST respond with a connection error of type
                    //# H3_FRAME_UNEXPECTED.

                    //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.6
                    //# A client MUST treat a GOAWAY frame on a stream other than
                    //# the control stream as a connection error of type H3_FRAME_UNEXPECTED.

                    //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.7
                    //# The MAX_PUSH_ID frame is always sent on the control stream.  Receipt
                    //# of a MAX_PUSH_ID frame on any other stream MUST be treated as a
                    //# connection error of type H3_FRAME_UNEXPECTED.
                    return Poll::Ready(Err(self.handle_connection_error_on_stream(
                        InternalConnectionError::new(
                            Code::H3_FRAME_UNEXPECTED,
                            format!("unexpected frame: {:?}", other_frame),
                        ),
                    )));
                }
            }
        };

        if !self.stream.is_eos() {
            // Get the trailing frame. After trailers no known frame is allowed.
            // But there still can be unknown frames.
            //= https://www.rfc-editor.org/rfc/rfc9114#section-4.1
            //# Receipt of an invalid sequence of frames MUST be treated as a
            //# connection error of type H3_FRAME_UNEXPECTED.
            match self.stream.poll_next(cx) {
                Poll::Ready(Err(frame_stream_error)) => {
                    return Poll::Ready(Err(self.handle_receive_stream_error(frame_stream_error)));
                }
                // Received a known frame after trailers -> fail.
                Poll::Ready(Ok(Some(trailing_frame))) => {
                    return Poll::Ready(Err(self.handle_connection_error_on_stream(
                        InternalConnectionError::new(
                            Code::H3_FRAME_UNEXPECTED,
                            format!("unexpected frame: {:?}", trailing_frame),
                        ),
                    )));
                }
                // Stream is finished no problematic frames received
                Poll::Ready(Ok(None)) => (),
                // Save the trailers and try again.
                Poll::Pending => {
                    self.trailers = Some(trailers);
                    return Poll::Pending;
                }
            }
        }

        let decode_result = match self.poll_decode_field_section(cx, &mut trailers) {
            Poll::Ready(decode_result) => decode_result,
            Poll::Pending => {
                self.trailers = Some(trailers);
                return Poll::Pending;
            }
        };

        let qpack::Decoded { fields, .. } = match decode_result {
            //= https://www.rfc-editor.org/rfc/rfc9114#section-4.2.2
            //# An HTTP/3 implementation MAY impose a limit on the maximum size of
            //# the message header it will accept on an individual HTTP message.
            Err(qpack::DecoderError::HeaderTooLong(cancel_size)) => {
                self.cancel_qpack_reading();
                return Poll::Ready(Err(StreamError::HeaderTooBig {
                    actual_size: cancel_size,
                    max_size: self.max_field_section_size,
                }));
            }
            Ok(decoded) => decoded,
            Err(error) => {
                let code = if error.is_internal() {
                    Code::H3_INTERNAL_ERROR
                } else {
                    Code::QPACK_DECOMPRESSION_FAILED
                };
                return Poll::Ready(Err(self.handle_connection_error_on_stream(
                    InternalConnectionError::new(
                        code,
                        format!("failed to decode trailers: {error}"),
                    ),
                )));
            }
        };

        Poll::Ready(Ok(Some(
            Header::try_from(fields)
                .map_err(|_e| {
                    self.stop_sending(Code::H3_MESSAGE_ERROR);
                    StreamError::StreamError {
                        code: Code::H3_MESSAGE_ERROR,
                        reason: "malformed request".to_string(),
                    }
                })?
                .into_fields(),
        )))
    }

    #[allow(missing_docs)]
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub fn stop_sending(&mut self, err_code: Code) {
        self.cancel_qpack_reading();
        self.stream.stop_sending(err_code);
    }

    #[inline(always)]
    pub(crate) fn poll_decode_field_section(
        &mut self,
        cx: &mut Context<'_>,
        field_section: &mut Bytes,
    ) -> Poll<Result<qpack::Decoded, qpack::DecoderError>> {
        let decode_result = match &mut self.decode_state {
            RequestDecodeState::Stateless {
                max_encoded_string_size,
            } => Poll::Ready(qpack::decode_stateless_limited(
                field_section,
                self.max_field_section_size,
                *max_encoded_string_size,
            )),
            RequestDecodeState::Dynamic(state) => state.decoder.poll_decode_field_section(
                cx,
                field_section,
                self.max_field_section_size,
                &mut state.prefix,
            ),
            RequestDecodeState::SendOnly => {
                return Poll::Ready(Err(qpack::DecoderError::Internal(
                    "attempted to decode a field section on a send-only stream half",
                )));
            }
        };

        match decode_result {
            Poll::Ready(Ok(decoded)) => {
                if let RequestDecodeState::Dynamic(state) = &mut self.decode_state {
                    state.prefix = None;
                    state.unblock();
                    if let Some(err) = state.acknowledge(decoded.dyn_ref).err() {
                        return Poll::Ready(Err(err));
                    }

                    // EOS proves there can be no later field section on this stream.
                    if self.stream.is_eos() {
                        state.finish_reading();
                    }
                }

                Poll::Ready(Ok(decoded))
            }
            Poll::Ready(Err(qpack::DecoderError::MissingRefs(required_ref)))
                if required_ref > 0 =>
            {
                // A blocked-stream limit violation wakes all registered requests
                // before closing the connection. Do not queue another waiter.
                if let RequestDecodeState::Dynamic(state) = &mut self.decode_state {
                    if state.shared.get_conn_error().is_some() {
                        return Poll::Ready(Err(qpack::DecoderError::Internal(
                            "connection closed while a QPACK field section was blocked",
                        )));
                    }
                    if let Err(err) = state.block(required_ref, cx.waker()) {
                        return Poll::Ready(Err(err));
                    }
                    return Poll::Pending;
                }
                Poll::Ready(Err(qpack::DecoderError::MissingRefs(required_ref)))
            }
            Poll::Ready(Err(err)) => {
                if let RequestDecodeState::Dynamic(state) = &mut self.decode_state {
                    state.prefix = None;
                }
                Poll::Ready(Err(err))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<S, B> RequestStream<S, B>
where
    S: quic::SendStream<B>,
    B: Buf,
{
    /// Send some data on the response body.
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub async fn send_data(&mut self, buf: B) -> Result<(), StreamError> {
        let frame = Frame::Data(buf);

        stream::write(&mut self.stream, frame)
            .await
            .map_err(|e| self.handle_quic_stream_error(e))?;
        Ok(())
    }

    /// Send a set of trailers to end the request.
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub async fn send_trailers(&mut self, trailers: HeaderMap) -> Result<(), StreamError> {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.2
        //= type=TODO
        //# Characters in field names MUST be
        //# converted to lowercase prior to their encoding.
        let mut block = BytesMut::new();

        let headers = Header::trailer(trailers);
        let mem_size = qpack::encode_stateless(&mut block, &headers).map_err(|_e| {
            self.handle_connection_error_on_stream(InternalConnectionError {
                code: Code::H3_INTERNAL_ERROR,
                message: "Failed to encode trailers".to_string(),
            })
        })?;
        // Do not retain the normalized fields while the encoded block waits on
        // QUIC backpressure.
        drop(headers);

        let max_mem_size = self.settings().max_field_section_size;

        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.2.2
        //# An implementation that
        //# has received this parameter SHOULD NOT send an HTTP message header
        //# that exceeds the indicated size, as the peer will likely refuse to
        //# process it.
        //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.4.2
        //# An HTTP implementation MUST NOT send frames or requests that would be
        //# invalid based on its current understanding of the peer's settings.

        if mem_size > max_mem_size {
            return Err(StreamError::HeaderTooBig {
                actual_size: mem_size,
                max_size: max_mem_size,
            });
        }

        stream::write(&mut self.stream, Frame::Headers(block.freeze()))
            .await
            .map_err(|e| self.handle_quic_stream_error(e))?;

        Ok(())
    }

    /// Stops a stream with an error code
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub fn stop_stream(&mut self, code: Code) {
        self.stream.reset(code.into());
    }

    #[allow(missing_docs)]
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub async fn finish(&mut self) -> Result<(), StreamError> {
        if self.send_grease_frame {
            // send a grease frame once per Connection
            //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.8
            //= type=implication
            //# Frame types of the format 0x1f * N + 0x21 for non-negative integer
            //# values of N are reserved to exercise the requirement that unknown
            //# types be ignored (Section 9).  These frames have no semantics, and
            //# they MAY be sent on any stream where frames are allowed to be sent.
            stream::write(&mut self.stream, Frame::Grease)
                .await
                .map_err(|e| self.handle_quic_stream_error(e))?;
            self.send_grease_frame = false;
        }

        future::poll_fn(|cx| self.stream.poll_finish(cx))
            .await
            .map_err(|e| self.handle_quic_stream_error(e))
    }
}

impl<S, B> RequestStream<S, B>
where
    S: quic::BidiStream<B>,
    B: Buf,
{
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub(crate) fn split(
        self,
    ) -> (
        RequestStream<S::SendStream, B>,
        RequestStream<S::RecvStream, B>,
    ) {
        let (send, recv) = self.stream.split();

        (
            RequestStream {
                stream: send,
                trailers: None,
                conn_state: self.conn_state.clone(),
                max_field_section_size: 0,
                send_grease_frame: self.send_grease_frame,
                decode_state: RequestDecodeState::SendOnly,
            },
            RequestStream {
                stream: recv,
                trailers: self.trailers,
                conn_state: self.conn_state,
                max_field_section_size: self.max_field_section_size,
                send_grease_frame: self.send_grease_frame,
                decode_state: self.decode_state,
            },
        )
    }
}

#[cfg(test)]
mod qpack_field_section_tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use futures_util::task::{ArcWake, waker};

    use super::*;

    fn field_section_guard() -> (DecoderGuard, mpsc::UnboundedReceiver<QpackEvent>) {
        let (events_send, events_recv) = mpsc::unbounded_channel();
        let decoder = QpackDecoder::new(qpack::Decoder::new(0, 0).unwrap(), events_send);
        let shared = Arc::new(SharedState::default());

        (
            DecoderGuard {
                stream_id: StreamId(0),
                shared,
                cancel_on_drop: true,
                blocked: None,
                decoder,
                prefix: None,
            },
            events_recv,
        )
    }

    #[test]
    fn request_decode_state_stays_within_two_words() {
        assert!(std::mem::size_of::<RequestDecodeState>() <= 2 * std::mem::size_of::<usize>());
    }

    #[test]
    fn send_half_does_not_cancel_the_receive_decode_state() {
        let (guard, mut events) = field_section_guard();
        let send = RequestDecodeState::SendOnly;
        let recv = RequestDecodeState::Dynamic(Box::new(guard));

        drop(send);
        assert!(events.try_recv().is_err());

        drop(recv);
        assert!(matches!(
            events.try_recv(),
            Ok(QpackEvent::StreamCancel(StreamId(0)))
        ));
        assert!(events.try_recv().is_err());
    }

    #[test]
    fn static_field_section_does_not_emit_acknowledgment() {
        let (mut guard, mut events) = field_section_guard();

        guard.acknowledge(false).unwrap();
        guard.finish_reading();
        drop(guard);

        assert!(events.try_recv().is_err());
    }

    #[test]
    fn each_dynamic_field_section_emits_an_acknowledgment() {
        let (mut guard, mut events) = field_section_guard();

        // Response headers and trailers are separate field sections on the same stream.
        guard.acknowledge(true).unwrap();
        guard.acknowledge(true).unwrap();
        guard.finish_reading();
        drop(guard);

        for _ in 0..2 {
            assert!(matches!(
                events.try_recv(),
                Ok(QpackEvent::HeaderAck(StreamId(0)))
            ));
        }
        assert!(events.try_recv().is_err());
    }

    #[test]
    fn abandoning_stream_after_acknowledgment_emits_cancellation() {
        let (mut guard, mut events) = field_section_guard();

        guard.acknowledge(true).unwrap();
        drop(guard);

        assert!(matches!(
            events.try_recv(),
            Ok(QpackEvent::HeaderAck(StreamId(0)))
        ));
        assert!(matches!(
            events.try_recv(),
            Ok(QpackEvent::StreamCancel(StreamId(0)))
        ));
    }

    #[test]
    fn explicit_cancellation_is_idempotent() {
        let (mut guard, mut events) = field_section_guard();

        guard.cancel_reading();
        guard.cancel_reading();
        drop(guard);

        assert!(matches!(
            events.try_recv(),
            Ok(QpackEvent::StreamCancel(StreamId(0)))
        ));
        assert!(events.try_recv().is_err());
    }

    #[test]
    fn blocked_stream_limit_counts_each_stream_once() {
        let mut blocked_streams = qpack::BlockedStreamRegistry::new(1);
        let waker = futures_util::task::noop_waker();

        assert!(
            blocked_streams
                .register(StreamId(0), 1, waker.clone())
                .is_ok()
        );
        assert!(
            blocked_streams
                .register(StreamId(0), 1, waker.clone())
                .is_ok()
        );
        assert!(
            blocked_streams
                .register(StreamId(4), 2, waker.clone())
                .is_err()
        );

        blocked_streams.release(StreamId(0), 1);
        assert!(blocked_streams.register(StreamId(4), 2, waker).is_ok());
    }

    struct WakeCounter {
        wakes: AtomicUsize,
        shared: Arc<SharedState>,
    }

    impl ArcWake for WakeCounter {
        fn wake_by_ref(arc_self: &Arc<Self>) {
            assert!(arc_self.shared.get_conn_error().is_some());
            arc_self.wakes.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn qpack_waiters_observe_connection_error_before_wake() {
        let shared = Arc::new(SharedState::default());
        let counter = Arc::new(WakeCounter {
            wakes: AtomicUsize::new(0),
            shared: shared.clone(),
        });
        let waker = waker(counter.clone());
        let mut blocked_streams = qpack::BlockedStreamRegistry::new(4);
        blocked_streams
            .register(StreamId(0), 1, waker.clone())
            .unwrap();
        let (events_send, mut events_recv) = mpsc::unbounded_channel();
        events_send
            .send(QpackEvent::RegisterBlocked {
                stream_id: StreamId(4),
                required_ref: 2,
                waker: waker.clone(),
            })
            .unwrap();
        events_send
            .send(QpackEvent::DecoderAccessWaker(waker))
            .unwrap();

        shared.set_conn_error(
            InternalConnectionError::new(
                Code::QPACK_ENCODER_STREAM_ERROR,
                "invalid encoder instruction".into(),
            )
            .into(),
        );
        wake_qpack_waiters_on_connection_error(&mut blocked_streams, &mut events_recv);

        assert_eq!(counter.wakes.load(Ordering::Relaxed), 3);
        assert!(
            events_send
                .send(QpackEvent::HeaderAck(StreamId(0)))
                .is_err()
        );
    }

    #[test]
    fn blocked_stream_limit_defers_wake_until_error_is_published() {
        let shared = Arc::new(SharedState::default());
        let counter = Arc::new(WakeCounter {
            wakes: AtomicUsize::new(0),
            shared: shared.clone(),
        });
        let mut blocked_streams = qpack::BlockedStreamRegistry::new(0);

        let waker = blocked_streams
            .register(StreamId(0), 1, waker(counter.clone()))
            .expect_err("the blocked-stream limit should reject the field section");
        assert_eq!(counter.wakes.load(Ordering::Relaxed), 0);

        shared.set_conn_error(
            InternalConnectionError::new(
                Code::QPACK_DECOMPRESSION_FAILED,
                "blocked-stream limit exceeded".into(),
            )
            .into(),
        );
        waker.wake();

        assert_eq!(counter.wakes.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn invalid_local_qpack_configuration_is_an_internal_error() {
        let conversion_error = u8::try_from(u16::MAX).unwrap_err();
        let error =
            invalid_qpack_decoder_configuration(qpack::DecoderError::BufSize(conversion_error));

        assert_eq!(error.code, Code::H3_INTERNAL_ERROR);
    }

    #[test]
    fn closed_qpack_decoder_event_channel_is_internal() {
        let (events_send, events_recv) = mpsc::unbounded_channel();
        let decoder = QpackDecoder::new(qpack::Decoder::new(0, 0).unwrap(), events_send);
        drop(events_recv);

        let error = decoder
            .queue_section_acknowledgment(StreamId(0))
            .unwrap_err();
        assert!(error.is_internal());
    }

    #[test]
    fn local_qpack_decoder_settings_match_the_wire_frame() {
        let mut config = Config {
            send_grease: false,
            ..Config::default()
        };
        config.settings.qpack_max_table_capacity = Some(256);
        config.settings.qpack_blocked_streams = Some(4);
        config.settings_order = Some(vec![frame::SettingId::MAX_HEADER_LIST_SIZE]);

        let wire_settings = local_settings(&config).unwrap();
        let effective: crate::config::Settings = (&wire_settings).into();
        assert_eq!(effective.qpack_max_table_capacity, None);
        assert_eq!(effective.qpack_blocked_streams, None);

        config.settings_order = None;
        config.settings.qpack_max_table_capacity = None;
        config.settings.qpack_blocked_streams = None;
        config.extra_settings = vec![
            (frame::SettingId::QPACK_MAX_TABLE_CAPACITY, 128),
            (frame::SettingId::QPACK_MAX_BLOCKED_STREAMS, 2),
        ];
        let wire_settings = local_settings(&config).unwrap();
        let effective: crate::config::Settings = (&wire_settings).into();
        assert_eq!(effective.qpack_max_table_capacity, Some(128));
        assert_eq!(effective.qpack_blocked_streams, Some(2));

        config.send_settings = false;
        let wire_settings = local_settings(&config).unwrap();
        let effective: crate::config::Settings = (&wire_settings).into();
        assert_eq!(effective.qpack_max_table_capacity, None);
        assert_eq!(effective.qpack_blocked_streams, None);
    }
}
