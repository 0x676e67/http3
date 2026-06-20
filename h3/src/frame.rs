use std::task::{Context, Poll};

use bytes::{Buf, Bytes};

#[cfg(feature = "tracing")]
use tracing::trace;

use crate::error::Code;
use crate::proto::frame::SettingsError;
use crate::proto::push::InvalidPushId;
use crate::quic::{InvalidStreamId, StreamErrorIncoming};
use crate::stream::{BufRecvStream, WriteBuf};
use crate::{
    buf::BufList,
    proto::{
        frame::{self, Frame, PayloadLen},
        stream::StreamId,
    },
    quic::{BidiStream, RecvStream, SendStream},
};

/// Decodes Frames from the underlying QUIC stream
pub struct FrameStream<S, B, R> {
    pub stream: BufRecvStream<S, B, R>,
    // Already read data from the stream
    decoder: FrameDecoder,
    remaining_data: usize,
    buffer: BufList<R>,
}

/// A request-stream frame whose HEADERS payload has not been buffered yet.
#[derive(Debug)]
pub(crate) enum RequestFrame {
    Headers,
    Frame(Frame<PayloadLen>),
}

impl<S, B, R> FrameStream<S, B, R> {
    pub fn new(stream: BufRecvStream<S, B, R>) -> Self {
        Self {
            stream,
            decoder: FrameDecoder::default(),
            remaining_data: 0,
            buffer: BufList::new(),
        }
    }

    /// Unwraps the Framed streamer and returns the underlying stream **without** data loss for
    /// partially received/read frames.
    pub fn into_inner(self) -> BufRecvStream<S, B, R> {
        self.stream
    }
}

impl<S, B, R> FrameStream<S, B, R>
where
    S: crate::quic::Is0rtt,
{
    /// Checks if the stream was opened in 0-RTT mode
    pub(crate) fn is_0rtt(&self) -> bool {
        self.stream.is_0rtt()
    }
}

impl<S, B, R> FrameStream<S, B, R>
where
    S: RecvStream<Buf = R>,
    R: Buf,
{
    /// Polls the stream for the next frame header
    ///
    /// When a frame header is received use `poll_data` to retrieve the frame's data.
    pub fn poll_next(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Frame<PayloadLen>>, FrameStreamError>> {
        assert_eq!(
            self.remaining_data, 0,
            "There is still data to read, please call poll_data() until it returns None."
        );

        loop {
            self.buffer_current_chunk();

            return match self.decoder.decode(&mut self.buffer)? {
                Some(Frame::Data(PayloadLen(len))) => {
                    self.remaining_data = len;
                    Poll::Ready(Ok(Some(Frame::Data(PayloadLen(len)))))
                }
                frame @ Some(Frame::WebTransportStream(_)) => {
                    self.remaining_data = usize::MAX;
                    Poll::Ready(Ok(frame))
                }
                Some(frame) => Poll::Ready(Ok(Some(frame))),
                None => match self.try_recv(cx)? {
                    // Received a chunk but frame is incomplete, poll until we get `Pending`.
                    Poll::Ready(false) => continue,
                    Poll::Pending => Poll::Pending,
                    Poll::Ready(true) => {
                        if self.stream.has_remaining() || self.buffer.has_remaining() {
                            // Reached the end of receive stream, but there is still some data:
                            // The frame is incomplete.
                            Poll::Ready(Err(FrameStreamError::UnexpectedEnd))
                        } else {
                            Poll::Ready(Ok(None))
                        }
                    }
                },
            };
        }
    }

    /// Polls the next request-stream frame without buffering a HEADERS payload.
    ///
    /// RFC 9114 defines HEADERS as an encoded field section. Returning its length
    /// here lets QPACK consume the payload through `poll_data` as transport chunks
    /// arrive instead of waiting for the complete frame.
    ///
    /// See [RFC 9114, Section 7.2.2](https://www.rfc-editor.org/rfc/rfc9114.html#section-7.2.2).
    pub(crate) fn poll_next_request(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<RequestFrame>, FrameStreamError>> {
        assert!(
            self.remaining_data == 0,
            "There is still data to read, please call poll_data() until it returns None."
        );

        loop {
            self.buffer_current_chunk();

            let headers = {
                let mut cursor = self.buffer.cursor();
                let decoded = Frame::decode_headers_prefix(&mut cursor);
                (cursor.position(), decoded)
            };

            match headers {
                (consumed, Ok(Some(PayloadLen(len)))) => {
                    self.buffer.advance(consumed);
                    self.decoder.expected = None;
                    self.remaining_data = len;
                    return Poll::Ready(Ok(Some(RequestFrame::Headers)));
                }
                (_, Err(frame::FrameError::Incomplete(_))) => {}
                (_, Err(_)) => unreachable!("HEADERS prefix decoding only reports incomplete data"),
                (_, Ok(None)) => match self.decoder.decode_one(&mut self.buffer)? {
                    Some(DecodedFrame::Frame(Frame::Data(PayloadLen(len)))) => {
                        self.remaining_data = len;
                        return Poll::Ready(Ok(Some(RequestFrame::Frame(Frame::Data(
                            PayloadLen(len),
                        )))));
                    }
                    Some(DecodedFrame::Frame(frame @ Frame::WebTransportStream(_))) => {
                        self.remaining_data = usize::MAX;
                        return Poll::Ready(Ok(Some(RequestFrame::Frame(frame))));
                    }
                    Some(DecodedFrame::Frame(frame)) => {
                        return Poll::Ready(Ok(Some(RequestFrame::Frame(frame))));
                    }
                    Some(DecodedFrame::Ignored) => continue,
                    None => {}
                },
            }

            match self.try_recv(cx)? {
                Poll::Ready(false) => continue,
                Poll::Pending => return Poll::Pending,
                Poll::Ready(true) => {
                    if self.stream.has_remaining() || self.buffer.has_remaining() {
                        // Reached the end of receive stream, but there is still some data:
                        // The frame is incomplete.
                        return Poll::Ready(Err(FrameStreamError::UnexpectedEnd));
                    } else {
                        return Poll::Ready(Ok(None));
                    }
                }
            }
        }
    }

    /// Retrieves the next piece of data in an incoming data packet or webtransport stream
    ///
    ///
    /// WebTransport bidirectional payload has no finite length and is processed until the end of the stream.
    pub fn poll_data(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Bytes>, FrameStreamError>> {
        if self.remaining_data == 0 {
            return Poll::Ready(Ok(None));
        }

        if self.buffer.has_remaining() {
            let len = self.buffer.chunk().len().min(self.remaining_data);
            self.remaining_data -= len;
            return Poll::Ready(Ok(Some(self.buffer.copy_to_bytes(len))));
        }

        let end = match self.try_recv(cx) {
            Poll::Ready(Ok(end)) => end,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => false,
        };
        let buf = self.stream.buf_mut();
        if end
            && buf
                .as_ref()
                .is_none_or(|d| d.remaining() < self.remaining_data)
        {
            return Poll::Ready(Err(FrameStreamError::UnexpectedEnd));
        }

        match (buf, end) {
            (None, true) => Poll::Ready(Err(FrameStreamError::UnexpectedEnd)),
            (None, false) => Poll::Pending,
            (Some(d), _) => {
                let len = d.chunk().len().min(self.remaining_data);
                self.remaining_data -= len;
                Poll::Ready(Ok(Some(d.copy_to_bytes(len))))
            }
        }
    }

    /// Retrieves at most `max_len` payload bytes from the current frame.
    ///
    /// Incremental HEADERS decoding uses a bounded chunk so a transport buffer
    /// containing the complete frame is not copied into the QPACK scratch buffer
    /// in one operation.
    ///
    /// See [RFC 9114, Section 4.2.2](https://www.rfc-editor.org/rfc/rfc9114.html#section-4.2.2).
    pub(crate) fn poll_data_chunk(
        &mut self,
        cx: &mut Context<'_>,
        max_len: usize,
    ) -> Poll<Result<Option<Bytes>, FrameStreamError>> {
        debug_assert!(max_len > 0);
        if self.remaining_data == 0 {
            return Poll::Ready(Ok(None));
        };

        // Consume buffered payload before polling QUIC again. Besides preserving
        // receive-side backpressure, this keeps the transport RecvStream available
        // for an immediate STOP_SENDING if header decoding rejects the section.
        if self.buffer.has_remaining() {
            let len = self
                .buffer
                .chunk()
                .len()
                .min(self.remaining_data)
                .min(max_len);
            self.remaining_data -= len;
            return Poll::Ready(Ok(Some(self.buffer.copy_to_bytes(len))));
        }

        let end = match self.try_recv(cx) {
            Poll::Ready(Ok(end)) => end,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => false,
        };
        let data = self.stream.buf_mut().as_mut().map(|data| {
            let len = data.chunk().len().min(self.remaining_data).min(max_len);
            data.copy_to_bytes(len)
        });

        match (data, end) {
            (None, true) => Poll::Ready(Err(FrameStreamError::UnexpectedEnd)),
            (None, false) => Poll::Pending,
            (Some(d), _) => {
                self.remaining_data -= d.remaining();
                Poll::Ready(Ok(Some(d)))
            }
        }
    }

    /// Stops the underlying stream with the provided error code
    pub(crate) fn stop_sending(&mut self, error_code: Code) {
        self.stream.stop_sending(error_code.into());
    }

    pub(crate) fn has_data(&self) -> bool {
        self.remaining_data != 0
    }

    pub(crate) fn is_eos(&self) -> bool {
        self.stream.is_eos()
            && !self.stream.has_remaining()
            && !self.buffer.has_remaining()
            && self.remaining_data == 0
    }

    fn try_recv(&mut self, cx: &mut Context<'_>) -> Poll<Result<bool, FrameStreamError>> {
        if self.stream.is_eos() {
            return Poll::Ready(Ok(true));
        }
        match self.stream.poll_read(cx) {
            Poll::Ready(Err(e)) => Poll::Ready(Err(FrameStreamError::Quic(e))),
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(eos)) => Poll::Ready(Ok(eos)),
        }
    }

    fn buffer_current_chunk(&mut self) {
        if let Some(buf) = self.stream.buf_mut().take() {
            if buf.has_remaining() {
                self.buffer.push(buf);
            }
        }
    }

    pub fn id(&self) -> StreamId {
        self.stream.recv_id()
    }
}

impl<T, B, R> SendStream<B> for FrameStream<T, B, R>
where
    T: SendStream<B>,
    B: Buf,
{
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        self.stream.poll_ready(cx)
    }

    fn send_data<D: Into<WriteBuf<B>>>(&mut self, data: D) -> Result<(), StreamErrorIncoming> {
        self.stream.send_data(data)
    }

    fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        self.stream.poll_finish(cx)
    }

    fn reset(&mut self, reset_code: u64) {
        self.stream.reset(reset_code)
    }

    fn send_id(&self) -> StreamId {
        self.stream.send_id()
    }
}

impl<S, B, R> FrameStream<S, B, R>
where
    S: BidiStream<B, RecvStream: RecvStream<Buf = R>> + RecvStream<Buf = R>,
    B: Buf,
    R: Buf,
{
    pub(crate) fn split(
        self,
    ) -> (
        FrameStream<S::SendStream, B, R>,
        FrameStream<S::RecvStream, B, R>,
    ) {
        let (send, recv) = self.stream.split();
        (
            FrameStream {
                stream: send,
                decoder: FrameDecoder::default(),
                remaining_data: 0,
                buffer: BufList::new(),
            },
            FrameStream {
                stream: recv,
                decoder: self.decoder,
                remaining_data: self.remaining_data,
                buffer: self.buffer,
            },
        )
    }
}

#[derive(Default)]
pub struct FrameDecoder {
    expected: Option<usize>,
}

impl FrameDecoder {
    fn decode<B: Buf>(
        &mut self,
        src: &mut BufList<B>,
    ) -> Result<Option<Frame<PayloadLen>>, FrameStreamError> {
        loop {
            match self.decode_one(src)? {
                Some(DecodedFrame::Frame(frame)) => return Ok(Some(frame)),
                Some(DecodedFrame::Ignored) => continue,
                None => return Ok(None),
            }
        }
    }

    fn decode_one<B: Buf>(
        &mut self,
        src: &mut BufList<B>,
    ) -> Result<Option<DecodedFrame>, FrameStreamError> {
        if !src.has_remaining() || self.expected.is_some_and(|min| src.remaining() < min) {
            return Ok(None);
        }

        let (pos, decoded) = {
            let mut cur = src.cursor();
            let decoded = Frame::decode(&mut cur);
            (cur.position(), decoded)
        };

        match decoded {
            Err(frame::FrameError::UnknownFrame(_ty)) => {
                // https://www.rfc-editor.org/rfc/rfc9114.html#section-7.2.8
                #[cfg(feature = "tracing")]
                trace!("ignore unknown frame type {:#x}", _ty);

                src.advance(pos);
                self.expected = None;
                Ok(Some(DecodedFrame::Ignored))
            }
            Err(frame::FrameError::Incomplete(min)) => {
                self.expected = Some(min);
                Ok(None)
            }
            Ok(frame) => {
                src.advance(pos);
                self.expected = None;
                Ok(Some(DecodedFrame::Frame(frame)))
            }
            // -------------- Map the error Values --------------
            Err(frame::FrameError::InvalidStreamId(e)) => Err(FrameStreamError::Proto(
                FrameProtocolError::InvalidStreamId(e),
            )),
            Err(frame::FrameError::InvalidPushId(e)) => Err(FrameStreamError::Proto(
                FrameProtocolError::InvalidPushId(e),
            )),
            Err(frame::FrameError::Settings(e)) => {
                Err(FrameStreamError::Proto(FrameProtocolError::Settings(e)))
            }
            Err(frame::FrameError::UnsupportedFrame(ty)) => Err(FrameStreamError::Proto(
                FrameProtocolError::ForbiddenFrame(ty),
            )),
            Err(frame::FrameError::InvalidFrameValue) => Err(FrameStreamError::Proto(
                FrameProtocolError::InvalidFrameValue,
            )),
            Err(frame::FrameError::Malformed) => {
                Err(FrameStreamError::Proto(FrameProtocolError::Malformed))
            }
        }
    }
}

enum DecodedFrame {
    Frame(Frame<PayloadLen>),
    Ignored,
}

#[derive(Debug)]
/// Errors that can occur while decoding frames
pub enum FrameStreamError {
    Proto(FrameProtocolError),
    Quic(StreamErrorIncoming),
    UnexpectedEnd,
}

#[derive(Debug, PartialEq)]
/// Protocol specific errors that can occur while decoding frames in a stream
pub enum FrameProtocolError {
    Malformed,
    ForbiddenFrame(u64), // Known (http2) frames that should generate an error
    InvalidFrameValue,
    Settings(SettingsError),
    InvalidStreamId(InvalidStreamId),
    InvalidPushId(InvalidPushId),
}

#[cfg(test)]
mod tests {
    use super::*;

    use assert_matches::assert_matches;
    use bytes::{BufMut, Bytes, BytesMut};
    use futures_util::future::poll_fn;
    use std::{
        collections::VecDeque,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
    };

    use crate::proto::{coding::Encode, frame::FrameType, varint::VarInt};

    // Decoder

    #[test]
    fn one_frame() {
        let mut buf = BytesMut::with_capacity(16);
        Frame::headers(&b"salut"[..]).encode_with_payload(&mut buf);
        let mut buf = BufList::from(buf);

        let mut decoder = FrameDecoder::default();
        assert_matches!(decoder.decode(&mut buf), Ok(Some(Frame::Headers(_))));
    }

    #[test]
    fn incomplete_frame() {
        let frame = Frame::headers(&b"salut"[..]);

        let mut buf = BytesMut::with_capacity(16);
        frame.encode(&mut buf);
        buf.truncate(buf.len() - 1);
        let mut buf = BufList::from(buf);

        let mut decoder = FrameDecoder::default();
        assert_matches!(decoder.decode(&mut buf), Ok(None));
    }

    #[test]
    fn header_spread_multiple_buf() {
        let mut buf = BytesMut::with_capacity(16);
        Frame::headers(&b"salut"[..]).encode_with_payload(&mut buf);
        let mut buf_list = BufList::new();
        // Cut buffer between type and length
        buf_list.push(&buf[..1]);
        buf_list.push(&buf[1..]);

        let mut decoder = FrameDecoder::default();
        assert_matches!(decoder.decode(&mut buf_list), Ok(Some(Frame::Headers(_))));
    }

    #[test]
    fn varint_spread_multiple_buf() {
        let mut buf = BytesMut::with_capacity(16);
        Frame::headers("salut".repeat(1024)).encode_with_payload(&mut buf);

        let mut buf_list = BufList::new();
        // Cut buffer in the middle of length's varint
        buf_list.push(&buf[..2]);
        buf_list.push(&buf[2..]);

        let mut decoder = FrameDecoder::default();
        assert_matches!(decoder.decode(&mut buf_list), Ok(Some(Frame::Headers(_))));
    }

    #[test]
    fn two_frames_then_incomplete() {
        let mut buf = BytesMut::with_capacity(64);
        Frame::headers(&b"header"[..]).encode_with_payload(&mut buf);
        Frame::Data(&b"body"[..]).encode_with_payload(&mut buf);
        Frame::headers(&b"trailer"[..]).encode_with_payload(&mut buf);

        buf.truncate(buf.len() - 1);
        let mut buf = BufList::from(buf);

        let mut decoder = FrameDecoder::default();
        assert_matches!(decoder.decode(&mut buf), Ok(Some(Frame::Headers(_))));
        assert_matches!(
            decoder.decode(&mut buf),
            Ok(Some(Frame::Data(PayloadLen(4))))
        );
        assert_matches!(decoder.decode(&mut buf), Ok(None));
    }

    // FrameStream

    macro_rules! assert_poll_matches {
        ($poll_fn:expr, $match:pat) => {
            assert_matches!(
                poll_fn($poll_fn).await,
                $match
            );
        };
        ($poll_fn:expr, $match:pat if $cond:expr ) => {
            assert_matches!(
                poll_fn($poll_fn).await,
                $match if $cond
            );
        }
    }

    #[tokio::test]
    async fn poll_full_request() {
        let mut recv = FakeRecv::default();
        let mut buf = BytesMut::with_capacity(64);

        Frame::headers(&b"header"[..]).encode_with_payload(&mut buf);
        Frame::Data(&b"body"[..]).encode_with_payload(&mut buf);
        Frame::headers(&b"trailer"[..]).encode_with_payload(&mut buf);
        recv.chunk(buf.freeze());

        let mut stream: FrameStream<_, (), _> = FrameStream::new(BufRecvStream::new(recv));

        assert_poll_matches!(|cx| stream.poll_next(cx), Ok(Some(Frame::Headers(_))));
        assert_poll_matches!(
            |cx| stream.poll_next(cx),
            Ok(Some(Frame::Data(PayloadLen(4))))
        );
        assert_poll_matches!(
            |cx| to_bytes(stream.poll_data(cx)),
            Ok(Some(b)) if b.remaining() == 4
        );
        assert_poll_matches!(|cx| stream.poll_next(cx), Ok(Some(Frame::Headers(_))));
    }

    #[tokio::test]
    async fn poll_next_incomplete_frame() {
        let mut recv = FakeRecv::default();
        let mut buf = BytesMut::with_capacity(64);

        Frame::headers(&b"header"[..]).encode_with_payload(&mut buf);
        let mut buf = buf.freeze();
        recv.chunk(buf.split_to(buf.len() - 1));
        let mut stream: FrameStream<_, (), _> = FrameStream::new(BufRecvStream::new(recv));

        assert_poll_matches!(
            |cx| stream.poll_next(cx),
            Err(FrameStreamError::UnexpectedEnd)
        );
    }

    #[tokio::test]
    #[should_panic(
        expected = "There is still data to read, please call poll_data() until it returns None"
    )]
    async fn poll_next_reamining_data() {
        let mut recv = FakeRecv::default();
        let mut buf = BytesMut::with_capacity(64);

        FrameType::DATA.encode(&mut buf);
        VarInt::from(4u32).encode(&mut buf);
        recv.chunk(buf.freeze());
        let mut stream: FrameStream<_, (), _> = FrameStream::new(BufRecvStream::new(recv));

        assert_poll_matches!(
            |cx| stream.poll_next(cx),
            Ok(Some(Frame::Data(PayloadLen(4))))
        );

        // There is still data to consume, poll_next should panic
        let _ = poll_fn(|cx| stream.poll_next(cx)).await;
    }

    #[tokio::test]
    async fn poll_data_split() {
        let mut recv = FakeRecv::default();
        let mut buf = BytesMut::with_capacity(64);

        // Body is split into two bufs
        Frame::Data(Bytes::from("body")).encode_with_payload(&mut buf);

        let mut buf = buf.freeze();
        recv.chunk(buf.split_to(buf.len() - 2));
        recv.chunk(buf);
        let mut stream: FrameStream<_, (), _> = FrameStream::new(BufRecvStream::new(recv));

        // We get the total size of data about to be received
        assert_poll_matches!(
            |cx| stream.poll_next(cx),
            Ok(Some(Frame::Data(PayloadLen(4))))
        );

        // Then we get parts of body, chunked as they arrived
        assert_poll_matches!(
            |cx| to_bytes(stream.poll_data(cx)),
            Ok(Some(b)) if b.remaining() == 2
        );
        assert_poll_matches!(
            |cx| to_bytes(stream.poll_data(cx)),
            Ok(Some(b)) if b.remaining() == 2
        );
    }

    #[tokio::test]
    async fn poll_data_unexpected_end() {
        let mut recv = FakeRecv::default();
        let mut buf = BytesMut::with_capacity(64);

        // Truncated body
        FrameType::DATA.encode(&mut buf);
        VarInt::from(4u32).encode(&mut buf);
        let data = Bytes::from("b");
        buf.put_slice(&data[..]);
        recv.chunk(buf.freeze());
        let mut stream: FrameStream<_, (), _> = FrameStream::new(BufRecvStream::new(recv));

        assert_poll_matches!(
            |cx| stream.poll_next(cx),
            Ok(Some(Frame::Data(PayloadLen(4))))
        );
        assert_poll_matches!(
            |cx| to_bytes(stream.poll_data(cx)),
            Ok(Some(d)) if d == data
        );
        assert_poll_matches!(
            |cx| to_bytes(stream.poll_data(cx)),
            Err(FrameStreamError::UnexpectedEnd)
        );
    }

    #[tokio::test]
    async fn poll_data_ignores_unknown_frames() {
        use crate::proto::varint::BufMutExt as _;

        let mut recv = FakeRecv::default();
        let mut buf = BytesMut::with_capacity(64);

        // grease a lil
        crate::proto::frame::FrameType::grease().encode(&mut buf);
        buf.write_var(0);

        // grease with some data
        crate::proto::frame::FrameType::grease().encode(&mut buf);
        buf.write_var(6);
        buf.put_slice(b"grease");

        // Body
        Frame::Data(Bytes::from("body")).encode_with_payload(&mut buf);

        recv.chunk(buf.freeze());
        let mut stream: FrameStream<_, (), _> = FrameStream::new(BufRecvStream::new(recv));

        assert_poll_matches!(
            |cx| stream.poll_next(cx),
            Ok(Some(Frame::Data(PayloadLen(4))))
        );
        assert_poll_matches!(
            |cx| to_bytes(stream.poll_data(cx)),
            Ok(Some(b)) if &*b == b"body"
        );
    }

    /*#[tokio::test]
    async fn poll_data_eos_but_buffered_data() {
        let mut recv = FakeRecv::default();
        let mut buf = BytesMut::with_capacity(64);

        FrameType::DATA.encode(&mut buf);
        VarInt::from(4u32).encode(&mut buf);
        buf.put_slice(&b"bo"[..]);
        recv.chunk(buf.clone().freeze());

        let mut stream: FrameStream<_, (), Bytes> = FrameStream::new(BufRecvStream::new(recv));

        assert_poll_matches!(
            |cx| stream.poll_next(cx),
            Ok(Some(Frame::Data(PayloadLen(4))))
        );

        buf.truncate(0);
        buf.put_slice(&b"dy"[..]);
        stream.stream.buf_mut().unwrap().push_bytes(&mut buf.freeze());

        assert_poll_matches!(
            |cx| to_bytes(stream.poll_data(cx)),
            Ok(Some(b)) if &*b == b"bo"
        );

        assert_poll_matches!(
            |cx| to_bytes(stream.poll_data(cx)),
            Ok(Some(b)) if &*b == b"dy"
        );
    }*/

    #[tokio::test]
    async fn poll_next_consumes_buffered_frame_before_reading_more() {
        let mut recv = FakeRecv::default();
        let reads = recv.reads();
        let mut buf = BytesMut::with_capacity(64);

        Frame::headers(&b"header"[..]).encode_with_payload(&mut buf);
        Frame::headers(&b"trailer"[..]).encode_with_payload(&mut buf);
        recv.chunk(buf.freeze());
        recv.chunk(Bytes::from_static(b"unused"));

        let mut stream: FrameStream<_, (), _> = FrameStream::new(BufRecvStream::new(recv));

        assert_poll_matches!(|cx| stream.poll_next(cx), Ok(Some(Frame::Headers(_))));
        assert_eq!(reads.load(Ordering::Relaxed), 1);

        assert_poll_matches!(|cx| stream.poll_next(cx), Ok(Some(Frame::Headers(_))));
        assert_eq!(reads.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn request_headers_payload_is_read_in_bounded_chunks() {
        let mut recv = FakeRecv::default();
        let mut encoded = BytesMut::new();
        Frame::headers(&b"header-payload"[..]).encode_with_payload(&mut encoded);
        recv.chunk(encoded.freeze());

        let mut stream: FrameStream<_, (), _> = FrameStream::new(BufRecvStream::new(recv));
        assert_poll_matches!(
            |cx| stream.poll_next_request(cx),
            Ok(Some(RequestFrame::Headers))
        );
        assert_poll_matches!(
            |cx| to_bytes(stream.poll_data_chunk(cx, 3)),
            Ok(Some(bytes)) if bytes == b"hea"[..]
        );
        assert_poll_matches!(
            |cx| to_bytes(stream.poll_data_chunk(cx, 3)),
            Ok(Some(bytes)) if bytes == b"der"[..]
        );
        assert!(stream.has_data());
    }

    #[tokio::test]
    async fn request_headers_payload_reports_zero_byte_truncation() {
        let mut recv = FakeRecv::default();
        let mut encoded = BytesMut::new();
        Frame::headers(&b"missing"[..]).encode(&mut encoded);
        recv.chunk(encoded.freeze());

        let mut stream: FrameStream<_, (), _> = FrameStream::new(BufRecvStream::new(recv));
        assert_poll_matches!(
            |cx| stream.poll_next_request(cx),
            Ok(Some(RequestFrame::Headers))
        );
        assert_poll_matches!(
            |cx| stream.poll_data_chunk(cx, 16),
            Err(FrameStreamError::UnexpectedEnd)
        );
    }

    #[tokio::test]
    async fn unknown_frame_before_headers_keeps_headers_incremental() {
        use crate::proto::varint::BufMutExt as _;

        let mut recv = FakeRecv::default();
        let mut encoded = BytesMut::new();
        FrameType::grease().encode(&mut encoded);
        encoded.write_var(3);
        encoded.put_slice(b"ext");
        Frame::headers(&b"header"[..]).encode_with_payload(&mut encoded);
        recv.chunk(encoded.freeze());

        let mut stream: FrameStream<_, (), _> = FrameStream::new(BufRecvStream::new(recv));
        assert_poll_matches!(
            |cx| stream.poll_next_request(cx),
            Ok(Some(RequestFrame::Headers))
        );
        assert_poll_matches!(
            |cx| stream.poll_data_chunk(cx, 16),
            Ok(Some(bytes)) if bytes == b"header"[..]
        );
    }

    // Helpers

    #[derive(Default)]
    struct FakeRecv {
        chunks: VecDeque<Bytes>,
        reads: Arc<AtomicUsize>,
    }

    impl FakeRecv {
        fn chunk(&mut self, buf: Bytes) -> &mut Self {
            self.chunks.push_back(buf);
            self
        }

        fn reads(&self) -> Arc<AtomicUsize> {
            self.reads.clone()
        }
    }

    impl RecvStream for FakeRecv {
        type Buf = Bytes;

        fn poll_data(
            &mut self,
            _: &mut Context<'_>,
        ) -> Poll<Result<Option<Self::Buf>, StreamErrorIncoming>> {
            self.reads.fetch_add(1, Ordering::Relaxed);
            Poll::Ready(Ok(self.chunks.pop_front()))
        }

        fn stop_sending(&mut self, _: u64) {
            unimplemented!()
        }

        fn recv_id(&self) -> StreamId {
            unimplemented!()
        }
    }

    fn to_bytes(
        x: Poll<Result<Option<impl Buf>, FrameStreamError>>,
    ) -> Poll<Result<Option<Bytes>, FrameStreamError>> {
        x.map(|b| b.map(|b| b.map(|mut b| b.copy_to_bytes(b.remaining()))))
    }
}
