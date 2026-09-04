use std::task::{Context, Poll};

use bytes::{Buf, Bytes};
#[cfg(feature = "tracing")]
use tracing::trace;

use crate::{
    buf::BufList,
    error::Code,
    proto::{
        frame::{self, Frame, FrameType, PayloadLen, SettingsError},
        push::InvalidPushId,
        stream::StreamId,
    },
    quic::{BidiStream, InvalidStreamId, RecvStream, SendStream, StreamErrorIncoming},
    stream::{BufRecvStream, WriteBuf},
};

/// Decodes HTTP/3 frames from the underlying QUIC stream.
pub struct FrameStream<S, B> {
    pub stream: BufRecvStream<S, B>,
    // Already read data from the stream
    decoder: FrameDecoder,
    remaining_data: usize,
    data_until_eos: bool,
}

/// A stream frame whose HEADERS payload has not been buffered yet.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub(crate) enum Frames {
    Headers,
    Frame(Frame<PayloadLen>),
}

impl<S, B> FrameStream<S, B> {
    pub fn new(stream: BufRecvStream<S, B>) -> Self {
        Self {
            stream,
            decoder: FrameDecoder::default(),
            remaining_data: 0,
            data_until_eos: false,
        }
    }

    /// Unwraps the Framed streamer and returns the underlying stream **without** data loss for
    /// partially received/read frames.
    pub fn into_inner(self) -> BufRecvStream<S, B> {
        self.stream
    }

    pub(crate) fn set_max_field_section_size(&mut self, max: usize) {
        self.decoder.max_field_section_size = max;
    }
}

impl<S, B> FrameStream<S, B>
where
    S: crate::quic::Is0rtt,
{
    /// Checks if the stream was opened in 0-RTT mode
    pub(crate) fn is_0rtt(&self) -> bool {
        self.stream.is_0rtt()
    }
}

impl<S, B> FrameStream<S, B>
where
    S: RecvStream,
{
    /// Polls the stream for the next frame header
    ///
    /// When a frame header is received use `poll_data` to retrieve the frame's data.
    pub fn poll_next(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Frame<PayloadLen>>, FrameStreamError>> {
        if self.remaining_data != 0 {
            return Poll::Ready(Err(FrameStreamError::Proto(FrameProtocolError::Malformed)));
        }

        loop {
            // Decode buffered frames before reading more from the transport.
            return match self.decoder.decode(self.stream.buf_mut())? {
                Some(Frame::Data(PayloadLen(len))) => {
                    self.remaining_data = len;
                    self.data_until_eos = false;
                    Poll::Ready(Ok(Some(Frame::Data(PayloadLen(len)))))
                }
                frame @ Some(Frame::WebTransportStream(_)) => {
                    self.remaining_data = usize::MAX;
                    self.data_until_eos = true;
                    Poll::Ready(Ok(frame))
                }
                Some(frame) => Poll::Ready(Ok(Some(frame))),
                None => match self.try_recv(cx)? {
                    // Received a chunk but frame is incomplete, poll until we get `Pending`.
                    Poll::Ready(false) => continue,
                    Poll::Pending => Poll::Pending,
                    Poll::Ready(true) => {
                        if self.stream.buf_mut().has_remaining()
                            || self.decoder.is_discarding_unknown_payload()
                        {
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

    /// Polls the next stream frame without buffering a HEADERS payload.
    ///
    /// RFC 9114 defines HEADERS as an encoded field section. Returning its length
    /// here lets QPACK consume the payload through `poll_data` as transport chunks
    /// arrive instead of waiting for the complete frame.
    ///
    /// See [RFC 9114, Section 7.2.2](https://www.rfc-editor.org/rfc/rfc9114.html#section-7.2.2).
    pub(crate) fn poll_next_frame(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Frames>, FrameStreamError>> {
        if self.remaining_data != 0 {
            return Poll::Ready(Err(FrameStreamError::Proto(FrameProtocolError::Malformed)));
        }

        loop {
            // Once an unknown frame prefix has been consumed, every byte up to
            // its declared length is payload. Do not probe those bytes for a
            // HEADERS prefix, even when a payload chunk happens to begin with
            // the HEADERS frame type.
            // https://www.rfc-editor.org/rfc/rfc9114.html#section-9
            if self.decoder.is_discarding_unknown_payload() {
                match self.decoder.decode_one(self.stream.buf_mut())? {
                    Some(DecodedFrame::Ignored) => continue,
                    None => {}
                    Some(DecodedFrame::Frame(_)) => {
                        return Poll::Ready(Err(FrameStreamError::Proto(
                            FrameProtocolError::Malformed,
                        )));
                    }
                }
            } else {
                let prefix = {
                    let mut cursor = self.stream.buf_mut().cursor();
                    let decoded = Frame::decode_payload_prefix(&mut cursor);
                    (cursor.position(), decoded)
                };

                match prefix {
                    (consumed, Ok(Some((ty, PayloadLen(len))))) => {
                        // Incremental consumption must not relax the public
                        // limit on a whole encoded field section. Decoded
                        // fields still accumulate until HEADERS is complete.
                        // https://www.rfc-editor.org/rfc/rfc9204.html#section-7.4
                        if ty == FrameType::HEADERS && len > self.decoder.max_field_section_size {
                            return Poll::Ready(Err(FrameStreamError::Proto(
                                FrameProtocolError::ExcessiveLoad {
                                    len: len as u64,
                                    limit: self.decoder.max_field_section_size,
                                },
                            )));
                        }
                        self.stream.buf_mut().advance(consumed);
                        self.remaining_data = len;
                        self.data_until_eos = false;
                        let frame = if ty == FrameType::HEADERS {
                            Frames::Headers
                        } else {
                            Frames::Frame(Frame::Data(PayloadLen(len)))
                        };
                        return Poll::Ready(Ok(Some(frame)));
                    }
                    (_, Err(frame::FrameError::Incomplete(_))) => {}
                    // A malformed prefix violates the HTTP/3 frame layout.
                    // https://www.rfc-editor.org/rfc/rfc9114.html#section-7.1
                    (_, Err(error)) => return Poll::Ready(Err(map_frame_error(error))),
                    (_, Ok(None)) => match self.decoder.decode_one(self.stream.buf_mut())? {
                        Some(DecodedFrame::Frame(frame @ Frame::WebTransportStream(_))) => {
                            self.remaining_data = usize::MAX;
                            self.data_until_eos = true;
                            return Poll::Ready(Ok(Some(Frames::Frame(frame))));
                        }
                        Some(DecodedFrame::Frame(frame)) => {
                            return Poll::Ready(Ok(Some(Frames::Frame(frame))));
                        }
                        // Unknown frames can appear between message frames. Resume
                        // prefix probing so a following HEADERS stays incremental.
                        // https://www.rfc-editor.org/rfc/rfc9114.html#section-9
                        Some(DecodedFrame::Ignored) => continue,
                        None => {}
                    },
                }
            }

            match self.try_recv(cx)? {
                Poll::Ready(false) => continue,
                Poll::Pending => return Poll::Pending,
                Poll::Ready(true)
                    if self.stream.buf_mut().has_remaining()
                        || self.decoder.is_discarding_unknown_payload() =>
                {
                    return Poll::Ready(Err(FrameStreamError::UnexpectedEnd));
                }
                Poll::Ready(true) => return Poll::Ready(Ok(None)),
            }
        }
    }

    /// Retrieves the next piece of data in an incoming data packet or webtransport stream
    ///
    ///
    /// WebTransport bidirectional payload has no finite length and is processed until the end of
    /// the stream.
    pub fn poll_data(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<impl Buf + use<S, B>>, FrameStreamError>> {
        if self.remaining_data == 0 {
            return Poll::Ready(Ok(None));
        }

        let end = match self.try_recv(cx) {
            Poll::Ready(Ok(end)) => end,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => false,
        };
        let data = self.stream.buf_mut().take_chunk(self.remaining_data);

        match (data, end) {
            // Only WebTransport treats FIN as the end of an unbounded payload.
            // A finite DATA length may also equal usize::MAX on 32-bit targets.
            (None, true) if self.data_until_eos => {
                self.remaining_data = 0;
                self.data_until_eos = false;
                Poll::Ready(Ok(None))
            }
            // A finite frame payload cannot end while bytes are outstanding.
            // https://www.rfc-editor.org/rfc/rfc9114.html#section-7.1
            (None, true) => Poll::Ready(Err(FrameStreamError::UnexpectedEnd)),
            (None, false) => Poll::Pending,
            (Some(d), _) if self.data_until_eos => Poll::Ready(Ok(Some(d))),
            (Some(d), true)
                if d.remaining() < self.remaining_data
                    && !self.stream.buf_mut().has_remaining() =>
            {
                Poll::Ready(Err(FrameStreamError::UnexpectedEnd))
            }
            (Some(d), _) => {
                self.remaining_data -= d.remaining();
                Poll::Ready(Ok(Some(d)))
            }
        }
    }

    /// Retrieves at most `max_len` payload bytes from the current frame.
    ///
    /// Incremental HEADERS decoding uses a bounded chunk so a transport buffer
    /// containing the complete frame is not copied into the QPACK scratch buffer
    /// in one operation.
    ///
    /// See [RFC 9114, Section 4.2.2](https://www.rfc-editor.org/rfc/rfc9114.html#section-4.2.2)
    /// and [RFC 9204, Section 2.2.1](https://www.rfc-editor.org/rfc/rfc9204.html#section-2.2.1).
    pub(crate) fn poll_data_chunk(
        &mut self,
        cx: &mut Context<'_>,
        max_len: usize,
    ) -> Poll<Result<Option<impl Buf + use<S, B>>, FrameStreamError>> {
        debug_assert!(max_len > 0);
        if self.remaining_data == 0 {
            return Poll::Ready(Ok(None));
        };

        // Consume buffered payload before polling QUIC again. Besides preserving
        // receive-side backpressure, this keeps the transport RecvStream available
        // for an immediate STOP_SENDING if header decoding rejects the section.
        if let Some(data) = self
            .stream
            .buf_mut()
            .take_chunk(self.remaining_data.min(max_len))
        {
            self.remaining_data -= data.remaining();
            return Poll::Ready(Ok(Some(data)));
        }

        let end = match self.try_recv(cx) {
            Poll::Ready(Ok(end)) => end,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => false,
        };
        let data = self
            .stream
            .buf_mut()
            .take_chunk(self.remaining_data.min(max_len));

        match (data, end) {
            // `poll_data_chunk` is used for finite HEADERS payloads. Reaching
            // FIN before `remaining_data` reaches zero is a malformed frame.
            // https://www.rfc-editor.org/rfc/rfc9114.html#section-7.1
            (None, true) => Poll::Ready(Err(FrameStreamError::UnexpectedEnd)),
            (None, false) => Poll::Pending,
            (Some(d), true)
                if d.remaining() < self.remaining_data
                    && !self.stream.buf_mut().has_remaining() =>
            {
                Poll::Ready(Err(FrameStreamError::UnexpectedEnd))
            }
            (Some(d), _) => {
                self.remaining_data -= d.remaining();
                Poll::Ready(Ok(Some(d)))
            }
        }
    }

    /// Takes a complete, contiguous buffered payload without reading QUIC.
    ///
    /// Call after accepting a finite frame prefix. A complete field section can
    /// then use the synchronous QPACK path without a second staging allocation.
    /// Fragmented or oversized payloads are left untouched for incremental reads.
    pub(crate) fn take_buffered_payload(&mut self, max_len: usize) -> Option<Bytes> {
        if self.data_until_eos || self.remaining_data > max_len {
            return None;
        }
        if self.remaining_data == 0 {
            return Some(Bytes::new());
        }
        if self.stream.buf().chunk().len() < self.remaining_data {
            return None;
        }
        let payload = self.stream.buf_mut().take_chunk(self.remaining_data)?;
        self.remaining_data = 0;
        Some(payload)
    }

    /// Stops the underlying stream with the provided error code
    pub(crate) fn stop_sending(&mut self, error_code: Code) {
        self.stream.stop_sending(error_code.into());
    }

    pub(crate) fn has_data(&self) -> bool {
        self.remaining_data != 0
    }

    pub(crate) fn is_eos(&self) -> bool {
        self.stream.is_eos() && !self.stream.buf().has_remaining()
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

    pub fn id(&self) -> StreamId {
        self.stream.recv_id()
    }
}

impl<T, B> SendStream<B> for FrameStream<T, B>
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

impl<S, B> FrameStream<S, B>
where
    S: BidiStream<B>,
    B: Buf,
{
    pub(crate) fn split(self) -> (FrameStream<S::SendStream, B>, FrameStream<S::RecvStream, B>) {
        let (send, recv) = self.stream.split();
        (
            FrameStream {
                stream: send,
                decoder: FrameDecoder::default(),
                remaining_data: 0,
                data_until_eos: false,
            },
            FrameStream {
                stream: recv,
                decoder: self.decoder,
                remaining_data: self.remaining_data,
                data_until_eos: self.data_until_eos,
            },
        )
    }
}

pub struct FrameDecoder {
    expected: Option<usize>,
    max_field_section_size: usize,
    ignored_payload: u64,
}

impl Default for FrameDecoder {
    fn default() -> Self {
        Self {
            expected: None,
            max_field_section_size: usize::MAX,
            ignored_payload: 0,
        }
    }
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
        if self.ignored_payload != 0 {
            return Ok(self.discard_unknown_payload(src));
        }

        if !src.has_remaining() || self.expected.is_some_and(|min| src.remaining() < min) {
            return Ok(None);
        }

        let (prefix_len, unknown) = {
            let mut cur = src.cursor();
            let decoded = Frame::decode_unknown_prefix(&mut cur);
            (cur.position(), decoded)
        };

        match unknown {
            Ok(Some((_ty, len))) => {
                // Keep only the number of bytes still to discard. This mirrors
                // the frame-state approach used for DATA and HEADERS payloads,
                // so an unknown frame never has to be buffered in full.
                // https://www.rfc-editor.org/rfc/rfc9114.html#section-9
                #[cfg(feature = "tracing")]
                trace!("ignore unknown frame type {:#x}", _ty);
                src.advance(prefix_len);
                self.expected = None;
                self.ignored_payload = len;
                return Ok(self.discard_unknown_payload(src));
            }
            Err(frame::FrameError::Incomplete(min)) => {
                self.expected = Some(min);
                return Ok(None);
            }
            Err(error) => return Err(map_frame_error(error)),
            Ok(None) => {}
        }

        let (pos, decoded) = {
            let mut cur = src.cursor();
            let decoded =
                Frame::decode_with_max_field_section_size(&mut cur, self.max_field_section_size);
            (cur.position(), decoded)
        };

        match decoded {
            Err(frame::FrameError::UnknownFrame(_ty)) => {
                //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.8
                //# Endpoints MUST
                //# NOT consider these frames to have any meaning upon receipt.
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
            Err(error) => Err(map_frame_error(error)),
        }
    }

    fn discard_unknown_payload<B: Buf>(&mut self, src: &mut BufList<B>) -> Option<DecodedFrame> {
        let consumed = src
            .remaining()
            .min(usize::try_from(self.ignored_payload).unwrap_or(usize::MAX));
        src.advance(consumed);
        self.ignored_payload -= consumed as u64;

        (self.ignored_payload == 0).then_some(DecodedFrame::Ignored)
    }

    fn is_discarding_unknown_payload(&self) -> bool {
        self.ignored_payload != 0
    }
}

#[allow(clippy::large_enum_variant)]
enum DecodedFrame {
    Frame(Frame<PayloadLen>),
    Ignored,
}

fn map_frame_error(error: frame::FrameError) -> FrameStreamError {
    match error {
        frame::FrameError::Incomplete(_) => FrameStreamError::UnexpectedEnd,
        frame::FrameError::UnknownFrame(_) => {
            FrameStreamError::Proto(FrameProtocolError::Malformed)
        }
        frame::FrameError::InvalidStreamId(e) => {
            FrameStreamError::Proto(FrameProtocolError::InvalidStreamId(e))
        }
        frame::FrameError::InvalidPushId(e) => {
            FrameStreamError::Proto(FrameProtocolError::InvalidPushId(e))
        }
        frame::FrameError::Settings(e) => FrameStreamError::Proto(FrameProtocolError::Settings(e)),
        frame::FrameError::UnsupportedFrame(ty) => {
            FrameStreamError::Proto(FrameProtocolError::ForbiddenFrame(ty))
        }
        frame::FrameError::InvalidFrameValue => {
            FrameStreamError::Proto(FrameProtocolError::InvalidFrameValue)
        }
        frame::FrameError::ExcessiveLoad { len, limit } => {
            FrameStreamError::Proto(FrameProtocolError::ExcessiveLoad { len, limit })
        }
        frame::FrameError::Malformed => FrameStreamError::Proto(FrameProtocolError::Malformed),
    }
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
    ExcessiveLoad { len: u64, limit: usize },
    Settings(SettingsError),
    InvalidStreamId(InvalidStreamId),
    InvalidPushId(InvalidPushId),
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use assert_matches::assert_matches;
    use bytes::{BufMut, Bytes, BytesMut};
    use futures_util::future::poll_fn;

    use super::*;
    use crate::{
        proto::{coding::Encode, frame::FrameType, varint::VarInt},
        webtransport::SessionId,
    };

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
    fn oversized_field_section_is_rejected_from_its_frame_header() {
        let mut wire = BytesMut::new();
        FrameType::HEADERS.encode(&mut wire);
        VarInt::from(5u32).encode(&mut wire);
        let mut buf = BufList::from(wire);
        let buffered = buf.remaining();

        let mut decoder = FrameDecoder {
            max_field_section_size: 4,
            ..FrameDecoder::default()
        };
        assert_matches!(
            decoder.decode(&mut buf),
            Err(FrameStreamError::Proto(FrameProtocolError::ExcessiveLoad {
                len: 5,
                limit: 4,
            }))
        );
        assert_eq!(buf.remaining(), buffered);
    }

    #[test]
    fn incomplete_buffered_frame_waits_while_stream_is_open() {
        for ty in [FrameType::HEADERS, FrameType::grease()] {
            let mut recv = FakeRecv::default();
            let mut wire = BytesMut::new();
            ty.encode(&mut wire);
            VarInt::from(4u32).encode(&mut wire);
            recv.chunk(wire.freeze()).pending_when_empty();

            let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));
            let mut cx = Context::from_waker(futures_util::task::noop_waker_ref());
            assert!(matches!(stream.poll_next(&mut cx), Poll::Pending));
        }
    }

    #[test]
    fn incomplete_buffered_frame_rejects_clean_end() {
        for ty in [FrameType::HEADERS, FrameType::grease()] {
            let mut recv = FakeRecv::default();
            let mut wire = BytesMut::new();
            ty.encode(&mut wire);
            VarInt::from(4u32).encode(&mut wire);
            recv.chunk(wire.freeze());

            let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));
            let mut cx = Context::from_waker(futures_util::task::noop_waker_ref());
            assert_matches!(
                stream.poll_next(&mut cx),
                Poll::Ready(Err(FrameStreamError::UnexpectedEnd))
            );
        }
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

        let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));

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
        let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));

        assert_poll_matches!(
            |cx| stream.poll_next(cx),
            Err(FrameStreamError::UnexpectedEnd)
        );
    }

    #[tokio::test]
    async fn poll_next_rejects_unconsumed_data() {
        let mut recv = FakeRecv::default();
        let mut buf = BytesMut::with_capacity(64);

        FrameType::DATA.encode(&mut buf);
        VarInt::from(4u32).encode(&mut buf);
        recv.chunk(buf.freeze());
        let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));

        assert_poll_matches!(
            |cx| stream.poll_next(cx),
            Ok(Some(Frame::Data(PayloadLen(4))))
        );

        assert_poll_matches!(
            |cx| stream.poll_next(cx),
            Err(FrameStreamError::Proto(FrameProtocolError::Malformed))
        );
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
        let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));

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
        buf.put_slice(&b"b"[..]);
        recv.chunk(buf.freeze());
        let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));

        assert_poll_matches!(
            |cx| stream.poll_next(cx),
            Ok(Some(Frame::Data(PayloadLen(4))))
        );
        assert_poll_matches!(
            |cx| to_bytes(stream.poll_data(cx)),
            Err(FrameStreamError::UnexpectedEnd)
        );
    }

    #[tokio::test]
    async fn poll_data_waits_when_fixed_payload_is_still_open() {
        let mut recv = FakeRecv::default();
        let mut buf = BytesMut::with_capacity(16);
        FrameType::DATA.encode(&mut buf);
        VarInt::from(4u32).encode(&mut buf);
        recv.chunk(buf.freeze()).pending_when_empty();

        let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));
        assert_poll_matches!(
            |cx| stream.poll_next(cx),
            Ok(Some(Frame::Data(PayloadLen(4))))
        );

        let mut cx = Context::from_waker(futures_util::task::noop_waker_ref());
        assert!(matches!(stream.poll_data(&mut cx), Poll::Pending));
    }

    #[tokio::test]
    async fn poll_data_rejects_clean_end_before_fixed_payload() {
        let mut recv = FakeRecv::default();
        let mut buf = BytesMut::with_capacity(16);
        FrameType::DATA.encode(&mut buf);
        VarInt::from(4u32).encode(&mut buf);
        recv.chunk(buf.freeze());

        let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));
        assert_poll_matches!(
            |cx| stream.poll_next(cx),
            Ok(Some(Frame::Data(PayloadLen(4))))
        );
        assert_poll_matches!(
            |cx| to_bytes(stream.poll_data(cx)),
            Err(FrameStreamError::UnexpectedEnd)
        );
    }

    #[tokio::test]
    async fn poll_webtransport_data_accepts_clean_end() {
        let mut recv = FakeRecv::default();
        let mut buf = BytesMut::with_capacity(16);
        Frame::<Bytes>::WebTransportStream(SessionId::try_from(0).unwrap()).encode(&mut buf);
        buf.put_slice(b"body");
        recv.chunk(buf.freeze());

        let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));
        assert_poll_matches!(
            |cx| stream.poll_next(cx),
            Ok(Some(Frame::WebTransportStream(_)))
        );
        assert_poll_matches!(
            |cx| to_bytes(stream.poll_data(cx)),
            Ok(Some(body)) if &*body == b"body"
        );
        assert_poll_matches!(|cx| to_bytes(stream.poll_data(cx)), Ok(None));
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
        let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));

        assert_poll_matches!(
            |cx| stream.poll_next(cx),
            Ok(Some(Frame::Data(PayloadLen(4))))
        );
        assert_poll_matches!(
            |cx| to_bytes(stream.poll_data(cx)),
            Ok(Some(b)) if &*b == b"body"
        );
    }

    #[tokio::test]
    async fn poll_data_eos_but_buffered_data() {
        let mut recv = FakeRecv::default();
        let mut buf = BytesMut::with_capacity(64);

        FrameType::DATA.encode(&mut buf);
        VarInt::from(4u32).encode(&mut buf);
        buf.put_slice(&b"bo"[..]);
        recv.chunk(buf.clone().freeze());

        let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));

        assert_poll_matches!(
            |cx| stream.poll_next(cx),
            Ok(Some(Frame::Data(PayloadLen(4))))
        );

        buf.truncate(0);
        buf.put_slice(&b"dy"[..]);
        stream.stream.buf_mut().push_bytes(&mut buf.freeze());

        assert_poll_matches!(
            |cx| to_bytes(stream.poll_data(cx)),
            Ok(Some(b)) if &*b == b"bo"
        );

        assert_poll_matches!(
            |cx| to_bytes(stream.poll_data(cx)),
            Ok(Some(b)) if &*b == b"dy"
        );
    }

    #[tokio::test]
    async fn poll_next_consumes_buffered_frame_before_reading_more() {
        let mut recv = FakeRecv::default();
        let reads = recv.reads();
        let mut buf = BytesMut::with_capacity(64);

        Frame::headers(&b"header"[..]).encode_with_payload(&mut buf);
        Frame::headers(&b"trailer"[..]).encode_with_payload(&mut buf);
        recv.chunk(buf.freeze());
        recv.chunk(Bytes::from_static(b"unused"));

        let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));

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

        let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));
        assert_poll_matches!(|cx| stream.poll_next_frame(cx), Ok(Some(Frames::Headers)));
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
    async fn streaming_prefixes_accept_split_nonminimal_varints() {
        for ty in [0u8, 1] {
            // Both type and length use legal two-byte encodings. Splitting
            // either integer must leave the prefix intact until it is complete.
            let prefix = [0x40, ty, 0x40, 4];
            for split in 1..prefix.len() {
                let mut recv = FakeRecv::default();
                recv.chunk(Bytes::copy_from_slice(&prefix[..split]))
                    .pending_when_empty();
                let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));
                // The encoded field-section budget must not limit DATA.
                stream.set_max_field_section_size(if ty == 0 { 0 } else { 4 });
                let mut cx = Context::from_waker(futures_util::task::noop_waker_ref());
                assert!(matches!(stream.poll_next_frame(&mut cx), Poll::Pending));
                assert_eq!(stream.stream.buf().remaining(), split);

                let mut rest = BytesMut::from(&prefix[split..]);
                rest.put_slice(b"body");
                Frame::headers(Bytes::new()).encode_with_payload(&mut rest);
                stream.stream.buf_mut().push(rest.freeze());
                match ty {
                    0 => {
                        assert_poll_matches!(
                            |cx| stream.poll_next_frame(cx),
                            Ok(Some(Frames::Frame(Frame::Data(PayloadLen(4)))))
                        );
                    }
                    _ => {
                        assert_poll_matches!(
                            |cx| stream.poll_next_frame(cx),
                            Ok(Some(Frames::Headers))
                        );
                    }
                }
                assert_poll_matches!(
                    |cx| to_bytes(stream.poll_data_chunk(cx, usize::MAX)),
                    Ok(Some(bytes)) if bytes == b"body"[..]
                );
                assert_poll_matches!(|cx| stream.poll_next_frame(cx), Ok(Some(Frames::Headers)));
            }
        }
    }

    #[tokio::test]
    async fn buffered_headers_keep_the_next_frame_and_do_not_read_quic() {
        for payload in [&b""[..], &b"headers"[..]] {
            let mut recv = FakeRecv::default();
            let reads = recv.reads();
            let mut encoded = BytesMut::new();
            Frame::headers(payload).encode_with_payload(&mut encoded);
            Frame::Data(Bytes::from_static(b"body")).encode_with_payload(&mut encoded);
            recv.chunk(encoded.freeze());

            let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));
            stream.set_max_field_section_size(payload.len());
            assert_poll_matches!(|cx| stream.poll_next_frame(cx), Ok(Some(Frames::Headers)));
            assert_eq!(reads.load(Ordering::Relaxed), 1);
            if !payload.is_empty() {
                assert!(stream.take_buffered_payload(payload.len() - 1).is_none());
                assert!(stream.has_data());
            }
            assert_eq!(
                stream.take_buffered_payload(payload.len()).unwrap(),
                payload
            );
            assert!(!stream.has_data());
            assert_eq!(reads.load(Ordering::Relaxed), 1);
            assert_poll_matches!(
                |cx| stream.poll_next_frame(cx),
                Ok(Some(Frames::Frame(Frame::Data(PayloadLen(4)))))
            );
            assert_poll_matches!(
                |cx| to_bytes(stream.poll_data(cx)),
                Ok(Some(bytes)) if bytes == b"body"[..]
            );
        }
    }

    #[tokio::test]
    async fn fragmented_headers_are_left_for_incremental_reads() {
        let mut recv = FakeRecv::default();
        let reads = recv.reads();
        let mut encoded = BytesMut::new();
        Frame::headers(&b"headers"[..]).encode_with_payload(&mut encoded);
        recv.chunk(encoded.split_to(encoded.len() - 3).freeze());
        recv.chunk(encoded.freeze());

        let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));
        assert_poll_matches!(|cx| stream.poll_next_frame(cx), Ok(Some(Frames::Headers)));
        assert!(stream.take_buffered_payload(7).is_none());
        assert_eq!(reads.load(Ordering::Relaxed), 1);
        assert_poll_matches!(
            |cx| to_bytes(stream.poll_data_chunk(cx, 7)),
            Ok(Some(bytes)) if bytes == b"head"[..]
        );
        assert_poll_matches!(
            |cx| to_bytes(stream.poll_data_chunk(cx, 7)),
            Ok(Some(bytes)) if bytes == b"ers"[..]
        );
        assert!(!stream.has_data());
    }

    #[tokio::test]
    async fn maximum_data_length_still_rejects_early_fin() {
        let mut recv = FakeRecv::default();
        let mut encoded = BytesMut::new();
        FrameType::DATA.encode(&mut encoded);
        let max_len = u64::try_from(usize::MAX)
            .unwrap_or(u64::MAX)
            .min(VarInt::MAX.0);
        VarInt::try_from(max_len).unwrap().encode(&mut encoded);
        recv.chunk(encoded.freeze());

        let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));
        assert_poll_matches!(
            |cx| stream.poll_next_frame(cx),
            Ok(Some(Frames::Frame(Frame::Data(PayloadLen(len))))) if len as u64 == max_len
        );
        assert_poll_matches!(
            |cx| to_bytes(stream.poll_data(cx)),
            Err(FrameStreamError::UnexpectedEnd)
        );
    }

    #[tokio::test]
    async fn request_headers_payload_reports_zero_byte_truncation() {
        let mut recv = FakeRecv::default();
        let mut encoded = BytesMut::new();
        FrameType::HEADERS.encode(&mut encoded);
        VarInt::from(4u32).encode(&mut encoded);
        recv.chunk(encoded.freeze());

        let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));
        assert_poll_matches!(|cx| stream.poll_next_frame(cx), Ok(Some(Frames::Headers)));
        assert_poll_matches!(
            |cx| to_bytes(stream.poll_data_chunk(cx, 4)),
            Err(FrameStreamError::UnexpectedEnd)
        );
    }

    #[tokio::test]
    async fn unknown_frame_is_discarded_before_incremental_headers() {
        use crate::proto::varint::BufMutExt as _;

        let mut recv = FakeRecv::default();
        let reads = recv.reads();

        let mut first = BytesMut::new();
        FrameType::RESERVED.encode(&mut first);
        first.write_var(6);
        first.put_slice(b"gre");
        recv.chunk(first.freeze());

        let mut second = BytesMut::new();
        second.put_slice(b"ase");
        FrameType::HEADERS.encode(&mut second);
        second.write_var(6);
        second.put_slice(b"hea");
        recv.chunk(second.freeze());

        let mut third = BytesMut::new();
        third.put_slice(b"der");
        Frame::Data(Bytes::from_static(b"body")).encode_with_payload(&mut third);
        recv.chunk(third.freeze());

        let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));
        assert_poll_matches!(|cx| stream.poll_next_frame(cx), Ok(Some(Frames::Headers)));
        assert_eq!(reads.load(Ordering::Relaxed), 2);
        assert_poll_matches!(
            |cx| to_bytes(stream.poll_data_chunk(cx, 3)),
            Ok(Some(bytes)) if bytes == b"hea"[..]
        );
        assert_poll_matches!(
            |cx| to_bytes(stream.poll_data_chunk(cx, 3)),
            Ok(Some(bytes)) if bytes == b"der"[..]
        );
        assert_poll_matches!(
            |cx| stream.poll_next_frame(cx),
            Ok(Some(Frames::Frame(Frame::Data(PayloadLen(4)))))
        );
        assert_poll_matches!(
            |cx| to_bytes(stream.poll_data(cx)),
            Ok(Some(bytes)) if bytes == b"body"[..]
        );
    }

    #[tokio::test]
    async fn unknown_payload_cannot_be_mistaken_for_headers() {
        use crate::proto::varint::BufMutExt as _;

        let mut recv = FakeRecv::default();
        let mut prefix = BytesMut::new();
        FrameType::RESERVED.encode(&mut prefix);
        prefix.write_var(2);
        recv.chunk(prefix.freeze());

        let mut payload_and_headers = BytesMut::new();
        // These are payload bytes of the unknown frame, not an empty HEADERS
        // frame. The next HEADERS frame is the one the caller must observe.
        FrameType::HEADERS.encode(&mut payload_and_headers);
        payload_and_headers.write_var(0);
        Frame::headers(Bytes::from_static(b"ok")).encode_with_payload(&mut payload_and_headers);
        recv.chunk(payload_and_headers.freeze());

        let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));
        assert_poll_matches!(|cx| stream.poll_next_frame(cx), Ok(Some(Frames::Headers)));
        assert_poll_matches!(
            |cx| to_bytes(stream.poll_data_chunk(cx, 2)),
            Ok(Some(bytes)) if bytes == b"ok"[..]
        );
    }

    #[tokio::test]
    async fn truncated_unknown_frame_is_rejected_after_prefix_is_consumed() {
        use crate::proto::varint::BufMutExt as _;

        let mut recv = FakeRecv::default();
        let mut encoded = BytesMut::new();
        FrameType::RESERVED.encode(&mut encoded);
        encoded.write_var(6);
        encoded.put_slice(b"gre");
        recv.chunk(encoded.freeze());

        let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));
        assert_poll_matches!(
            |cx| stream.poll_next_frame(cx),
            Err(FrameStreamError::UnexpectedEnd)
        );
    }

    // Helpers

    #[derive(Default)]
    struct FakeRecv {
        chunks: VecDeque<Bytes>,
        reads: Arc<AtomicUsize>,
        pending_when_empty: bool,
    }

    impl FakeRecv {
        fn chunk(&mut self, buf: Bytes) -> &mut Self {
            self.chunks.push_back(buf);
            self
        }

        fn reads(&self) -> Arc<AtomicUsize> {
            self.reads.clone()
        }

        fn pending_when_empty(&mut self) -> &mut Self {
            self.pending_when_empty = true;
            self
        }
    }

    impl RecvStream for FakeRecv {
        type Buf = Bytes;

        fn poll_data(
            &mut self,
            _: &mut Context<'_>,
        ) -> Poll<Result<Option<Self::Buf>, StreamErrorIncoming>> {
            self.reads.fetch_add(1, Ordering::Relaxed);
            match self.chunks.pop_front() {
                Some(chunk) => Poll::Ready(Ok(Some(chunk))),
                None if self.pending_when_empty => Poll::Pending,
                None => Poll::Ready(Ok(None)),
            }
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
