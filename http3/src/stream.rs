use std::{
    marker::PhantomData,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use futures_util::{future, ready};
use pin_project_lite::pin_project;
use tokio::io::ReadBuf;

use crate::{
    buf::BufList,
    error::{Code, internal_error::InternalConnectionError},
    frame::FrameStream,
    proto::{
        coding::Encode,
        frame::{Frame, FrameHeader, Settings},
        stream::StreamType,
        varint::VarInt,
    },
    quic::{
        self, BidiStream, ConnectionErrorIncoming, RecvStream, SendStream, SendStreamUnframed,
        StreamErrorIncoming,
    },
    webtransport::SessionId,
};

#[inline]
/// Transmits data by encoding in wire format.
pub(crate) async fn write<S, D, B>(stream: &mut S, data: D) -> Result<(), StreamErrorIncoming>
where
    S: SendStream<B>,
    D: Into<WriteBuf<B>>,
    B: Buf,
{
    stream.send_data(data)?;
    future::poll_fn(|cx| stream.poll_ready(cx)).await?;

    Ok(())
}

// SETTINGS is connection-scoped and uses the spill representation below, so
// request streams only carry enough inline storage for a stream type and the
// largest ordinary frame prefix.
const WRITE_BUF_ENCODE_SIZE: usize = StreamType::MAX_ENCODED_SIZE + Frame::MAX_ENCODED_SIZE;

enum EncodedHeader {
    Inline([u8; WRITE_BUF_ENCODE_SIZE]),
    Heap(Bytes),
}

/// Wrap frames to encode their header inline before sending them on the wire.
/// Connection-scoped SETTINGS uses growable storage when it exceeds the inline prefix.
///
/// Implements `Buf` so wire data is seamlessly available for transport layer transmits:
/// `Buf::chunk()` will yield the encoded header, then the payload. For unidirectional streams,
/// this type makes it possible to prefix wire data with the `StreamType`.
///
/// Conveying frames as `Into<WriteBuf>` makes it possible to encode only when generating
/// wire-format data is necessary (say, in `quic::SendStream::send_data`). It also has a public API
/// ergonomy advantage: `WriteBuf` doesn't have to appear in public associated types. On the other
/// hand, QUIC implementers have to call `into()`, which will encode the header in `Self::buf`.
pub struct WriteBuf<B> {
    buf: EncodedHeader,
    len: usize,
    pos: usize,
    frame: Option<Frame<B>>,
}

impl<B> WriteBuf<B>
where
    B: Buf,
{
    fn inline(frame: Option<Frame<B>>) -> Self {
        Self {
            buf: EncodedHeader::Inline([0; WRITE_BUF_ENCODE_SIZE]),
            len: 0,
            pos: 0,
            frame,
        }
    }

    fn heap(encoded: Bytes, frame: Option<Frame<B>>) -> Self {
        Self {
            len: encoded.len(),
            buf: EncodedHeader::Heap(encoded),
            pos: 0,
            frame,
        }
    }

    fn encode_heap(value: &impl Encode, capacity: usize) -> Bytes {
        let mut encoded = BytesMut::with_capacity(capacity);
        value.encode(&mut encoded);
        encoded.freeze()
    }

    fn encode_stream_type(&mut self, ty: StreamType) {
        self.encode_value(&ty);
    }

    fn encode_value(&mut self, value: &impl Encode) {
        match &mut self.buf {
            EncodedHeader::Inline(buf) => {
                let tail = &mut buf[self.len..];
                let initial = tail.remaining_mut();
                let mut buf_mut = tail;
                value.encode(&mut buf_mut);
                self.len += initial - buf_mut.remaining_mut();
            }
            EncodedHeader::Heap(buf) => {
                let mut encoded = BytesMut::with_capacity(
                    buf.len().saturating_add(VarInt::MAX_SIZE.saturating_mul(3)),
                );
                encoded.extend_from_slice(buf);
                value.encode(&mut encoded);
                self.len = encoded.len();
                *buf = encoded.freeze();
            }
        }
    }

    fn encode_frame_header(&mut self) {
        if let Some(frame) = self.frame.take() {
            match &mut self.buf {
                EncodedHeader::Inline(buf) => {
                    let tail = &mut buf[self.len..];
                    let initial = tail.remaining_mut();
                    let mut buf_mut = tail;
                    Self::encode_frame_prefix(&frame, &mut buf_mut);
                    self.len += initial - buf_mut.remaining_mut();
                }
                EncodedHeader::Heap(buf) => {
                    let mut encoded = BytesMut::with_capacity(
                        buf.len().saturating_add(VarInt::MAX_SIZE.saturating_mul(3)),
                    );
                    encoded.extend_from_slice(buf);
                    Self::encode_frame_prefix(&frame, &mut encoded);
                    self.len = encoded.len();
                    *buf = encoded.freeze();
                }
            }
            self.frame = Some(frame);
        }
    }

    /// Keeps a small HEADERS frame in one contiguous chunk. Quinn otherwise
    /// observes the frame prefix and QPACK block as two writes, each requiring
    /// a separate trip through its send-stream state.
    fn coalesce_small_headers(&mut self) {
        let Self {
            buf: EncodedHeader::Inline(buf),
            len,
            frame: Some(Frame::Headers(payload)),
            ..
        } = self
        else {
            return;
        };

        let payload_len = payload.remaining();
        let Some(end) = len.checked_add(payload_len) else {
            return;
        };
        if end > WRITE_BUF_ENCODE_SIZE || payload.chunk().len() < payload_len {
            return;
        }

        buf[*len..end].copy_from_slice(&payload.chunk()[..payload_len]);
        *len = end;
        payload.advance(payload_len);
    }

    fn encode_frame_prefix<T: BufMut>(frame: &Frame<B>, buf: &mut T) {
        match frame {
            // PUSH_PROMISE carries a separately streamed QPACK field section.
            // Only its frame header and Push ID belong in the prefix.
            Frame::PushPromise(push) => push.encode_header(buf),
            _ => frame.encode(buf),
        }
    }
}

impl<B> From<StreamType> for WriteBuf<B>
where
    B: Buf,
{
    fn from(ty: StreamType) -> Self {
        let mut me = Self::inline(None);
        me.encode_stream_type(ty);
        me
    }
}

impl<B> From<UniStreamHeader> for WriteBuf<B>
where
    B: Buf,
{
    fn from(header: UniStreamHeader) -> Self {
        match header {
            UniStreamHeader::Control(settings) => {
                let capacity = settings
                    .len()
                    .saturating_add(VarInt::MAX_SIZE.saturating_mul(3));
                let header = UniStreamHeader::Control(settings);
                let encoded = Self::encode_heap(&header, capacity);
                Self::heap(encoded, None)
            }
            header => {
                let mut this = Self::inline(None);
                this.encode_value(&header);
                this
            }
        }
    }
}

#[allow(clippy::large_enum_variant)]
pub enum UniStreamHeader {
    Control(Settings),
    WebTransportUni(SessionId),
    Encoder,
    Decoder,
}

impl Encode for UniStreamHeader {
    fn encode<B: BufMut>(&self, buf: &mut B) {
        match self {
            Self::Control(settings) => {
                StreamType::CONTROL.encode(buf);
                settings.encode(buf);
            }
            Self::WebTransportUni(session_id) => {
                StreamType::WEBTRANSPORT_UNI.encode(buf);
                session_id.encode(buf);
            }
            UniStreamHeader::Encoder => {
                StreamType::ENCODER.encode(buf);
            }
            UniStreamHeader::Decoder => {
                StreamType::DECODER.encode(buf);
            }
        }
    }
}

impl<B> From<BidiStreamHeader> for WriteBuf<B>
where
    B: Buf,
{
    fn from(header: BidiStreamHeader) -> Self {
        let mut this = Self::inline(None);

        this.encode_value(&header);
        this
    }
}

pub enum BidiStreamHeader {
    WebTransportBidi(SessionId),
}

impl Encode for BidiStreamHeader {
    fn encode<B: BufMut>(&self, buf: &mut B) {
        match self {
            Self::WebTransportBidi(session_id) => {
                StreamType::WEBTRANSPORT_BIDI.encode(buf);
                session_id.encode(buf);
            }
        }
    }
}

impl<B> From<Frame<B>> for WriteBuf<B>
where
    B: Buf,
{
    fn from(frame: Frame<B>) -> Self {
        if let Frame::Settings(settings) = &frame {
            let capacity = settings
                .len()
                .saturating_add(VarInt::MAX_SIZE.saturating_mul(2));
            let encoded = Self::encode_heap(&frame, capacity);
            Self::heap(encoded, None)
        } else {
            let mut this = Self::inline(Some(frame));
            this.encode_frame_header();
            this.coalesce_small_headers();
            this
        }
    }
}

impl<B> From<(StreamType, Frame<B>)> for WriteBuf<B>
where
    B: Buf,
{
    fn from(ty_stream: (StreamType, Frame<B>)) -> Self {
        let (ty, frame) = ty_stream;
        if let Frame::Settings(settings) = &frame {
            let capacity = settings
                .len()
                .saturating_add(VarInt::MAX_SIZE.saturating_mul(3));
            let mut encoded = BytesMut::with_capacity(capacity);
            ty.encode(&mut encoded);
            frame.encode(&mut encoded);
            Self::heap(encoded.freeze(), None)
        } else {
            let mut this = Self::inline(Some(frame));
            this.encode_value(&ty);
            this.encode_frame_header();
            this.coalesce_small_headers();
            this
        }
    }
}

impl<B> Buf for WriteBuf<B>
where
    B: Buf,
{
    fn remaining(&self) -> usize {
        self.len - self.pos
            + self
                .frame
                .as_ref()
                .and_then(|f| f.payload())
                .map_or(0, |x| x.remaining())
    }

    fn chunk(&self) -> &[u8] {
        if self.len - self.pos > 0 {
            match &self.buf {
                EncodedHeader::Inline(buf) => &buf[self.pos..self.len],
                EncodedHeader::Heap(buf) => &buf[self.pos..self.len],
            }
        } else if let Some(payload) = self.frame.as_ref().and_then(|f| f.payload()) {
            payload.chunk()
        } else {
            &[]
        }
    }

    fn advance(&mut self, mut cnt: usize) {
        let remaining_header = self.len - self.pos;
        if remaining_header > 0 {
            let advanced = usize::min(cnt, remaining_header);
            self.pos += advanced;
            cnt -= advanced;
        }

        if let Some(payload) = self.frame.as_mut().and_then(|f| f.payload_mut()) {
            payload.advance(cnt);
        }
    }
}

pub(super) enum AcceptedRecvStream<S, B>
where
    S: quic::RecvStream,
    B: Buf,
{
    Control(FrameStream<S, B>),
    Push(FrameStream<S, B>),
    Encoder(BufRecvStream<S, B>),
    Decoder(BufRecvStream<S, B>),
    WebTransportUni(SessionId, BufRecvStream<S, B>),
    Unknown(BufRecvStream<S, B>),
}

/// Resolves an incoming streams type as well as `PUSH_ID`s and `SESSION_ID`s
pub(super) struct AcceptRecvStream<S, B> {
    stream: BufRecvStream<S, B>,
    ty: Option<StreamType>,
    /// push_id or session_id
    id: Option<VarInt>,
    expected: Option<usize>,
}

impl<S, B> AcceptRecvStream<S, B>
where
    S: RecvStream,
    B: Buf,
{
    pub fn new(stream: S) -> Self {
        Self {
            stream: BufRecvStream::new(stream),
            ty: None,
            id: None,
            expected: None,
        }
    }

    pub fn into_stream(self) -> AcceptedRecvStream<S, B> {
        match self.ty.expect("Stream type not resolved yet") {
            StreamType::CONTROL => AcceptedRecvStream::Control(FrameStream::new(self.stream)),
            StreamType::PUSH => AcceptedRecvStream::Push(FrameStream::new(self.stream)),
            StreamType::ENCODER => AcceptedRecvStream::Encoder(self.stream),
            StreamType::DECODER => AcceptedRecvStream::Decoder(self.stream),
            StreamType::WEBTRANSPORT_UNI => AcceptedRecvStream::WebTransportUni(
                SessionId::from_varint(self.id.expect("Session ID not resolved yet")),
                self.stream,
            ),
            _ => AcceptedRecvStream::Unknown(self.stream),
        }
    }

    // helper function to poll the next VarInt from self.stream
    fn poll_next_varint(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(VarInt, Option<StreamEnd>), PollTypeError>> {
        // Flag if the stream was reset or finished by the peer
        let mut stream_stopped = None;

        loop {
            if stream_stopped.is_some() {
                return Poll::Ready(Err(PollTypeError::EndOfStream));
            }
            //= https://www.rfc-editor.org/rfc/rfc9114#section-6.2
            //# A receiver MUST tolerate unidirectional streams being
            //# closed or reset prior to the reception of the unidirectional stream
            //# header.
            stream_stopped = match ready!(self.stream.poll_read(cx)) {
                Ok(false) => None,
                Ok(true) => Some(StreamEnd::EndOfStream),
                Err(StreamErrorIncoming::ConnectionErrorIncoming { connection_error }) => {
                    return Poll::Ready(Err(PollTypeError::IncomingError(connection_error)));
                }
                Err(StreamErrorIncoming::StreamTerminated { error_code }) => {
                    Some(StreamEnd::Reset(error_code))
                }
                Err(StreamErrorIncoming::Unknown(_err)) => {
                    #[cfg(feature = "tracing")]
                    tracing::error!("Unknown error when reading stream {}", _err);

                    Some(StreamEnd::Other)
                }
            };

            let mut buf = self.stream.buf_mut();
            if self.expected.is_none() && buf.remaining() >= 1 {
                self.expected = Some(VarInt::encoded_size(buf.chunk()[0]));
            }

            if let Some(expected) = self.expected {
                if buf.remaining() < expected {
                    continue;
                }
            } else {
                continue;
            }

            let reult = VarInt::decode(&mut buf).map_err(|_| {
                PollTypeError::InternalError(InternalConnectionError::new(
                    Code::H3_INTERNAL_ERROR,
                    "Unexpected end parsing varint".to_string(),
                ))
            })?;

            return Poll::Ready(Ok((reult, stream_stopped)));
        }
    }

    pub fn poll_type(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), PollTypeError>> {
        // If we haven't parsed the stream type yet
        if self.ty.is_none() {
            // TODO create a test for the StreamEnd Option
            // If the stream ended or reset directly after the type was received
            // can we poll data again?
            let (var, _) = ready!(self.poll_next_varint(cx))?;
            let ty = StreamType::from_value(var.0);
            self.ty = Some(ty);
        }

        // If the type requires a second VarInt (PUSH or WEBTRANSPORT_UNI)
        if matches!(
            self.ty,
            Some(StreamType::PUSH | StreamType::WEBTRANSPORT_UNI)
        ) && self.id.is_none()
        {
            let (var, _) = ready!(self.poll_next_varint(cx))?;
            self.id = Some(var);
        }

        Poll::Ready(Ok(()))
    }
}

enum StreamEnd {
    EndOfStream,
    #[allow(dead_code)]
    Reset(u64),
    // if the quic layer returns an unknown error
    Other,
}

pub(super) enum PollTypeError {
    IncomingError(ConnectionErrorIncoming),
    InternalError(InternalConnectionError),
    // Stream stopped with eos or reset.
    // No Code is received
    EndOfStream,
}

pin_project! {
    /// A stream which allows partial reading of the data without data loss.
    ///
    /// This fixes the problem where `poll_data` returns more than the needed amount of bytes,
    /// requiring correct implementations to hold on to that extra data and return it later.
    ///
    /// # Usage
    ///
    /// Implements `quic::RecvStream` which will first return buffered data, and then read from the
    /// stream
    pub struct BufRecvStream<S, B> {
        buf: BufList<Bytes>,
        // Indicates that the end of the stream has been reached
        //
        // Data may still be available as buffered
        eos: bool,
        stream: S,
        _marker: PhantomData<B>,
    }
}

impl<S, B> std::fmt::Debug for BufRecvStream<S, B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BufRecvStream")
            .field("buf", &self.buf)
            .field("eos", &self.eos)
            .field("stream", &"...")
            .finish()
    }
}

impl<S, B> BufRecvStream<S, B> {
    pub fn new(stream: S) -> Self {
        Self {
            buf: BufList::new(),
            eos: false,
            stream,
            _marker: PhantomData,
        }
    }
}

impl<S, B> BufRecvStream<S, B>
where
    S: crate::quic::Is0rtt,
{
    /// Checks if the stream was opened in 0-RTT mode
    pub(crate) fn is_0rtt(&self) -> bool {
        self.stream.is_0rtt()
    }
}

impl<B, S: RecvStream> BufRecvStream<S, B> {
    /// Reads more data into the buffer, returning the number of bytes read.
    ///
    /// Returns `true` if the end of the stream is reached.
    pub fn poll_read(&mut self, cx: &mut Context<'_>) -> Poll<Result<bool, StreamErrorIncoming>> {
        let data = ready!(self.stream.poll_data(cx))?;

        if let Some(mut data) = data {
            self.buf.push_bytes(&mut data);
            Poll::Ready(Ok(false))
        } else {
            self.eos = true;
            Poll::Ready(Ok(true))
        }
    }

    /// Returns the currently buffered data, allowing it to be partially read
    #[inline]
    pub(crate) fn buf_mut(&mut self) -> &mut BufList<Bytes> {
        &mut self.buf
    }

    /// Returns the next chunk of data from the stream
    ///
    /// Return `None` when there is no more buffered data; use [`Self::poll_read`].
    pub fn take_chunk(&mut self, limit: usize) -> Option<Bytes> {
        self.buf.take_chunk(limit)
    }

    /// Returns true if there is remaining buffered data
    pub fn has_remaining(&mut self) -> bool {
        self.buf.has_remaining()
    }

    #[inline]
    pub(crate) fn buf(&self) -> &BufList<Bytes> {
        &self.buf
    }

    pub fn is_eos(&self) -> bool {
        self.eos
    }
}

impl<S: RecvStream, B> RecvStream for BufRecvStream<S, B> {
    type Buf = Bytes;

    fn poll_data(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<Option<Self::Buf>, StreamErrorIncoming>> {
        // There is data buffered, return that immediately
        if let Some(chunk) = self.buf.take_first_chunk() {
            return Poll::Ready(Ok(Some(chunk)));
        }

        if let Some(mut data) = ready!(self.stream.poll_data(cx))? {
            Poll::Ready(Ok(Some(data.copy_to_bytes(data.remaining()))))
        } else {
            self.eos = true;
            Poll::Ready(Ok(None))
        }
    }

    fn stop_sending(&mut self, error_code: u64) {
        self.stream.stop_sending(error_code)
    }

    fn recv_id(&self) -> quic::StreamId {
        self.stream.recv_id()
    }
}

impl<S, B> SendStream<B> for BufRecvStream<S, B>
where
    B: Buf,
    S: SendStream<B>,
{
    fn poll_finish(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), StreamErrorIncoming>> {
        self.stream.poll_finish(cx)
    }

    fn reset(&mut self, reset_code: u64) {
        self.stream.reset(reset_code)
    }

    fn send_id(&self) -> quic::StreamId {
        self.stream.send_id()
    }

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), StreamErrorIncoming>> {
        self.stream.poll_ready(cx)
    }

    fn send_data<T: Into<WriteBuf<B>>>(&mut self, data: T) -> Result<(), StreamErrorIncoming> {
        self.stream.send_data(data)
    }
}

impl<S, B> SendStreamUnframed<B> for BufRecvStream<S, B>
where
    B: Buf,
    S: SendStreamUnframed<B>,
{
    #[inline]
    fn poll_send<D: Buf>(
        &mut self,
        cx: &mut std::task::Context<'_>,
        buf: &mut D,
    ) -> Poll<Result<usize, StreamErrorIncoming>> {
        self.stream.poll_send(cx, buf)
    }
}

impl<S, B> BidiStream<B> for BufRecvStream<S, B>
where
    B: Buf,
    S: BidiStream<B>,
{
    type SendStream = BufRecvStream<S::SendStream, B>;

    type RecvStream = BufRecvStream<S::RecvStream, B>;

    fn split(self) -> (Self::SendStream, Self::RecvStream) {
        let (send, recv) = self.stream.split();
        (
            BufRecvStream {
                // Sending is not buffered
                buf: BufList::new(),
                eos: self.eos,
                stream: send,
                _marker: PhantomData,
            },
            BufRecvStream {
                buf: self.buf,
                eos: self.eos,
                stream: recv,
                _marker: PhantomData,
            },
        )
    }
}

impl<S, B> futures_util::io::AsyncRead for BufRecvStream<S, B>
where
    B: Buf,
    S: RecvStream,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<futures_util::io::Result<usize>> {
        let p = &mut *self;
        // Poll for data if the buffer is empty
        //
        // If there is data available *do not* poll for more data, as that may suspend indefinitely
        // if no more data is sent, causing data loss.
        if !p.has_remaining() {
            let eos = ready!(p.poll_read(cx).map_err(convert_to_std_io_error))?;
            if eos {
                return Poll::Ready(Ok(0));
            }
        }

        let chunk = p.buf_mut().take_chunk(buf.len());
        if let Some(chunk) = chunk {
            assert!(chunk.len() <= buf.len());
            let len = chunk.len().min(buf.len());
            // Write the subset into the destination
            buf[..len].copy_from_slice(&chunk);
            Poll::Ready(Ok(len))
        } else {
            Poll::Ready(Ok(0))
        }
    }
}

impl<S, B> tokio::io::AsyncRead for BufRecvStream<S, B>
where
    B: Buf,
    S: RecvStream,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<futures_util::io::Result<()>> {
        let p = &mut *self;
        // Poll for data if the buffer is empty
        //
        // If there is data available *do not* poll for more data, as that may suspend indefinitely
        // if no more data is sent, causing data loss.
        if !p.has_remaining() {
            let eos = ready!(p.poll_read(cx).map_err(convert_to_std_io_error))?;
            if eos {
                return Poll::Ready(Ok(()));
            }
        }

        let chunk = p.buf_mut().take_chunk(buf.remaining());
        if let Some(chunk) = chunk {
            assert!(chunk.len() <= buf.remaining());
            // Write the subset into the destination
            buf.put_slice(&chunk);
            Poll::Ready(Ok(()))
        } else {
            Poll::Ready(Ok(()))
        }
    }
}

impl<S, B> futures_util::io::AsyncWrite for BufRecvStream<S, B>
where
    B: Buf,
    S: SendStreamUnframed<B>,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let p = &mut *self;
        p.poll_send(cx, &mut buf).map_err(convert_to_std_io_error)
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let p = &mut *self;
        p.poll_finish(cx).map_err(convert_to_std_io_error)
    }
}

impl<S, B> tokio::io::AsyncWrite for BufRecvStream<S, B>
where
    B: Buf,
    S: SendStreamUnframed<B>,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let p = &mut *self;
        p.poll_send(cx, &mut buf).map_err(convert_to_std_io_error)
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let p = &mut *self;
        p.poll_finish(cx).map_err(convert_to_std_io_error)
    }
}

fn convert_to_std_io_error(error: StreamErrorIncoming) -> std::io::Error {
    std::io::Error::other(error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{coding::BufExt, frame::SettingId, push::PushId};

    fn large_settings() -> Settings {
        let mut settings = Settings::default();
        for index in 0..32 {
            settings
                .insert(SettingId(0x21 + 0x1f * index), index)
                .unwrap();
        }
        settings
    }

    #[test]
    fn write_wt_uni_header() {
        let mut w = WriteBuf::<Bytes>::from(UniStreamHeader::WebTransportUni(
            SessionId::from_varint(VarInt(5)),
        ));

        let ty = w.get_var().unwrap();
        println!("Got type: {ty} {ty:#x}");
        assert_eq!(ty, 0x54);

        let id = w.get_var().unwrap();
        println!("Got id: {id}");
    }

    #[test]
    fn write_buf_encode_streamtype() {
        let wbuf = WriteBuf::<Bytes>::from(StreamType::ENCODER);

        assert_eq!(wbuf.chunk(), b"\x02");
        assert_eq!(wbuf.len, 1);
    }

    #[test]
    fn write_buf_encode_frame() {
        let wbuf = WriteBuf::<Bytes>::from(Frame::Goaway(VarInt(2)));

        assert_eq!(wbuf.chunk(), b"\x07\x01\x02");
        assert_eq!(wbuf.len, 3);
    }

    #[test]
    fn write_buf_encode_streamtype_then_frame() {
        let wbuf = WriteBuf::<Bytes>::from((StreamType::ENCODER, Frame::Goaway(VarInt(2))));

        assert_eq!(wbuf.chunk(), b"\x02\x07\x01\x02");
    }

    #[test]
    fn write_buf_spills_large_settings() {
        let mut expected = BytesMut::new();
        UniStreamHeader::Control(large_settings()).encode(&mut expected);

        let mut wbuf = WriteBuf::<Bytes>::from(UniStreamHeader::Control(large_settings()));
        assert!(wbuf.len > WRITE_BUF_ENCODE_SIZE);
        let mut encoded = wbuf.copy_to_bytes(wbuf.remaining());
        assert_eq!(encoded.as_ref(), expected.as_ref());

        assert_eq!(encoded.get_var().unwrap(), 0);
        assert!(matches!(
            Frame::<crate::proto::frame::PayloadLen>::decode(&mut encoded),
            Ok(Frame::Settings(_))
        ));
        assert!(!encoded.has_remaining());
    }

    #[test]
    fn write_buf_spills_large_settings_after_stream_type() {
        let mut expected = BytesMut::new();
        StreamType::CONTROL.encode(&mut expected);
        Frame::<Bytes>::Settings(large_settings()).encode(&mut expected);

        let mut wbuf =
            WriteBuf::<Bytes>::from((StreamType::CONTROL, Frame::Settings(large_settings())));
        assert!(wbuf.len > WRITE_BUF_ENCODE_SIZE);
        let mut encoded = wbuf.copy_to_bytes(wbuf.remaining());
        assert_eq!(encoded.as_ref(), expected.as_ref());

        assert_eq!(encoded.get_var().unwrap(), 0);
        assert!(matches!(
            Frame::<crate::proto::frame::PayloadLen>::decode(&mut encoded),
            Ok(Frame::Settings(_))
        ));
        assert!(!encoded.has_remaining());
    }

    #[test]
    fn every_non_settings_frame_prefix_fits_inline_storage() {
        fn assert_inline(frame: Frame<Bytes>) {
            match &frame {
                Frame::Settings(_) => panic!("SETTINGS must use heap storage"),
                Frame::Data(_)
                | Frame::Headers(_)
                | Frame::CancelPush(_)
                | Frame::PushPromise(_)
                | Frame::Goaway(_)
                | Frame::MaxPushId(_)
                | Frame::WebTransportStream(_)
                | Frame::Grease => {}
            }

            let wbuf = WriteBuf::from(frame);
            assert!(matches!(&wbuf.buf, EncodedHeader::Inline(_)));
            assert!(wbuf.len <= WRITE_BUF_ENCODE_SIZE);
        }

        assert_inline(Frame::Data(Bytes::from_static(b"data")));
        assert_inline(Frame::Headers(Bytes::from_static(b"headers")));
        assert_inline(Frame::CancelPush(
            PushId::try_from(VarInt::MAX.into_inner()).unwrap(),
        ));
        assert_inline(Frame::Goaway(VarInt::MAX));
        assert_inline(Frame::MaxPushId(
            PushId::try_from(VarInt::MAX.into_inner()).unwrap(),
        ));
        assert_inline(Frame::WebTransportStream(SessionId::from_varint(
            VarInt::MAX,
        )));
        assert_inline(Frame::Grease);
    }

    #[test]
    fn small_headers_are_one_inline_chunk() {
        let payload = Bytes::from_static(b"small qpack block");
        let payload_len = payload.len();
        let mut expected = BytesMut::new();
        Frame::<Bytes>::Headers(payload.clone()).encode_with_payload(&mut expected);

        let mut write_buf = WriteBuf::from(Frame::<Bytes>::Headers(payload));

        assert!(matches!(&write_buf.buf, EncodedHeader::Inline(_)));
        assert_eq!(write_buf.chunk(), expected.as_ref());
        assert_eq!(write_buf.remaining(), expected.len());
        assert_eq!(
            write_buf
                .frame
                .as_ref()
                .and_then(Frame::payload)
                .map(Buf::remaining),
            Some(0)
        );

        let prefix_len = expected.len() - payload_len;
        write_buf.advance(1);
        assert_eq!(write_buf.chunk(), &expected[1..]);
        assert_eq!(write_buf.remaining(), expected.len() - 1);

        write_buf.advance(prefix_len - 1);
        assert_eq!(write_buf.chunk(), &expected[prefix_len..]);
        assert_eq!(write_buf.remaining(), payload_len);

        write_buf.advance(3);
        assert_eq!(write_buf.chunk(), &expected[prefix_len + 3..]);
        assert_eq!(write_buf.remaining(), payload_len - 3);

        write_buf.advance(payload_len - 3);
        assert_eq!(write_buf.remaining(), 0);
        assert!(write_buf.chunk().is_empty());
    }

    #[test]
    fn large_headers_keep_their_separate_payload() {
        let payload = Bytes::from(vec![0x5a; WRITE_BUF_ENCODE_SIZE]);
        let write_buf = WriteBuf::from(Frame::<Bytes>::Headers(payload.clone()));

        assert!(write_buf.len < WRITE_BUF_ENCODE_SIZE);
        assert_eq!(write_buf.chunk().len(), write_buf.len);
        assert_eq!(
            write_buf
                .frame
                .as_ref()
                .and_then(Frame::payload)
                .map(Buf::remaining),
            Some(payload.len())
        );
        assert_eq!(write_buf.remaining(), write_buf.len + payload.len());
    }

    #[test]
    fn headers_coalescing_respects_the_inline_boundary() {
        let payload = Bytes::from(vec![0x5a; WRITE_BUF_ENCODE_SIZE - 2]);
        let write_buf = WriteBuf::from(Frame::<Bytes>::Headers(payload));
        assert_eq!(write_buf.len, WRITE_BUF_ENCODE_SIZE);
        assert_eq!(write_buf.chunk().len(), WRITE_BUF_ENCODE_SIZE);
        assert_eq!(
            write_buf
                .frame
                .as_ref()
                .and_then(Frame::payload)
                .map(Buf::remaining),
            Some(0)
        );

        let payload = Bytes::from(vec![0x5a; WRITE_BUF_ENCODE_SIZE - 1]);
        let write_buf = WriteBuf::from(Frame::<Bytes>::Headers(payload.clone()));
        assert_eq!(write_buf.chunk().len(), write_buf.len);
        assert_eq!(write_buf.remaining(), WRITE_BUF_ENCODE_SIZE + 1);
        assert_eq!(
            write_buf
                .frame
                .as_ref()
                .and_then(Frame::payload)
                .map(Buf::remaining),
            Some(payload.len())
        );

        let payload = Bytes::from(vec![0x5a; WRITE_BUF_ENCODE_SIZE - 3]);
        let write_buf = WriteBuf::from((StreamType::ENCODER, Frame::<Bytes>::Headers(payload)));
        assert_eq!(write_buf.len, WRITE_BUF_ENCODE_SIZE);
        assert_eq!(write_buf.chunk().len(), WRITE_BUF_ENCODE_SIZE);
        assert_eq!(
            write_buf
                .frame
                .as_ref()
                .and_then(Frame::payload)
                .map(Buf::remaining),
            Some(0)
        );

        let payload = Bytes::from(vec![0x5a; WRITE_BUF_ENCODE_SIZE - 2]);
        let write_buf = WriteBuf::from((
            StreamType::ENCODER,
            Frame::<Bytes>::Headers(payload.clone()),
        ));
        assert_eq!(write_buf.chunk().len(), write_buf.len);
        assert_eq!(write_buf.remaining(), WRITE_BUF_ENCODE_SIZE + 1);
        assert_eq!(
            write_buf
                .frame
                .as_ref()
                .and_then(Frame::payload)
                .map(Buf::remaining),
            Some(payload.len())
        );
    }

    #[cfg(target_pointer_width = "64")]
    #[test]
    fn write_buf_stays_small_on_64_bit_targets() {
        assert!(std::mem::size_of::<WriteBuf<Bytes>>() <= 192);
    }

    #[test]
    fn write_buf_advances() {
        let mut wbuf =
            WriteBuf::<Bytes>::from((StreamType::ENCODER, Frame::Data(Bytes::from("hey"))));

        assert_eq!(wbuf.chunk(), b"\x02\x00\x03");
        wbuf.advance(3);
        assert_eq!(wbuf.remaining(), 3);
        assert_eq!(wbuf.chunk(), b"hey");
        wbuf.advance(2);
        assert_eq!(wbuf.chunk(), b"y");
        wbuf.advance(1);
        assert_eq!(wbuf.remaining(), 0);
    }

    #[test]
    fn write_buf_advance_jumps_header_and_payload_start() {
        let mut wbuf =
            WriteBuf::<Bytes>::from((StreamType::ENCODER, Frame::Data(Bytes::from("hey"))));

        wbuf.advance(4);
        assert_eq!(wbuf.chunk(), b"ey");
    }
}
