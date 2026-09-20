use std::{
    sync::{
        Arc, Barrier,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::{Context, Poll},
};

use bytes::{Buf, Bytes};
use http3::{
    error::Code,
    quic::{self, ConnectionErrorIncoming, StreamErrorIncoming, StreamId, WriteBuf},
};
use interop::{generate_test_certificate, install_crypto_provider};

#[derive(Default)]
pub struct Observation {
    pub bytes: AtomicUsize,
    pub gate: Option<Gate>,
}

pub struct Gate {
    pub entered: Barrier,
    pub release: Barrier,
    once: AtomicBool,
}

impl Gate {
    pub fn new() -> Self {
        Self {
            entered: Barrier::new(2),
            release: Barrier::new(2),
            once: AtomicBool::new(false),
        }
    }
}

pub struct Observed<T> {
    pub inner: T,
    pub observation: Arc<Observation>,
}

impl<T> Observed<T> {
    fn wrap<U>(&self, inner: U) -> Observed<U> {
        Observed {
            inner,
            observation: self.observation.clone(),
        }
    }
}

impl<T: quic::OpenStreams<Bytes>> quic::OpenStreams<Bytes> for Observed<T> {
    type BidiStream = Observed<T::BidiStream>;
    type SendStream = T::SendStream;
    fn poll_open_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, StreamErrorIncoming>> {
        self.inner
            .poll_open_bidi(cx)
            .map(|result| result.map(|inner| self.wrap(inner)))
    }
    fn poll_open_send(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::SendStream, StreamErrorIncoming>> {
        self.inner.poll_open_send(cx)
    }
    fn close(&mut self, code: Code, reason: &[u8]) {
        self.inner.close(code, reason);
    }
}

impl<T: quic::Connection<Bytes>> quic::Connection<Bytes> for Observed<T> {
    type RecvStream = T::RecvStream;
    type OpenStreams = Observed<T::OpenStreams>;
    fn poll_accept_recv(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::RecvStream, ConnectionErrorIncoming>> {
        self.inner.poll_accept_recv(cx)
    }
    fn poll_accept_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, ConnectionErrorIncoming>> {
        self.inner
            .poll_accept_bidi(cx)
            .map(|result| result.map(|inner| self.wrap(inner)))
    }
    fn opener(&self) -> Self::OpenStreams {
        self.wrap(self.inner.opener())
    }
}

impl<T: quic::RecvStream> quic::RecvStream for Observed<T> {
    type Buf = T::Buf;
    fn poll_data(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Self::Buf>, StreamErrorIncoming>> {
        let result = self.inner.poll_data(cx);
        if let Poll::Ready(Ok(Some(data))) = &result {
            self.observation
                .bytes
                .fetch_add(data.remaining(), Ordering::SeqCst);
        }
        result
    }
    fn stop_sending(&mut self, code: u64) {
        self.inner.stop_sending(code);
    }
    fn recv_id(&self) -> StreamId {
        self.inner.recv_id()
    }
}

impl<T: quic::SendStream<Bytes>> quic::SendStream<Bytes> for Observed<T> {
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        self.inner.poll_ready(cx)
    }
    fn send_data<D: Into<WriteBuf<Bytes>>>(&mut self, data: D) -> Result<(), StreamErrorIncoming> {
        self.inner.send_data(data)
    }
    fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        self.inner.poll_finish(cx)
    }
    fn reset(&mut self, code: u64) {
        self.inner.reset(code);
    }
    fn send_id(&self) -> StreamId {
        self.inner.send_id()
    }
}

impl<T: quic::BidiStream<Bytes>> quic::BidiStream<Bytes> for Observed<T> {
    type SendStream = T::SendStream;
    type RecvStream = Observed<T::RecvStream>;
    fn split(self) -> (Self::SendStream, Self::RecvStream) {
        let (send, recv) = self.inner.split();
        (
            send,
            Observed {
                inner: recv,
                observation: self.observation,
            },
        )
    }
}

impl<T: quic::Is0rtt> quic::Is0rtt for Observed<T> {
    fn is_0rtt(&self) -> bool {
        self.inner.is_0rtt()
    }
}

pub struct Stop<T> {
    inner: T,
    observation: Arc<Observation>,
}
impl<T: Clone> Clone for Stop<T> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            observation: self.observation.clone(),
        }
    }
}

impl<T: quic::StopRecv> quic::StopRecv for Stop<T> {
    fn stop_sending(&self, code: u64) {
        if let Some(gate) = &self.observation.gate
            && !gate.once.swap(true, Ordering::SeqCst)
        {
            gate.entered.wait();
            gate.release.wait();
        }
        self.inner.stop_sending(code);
    }
}

impl<T: quic::RecvStreamControl> quic::RecvStreamControl for Observed<T> {
    type Stop = Stop<T::Stop>;
    fn stop_handle(&mut self) -> Self::Stop {
        Stop {
            inner: self.inner.stop_handle(),
            observation: self.observation.clone(),
        }
    }
}

pub async fn pair() -> (
    quic_backend::Endpoint,
    quinn::Endpoint,
    quic_backend::Connection,
    quinn::Connection,
) {
    install_crypto_provider();
    let cert = generate_test_certificate().unwrap();
    let mut server_tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.cert_der()],
            rustls::pki_types::PrivateKeyDer::try_from(cert.key_der.clone()).unwrap(),
        )
        .unwrap();
    server_tls.alpn_protocols = vec![b"h3".to_vec()];
    let server = quinn::Endpoint::server(
        quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(server_tls).unwrap(),
        )),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.cert_der()).unwrap();
    let mut tls = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let client = quic_backend::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    client.set_default_client_config(quic_backend::ClientConfig::new(Arc::new(
        quic_backend::crypto::rustls::QuicClientConfig::try_from(tls).unwrap(),
    )));
    let (client_conn, server_conn) = tokio::join!(
        client
            .connect(server.local_addr().unwrap(), "localhost")
            .unwrap(),
        async { server.accept().await.unwrap().await }
    );
    (client, server, client_conn.unwrap(), server_conn.unwrap())
}

use ::quic as quic_backend;

pub async fn control_stream(server: &quinn::Connection) -> quinn::SendStream {
    let mut stream = server.open_uni().await.unwrap();
    stream.write_all(&[0, 4, 0]).await.unwrap();
    stream
}
