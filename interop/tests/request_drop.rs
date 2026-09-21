//! Stream lifecycle contracts against upstream h3 and raw QUIC peers.

use std::{
    future::{Future, poll_fn},
    sync::Arc,
    task::Poll,
    time::Duration,
};

use bytes::{Buf, Bytes, BytesMut};
use futures::FutureExt;
use http::{Request, Response};
use tokio::{sync::oneshot, time::timeout};

#[path = "request_drop/tls.rs"]
mod tls;

#[tokio::test]
async fn dropping_request_or_send_half_resets_upload() {
    bounded(async {
        for split in [false, true] {
            let (_, server_config, client_config) = tls::config();
            let (client, server, _endpoints) = quic_pair(server_config, client_config).await;
            let (client, server) = tokio::join!(
                http3::client::new(http3_quic::Connection::new(client)),
                h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(server)),
            );
            let (mut driver, mut sender) = client.unwrap();
            let mut server = server.unwrap();
            let drive = tokio::spawn(async move { driver.wait_idle().await });
            let (accepted_tx, accepted_rx) = oneshot::channel();
            let peer = tokio::spawn(async move {
                let (_, mut stream) = server
                    .accept()
                    .await
                    .unwrap()
                    .unwrap()
                    .resolve_request()
                    .await
                    .unwrap();
                accepted_tx.send(()).unwrap();
                let error = stream
                    .recv_data()
                    .await
                    .err()
                    .expect("upload must be reset");
                assert!(
                    matches!(error, h3::error::StreamError::RemoteTerminate { code, .. }
                    if code == h3::error::Code::H3_REQUEST_CANCELLED.value())
                );
                if split {
                    stream.send_response(Response::new(())).await.unwrap();
                    stream
                        .send_data(Bytes::from_static(b"still receiving"))
                        .await
                        .unwrap();
                    stream.finish().await.unwrap();
                }
                server
            });
            let stream = sender
                .send_request(Request::post("https://localhost/drop").body(()).unwrap())
                .await
                .unwrap();
            accepted_rx.await.unwrap();
            if split {
                let (send, mut recv) = stream.split();
                drop(send);
                assert_eq!(recv.recv_response().await.unwrap().status(), 200);
                let mut body = BytesMut::new();
                while let Some(mut data) = recv.recv_data().await.unwrap() {
                    body.extend_from_slice(&data.copy_to_bytes(data.remaining()));
                }
                assert_eq!(&body[..], b"still receiving");
                assert!(recv.recv_trailers().await.unwrap().is_none());
            } else {
                drop(stream);
            }
            let _server = peer.await.unwrap();
            drop(sender);
            drop(_server);
            assert!(drive.await.unwrap().is_h3_no_error());
        }
    })
    .await;
}

#[tokio::test]
async fn dropping_receive_half_stops_download_without_canceling_upload() {
    bounded(async {
        let (_, server_config, mut client_config) = tls::config();
        const RECEIVE_WINDOW: u32 = 64 * 1024;
        let mut transport = quic::TransportConfig::default();
        transport.stream_receive_window(RECEIVE_WINDOW.into());
        client_config.transport_config(Arc::new(transport));
        let (client, server, _endpoints) = quic_pair(server_config, client_config).await;
        let (client, server) = tokio::join!(
            http3::client::new(http3_quic::Connection::new(client)),
            h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(server)),
        );
        let (mut driver, mut sender) = client.unwrap();
        let mut server = server.unwrap();
        let drive = tokio::spawn(async move { driver.wait_idle().await });
        let peer = tokio::spawn(async move {
            let (_, mut stream) = server
                .accept()
                .await
                .unwrap()
                .unwrap()
                .resolve_request()
                .await
                .unwrap();
            stream.send_response(Response::new(())).await.unwrap();
            let (mut send, mut recv) = stream.split();
            let ((), ()) = tokio::join!(
                async {
                    // Leave room for a prefetched chunk while reading headers,
                    // but keep this write blocked until STOP_SENDING arrives.
                    // https://www.rfc-editor.org/rfc/rfc9000.html#section-4.1
                    let error = send
                        .send_data(Bytes::from(vec![0; 4 * RECEIVE_WINDOW as usize]))
                        .await
                        .expect_err("download must be stopped");
                    assert!(
                        matches!(error, h3::error::StreamError::RemoteTerminate { code, .. }
                    if code == h3::error::Code::H3_REQUEST_CANCELLED.value())
                    );
                },
                async {
                    let mut body = BytesMut::new();
                    while let Some(mut data) = recv.recv_data().await.unwrap() {
                        body.extend_from_slice(&data.copy_to_bytes(data.remaining()));
                    }
                    assert_eq!(&body[..], b"still sending");
                }
            );
            server
        });
        let mut stream = sender
            .send_request(
                Request::post("https://localhost/drop-recv")
                    .body(())
                    .unwrap(),
            )
            .await
            .unwrap();
        stream.recv_response().await.unwrap();
        let (mut send, recv) = stream.split();
        drop(recv);
        send.send_data(Bytes::from_static(b"still sending"))
            .await
            .unwrap();
        send.finish().await.unwrap();
        drop(send);
        let _server = peer.await.unwrap();
        drop(sender);
        drop(_server);
        assert!(drive.await.unwrap().is_h3_no_error());
    })
    .await;
}

#[tokio::test]
async fn finish_after_cancelled_write_delivers_complete_body() {
    bounded(async {
        let (_, mut server_config, client_config) = tls::config();
        const RECEIVE_WINDOW: u32 = 64 * 1024;
        const BODY_LEN: usize = 4 * RECEIVE_WINDOW as usize;
        let mut transport = quinn::TransportConfig::default();
        transport.stream_receive_window(RECEIVE_WINDOW.into());
        server_config.transport_config(Arc::new(transport));
        let (client, server, _endpoints) = quic_pair(server_config, client_config).await;
        let (client, server) = tokio::join!(
            http3::client::new(http3_quic::Connection::new(client)),
            h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(server)),
        );
        let (mut driver, mut sender) = client.unwrap();
        let mut server = server.unwrap();
        let drive = tokio::spawn(async move { driver.wait_idle().await });
        let (read_tx, read_rx) = oneshot::channel();
        let peer = tokio::spawn(async move {
            let (_, mut stream) = server
                .accept()
                .await
                .unwrap()
                .unwrap()
                .resolve_request()
                .await
                .unwrap();
            // Keep the upload flow-controlled until the client cancels its write
            // future. FIN must follow the entire DATA frame, not truncate it.
            // https://www.rfc-editor.org/rfc/rfc9114.html#section-4.1
            read_rx.await.unwrap();
            let mut body = BytesMut::new();
            while let Some(mut data) = stream.recv_data().await.unwrap() {
                body.extend_from_slice(&data.copy_to_bytes(data.remaining()));
            }
            assert_eq!(body.len(), BODY_LEN);
            assert!(body.iter().all(|byte| *byte == b'x'));
            assert!(stream.recv_trailers().await.unwrap().is_none());
            stream.send_response(Response::new(())).await.unwrap();
            stream.finish().await.unwrap();
            server
        });
        let mut stream = sender
            .send_request(
                Request::post("https://localhost/finish-pending")
                    .header("content-length", BODY_LEN)
                    .body(())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(
            stream
                .send_data(Bytes::from(vec![b'x'; BODY_LEN]))
                .now_or_never()
                .is_none()
        );
        read_tx.send(()).unwrap();
        stream.finish().await.unwrap();
        assert_eq!(stream.recv_response().await.unwrap().status(), 200);
        assert!(stream.recv_data().await.unwrap().is_none());
        assert!(stream.recv_trailers().await.unwrap().is_none());
        drop(stream);
        let _server = peer.await.unwrap();
        drop(sender);
        drop(_server);
        assert!(drive.await.unwrap().is_h3_no_error());
    })
    .await;
}

/// Connects a `quic` client to a `quinn` server over loopback UDP.
///
/// The two halves are separate crates on purpose: `http3-quic` is built on
/// `quic`, while the upstream `h3` peer these tests validate against is built on
/// `quinn`. They interoperate on the wire, not in the type system.
async fn quic_pair(
    server_config: quinn::ServerConfig,
    client_config: quic::ClientConfig,
) -> (
    quic::Connection,
    quinn::Connection,
    (quic::Endpoint, quinn::Endpoint),
) {
    let server_endpoint =
        quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let client_endpoint = quic::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    client_endpoint.set_default_client_config(client_config);
    let client = client_endpoint
        .connect(server_endpoint.local_addr().unwrap(), "localhost")
        .unwrap();
    let (client, server) = tokio::join!(client, async {
        server_endpoint.accept().await.unwrap().await.unwrap()
    });
    (client.unwrap(), server, (client_endpoint, server_endpoint))
}

async fn bounded<F: Future>(future: F) -> F::Output {
    timeout(Duration::from_secs(10), future)
        .await
        .expect("HTTP/3 test timed out")
}

#[tokio::test]
async fn empty_data_frames_do_not_truncate_response() {
    bounded(async {
        let (_, server_config, client_config) = tls::config();
        let (client, server, _endpoints) = quic_pair(server_config, client_config).await;
        let (_driver, mut sender) = http3::client::new(http3_quic::Connection::new(client))
            .await
            .unwrap();
        let mut request = sender
            .send_request(
                Request::get("https://localhost/empty-data")
                    .body(())
                    .unwrap(),
            )
            .await
            .unwrap();
        request.finish().await.unwrap();
        let mut control = server.open_uni().await.unwrap();
        control.write_all(&[0, 4, 0]).await.unwrap();
        let (mut send, _recv) = server.accept_bi().await.unwrap();
        // Write explicit frame bytes so a server API cannot omit empty DATA:
        // HEADERS(:status=200), empty DATA, DATA("abc"), empty DATA, FIN.
        // DATA boundaries are not body EOF (RFC 9114 Sections 4.1 and 7.2.1).
        // https://www.rfc-editor.org/rfc/rfc9114.html#section-4.1
        send.write_all(&[1, 3, 0, 0, 0xd9, 0, 0, 0, 3, b'a', b'b', b'c', 0, 0])
            .await
            .unwrap();
        send.finish().unwrap();
        assert_eq!(request.recv_response().await.unwrap().status(), 200);
        let mut body = BytesMut::new();
        while let Some(mut data) = request.recv_data().await.unwrap() {
            body.extend_from_slice(&data.copy_to_bytes(data.remaining()));
        }
        assert_eq!(&body[..], b"abc");
        assert!(request.recv_trailers().await.unwrap().is_none());
    })
    .await;
}

#[tokio::test]
async fn pending_response_read_preserves_cancellation_code() {
    bounded(async {
        for explicit in [false, true] {
            let (_, server_config, client_config) = tls::config();
            let (client, server, _endpoints) = quic_pair(server_config, client_config).await;
            let (_driver, mut sender) = http3::client::new(http3_quic::Connection::new(client))
                .await
                .unwrap();
            let mut request = sender
                .send_request(
                    Request::get("https://localhost/pending-read")
                        .body(())
                        .unwrap(),
                )
                .await
                .unwrap();
            request.finish().await.unwrap();
            let mut control = server.open_uni().await.unwrap();
            control.write_all(&[0, 4, 0]).await.unwrap();
            let (mut send, _recv) = server.accept_bi().await.unwrap();
            // Leave the response open and idle after headers and empty DATA.
            // Cancellation must not wait for more peer data or become code 0.
            // https://github.com/hyperium/h3/issues/361
            // https://www.rfc-editor.org/rfc/rfc9114.html#section-4.1.1
            send.write_all(&[1, 3, 0, 0, 0xd9, 0, 0]).await.unwrap();
            request.recv_response().await.unwrap();
            poll_fn(|cx| match request.poll_recv_data(cx) {
                Poll::Pending => Poll::Ready(()),
                Poll::Ready(_) => panic!("idle response body must remain pending"),
            })
            .await;
            let expected = if explicit {
                http3::error::Code::H3_MESSAGE_ERROR
            } else {
                http3::error::Code::H3_REQUEST_CANCELLED
            };
            if explicit {
                request.stop_sending(expected);
            }
            drop(request);
            assert_eq!(
                send.stopped().await.unwrap().unwrap().into_inner(),
                expected.value()
            );
        }
    })
    .await;
}
