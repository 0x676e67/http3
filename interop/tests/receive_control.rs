#[path = "support/receive_control.rs"]
mod support;

use std::{
    future::{Future, poll_fn},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use bytes::Bytes;
use futures::task::{ArcWake, waker};
use http3::error::{Code, StreamError};
use support::{Observation, Observed, control_stream, pair};

#[derive(Default)]
struct Wakes(AtomicUsize);
impl ArcWake for Wakes {
    fn wake_by_ref(this: &Arc<Self>) {
        this.0.fetch_add(1, Ordering::SeqCst);
    }
}

fn canceled<T>(result: Result<T, StreamError>, code: Code) {
    assert!(matches!(result, Err(StreamError::StreamError { code: actual, .. }) if actual == code));
}

#[tokio::test]
async fn receive_control_preserves_receive_errors_and_late_registration() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let (_client_ep, _server_ep, client_conn, server) = pair().await;
        let _control = control_stream(&server).await;
        let (mut driver, mut sender) = http3::client::builder().send_grease(false)
            .qpack_max_table_capacity(64u64).qpack_blocked_streams(1u64)
            .build::<_, _, Bytes>(http3_quic::Connection::new(client_conn)).await.unwrap();
        let driver = tokio::spawn(poll_fn(move |cx| driver.poll_close(cx)));
        for mode in 0..5 {
            let mut request = sender.send_request(http::Request::get("https://localhost/").body(()).unwrap()).await.unwrap();
            let (mut send, _recv) = server.accept_bi().await.unwrap();
            if mode == 0 {
                let _control = request.recv_control();
                send.reset(quinn::VarInt::from_u64(Code::H3_MESSAGE_ERROR.value()).unwrap()).unwrap();
                assert!(matches!(request.recv_response().await, Err(StreamError::RemoteTerminate { code, .. }) if code == Code::H3_MESSAGE_ERROR));
                continue;
            }
            send.write_all(&[1, 3, 0, 0, 0xd9]).await.unwrap();
            assert_eq!(request.recv_response().await.unwrap().status(), 200);
            let wakes = Arc::new(Wakes::default()); let task_waker = waker(wakes.clone());
            let mut cx = Context::from_waker(&task_waker);
            if mode == 1 {
                // A caller may request control after a poll API already parked.
                assert!(request.poll_recv_data(&mut cx).is_pending());
                let control = request.recv_control();
                control.stop_sending(Code::H3_MESSAGE_ERROR);
                assert!(wakes.0.load(Ordering::SeqCst) > 0);
                canceled(request.recv_data().await, Code::H3_MESSAGE_ERROR);
            } else if mode == 2 {
                request.stop_sending(Code::H3_MESSAGE_ERROR);
                request.recv_control().stop_sending(Code::H3_INTERNAL_ERROR);
                canceled(request.recv_data().await, Code::H3_MESSAGE_ERROR);
            } else {
                let control = request.recv_control();
                let mut receiving: std::pin::Pin<Box<dyn Future<Output = Result<(), StreamError>> + '_>> = if mode == 3 {
                    Box::pin(async { request.recv_data().await.map(|_| ()) })
                } else {
                    Box::pin(async { request.recv_trailers().await.map(|_| ()) })
                };
                assert!(receiving.as_mut().poll(&mut cx).is_pending());
                control.stop_sending(Code::H3_MESSAGE_ERROR);
                assert!(wakes.0.load(Ordering::SeqCst) > 0);
                canceled(receiving.await, Code::H3_MESSAGE_ERROR);
            }
            assert_eq!(send.stopped().await.unwrap().unwrap().into_inner(), Code::H3_MESSAGE_ERROR.value());
        }
        assert!(server.close_reason().is_none());
        drop(sender); server.close(0u32.into(), b"done"); driver.abort(); let _ = driver.await;
    }).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn independent_receive_stop_preserves_upload_and_first_code() {
    tokio::time::timeout(Duration::from_secs(10), async {
        for race_drop in [false, true] {
            let (_client_ep, _server_ep, client_conn, server) = pair().await;
            let _control = control_stream(&server).await;
            let observation = Arc::new(Observation {
                gate: race_drop.then(support::Gate::new),
                ..Default::default()
            });
            let transport = Observed {
                inner: http3_quic::Connection::new(client_conn),
                observation: observation.clone(),
            };
            let (mut driver, mut sender) = http3::client::builder()
                .send_grease(false)
                .build::<_, _, Bytes>(transport)
                .await
                .unwrap();
            let driver = tokio::spawn(poll_fn(move |cx| driver.poll_close(cx)));
            let mut request = sender
                .send_request(http::Request::get("https://localhost/").body(()).unwrap())
                .await
                .unwrap();
            let control = request.recv_control();
            drop(control.clone()); // Handle Drop must not stop either direction.
            let (mut peer_send, mut peer_recv) = server.accept_bi().await.unwrap();
            peer_send.write_all(&[1, 3, 0, 0, 0xd9]).await.unwrap();
            assert_eq!(request.recv_response().await.unwrap().status(), 200);
            let (mut upload, mut recv) = request.split();
            let code = Code::H3_MESSAGE_ERROR;
            let wakes = Arc::new(Wakes::default());
            let task_waker = waker(wakes.clone());
            let mut cx = Context::from_waker(&task_waker);
            assert!(recv.poll_recv_data(&mut cx).is_pending());

            if race_drop {
                let other = control.clone();
                let stopper = std::thread::spawn(move || other.stop_sending(code));
                observation.gate.as_ref().unwrap().entered.wait();
                // Cancellation selected its code, but raw stop has not run.
                drop(recv);
                observation.gate.as_ref().unwrap().release.wait();
                stopper.join().unwrap();
            } else {
                let other = control.clone();
                std::thread::spawn(move || other.stop_sending(code))
                    .join()
                    .unwrap();
                assert!(wakes.0.load(Ordering::SeqCst) > 0);
                // Do not poll or drop recv until the peer has observed STOP.
                assert_eq!(
                    peer_send.stopped().await.unwrap().unwrap().into_inner(),
                    code.value()
                );
                canceled(recv.recv_data().await, code);
                recv.stop_sending(Code::H3_REQUEST_CANCELLED);
                drop(recv);
            }
            control.stop_sending(Code::H3_INTERNAL_ERROR);
            assert_eq!(
                peer_send.stopped().await.unwrap().unwrap().into_inner(),
                code.value()
            );
            upload
                .send_data(Bytes::from_static(b"upload survives"))
                .await
                .unwrap();
            upload.finish().await.unwrap();
            let wire = peer_recv.read_to_end(4096).await.unwrap();
            assert!(wire.ends_with(b"upload survives"));

            let mut next = sender
                .send_request(
                    http::Request::get("https://localhost/next")
                        .body(())
                        .unwrap(),
                )
                .await
                .unwrap();
            next.finish().await.unwrap();
            let (mut send, _recv) = server.accept_bi().await.unwrap();
            send.write_all(&[1, 3, 0, 0, 0xd9]).await.unwrap();
            send.finish().unwrap();
            assert_eq!(next.recv_response().await.unwrap().status(), 200);
            assert!(next.recv_data().await.unwrap().is_none());
            next.recv_control().stop_sending(Code::H3_MESSAGE_ERROR);
            assert!(next.recv_data().await.unwrap().is_none());
            drop(next);
            drop(upload);
            drop(control);
            drop(sender);
            server.close(0u32.into(), b"done");
            driver.abort();
            let _ = driver.await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn independent_receive_stop_releases_qpack_and_sends_one_cancellation() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let (_client_ep, _server_ep, client_conn, server) = pair().await;
        let _control = control_stream(&server).await;
        let observation = Arc::new(Observation::default());
        let transport = Observed {
            inner: http3_quic::Connection::new(client_conn),
            observation: observation.clone(),
        };
        let (mut driver, mut sender) = http3::client::builder()
            .send_grease(false)
            .qpack_max_table_capacity(64u64)
            .qpack_blocked_streams(1u64)
            .build::<_, _, Bytes>(transport)
            .await
            .unwrap();
        let driver = tokio::spawn(poll_fn(move |cx| driver.poll_close(cx)));
        let mut held = Vec::new();
        let mut decoder = loop {
            let mut stream = server.accept_uni().await.unwrap();
            let mut ty = [0];
            stream.read_exact(&mut ty).await.unwrap();
            if ty[0] == 3 {
                break stream;
            }
            held.push(stream);
        };

        for index in 0..2 {
            let request = sender
                .send_request(
                    http::Request::get("https://localhost/blocked")
                        .body(())
                        .unwrap(),
                )
                .await
                .unwrap();
            let (mut upload, mut recv) = request.split();
            let control = recv.recv_control(); // Capability also works after split.
            let (mut peer_send, mut peer_recv) = server.accept_bi().await.unwrap();
            let before = observation.bytes.load(Ordering::SeqCst);
            // RIC=1, Base=1: :status is the unavailable first dynamic entry.
            peer_send.write_all(&[1, 3, 2, 0, 0x80]).await.unwrap();
            let mut response = Box::pin(recv.recv_response());
            poll_fn(|cx| {
                assert!(response.as_mut().poll(cx).is_pending());
                if observation.bytes.load(Ordering::SeqCst) >= before + 5 {
                    Poll::Ready(())
                } else {
                    Poll::Pending
                }
            })
            .await;
            let wakes = Arc::new(Wakes::default());
            let task_waker = waker(wakes.clone());
            assert!(
                response
                    .as_mut()
                    .poll(&mut Context::from_waker(&task_waker))
                    .is_pending()
            );
            control.stop_sending(Code::H3_REQUEST_CANCELLED);
            assert!(wakes.0.load(Ordering::SeqCst) > 0);
            // Neither response nor its receive owner is polled/dropped here.
            assert_eq!(
                peer_send.stopped().await.unwrap().unwrap().into_inner(),
                Code::H3_REQUEST_CANCELLED.value()
            );
            let mut instruction = [0];
            decoder.read_exact(&mut instruction).await.unwrap();
            assert_eq!(instruction, [0x40 + index * 4]);
            canceled(response.await, Code::H3_REQUEST_CANCELLED);
            recv.stop_sending(Code::H3_MESSAGE_ERROR);
            control.stop_sending(Code::H3_INTERNAL_ERROR);
            drop(recv);
            upload
                .send_data(Bytes::from_static(b"still uploading"))
                .await
                .unwrap();
            upload.finish().await.unwrap();
            assert!(
                peer_recv
                    .read_to_end(4096)
                    .await
                    .unwrap()
                    .ends_with(b"still uploading")
            );
        }

        // Another blocked response with max_blocked=1 proves the old driver
        // registrations were released. Resolve this one and verify ACK/FIN.
        let mut request = sender
            .send_request(
                http::Request::get("https://localhost/complete")
                    .body(())
                    .unwrap(),
            )
            .await
            .unwrap();
        request.finish().await.unwrap();
        let control = request.recv_control();
        let (mut peer_send, _recv) = server.accept_bi().await.unwrap();
        let before = observation.bytes.load(Ordering::SeqCst);
        peer_send.write_all(&[1, 3, 2, 0, 0x80]).await.unwrap();
        peer_send.finish().unwrap();
        let mut response = Box::pin(request.recv_response());
        poll_fn(|cx| {
            assert!(response.as_mut().poll(cx).is_pending());
            if observation.bytes.load(Ordering::SeqCst) >= before + 5 {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        })
        .await;
        let mut encoder = server.open_uni().await.unwrap();
        // Encoder stream, capacity 64, literal insertion :status=200.
        encoder
            .write_all(b"\x02\x3f\x21\x47:status\x03200")
            .await
            .unwrap();
        assert_eq!(response.await.unwrap().status(), 200);
        assert!(request.recv_data().await.unwrap().is_none());
        control.stop_sending(Code::H3_MESSAGE_ERROR);
        drop(request);
        drop(control);
        let mut feedback = [0; 2];
        decoder.read_exact(&mut feedback).await.unwrap();
        feedback.sort_unstable();
        assert_eq!(feedback, [1, 0x88]);

        // A poll API can already be QPACK-blocked when control is requested.
        // FIN has been read, so QUIC has no pending-read waker to fall back to.
        let mut trailers = sender
            .send_request(
                http::Request::get("https://localhost/trailers")
                    .body(())
                    .unwrap(),
            )
            .await
            .unwrap();
        trailers.finish().await.unwrap();
        let (mut peer_send, _recv) = server.accept_bi().await.unwrap();
        // Static response headers followed by trailers referencing insert 2.
        peer_send
            .write_all(&[1, 3, 0, 0, 0xd9, 1, 3, 3, 0, 0x80])
            .await
            .unwrap();
        peer_send.finish().unwrap();
        trailers.recv_response().await.unwrap();
        assert!(trailers.recv_data().await.unwrap().is_none());
        let wakes = Arc::new(Wakes::default());
        let task_waker = waker(wakes.clone());
        let mut cx = Context::from_waker(&task_waker);
        assert!(trailers.poll_recv_trailers(&mut cx).is_pending());
        let control = trailers.recv_control();
        control.stop_sending(Code::H3_REQUEST_CANCELLED);
        assert!(wakes.0.load(Ordering::SeqCst) > 0);
        canceled(trailers.recv_trailers().await, Code::H3_REQUEST_CANCELLED);
        drop(trailers);
        drop(control);
        let mut cancellation = [0];
        decoder.read_exact(&mut cancellation).await.unwrap();
        assert_eq!(cancellation, [0x4c]);

        // No duplicate cancellation/ACK may follow completion or reader Drop.
        let mut extra = [0];
        let mut pending = std::pin::pin!(decoder.read(&mut extra));
        assert!(futures::poll!(&mut pending).is_pending());
        assert!(server.close_reason().is_none());
        drop(sender);
        server.close(0u32.into(), b"done");
        driver.abort();
        let _ = driver.await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn native_reader_drop_wakes_pending_read_and_preserves_stop_code() {
    use http3::quic::{
        self, BidiStream, RecvStream, RecvStreamControl, SendStream, SendStreamUnframed, StopRecv,
    };

    tokio::time::timeout(Duration::from_secs(10), async {
        let (_client_ep, _server_ep, client_conn, server) = pair().await;
        let mut transport = http3_quic::Connection::new(client_conn);
        for explicit in [false, true] {
            let (mut peer_send, mut peer_recv) = server.open_bi().await.unwrap();
            peer_send.write_all(b"x").await.unwrap();
            let stream = poll_fn(|cx| {
                <http3_quic::Connection as quic::Connection<Bytes>>::poll_accept_bidi(
                    &mut transport,
                    cx,
                )
            })
            .await
            .unwrap();
            let (mut upload, mut recv) = stream.split();
            assert_eq!(
                poll_fn(|cx| recv.poll_data(cx)).await.unwrap().unwrap(),
                Bytes::from_static(b"x")
            );
            let stop = recv.stop_handle();
            drop(stop.clone());
            let wakes = Arc::new(Wakes::default());
            let task_waker = waker(wakes.clone());
            assert!(
                recv.poll_data(&mut Context::from_waker(&task_waker))
                    .is_pending()
            );
            let code = if explicit {
                Code::H3_MESSAGE_ERROR.value()
            } else {
                0
            };
            if explicit {
                stop.stop_sending(code);
                stop.stop_sending(Code::H3_INTERNAL_ERROR.value());
            }
            // Exercise adapter teardown directly, without the HTTP Drop guard.
            drop(recv);
            assert!(wakes.0.load(Ordering::SeqCst) > 0);
            stop.stop_sending(Code::H3_REQUEST_CANCELLED.value());
            assert_eq!(
                peer_send.stopped().await.unwrap().unwrap().into_inner(),
                code
            );
            let mut bytes = Bytes::from_static(b"upload survives");
            while !bytes.is_empty() {
                poll_fn(|cx| upload.poll_send(cx, &mut bytes))
                    .await
                    .unwrap();
            }
            poll_fn(|cx| upload.poll_finish(cx)).await.unwrap();
            assert_eq!(peer_recv.read_to_end(64).await.unwrap(), b"upload survives");
        }
        assert!(server.close_reason().is_none());
        server.close(0u32.into(), b"done");
    })
    .await
    .unwrap();
}
