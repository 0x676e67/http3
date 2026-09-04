use std::{future::Future as _, hint::black_box, time::Duration};

use assert_matches::assert_matches;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use futures_util::future;
use http::{HeaderMap, Request, Response, StatusCode, request};

use super::{Pair, http3_quinn, init_tracing};
use crate::{
    client,
    config::Settings,
    error::{Code, ConnectionError, LocalError, StreamError},
    proto::{
        coding::Encode,
        frame::{self, Frame, FrameType},
        headers::Header,
        push::PushId,
        stream::StreamType,
        varint::VarInt,
    },
    qpack,
    quic::ConnectionErrorIncoming,
    server,
    shared_state::ConnectionState,
    tests::get_stream_blocking,
};

#[tokio::test]
async fn get() {
    init_tracing();
    let mut pair = Pair::default();
    let mut server = pair.server();

    let client_fut = async {
        let (mut driver, mut client) = client::new(pair.client().await).await.expect("client init");
        let drive_fut = async { future::poll_fn(|cx| driver.poll_close(cx)).await };
        let req_fut = async move {
            let mut request_stream = client
                .send_request(Request::get("http://localhost/salut").body(()).unwrap())
                .await
                .expect("request");

            let response = request_stream.recv_response().await.expect("recv response");
            assert_eq!(response.status(), StatusCode::OK);

            let body = request_stream
                .recv_data()
                .await
                .expect("recv data")
                .expect("body");
            assert_eq!(body.chunk(), b"wonderful hypertext");
        };
        tokio::join!(req_fut, drive_fut)
    };

    let server_fut = async {
        let conn = server.next().await;
        let mut incoming_req = server::Connection::new(conn).await.unwrap();

        let (_request, mut request_stream) = get_stream_blocking(&mut incoming_req)
            .await
            .expect("accept");
        request_stream
            .send_response(
                Response::builder()
                    .status(200)
                    .body(())
                    .expect("build response"),
            )
            .await
            .expect("send_response");
        request_stream
            .send_data("wonderful hypertext".into())
            .await
            .expect("send_data");
        request_stream.finish().await.expect("finish");

        assert_matches!(
            incoming_req.accept().await.err().unwrap(),
            ConnectionError::Remote(ConnectionErrorIncoming::ApplicationClose{error_code: code, ..})
            if code == Code::H3_NO_ERROR.value()
        );
    };

    tokio::join!(server_fut, client_fut);
}

#[tokio::test]
async fn client_dynamic_qpack_request_round_trip() {
    const TABLE_CAPACITY: u64 = 256;

    init_tracing();
    let mut pair = Pair::default();
    let mut transport_server = pair.server();

    let client_fut = async {
        let mut builder = client::builder();
        builder
            .qpack_encoder_table_capacity(TABLE_CAPACITY as usize)
            .send_grease(false);
        let (mut driver, mut send) = builder
            .build::<_, _, Bytes>(pair.client().await)
            .await
            .expect("client init");
        let encoder = driver
            .inner
            .dynamic_qpack_encoder()
            .expect("dynamic QPACK encoder");

        future::poll_fn(|cx| {
            if let std::task::Poll::Ready(error) = driver.poll_close(cx) {
                panic!("connection closed before QPACK encoder became ready: {error:?}");
            }
            encoder
                .dynamic_ready()
                .unwrap()
                .then_some(())
                .map_or(std::task::Poll::Pending, std::task::Poll::Ready)
        })
        .await;

        for request_index in 0..2 {
            if request_index == 1 {
                future::poll_fn(|cx| {
                    if let std::task::Poll::Ready(error) = driver.poll_close(cx) {
                        panic!("connection closed before QPACK insert acknowledgment: {error:?}");
                    }
                    encoder
                        .has_acknowledged_all_insertions()
                        .unwrap()
                        .then_some(())
                        .map_or(std::task::Poll::Pending, std::task::Poll::Ready)
                })
                .await;
            }

            let mut request = Box::pin(async {
                let mut stream = send
                    .send_request(
                        Request::get("http://localhost/dynamic")
                            .header("x-repeated", "stable-value")
                            .body(())
                            .unwrap(),
                    )
                    .await
                    .expect("send request");
                stream.finish().await.expect("finish request");
                let response = stream.recv_response().await.expect("receive response");
                assert_eq!(response.status(), StatusCode::OK);
            });
            future::poll_fn(|cx| {
                if let std::task::Poll::Ready(result) = request.as_mut().poll(cx) {
                    return std::task::Poll::Ready(result);
                }
                if let std::task::Poll::Ready(error) = driver.poll_close(cx) {
                    panic!("connection closed during dynamic QPACK request: {error:?}");
                }
                std::task::Poll::Pending
            })
            .await;
        }

        drop(send);
        future::poll_fn(|cx| driver.poll_close(cx)).await
    };

    let server_fut = async {
        let mut builder = server::builder();
        builder
            .qpack_max_table_capacity(TABLE_CAPACITY)
            .send_grease(false);
        let mut incoming = builder
            .build(transport_server.next().await)
            .await
            .expect("server init");

        for _ in 0..2 {
            let resolver = incoming.accept().await.expect("accept dynamic request");
            let (request, mut stream) = resolver
                .expect("request stream")
                .resolve_request()
                .await
                .expect("decode dynamic request");
            assert_eq!(request.headers()["x-repeated"], "stable-value");
            stream
                .send_response(Response::builder().status(200).body(()).unwrap())
                .await
                .expect("send response");
            stream.finish().await.expect("finish response");
        }

        let error = match incoming.accept().await {
            Err(error) => error,
            Ok(_) => panic!("server accepted another request"),
        };
        assert!(error.is_h3_no_error(), "{error:?}");
    };

    let ((), client_result) = tokio::select! {
        biased;
        _ = tokio::time::sleep(Duration::from_secs(5)) => {
            panic!("dynamic QPACK request timed out")
        }
        result = async { tokio::join!(server_fut, client_fut) } => result,
    };
    assert!(client_result.is_h3_no_error(), "{client_result:?}");
}

#[tokio::test]
async fn server_rejects_blocked_request_when_advertised_limit_is_zero() {
    const TABLE_CAPACITY: u64 = 34;

    init_tracing();
    let mut pair = Pair::default();
    let mut server = pair.server();

    let client_fut = async {
        let connection = pair.client_inner().await;

        let mut control_stream = connection.open_uni().await.unwrap();
        let mut control = BytesMut::new();
        StreamType::CONTROL.encode(&mut control);
        Frame::<Bytes>::Settings(frame::Settings::default()).encode(&mut control);
        control_stream.write_all(&control).await.unwrap();

        // Keep the peer encoder stream open, but leave insertion 1 in transit.
        let mut encoder_stream = connection.open_uni().await.unwrap();
        let mut encoder_header = BytesMut::new();
        StreamType::ENCODER.encode(&mut encoder_header);
        encoder_stream.write_all(&encoder_header).await.unwrap();

        let (mut request_send, _request_recv) = connection.open_bi().await.unwrap();
        // MaxEntries is 1. Encoded RIC 2 reconstructs to Required Insert Count
        // 1, so this field section would block while the decoder Insert Count
        // remains 0.
        let mut request = BytesMut::new();
        Frame::headers(vec![0x02, 0x00, 0x80]).encode_with_payload(&mut request);
        request_send.write_all(&request).await.unwrap();

        assert_matches!(
            connection.closed().await,
            quinn::ConnectionError::ApplicationClosed(quinn::ApplicationClose {
                error_code,
                ..
            }) if error_code.into_inner() == Code::QPACK_DECOMPRESSION_FAILED.value()
        );
    };

    let server_fut = async {
        let conn = server.next().await;
        let mut incoming = server::builder()
            .qpack_max_table_capacity(TABLE_CAPACITY)
            .build(conn)
            .await
            .unwrap();
        let resolver = incoming.accept().await.unwrap().unwrap();
        assert_matches!(
            resolver.resolve_request().await.map(|_| ()),
            Err(StreamError::ConnectionError(ConnectionError::Local {
                error: LocalError::Application {
                    code: Code::QPACK_DECOMPRESSION_FAILED,
                    ..
                }
            }))
        );
        assert_matches!(
            incoming.accept().await.map(|_| ()).unwrap_err(),
            ConnectionError::Local {
                error: LocalError::Application {
                    code: Code::QPACK_DECOMPRESSION_FAILED,
                    ..
                }
            }
        );
    };

    tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(server_fut, client_fut);
    })
    .await
    .expect("blocked request did not close the connection");
}

#[tokio::test]
async fn client_rejects_huffman_eos_in_response_field_section() {
    init_tracing();
    let mut pair = Pair::default();
    let server = pair.server_inner();

    let client_fut = async {
        let (mut driver, mut send) = client::new(pair.client().await).await.unwrap();
        let mut request_stream = send
            .send_request(Request::get("http://localhost/").body(()).unwrap())
            .await
            .unwrap();

        let (response, connection) = tokio::join!(
            async {
                let response = request_stream.recv_response().await;
                drop(send);
                response
            },
            future::poll_fn(|cx| driver.poll_close(cx)),
        );
        assert_matches!(
            response,
            Err(StreamError::ConnectionError(ConnectionError::Local {
                error: LocalError::Application {
                    code: Code::QPACK_DECOMPRESSION_FAILED,
                    ..
                }
            }))
        );
        assert_matches!(
            connection,
            ConnectionError::Local {
                error: LocalError::Application {
                    code: Code::QPACK_DECOMPRESSION_FAILED,
                    ..
                }
            }
        );
    };

    let server_fut = async {
        let connection = server.accept().await.unwrap().await.unwrap();
        let mut control_stream = connection.open_uni().await.unwrap();
        let mut control = BytesMut::new();
        StreamType::CONTROL.encode(&mut control);
        Frame::<Bytes>::Settings(frame::Settings::default()).encode(&mut control);
        control_stream.write_all(&control).await.unwrap();

        let (mut response_send, _request_recv) = connection.accept_bi().await.unwrap();
        // RIC 0, Base 0, a static-name literal, then a Huffman string carrying
        // the forbidden EOS symbol.
        // https://www.rfc-editor.org/rfc/rfc9204.html#section-4.1.2
        // https://www.rfc-editor.org/rfc/rfc7541.html#section-5.2
        let field_section = [0x00, 0x00, 0b0101_0000, 0b1000_0100, 0xff, 0xff, 0xff, 0xff];
        let mut response = BytesMut::new();
        Frame::headers(field_section.to_vec()).encode_with_payload(&mut response);
        response_send.write_all(&response).await.unwrap();

        assert_matches!(
            connection.closed().await,
            quinn::ConnectionError::ApplicationClosed(quinn::ApplicationClose {
                error_code,
                ..
            }) if error_code.into_inner() == Code::QPACK_DECOMPRESSION_FAILED.value()
        );
    };

    tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(server_fut, client_fut);
    })
    .await
    .expect("malformed response field section did not close the connection");
}

#[tokio::test]
async fn client_keeps_blocked_field_section_prefix_across_table_updates() {
    const TABLE_CAPACITY: u64 = 34;

    init_tracing();
    let mut pair = Pair::default();
    let server = pair.server_inner();
    let (blocked_send, blocked_recv) = tokio::sync::oneshot::channel();

    let client_fut = async {
        let mut builder = client::builder();
        builder
            .qpack_max_table_capacity(TABLE_CAPACITY)
            .qpack_blocked_streams(1);
        let (mut driver, mut send) = builder
            .build::<_, _, Bytes>(pair.client().await)
            .await
            .unwrap();
        let mut request_stream = send
            .send_request(Request::get("http://localhost/").body(()).unwrap())
            .await
            .unwrap();

        let mut response = Box::pin(request_stream.recv_response());
        future::poll_fn(|cx| {
            if let std::task::Poll::Ready(error) = driver.poll_close(cx) {
                panic!("connection closed before the field section blocked: {error:?}");
            }
            if let std::task::Poll::Ready(result) = response.as_mut().poll(cx) {
                panic!("response completed before the field section blocked: {result:?}");
            }

            if driver.inner.qpack_blocked_stream_count() == 1 {
                std::task::Poll::Ready(())
            } else {
                std::task::Poll::Pending
            }
        })
        .await;
        blocked_send.send(()).unwrap();

        let (response, connection) =
            tokio::join!(response, future::poll_fn(|cx| driver.poll_close(cx)),);
        drop(send);
        assert_matches!(
            response,
            Err(StreamError::ConnectionError(ConnectionError::Local {
                error: LocalError::Application {
                    code: Code::QPACK_DECOMPRESSION_FAILED,
                    ..
                }
            }))
        );
        assert_matches!(
            connection,
            ConnectionError::Local {
                error: LocalError::Application {
                    code: Code::QPACK_DECOMPRESSION_FAILED,
                    ..
                }
            }
        );
    };

    let server_fut = async {
        let connection = server.accept().await.unwrap().await.unwrap();
        let mut control_stream = connection.open_uni().await.unwrap();
        let mut control = BytesMut::new();
        StreamType::CONTROL.encode(&mut control);
        Frame::<Bytes>::Settings(frame::Settings::default()).encode(&mut control);
        control_stream.write_all(&control).await.unwrap();

        let mut encoder_stream = connection.open_uni().await.unwrap();
        let mut encoder_header = BytesMut::new();
        StreamType::ENCODER.encode(&mut encoder_header);
        encoder_stream.write_all(&encoder_header).await.unwrap();

        let (mut response_send, _request_recv) = connection.accept_bi().await.unwrap();
        // With MaxEntries 1, encoded RIC 2 reconstructs to RIC 1 while the
        // decoder table is empty. Relative index 0 therefore names insertion 1.
        let mut response = BytesMut::new();
        Frame::headers(vec![0x02, 0x00, 0x80]).encode_with_payload(&mut response);
        response_send.write_all(&response).await.unwrap();

        // Wait until the connection driver has recorded the original Required
        // Insert Count. Each subsequent 34-byte entry evicts its predecessor.
        blocked_recv.await.unwrap();
        let mut instructions = BytesMut::new();
        qpack::DynamicTableSizeUpdate(usize::try_from(TABLE_CAPACITY).unwrap())
            .encode(&mut instructions);
        for value in ["1", "2", "3"] {
            qpack::InsertWithoutNameRef::new("a", value)
                .encode(&mut instructions)
                .unwrap();
        }
        encoder_stream.write_all(&instructions).await.unwrap();

        // The original insertion is gone. Reconstructing the prefix a second
        // time would incorrectly bind the response to insertion 3 instead.
        // https://www.rfc-editor.org/rfc/rfc9204.html#section-4.5.1.1
        assert_matches!(
            connection.closed().await,
            quinn::ConnectionError::ApplicationClosed(quinn::ApplicationClose {
                error_code,
                ..
            }) if error_code.into_inner() == Code::QPACK_DECOMPRESSION_FAILED.value()
        );
    };

    tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(server_fut, client_fut);
    })
    .await
    .expect("blocked field section did not preserve its reconstructed prefix");
}

#[tokio::test]
async fn client_rejects_oversized_encoded_field_section_from_frame_header() {
    init_tracing();
    let mut pair = Pair::default();
    let server = pair.server_inner();

    let client_fut = async {
        let mut builder = client::builder();
        builder.max_qpack_decode_buffer_size(4);
        let (mut driver, mut send) = builder
            .build::<_, _, Bytes>(pair.client().await)
            .await
            .unwrap();
        let mut request_stream = send
            .send_request(Request::get("http://localhost/").body(()).unwrap())
            .await
            .unwrap();

        let (response, connection) = tokio::join!(
            async {
                let response = request_stream.recv_response().await;
                drop(send);
                response
            },
            future::poll_fn(|cx| driver.poll_close(cx)),
        );
        assert_matches!(
            response,
            Err(StreamError::ConnectionError(ConnectionError::Local {
                error: LocalError::Application {
                    code: Code::H3_EXCESSIVE_LOAD,
                    ..
                }
            }))
        );
        assert_matches!(
            connection,
            ConnectionError::Local {
                error: LocalError::Application {
                    code: Code::H3_EXCESSIVE_LOAD,
                    ..
                }
            }
        );
    };

    let server_fut = async {
        let connection = server.accept().await.unwrap().await.unwrap();
        let mut control_stream = connection.open_uni().await.unwrap();
        let mut control = BytesMut::new();
        StreamType::CONTROL.encode(&mut control);
        Frame::<Bytes>::Settings(frame::Settings::default()).encode(&mut control);
        control_stream.write_all(&control).await.unwrap();

        let (mut response_send, _request_recv) = connection.accept_bi().await.unwrap();
        let mut response_header = BytesMut::new();
        FrameType::HEADERS.encode(&mut response_header);
        VarInt::from(5u32).encode(&mut response_header);
        response_send.write_all(&response_header).await.unwrap();

        assert_matches!(
            connection.closed().await,
            quinn::ConnectionError::ApplicationClosed(quinn::ApplicationClose {
                error_code,
                ..
            }) if error_code.into_inner() == Code::H3_EXCESSIVE_LOAD.value()
        );
    };

    tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(server_fut, client_fut);
    })
    .await
    .expect("oversized encoded field section did not close the connection");
}

#[tokio::test]
async fn server_rejects_oversized_encoded_field_section_from_frame_header() {
    init_tracing();
    let mut pair = Pair::default();
    let mut server = pair.server();

    let client_fut = async {
        let connection = pair.client_inner().await;

        let mut control_stream = connection.open_uni().await.unwrap();
        let mut control = BytesMut::new();
        StreamType::CONTROL.encode(&mut control);
        Frame::<Bytes>::Settings(frame::Settings::default()).encode(&mut control);
        control_stream.write_all(&control).await.unwrap();

        let (mut request_send, _request_recv) = connection.open_bi().await.unwrap();
        let mut request_header = BytesMut::new();
        FrameType::HEADERS.encode(&mut request_header);
        VarInt::from(5u32).encode(&mut request_header);
        request_send.write_all(&request_header).await.unwrap();

        assert_matches!(
            connection.closed().await,
            quinn::ConnectionError::ApplicationClosed(quinn::ApplicationClose {
                error_code,
                ..
            }) if error_code.into_inner() == Code::H3_EXCESSIVE_LOAD.value()
        );
    };

    let server_fut = async {
        let conn = server.next().await;
        let mut builder = server::builder();
        builder.max_qpack_decode_buffer_size(4);
        let mut incoming = builder.build(conn).await.unwrap();
        let resolver = incoming.accept().await.unwrap().unwrap();
        assert_matches!(
            resolver.resolve_request().await.map(|_| ()),
            Err(StreamError::ConnectionError(ConnectionError::Local {
                error: LocalError::Application {
                    code: Code::H3_EXCESSIVE_LOAD,
                    ..
                }
            }))
        );
        assert_matches!(
            incoming.accept().await.map(|_| ()).unwrap_err(),
            ConnectionError::Local {
                error: LocalError::Application {
                    code: Code::H3_EXCESSIVE_LOAD,
                    ..
                }
            }
        );
    };

    tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(server_fut, client_fut);
    })
    .await
    .expect("oversized request field section did not close the connection");
}

#[tokio::test]
async fn get_with_trailers_unknown_content_type() {
    init_tracing();
    let mut pair = Pair::default();
    let mut server = pair.server();

    let client_fut = async {
        let (mut driver, mut client) = client::new(pair.client().await).await.expect("client init");
        let drive_fut = async { future::poll_fn(|cx| driver.poll_close(cx)).await };
        let req_fut = async move {
            let mut request_stream = client
                .send_request(Request::get("http://localhost/salut").body(()).unwrap())
                .await
                .expect("request");
            request_stream.recv_response().await.expect("recv response");
            request_stream
                .recv_data()
                .await
                .expect("recv data")
                .expect("body");

            assert!(request_stream.recv_data().await.unwrap().is_none());
            let trailers = request_stream
                .recv_trailers()
                .await
                .expect("recv trailers")
                .expect("trailers none");
            assert_eq!(trailers.get("trailer").unwrap(), &"value");
        };
        tokio::join!(req_fut, drive_fut);
    };

    let server_fut = async {
        let conn = server.next().await;
        let mut incoming_req = server::Connection::new(conn).await.unwrap();

        let (_, mut request_stream) = get_stream_blocking(&mut incoming_req)
            .await
            .expect("accept");
        request_stream
            .send_response(
                Response::builder()
                    .status(200)
                    .body(())
                    .expect("build response"),
            )
            .await
            .expect("send_response");
        request_stream
            .send_data("wonderful hypertext".into())
            .await
            .expect("send_data");
        let mut trailers = HeaderMap::new();
        trailers.insert("trailer", "value".parse().unwrap());
        request_stream
            .send_trailers(trailers)
            .await
            .expect("send_trailers");
        request_stream.finish().await.expect("finish");

        assert_matches!(
            incoming_req.accept().await.err().unwrap(),
            ConnectionError::Remote(ConnectionErrorIncoming::ApplicationClose{error_code: code, ..})
            if code == Code::H3_NO_ERROR.value()
        );
    };

    tokio::join!(server_fut, client_fut);
}

#[tokio::test]
async fn get_with_trailers_known_content_type() {
    init_tracing();
    let mut pair = Pair::default();
    let mut server = pair.server();

    let client_fut = async {
        let (mut driver, mut client) = client::new(pair.client().await).await.expect("client init");
        let drive_fut = async { future::poll_fn(|cx| driver.poll_close(cx)).await };
        let req_fut = async move {
            let mut request_stream = client
                .send_request(Request::get("http://localhost/salut").body(()).unwrap())
                .await
                .expect("request");
            request_stream.recv_response().await.expect("recv response");
            request_stream
                .recv_data()
                .await
                .expect("recv data")
                .expect("body");

            let trailers = request_stream
                .recv_trailers()
                .await
                .expect("recv trailers")
                .expect("trailers none");
            assert_eq!(trailers.get("trailer").unwrap(), &"value");
        };
        tokio::join!(req_fut, drive_fut);
    };

    let server_fut = async {
        let conn = server.next().await;
        let mut incoming_req = server::Connection::new(conn).await.unwrap();

        let (_, mut request_stream) = get_stream_blocking(&mut incoming_req)
            .await
            .expect("accept");
        request_stream
            .send_response(
                Response::builder()
                    .status(200)
                    .body(())
                    .expect("build response"),
            )
            .await
            .expect("send_response");
        request_stream
            .send_data("wonderful hypertext".into())
            .await
            .expect("send_data");

        let mut trailers = HeaderMap::new();
        trailers.insert("trailer", "value".parse().unwrap());
        request_stream
            .send_trailers(trailers)
            .await
            .expect("send_trailers");
        request_stream.finish().await.expect("finish");

        assert_matches!(
            incoming_req.accept().await.err().unwrap(),
            ConnectionError::Remote(ConnectionErrorIncoming::ApplicationClose{error_code: code, ..})
            if code == Code::H3_NO_ERROR.value()
        );
    };

    tokio::join!(server_fut, client_fut);
}

#[tokio::test]
async fn post() {
    init_tracing();
    let mut pair = Pair::default();
    let mut server = pair.server();

    let client_fut = async {
        let (mut driver, mut client) = client::new(pair.client().await).await.expect("client init");
        let drive_fut = async { future::poll_fn(|cx| driver.poll_close(cx)).await };
        let req_fut = async move {
            let mut request_stream = client
                .send_request(Request::get("http://localhost/salut").body(()).unwrap())
                .await
                .expect("request");

            request_stream
                .send_data("wonderful json".into())
                .await
                .expect("send_data");
            request_stream.finish().await.expect("client finish");

            request_stream.recv_response().await.expect("recv response");
        };
        tokio::join!(req_fut, drive_fut);
    };

    let server_fut = async {
        let conn = server.next().await;
        let mut incoming_req = server::Connection::new(conn).await.unwrap();

        let (_, mut request_stream) = get_stream_blocking(&mut incoming_req)
            .await
            .expect("accept");
        request_stream
            .send_response(
                Response::builder()
                    .status(200)
                    .body(())
                    .expect("build response"),
            )
            .await
            .expect("send_response");

        let request_body = request_stream
            .recv_data()
            .await
            .expect("recv data")
            .expect("server recv body");
        assert_eq!(request_body.chunk(), b"wonderful json");
        request_stream.finish().await.expect("client finish");

        // keep connection until client is finished
        assert_matches!(
            incoming_req.accept().await.err().unwrap(),
            ConnectionError::Remote(ConnectionErrorIncoming::ApplicationClose{error_code: code, ..})
            if code == Code::H3_NO_ERROR.value()
        );
    };

    tokio::join!(server_fut, client_fut);
}

#[tokio::test]
async fn header_too_big_response_from_server() {
    init_tracing();
    let mut pair = Pair::default();
    let mut server = pair.server();

    let client_fut = async {
        let (mut driver, mut client) = client::new(pair.client().await).await.expect("client init");
        let drive_fut = async { future::poll_fn(|cx| driver.poll_close(cx)).await };
        let req_fut = async move {
            let mut request_stream = client
                .send_request(Request::get("http://localhost/salut").body(()).unwrap())
                .await
                .expect("request");
            request_stream.finish().await.expect("client finish");
            let response = request_stream.recv_response().await.unwrap();
            assert_eq!(
                response.status(),
                StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE
            );
        };
        tokio::join!(req_fut, drive_fut);
    };

    let server_fut = async {
        let conn = server.next().await;
        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.2.2
        //= type=test
        //# An HTTP/3 implementation MAY impose a limit on the maximum size of
        //# the message header it will accept on an individual HTTP message.
        let mut incoming_req = server::builder()
            .max_field_section_size(12)
            .build(conn)
            .await
            .unwrap();

        let resolver = incoming_req.accept().await.unwrap().unwrap();

        let err_kind = resolver
            .resolve_request()
            .await
            .err()
            .expect("should return an error");

        assert_matches!(
            err_kind,
            StreamError::HeaderTooBig {
                actual_size: 42,
                max_size: 12
            }
        );

        // connection will end without an error
        assert_matches!(
            incoming_req.accept().await.err().unwrap(),
            ConnectionError::Remote(ConnectionErrorIncoming::ApplicationClose{error_code: code, ..})
            if code == Code::H3_NO_ERROR.value()
        );
    };

    tokio::join!(server_fut, client_fut);
}

#[tokio::test]
async fn header_too_big_response_from_server_trailers() {
    init_tracing();
    let mut pair = Pair::default();
    let mut server = pair.server();

    let client_fut = async {
        let (mut driver, mut client) = client::new(pair.client().await).await.expect("client init");
        let drive_fut = async { future::poll_fn(|cx| driver.poll_close(cx)).await };
        let req_fut = async {
            let mut request_stream = client
                .send_request(Request::get("http://localhost/salut").body(()).unwrap())
                .await
                .expect("request");
            request_stream
                .send_data("wonderful json".into())
                .await
                .expect("send_data");

            let mut trailers = HeaderMap::new();
            trailers.insert("trailer", "A".repeat(200).parse().unwrap());
            request_stream
                .send_trailers(trailers)
                .await
                .expect("send trailers");
            request_stream.finish().await.expect("client finish");
            let _ = request_stream.recv_response().await;
        };
        tokio::select! {biased; _ = req_fut => (), _ = drive_fut => () }
    };

    let server_fut = async {
        let conn = server.next().await;
        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.2.2
        //= type=test
        //# An HTTP/3 implementation MAY impose a limit on the maximum size of
        //# the message header it will accept on an individual HTTP message.
        let mut incoming_req = server::builder()
            .max_field_section_size(207)
            .build(conn)
            .await
            .unwrap();

        let (_request, mut request_stream) = get_stream_blocking(&mut incoming_req)
            .await
            .expect("accept");
        let _ = request_stream
            .recv_data()
            .await
            .expect("recv data")
            .expect("body");
        let err_kind = request_stream.recv_trailers().await.unwrap_err();
        assert_matches!(
            err_kind,
            StreamError::HeaderTooBig {
                actual_size: 239,
                max_size: 207,
                ..
            }
        );
        let _ = incoming_req.accept().await;
    };

    tokio::join!(server_fut, client_fut);
}

#[tokio::test]
async fn header_too_big_client_error() {
    init_tracing();
    let mut pair = Pair::default();
    let mut server = pair.server();

    let client_fut = async {
        let (mut driver, mut client) = client::new(pair.client().await).await.expect("client init");
        let drive_fut = async {
            assert_matches!(
                future::poll_fn(|cx| driver.poll_close(cx)).await,
                ConnectionError::Remote(ConnectionErrorIncoming::ApplicationClose{
                    error_code: code,
                    ..
                }) if code == Code::H3_NO_ERROR.value()
            );
        };
        let req_fut = async {
            // pretend client already received server's settings
            let settings = Settings {
                max_field_section_size: 12,
                ..Settings::default()
            };
            // Sets the settings if not already received
            client.set_settings(settings);

            let req = Request::get("http://localhost/salut").body(()).unwrap();
            let err_kind = client.send_request(req).await.map(|_| ()).unwrap_err();

            assert_matches!(
                err_kind,
                StreamError::HeaderTooBig {
                    actual_size: 179,
                    max_size: 12,
                    ..
                }
            );
        };
        tokio::join! {req_fut, drive_fut }
    };

    let server_fut = async {
        let conn = server.next().await;

        let mut incoming_req = server::builder()
            .max_field_section_size(12)
            .build(conn)
            .await
            .unwrap();

        let incoming = incoming_req.accept().await.unwrap().unwrap();

        // client does not send any data, so the server will not receive any data, resulting in a
        // H3_REQUEST_INCOMPLETE
        assert_matches!(
            incoming
                .resolve_request()
                .await
                .err()
                .expect("should return an error"),
            StreamError::StreamError {
                code: Code::H3_REQUEST_INCOMPLETE,
                reason: _
            }
        );
    };

    tokio::join!(server_fut, client_fut);
}

#[tokio::test]
async fn header_too_big_client_error_trailer() {
    init_tracing();
    let mut pair = Pair::default();
    let mut server = pair.server();

    let client_fut = async {
        let (mut driver, mut client) = client::new(pair.client().await).await.expect("client init");
        let drive_fut = async {
            let err = future::poll_fn(|cx| driver.poll_close(cx)).await;
            match err {
                ConnectionError::Timeout => (),
                _ => panic!("unexpected error: {:?}", err),
            }
        };
        let req_fut = async {
            let settings = Settings {
                max_field_section_size: 200,
                ..Settings::default()
            };
            client.set_settings(settings);

            let mut request_stream = client
                .send_request(Request::get("http://localhost/salut").body(()).unwrap())
                .await
                .expect("request");
            request_stream
                .send_data("wonderful json".into())
                .await
                .expect("send_data");

            let mut trailers = HeaderMap::new();
            trailers.insert("trailer", "A".repeat(200).parse().unwrap());

            let err_kind = request_stream.send_trailers(trailers).await.unwrap_err();

            assert_matches!(
                err_kind,
                StreamError::HeaderTooBig {
                    actual_size: 239,
                    max_size: 200,
                    ..
                }
            );

            request_stream.finish().await.expect("client finish");
        };
        tokio::join! {req_fut,drive_fut};
    };

    let server_fut = async {
        let conn = server.next().await;
        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.2.2
        //= type=test
        //# An HTTP/3 implementation MAY impose a limit on the maximum size of
        //# the message header it will accept on an individual HTTP message.
        let mut incoming_req = server::builder()
            .max_field_section_size(207)
            .build(conn)
            .await
            .unwrap();

        let (_request, mut request_stream) = get_stream_blocking(&mut incoming_req)
            .await
            .expect("accept");
        let _ = request_stream
            .recv_data()
            .await
            .expect("recv data")
            .expect("body");
        let _ = incoming_req.accept().await;
    };

    tokio::join!(server_fut, client_fut);
}

#[tokio::test]
async fn header_too_big_discard_from_client() {
    init_tracing();
    let mut pair = Pair::default();
    let mut server = pair.server();

    let client_fut = async {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.2.2
        //= type=test
        //# An implementation that
        //# has received this parameter SHOULD NOT send an HTTP message header
        //# that exceeds the indicated size, as the peer will likely refuse to
        //# process it.

        let (mut driver, mut client) = client::builder()
            .max_field_section_size(12)
            // Don't send settings, so server doesn't know about the low max_field_section_size
            .send_settings(false)
            .build::<_, _, Bytes>(pair.client().await)
            .await
            .expect("client init");
        let drive_fut = async { future::poll_fn(|cx| driver.poll_close(cx)).await };
        let req_fut = async {
            let mut request_stream = client
                .send_request(Request::get("http://localhost/salut").body(()).unwrap())
                .await
                .expect("request");
            request_stream.finish().await.expect("client finish");
            let err_kind = request_stream.recv_response().await.unwrap_err();
            assert_matches!(
                err_kind,
                StreamError::HeaderTooBig {
                    actual_size: 42,
                    max_size: 12,
                    ..
                }
            );

            let mut request_stream = client
                .send_request(Request::get("http://localhost/salut").body(()).unwrap())
                .await
                .expect("request");
            request_stream.finish().await.expect("client finish");
            let _ = request_stream.recv_response().await.unwrap_err();
        };
        tokio::select! {biased; _ = req_fut => (), _ = drive_fut => () }
    };

    let server_fut = async {
        let conn = server.next().await;
        let mut incoming_req = server::Connection::new(conn).await.unwrap();

        let (_request, mut request_stream) = get_stream_blocking(&mut incoming_req)
            .await
            .expect("accept");
        request_stream
            .send_response(
                Response::builder()
                    .status(200)
                    .body(())
                    .expect("build response"),
            )
            .await
            .expect("send_response");

        // Keep sending: wait for the stream to be cancelled by the client
        let mut err = None;
        for _ in 0..100 {
            if let Err(e) = request_stream.send_data("some data".into()).await {
                err = Some(e);
                break;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        assert_matches!(
            err.as_ref().unwrap(),
            StreamError::RemoteTerminate {
                code: Code::H3_REQUEST_CANCELLED,
                ..
            }
        );
        let _ = incoming_req.accept().await;
    };

    tokio::join!(server_fut, client_fut);
}

#[tokio::test]
async fn header_too_big_discard_from_client_trailers() {
    init_tracing();
    let mut pair = Pair::default();
    let mut server = pair.server();

    let client_fut = async {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.2.2
        //= type=test
        //# An implementation that
        //# has received this parameter SHOULD NOT send an HTTP message header
        //# that exceeds the indicated size, as the peer will likely refuse to
        //# process it.

        let (mut driver, mut client) = client::builder()
            .max_field_section_size(200)
            // Don't send settings, so server doesn't know about the low max_field_section_size
            .send_settings(false)
            .build::<_, _, Bytes>(pair.client().await)
            .await
            .expect("client init");

        let drive_fut = async { future::poll_fn(|cx| driver.poll_close(cx)).await };
        let req_fut = async {
            let mut request_stream = client
                .send_request(Request::get("http://localhost/salut").body(()).unwrap())
                .await
                .expect("request");
            request_stream.recv_response().await.expect("recv response");
            request_stream.recv_data().await.expect("recv data");

            let err_kind = request_stream.recv_trailers().await.unwrap_err();
            assert_matches!(
                err_kind,
                StreamError::HeaderTooBig {
                    actual_size: 539,
                    max_size: 200,
                    ..
                }
            );
            request_stream.finish().await.expect("client finish");
        };
        tokio::select! {biased; _ = req_fut => (), _ = drive_fut => () }
    };

    let server_fut = async {
        let conn = server.next().await;
        let mut incoming_req = server::Connection::new(conn).await.unwrap();

        let (_request, mut request_stream) = get_stream_blocking(&mut incoming_req)
            .await
            .expect("accept");

        request_stream
            .send_response(
                Response::builder()
                    .status(200)
                    .body(())
                    .expect("build response"),
            )
            .await
            .expect("send_response");

        request_stream
            .send_data("wonderful hypertext".into())
            .await
            .expect("send_data");

        let mut trailers = HeaderMap::new();
        trailers.insert("trailer", "value".repeat(100).parse().unwrap());
        request_stream
            .send_trailers(trailers)
            .await
            .expect("send_trailers");
        request_stream.finish().await.expect("finish");

        let _ = incoming_req.accept().await;
    };

    tokio::join!(server_fut, client_fut);
}

#[tokio::test]
async fn header_too_big_server_error() {
    init_tracing();
    let mut pair = Pair::default();
    let mut server = pair.server();

    let client_fut = async {
        let (mut driver, mut client) = client::new(pair.client().await) // header size limit faked for brevity
            .await
            .expect("client init");
        let drive_fut = async { future::poll_fn(|cx| driver.poll_close(cx)).await };
        let req_fut = async {
            let req = Request::get("http://localhost/salut").body(()).unwrap();
            let _ = client
                .send_request(req)
                .await
                .unwrap()
                .recv_response()
                .await;
        };
        tokio::select! { _ = req_fut => (), _ = drive_fut => () }
    };

    let server_fut = async {
        let conn = server.next().await;
        let mut incoming_req = server::Connection::new(conn).await.unwrap();

        // pretend the server received a smaller max_field_section_size
        let settings = Settings {
            max_field_section_size: 12,
            ..Settings::default()
        };
        incoming_req.set_settings(settings);

        let (_request, mut request_stream) = get_stream_blocking(&mut incoming_req)
            .await
            .expect("accept");

        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.2.2
        //= type=test
        //# An implementation that
        //# has received this parameter SHOULD NOT send an HTTP message header
        //# that exceeds the indicated size, as the peer will likely refuse to
        //# process it.

        let err_kind = request_stream
            .send_response(
                Response::builder()
                    .status(200)
                    .body(())
                    .expect("build response"),
            )
            .await
            .map(|_| ())
            .unwrap_err();

        assert_matches!(
            err_kind,
            StreamError::HeaderTooBig {
                actual_size: 42,
                max_size: 12,
                ..
            }
        );
    };

    tokio::join!(server_fut, client_fut);
}

#[tokio::test]
async fn header_too_big_server_error_trailers() {
    init_tracing();
    let mut pair = Pair::default();
    let mut server = pair.server();

    let client_fut = async {
        let (mut driver, mut client) = client::new(pair.client().await) // header size limit faked for brevity
            .await
            .expect("client init");
        let drive_fut = async { future::poll_fn(|cx| driver.poll_close(cx)).await };
        let req_fut = async {
            let req = Request::get("http://localhost/salut").body(()).unwrap();
            let _ = client
                .send_request(req)
                .await
                .unwrap()
                .recv_response()
                .await;
        };
        tokio::select! { _ = req_fut => (), _ = drive_fut => () }
    };

    let server_fut = async {
        let conn = server.next().await;
        let mut incoming_req = server::Connection::new(conn).await.unwrap();

        // pretend the server already received client's settings
        let settings = Settings {
            max_field_section_size: 42,
            ..Settings::default()
        };
        incoming_req.set_settings(settings);

        let (_request, mut request_stream) = get_stream_blocking(&mut incoming_req)
            .await
            .expect("accept");
        request_stream
            .send_response(
                Response::builder()
                    .status(200)
                    .body(())
                    .expect("build response"),
            )
            .await
            .unwrap();
        request_stream
            .send_data("wonderful hypertext".into())
            .await
            .expect("send_data");

        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.2.2
        //= type=test
        //# An implementation that
        //# has received this parameter SHOULD NOT send an HTTP message header
        //# that exceeds the indicated size, as the peer will likely refuse to
        //# process it.

        let mut trailers = HeaderMap::new();
        trailers.insert("trailer", "value".repeat(100).parse().unwrap());
        let err_kind = request_stream.send_trailers(trailers).await.unwrap_err();

        assert_matches!(
            err_kind,
            StreamError::HeaderTooBig {
                actual_size: 539,
                max_size: 42,
                ..
            }
        );
    };

    tokio::join!(server_fut, client_fut);
}

#[tokio::test]
async fn get_timeout_client_recv_response() {
    init_tracing();
    let mut pair = Pair::default();
    pair.with_timeout(Duration::from_millis(100));
    let mut server = pair.server();

    let client_fut = async {
        let (mut conn, mut client) = client::new(pair.client().await).await.expect("client init");
        let request_fut = async {
            let mut request_stream = client
                .send_request(Request::get("http://localhost/salut").body(()).unwrap())
                .await
                .expect("request");

            let response = request_stream.recv_response().await;
            assert_matches!(
                response.unwrap_err(),
                StreamError::ConnectionError(ConnectionError::Timeout)
            );
        };

        let drive_fut = async move {
            let result = future::poll_fn(|cx| conn.poll_close(cx)).await;
            assert_matches!(result, ConnectionError::Timeout);
        };

        tokio::join!(drive_fut, request_fut);
    };

    let server_fut = async {
        let conn = server.next().await;
        let mut incoming_req = server::Connection::new(conn).await.unwrap();

        // _req must not be dropped, else the connection will be closed and the timeout
        // won't be triggered
        let _req = incoming_req.accept().await.expect("accept").unwrap();
        tokio::time::sleep(Duration::from_millis(500)).await;
    };

    tokio::join!(server_fut, client_fut);
}

#[tokio::test]
async fn get_timeout_client_recv_data() {
    init_tracing();
    let mut pair = Pair::default();
    pair.with_timeout(Duration::from_millis(200));
    let mut server = pair.server();

    let client_fut = async {
        let (mut conn, mut client) = client::new(pair.client().await).await.expect("client init");
        let request_fut = async {
            let mut request_stream = client
                .send_request(Request::get("http://localhost/salut").body(()).unwrap())
                .await
                .expect("request");

            let _ = request_stream.recv_response().await.unwrap();
            let data = request_stream.recv_data().await;
            assert_matches!(
                data.map(|_| ()).unwrap_err(),
                StreamError::ConnectionError(ConnectionError::Timeout)
            );
        };

        let drive_fut = async move {
            let result = future::poll_fn(|cx| conn.poll_close(cx)).await;
            assert_matches!(result, ConnectionError::Timeout);
        };

        tokio::join!(drive_fut, request_fut);
    };

    let server_fut = async {
        let conn = server.next().await;
        let mut incoming_req = server::Connection::new(conn).await.unwrap();

        let (_request, mut request_stream) = get_stream_blocking(&mut incoming_req)
            .await
            .expect("accept");
        request_stream
            .send_response(
                Response::builder()
                    .status(200)
                    .body(())
                    .expect("build response"),
            )
            .await
            .expect("send_response");
        tokio::time::sleep(Duration::from_millis(500)).await;
    };

    tokio::join!(server_fut, client_fut);
}

#[tokio::test]
async fn get_timeout_server_accept() {
    init_tracing();
    let mut pair = Pair::default();
    pair.with_timeout(Duration::from_millis(200));
    let mut server = pair.server();

    let client_fut = async {
        let (mut conn, _client) = client::new(pair.client().await).await.expect("client init");
        let request_fut = async {
            tokio::time::sleep(Duration::from_millis(500)).await;
        };

        let drive_fut = async move {
            let result = future::poll_fn(|cx| conn.poll_close(cx)).await;
            assert_matches!(result, ConnectionError::Timeout);
        };

        tokio::join!(drive_fut, request_fut);
    };

    let server_fut = async {
        let conn = server.next().await;
        let mut incoming_req = server::Connection::new(conn).await.unwrap();

        assert_matches!(
            incoming_req.accept().await.map(|_| ()).unwrap_err(),
            ConnectionError::Timeout
        );
    };

    tokio::join!(server_fut, client_fut);
}

#[tokio::test]
async fn post_timeout_server_recv_data() {
    init_tracing();
    let mut pair = Pair::default();
    pair.with_timeout(Duration::from_millis(100));
    let mut server = pair.server();

    let client_fut = async {
        let (_conn, mut client) = client::new(pair.client().await).await.expect("client init");
        let _request_stream = client
            .send_request(Request::post("http://localhost/salut").body(()).unwrap())
            .await
            .expect("request");
        tokio::time::sleep(Duration::from_millis(500)).await;
    };

    let server_fut = async {
        let conn = server.next().await;
        let mut incoming_req = server::Connection::new(conn).await.unwrap();

        let (_, mut req_stream) = get_stream_blocking(&mut incoming_req)
            .await
            .expect("accept");
        assert_matches!(
            req_stream.recv_data().await.map(|_| ()).unwrap_err(),
            StreamError::ConnectionError(ConnectionError::Timeout)
        );
    };

    tokio::join!(server_fut, client_fut);
}

// 4.1. HTTP Message Exchanges

// An HTTP message (request or response) consists of:
// * the header section, sent as a single HEADERS frame (see Section 7.2.2),
// * optionally, the content, if present, sent as a series of DATA frames (see Section 7.2.1),
// * and optionally, the trailer section, if present, sent as a single HEADERS frame.

#[tokio::test]
async fn request_valid_one_header() {
    request_sequence_ok(|mut buf| {
        request_encode(
            &mut buf,
            Request::post("http://localhost/salut").body(()).unwrap(),
        );
    })
    .await;
}

#[tokio::test]
async fn request_valid_header_data() {
    request_sequence_ok(|mut buf| {
        request_encode(
            &mut buf,
            Request::post("http://localhost/salut").body(()).unwrap(),
        );
        Frame::Data(Bytes::from("fada")).encode_with_payload(&mut buf);
    })
    .await;
}

#[tokio::test]
async fn request_valid_header_data_trailer() {
    request_sequence_ok(|mut buf| {
        request_encode(
            &mut buf,
            Request::post("http://localhost/salut").body(()).unwrap(),
        );
        Frame::Data(Bytes::from("fada")).encode_with_payload(&mut buf);
        let mut trailers = HeaderMap::new();
        trailers.insert("trailer", "value".parse().unwrap());
        trailers_encode(buf, trailers);
    })
    .await;
}

#[tokio::test]
async fn request_valid_header_multiple_data_trailer() {
    request_sequence_ok(|mut buf| {
        request_encode(
            &mut buf,
            Request::post("http://localhost/salut").body(()).unwrap(),
        );
        Frame::Data(Bytes::from("fada")).encode_with_payload(&mut buf);
        Frame::Data(Bytes::from("fada")).encode_with_payload(&mut buf);
        Frame::Data(Bytes::from("fada")).encode_with_payload(&mut buf);
        let mut trailers = HeaderMap::new();
        trailers.insert("trailer", "value".parse().unwrap());
        trailers_encode(buf, trailers);
    })
    .await;
}

#[tokio::test]
async fn request_valid_header_trailer() {
    request_sequence_ok(|mut buf| {
        request_encode(
            &mut buf,
            Request::post("http://localhost/salut").body(()).unwrap(),
        );
        let mut trailers = HeaderMap::new();
        trailers.insert("trailer", "value".parse().unwrap());
        trailers_encode(buf, trailers);
    })
    .await;
}

// Frames of unknown types (Section 9), including reserved frames (Section
// 7.2.8) MAY be sent on a request or push stream before, after, or interleaved
// with other frames described in this section.

#[tokio::test]
async fn request_valid_unknown_frame_before() {
    request_sequence_ok(|mut buf| {
        unknown_frame_encode(buf);
        request_encode(
            &mut buf,
            Request::post("http://localhost/salut").body(()).unwrap(),
        );
    })
    .await;
}

#[tokio::test]
async fn request_valid_unknown_frame_after_one_header() {
    request_sequence_ok(|mut buf| {
        request_encode(
            &mut buf,
            Request::post("http://localhost/salut").body(()).unwrap(),
        );
        unknown_frame_encode(buf);
    })
    .await;
}

#[tokio::test]
async fn request_valid_unknown_frame_interleaved_after_header() {
    request_sequence_ok(|mut buf| {
        request_encode(
            &mut buf,
            Request::post("http://localhost/salut").body(()).unwrap(),
        );
        unknown_frame_encode(buf);
        Frame::Data(Bytes::from("fada")).encode_with_payload(&mut buf);
    })
    .await;
}

#[tokio::test]
async fn request_valid_unknown_frame_interleaved_between_data() {
    request_sequence_ok(|mut buf| {
        request_encode(
            &mut buf,
            Request::post("http://localhost/salut").body(()).unwrap(),
        );
        Frame::Data(Bytes::from("fada")).encode_with_payload(&mut buf);
        unknown_frame_encode(buf);
        Frame::Data(Bytes::from("fada")).encode_with_payload(&mut buf);
    })
    .await;
}

#[tokio::test]
async fn request_valid_unknown_frame_interleaved_after_data() {
    request_sequence_ok(|mut buf| {
        request_encode(
            &mut buf,
            Request::post("http://localhost/salut").body(()).unwrap(),
        );
        Frame::Data(Bytes::from("fada")).encode_with_payload(&mut buf);
        unknown_frame_encode(buf);
        Frame::Data(Bytes::from("fada")).encode_with_payload(&mut buf);
    })
    .await;
}

#[tokio::test]
async fn request_valid_unknown_frame_interleaved_before_trailers() {
    request_sequence_ok(|mut buf| {
        request_encode(
            &mut buf,
            Request::post("http://localhost/salut").body(()).unwrap(),
        );
        Frame::Data(Bytes::from("fada")).encode_with_payload(&mut buf);
        unknown_frame_encode(buf);
        let mut trailers = HeaderMap::new();
        trailers.insert("trailer", "value".parse().unwrap());
        trailers_encode(buf, trailers);
    })
    .await;
}

#[tokio::test]
async fn request_valid_unknown_frame_after_trailers() {
    request_sequence_ok(|mut buf| {
        request_encode(
            &mut buf,
            Request::post("http://localhost/salut").body(()).unwrap(),
        );
        Frame::Data(Bytes::from("fada")).encode_with_payload(&mut buf);
        let mut trailers = HeaderMap::new();
        trailers.insert("trailer", "value".parse().unwrap());
        trailers_encode(buf, trailers);
        unknown_frame_encode(buf);
    })
    .await;
}

//= https://www.rfc-editor.org/rfc/rfc9114#section-4.1
//= type=test
//# Receipt of an invalid sequence of frames MUST be treated as a
//# connection error of type H3_FRAME_UNEXPECTED.
fn invalid_request_frames() -> Vec<Frame<Bytes>> {
    vec![
        Frame::CancelPush(PushId(0)),
        Frame::Settings(frame::Settings::default()),
        Frame::Goaway(VarInt(1)),
        Frame::MaxPushId(PushId(1)),
    ]
}

#[tokio::test]
async fn request_invalid_frame_first() {
    //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.3
    //= type=test
    //# Receiving a
    //# CANCEL_PUSH frame on a stream other than the control stream MUST be
    //# treated as a connection error of type H3_FRAME_UNEXPECTED.

    //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.4
    //= type=test
    //# If an endpoint receives a SETTINGS frame on a different
    //# stream, the endpoint MUST respond with a connection error of type
    //# H3_FRAME_UNEXPECTED.

    //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.6
    //= type=test
    //# A client MUST treat a GOAWAY frame on a stream other than
    //# the control stream as a connection error of type H3_FRAME_UNEXPECTED.

    //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.7
    //= type=test
    //# The MAX_PUSH_ID frame is always sent on the control stream.  Receipt
    //# of a MAX_PUSH_ID frame on any other stream MUST be treated as a
    //# connection error of type H3_FRAME_UNEXPECTED.
    for frame in invalid_request_frames() {
        request_sequence_unexpected(|mut buf| frame.encode(&mut buf)).await;
    }
}

#[tokio::test]
async fn request_invalid_frame_after_header() {
    for frame in invalid_request_frames() {
        request_sequence_unexpected(|mut buf| {
            request_encode(
                &mut buf,
                Request::post("http://localhost/salut").body(()).unwrap(),
            );
            frame.encode(&mut buf);
        })
        .await;
    }
}

#[tokio::test]
async fn request_invalid_frame_after_data() {
    for frame in invalid_request_frames() {
        request_sequence_unexpected(|mut buf| {
            request_encode(
                &mut buf,
                Request::post("http://localhost/salut").body(()).unwrap(),
            );
            Frame::Data(Bytes::from("fada")).encode_with_payload(&mut buf);
            frame.encode(&mut buf);
        })
        .await;
    }
}

#[tokio::test]
async fn request_invalid_frame_after_trailers() {
    for frame in invalid_request_frames() {
        request_sequence_unexpected(|mut buf| {
            request_encode(
                &mut buf,
                Request::post("http://localhost/salut").body(()).unwrap(),
            );
            Frame::Data(Bytes::from("fada")).encode_with_payload(&mut buf);
            let mut trailers = HeaderMap::new();
            trailers.insert("trailer", "value".parse().unwrap());
            trailers_encode(buf, trailers);
            frame.encode(&mut buf);
        })
        .await;
    }
}

#[tokio::test]
async fn request_invalid_data_after_trailers() {
    request_sequence_unexpected(|mut buf| {
        request_encode(
            &mut buf,
            Request::post("http://localhost/salut").body(()).unwrap(),
        );
        let mut trailers = HeaderMap::new();
        trailers.insert("trailer", "value".parse().unwrap());
        trailers_encode(buf, trailers);
        Frame::Data(Bytes::from("fada")).encode_with_payload(&mut buf);
    })
    .await;
}

#[tokio::test]
async fn request_invalid_data_first() {
    request_sequence_unexpected(|mut buf| {
        Frame::Data(Bytes::from("fada")).encode_with_payload(&mut buf);
    })
    .await;
}

#[tokio::test]
async fn request_invalid_two_trailers() {
    request_sequence_unexpected(|mut buf| {
        request_encode(
            &mut buf,
            Request::post("http://localhost/salut").body(()).unwrap(),
        );
        Frame::Data(Bytes::from("fada")).encode_with_payload(&mut buf);
        let mut trailers = HeaderMap::new();
        trailers.insert("trailer", "value".parse().unwrap());
        trailers_encode(buf, trailers.clone());
        trailers_encode(buf, trailers);
    })
    .await;
}

#[tokio::test]
async fn request_invalid_trailing_byte() {
    request_sequence_frame_error(|mut buf| {
        request_encode(
            &mut buf,
            Request::post("http://localhost/salut").body(()).unwrap(),
        );
        Frame::Data(Bytes::from("fada")).encode_with_payload(&mut buf);
        let mut trailers = HeaderMap::new();
        trailers.insert("trailer", "value".parse().unwrap());
        trailers_encode(buf, trailers);

        //= https://www.rfc-editor.org/rfc/rfc9114#section-7.1
        //= type=test
        //# A frame payload that contains additional bytes
        //# after the identified fields or a frame payload that terminates before
        //# the end of the identified fields MUST be treated as a connection
        //# error of type H3_FRAME_ERROR.
        buf.put_u8(255);
    })
    .await;
}

#[tokio::test]
async fn request_invalid_data_frame_length_too_large() {
    request_sequence_frame_error(|mut buf| {
        request_encode(
            &mut buf,
            Request::post("http://localhost/salut").body(()).unwrap(),
        );
        FrameType::DATA.encode(&mut buf);

        //= https://www.rfc-editor.org/rfc/rfc9114#section-7.1
        //= type=test
        //# A frame payload that contains additional bytes
        //# after the identified fields or a frame payload that terminates before
        //# the end of the identified fields MUST be treated as a connection
        //# error of type H3_FRAME_ERROR.
        VarInt::from(5u32).encode(&mut buf);
        buf.put_slice(b"fada");

        let mut trailers = HeaderMap::new();
        trailers.insert("trailer", "value".parse().unwrap());
        trailers_encode(buf, trailers);
    })
    .await;
}

#[tokio::test]
async fn request_invalid_data_frame_length_too_short() {
    request_sequence_frame_error(|mut buf| {
        request_encode(
            &mut buf,
            Request::post("http://localhost/salut").body(()).unwrap(),
        );
        FrameType::DATA.encode(&mut buf);

        //= https://www.rfc-editor.org/rfc/rfc9114#section-7.1
        //= type=test
        //# A frame payload that contains additional bytes
        //# after the identified fields or a frame payload that terminates before
        //# the end of the identified fields MUST be treated as a connection
        //# error of type H3_FRAME_ERROR.
        VarInt::from(3u32).encode(&mut buf);
        buf.put_slice(b"fada");
    })
    .await;
}

// Helpers

fn request_encode<B: BufMut>(buf: &mut B, req: http::Request<()>) {
    let (parts, _) = req.into_parts();
    let request::Parts {
        method,
        uri,
        headers,
        extensions,
        ..
    } = parts;
    let headers = Header::request(method, uri, headers, extensions).unwrap();
    let mut block = BytesMut::new();
    qpack::encode_stateless(&mut block, &headers).unwrap();
    Frame::headers(block).encode_with_payload(buf);
}

fn trailers_encode<B: BufMut>(buf: &mut B, fields: HeaderMap) {
    let headers = Header::trailer(fields);
    let mut block = BytesMut::new();
    qpack::encode_stateless(&mut block, &headers).unwrap();
    Frame::headers(block).encode_with_payload(buf);
}

fn unknown_frame_encode<B: BufMut>(buf: &mut B) {
    buf.put_slice(&[22, 4, 0, 255, 128, 0]);
}

async fn request_sequence_ok<F>(request: F)
where
    F: Fn(&mut BytesMut),
{
    request_sequence_check(request, None).await;
}

async fn request_sequence_unexpected<F>(request: F)
where
    F: Fn(&mut BytesMut),
{
    //= https://www.rfc-editor.org/rfc/rfc9114#section-4.1
    //= type=test
    //# Receipt of an invalid sequence of frames MUST be treated as a
    //# connection error of type H3_FRAME_UNEXPECTED.

    request_sequence_check(request, Some(Code::H3_FRAME_UNEXPECTED)).await;
}

async fn request_sequence_frame_error<F>(request: F)
where
    F: Fn(&mut BytesMut),
{
    request_sequence_check(request, Some(Code::H3_FRAME_ERROR)).await;
}

async fn request_sequence_check<F>(request: F, expected_error_code: Option<Code>)
where
    F: Fn(&mut BytesMut),
{
    init_tracing();
    let mut pair = Pair::default();
    let mut server = pair.server();

    let client_fut = async {
        let connection = pair.client_inner().await;

        let (mut driver, send) = client::new(http3_quinn::Connection::new(connection.clone()))
            .await
            .unwrap();

        let (mut req_send, mut req_recv) = connection.open_bi().await.unwrap();

        let client = async move {
            let mut buf = BytesMut::new();
            request(&mut buf);
            req_send.write_all(&buf[..]).await.unwrap();
            req_send.finish().unwrap();

            // wait to give the server time to return the error before dropping send
            tokio::time::sleep(Duration::from_millis(100)).await;

            loop {
                match req_recv.read(&mut buf).await {
                    Ok(Some(i)) => {
                        black_box(i);
                    }
                    Ok(None) => break,
                    Err(err) => {
                        return Err(err);
                    }
                }
            }

            // drop the SendRequest to let driver know there will be no more requests
            drop(send);

            Result::<(), quinn::ReadError>::Ok(())
        };

        let driver = async {
            Result::<(), ConnectionError>::Err(future::poll_fn(|cx| driver.poll_close(cx)).await)
        };

        tokio::join!(client, driver)
    };

    let server_fut = async {
        let conn = server.next().await;
        let mut incoming = server::Connection::new(conn).await.unwrap();
        let request_resolver = incoming
            .accept()
            .await
            .unwrap()
            .expect("request stream end unexpected");

        let driver = async move {
            match incoming.accept().await {
                Ok(_) => (),
                Err(err) => return Err(err),
            };
            Result::<(), ConnectionError>::Ok(())
        };

        let stream = async {
            let (_, mut stream) = request_resolver.resolve_request().await?;

            while stream.recv_data().await?.is_some() {}
            stream.recv_trailers().await?;

            Result::<(), StreamError>::Ok(())
        };
        tokio::join!(driver, stream)
    };

    let (
        (server_result_driver, server_result_stream),
        (client_result_stream, client_result_driver),
    ) = tokio::join!(server_fut, client_fut);

    if let Err(err) = client_result_stream {
        // we have no influence wether the quinn returns the connection error to the stream api
        // but if it returns an error it needs to be the expected one
        assert_matches!(err, quinn::ReadError::ConnectionLost(quinn::ConnectionError::ApplicationClosed(code))
            if code.error_code.into_inner() == expected_error_code.expect("If this is a error an error was expected").value());
    }

    if let Some(expected_error_code) = expected_error_code {
        assert_matches!(
            server_result_driver,
            Err(ConnectionError::Local { error: LocalError::Application { code: err, .. } }) if err == expected_error_code
        );
        assert_matches!(
            client_result_driver,
            Err(ConnectionError::Remote(ConnectionErrorIncoming::ApplicationClose { error_code: err } )) if err == expected_error_code.value()
        );
        assert_matches!(
            server_result_stream,
            Err(StreamError::ConnectionError(ConnectionError::Local { error: LocalError::Application { code: err, .. } })) if err == expected_error_code
        );
    } else {
        // No error expected should be H3_NO_ERROR
        assert_matches!(
            client_result_driver,
            Err(ConnectionError::Local {
                error: LocalError::Application {
                    code: Code::H3_NO_ERROR,
                    ..
                },
            })
        );
        assert_matches!(
            server_result_driver,
            Err(ConnectionError::Remote(
                ConnectionErrorIncoming::ApplicationClose {
                    error_code: err
                }
            )) if err == Code::H3_NO_ERROR.value()
        );
        // Stream closes with no error
        assert_matches!(server_result_stream, Ok(()));
    }
}
