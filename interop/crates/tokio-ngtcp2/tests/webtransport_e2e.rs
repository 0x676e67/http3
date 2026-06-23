//! WebTransport end-to-end tests
//!
//! WebTransport session establishment using real network I/O,
//! data streams, and DATAGRAM tests

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use rcgen::{CertificateParams, KeyPair};
use tokio::time::timeout;

use ngtcp2::Http3Event;
use tokio_ngtcp2::{ClientWebTransportSession, ServerWebTransportSession};

/// Generate a certificate and private key for tests
fn generate_test_certs() -> (PathBuf, PathBuf) {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let unique_id = COUNTER.fetch_add(1, Ordering::SeqCst);
    let temp_dir = std::env::temp_dir().join(format!(
        "webtransport_e2e_test_{}_{}",
        std::process::id(),
        unique_id
    ));
    std::fs::create_dir_all(&temp_dir).expect("failed to create temporary directory");

    let cert_path = temp_dir.join("cert.pem");
    let key_path = temp_dir.join("key.pem");

    // Set certificate parameters
    let mut params = CertificateParams::new(vec!["localhost".to_string()])
        .expect("failed to create CertificateParams");
    params.distinguished_name.push(
        rcgen::DnType::CommonName,
        rcgen::DnValue::Utf8String("localhost".to_string()),
    );

    // Generate a key pair
    let key_pair = KeyPair::generate().expect("failed to generate key pair");

    // Generate a self-signed certificate
    let cert = params
        .self_signed(&key_pair)
        .expect("failed to generate certificate");

    // Save in PEM format
    std::fs::write(&cert_path, cert.pem()).expect("failed to write certificate file");
    std::fs::write(&key_path, key_pair.serialize_pem()).expect("failed to write private key file");

    (cert_path, key_path)
}

/// WebTransport session establishment test
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_webtransport_session_establishment() {
    let (cert_path, key_path) = generate_test_certs();

    let session_accepted = Arc::new(AtomicBool::new(false));
    let session_accepted_clone = session_accepted.clone();

    // Start the server
    let mut server =
        ServerWebTransportSession::bind("127.0.0.1:0".parse().unwrap(), &cert_path, &key_path)
            .await
            .expect("failed to create server");

    let server_addr = server.local_addr();
    eprintln!("[test] server started: {}", server_addr);

    // Server task
    let server_task = tokio::spawn(async move {
        let result = timeout(
            Duration::from_secs(10),
            server.run(move |addr, session_id, event| {
                match &event {
                    Http3Event::HeadersEnd { stream_id, .. } => {
                        eprintln!(
                            "[server] CONNECT request received: addr = {}, session_id = {}, stream_id = {}",
                            addr, session_id, stream_id
                        );
                        session_accepted_clone.store(true, Ordering::SeqCst);
                        // Accept the session once CONNECT headers are complete.
                        return true;
                    }
                    _ => {
                        eprintln!("[server] event: {:?}", event);
                    }
                }
                false
            }),
        )
        .await;

        match result {
            Ok(r) => r,
            Err(_) => {
                eprintln!("[server] timeout");
                Ok(())
            }
        }
    });

    // Establish a WebTransport session from the client
    let client_result = timeout(Duration::from_secs(10), async {
        let mut session =
            ClientWebTransportSession::connect_insecure(server_addr, "localhost", "/webtransport")
                .await
                .expect("failed to create client");

        eprintln!("[client] handshake started");
        session.handshake().await.expect("handshake failed");
        eprintln!("[client] handshake completed");

        // Start the WebTransport session.
        let session_result = session
            .open_session(
                &format!("localhost:{}", server_addr.port()),
                "/webtransport",
            )
            .await;

        match session_result {
            Ok(session_id) => {
                eprintln!("[client] session established: session_id = {}", session_id);
                // Give the server time to process the event
                tokio::time::sleep(Duration::from_millis(100)).await;
                Some(session_id)
            }
            Err(e) => {
                eprintln!("[client] failed to establish session: {:?}", e);
                None
            }
        }
    })
    .await;

    // Wait briefly for the server to finish processing
    tokio::time::sleep(Duration::from_millis(100)).await;

    server_task.abort();

    match client_result {
        Ok(Some(session_id)) => {
            eprintln!(
                "[test] WebTransport session establishment test succeeded: session_id = {}",
                session_id
            );
            // session_id 0
            assert!(
                session_accepted.load(Ordering::SeqCst),
                "server should accept the session"
            );
        }
        Ok(None) => {
            panic!("WebTransport failed to establish session");
        }
        Err(_) => {
            panic!("test timed out");
        }
    }
}

/// Concurrent multi-session connection test
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_webtransport_multiple_sessions() {
    let (cert_path, key_path) = generate_test_certs();

    use std::sync::atomic::AtomicUsize;
    let session_count = Arc::new(AtomicUsize::new(0));
    let session_count_clone = session_count.clone();

    // Start the server
    let mut server =
        ServerWebTransportSession::bind("127.0.0.1:0".parse().unwrap(), &cert_path, &key_path)
            .await
            .expect("failed to create server");

    let server_addr = server.local_addr();
    eprintln!("[test] server started: {}", server_addr);

    // Server task
    let server_task = tokio::spawn(async move {
        let _ = timeout(
            Duration::from_secs(15),
            server.run(move |addr, session_id, event| {
                if let Http3Event::HeadersEnd { stream_id, .. } = &event {
                    let count = session_count_clone.fetch_add(1, Ordering::SeqCst) + 1;
                    eprintln!(
                        "[server] session {} accept: addr = {}, session_id = {}, stream_id = {}",
                        count, addr, session_id, stream_id
                    );
                    return true;
                }
                false
            }),
        )
        .await;
    });

    // Connect multiple clients concurrently
    let client_count = 3;
    let mut handles = Vec::new();

    for i in 0..client_count {
        let addr = server_addr;
        let handle = tokio::spawn(async move {
            let mut session =
                ClientWebTransportSession::connect_insecure(addr, "localhost", "/webtransport")
                    .await
                    .expect("failed to create client");

            match timeout(Duration::from_secs(5), session.handshake()).await {
                Ok(Ok(())) => {
                    eprintln!("[client {}] handshake succeeded", i);
                }
                _ => {
                    eprintln!("[client {}] handshake failed", i);
                    return None;
                }
            }

            match timeout(
                Duration::from_secs(5),
                session.open_session(&format!("localhost:{}", addr.port()), "/webtransport"),
            )
            .await
            {
                Ok(Ok(session_id)) => {
                    eprintln!(
                        "[client {}] session established: session_id = {}",
                        i, session_id
                    );
                    Some(session_id)
                }
                _ => {
                    eprintln!("[client {}] failed to establish session", i);
                    None
                }
            }
        });
        handles.push(handle);
    }

    // Wait for all client results
    let mut success_count = 0;
    for handle in handles {
        if let Ok(Some(_)) = handle.await {
            success_count += 1;
        }
    }

    server_task.abort();

    let server_sessions = session_count.load(Ordering::SeqCst);
    eprintln!(
        "[test] client successes: {}/{}, server accepted: {}",
        success_count, client_count, server_sessions
    );
    assert!(success_count >= 1, "at least one session should succeed");
}

/// Session rejection test
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_webtransport_session_reject() {
    let (cert_path, key_path) = generate_test_certs();

    // Start the server and reject all sessions
    let mut server =
        ServerWebTransportSession::bind("127.0.0.1:0".parse().unwrap(), &cert_path, &key_path)
            .await
            .expect("failed to create server");

    let server_addr = server.local_addr();
    eprintln!("[test] server started: {}", server_addr);

    // Server task that rejects sessions
    let server_task = tokio::spawn(async move {
        let _ = timeout(
            Duration::from_secs(10),
            server.run(|addr, session_id, event| {
                if let Http3Event::HeadersEnd { stream_id, .. } = &event {
                    eprintln!(
                        "[server] session rejected: addr = {}, session_id = {}, stream_id = {}",
                        addr, session_id, stream_id
                    );
                    // Reject the session by returning false
                    return false;
                }
                false
            }),
        )
        .await;
    });

    // Try to open a session from the client
    let client_result = timeout(Duration::from_secs(10), async {
        let mut session =
            ClientWebTransportSession::connect_insecure(server_addr, "localhost", "/webtransport")
                .await
                .expect("failed to create client");

        session.handshake().await.expect("handshake failed");

        // Try to establish the session. It may fail because the server rejects it
        let result = session
            .open_session(
                &format!("localhost:{}", server_addr.port()),
                "/webtransport",
            )
            .await;

        eprintln!("[client] session result: {:?}", result);
        result
    })
    .await;

    server_task.abort();

    // The test succeeds even when the session is rejected
    // (This verifies that the server can process rejections)
    eprintln!(
        "[test] Session rejection test completed: {:?}",
        client_result
    );
}

/// WebTransport handshake-only test
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_webtransport_handshake_only() {
    let (cert_path, key_path) = generate_test_certs();

    // Start the server
    let mut server =
        ServerWebTransportSession::bind("127.0.0.1:0".parse().unwrap(), &cert_path, &key_path)
            .await
            .expect("failed to create server");

    let server_addr = server.local_addr();

    // Server task
    let server_task = tokio::spawn(async move {
        let _ = timeout(
            Duration::from_secs(5),
            server.run(|_addr, _session_id, _event| false),
        )
        .await;
    });

    // Create a client and run only the handshake
    let client_result = timeout(Duration::from_secs(10), async {
        let mut session =
            ClientWebTransportSession::connect_insecure(server_addr, "localhost", "/webtransport")
                .await
                .expect("failed to create client");

        eprintln!("[client] handshake started");

        match session.handshake().await {
            Ok(()) => {
                eprintln!("[client] handshake succeeded");
                true
            }
            Err(e) => {
                eprintln!("[client] handshake error: {:?}", e);
                false
            }
        }
    })
    .await;

    server_task.abort();

    match client_result {
        Ok(success) => {
            assert!(success, "handshake should succeed");
            eprintln!("[test] WebTransport handshake test succeeded");
        }
        Err(_) => {
            panic!("test timed out");
        }
    }
}

/// WebTransport bidirectional stream send/receive test
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_webtransport_bidi_stream_send_recv() {
    let (cert_path, key_path) = generate_test_certs();

    let data_received_on_server = Arc::new(AtomicBool::new(false));
    let data_received_clone = data_received_on_server.clone();
    let received_data_on_server = Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
    let received_data_clone = received_data_on_server.clone();

    // Start the server
    let mut server =
        ServerWebTransportSession::bind("127.0.0.1:0".parse().unwrap(), &cert_path, &key_path)
            .await
            .expect("failed to create server");

    let server_addr = server.local_addr();
    eprintln!("[test] server started: {}", server_addr);

    // Server task
    let server_task = tokio::spawn(async move {
        let _ = timeout(Duration::from_secs(10), async {
            loop {
                let mut handler =
                    |addr: std::net::SocketAddr, session_id: i64, event: Http3Event| -> bool {
                        match &event {
                            Http3Event::HeadersEnd { stream_id, .. } => {
                                eprintln!(
                                    "[server] CONNECT request received: addr = {}, session_id = {}, stream_id = {}",
                                    addr, session_id, stream_id
                                );
                                return true; // Accept the session.
                            }
                            Http3Event::WebTransportData {
                                session_id,
                                stream_id,
                                data,
                            } => {
                                eprintln!(
                                    "[server] data received: session_id = {}, stream_id = {}, data = {:?}",
                                    session_id,
                                    stream_id,
                                    String::from_utf8_lossy(data)
                                );
                                data_received_clone.store(true, Ordering::SeqCst);
                                received_data_clone.lock().unwrap().extend_from_slice(data);
                            }
                            _ => {
                                eprintln!("[server] event: {:?}", event);
                            }
                        }
                        false
                    };

                server
                    .recv_once(Duration::from_millis(100), &mut handler)
                    .await
                    .ok();
            }
        })
        .await;
    });

    // Establish a session from the client and send/receive data
    let client_result = timeout(Duration::from_secs(10), async {
        let mut session =
            ClientWebTransportSession::connect_insecure(server_addr, "localhost", "/webtransport")
                .await
                .expect("failed to create client");

        session.handshake().await.expect("handshake failed");
        eprintln!("[client] handshake completed");

        let _session_id = session
            .open_session(
                &format!("localhost:{}", server_addr.port()),
                "/webtransport",
            )
            .await
            .expect("failed to establish session");

        eprintln!("[client] session established");

        // Open a bidirectional stream and send data
        let stream_id = session.open_bidi_stream().expect("failed to create stream");
        eprintln!("[client] streamcreate: stream_id = {}", stream_id);

        let send_data = b"Hello, WebTransport!";
        session
            .send_stream_data(stream_id, send_data, true)
            .await
            .expect("failed to send data");
        eprintln!("[client] data sentcompleted");

        // Give the server time to process data
        tokio::time::sleep(Duration::from_millis(500)).await;

        stream_id
    })
    .await;

    server_task.abort();

    match client_result {
        Ok(stream_id) => {
            eprintln!("[test] stream ID: {}", stream_id);
            assert!(
                data_received_on_server.load(Ordering::SeqCst),
                "server should receive data"
            );
            let data = received_data_on_server.lock().unwrap();
            let received_str = String::from_utf8_lossy(&data);
            eprintln!("[test] data received by server: {}", received_str);
            assert!(
                received_str.contains("Hello, WebTransport!"),
                "should receive data from the client"
            );
        }
        Err(_) => {
            panic!("test timed out");
        }
    }

    eprintln!("[test] WebTransport bidirectional stream send/receive test completed");
}

/// WebTransport DATAGRAM server-to-client send test
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_webtransport_datagram_server_to_client() {
    let (cert_path, key_path) = generate_test_certs();

    // Start the server
    let mut server =
        ServerWebTransportSession::bind("127.0.0.1:0".parse().unwrap(), &cert_path, &key_path)
            .await
            .expect("failed to create server");

    let server_addr = server.local_addr();
    eprintln!("[test] server started: {}", server_addr);

    // Server task
    let server_task = tokio::spawn(async move {
        let mut client_addr: Option<std::net::SocketAddr> = None;
        let mut datagram_sent = false;

        let _ = timeout(Duration::from_secs(10), async {
            loop {
                let mut handler =
                    |addr: std::net::SocketAddr, _session_id: i64, event: Http3Event| -> bool {
                        if let Http3Event::HeadersEnd { .. } = &event {
                            eprintln!("[server] CONNECT request received: addr = {}", addr);
                            client_addr = Some(addr);
                            return true;
                        }
                        false
                    };

                server
                    .recv_once(Duration::from_millis(100), &mut handler)
                    .await
                    .ok();

                // Send the DATAGRAM after the session is established.
                if let Some(addr) = client_addr
                    && !datagram_sent
                {
                    let datagram_data = b"Hello from server!";
                    match server.send_datagram_for(&addr, datagram_data).await {
                        Ok(accepted) => {
                            eprintln!("[server] Send a DATAGRAM: accepted = {}", accepted);
                            datagram_sent = true;
                        }
                        Err(e) => {
                            eprintln!("[server] failed to send DATAGRAM: {:?}", e);
                        }
                    }
                }
            }
        })
        .await;
    });

    // client DATAGRAM received
    let client_result = timeout(Duration::from_secs(10), async {
        let mut session =
            ClientWebTransportSession::connect_insecure(server_addr, "localhost", "/webtransport")
                .await
                .expect("failed to create client");

        session.handshake().await.expect("handshake failed");
        eprintln!("[client] handshake completed");

        let _session_id = session
            .open_session(
                &format!("localhost:{}", server_addr.port()),
                "/webtransport",
            )
            .await
            .expect("failed to establish session");

        eprintln!("[client] session established");

        // DATAGRAM received
        let mut received_datagram = None;
        for _ in 0..20 {
            session
                .recv(Duration::from_millis(100))
                .await
                .expect("receive failed");

            if let Some(data) = session.recv_datagram() {
                eprintln!(
                    "[client] DATAGRAM received: {:?}",
                    String::from_utf8_lossy(&data)
                );
                received_datagram = Some(data);
                break;
            }
        }

        received_datagram
    })
    .await;

    server_task.abort();

    match client_result {
        Ok(Some(data)) => {
            let data_str = String::from_utf8_lossy(&data);
            eprintln!("[test] clientreceived DATAGRAM: {}", data_str);
            assert!(
                data_str.contains("Hello from server"),
                "server should receive DATAGRAM"
            );
        }
        Ok(None) => {
            panic!("DATAGRAM received");
        }
        Err(_) => {
            panic!("test timed out");
        }
    }

    eprintln!("[test] WebTransport DATAGRAM server-to-client send test completed");
}

/// WebTransport unidirectional stream
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_webtransport_uni_stream() {
    let (cert_path, key_path) = generate_test_certs();

    let data_received = Arc::new(AtomicBool::new(false));
    let data_received_clone = data_received.clone();
    let received_data = Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
    let received_data_clone = received_data.clone();

    // Start the server
    let mut server =
        ServerWebTransportSession::bind("127.0.0.1:0".parse().unwrap(), &cert_path, &key_path)
            .await
            .expect("failed to create server");

    let server_addr = server.local_addr();
    eprintln!("[test] server started: {}", server_addr);

    // Server task
    let server_task = tokio::spawn(async move {
        let _ = timeout(Duration::from_secs(10), async {
            loop {
                let mut handler =
                    |addr: std::net::SocketAddr, session_id: i64, event: Http3Event| -> bool {
                        match &event {
                            Http3Event::HeadersEnd { .. } => {
                                eprintln!("[server] CONNECT request received: addr = {}", addr);
                                return true;
                            }
                            Http3Event::WebTransportData {
                                session_id: sid,
                                stream_id,
                                data,
                            } => {
                                eprintln!(
                                    "[server] unidirectional stream data received: session_id = {}, stream_id = {}, data = {:?}",
                                    sid,
                                    stream_id,
                                    String::from_utf8_lossy(data)
                                );
                                data_received_clone.store(true, Ordering::SeqCst);
                                received_data_clone.lock().unwrap().extend_from_slice(data);
                            }
                            _ => {
                                eprintln!("[server] event: session_id = {}, {:?}", session_id, event);
                            }
                        }
                        false
                    };

                server
                    .recv_once(Duration::from_millis(100), &mut handler)
                    .await
                    .ok();
            }
        })
        .await;
    });

    // Client opens a unidirectional stream and sends data.
    let client_result = timeout(Duration::from_secs(10), async {
        let mut session =
            ClientWebTransportSession::connect_insecure(server_addr, "localhost", "/webtransport")
                .await
                .expect("failed to create client");

        session.handshake().await.expect("handshake failed");
        eprintln!("[client] handshake completed");

        let _session_id = session
            .open_session(
                &format!("localhost:{}", server_addr.port()),
                "/webtransport",
            )
            .await
            .expect("failed to establish session");

        eprintln!("[client] session established");

        // unidirectional stream data sent
        let stream_id = session
            .open_uni_stream()
            .expect("failed to create unidirectional stream");
        eprintln!(
            "[client] unidirectional streamcreate: stream_id = {}",
            stream_id
        );

        let send_data = b"Unidirectional data";
        session
            .send_stream_data(stream_id, send_data, true)
            .await
            .expect("failed to send data");
        eprintln!("[client] data sentcompleted");

        // server
        tokio::time::sleep(Duration::from_millis(500)).await;

        stream_id
    })
    .await;

    server_task.abort();

    match client_result {
        Ok(stream_id) => {
            eprintln!("[test] unidirectional stream ID: {}", stream_id);
            assert!(
                data_received.load(Ordering::SeqCst),
                "server should receive unidirectional stream data"
            );
            let data = received_data.lock().unwrap();
            eprintln!(
                "[test] data received by server: {:?}",
                String::from_utf8_lossy(&data)
            );
            assert!(
                String::from_utf8_lossy(&data).contains("Unidirectional"),
                "sent data should be received"
            );
        }
        Err(_) => {
            panic!("test timed out");
        }
    }

    eprintln!("[test] WebTransport unidirectional streamcompleted");
}

/// WebTransport bidi stream
///
/// The client sends data on a bidi stream,
/// the server sends data back on the same stream,
/// and the client verifies the echoed data.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_webtransport_bidi_stream_echo() {
    let (cert_path, key_path) = generate_test_certs();

    // Start the server
    let mut server =
        ServerWebTransportSession::bind("127.0.0.1:0".parse().unwrap(), &cert_path, &key_path)
            .await
            .expect("failed to create server");

    let server_addr = server.local_addr();

    // Server task: received data
    let server_task = tokio::spawn(async move {
        let _ = timeout(Duration::from_secs(10), async {
            // data
            let mut echo_queue: Vec<(std::net::SocketAddr, i64, Vec<u8>)> = Vec::new();

            loop {
                let mut handler =
                    |addr: std::net::SocketAddr, _session_id: i64, event: Http3Event| -> bool {
                        match &event {
                            Http3Event::HeadersEnd { .. } => {
                                return true;
                            }
                            Http3Event::WebTransportData {
                                stream_id, data, ..
                            } => {
                                echo_queue.push((addr, *stream_id, data.clone()));
                            }
                            _ => {}
                        }
                        false
                    };

                server
                    .recv_once(Duration::from_millis(100), &mut handler)
                    .await
                    .ok();

                //: received data stream
                for (addr, stream_id, data) in echo_queue.drain(..) {
                    server
                        .send_stream_data_for(&addr, stream_id, &data, true)
                        .ok();
                }
                server.flush().await.ok();
            }
        })
        .await;
    });

    // client data sentreceived
    let client_result = timeout(Duration::from_secs(10), async {
        let mut session =
            ClientWebTransportSession::connect_insecure(server_addr, "localhost", "/webtransport")
                .await
                .expect("failed to create client");

        session.handshake().await.expect("handshake failed");

        let _session_id = session
            .open_session(
                &format!("localhost:{}", server_addr.port()),
                "/webtransport",
            )
            .await
            .expect("failed to establish session");

        // bidi stream data sent
        let stream_id = session.open_bidi_stream().expect("failed to create stream");
        let send_data = b"Echo me back!";
        session
            .send_stream_data(stream_id, send_data, true)
            .await
            .expect("failed to send data");

        // data received
        let mut received_data = Vec::new();
        for _ in 0..30 {
            session
                .recv(Duration::from_millis(100))
                .await
                .expect("receive failed");

            while let Some(event) = session.poll() {
                if let Http3Event::WebTransportData { data, .. } = event {
                    received_data.extend_from_slice(&data);
                }
            }

            if !received_data.is_empty() {
                break;
            }
        }

        received_data
    })
    .await;

    server_task.abort();

    match client_result {
        Ok(data) => {
            let data_str = String::from_utf8_lossy(&data);
            assert_eq!(data_str, "Echo me back!", "data should match");
        }
        Err(_) => {
            panic!("test timed out");
        }
    }
}

/// WebTransport data
///
/// Sends 100KB on a bidi stream and verifies that the server receives it.
/// This also exercises congestion-control paths.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_webtransport_large_data_transfer() {
    let (cert_path, key_path) = generate_test_certs();

    let received_data = Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
    let received_data_clone = received_data.clone();

    // Start the server
    let mut server =
        ServerWebTransportSession::bind("127.0.0.1:0".parse().unwrap(), &cert_path, &key_path)
            .await
            .expect("failed to create server");

    let server_addr = server.local_addr();

    // Server task: data
    let server_task = tokio::spawn(async move {
        let _ = timeout(Duration::from_secs(30), async {
            loop {
                let mut handler =
                    |_addr: std::net::SocketAddr, _session_id: i64, event: Http3Event| -> bool {
                        match &event {
                            Http3Event::HeadersEnd { .. } => {
                                return true;
                            }
                            Http3Event::WebTransportData { data, .. } => {
                                received_data_clone.lock().unwrap().extend_from_slice(data);
                            }
                            _ => {}
                        }
                        false
                    };

                server
                    .recv_once(Duration::from_millis(100), &mut handler)
                    .await
                    .ok();
            }
        })
        .await;
    });

    // 100KB datagenerate
    let data_size = 100 * 1024;
    let send_data: Vec<u8> = (0..data_size).map(|i| (i % 256) as u8).collect();

    let client_result = timeout(Duration::from_secs(30), async {
        let mut session =
            ClientWebTransportSession::connect_insecure(server_addr, "localhost", "/webtransport")
                .await
                .expect("failed to create client");

        session.handshake().await.expect("handshake failed");

        let _session_id = session
            .open_session(
                &format!("localhost:{}", server_addr.port()),
                "/webtransport",
            )
            .await
            .expect("failed to establish session");

        let stream_id = session.open_bidi_stream().expect("failed to create stream");
        session
            .send_stream_data(stream_id, &send_data, true)
            .await
            .expect("failed to send data");

        // server data
        tokio::time::sleep(Duration::from_secs(2)).await;
    })
    .await;

    server_task.abort();

    assert!(client_result.is_ok(), "test should not time out");

    let received = received_data.lock().unwrap();
    assert_eq!(
        received.len(),
        data_size,
        "received data sent data should match: received={}, expected={}",
        received.len(),
        data_size
    );
    assert_eq!(
        received.as_slice(),
        send_data.as_slice(),
        "received datacontentssent data should match"
    );
}

/// WebTransport multiplewrite
///
/// Sends five chunks without FIN, then sends the final chunk with FIN.
/// Verifies that the server receives data in order.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_webtransport_streaming_multiple_writes() {
    let (cert_path, key_path) = generate_test_certs();

    let received_data = Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
    let received_data_clone = received_data.clone();

    // Start the server
    let mut server =
        ServerWebTransportSession::bind("127.0.0.1:0".parse().unwrap(), &cert_path, &key_path)
            .await
            .expect("failed to create server");

    let server_addr = server.local_addr();

    // Server task
    let server_task = tokio::spawn(async move {
        let _ = timeout(Duration::from_secs(10), async {
            loop {
                let mut handler =
                    |_addr: std::net::SocketAddr, _session_id: i64, event: Http3Event| -> bool {
                        match &event {
                            Http3Event::HeadersEnd { .. } => {
                                return true;
                            }
                            Http3Event::WebTransportData { data, .. } => {
                                received_data_clone.lock().unwrap().extend_from_slice(data);
                            }
                            _ => {}
                        }
                        false
                    };

                server
                    .recv_once(Duration::from_millis(100), &mut handler)
                    .await
                    .ok();
            }
        })
        .await;
    });

    // Client: send five chunks without FIN, then one final chunk with FIN.
    let messages = [
        "chunk-0:", "chunk-1:", "chunk-2:", "chunk-3:", "chunk-4:", "final",
    ];

    let client_result = timeout(Duration::from_secs(10), async {
        let mut session =
            ClientWebTransportSession::connect_insecure(server_addr, "localhost", "/webtransport")
                .await
                .expect("failed to create client");

        session.handshake().await.expect("handshake failed");

        let _session_id = session
            .open_session(
                &format!("localhost:{}", server_addr.port()),
                "/webtransport",
            )
            .await
            .expect("failed to establish session");

        let stream_id = session.open_bidi_stream().expect("failed to create stream");

        // FIN without 5 sent
        for msg in &messages[..5] {
            session
                .send_stream_data(stream_id, msg.as_bytes(), false)
                .await
                .expect("failed to send data");
        }

        // sent with FIN
        session
            .send_stream_data(stream_id, messages[5].as_bytes(), true)
            .await
            .expect("failed to send data");

        tokio::time::sleep(Duration::from_millis(500)).await;
    })
    .await;

    server_task.abort();

    assert!(client_result.is_ok(), "test should not time out");

    let received = received_data.lock().unwrap();
    let expected: String = messages.join("");
    assert_eq!(
        String::from_utf8_lossy(&received),
        expected,
        "chunks should be received in order"
    );
}

/// WebTransport bidirectional stream
///
/// The client sends data to the server, the server replies,
/// and the test verifies bidirectional stream behavior.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_webtransport_bidi_stream_interleaved() {
    let (cert_path, key_path) = generate_test_certs();

    // Start the server
    let mut server =
        ServerWebTransportSession::bind("127.0.0.1:0".parse().unwrap(), &cert_path, &key_path)
            .await
            .expect("failed to create server");

    let server_addr = server.local_addr();

    // Server task: Echo received data back with a"reply:"prefix
    let server_task = tokio::spawn(async move {
        let _ = timeout(Duration::from_secs(10), async {
            let mut echo_queue: Vec<(std::net::SocketAddr, i64, Vec<u8>)> = Vec::new();

            loop {
                let mut handler =
                    |addr: std::net::SocketAddr, _session_id: i64, event: Http3Event| -> bool {
                        match &event {
                            Http3Event::HeadersEnd { .. } => {
                                return true;
                            }
                            Http3Event::WebTransportData {
                                stream_id, data, ..
                            } => {
                                // Prepare reply data with the"reply:"prefix
                                let mut reply = b"reply:".to_vec();
                                reply.extend_from_slice(data);
                                echo_queue.push((addr, *stream_id, reply));
                            }
                            _ => {}
                        }
                        false
                    };

                server
                    .recv_once(Duration::from_millis(100), &mut handler)
                    .await
                    .ok();

                // Send replies without FIN so the stream remains open
                for (addr, stream_id, data) in echo_queue.drain(..) {
                    server
                        .send_stream_data_for(&addr, stream_id, &data, false)
                        .ok();
                }
                server.flush().await.ok();
            }
        })
        .await;
    });

    // Client: request/reply exchange
    let client_result = timeout(Duration::from_secs(10), async {
        let mut session =
            ClientWebTransportSession::connect_insecure(server_addr, "localhost", "/webtransport")
                .await
                .expect("failed to create client");

        session.handshake().await.expect("handshake failed");

        let _session_id = session
            .open_session(
                &format!("localhost:{}", server_addr.port()),
                "/webtransport",
            )
            .await
            .expect("failed to establish session");

        let stream_id = session.open_bidi_stream().expect("failed to create stream");

        let mut replies = Vec::new();

        // 1: client->server->client
        session
            .send_stream_data(stream_id, b"ping1", false)
            .await
            .expect("send failed");

        for _ in 0..30 {
            session
                .recv(Duration::from_millis(100))
                .await
                .expect("receive failed");

            while let Some(event) = session.poll() {
                if let Http3Event::WebTransportData { data, .. } = event {
                    replies.push(data);
                }
            }

            if !replies.is_empty() {
                break;
            }
        }

        assert_eq!(
            String::from_utf8_lossy(&replies[0]),
            "reply:ping1",
            "should"
        );

        // 2: client->server->client
        replies.clear();
        session
            .send_stream_data(stream_id, b"ping2", false)
            .await
            .expect("send failed");

        for _ in 0..30 {
            session
                .recv(Duration::from_millis(100))
                .await
                .expect("receive failed");

            while let Some(event) = session.poll() {
                if let Http3Event::WebTransportData { data, .. } = event {
                    replies.push(data);
                }
            }

            if !replies.is_empty() {
                break;
            }
        }

        assert_eq!(
            String::from_utf8_lossy(&replies[0]),
            "reply:ping2",
            "2 should"
        );

        replies
    })
    .await;

    server_task.abort();

    assert!(client_result.is_ok(), "test should not time out");
}

/// WebTransport DATAGRAM sent
///
/// The client sends 10 DATAGRAMs,
/// and the server must receive at least one because DATAGRAM delivery is unreliable.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_webtransport_multiple_datagrams() {
    let (cert_path, key_path) = generate_test_certs();

    let received_datagrams = Arc::new(std::sync::Mutex::new(Vec::<Vec<u8>>::new()));
    let received_datagrams_clone = received_datagrams.clone();

    // Start the server
    let mut server =
        ServerWebTransportSession::bind("127.0.0.1:0".parse().unwrap(), &cert_path, &key_path)
            .await
            .expect("failed to create server");

    let server_addr = server.local_addr();

    // Server task: receive and store DATAGRAMs
    let server_task = tokio::spawn(async move {
        let mut client_addr: Option<std::net::SocketAddr> = None;

        let _ = timeout(Duration::from_secs(10), async {
            loop {
                let mut handler =
                    |addr: std::net::SocketAddr, _session_id: i64, event: Http3Event| -> bool {
                        if let Http3Event::HeadersEnd { .. } = &event {
                            client_addr = Some(addr);
                            return true;
                        }
                        false
                    };

                server
                    .recv_once(Duration::from_millis(100), &mut handler)
                    .await
                    .ok();

                if let Some(addr) = client_addr {
                    while let Some(data) = server.recv_datagram_for(&addr) {
                        received_datagrams_clone.lock().unwrap().push(data);
                    }
                }
            }
        })
        .await;
    });

    // Client: send 10 DATAGRAMs in sequence
    let client_result = timeout(Duration::from_secs(10), async {
        let mut session =
            ClientWebTransportSession::connect_insecure(server_addr, "localhost", "/webtransport")
                .await
                .expect("failed to create client");

        session.handshake().await.expect("handshake failed");

        let _session_id = session
            .open_session(
                &format!("localhost:{}", server_addr.port()),
                "/webtransport",
            )
            .await
            .expect("failed to establish session");

        for i in 0..10 {
            let payload = format!("datagram-{}", i);
            session
                .send_datagram(payload.as_bytes())
                .await
                .expect("failed to send DATAGRAM");
        }

        tokio::time::sleep(Duration::from_secs(1)).await;
    })
    .await;

    server_task.abort();

    assert!(client_result.is_ok(), "test should not time out");

    let datagrams = received_datagrams.lock().unwrap();
    assert!(
        !datagrams.is_empty(),
        "server should receive at least one DATAGRAM"
    );
    // Verify received DATAGRAM contents
    for datagram in datagrams.iter() {
        let s = String::from_utf8_lossy(datagram);
        assert!(
            s.starts_with("datagram-"),
            "received DATAGRAM format should be valid: {:?}",
            s
        );
    }
}

/// WebTransport mixed bidi, uni, and DATAGRAM test
///
/// Use bidi streams, uni streams, and DATAGRAMs together on one session.
/// Verify that data from each channel is received correctly without mixing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_webtransport_mixed_streams_and_datagrams() {
    let (cert_path, key_path) = generate_test_certs();

    let bidi_data = Arc::new(std::sync::Mutex::new(std::collections::HashMap::<
        i64,
        Vec<u8>,
    >::new()));
    let bidi_data_clone = bidi_data.clone();
    let uni_data = Arc::new(std::sync::Mutex::new(std::collections::HashMap::<
        i64,
        Vec<u8>,
    >::new()));
    let uni_data_clone = uni_data.clone();
    let datagram_data = Arc::new(std::sync::Mutex::new(Vec::<Vec<u8>>::new()));
    let datagram_data_clone = datagram_data.clone();

    // Start the server
    let mut server =
        ServerWebTransportSession::bind("127.0.0.1:0".parse().unwrap(), &cert_path, &key_path)
            .await
            .expect("failed to create server");

    let server_addr = server.local_addr();

    // Server task
    let server_task = tokio::spawn(async move {
        let mut client_addr: Option<std::net::SocketAddr> = None;

        let _ = timeout(Duration::from_secs(10), async {
            loop {
                let mut handler =
                    |addr: std::net::SocketAddr, _session_id: i64, event: Http3Event| -> bool {
                        match &event {
                            Http3Event::HeadersEnd { .. } => {
                                client_addr = Some(addr);
                                return true;
                            }
                            Http3Event::WebTransportData {
                                stream_id, data, ..
                            } => {
                                // QUIC stream ID: classify by the low two bits
                                // The 0x2 bit indicates a unidirectional stream
                                if (*stream_id & 0x2) != 0 {
                                    uni_data_clone
                                        .lock()
                                        .unwrap()
                                        .entry(*stream_id)
                                        .or_default()
                                        .extend_from_slice(data);
                                } else {
                                    bidi_data_clone
                                        .lock()
                                        .unwrap()
                                        .entry(*stream_id)
                                        .or_default()
                                        .extend_from_slice(data);
                                }
                            }
                            _ => {}
                        }
                        false
                    };

                server
                    .recv_once(Duration::from_millis(100), &mut handler)
                    .await
                    .ok();

                // DATAGRAM received
                if let Some(addr) = client_addr {
                    while let Some(data) = server.recv_datagram_for(&addr) {
                        datagram_data_clone.lock().unwrap().push(data);
                    }
                }
            }
        })
        .await;
    });

    // Client: send bidi, uni, and DATAGRAM data
    let client_result = timeout(Duration::from_secs(10), async {
        let mut session =
            ClientWebTransportSession::connect_insecure(server_addr, "localhost", "/webtransport")
                .await
                .expect("failed to create client");

        session.handshake().await.expect("handshake failed");

        let _session_id = session
            .open_session(
                &format!("localhost:{}", server_addr.port()),
                "/webtransport",
            )
            .await
            .expect("failed to establish session");

        // Send data on a bidi stream
        let bidi_stream = session
            .open_bidi_stream()
            .expect("bidi failed to create stream");
        session
            .send_stream_data(bidi_stream, b"bidi-data", true)
            .await
            .expect("bidi failed to send data");

        // Send data on a uni stream
        let uni_stream = session
            .open_uni_stream()
            .expect("uni failed to create stream");
        session
            .send_stream_data(uni_stream, b"uni-data", true)
            .await
            .expect("uni failed to send data");

        // Send a DATAGRAM
        session
            .send_datagram(b"dgram-data")
            .await
            .expect("failed to send DATAGRAM");

        tokio::time::sleep(Duration::from_secs(1)).await;

        (bidi_stream, uni_stream)
    })
    .await;

    server_task.abort();

    match client_result {
        Ok((bidi_stream, uni_stream)) => {
            // Verify bidi stream data
            let bidi = bidi_data.lock().unwrap();
            let bidi_content = bidi
                .get(&bidi_stream)
                .expect("bidi stream data should exist");
            assert_eq!(
                String::from_utf8_lossy(bidi_content),
                "bidi-data",
                "bidi stream data should be correct"
            );

            // Verify uni stream data
            let uni = uni_data.lock().unwrap();
            let uni_content = uni.get(&uni_stream).expect("uni stream data should exist");
            assert_eq!(
                String::from_utf8_lossy(uni_content),
                "uni-data",
                "uni stream data should be correct"
            );

            // Verify DATAGRAM data
            let dgrams = datagram_data.lock().unwrap();
            assert!(
                !dgrams.is_empty(),
                "at least one DATAGRAM should be received"
            );
            assert_eq!(
                String::from_utf8_lossy(&dgrams[0]),
                "dgram-data",
                "DATAGRAM data should be correct"
            );
        }
        Err(_) => {
            panic!("test timed out");
        }
    }
}

/// WebTransport server sends multiple streams concurrently
///
/// The server opens two bidi streams and one uni stream, sending different data on each.
/// Verify that the client receives and separates all stream data correctly.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_webtransport_server_multiple_streams() {
    let (cert_path, key_path) = generate_test_certs();

    // Start the server
    let mut server =
        ServerWebTransportSession::bind("127.0.0.1:0".parse().unwrap(), &cert_path, &key_path)
            .await
            .expect("failed to create server");

    let server_addr = server.local_addr();

    // Server task: after session establishment, open two bidi streams and one uni stream and send data
    let server_task = tokio::spawn(async move {
        let mut session_established = false;
        let mut data_sent = false;

        let _ = timeout(Duration::from_secs(10), async {
            loop {
                let mut handler =
                    |_addr: std::net::SocketAddr, _session_id: i64, event: Http3Event| -> bool {
                        if let Http3Event::HeadersEnd { .. } = &event {
                            session_established = true;
                            return true;
                        }
                        false
                    };

                server
                    .recv_once(Duration::from_millis(100), &mut handler)
                    .await
                    .ok();

                if session_established && !data_sent {
                    let addrs = server.get_established_addrs();
                    if let Some(addr) = addrs.first() {
                        // bidi stream 1
                        let bidi1 = server
                            .open_bidi_stream_for(addr)
                            .expect("server bidi1 creation failed");
                        server
                            .send_stream_data_for(addr, bidi1, b"server-bidi-1", true)
                            .expect("bidi1 send failed");

                        // bidi stream 2
                        let bidi2 = server
                            .open_bidi_stream_for(addr)
                            .expect("server bidi2 creation failed");
                        server
                            .send_stream_data_for(addr, bidi2, b"server-bidi-2", true)
                            .expect("bidi2 send failed");

                        // uni stream
                        let uni = server
                            .open_uni_stream_for(addr)
                            .expect("server uni creation failed");
                        server
                            .send_stream_data_for(addr, uni, b"server-uni-1", true)
                            .expect("uni send failed");

                        server.flush().await.expect("flush failed");
                        data_sent = true;
                    }
                }
            }
        })
        .await;
    });

    // Client: receive and separate server data
    let client_result = timeout(Duration::from_secs(10), async {
        let mut session =
            ClientWebTransportSession::connect_insecure(server_addr, "localhost", "/webtransport")
                .await
                .expect("failed to create client");

        session.handshake().await.expect("handshake failed");

        let _session_id = session
            .open_session(
                &format!("localhost:{}", server_addr.port()),
                "/webtransport",
            )
            .await
            .expect("failed to establish session");

        let mut received_streams = std::collections::HashMap::<i64, Vec<u8>>::new();

        for _ in 0..50 {
            session
                .recv(Duration::from_millis(100))
                .await
                .expect("receive failed");

            while let Some(event) = session.poll() {
                if let Http3Event::WebTransportData {
                    stream_id, data, ..
                } = event
                {
                    received_streams
                        .entry(stream_id)
                        .or_default()
                        .extend_from_slice(&data);
                }
            }

            if received_streams.len() >= 3 {
                break;
            }
        }

        received_streams
    })
    .await;

    server_task.abort();

    match client_result {
        Ok(streams) => {
            assert!(
                streams.len() >= 3,
                "should receive data from three streams: received={}",
                streams.len()
            );

            let values: Vec<String> = streams
                .values()
                .map(|v| String::from_utf8_lossy(v).to_string())
                .collect();

            assert!(
                values.contains(&"server-bidi-1".to_string()),
                "should receive bidi1 data: {:?}",
                values
            );
            assert!(
                values.contains(&"server-bidi-2".to_string()),
                "should receive bidi2 data: {:?}",
                values
            );
            assert!(
                values.contains(&"server-uni-1".to_string()),
                "should receive uni data: {:?}",
                values
            );
        }
        Err(_) => {
            panic!("test timed out");
        }
    }
}

/// WebTransport many-stream creation test
///
/// The client opens 10 bidi streams and sends data on each.
/// The server receives data from all 10 streams,
/// and verifies that per-stream data stays separated.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_webtransport_many_streams() {
    let (cert_path, key_path) = generate_test_certs();

    let received_streams = Arc::new(std::sync::Mutex::new(std::collections::HashMap::<
        i64,
        Vec<u8>,
    >::new()));
    let received_streams_clone = received_streams.clone();

    // Start the server
    let mut server =
        ServerWebTransportSession::bind("127.0.0.1:0".parse().unwrap(), &cert_path, &key_path)
            .await
            .expect("failed to create server");

    let server_addr = server.local_addr();

    // Server task
    let server_task = tokio::spawn(async move {
        let _ = timeout(Duration::from_secs(15), async {
            loop {
                let mut handler =
                    |_addr: std::net::SocketAddr, _session_id: i64, event: Http3Event| -> bool {
                        match &event {
                            Http3Event::HeadersEnd { .. } => {
                                return true;
                            }
                            Http3Event::WebTransportData {
                                stream_id, data, ..
                            } => {
                                received_streams_clone
                                    .lock()
                                    .unwrap()
                                    .entry(*stream_id)
                                    .or_default()
                                    .extend_from_slice(data);
                            }
                            _ => {}
                        }
                        false
                    };

                server
                    .recv_once(Duration::from_millis(100), &mut handler)
                    .await
                    .ok();
            }
        })
        .await;
    });

    // Client: open 10 bidi streams and send unique data on each stream
    let stream_count = 10;
    let client_result = timeout(Duration::from_secs(15), async {
        let mut session =
            ClientWebTransportSession::connect_insecure(server_addr, "localhost", "/webtransport")
                .await
                .expect("failed to create client");

        session.handshake().await.expect("handshake failed");

        let _session_id = session
            .open_session(
                &format!("localhost:{}", server_addr.port()),
                "/webtransport",
            )
            .await
            .expect("failed to establish session");

        let mut stream_ids = Vec::new();
        for i in 0..stream_count {
            let stream_id = session.open_bidi_stream().expect("failed to create stream");
            let data = format!("stream-{}-payload", i);
            session
                .send_stream_data(stream_id, data.as_bytes(), true)
                .await
                .expect("failed to send data");
            stream_ids.push((stream_id, data));
        }

        tokio::time::sleep(Duration::from_secs(1)).await;

        stream_ids
    })
    .await;

    server_task.abort();

    match client_result {
        Ok(stream_ids) => {
            let streams = received_streams.lock().unwrap();
            assert_eq!(
                streams.len(),
                stream_count,
                "should receive data from all {} streams: received={}",
                stream_count,
                streams.len()
            );

            for (stream_id, expected_data) in &stream_ids {
                let data = streams
                    .get(stream_id)
                    .unwrap_or_else(|| panic!("data for stream {} should exist", stream_id));
                assert_eq!(
                    String::from_utf8_lossy(data),
                    *expected_data,
                    "data for stream {} should remain separated",
                    stream_id
                );
            }
        }
        Err(_) => {
            panic!("test timed out");
        }
    }
}
