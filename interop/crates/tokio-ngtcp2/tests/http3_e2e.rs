//! HTTP/3 client/server I/O tests
//!
//! HTTP/3 request/response tests using real network I/O

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use rcgen::{CertificateParams, KeyPair};
use serial_test::serial;
use tokio::time::timeout;

use ngtcp2::{Header, Http3Event};
use tokio_ngtcp2::{Client, Server};

/// Generate a certificate and private key for tests
fn generate_test_certs() -> (PathBuf, PathBuf) {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let unique_id = COUNTER.fetch_add(1, Ordering::SeqCst);
    let temp_dir =
        std::env::temp_dir().join(format!("http3_test_{}_{}", std::process::id(), unique_id));
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

/// HTTP/3 GET request/response test
#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_http3_get_request() {
    let (cert_path, key_path) = generate_test_certs();

    let request_received = Arc::new(AtomicBool::new(false));
    let request_received_clone = request_received.clone();

    // Start the server
    let mut server = Server::bind(
        "127.0.0.1:0".parse().unwrap(),
        &cert_path,
        &key_path,
        None,
        None,
    )
    .await
    .expect("failed to create server");

    let server_addr = server.local_addr();
    eprintln!("[test] server started: {}", server_addr);

    // Server task
    let server_task = tokio::spawn(async move {
        let result = timeout(
            Duration::from_secs(10),
            server.run(move |addr, event| {
                eprintln!("[server] event received: addr = {}", addr);
                match event {
                    Http3Event::HeadersBegin { stream_id } => {
                        eprintln!("[server] HeadersBegin: stream_id = {}", stream_id);
                        None
                    }
                    Http3Event::Header { stream_id, header } => {
                        eprintln!(
                            "[server] Header: stream_id = {}, name = {:?}, value = {:?}",
                            stream_id,
                            header.name_str(),
                            header.value_str()
                        );
                        None
                    }
                    Http3Event::HeadersEnd { stream_id, fin } => {
                        eprintln!(
                            "[server] HeadersEnd: stream_id = {}, fin = {}",
                            stream_id, fin
                        );
                        request_received_clone.store(true, Ordering::SeqCst);
                        // 200 OK response
                        Some((vec![Header::status(200)], Vec::new()))
                    }
                    Http3Event::Data { stream_id, data } => {
                        eprintln!(
                            "[server] Data: stream_id = {}, len = {}",
                            stream_id,
                            data.len()
                        );
                        None
                    }
                    _ => {
                        eprintln!("[server] Other event: {:?}", event);
                        None
                    }
                }
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

    // Create the client
    let client_result = timeout(Duration::from_secs(10), async {
        let mut client = Client::connect_insecure_default(server_addr, "localhost")
            .await
            .expect("failed to create client");

        // handshake
        client.handshake().await.expect("handshake failed");
        eprintln!("[client] handshake completed");

        // Send a GET request
        let headers = vec![
            Header::method("GET"),
            Header::scheme("https"),
            Header::authority(&format!("localhost:{}", server_addr.port())),
            Header::path("/"),
        ];

        let stream_id = client
            .send_request(&headers)
            .expect("failed to send request");
        eprintln!("[client] request sent: stream_id = {}", stream_id);

        // Send HTTP/3 data
        client.flush().await.expect("flush failed");

        // Wait for the response with a short sleep
        tokio::time::sleep(Duration::from_millis(500)).await;

        stream_id
    })
    .await;

    server_task.abort();

    match client_result {
        Ok(stream_id) => {
            eprintln!(
                "[test] HTTP/3 GET request test completed: stream_id = {}",
                stream_id
            );
            assert!(
                request_received.load(Ordering::SeqCst),
                "server should receive the request"
            );
        }
        Err(_) => {
            panic!("test timed out");
        }
    }
}

/// HTTP/3 POST request test
#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_http3_post_request() {
    let (cert_path, key_path) = generate_test_certs();

    let request_received = Arc::new(AtomicBool::new(false));
    let request_received_clone = request_received.clone();

    // Start the server
    let mut server = Server::bind(
        "127.0.0.1:0".parse().unwrap(),
        &cert_path,
        &key_path,
        None,
        None,
    )
    .await
    .expect("failed to create server");

    let server_addr = server.local_addr();

    // Server task
    let server_task = tokio::spawn(async move {
        let _ = timeout(
            Duration::from_secs(10),
            server.run(move |_addr, event| match event {
                Http3Event::HeadersEnd { stream_id, .. } => {
                    eprintln!("[server] POST request received: stream_id = {}", stream_id);
                    request_received_clone.store(true, Ordering::SeqCst);
                    Some((vec![Header::status(201)], Vec::new()))
                }
                _ => None,
            }),
        )
        .await;
    });

    // Create the client
    let client_result = timeout(Duration::from_secs(10), async {
        let mut client = Client::connect_insecure_default(server_addr, "localhost")
            .await
            .expect("failed to create client");

        // handshake
        client.handshake().await.expect("handshake failed");

        // Send a POST request
        let headers = vec![
            Header::method("POST"),
            Header::scheme("https"),
            Header::authority(&format!("localhost:{}", server_addr.port())),
            Header::path("/api/data"),
            Header::new(b"content-type", b"application/json"),
        ];

        let stream_id = client
            .send_request(&headers)
            .expect("failed to send request");
        eprintln!("[client] POST request sent: stream_id = {}", stream_id);

        // Send HTTP/3 data
        client.flush().await.expect("flush failed");

        tokio::time::sleep(Duration::from_millis(500)).await;

        stream_id
    })
    .await;

    server_task.abort();

    assert!(client_result.is_ok(), "test should not time out");
    assert!(
        request_received.load(Ordering::SeqCst),
        "server should receive the request"
    );

    eprintln!("[test] HTTP/3 POST request test completed");
}

/// Concurrent request handling test
#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_http3_concurrent_requests() {
    let (cert_path, key_path) = generate_test_certs();

    use std::sync::atomic::AtomicUsize;
    let request_count = Arc::new(AtomicUsize::new(0));
    let request_count_clone = request_count.clone();

    // Start the server
    let mut server = Server::bind(
        "127.0.0.1:0".parse().unwrap(),
        &cert_path,
        &key_path,
        None,
        None,
    )
    .await
    .expect("failed to create server");

    let server_addr = server.local_addr();

    // Server task
    let server_task = tokio::spawn(async move {
        let _ = timeout(
            Duration::from_secs(10),
            server.run(move |_addr, event| {
                if let Http3Event::HeadersEnd { stream_id, .. } = event {
                    let count = request_count_clone.fetch_add(1, Ordering::SeqCst) + 1;
                    eprintln!(
                        "[server] request {} received: stream_id = {}",
                        count, stream_id
                    );
                    Some((vec![Header::status(200)], Vec::new()))
                } else {
                    None
                }
            }),
        )
        .await;
    });

    // Create the client and send multiple requests
    let client_result = timeout(Duration::from_secs(10), async {
        let mut client = Client::connect_insecure_default(server_addr, "localhost")
            .await
            .expect("failed to create client");

        // handshake
        client.handshake().await.expect("handshake failed");

        // Send multiple requests
        let request_paths = ["/", "/api/users", "/api/data"];
        let mut stream_ids = Vec::new();

        for path in &request_paths {
            let headers = vec![
                Header::method("GET"),
                Header::scheme("https"),
                Header::authority(&format!("localhost:{}", server_addr.port())),
                Header::path(path),
            ];

            let stream_id = client
                .send_request(&headers)
                .expect("failed to send request");
            stream_ids.push(stream_id);
            eprintln!(
                "[client] request sent: path = {}, stream_id = {}",
                path, stream_id
            );
        }

        // Send HTTP/3 data
        client.flush().await.expect("flush failed");

        tokio::time::sleep(Duration::from_millis(500)).await;

        stream_ids
    })
    .await;

    server_task.abort();

    match client_result {
        Ok(stream_ids) => {
            eprintln!("[test] requests sent: {}", stream_ids.len());
            let received = request_count.load(Ordering::SeqCst);
            eprintln!("[test] requests received by server: {}", received);
            assert!(received >= 1, "at least one request should be received");
        }
        Err(_) => {
            panic!("test timed out");
        }
    }

    eprintln!("[test] HTTP/3 concurrentrequest test completed");
}

/// HTTP/3 POST request with JSON body test
#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_http3_request_with_body() {
    let (cert_path, key_path) = generate_test_certs();

    let body_received = Arc::new(AtomicBool::new(false));
    let body_received_clone = body_received.clone();
    let received_body = Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
    let received_body_clone = received_body.clone();

    // Start the server
    let mut server = Server::bind(
        "127.0.0.1:0".parse().unwrap(),
        &cert_path,
        &key_path,
        None,
        None,
    )
    .await
    .expect("failed to create server");

    let server_addr = server.local_addr();
    eprintln!("[test] server started: {}", server_addr);

    // Server task
    let server_task = tokio::spawn(async move {
        let _ = timeout(
            Duration::from_secs(10),
            server.run(move |_addr, event| {
                match event {
                    Http3Event::Data { stream_id, data } => {
                        eprintln!(
                            "[server] Data received: stream_id = {}, data = {:?}",
                            stream_id,
                            String::from_utf8_lossy(&data)
                        );
                        body_received_clone.store(true, Ordering::SeqCst);
                        received_body_clone.lock().unwrap().extend_from_slice(&data);
                        None
                    }
                    Http3Event::HeadersEnd { stream_id, .. } => {
                        eprintln!("[server] HeadersEnd: stream_id = {}", stream_id);
                        // Delay the response until Data is received
                        None
                    }
                    Http3Event::StreamEnd { stream_id } => {
                        eprintln!("[server] StreamEnd: stream_id = {}", stream_id);
                        // Return the response when the stream ends
                        Some((vec![Header::status(200)], Vec::new()))
                    }
                    _ => None,
                }
            }),
        )
        .await;
    });

    // Create the client
    let client_result = timeout(Duration::from_secs(10), async {
        let mut client = Client::connect_insecure_default(server_addr, "localhost")
            .await
            .expect("failed to create client");

        // handshake
        client.handshake().await.expect("handshake failed");
        eprintln!("[client] handshake completed");

        // Send a POST request with a body
        let body = br#"{"name":"test","value": 123}"#.to_vec();
        let headers = vec![
            Header::method("POST"),
            Header::scheme("https"),
            Header::authority(&format!("localhost:{}", server_addr.port())),
            Header::path("/api/data"),
            Header::new(b"content-type", b"application/json"),
            Header::new(b"content-length", body.len().to_string().as_bytes()),
        ];

        let stream_id = client
            .send_request_with_body(&headers, body)
            .expect("failed to send request");
        eprintln!("[client] POST request sent: stream_id = {}", stream_id);

        // Send HTTP/3 data
        client.flush().await.expect("flush failed");

        // Give the server time to process data
        tokio::time::sleep(Duration::from_millis(500)).await;

        stream_id
    })
    .await;

    server_task.abort();

    assert!(client_result.is_ok(), "test should not time out");
    assert!(
        body_received.load(Ordering::SeqCst),
        "server should receive the request body"
    );

    let body_data = received_body.lock().unwrap();
    assert!(!body_data.is_empty(), "received body should not be empty");
    eprintln!(
        "[test] received body: {:?}",
        String::from_utf8_lossy(&body_data)
    );

    eprintln!("[test] HTTP/3 POST request + body send test completed");
}

/// HTTP/3 response body receive test
#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_http3_response_body() {
    let (cert_path, key_path) = generate_test_certs();

    let response_body = b"Hello, HTTP/3 World!".to_vec();
    let expected_body = response_body.clone();

    // Start the server
    let mut server = Server::bind(
        "127.0.0.1:0".parse().unwrap(),
        &cert_path,
        &key_path,
        None,
        None,
    )
    .await
    .expect("failed to create server");

    let server_addr = server.local_addr();
    eprintln!("[test] server started: {}", server_addr);

    // Server task (Return a response with a body)
    let server_task = tokio::spawn(async move {
        let _ = timeout(
            Duration::from_secs(10),
            server.run(move |_addr, event| {
                if let Http3Event::HeadersEnd { stream_id, .. } = event {
                    eprintln!("[server] request received: stream_id = {}", stream_id);
                    // Return a response with a body
                    let headers = vec![
                        Header::status(200),
                        Header::new(b"content-type", b"text/plain"),
                    ];
                    return Some((headers, response_body.clone()));
                }
                None
            }),
        )
        .await;
    });

    // Create a client and receive the response body
    let client_result = timeout(Duration::from_secs(10), async {
        let mut client = Client::connect_insecure_default(server_addr, "localhost")
            .await
            .expect("failed to create client");

        // handshake
        client.handshake().await.expect("handshake failed");
        eprintln!("[client] handshake completed");

        // Send a GET request
        let headers = vec![
            Header::method("GET"),
            Header::scheme("https"),
            Header::authority(&format!("localhost:{}", server_addr.port())),
            Header::path("/"),
        ];

        let stream_id = client
            .send_request(&headers)
            .expect("failed to send request");
        eprintln!("[client] request sent: stream_id = {}", stream_id);

        // Send HTTP/3 data
        client.flush().await.expect("flush failed");

        // Receive responses
        let mut received_body = Vec::new();
        let mut response_received = false;

        for _ in 0..20 {
            client
                .recv(Duration::from_millis(100))
                .await
                .expect("receive failed");

            while let Some(event) = client.poll() {
                match event {
                    Http3Event::Data { data, .. } => {
                        eprintln!(
                            "[client] Data received: {:?}",
                            String::from_utf8_lossy(&data)
                        );
                        received_body.extend_from_slice(&data);
                    }
                    Http3Event::HeadersEnd { .. } => {
                        eprintln!("[client] HeadersEnd received");
                        response_received = true;
                    }
                    Http3Event::StreamEnd { .. } => {
                        eprintln!("[client] StreamEnd received");
                    }
                    _ => {}
                }
            }

            if response_received && !received_body.is_empty() {
                break;
            }
        }

        received_body
    })
    .await;

    server_task.abort();

    match client_result {
        Ok(received_body) => {
            eprintln!(
                "[test] received body: {:?}",
                String::from_utf8_lossy(&received_body)
            );
            assert_eq!(
                received_body, expected_body,
                "received body should match the expected value"
            );
        }
        Err(_) => {
            panic!("test timed out");
        }
    }

    eprintln!("[test] HTTP/3 response body receive test completed");
}

/// HTTP/3 stream multiplexing test
#[serial]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_http3_stream_multiplexing() {
    let (cert_path, key_path) = generate_test_certs();

    use std::sync::atomic::AtomicUsize;
    let request_count = Arc::new(AtomicUsize::new(0));
    let request_count_clone = request_count.clone();

    // Start the server
    let mut server = Server::bind(
        "127.0.0.1:0".parse().unwrap(),
        &cert_path,
        &key_path,
        None,
        None,
    )
    .await
    .expect("failed to create server");

    let server_addr = server.local_addr();
    eprintln!("[test] server started: {}", server_addr);

    // Server task
    let server_task = tokio::spawn(async move {
        let _ = timeout(
            Duration::from_secs(10),
            server.run(move |_addr, event| {
                if let Http3Event::HeadersEnd { stream_id, .. } = event {
                    let count = request_count_clone.fetch_add(1, Ordering::SeqCst) + 1;
                    eprintln!(
                        "[server] request {} received: stream_id = {}",
                        count, stream_id
                    );
                    // Return a unique response for each request
                    let body = format!("Response for stream {}", stream_id).into_bytes();
                    let headers = vec![
                        Header::status(200),
                        Header::new(b"x-stream-id", stream_id.to_string().as_bytes()),
                    ];
                    return Some((headers, body));
                }
                None
            }),
        )
        .await;
    });

    // Create a client and open multiple streams concurrently
    let client_result = timeout(Duration::from_secs(10), async {
        let mut client = Client::connect_insecure_default(server_addr, "localhost")
            .await
            .expect("failed to create client");

        // handshake
        client.handshake().await.expect("handshake failed");
        eprintln!("[client] handshake completed");

        // Send three requests concurrently
        let paths = ["/stream1", "/stream2", "/stream3"];
        let mut stream_ids = Vec::new();

        for path in &paths {
            let headers = vec![
                Header::method("GET"),
                Header::scheme("https"),
                Header::authority(&format!("localhost:{}", server_addr.port())),
                Header::path(path),
            ];

            let stream_id = client
                .send_request(&headers)
                .expect("failed to send request");
            stream_ids.push(stream_id);
            eprintln!(
                "[client] request sent: path = {}, stream_id = {}",
                path, stream_id
            );
        }

        // Send HTTP/3 data
        client.flush().await.expect("flush failed");

        // Receive responses
        let mut responses_received = 0;
        let mut bodies_received = std::collections::HashMap::new();

        for _ in 0..30 {
            client
                .recv(Duration::from_millis(100))
                .await
                .expect("receive failed");

            while let Some(event) = client.poll() {
                match event {
                    Http3Event::Data { stream_id, data } => {
                        eprintln!(
                            "[client] Data received: stream_id = {}, data = {:?}",
                            stream_id,
                            String::from_utf8_lossy(&data)
                        );
                        bodies_received
                            .entry(stream_id)
                            .or_insert_with(Vec::new)
                            .extend_from_slice(&data);
                    }
                    Http3Event::HeadersEnd { stream_id, .. } => {
                        eprintln!("[client] HeadersEnd received: stream_id = {}", stream_id);
                        responses_received += 1;
                    }
                    _ => {}
                }
            }

            if responses_received >= 3 && bodies_received.len() >= 3 {
                break;
            }
        }

        (stream_ids, responses_received, bodies_received)
    })
    .await;

    server_task.abort();

    match client_result {
        Ok((stream_ids, responses_received, bodies_received)) => {
            eprintln!(
                "[test] streams sent: {}, responses received: {}, bodies received: {}",
                stream_ids.len(),
                responses_received,
                bodies_received.len()
            );
            assert_eq!(stream_ids.len(), 3, "should open three streams");
            assert!(responses_received >= 3, "should receive three responses");
            assert!(bodies_received.len() >= 3, "should receive three bodies");

            // Check that each stream received the right response
            for stream_id in &stream_ids {
                if let Some(body) = bodies_received.get(stream_id) {
                    let body_str = String::from_utf8_lossy(body);
                    assert!(
                        body_str.contains(&stream_id.to_string()),
                        "body for stream {} should contain the stream ID",
                        stream_id
                    );
                }
            }
        }
        Err(_) => {
            panic!("test timed out");
        }
    }

    eprintln!("[test] HTTP/3 stream multiplexing test completed");
}
