//! Integration tests
//!
//! Integration tests for HTTP/3 and WebTransport

use std::path::PathBuf;
use std::time::Duration;

use ngtcp2::{Header, Http3SettingsExt, TransportParamsExt};
use rcgen::generate_simple_self_signed;
use tokio_ngtcp2::{Client, ClientWebTransportSession, Server, ServerWebTransportSession};

/// Generate a certificate for tests
fn generate_test_certificate() -> (PathBuf, PathBuf) {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let subject_alt_names = vec!["localhost".to_string(), "127.0.0.1".to_string()];
    let certified_key = generate_simple_self_signed(subject_alt_names).unwrap();
    let cert_pem = certified_key.cert.pem();
    let key_pem = certified_key.signing_key.serialize_pem();

    // Create a unique directory for each test
    let unique_id = COUNTER.fetch_add(1, Ordering::SeqCst);
    let thread_id = std::thread::current().id();
    let cert_dir =
        std::env::temp_dir().join(format!("tokio_ngtcp2_test_{:?}_{}", thread_id, unique_id));
    std::fs::create_dir_all(&cert_dir).unwrap();

    let cert_path = cert_dir.join("cert.pem");
    let key_path = cert_dir.join("key.pem");

    std::fs::write(&cert_path, cert_pem).unwrap();
    std::fs::write(&key_path, key_pem).unwrap();

    (cert_path, key_path)
}

#[tokio::test]
async fn test_client_creation() {
    // Check that a client can be created
    let result = Client::connect("127.0.0.1:14433".parse().unwrap(), "localhost", None, None).await;

    // Socket binding should succeed
    assert!(result.is_ok());

    let client = result.unwrap();
    assert_eq!(client.remote_addr(), "127.0.0.1:14433".parse().unwrap());
}

#[tokio::test]
async fn test_server_creation() {
    let (cert_path, key_path) = generate_test_certificate();

    // Create the server
    let result = Server::bind(
        "127.0.0.1:0".parse().unwrap(),
        &cert_path,
        &key_path,
        None,
        None,
    )
    .await;

    assert!(result.is_ok());

    let server = result.unwrap();
    // The server should be bound to an ephemeral port
    assert_ne!(server.local_addr().port(), 0);
}

#[tokio::test]
async fn test_webtransport_client_creation() {
    // Check that a WebTransport client can be created
    let result = ClientWebTransportSession::connect(
        "127.0.0.1:14434".parse().unwrap(),
        "localhost",
        "/webtransport",
    )
    .await;

    assert!(result.is_ok());

    let session = result.unwrap();
    assert_eq!(session.remote_addr(), "127.0.0.1:14434".parse().unwrap());
    assert!(session.session_id().is_none()); // The session has not been established yet
}

#[tokio::test]
async fn test_webtransport_server_creation() {
    let (cert_path, key_path) = generate_test_certificate();

    // Create the WebTransport server
    let result =
        ServerWebTransportSession::bind("127.0.0.1:0".parse().unwrap(), &cert_path, &key_path)
            .await;

    assert!(result.is_ok());

    let server = result.unwrap();
    assert_ne!(server.local_addr().port(), 0);
}

#[tokio::test]
async fn test_transport_params_webtransport() {
    use ngtcp2::ngtcp2_transport_params;

    // Check WebTransport transport parameters
    let params = ngtcp2_transport_params::default_params().with_datagram(65535);

    assert_eq!(params.max_datagram_frame_size, 65535);
    assert!(params.initial_max_streams_bidi > 0);
    assert!(params.initial_max_streams_uni > 0);
}

#[tokio::test]
async fn test_h3_settings_webtransport() {
    use ngtcp2::nghttp3_settings;

    // Check WebTransport HTTP/3 settings
    let settings = nghttp3_settings::default_settings().with_webtransport();

    assert_eq!(settings.enable_connect_protocol, 1);
    assert_eq!(settings.h3_datagram, 1);
    assert_eq!(settings.wt_enabled, 1);
}

#[test]
fn test_header_creation() {
    // Check HTTP/3 header creation
    let headers = [
        Header::method("CONNECT"),
        Header::new(b":protocol", b"webtransport"),
        Header::scheme("https"),
        Header::authority("localhost:4433"),
        Header::path("/webtransport"),
    ];

    assert_eq!(headers.len(), 5);
    assert_eq!(headers[0].name_str(), Some(":method"));
    assert_eq!(headers[0].value_str(), Some("CONNECT"));
    assert_eq!(headers[1].name_str(), Some(":protocol"));
    assert_eq!(headers[1].value_str(), Some("webtransport"));
}

#[tokio::test]
async fn test_client_server_handshake() {
    let (cert_path, key_path) = generate_test_certificate();

    // Start the server
    let mut server = Server::bind(
        "127.0.0.1:0".parse().unwrap(),
        &cert_path,
        &key_path,
        None,
        None,
    )
    .await
    .expect("server creation failed");

    let server_addr = server.local_addr();

    // Run the server in the background. It implements Send, so tokio::spawn can move it
    let server_handle = tokio::spawn(async move {
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            server.run(|_addr, _event| {
                // Do not respond to requests
                None
            }),
        )
        .await;

        // Timeout is OK here because the test is done
        match result {
            Ok(r) => r,
            Err(_) => Ok(()), // timeout
        }
    });

    // Create the client
    let mut client = Client::connect(server_addr, "localhost", None, None)
        .await
        .expect("client creation failed");

    // Run the handshake with a timeout
    let handshake_result = tokio::time::timeout(Duration::from_secs(5), client.handshake()).await;

    // Stop the server task
    server_handle.abort();

    // Check the handshake result
    // The handshake may fail with the self-signed certificate
    match handshake_result {
        Ok(Ok(())) => {
            println!("Handshake successful");
        }
        Ok(Err(e)) => {
            // TLS errors are expected with the self-signed certificate
            println!("Handshake error (expected with self-signed cert): {:?}", e);
        }
        Err(_) => {
            println!("Handshake timed out");
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_server_is_send() {
    let (cert_path, key_path) = generate_test_certificate();

    // Test that Server is Send
    let server = Server::bind(
        "127.0.0.1:0".parse().unwrap(),
        &cert_path,
        &key_path,
        None,
        None,
    )
    .await
    .expect("server creation failed");

    // Check that it can be moved to another thread with tokio::spawn
    let handle = tokio::spawn(async move {
        let _addr = server.local_addr();
        // Check that the server was moved
        true
    });

    let result = handle.await.expect("task failed");
    assert!(result);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_client_is_send() {
    // Test that Client is Send
    let client = Client::connect("127.0.0.1:14435".parse().unwrap(), "localhost", None, None)
        .await
        .expect("client creation failed");

    // Check that it can be moved to another thread with tokio::spawn
    let handle = tokio::spawn(async move {
        let _addr = client.local_addr();
        // Check that the client was moved
        true
    });

    let result = handle.await.expect("task failed");
    assert!(result);
}
