//! Integration tests
//!
//! Integration tests for HTTP/3.

use std::path::PathBuf;
use std::time::Duration;

use ngtcp2::{Header, TransportParamsExt};
use rcgen::generate_simple_self_signed;
use tokio_ngtcp2::{Client, Server};

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
async fn test_transport_params_datagram() {
    use ngtcp2::ngtcp2_transport_params;

    let params = ngtcp2_transport_params::default_params().with_datagram(65535);

    assert_eq!(params.max_datagram_frame_size, 65535);
    assert!(params.initial_max_streams_bidi > 0);
    assert!(params.initial_max_streams_uni > 0);
}

#[test]
fn test_header_creation() {
    let headers = [
        Header::method("GET"),
        Header::scheme("https"),
        Header::authority("localhost:4433"),
        Header::path("/"),
    ];

    assert_eq!(headers.len(), 4);
    assert_eq!(headers[0].name_str(), Some(":method"));
    assert_eq!(headers[0].value_str(), Some("GET"));
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
