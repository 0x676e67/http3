//! QUIC client/server I/O tests
//!
//! QUIC handshake tests using real network I/O

use std::path::PathBuf;
use std::time::Duration;

use rcgen::{CertificateParams, KeyPair};
use tokio::time::timeout;

use tokio_ngtcp2::{Client, Server};

/// Generate a certificate and private key for tests
fn generate_test_certs() -> (PathBuf, PathBuf) {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let unique_id = COUNTER.fetch_add(1, Ordering::SeqCst);
    let temp_dir =
        std::env::temp_dir().join(format!("quic_test_{}_{}", std::process::id(), unique_id));
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

/// QUIC handshake test without certificate validation
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_quic_handshake_insecure() {
    let (cert_path, key_path) = generate_test_certs();

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
            server.run(|addr, event| {
                eprintln!(
                    "[server] event received: addr = {}, event = {:?}",
                    addr, event
                );
                None
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

    // Create the client (without certificate verification)
    let client_result = timeout(Duration::from_secs(10), async {
        let mut client = Client::connect_insecure_default(server_addr, "localhost")
            .await
            .expect("failed to create client");

        eprintln!("[client] handshake started");

        // Run the handshake
        match client.handshake().await {
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
            eprintln!("[test] QUIC handshake test succeeded");
        }
        Err(_) => {
            panic!("test timed out");
        }
    }
}

/// Concurrent multi-client connection test
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_quic_multiple_clients() {
    let (cert_path, key_path) = generate_test_certs();

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
            server.run(|addr, event| {
                eprintln!(
                    "[server] event received: addr = {}, event = {:?}",
                    addr, event
                );
                None
            }),
        )
        .await;

        match result {
            Ok(r) => r,
            Err(_) => Ok(()),
        }
    });

    // Connect multiple clients concurrently
    let client_count = 3;
    let mut handles = Vec::new();

    for i in 0..client_count {
        let addr = server_addr;
        let handle = tokio::spawn(async move {
            let mut client = Client::connect_insecure_default(addr, "localhost")
                .await
                .expect("failed to create client");

            eprintln!("[client {}] handshake started", i);

            match timeout(Duration::from_secs(5), client.handshake()).await {
                Ok(Ok(())) => {
                    eprintln!("[client {}] handshake succeeded", i);
                    true
                }
                Ok(Err(e)) => {
                    eprintln!("[client {}] handshake error: {:?}", i, e);
                    false
                }
                Err(_) => {
                    eprintln!("[client {}] timeout", i);
                    false
                }
            }
        });
        handles.push(handle);
    }

    // Wait for all client results
    let mut success_count = 0;
    for handle in handles {
        if handle.await.unwrap_or(false) {
            success_count += 1;
        }
    }

    server_task.abort();

    eprintln!(
        "[test] successful clients: {}/{}",
        success_count, client_count
    );
    assert!(success_count >= 1, "at least one client should succeed");
}

/// Client/server clean shutdown test
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_quic_connection_close() {
    let (cert_path, key_path) = generate_test_certs();

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
        let _ = timeout(Duration::from_secs(5), server.run(|_addr, _event| None)).await;
    });

    // Create the clienthandshake
    let mut client = Client::connect_insecure_default(server_addr, "localhost")
        .await
        .expect("failed to create client");

    // handshake
    let handshake_result = timeout(Duration::from_secs(5), client.handshake()).await;
    assert!(handshake_result.is_ok(), "handshake should not time out");

    // Drop the client to close the connection
    drop(client);

    // Stop the server
    server_task.abort();

    eprintln!("[test] connection close test completed");
}
