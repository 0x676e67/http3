//! QUIC Sans I/O
//!
//! Directly tests Connection read_pkt / write_pkt.
//! Packets are exchanged without real network I/O,
//! then the handshake state is verified.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use ngtcp2::{Connection, ConnectionId, PacketInfo, TlsContext, TransportParamsExt};
use ngtcp2_sys::ngtcp2_transport_params;
use rcgen::{CertificateParams, KeyPair};

/// Generate a certificate and private key for tests
fn generate_test_certs() -> (PathBuf, PathBuf) {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let unique_id = COUNTER.fetch_add(1, Ordering::SeqCst);
    let temp_dir = std::env::temp_dir().join(format!(
        "quic_sans_io_test_{}_{}",
        std::process::id(),
        unique_id
    ));
    std::fs::create_dir_all(&temp_dir).expect("failed to create temporary directory");

    let cert_path = temp_dir.join("cert.pem");
    let key_path = temp_dir.join("key.pem");

    let mut params = CertificateParams::new(vec!["localhost".to_string()])
        .expect("failed to create CertificateParams");
    params.distinguished_name.push(
        rcgen::DnType::CommonName,
        rcgen::DnValue::Utf8String("localhost".to_string()),
    );

    let key_pair = KeyPair::generate().expect("failed to generate key pair");
    let cert = params
        .self_signed(&key_pair)
        .expect("failed to generate certificate");

    std::fs::write(&cert_path, cert.pem()).expect("failed to write certificate file");
    std::fs::write(&key_path, key_pair.serialize_pem()).expect("failed to write private key file");

    (cert_path, key_path)
}

/// Return a test timestamp in nanoseconds
fn timestamp() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}

/// create client, generate Initial packet
#[test]
fn test_client_initial_packet_generation() {
    let dcid = ConnectionId::random(16).unwrap();
    let scid = ConnectionId::random(16).unwrap();
    let local_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
    let remote_addr: SocketAddr = "127.0.0.1:4433".parse().unwrap();

    // create TLS context (without certificate verification)
    let tls_ctx =
        TlsContext::new_client_with_options(&[b"h3"], false).expect("TLS contextcreation failed");
    let tls_session = tls_ctx
        .create_session()
        .expect("failed to create TLS session");

    // transport parameters
    let params = ngtcp2_transport_params::default_params().with_datagram(65535);

    let ts = timestamp();

    // create client
    let mut client = Connection::client_new(
        &dcid,
        &scid,
        local_addr,
        remote_addr,
        "localhost",
        tls_session,
        &params,
        ts,
    )
    .expect("failed to create client connection");

    // generate Initial packet
    let mut buf = vec![0u8; 1350];
    let (written, _pkt_info) = client
        .write_pkt(&mut buf, ts)
        .expect("packet generation failed");

    // generatecheck
    assert!(written > 0, "Initial packet should be generated");
    eprintln!("Initial: {} bytes", written);

    // QUIC headercheck
    // Long Header Format: bit 1
    assert!(buf[0] & 0x80 != 0, "Long Header should");

    // handshake completed
    assert!(
        !client.is_handshake_completed(),
        "handshake should not be completed yet"
    );
}

/// create server
#[test]
fn test_server_connection_creation() {
    let (cert_path, key_path) = generate_test_certs();

    // client DCID server SCID for
    let client_dcid = ConnectionId::random(16).unwrap();
    let server_scid = ConnectionId::random(16).unwrap();
    let local_addr: SocketAddr = "127.0.0.1:4433".parse().unwrap();
    let remote_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();

    // create TLS context
    let tls_ctx = TlsContext::new_server(&cert_path, &key_path, &[b"h3"])
        .expect("TLS contextcreation failed");
    let tls_session = tls_ctx
        .create_session()
        .expect("failed to create TLS session");

    // transport parameters
    let params = ngtcp2_transport_params::default_params()
        .with_datagram(65535)
        .with_original_dcid(&client_dcid);

    let ts = timestamp();

    // create server
    let server = Connection::server_new(
        &client_dcid,
        &server_scid,
        local_addr,
        remote_addr,
        tls_session,
        &params,
        ts,
    )
    .expect("failed to create server connection");

    // handshake completed
    assert!(
        !server.is_handshake_completed(),
        "handshake should not be completed yet"
    );
}

/// client/serverhandshake completed
#[test]
fn test_quic_handshake() {
    let (cert_path, key_path) = generate_test_certs();

    // Generate connection IDs
    let client_dcid = ConnectionId::random(16).unwrap();
    let client_scid = ConnectionId::random(16).unwrap();
    let server_scid = ConnectionId::random(16).unwrap();

    let client_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
    let server_addr: SocketAddr = "127.0.0.1:4433".parse().unwrap();

    let ts = timestamp();

    // create client
    let client_tls_ctx = TlsContext::new_client_with_options(&[b"h3"], false)
        .expect("failed to create client TLS context");
    let client_tls_session = client_tls_ctx
        .create_session()
        .expect("client failed to create TLS session");

    let client_params = ngtcp2_transport_params::default_params().with_datagram(65535);

    let mut client = Connection::client_new(
        &client_dcid,
        &client_scid,
        client_addr,
        server_addr,
        "localhost",
        client_tls_session,
        &client_params,
        ts,
    )
    .expect("failed to create client connection");

    // server create TLS context
    let server_tls_ctx = TlsContext::new_server(&cert_path, &key_path, &[b"h3"])
        .expect("failed to create server TLS context");

    let pkt_info = PacketInfo::default();
    let mut buf = vec![0u8; 1350];
    let mut round = 0;
    const MAX_ROUNDS: usize = 10;

    // create server (Initial receivedcreate)
    let mut server: Option<Connection> = None;

    while round < MAX_ROUNDS {
        round += 1;
        let current_ts = timestamp();
        eprintln!("--- Round {} ---", round);

        // clientgenerate
        let (client_written, _) = client
            .write_pkt(&mut buf, current_ts)
            .unwrap_or((0, pkt_info));
        if client_written > 0 {
            eprintln!("client -> server: {} bytes", client_written);

            // Create the server after receiving Initial
            if server.is_none() {
                let server_tls_session = server_tls_ctx
                    .create_session()
                    .expect("server failed to create TLS session");

                let server_params = ngtcp2_transport_params::default_params()
                    .with_datagram(65535)
                    .with_original_dcid(&client_dcid);

                server = Some(
                    Connection::server_new(
                        &client_scid,
                        &server_scid,
                        server_addr,
                        client_addr,
                        server_tls_session,
                        &server_params,
                        current_ts,
                    )
                    .expect("failed to create server connection"),
                );
            }

            // server
            if let Some(ref mut s) = server {
                let result = s.read_pkt(
                    &server_addr,
                    &client_addr,
                    &pkt_info,
                    &buf[..client_written],
                    current_ts,
                );
                match result {
                    Ok(()) => eprintln!("server: succeeded"),
                    Err(e) => {
                        eprintln!("server: error: {:?}", e);
                        // errorcheck
                        if format!("{:?}", e).contains("-225") {
                            eprintln!("ERR_TRANSPORT_PARAM (-225)");
                            eprintln!("transport parameters");
                        }
                    }
                }
            }
        }

        // servergenerate
        if let Some(ref mut s) = server {
            let (server_written, _) = s.write_pkt(&mut buf, current_ts).unwrap_or((0, pkt_info));
            if server_written > 0 {
                eprintln!("server -> client: {} bytes", server_written);

                // client
                let result = client.read_pkt(
                    &client_addr,
                    &server_addr,
                    &pkt_info,
                    &buf[..server_written],
                    current_ts,
                );
                match result {
                    Ok(()) => eprintln!("client: succeeded"),
                    Err(e) => eprintln!("client: error: {:?}", e),
                }
            }
        }

        // handshake completedcheck
        let client_done = client.is_handshake_completed();
        let server_done = server.as_ref().is_some_and(|s| s.is_handshake_completed());

        eprintln!(
            "handshakestate: client={}, server={}",
            client_done, server_done
        );

        if client_done && server_done {
            eprintln!("handshake completed!");
            break;
        }
    }

    // check handshake completion
    assert!(
        client.is_handshake_completed(),
        "clienthandshake should not be completed yet"
    );
    assert!(
        server.as_ref().is_some_and(|s| s.is_handshake_completed()),
        "serverhandshake should not be completed yet"
    );
}

/// streamstatecheck
#[test]
fn test_stream_open_after_handshake() {
    let (cert_path, key_path) = generate_test_certs();

    // Generate connection IDs
    let client_dcid = ConnectionId::random(16).unwrap();
    let client_scid = ConnectionId::random(16).unwrap();
    let server_scid = ConnectionId::random(16).unwrap();

    let client_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
    let server_addr: SocketAddr = "127.0.0.1:4433".parse().unwrap();

    let ts = timestamp();

    // create client
    let client_tls_ctx = TlsContext::new_client_with_options(&[b"h3"], false)
        .expect("failed to create client TLS context");
    let client_tls_session = client_tls_ctx
        .create_session()
        .expect("client failed to create TLS session");

    let client_params = ngtcp2_transport_params::default_params().with_datagram(65535);

    let mut client = Connection::client_new(
        &client_dcid,
        &client_scid,
        client_addr,
        server_addr,
        "localhost",
        client_tls_session,
        &client_params,
        ts,
    )
    .expect("failed to create client connection");

    // server create TLS context
    let server_tls_ctx = TlsContext::new_server(&cert_path, &key_path, &[b"h3"])
        .expect("failed to create server TLS context");

    let pkt_info = PacketInfo::default();
    let mut buf = vec![0u8; 1350];
    let mut server: Option<Connection> = None;

    // handshake completed
    for _round in 0..10 {
        let current_ts = timestamp();

        // clientgenerate
        let (client_written, _) = client
            .write_pkt(&mut buf, current_ts)
            .unwrap_or((0, pkt_info));
        if client_written > 0 {
            if server.is_none() {
                let server_tls_session = server_tls_ctx
                    .create_session()
                    .expect("server failed to create TLS session");

                let server_params = ngtcp2_transport_params::default_params()
                    .with_datagram(65535)
                    .with_original_dcid(&client_dcid);

                server = Some(
                    Connection::server_new(
                        &client_scid,
                        &server_scid,
                        server_addr,
                        client_addr,
                        server_tls_session,
                        &server_params,
                        current_ts,
                    )
                    .expect("failed to create server connection"),
                );
            }

            if let Some(ref mut s) = server {
                let _ = s.read_pkt(
                    &server_addr,
                    &client_addr,
                    &pkt_info,
                    &buf[..client_written],
                    current_ts,
                );
            }
        }

        if let Some(ref mut s) = server {
            let (server_written, _) = s.write_pkt(&mut buf, current_ts).unwrap_or((0, pkt_info));
            if server_written > 0 {
                let _ = client.read_pkt(
                    &client_addr,
                    &server_addr,
                    &pkt_info,
                    &buf[..server_written],
                    current_ts,
                );
            }
        }

        if client.is_handshake_completed()
            && server.as_ref().is_some_and(|s| s.is_handshake_completed())
        {
            break;
        }
    }

    // check handshake completion
    assert!(
        client.is_handshake_completed(),
        "clienthandshake should not be completed yet"
    );
    assert!(
        server.as_ref().is_some_and(|s| s.is_handshake_completed()),
        "serverhandshake should not be completed yet"
    );

    eprintln!("handshake completed");

    // client bidirectional stream
    let stream_id = client.open_bidi_stream().expect("failed to open stream");
    eprintln!("bidirectional stream ID: {}", stream_id);
    assert_eq!(stream_id, 0, "bidirectional stream ID 0");

    // unidirectional stream
    let uni_stream_id = client
        .open_uni_stream()
        .expect("failed to open unidirectional stream");
    eprintln!("unidirectional stream ID: {}", uni_stream_id);
    assert_eq!(uni_stream_id, 2, "unidirectional stream ID 2");

    // streamcheck
    let bidi_left = client.get_streams_bidi_left();
    let uni_left = client.get_streams_uni_left();
    eprintln!(
        "bidirectional stream: {}, unidirectional stream: {}",
        bidi_left, uni_left
    );
    assert!(bidi_left > 0, "bidirectional stream");
    assert!(uni_left > 0, "unidirectional stream");
}

/// statecheck
#[test]
fn test_connection_state() {
    let (cert_path, key_path) = generate_test_certs();

    // Generate connection IDs
    let client_dcid = ConnectionId::random(16).unwrap();
    let client_scid = ConnectionId::random(16).unwrap();
    let server_scid = ConnectionId::random(16).unwrap();

    let client_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
    let server_addr: SocketAddr = "127.0.0.1:4433".parse().unwrap();

    let ts = timestamp();

    // create client
    let client_tls_ctx = TlsContext::new_client_with_options(&[b"h3"], false)
        .expect("failed to create client TLS context");
    let client_tls_session = client_tls_ctx
        .create_session()
        .expect("client failed to create TLS session");

    let client_params = ngtcp2_transport_params::default_params().with_datagram(65535);

    let mut client = Connection::client_new(
        &client_dcid,
        &client_scid,
        client_addr,
        server_addr,
        "localhost",
        client_tls_session,
        &client_params,
        ts,
    )
    .expect("failed to create client connection");

    // server create TLS context
    let server_tls_ctx = TlsContext::new_server(&cert_path, &key_path, &[b"h3"])
        .expect("failed to create server TLS context");

    let pkt_info = PacketInfo::default();
    let mut buf = vec![0u8; 1350];
    let mut server: Option<Connection> = None;

    // handshake completed
    for _round in 0..10 {
        let current_ts = timestamp();

        let (client_written, _) = client
            .write_pkt(&mut buf, current_ts)
            .unwrap_or((0, pkt_info));
        if client_written > 0 {
            if server.is_none() {
                let server_tls_session = server_tls_ctx
                    .create_session()
                    .expect("server failed to create TLS session");

                let server_params = ngtcp2_transport_params::default_params()
                    .with_datagram(65535)
                    .with_original_dcid(&client_dcid);

                server = Some(
                    Connection::server_new(
                        &client_scid,
                        &server_scid,
                        server_addr,
                        client_addr,
                        server_tls_session,
                        &server_params,
                        current_ts,
                    )
                    .expect("failed to create server connection"),
                );
            }

            if let Some(ref mut s) = server {
                let _ = s.read_pkt(
                    &server_addr,
                    &client_addr,
                    &pkt_info,
                    &buf[..client_written],
                    current_ts,
                );
            }
        }

        if let Some(ref mut s) = server {
            let (server_written, _) = s.write_pkt(&mut buf, current_ts).unwrap_or((0, pkt_info));
            if server_written > 0 {
                let _ = client.read_pkt(
                    &client_addr,
                    &server_addr,
                    &pkt_info,
                    &buf[..server_written],
                    current_ts,
                );
            }
        }

        if client.is_handshake_completed()
            && server.as_ref().is_some_and(|s| s.is_handshake_completed())
        {
            break;
        }
    }

    // check handshake completion
    assert!(
        client.is_handshake_completed(),
        "clienthandshake should not be completed yet"
    );

    // statecheck
    assert!(!client.is_in_closing_period(), "should");
    assert!(!client.is_in_draining_period(), "should");

    // check
    let max_data_left = client.get_max_data_left();
    eprintln!("max_data_left: {}", max_data_left);
    assert!(max_data_left > 0, "data should be sent");

    // DATAGRAM check
    assert!(!client.has_datagram(), "stateDATAGRAMshould");
    assert!(client.poll_datagram().is_none(), "DATAGRAMshould");

    // stream datacheck
    assert!(!client.has_stream_data(), "statestream data should match");
    assert!(
        client.poll_stream_data().is_none(),
        "stream data should match"
    );

    eprintln!("statecompleted");
}
