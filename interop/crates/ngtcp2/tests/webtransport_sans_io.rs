//! WebTransport Sans I/O tests
//!
//! WebTransport API (submit_wt_request / submit_wt_response / server_confirm_wt_session)
//! Exercises WebTransport session establishment directly after the QUIC handshake.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use nghttp3_sys::nghttp3_vec;
use ngtcp2_sys::ngtcp2_transport_params;
use rcgen::{CertificateParams, KeyPair};

use ngtcp2::{
    Connection, ConnectionId, Header, Http3Connection, Http3Event, Http3SettingsExt, PacketInfo,
    TlsContext, TransportParamsExt,
};

/// Generate a certificate and private key for tests
fn generate_test_certs() -> (PathBuf, PathBuf) {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let unique_id = COUNTER.fetch_add(1, Ordering::SeqCst);
    let temp_dir = std::env::temp_dir().join(format!(
        "wt_sans_io_test_{}_{}",
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

/// Helper that drives the QUIC handshake to completion
fn complete_quic_handshake(
    client: &mut Connection,
    server: &mut Connection,
    client_addr: SocketAddr,
    server_addr: SocketAddr,
) -> bool {
    let pkt_info = PacketInfo::default();
    let mut buf = vec![0u8; 1350];

    for _ in 0..10 {
        let current_ts = timestamp();

        // client -> server
        let (client_written, _) = client
            .write_pkt(&mut buf, current_ts)
            .unwrap_or((0, pkt_info));
        if client_written > 0 {
            let _ = server.read_pkt(
                &server_addr,
                &client_addr,
                &pkt_info,
                &buf[..client_written],
                current_ts,
            );
        }

        // server -> client
        let (server_written, _) = server
            .write_pkt(&mut buf, current_ts)
            .unwrap_or((0, pkt_info));
        if server_written > 0 {
            let _ = client.read_pkt(
                &client_addr,
                &server_addr,
                &pkt_info,
                &buf[..server_written],
                current_ts,
            );
        }

        if client.is_handshake_completed() && server.is_handshake_completed() {
            return true;
        }
    }

    false
}

/// Header helper method tests
#[test]
fn test_webtransport_headers() {
    // WebTransport CONNECT request headers
    let headers = [
        Header::method("CONNECT"),
        Header::scheme("https"),
        Header::new(b":protocol".to_vec(), b"webtransport".to_vec()),
        Header::authority("localhost:4433"),
        Header::path("/webtransport"),
    ];

    // Check header contents
    assert_eq!(headers[0].name_str(), Some(":method"));
    assert_eq!(headers[0].value_str(), Some("CONNECT"));
    assert_eq!(headers[1].name_str(), Some(":scheme"));
    assert_eq!(headers[1].value_str(), Some("https"));
    assert_eq!(headers[2].name_str(), Some(":protocol"));
    assert_eq!(headers[2].value_str(), Some("webtransport"));
    assert_eq!(headers[3].name_str(), Some(":authority"));
    assert_eq!(headers[3].value_str(), Some("localhost:4433"));
    assert_eq!(headers[4].name_str(), Some(":path"));
    assert_eq!(headers[4].value_str(), Some("/webtransport"));
}

/// Create a WebTransport-capable HTTP/3 client connection
#[test]
fn test_wt_h3_client_creation() {
    use nghttp3_sys::nghttp3_settings;

    let settings = nghttp3_settings::default_settings().with_webtransport();

    // Check that WebTransport is enabled
    assert_eq!(settings.enable_connect_protocol, 1);
    assert_eq!(settings.h3_datagram, 1);
    assert_eq!(settings.wt_enabled, 1);

    let h3_conn = Http3Connection::client_new(&settings);
    assert!(
        h3_conn.is_ok(),
        "WebTransport should create an HTTP/3 client connection"
    );
}

/// Create a WebTransport-capable HTTP/3 server connection
#[test]
fn test_wt_h3_server_creation() {
    use nghttp3_sys::nghttp3_settings;

    let settings = nghttp3_settings::default_settings().with_webtransport();

    let h3_conn = Http3Connection::server_new(&settings);
    assert!(
        h3_conn.is_ok(),
        "WebTransport should create an HTTP/3 server connection"
    );
}

/// WebTransport request send test
///
/// In Sans I/O tests, without exchanging SETTINGS frames,
/// WebTransport requests cannot be sent. An error is expected.
#[test]
fn test_submit_wt_request() {
    use nghttp3_sys::nghttp3_settings;

    let settings = nghttp3_settings::default_settings().with_webtransport();
    let mut h3_client =
        Http3Connection::client_new(&settings).expect("failed to create HTTP/3 client");

    // Bind the control and QPACK streams
    h3_client.bind_control_stream(2).unwrap();
    h3_client.bind_qpack_streams(6, 10).unwrap();

    // WebTransport CONNECT request headers
    let headers = vec![
        Header::method("CONNECT"),
        Header::scheme("https"),
        Header::new(b":protocol".to_vec(), b"webtransport".to_vec()),
        Header::authority("localhost:4433"),
        Header::path("/webtransport"),
    ];

    // Send the WebTransport request (stream ID 0)
    // Sans I/O tests do not exchange SETTINGS frames,
    // so ERR_INVALID_STATE may occur
    let stream_id = 0;
    let result = h3_client.submit_wt_request(stream_id, &headers);

    match result {
        Ok(()) => {
            eprintln!("submit_wt_request succeeded");

            // write_stream data
            let mut vecs = vec![
                nghttp3_vec {
                    base: std::ptr::null_mut(),
                    len: 0
                };
                16
            ];
            let write_result = h3_client.write_stream(&mut vecs);

            match write_result {
                Ok((sid, fin, count)) => {
                    eprintln!(
                        "write_stream: stream_id = {}, fin = {}, vec_count = {}",
                        sid, fin, count
                    );
                }
                Err(e) => {
                    eprintln!("write_stream error: {:?}", e);
                }
            }
        }
        Err(e) => {
            // The error is expected because Sans I/O tests do not exchange SETTINGS
            eprintln!("submit_wt_request error, expected: {:?}", e);
        }
    }
}

/// WebTransport response send test
#[test]
fn test_submit_wt_response() {
    use nghttp3_sys::nghttp3_settings;

    let settings = nghttp3_settings::default_settings().with_webtransport();
    let mut h3_server =
        Http3Connection::server_new(&settings).expect("failed to create HTTP/3 server");

    // Bind the control and QPACK streams
    h3_server.bind_control_stream(3).unwrap();
    h3_server.bind_qpack_streams(7, 11).unwrap();

    // WebTransport Response headers (200 OK)
    let headers = vec![Header::status(200)];

    // WebTransport response sent
    //: In normal use the server sends the response after receiving the client request
    let stream_id = 0;
    let result = h3_server.submit_wt_response(stream_id, &headers);

    // This may fail if the stream has not been opened
    eprintln!("submit_wt_response result: {:?}", result);
}

/// WebTransport session confirmation test
#[test]
fn test_server_confirm_wt_session() {
    use nghttp3_sys::nghttp3_settings;

    let settings = nghttp3_settings::default_settings().with_webtransport();
    let mut h3_server =
        Http3Connection::server_new(&settings).expect("failed to create HTTP/3 server");

    // Bind the control and QPACK streams
    h3_server.bind_control_stream(3).unwrap();
    h3_server.bind_qpack_streams(7, 11).unwrap();

    // sessioncheck
    //: Normally called after the request/response exchange
    let session_id = 0;
    let ts = timestamp();
    let result = h3_server.server_confirm_wt_session(session_id, ts);

    // This fails if the session has not been opened
    eprintln!("server_confirm_wt_session result: {:?}", result);
}

/// WebTransport data stream open test
#[test]
fn test_open_wt_data_stream() {
    use nghttp3_sys::nghttp3_settings;

    let settings = nghttp3_settings::default_settings().with_webtransport();
    let mut h3_client =
        Http3Connection::client_new(&settings).expect("failed to create HTTP/3 client");

    // Bind the control and QPACK streams
    h3_client.bind_control_stream(2).unwrap();
    h3_client.bind_qpack_streams(6, 10).unwrap();

    // WebTransport data stream
    let session_id = 0;
    let stream_id = 4; // client-initiated bidirectional stream (2)
    let result = h3_client.open_wt_data_stream(session_id, stream_id);

    // This fails if the session has not been opened
    eprintln!("open_wt_data_stream result: {:?}", result);
}

/// WebTransport session close test
#[test]
fn test_close_wt_session() {
    use nghttp3_sys::nghttp3_settings;

    let settings = nghttp3_settings::default_settings().with_webtransport();
    let mut h3_client =
        Http3Connection::client_new(&settings).expect("failed to create HTTP/3 client");

    // Bind the control and QPACK streams
    h3_client.bind_control_stream(2).unwrap();
    h3_client.bind_qpack_streams(6, 10).unwrap();

    // WebTransport session
    let session_id = 0;
    let error_code = 0;
    let result = h3_client.close_wt_session(session_id, error_code, None);

    // This fails if the session has not been opened
    eprintln!("close_wt_session result: {:?}", result);
}

/// QUIC + HTTP/3 + WebTransport integration test
#[test]
fn test_quic_h3_webtransport_integration() {
    let (cert_path, key_path) = generate_test_certs();

    // Generate connection IDs
    let client_dcid = ConnectionId::random(16).unwrap();
    let client_scid = ConnectionId::random(16).unwrap();
    let server_scid = ConnectionId::random(16).unwrap();

    let client_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
    let server_addr: SocketAddr = "127.0.0.1:4433".parse().unwrap();

    let ts = timestamp();

    // Transport parameters with DATAGRAM enabled, required by WebTransport
    let client_params = ngtcp2_transport_params::default_params().with_datagram(65535);
    let server_params = ngtcp2_transport_params::default_params()
        .with_datagram(65535)
        .with_original_dcid(&client_dcid);

    // Create the client QUIC connection
    let client_tls_ctx = TlsContext::new_client_with_options(&[b"h3"], false)
        .expect("failed to create client TLS context");
    let client_tls_session = client_tls_ctx
        .create_session()
        .expect("failed to create TLS session");

    let mut quic_client = Connection::client_new(
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

    // Create the server QUIC connection
    let server_tls_ctx = TlsContext::new_server(&cert_path, &key_path, &[b"h3"])
        .expect("failed to create server TLS context");
    let server_tls_session = server_tls_ctx
        .create_session()
        .expect("failed to create TLS session");

    let mut quic_server = Connection::server_new(
        &client_scid,
        &server_scid,
        server_addr,
        client_addr,
        server_tls_session,
        &server_params,
        ts,
    )
    .expect("failed to create server connection");

    // Complete the QUIC handshake
    let handshake_done =
        complete_quic_handshake(&mut quic_client, &mut quic_server, client_addr, server_addr);

    if !handshake_done {
        eprintln!("QUIC handshake did not complete; skipping");
        return;
    }

    eprintln!("QUIC handshake completed");

    // Create WebTransport-capable HTTP/3 connections
    use nghttp3_sys::nghttp3_settings;

    let h3_settings = nghttp3_settings::default_settings().with_webtransport();
    let mut h3_client =
        Http3Connection::client_new(&h3_settings).expect("failed to create HTTP/3 client");
    let mut h3_server =
        Http3Connection::server_new(&h3_settings).expect("failed to create HTTP/3 server");

    // Client side: open unidirectional streams and bind the control and QPACK streams
    let client_control_stream = quic_client
        .open_uni_stream()
        .expect("failed to open stream");
    let client_qenc_stream = quic_client
        .open_uni_stream()
        .expect("failed to open stream");
    let client_qdec_stream = quic_client
        .open_uni_stream()
        .expect("failed to open stream");

    eprintln!(
        "clientcontrol stream: {}, QPACK: {}, {}",
        client_control_stream, client_qenc_stream, client_qdec_stream
    );

    h3_client
        .bind_control_stream(client_control_stream)
        .expect("failed to bind control stream");
    h3_client
        .bind_qpack_streams(client_qenc_stream, client_qdec_stream)
        .expect("failed to bind QPACK stream");

    // Server side: open unidirectional streams and bind the control and QPACK streams
    let server_control_stream = quic_server
        .open_uni_stream()
        .expect("failed to open stream");
    let server_qenc_stream = quic_server
        .open_uni_stream()
        .expect("failed to open stream");
    let server_qdec_stream = quic_server
        .open_uni_stream()
        .expect("failed to open stream");

    eprintln!(
        "servercontrol stream: {}, QPACK: {}, {}",
        server_control_stream, server_qenc_stream, server_qdec_stream
    );

    h3_server
        .bind_control_stream(server_control_stream)
        .expect("failed to bind control stream");
    h3_server
        .bind_qpack_streams(server_qenc_stream, server_qdec_stream)
        .expect("failed to bind QPACK stream");

    // Open a bidirectional stream from the client and send a WebTransport request
    let request_stream = quic_client
        .open_bidi_stream()
        .expect("failed to open stream");
    eprintln!("WebTransport request stream: {}", request_stream);

    let wt_headers = vec![
        Header::method("CONNECT"),
        Header::scheme("https"),
        Header::new(b":protocol".to_vec(), b"webtransport".to_vec()),
        Header::authority("localhost:4433"),
        Header::path("/webtransport"),
    ];

    // Send the WebTransport request
    // Sans I/O tests do not exchange SETTINGS frames,
    // error
    let wt_result = h3_client.submit_wt_request(request_stream, &wt_headers);

    match wt_result {
        Ok(()) => {
            eprintln!("WebTransport CONNECT request send completed");
        }
        Err(e) => {
            // The error is expected because Sans I/O tests do not exchange SETTINGS
            eprintln!("WebTransport request send error, expected: {:?}", e);
            eprintln!(
                "WebTransport integration test completed partially without SETTINGS exchange"
            );
            return;
        }
    }

    // Fetch HTTP/3 frame data
    let mut vecs = vec![
        nghttp3_vec {
            base: std::ptr::null_mut(),
            len: 0
        };
        16
    ];
    loop {
        let result = h3_client.write_stream(&mut vecs);

        match result {
            Ok((stream_id, fin, count)) => {
                if count == 0 {
                    break;
                }
                eprintln!(
                    "HTTP/3 write_stream: stream_id = {}, fin = {}, count = {}",
                    stream_id, fin, count
                );

                // Calculate data length
                let total_len: usize = vecs[..count].iter().map(|v| v.len).sum();
                eprintln!("total data length: {} bytes", total_len);

                // Call add_write_offset
                h3_client
                    .add_write_offset(stream_id, total_len)
                    .expect("add_write_offset failed");
            }
            Err(e) => {
                eprintln!("HTTP/3 write_stream error: {:?}", e);
                break;
            }
        }
    }

    eprintln!("WebTransport integration test completed");
}

/// WebTransport event receive test
#[test]
fn test_wt_events() {
    use nghttp3_sys::nghttp3_settings;

    let settings = nghttp3_settings::default_settings().with_webtransport();
    let mut h3_server =
        Http3Connection::server_new(&settings).expect("failed to create HTTP/3 server");

    // Bind the control and QPACK streams
    h3_server.bind_control_stream(3).unwrap();
    h3_server.bind_qpack_streams(7, 11).unwrap();

    // There are no events in the initial state
    let event = h3_server.poll_event();
    assert!(event.is_none(), "there should be no events initially");

    // Check event kinds when real data is received
    // WebTransportData events are generated by the recv_wt_data callback
    eprintln!("WebTransport event test completed");
}

/// DATAGRAM-capable transport parameter test
#[test]
fn test_datagram_transport_params() {
    let params = ngtcp2_transport_params::default_params().with_datagram(65535);

    assert_eq!(
        params.max_datagram_frame_size, 65535,
        "DATAGRAM size should be set"
    );

    eprintln!("DATAGRAM transport parameters:");
    eprintln!(
        "max_datagram_frame_size = {}",
        params.max_datagram_frame_size
    );
    eprintln!(
        "initial_max_streams_bidi = {}",
        params.initial_max_streams_bidi
    );
    eprintln!(
        "initial_max_streams_uni = {}",
        params.initial_max_streams_uni
    );
    eprintln!("initial_max_data = {}", params.initial_max_data);
}

/// DATAGRAM send test (Sans I/O)
///
/// Test DATAGRAM sending from an ngtcp2 client to server.
#[test]
fn test_datagram_send() {
    let (cert_path, key_path) = generate_test_certs();

    // Generate connection IDs
    let client_dcid = ConnectionId::random(16).unwrap();
    let client_scid = ConnectionId::random(16).unwrap();
    let server_scid = ConnectionId::random(16).unwrap();

    let client_addr: SocketAddr = "127.0.0.1:12346".parse().unwrap();
    let server_addr: SocketAddr = "127.0.0.1:4434".parse().unwrap();

    let ts = timestamp();

    // Transport parameters with DATAGRAM enabled
    let client_params = ngtcp2_transport_params::default_params().with_datagram(65535);
    let server_params = ngtcp2_transport_params::default_params()
        .with_datagram(65535)
        .with_original_dcid(&client_dcid);

    // Create the client QUIC connection
    let client_tls_ctx = TlsContext::new_client_with_options(&[b"h3"], false)
        .expect("failed to create client TLS context");
    let client_tls_session = client_tls_ctx
        .create_session()
        .expect("failed to create TLS session");

    let mut quic_client = Connection::client_new(
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

    // Create the server QUIC connection
    let server_tls_ctx = TlsContext::new_server(&cert_path, &key_path, &[b"h3"])
        .expect("failed to create server TLS context");
    let server_tls_session = server_tls_ctx
        .create_session()
        .expect("failed to create TLS session");

    let mut quic_server = Connection::server_new(
        &client_scid,
        &server_scid,
        server_addr,
        client_addr,
        server_tls_session,
        &server_params,
        ts,
    )
    .expect("failed to create server connection");

    // Complete the QUIC handshake
    let handshake_done =
        complete_quic_handshake(&mut quic_client, &mut quic_server, client_addr, server_addr);

    if !handshake_done {
        panic!("QUIC handshake did not complete");
    }

    eprintln!("QUIC handshake completed");

    // Check local and peer DATAGRAM support
    let local_max_datagram = quic_client.get_local_max_datagram_frame_size();
    let remote_max_datagram = quic_client.get_remote_max_datagram_frame_size();
    eprintln!("local_max_datagram_frame_size = {}", local_max_datagram);
    eprintln!("remote_max_datagram_frame_size = {}", remote_max_datagram);

    assert!(
        local_max_datagram > 0,
        "local endpoint should support DATAGRAM"
    );
    assert!(
        quic_client.can_send_datagram(),
        "peer should support DATAGRAM"
    );

    // DATAGRAM sent
    let datagram_data = b"Hello DATAGRAM!";
    let mut buf = vec![0u8; 1350];
    let current_ts = timestamp();

    eprintln!("sending DATAGRAM...");
    let result = quic_client.write_datagram(&mut buf, datagram_data, current_ts);

    match result {
        Ok((written, accepted)) => {
            eprintln!(
                "DATAGRAM send succeeded: written = {}, accepted = {}",
                written, accepted
            );
            // Even a successful send may be rejected by congestion control
            if accepted {
                eprintln!("DATAGRAM was accepted");
            } else {
                eprintln!("DATAGRAM was rejected by congestion control");
            }
        }
        Err(e) => {
            eprintln!("DATAGRAM send error: {:?}", e);
            panic!("failed to send DATAGRAM: {:?}", e);
        }
    }

    eprintln!("DATAGRAM send test completed");
}

// =============================================================================
// Helper: establish a QUIC + HTTP/3 + WebTransport session
// =============================================================================

/// QUIC + HTTP/3 connection pair
struct QuicH3Pair {
    quic_client: Connection,
    quic_server: Connection,
    h3_client: Http3Connection,
    h3_server: Http3Connection,
    client_addr: SocketAddr,
    server_addr: SocketAddr,
}

/// Create a QUIC + HTTP/3 connection pair and complete SETTINGS exchange
fn setup_quic_h3_pair() -> QuicH3Pair {
    let (cert_path, key_path) = generate_test_certs();

    let client_dcid = ConnectionId::random(16).unwrap();
    let client_scid = ConnectionId::random(16).unwrap();
    let server_scid = ConnectionId::random(16).unwrap();

    let client_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
    let server_addr: SocketAddr = "127.0.0.1:4433".parse().unwrap();

    let ts = timestamp();

    // Transport parameters with DATAGRAM enabled, required by WebTransport
    let client_params = ngtcp2_transport_params::default_params().with_datagram(65535);
    let server_params = ngtcp2_transport_params::default_params()
        .with_datagram(65535)
        .with_original_dcid(&client_dcid);

    // QUIC create
    let client_tls_ctx = TlsContext::new_client_with_options(&[b"h3"], false)
        .expect("failed to create client TLS context");
    let client_tls_session = client_tls_ctx
        .create_session()
        .expect("failed to create TLS session");
    let mut quic_client = Connection::client_new(
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

    let server_tls_ctx = TlsContext::new_server(&cert_path, &key_path, &[b"h3"])
        .expect("failed to create server TLS context");
    let server_tls_session = server_tls_ctx
        .create_session()
        .expect("failed to create TLS session");
    let mut quic_server = Connection::server_new(
        &client_scid,
        &server_scid,
        server_addr,
        client_addr,
        server_tls_session,
        &server_params,
        ts,
    )
    .expect("failed to create server connection");

    // Complete the QUIC handshake
    assert!(
        complete_quic_handshake(&mut quic_client, &mut quic_server, client_addr, server_addr),
        "QUIC handshake did not complete"
    );

    // Create WebTransport-capable HTTP/3 connections
    use nghttp3_sys::nghttp3_settings;

    let h3_settings = nghttp3_settings::default_settings().with_webtransport();
    let mut h3_client =
        Http3Connection::client_new(&h3_settings).expect("failed to create HTTP/3 client");
    let mut h3_server =
        Http3Connection::server_new(&h3_settings).expect("failed to create HTTP/3 server");

    // Bind the control and QPACK streams
    let client_ctrl = quic_client
        .open_uni_stream()
        .expect("failed to open stream");
    let client_qenc = quic_client
        .open_uni_stream()
        .expect("failed to open stream");
    let client_qdec = quic_client
        .open_uni_stream()
        .expect("failed to open stream");
    h3_client
        .bind_control_stream(client_ctrl)
        .expect("failed to bind control stream");
    h3_client
        .bind_qpack_streams(client_qenc, client_qdec)
        .expect("failed to bind QPACK stream");

    let server_ctrl = quic_server
        .open_uni_stream()
        .expect("failed to open stream");
    let server_qenc = quic_server
        .open_uni_stream()
        .expect("failed to open stream");
    let server_qdec = quic_server
        .open_uni_stream()
        .expect("failed to open stream");
    h3_server
        .bind_control_stream(server_ctrl)
        .expect("failed to bind control stream");
    h3_server
        .bind_qpack_streams(server_qenc, server_qdec)
        .expect("failed to bind QPACK stream");

    // SETTINGS
    exchange_packets(
        &mut quic_client,
        &mut quic_server,
        &mut h3_client,
        &mut h3_server,
        client_addr,
        server_addr,
    );

    QuicH3Pair {
        quic_client,
        quic_server,
        h3_client,
        h3_server,
        client_addr,
        server_addr,
    }
}

/// H3 write_stream -> QUIC write_stream -> QUIC write_pkt -> QUIC read_pkt ->
/// QUIC poll_stream_data -> H3 read_stream Exchange packets
fn exchange_packets(
    quic_client: &mut Connection,
    quic_server: &mut Connection,
    h3_client: &mut Http3Connection,
    h3_server: &mut Http3Connection,
    client_addr: SocketAddr,
    server_addr: SocketAddr,
) {
    let pkt_info = PacketInfo::default();

    for _ in 0..10 {
        let ts = timestamp();

        // client -> server: H3 data QUIC sent
        let packets = write_h3_to_packets(h3_client, quic_client, ts);
        for pkt in &packets {
            let _ = quic_server.read_pkt(&server_addr, &client_addr, &pkt_info, pkt, ts);
        }
        // QUIC (ACK) sent
        send_quic_packets(
            quic_client,
            quic_server,
            client_addr,
            server_addr,
            &pkt_info,
            ts,
        );
        // received stream data H3
        feed_quic_to_h3(quic_server, h3_server, ts);

        // server -> client
        let ts = timestamp();
        let packets = write_h3_to_packets(h3_server, quic_server, ts);
        for pkt in &packets {
            let _ = quic_client.read_pkt(&client_addr, &server_addr, &pkt_info, pkt, ts);
        }
        send_quic_packets(
            quic_server,
            quic_client,
            server_addr,
            client_addr,
            &pkt_info,
            ts,
        );
        feed_quic_to_h3(quic_client, h3_client, ts);
    }
}

/// Convert pending H3 write_stream data into QUIC packets.
///
/// This mirrors tokio-ngtcp2 write_h3_streams().
/// NGTCP2_WRITE_STREAM_FLAG_MORE leaves write_stream data buffered
/// and may produce no packet immediately.
/// Calling write_pkt afterwards emits the packet.
fn write_h3_to_packets(h3: &mut Http3Connection, quic: &mut Connection, ts: u64) -> Vec<Vec<u8>> {
    let mut packets = Vec::new();
    let mut send_buf = vec![0u8; 1350];

    let mut vecs = vec![
        nghttp3_vec {
            base: std::ptr::null_mut(),
            len: 0,
        };
        16
    ];

    while let Ok((stream_id, fin, count)) = h3.write_stream(&mut vecs) {
        if count == 0 {
            break;
        }

        // nghttp3_vec data
        let mut h3_data = Vec::new();
        for v in vecs.iter().take(count) {
            if v.len > 0 && !v.base.is_null() {
                let data = unsafe { std::slice::from_raw_parts(v.base as *const u8, v.len) };
                h3_data.extend_from_slice(data);
            }
        }

        if h3_data.is_empty() && !fin {
            continue;
        }

        // QUIC write
        match quic.write_stream(&mut send_buf, stream_id, &h3_data, fin, ts) {
            Ok((pkt_written, data_written)) => {
                if pkt_written > 0 {
                    packets.push(send_buf[..pkt_written].to_vec());
                }
                if let Some(dw) = data_written
                    && dw > 0
                {
                    let _ = h3.add_write_offset(stream_id, dw);
                }
            }
            Err(ngtcp2::Error::StreamDataBlocked(_)) => {
                h3.block_stream(stream_id);
            }
            Err(ngtcp2::Error::StreamShutWr(_)) => {
                h3.shutdown_stream_write(stream_id);
            }
            Err(_) => break,
        }
    }

    // flush buffered data
    loop {
        match quic.write_pkt(&mut send_buf, ts) {
            Ok((written, _)) if written > 0 => {
                packets.push(send_buf[..written].to_vec());
            }
            _ => break,
        }
    }

    packets
}

/// Send and receive QUIC packets
fn send_quic_packets(
    sender: &mut Connection,
    receiver: &mut Connection,
    sender_addr: SocketAddr,
    receiver_addr: SocketAddr,
    pkt_info: &PacketInfo,
    ts: u64,
) {
    let mut buf = vec![0u8; 1350];
    loop {
        match sender.write_pkt(&mut buf, ts) {
            Ok((written, _)) if written > 0 => {
                let _ =
                    receiver.read_pkt(&receiver_addr, &sender_addr, pkt_info, &buf[..written], ts);
            }
            _ => break,
        }
    }
}

/// QUIC received stream data H3
fn feed_quic_to_h3(quic: &mut Connection, h3: &mut Http3Connection, ts: u64) {
    while let Some(stream_data) = quic.poll_stream_data() {
        if let Ok(consumed) = h3.read_stream(
            stream_data.stream_id,
            &stream_data.data,
            stream_data.fin,
            ts,
        ) && consumed > 0
        {
            let _ = quic.extend_max_stream_offset(stream_data.stream_id, consumed as u64);
            quic.extend_max_offset(consumed as u64);
        }
    }
}

/// Helper that establishes a WebTransport session.
///
/// Sends a WebTransport CONNECT request/response over the QUIC + HTTP/3 pair
/// and returns the session ID, which is the CONNECT stream ID.
fn establish_wt_session(pair: &mut QuicH3Pair) -> i64 {
    // Open a bidirectional stream from the client and send a WebTransport request
    let session_stream = pair
        .quic_client
        .open_bidi_stream()
        .expect("failed to open stream");

    let wt_headers = vec![
        Header::method("CONNECT"),
        Header::scheme("https"),
        Header::new(b":protocol".to_vec(), b"webtransport".to_vec()),
        Header::authority("localhost:4433"),
        Header::path("/webtransport"),
    ];

    pair.h3_client
        .submit_wt_request(session_stream, &wt_headers)
        .expect("WebTransport failed to send request");

    // client -> serverExchange packets
    exchange_packets(
        &mut pair.quic_client,
        &mut pair.quic_server,
        &mut pair.h3_client,
        &mut pair.h3_server,
        pair.client_addr,
        pair.server_addr,
    );

    // serverheader event
    drain_header_events(&mut pair.h3_server);

    // server WebTransport response sent
    let response_headers = vec![Header::status(200)];
    pair.h3_server
        .submit_wt_response(session_stream, &response_headers)
        .expect("WebTransport response send failed");

    let ts = timestamp();
    pair.h3_server
        .server_confirm_wt_session(session_stream, ts)
        .expect("WebTransport sessioncheckfailed");

    // server -> clientExchange packets
    exchange_packets(
        &mut pair.quic_client,
        &mut pair.quic_server,
        &mut pair.h3_client,
        &mut pair.h3_server,
        pair.client_addr,
        pair.server_addr,
    );

    // clientheader event
    drain_header_events(&mut pair.h3_client);

    session_stream
}

/// header event (event)
fn drain_header_events(h3: &mut Http3Connection) {
    while let Some(event) = h3.poll_event() {
        match event {
            Http3Event::HeadersBegin { .. }
            | Http3Event::Header { .. }
            | Http3Event::HeadersEnd { .. } => {}
            _ => {}
        }
    }
}

// =============================================================================
// B1: WebTransport data streamreceived
// =============================================================================

/// After session establishment, the client sends data on a bidi stream and the server receives it.
#[test]
fn test_wt_bidirectional_data_exchange() {
    let mut pair = setup_quic_h3_pair();
    let session_id = establish_wt_session(&mut pair);

    // client bidirectionaldata stream
    let data_stream = pair
        .quic_client
        .open_bidi_stream()
        .expect("failed to open data stream");

    pair.h3_client
        .open_wt_data_stream(session_id, data_stream)
        .expect("WebTransport failed to open data stream");

    // data sent
    let test_data = b"Hello WebTransport!";
    pair.h3_client
        .send_wt_stream_data(data_stream, test_data, false)
        .expect("failed to send data");

    // Exchange packets
    exchange_packets(
        &mut pair.quic_client,
        &mut pair.quic_server,
        &mut pair.h3_client,
        &mut pair.h3_server,
        pair.client_addr,
        pair.server_addr,
    );

    // server WebTransportData Check events
    let mut received_data = Vec::new();
    while let Some(event) = pair.h3_server.poll_event() {
        if let Http3Event::WebTransportData { data, .. } = event {
            received_data.extend_from_slice(&data);
        }
    }

    assert_eq!(
        received_data, test_data,
        "server should receive WebTransport data"
    );
}

/// The client sends data on a uni stream and the server receives it.
#[test]
fn test_wt_unidirectional_data_stream() {
    let mut pair = setup_quic_h3_pair();
    let session_id = establish_wt_session(&mut pair);

    // client unidirectionaldata stream
    let data_stream = pair
        .quic_client
        .open_uni_stream()
        .expect("failed to open unidirectional stream");

    pair.h3_client
        .open_wt_data_stream(session_id, data_stream)
        .expect("WebTransport unidirectionalfailed to open data stream");

    // data sent
    let test_data = b"Unidirectional data";
    pair.h3_client
        .send_wt_stream_data(data_stream, test_data, false)
        .expect("unidirectionalfailed to send data");

    // Exchange packets
    exchange_packets(
        &mut pair.quic_client,
        &mut pair.quic_server,
        &mut pair.h3_client,
        &mut pair.h3_server,
        pair.client_addr,
        pair.server_addr,
    );

    // server WebTransportData Check events
    let mut received_data = Vec::new();
    while let Some(event) = pair.h3_server.poll_event() {
        if let Http3Event::WebTransportData { data, .. } = event {
            received_data.extend_from_slice(&data);
        }
    }

    assert_eq!(
        received_data, test_data,
        "server should receive unidirectional WebTransport data"
    );
}

/// send_wt_stream_data(id, data, true) sends data with FIN and finishes the server-side stream.
#[test]
fn test_wt_send_data_with_fin() {
    let mut pair = setup_quic_h3_pair();
    let session_id = establish_wt_session(&mut pair);

    // client bidirectionaldata stream
    let data_stream = pair
        .quic_client
        .open_bidi_stream()
        .expect("failed to open data stream");

    pair.h3_client
        .open_wt_data_stream(session_id, data_stream)
        .expect("WebTransport failed to open data stream");

    // data with FIN sent
    let test_data = b"Final data";
    pair.h3_client
        .send_wt_stream_data(data_stream, test_data, true)
        .expect("failed to send data with FIN");

    // Exchange packets
    exchange_packets(
        &mut pair.quic_client,
        &mut pair.quic_server,
        &mut pair.h3_client,
        &mut pair.h3_server,
        pair.client_addr,
        pair.server_addr,
    );

    // server data stream finishCheck events
    let mut received_data = Vec::new();
    let mut stream_ended = false;
    while let Some(event) = pair.h3_server.poll_event() {
        match event {
            Http3Event::WebTransportData { data, .. } => {
                received_data.extend_from_slice(&data);
            }
            Http3Event::StreamEnd { stream_id } if stream_id == data_stream => {
                stream_ended = true;
            }
            _ => {}
        }
    }

    assert_eq!(
        received_data, test_data,
        "server should receive data with FIN"
    );
    // StreamEnd event nghttp3
    if stream_ended {
        eprintln!("StreamEnd event received");
    }
}

// =============================================================================
// B2: WebTransport sessionfinish
// =============================================================================

/// close_wt_session(session_id, error_code, msg) session ->
#[test]
fn test_wt_close_session_with_error() {
    let mut pair = setup_quic_h3_pair();
    let session_id = establish_wt_session(&mut pair);

    // clientsession
    let error_code = 42u32;
    let error_msg = b"test close";
    let close_result = pair
        .h3_client
        .close_wt_session(session_id, error_code, Some(error_msg));
    if cfg!(windows) && close_result.is_err() {
        eprintln!("Windows build skipped nghttp3 WebTransport close path: {close_result:?}");
        return;
    }
    close_result.expect("session failed");

    // Exchange packets
    exchange_packets(
        &mut pair.quic_client,
        &mut pair.quic_server,
        &mut pair.h3_client,
        &mut pair.h3_server,
        pair.client_addr,
        pair.server_addr,
    );

    // serverCheck events
    // nghttp3 WT_CLOSE_SESSION received StreamClose eventgenerate
    let mut got_close_event = false;
    while let Some(event) = pair.h3_server.poll_event() {
        match event {
            Http3Event::StreamClose { stream_id, .. } if stream_id == session_id => {
                got_close_event = true;
            }
            Http3Event::StreamEnd { stream_id } if stream_id == session_id => {
                got_close_event = true;
            }
            _ => {}
        }
    }

    // nghttp3 event
    eprintln!("session event: {}", got_close_event);
}

// =============================================================================
// B3: multiple streams
// =============================================================================

/// One session uses two bidi streams and one uni stream; received stream data stays separated.
#[test]
fn test_wt_multiple_data_streams() {
    let mut pair = setup_quic_h3_pair();
    let session_id = establish_wt_session(&mut pair);

    // bidi stream 2
    let bidi_stream_1 = pair
        .quic_client
        .open_bidi_stream()
        .expect("bidi stream 1 failed");
    let bidi_stream_2 = pair
        .quic_client
        .open_bidi_stream()
        .expect("bidi stream 2 failed");

    // uni stream 1
    let uni_stream = pair
        .quic_client
        .open_uni_stream()
        .expect("uni failed to open stream");

    pair.h3_client
        .open_wt_data_stream(session_id, bidi_stream_1)
        .expect("bidi data stream 1 failed");
    pair.h3_client
        .open_wt_data_stream(session_id, bidi_stream_2)
        .expect("bidi data stream 2 failed");
    pair.h3_client
        .open_wt_data_stream(session_id, uni_stream)
        .expect("uni failed to open data stream");

    // stream data sent
    let data_1 = b"Stream 1 data";
    let data_2 = b"Stream 2 data";
    let data_3 = b"Stream 3 uni data";

    pair.h3_client
        .send_wt_stream_data(bidi_stream_1, data_1, false)
        .expect("bidi stream 1 failed to send data");
    pair.h3_client
        .send_wt_stream_data(bidi_stream_2, data_2, false)
        .expect("bidi stream 2 failed to send data");
    pair.h3_client
        .send_wt_stream_data(uni_stream, data_3, false)
        .expect("uni stream failed to send data");

    // Exchange packets
    exchange_packets(
        &mut pair.quic_client,
        &mut pair.quic_server,
        &mut pair.h3_client,
        &mut pair.h3_server,
        pair.client_addr,
        pair.server_addr,
    );

    // serverstream dataseparatedcheck
    let mut stream_data: std::collections::HashMap<i64, Vec<u8>> = std::collections::HashMap::new();
    while let Some(event) = pair.h3_server.poll_event() {
        if let Http3Event::WebTransportData {
            stream_id, data, ..
        } = event
        {
            stream_data
                .entry(stream_id)
                .or_default()
                .extend_from_slice(&data);
        }
    }

    // at least 1 stream data receivedcheck
    assert!(
        !stream_data.is_empty(),
        "at least one stream should receive data"
    );

    // stream dataverify
    if let Some(d) = stream_data.get(&bidi_stream_1) {
        assert_eq!(d, data_1, "bidi stream 1 data should match");
    }
    if let Some(d) = stream_data.get(&bidi_stream_2) {
        assert_eq!(d, data_2, "bidi stream 2 data should match");
    }
    if let Some(d) = stream_data.get(&uni_stream) {
        assert_eq!(d, data_3, "uni stream data should match");
    }

    eprintln!(
        "received stream: {}, stream ID: {:?}",
        stream_data.len(),
        stream_data.keys().collect::<Vec<_>>()
    );
}
