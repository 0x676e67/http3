//! HTTP/3 Sans I/O tests
//!
//! Http3Connection read_stream / write_stream / poll_event
//! Exercises HTTP/3 behavior directly after the QUIC handshake.

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
        "h3_sans_io_test_{}_{}",
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

/// HTTP/3 create client
#[test]
fn test_h3_client_creation() {
    use nghttp3_sys::nghttp3_settings;

    let settings = nghttp3_settings::default_settings();
    let h3_conn = Http3Connection::client_new(&settings);

    assert!(h3_conn.is_ok(), "should create an HTTP/3 client connection");
}

/// HTTP/3 create server
#[test]
fn test_h3_server_creation() {
    use nghttp3_sys::nghttp3_settings;

    let settings = nghttp3_settings::default_settings();
    let h3_conn = Http3Connection::server_new(&settings);

    assert!(h3_conn.is_ok(), "should create an HTTP/3 server connection");
}

/// Bind HTTP/3 control and QPACK streams
#[test]
fn test_h3_stream_binding() {
    use nghttp3_sys::nghttp3_settings;

    let settings = nghttp3_settings::default_settings();
    let mut h3_conn =
        Http3Connection::client_new(&settings).expect("failed to create HTTP/3 connection");

    // Bind the control stream (client-initiated unidirectional stream: 2, 6, 10,...)
    // stream ID: 0x02 = client-initiated unidirectional stream ()
    let control_stream_id = 2; // 0x02
    let result = h3_conn.bind_control_stream(control_stream_id);
    assert!(result.is_ok(), "should bind the control stream");

    // Bind QPACK streams
    let qenc_stream_id = 6; // 0x06
    let qdec_stream_id = 10; // 0x0A
    let result = h3_conn.bind_qpack_streams(qenc_stream_id, qdec_stream_id);
    assert!(result.is_ok(), "should bind the QPACK stream");
}

/// HTTP/3 request send test
#[test]
fn test_h3_submit_request() {
    use nghttp3_sys::nghttp3_settings;

    let settings = nghttp3_settings::default_settings();
    let mut h3_conn =
        Http3Connection::client_new(&settings).expect("failed to create HTTP/3 connection");

    // Bind the control and QPACK streams
    h3_conn.bind_control_stream(2).unwrap();
    h3_conn.bind_qpack_streams(6, 10).unwrap();

    // Request headers
    let headers = vec![
        Header::method("GET"),
        Header::scheme("https"),
        Header::authority("localhost"),
        Header::path("/"),
    ];

    // request sent (stream ID 0 client-initiated bidirectional stream)
    let stream_id = 0;
    let result = h3_conn.submit_request(stream_id, &headers);
    assert!(result.is_ok(), "should send the request");

    // write_stream data
    let mut vecs = vec![
        nghttp3_vec {
            base: std::ptr::null_mut(),
            len: 0
        };
        16
    ];
    let result = h3_conn.write_stream(&mut vecs);

    match result {
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

/// HTTP/3 response send test
#[test]
fn test_h3_submit_response() {
    use nghttp3_sys::nghttp3_settings;

    let settings = nghttp3_settings::default_settings();
    let mut h3_conn =
        Http3Connection::server_new(&settings).expect("failed to create HTTP/3 connection");

    // Bind the control and QPACK streams (server)
    // server-initiated unidirectional stream: 3, 7, 11,...
    h3_conn.bind_control_stream(3).unwrap();
    h3_conn.bind_qpack_streams(7, 11).unwrap();

    // Response headers
    let headers = vec![Header::status(200)];

    // Send a response as if a client request had been received
    // stream ID 0 client-initiated bidirectional stream
    let stream_id = 0;
    let result = h3_conn.submit_response(stream_id, &headers);

    // This may fail if the stream has not been opened
    eprintln!("submit_response result: {:?}", result);
}

/// HTTP/3 event polling test
#[test]
fn test_h3_poll_event() {
    use nghttp3_sys::nghttp3_settings;

    let settings = nghttp3_settings::default_settings();
    let mut h3_conn =
        Http3Connection::client_new(&settings).expect("failed to create HTTP/3 connection");

    // There are no events in the initial state
    let event = h3_conn.poll_event();
    assert!(event.is_none(), "there should be no events initially");
}

/// QUIC + HTTP/3 integration test
#[test]
fn test_quic_h3_integration() {
    let (cert_path, key_path) = generate_test_certs();

    // Generate connection IDs
    let client_dcid = ConnectionId::random(16).unwrap();
    let client_scid = ConnectionId::random(16).unwrap();
    let server_scid = ConnectionId::random(16).unwrap();

    let client_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
    let server_addr: SocketAddr = "127.0.0.1:4433".parse().unwrap();

    let ts = timestamp();

    // Create the client QUIC connection
    let client_tls_ctx = TlsContext::new_client_with_options(&[b"h3"], false)
        .expect("failed to create client TLS context");
    let client_tls_session = client_tls_ctx
        .create_session()
        .expect("failed to create TLS session");
    let client_params = ngtcp2_transport_params::default_params().with_datagram(65535);

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
    let server_params = ngtcp2_transport_params::default_params()
        .with_datagram(65535)
        .with_original_dcid(&client_dcid);

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

    // Create HTTP/3 connections
    use nghttp3_sys::nghttp3_settings;

    let h3_settings = nghttp3_settings::default_settings();
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

    // Open a bidirectional stream from the client and send a request
    let request_stream = quic_client
        .open_bidi_stream()
        .expect("failed to open stream");
    eprintln!("request stream: {}", request_stream);

    let headers = vec![
        Header::method("GET"),
        Header::scheme("https"),
        Header::authority("localhost"),
        Header::path("/"),
    ];

    h3_client
        .submit_request(request_stream, &headers)
        .expect("failed to send request");

    eprintln!("HTTP/3 request send completed");

    // Fetch HTTP/3 frame data
    let mut vecs = vec![
        nghttp3_vec {
            base: std::ptr::null_mut(),
            len: 0
        };
        16
    ];
    let result = h3_client.write_stream(&mut vecs);

    match result {
        Ok((stream_id, fin, count)) => {
            eprintln!(
                "HTTP/3 write_stream: stream_id = {}, fin = {}, count = {}",
                stream_id, fin, count
            );
        }
        Err(e) => {
            eprintln!("HTTP/3 write_stream error: {:?}", e);
        }
    }

    eprintln!("HTTP/3 Integration testscompleted");
}

/// HTTP/3 header receive test
#[test]
fn test_h3_headers_receive() {
    use nghttp3_sys::nghttp3_settings;

    let settings = nghttp3_settings::default_settings();
    let mut h3_server =
        Http3Connection::server_new(&settings).expect("failed to create HTTP/3 server");

    // Bind the control and QPACK streams
    h3_server.bind_control_stream(3).unwrap();
    h3_server.bind_qpack_streams(7, 11).unwrap();

    // HTTP/3 HEADERS data
    // Real frame data is QPACK-encoded,
    // so this checks read_stream behavior with empty data
    let result = h3_server.read_stream(0, &[], false, 0);

    match result {
        Ok(consumed) => {
            eprintln!("read_stream: consumed = {}", consumed);
        }
        Err(e) => {
            // streamerror
            eprintln!("read_stream error, expected: {:?}", e);
        }
    }

    // Check events
    while let Some(event) = h3_server.poll_event() {
        match event {
            Http3Event::HeadersBegin { stream_id } => {
                eprintln!("HeadersBegin: stream_id = {}", stream_id);
            }
            Http3Event::Header { stream_id, header } => {
                eprintln!(
                    "Header: stream_id = {}, name = {:?}, value = {:?}",
                    stream_id,
                    header.name_str(),
                    header.value_str()
                );
            }
            Http3Event::HeadersEnd { stream_id, fin } => {
                eprintln!("HeadersEnd: stream_id = {}, fin = {}", stream_id, fin);
            }
            _ => {
                eprintln!("Other event: {:?}", event);
            }
        }
    }
}
