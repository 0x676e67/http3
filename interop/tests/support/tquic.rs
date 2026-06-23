use std::{
    cell::RefCell,
    collections::HashMap,
    path::PathBuf,
    rc::Rc,
    time::{Duration, Instant},
};

use interop::{
    BoxError, ClientInteropConfig, DEFAULT_INTEROP_CASE, INTEROP_TEST_TIMEOUT,
    generate_test_certificate, install_crypto_provider, interop_body, interop_case_from_path,
    run_local_quinn_client_interop_matrix_with_config,
};
use tquic::h3::NameValue;

use super::cert::CertificateFiles;

// tquic::h3::send_body can accept fewer bytes than the slice we pass when
// QUIC flow control is tight. Keeping chunks moderate reduces retry work while
// still forcing multi-frame DATA paths in the large-body cases.
// https://www.rfc-editor.org/rfc/rfc9114.html#section-7.2.1
const BODY_CHUNK_SIZE: usize = 64 * 1024;

#[derive(Clone, Copy, Debug)]
pub struct ServerConfig {
    qpack_max_table_capacity: Option<u64>,
    qpack_blocked_streams: Option<u64>,
}

impl ServerConfig {
    pub fn stateless_qpack() -> Self {
        Self {
            qpack_max_table_capacity: Some(0),
            qpack_blocked_streams: Some(0),
        }
    }

    pub fn dynamic_qpack() -> Self {
        Self {
            qpack_max_table_capacity: Some(4096),
            qpack_blocked_streams: Some(100),
        }
    }

    fn h3_config(self) -> tquic::h3::Http3Config {
        let mut config = tquic::h3::Http3Config::new().unwrap();

        // RFC 9204 Section 5: these SETTINGS values are the decoder's
        // advertised limits for QPACK dynamic-table use by the peer.
        // https://www.rfc-editor.org/rfc/rfc9204.html#section-5
        if let Some(capacity) = self.qpack_max_table_capacity {
            config.set_qpack_max_table_capacity(capacity);
        }
        if let Some(blocked_streams) = self.qpack_blocked_streams {
            config.set_qpack_blocked_streams(blocked_streams);
        }

        config
    }
}

struct PacketSender {
    socket: RefCell<std::net::UdpSocket>,
}

impl tquic::PacketSendHandler for PacketSender {
    fn on_packets_send(&self, pkts: &[(Vec<u8>, tquic::PacketInfo)]) -> tquic::Result<usize> {
        let socket = self.socket.borrow();
        let mut sent = 0;

        for (pkt, info) in pkts {
            if socket.send_to(pkt, info.dst).is_err() {
                break;
            }
            sent += 1;
        }

        Ok(sent)
    }
}

struct ServerHandler {
    h3_conn: Option<tquic::h3::connection::Http3Connection>,
    config: ServerConfig,
    requests: HashMap<u64, interop::InteropCase>,
    // Body state survives across writable callbacks. Dropping this would make
    // large responses look like random truncation under flow control.
    pending_bodies: HashMap<u64, PendingBody>,
}

struct PendingBody {
    body: Vec<u8>,
    offset: usize,
}

impl ServerHandler {
    fn new(config: ServerConfig) -> Self {
        Self {
            h3_conn: None,
            config,
            requests: HashMap::new(),
            pending_bodies: HashMap::new(),
        }
    }

    fn process_h3_events(&mut self, conn: &mut tquic::Connection) {
        if self.h3_conn.is_none() {
            return;
        }

        let mut buf = [0u8; 4096];
        loop {
            let event = self.h3_conn.as_mut().unwrap().poll(conn);
            match event {
                Ok((stream_id, tquic::h3::Http3Event::Headers { headers, .. })) => {
                    let case = headers
                        .iter()
                        .find(|header| header.name() == b":path")
                        .and_then(|header| std::str::from_utf8(header.value()).ok())
                        .and_then(interop_case_from_path)
                        .unwrap_or(DEFAULT_INTEROP_CASE);
                    self.requests.insert(stream_id, case);
                }
                Ok((stream_id, tquic::h3::Http3Event::Data)) => {
                    // Drain request DATA even though these interop cases use
                    // GET. Leaving bytes unread can hold stream credit and make
                    // response-side progress look like a server send bug.
                    while self
                        .h3_conn
                        .as_mut()
                        .unwrap()
                        .recv_body(conn, stream_id, &mut buf)
                        .is_ok()
                    {}
                }
                Ok((stream_id, tquic::h3::Http3Event::Finished)) => {
                    let case = self
                        .requests
                        .remove(&stream_id)
                        .unwrap_or(DEFAULT_INTEROP_CASE);
                    let body = interop_body(case);
                    let status = case.status.to_string();
                    let content_length = body.len().to_string();

                    // RFC 9114 Section 4.1: once the request stream is
                    // complete, the server responds on that same stream.
                    // https://www.rfc-editor.org/rfc/rfc9114.html#section-4.1
                    let response_headers = vec![
                        tquic::h3::Header::new(b":status", status.as_bytes()),
                        tquic::h3::Header::new(b"content-type", b"application/octet-stream"),
                        tquic::h3::Header::new(b"content-length", content_length.as_bytes()),
                    ];
                    let headers_blocked = match self.h3_conn.as_mut().unwrap().send_headers(
                        conn,
                        stream_id,
                        &response_headers,
                        body.is_empty(),
                    ) {
                        Ok(()) => false,
                        Err(tquic::h3::Http3Error::StreamBlocked) => true,
                        Err(err) => {
                            eprintln!("[tquic server] send headers error: {err:?}");
                            return;
                        }
                    };

                    if !body.is_empty() || headers_blocked {
                        self.pending_bodies
                            .insert(stream_id, PendingBody { body, offset: 0 });
                        self.flush_pending_body(conn, stream_id);
                    }
                }
                Ok((_, tquic::h3::Http3Event::Reset(_))) => {}
                Ok((_, tquic::h3::Http3Event::GoAway)) => {}
                Ok((_, tquic::h3::Http3Event::PriorityUpdate)) => {}
                Err(tquic::h3::Http3Error::Done) => break,
                Err(err) => {
                    eprintln!("[tquic server] h3 poll error: {err:?}");
                    break;
                }
            }
        }

        self.flush_pending_bodies(conn);
    }

    fn flush_pending_bodies(&mut self, conn: &mut tquic::Connection) {
        let stream_ids = self.pending_bodies.keys().copied().collect::<Vec<_>>();
        for stream_id in stream_ids {
            self.flush_pending_body(conn, stream_id);
        }
    }

    fn flush_pending_body(&mut self, conn: &mut tquic::Connection, stream_id: u64) {
        let Some(h3) = self.h3_conn.as_mut() else {
            return;
        };
        let Some(pending) = self.pending_bodies.get_mut(&stream_id) else {
            return;
        };

        if pending.body.is_empty() {
            match h3.send_body(conn, stream_id, bytes::Bytes::new(), true) {
                Ok(_) | Err(tquic::h3::Http3Error::NoError) => {
                    self.pending_bodies.remove(&stream_id);
                }
                Err(tquic::h3::Http3Error::Done | tquic::h3::Http3Error::StreamBlocked) => {
                    let _ = conn.stream_want_write(stream_id, true);
                }
                Err(err) => {
                    eprintln!("[tquic server] send empty body error: {err:?}");
                    self.pending_bodies.remove(&stream_id);
                }
            }
            return;
        }

        loop {
            let remaining = pending.body.len().saturating_sub(pending.offset);
            if remaining == 0 {
                self.pending_bodies.remove(&stream_id);
                break;
            }

            let chunk_len = remaining.min(BODY_CHUNK_SIZE);
            let end = pending.offset + chunk_len;
            let fin = end == pending.body.len();

            // RFC 9114 Section 7.2.1 DATA frames are carried on request
            // streams. tquic::h3::send_body returns the accepted payload byte
            // count, which can be smaller than the Bytes we pass when QUIC
            // flow control is tight. Keep the unsent suffix here and resume
            // when the stream becomes writable again.
            // https://www.rfc-editor.org/rfc/rfc9114.html#section-7.2.1
            // https://docs.rs/tquic/latest/tquic/h3/connection/struct.Http3Connection.html#method.send_body
            match h3.send_body(
                conn,
                stream_id,
                bytes::Bytes::copy_from_slice(&pending.body[pending.offset..end]),
                fin,
            ) {
                Ok(0) => {
                    let _ = conn.stream_want_write(stream_id, true);
                    break;
                }
                Ok(written) => {
                    pending.offset += written;
                    if written < chunk_len {
                        let _ = conn.stream_want_write(stream_id, true);
                        break;
                    }
                }
                Err(tquic::h3::Http3Error::NoError) => continue,
                Err(tquic::h3::Http3Error::Done | tquic::h3::Http3Error::StreamBlocked) => {
                    let _ = conn.stream_want_write(stream_id, true);
                    break;
                }
                Err(err) => {
                    eprintln!("[tquic server] send body error: {err:?}");
                    self.pending_bodies.remove(&stream_id);
                    break;
                }
            }
        }
    }
}

impl tquic::TransportHandler for ServerHandler {
    fn on_conn_created(&mut self, _conn: &mut tquic::Connection) {}

    fn on_conn_established(&mut self, conn: &mut tquic::Connection) {
        let h3_config = self.config.h3_config();
        self.h3_conn = Some(
            tquic::h3::connection::Http3Connection::new_with_quic_conn(conn, &h3_config).unwrap(),
        );
    }

    fn on_conn_closed(&mut self, _conn: &mut tquic::Connection) {}

    fn on_stream_created(&mut self, _conn: &mut tquic::Connection, _stream_id: u64) {}

    fn on_stream_readable(&mut self, conn: &mut tquic::Connection, _stream_id: u64) {
        self.process_h3_events(conn);
    }

    fn on_stream_writable(&mut self, conn: &mut tquic::Connection, stream_id: u64) {
        self.flush_pending_body(conn, stream_id);
        if !self.pending_bodies.contains_key(&stream_id) {
            let _ = conn.stream_want_write(stream_id, false);
        }
    }

    fn on_stream_closed(&mut self, _conn: &mut tquic::Connection, stream_id: u64) {
        self.pending_bodies.remove(&stream_id);
    }

    fn on_new_token(&mut self, _conn: &mut tquic::Connection, _token: Vec<u8>) {}
}

pub async fn run_client_interop(
    server_config: ServerConfig,
    client_config: ClientInteropConfig,
) -> Result<(), BoxError> {
    install_crypto_provider();

    let cert = generate_test_certificate()?;
    let cert_files = CertificateFiles::new(&cert)?;

    let (port_tx, port_rx) = std::sync::mpsc::channel();
    let (shutdown_tx, shutdown_rx) = std::sync::mpsc::channel();
    let cert_path = cert_files.cert_path.clone();
    let key_path = cert_files.key_path.clone();

    let server_thread = std::thread::spawn(move || {
        if let Err(err) = start_server(cert_path, key_path, port_tx, shutdown_rx, server_config) {
            eprintln!("[tquic server] failed: {err:?}");
        }
    });

    let port = port_rx.recv_timeout(Duration::from_secs(5))?;
    let server_addr = format!("127.0.0.1:{port}").parse()?;

    let client_result = tokio::time::timeout(
        INTEROP_TEST_TIMEOUT,
        run_local_quinn_client_interop_matrix_with_config(server_addr, &cert, client_config),
    )
    .await;

    let _ = shutdown_tx.send(());
    let _ = server_thread.join();
    client_result??;
    Ok(())
}

fn start_server(
    cert_path: PathBuf,
    key_path: PathBuf,
    port_tx: std::sync::mpsc::Sender<u16>,
    shutdown_rx: std::sync::mpsc::Receiver<()>,
    server_config: ServerConfig,
) -> Result<(), BoxError> {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0")?;
    let local_addr = socket.local_addr()?;
    port_tx.send(local_addr.port())?;
    socket.set_nonblocking(true)?;

    let mut config = tquic::Config::new()?;
    config.set_max_idle_timeout(10_000);
    config.set_initial_max_data(10_000_000);
    config.set_initial_max_stream_data_bidi_local(1_000_000);
    config.set_initial_max_stream_data_bidi_remote(1_000_000);
    config.set_initial_max_stream_data_uni(1_000_000);
    config.set_initial_max_streams_bidi(100);
    config.set_initial_max_streams_uni(100);

    let tls_config = tquic::TlsConfig::new_server_config(
        cert_path.to_str().ok_or("invalid cert path")?,
        key_path.to_str().ok_or("invalid key path")?,
        vec![b"h3".to_vec()],
        false,
    )?;
    config.set_tls_config(tls_config);

    let sender = Rc::new(PacketSender {
        socket: RefCell::new(socket.try_clone()?),
    });
    let handler = ServerHandler::new(server_config);
    let mut endpoint = tquic::Endpoint::new(Box::new(config), true, Box::new(handler), sender);
    let mut recv_buf = vec![0u8; 65_535];
    let deadline = Instant::now() + INTEROP_TEST_TIMEOUT;

    loop {
        if shutdown_rx.try_recv().is_ok() || Instant::now() >= deadline {
            break;
        }

        let mut made_progress = false;
        loop {
            match socket.recv_from(&mut recv_buf) {
                Ok((len, from)) => {
                    made_progress = true;
                    let pkt_info = tquic::PacketInfo {
                        src: from,
                        dst: local_addr,
                        time: Instant::now(),
                    };
                    let _ = endpoint.recv(&mut recv_buf[..len], &pkt_info);
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(err) => {
                    eprintln!("[tquic server] recv error: {err:?}");
                    break;
                }
            }
        }

        endpoint.on_timeout(Instant::now());
        let _ = endpoint.process_connections();

        if !made_progress {
            let wait = endpoint.timeout().unwrap_or(Duration::from_millis(1));
            // Large DATA responses advance through repeated QUIC writable
            // events. Sleeping after every packet limits throughput badly, so
            // only pause when the socket is drained and no immediate work was
            // observed in this loop.
            // https://www.rfc-editor.org/rfc/rfc9114.html#section-7.2.1
            std::thread::sleep(wait.min(Duration::from_millis(1)));
        }
    }

    endpoint.close(true);
    Ok(())
}
