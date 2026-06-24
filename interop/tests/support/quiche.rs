use std::{path::PathBuf, time::Duration};

use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use interop::{
    BoxError, ClientInteropConfig, DEFAULT_INTEROP_CASE, INTEROP_PADDING_HEADER_NAME,
    INTEROP_TEST_TIMEOUT, generate_test_certificate, install_crypto_provider, interop_body,
    interop_case_from_path, interop_response_header_value,
    run_local_quinn_client_interop_matrix_with_config,
    run_local_quinn_client_max_field_section_size_limit,
};
use tokio::{net::UdpSocket, sync::mpsc};
use tokio_quiche::{
    ConnectionParams, ServerH3Driver,
    buf_factory::BufFactory,
    http3::{
        driver::{
            H3Event, IncomingH3Headers, OutboundFrame, OutboundFrameSender, ServerEventStream,
            ServerH3Event,
        },
        settings::Http3Settings,
    },
    listen,
    metrics::DefaultMetrics,
    quiche::h3::{Header, NameValue},
    settings::{CertificateKind, Hooks, QuicSettings, TlsCertificatePaths},
};

use super::cert::CertificateFiles;

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

    fn h3_settings(self) -> Http3Settings {
        Http3Settings {
            max_header_list_size: Some(16 * 1024),
            // RFC 9204 Section 5: these SETTINGS values advertise whether the
            // peer may use QPACK dynamic-table references and blocked streams.
            // https://www.rfc-editor.org/rfc/rfc9204.html#section-5
            qpack_max_table_capacity: self.qpack_max_table_capacity,
            qpack_blocked_streams: self.qpack_blocked_streams,
            ..Default::default()
        }
    }
}

pub async fn run_client_interop(
    server_config: ServerConfig,
    client_config: ClientInteropConfig,
) -> Result<(), BoxError> {
    install_crypto_provider();

    let cert = generate_test_certificate()?;
    let cert_files = CertificateFiles::new(&cert)?;

    let (port_tx, port_rx) = std::sync::mpsc::channel();
    let (shutdown_tx, shutdown_rx) = mpsc::channel(1);
    let cert_path = cert_files.cert_path.clone();
    let key_path = cert_files.key_path.clone();

    let server_task = tokio::spawn(async move {
        if let Err(err) =
            start_server(cert_path, key_path, port_tx, shutdown_rx, server_config).await
        {
            eprintln!("[tokio-quiche server] failed: {err:?}");
        }
    });

    let port = port_rx.recv_timeout(Duration::from_secs(5))?;
    let server_addr = format!("127.0.0.1:{port}").parse()?;

    let client_result = tokio::time::timeout(
        INTEROP_TEST_TIMEOUT,
        run_local_quinn_client_interop_matrix_with_config(server_addr, &cert, client_config),
    )
    .await;

    let _ = shutdown_tx.send(()).await;
    server_task.abort();
    let _ = server_task.await;
    client_result??;
    Ok(())
}

pub async fn run_max_field_section_size_limit(
    server_config: ServerConfig,
    client_config: ClientInteropConfig,
) -> Result<(), BoxError> {
    install_crypto_provider();

    let cert = generate_test_certificate()?;
    let cert_files = CertificateFiles::new(&cert)?;

    let (port_tx, port_rx) = std::sync::mpsc::channel();
    let (shutdown_tx, shutdown_rx) = mpsc::channel(1);
    let cert_path = cert_files.cert_path.clone();
    let key_path = cert_files.key_path.clone();

    let server_task = tokio::spawn(async move {
        if let Err(err) =
            start_server(cert_path, key_path, port_tx, shutdown_rx, server_config).await
        {
            eprintln!("[tokio-quiche server] failed: {err:?}");
        }
    });

    let port = port_rx.recv_timeout(Duration::from_secs(5))?;
    let server_addr = format!("127.0.0.1:{port}").parse()?;

    let client_result = tokio::time::timeout(
        INTEROP_TEST_TIMEOUT,
        run_local_quinn_client_max_field_section_size_limit(server_addr, &cert, client_config),
    )
    .await;

    let _ = shutdown_tx.send(()).await;
    server_task.abort();
    let _ = server_task.await;
    client_result??;
    Ok(())
}

async fn start_server(
    cert_path: PathBuf,
    key_path: PathBuf,
    port_tx: std::sync::mpsc::Sender<u16>,
    mut shutdown_rx: mpsc::Receiver<()>,
    config: ServerConfig,
) -> Result<(), BoxError> {
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let local_addr = socket.local_addr()?;
    port_tx.send(local_addr.port())?;

    let cert_path = cert_path.to_str().ok_or("invalid cert path")?.to_owned();
    let key_path = key_path.to_str().ok_or("invalid key path")?.to_owned();

    let mut quic_settings = QuicSettings::default();
    quic_settings.max_idle_timeout = Some(Duration::from_secs(10));
    quic_settings.initial_max_data = 10_000_000;
    quic_settings.initial_max_stream_data_bidi_local = 1_000_000;
    quic_settings.initial_max_stream_data_bidi_remote = 1_000_000;
    quic_settings.initial_max_stream_data_uni = 1_000_000;
    quic_settings.initial_max_streams_bidi = 100;
    quic_settings.initial_max_streams_uni = 100;
    quic_settings.disable_active_migration = true;

    let mut listeners = listen(
        [socket],
        ConnectionParams::new_server(
            quic_settings,
            TlsCertificatePaths {
                cert: &cert_path,
                private_key: &key_path,
                kind: CertificateKind::X509,
            },
            Hooks::default(),
        ),
        DefaultMetrics,
    )?;

    let accepted_connections = &mut listeners[0];
    let timeout = tokio::time::sleep(INTEROP_TEST_TIMEOUT);
    tokio::pin!(timeout);

    loop {
        tokio::select! {
            biased;

            _ = shutdown_rx.recv() => break,
            _ = &mut timeout => break,
            accepted = accepted_connections.next() => {
                let Some(accepted) = accepted else {
                    break;
                };

                let conn = match accepted {
                    Ok(conn) => conn,
                    Err(err) => {
                        eprintln!("[tokio-quiche server] accept failed: {err:?}");
                        continue;
                    }
                };

                let (driver, mut controller) = ServerH3Driver::new(config.h3_settings());
                conn.start(driver);

                tokio::spawn(async move {
                    if let Err(err) = serve_connection(controller.event_receiver_mut()).await {
                        eprintln!("[tokio-quiche server] connection failed: {err:?}");
                    }
                });
            }
        }
    }

    Ok(())
}

async fn serve_connection(receiver: &mut ServerEventStream) -> Result<(), BoxError> {
    while let Some(event) = receiver.recv().await {
        match event {
            ServerH3Event::Headers {
                incoming_headers, ..
            } => {
                tokio::spawn(async move {
                    if let Err(err) = send_response(incoming_headers).await {
                        eprintln!("[tokio-quiche server] response failed: {err:?}");
                    }
                });
            }
            ServerH3Event::Core(H3Event::ConnectionError(err)) => return Err(err.into()),
            ServerH3Event::Core(H3Event::ConnectionShutdown(Some(err))) => return Err(err.into()),
            ServerH3Event::Core(H3Event::ConnectionShutdown(None)) => return Ok(()),
            ServerH3Event::Core(_) => {}
        }
    }

    Ok(())
}

async fn send_response(incoming_headers: IncomingH3Headers) -> Result<(), BoxError> {
    let IncomingH3Headers {
        headers,
        send: mut frame_sender,
        ..
    } = incoming_headers;

    assert!(
        headers
            .iter()
            .any(|header| header.name() == b":method" && header.value() == b"GET")
    );

    let case = headers
        .iter()
        .find(|header| header.name() == b":path")
        .and_then(|header| std::str::from_utf8(header.value()).ok())
        .and_then(interop_case_from_path)
        .unwrap_or(DEFAULT_INTEROP_CASE);
    let body = interop_body(case);
    let status = case.status.to_string();
    let content_length = body.len().to_string();
    let padding = interop_response_header_value(case);

    // RFC 9114 Section 4.1: response HEADERS and DATA are sent on the same
    // client-initiated bidirectional stream as the request.
    // https://www.rfc-editor.org/rfc/rfc9114.html#section-4.1
    let mut response_headers = vec![
        Header::new(b":status", status.as_bytes()),
        Header::new(b"content-type", b"application/octet-stream"),
        Header::new(b"content-length", content_length.as_bytes()),
    ];
    if let Some(padding) = padding.as_ref() {
        response_headers.push(Header::new(INTEROP_PADDING_HEADER_NAME, padding));
    }

    frame_sender
        .send(OutboundFrame::Headers(response_headers, None))
        .await?;
    send_body(&mut frame_sender, body).await
}

async fn send_body(frame_sender: &mut OutboundFrameSender, body: Vec<u8>) -> Result<(), BoxError> {
    // tokio-quiche frames own their buffers. Split large responses at the
    // backend's buffer size so DATA is drained through normal flow-control
    // paths instead of one very large allocation.
    // https://www.rfc-editor.org/rfc/rfc9114.html#section-7.2.1
    // https://docs.rs/tokio-quiche/latest/tokio_quiche/buf_factory/struct.BufFactory.html
    for chunk in body.chunks(BufFactory::MAX_BUF_SIZE) {
        frame_sender
            .send(OutboundFrame::Body(Bytes::copy_from_slice(chunk), false))
            .await?;
    }

    frame_sender
        .send(OutboundFrame::Body(Bytes::new(), true))
        .await?;
    Ok(())
}
