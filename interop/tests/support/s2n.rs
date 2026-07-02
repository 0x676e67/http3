use std::{path::PathBuf, time::Duration};

use bytes::Bytes;
use h3::{
    error::{Code, ConnectionError},
    quic::ConnectionErrorIncoming,
};
use interop::{
    BoxError, ClientInteropConfig, DEFAULT_INTEROP_CASE, FIELD_SECTION_LIMIT_TEST_MAX,
    INTEROP_PADDING_HEADER_NAME, INTEROP_TEST_TIMEOUT, generate_test_certificate,
    install_crypto_provider, interop_body, interop_case_from_path, interop_response_header_value,
    run_local_quinn_client_interop_matrix_with_config,
    run_local_quinn_client_max_field_section_size_limit,
};
use s2n_quic::{Server, provider::limits::Limits};
use s2n_quic_h3::Connection as S2nH3Connection;
use tokio::sync::mpsc;

use super::cert::CertificateFiles;

type HeaderLimitRejectSender = mpsc::UnboundedSender<(u64, u64)>;

#[derive(Clone, Copy, Debug)]
pub struct ServerConfig {
    send_grease: bool,
}

impl ServerConfig {
    pub fn stateless_qpack() -> Self {
        Self { send_grease: false }
    }

    /// Enables server-side HTTP/3 GREASE through the upstream h3 server stack.
    ///
    /// s2n-quic-h3 only adapts s2n-quic to h3's QUIC traits; reserved
    /// SETTINGS, frame, and stream codepoints are emitted by h3 itself.
    ///
    /// See RFC 9114:
    /// <https://www.rfc-editor.org/rfc/rfc9114.html#section-7.2.8>
    /// <https://www.rfc-editor.org/rfc/rfc9114.html#section-6.2.3>
    /// <https://www.rfc-editor.org/rfc/rfc9114.html#section-7.2.4.1>
    pub fn with_grease(mut self) -> Self {
        self.send_grease = true;
        self
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
        if let Err(err) = start_server(
            cert_path,
            key_path,
            port_tx,
            shutdown_rx,
            server_config,
            None,
        )
        .await
        {
            eprintln!("[s2n/h3 server] failed: {err:?}");
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
    let (reject_tx, mut reject_rx) = mpsc::unbounded_channel();
    let cert_path = cert_files.cert_path.clone();
    let key_path = cert_files.key_path.clone();

    let server_task = tokio::spawn(async move {
        if let Err(err) = start_server(
            cert_path,
            key_path,
            port_tx,
            shutdown_rx,
            server_config,
            Some(reject_tx),
        )
        .await
        {
            eprintln!("[s2n/h3 server] failed: {err:?}");
        }
    });

    let port = port_rx.recv_timeout(Duration::from_secs(5))?;
    let server_addr = format!("127.0.0.1:{port}").parse()?;

    let client = tokio::time::timeout(
        INTEROP_TEST_TIMEOUT,
        run_local_quinn_client_max_field_section_size_limit(server_addr, &cert, client_config),
    );
    let server_reject = tokio::time::timeout(Duration::from_secs(10), reject_rx.recv());
    let (client_result, server_reject) = tokio::join!(client, server_reject);

    let _ = shutdown_tx.send(()).await;
    server_task.abort();
    let _ = server_task.await;

    match client_result {
        Ok(Err(_)) => {}
        Ok(Ok(())) => {
            return Err(std::io::Error::other(
                "expected s2n/h3 server to reject oversized response headers before send",
            )
            .into());
        }
        Err(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "timed out waiting for client-side max_field_section_size result",
            )
            .into());
        }
    }

    let Some((actual_size, max_size)) = server_reject.map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "timed out waiting for s2n/h3 server-side field section rejection",
        )
    })?
    else {
        return Err(std::io::Error::other(
            "s2n/h3 server stopped without reporting field section rejection",
        )
        .into());
    };

    assert_eq!(max_size, FIELD_SECTION_LIMIT_TEST_MAX);
    assert!(
        actual_size > max_size,
        "expected s2n/h3 server to reject field section over {max_size}, got {actual_size}"
    );

    Ok(())
}

async fn start_server(
    cert_path: PathBuf,
    key_path: PathBuf,
    port_tx: std::sync::mpsc::Sender<u16>,
    mut shutdown_rx: mpsc::Receiver<()>,
    config: ServerConfig,
    header_limit_rejects: Option<HeaderLimitRejectSender>,
) -> Result<(), BoxError> {
    let limits = Limits::new()
        .with_max_idle_timeout(Duration::from_secs(10))?
        .with_data_window(32 * 1024 * 1024)?
        .with_bidirectional_remote_data_window(16 * 1024 * 1024)?
        .with_unidirectional_data_window(1024 * 1024)?
        .with_max_open_remote_bidirectional_streams(100)?
        .with_max_open_remote_unidirectional_streams(100)?
        .with_max_send_buffer_size(2 * 1024 * 1024)?;

    let mut server = Server::builder()
        .with_tls((cert_path.as_path(), key_path.as_path()))?
        .with_io("127.0.0.1:0")?
        .with_limits(limits)?
        .start()?;
    let local_addr = server.local_addr()?;
    port_tx.send(local_addr.port())?;

    let timeout = tokio::time::sleep(INTEROP_TEST_TIMEOUT);
    tokio::pin!(timeout);

    loop {
        tokio::select! {
            biased;

            _ = shutdown_rx.recv() => break,
            _ = &mut timeout => break,
            accepted = server.accept() => {
                let Some(connection) = accepted else {
                    break;
                };

                let header_limit_rejects = header_limit_rejects.clone();
                tokio::spawn(async move {
                    let result =
                        serve_connection(S2nH3Connection::new(connection), config, header_limit_rejects)
                            .await;
                    if let Err(err) = result
                        && !is_h3_no_error(&err)
                    {
                        eprintln!("[s2n/h3 server] connection failed: {err:?}");
                    }
                });
            }
        }
    }

    Ok(())
}

fn is_h3_no_error(error: &ConnectionError) -> bool {
    // The test client closes the underlying QUIC connection with application
    // code 0 after all responses are read. That is harness shutdown, while
    // h3's own no-error code is H3_NO_ERROR (0x100).
    // https://www.rfc-editor.org/rfc/rfc9000.html#section-20.2
    matches!(
        error,
        ConnectionError::Remote(ConnectionErrorIncoming::ApplicationClose { error_code })
            if *error_code == 0 || *error_code == Code::H3_NO_ERROR.value()
    ) || error.is_h3_no_error()
}

async fn serve_connection(
    connection: S2nH3Connection,
    config: ServerConfig,
    header_limit_rejects: Option<HeaderLimitRejectSender>,
) -> Result<(), h3::error::ConnectionError> {
    let mut builder = h3::server::builder();
    builder
        .max_field_section_size(16 * 1024)
        .send_grease(config.send_grease);

    let mut connection = builder.build(connection).await?;

    loop {
        let Some(resolver) = connection.accept().await? else {
            return Ok(());
        };

        let header_limit_rejects = header_limit_rejects.clone();
        tokio::spawn(async move {
            if let Err(err) = serve_request(resolver, header_limit_rejects).await {
                eprintln!("[s2n/h3 server] request failed: {err:?}");
            }
        });
    }
}

async fn serve_request(
    resolver: h3::server::RequestResolver<S2nH3Connection, Bytes>,
    header_limit_rejects: Option<HeaderLimitRejectSender>,
) -> Result<(), BoxError> {
    let (request, mut stream) = resolver.resolve_request().await?;
    while let Some(_chunk) = stream.recv_data().await? {}

    let case = request
        .uri()
        .path_and_query()
        .and_then(|path| interop_case_from_path(path.as_str()))
        .unwrap_or(DEFAULT_INTEROP_CASE);
    let body = interop_body(case);
    let content_length = body.len().to_string();
    let padding = interop_response_header_value(case);

    let mut response = http::Response::builder()
        .status(case.status)
        .header("content-type", "application/octet-stream")
        .header("content-length", content_length);

    if let Some(padding) = padding {
        response = response.header(INTEROP_PADDING_HEADER_NAME, padding);
    }

    // RFC 9114 Section 4.1 sends response HEADERS and DATA on the same
    // client-initiated bidirectional stream that carried the request.
    // https://www.rfc-editor.org/rfc/rfc9114.html#section-4.1
    match stream.send_response(response.body(())?).await {
        Ok(()) => {}
        Err(h3::error::StreamError::HeaderTooBig {
            actual_size,
            max_size,
            ..
        }) => {
            if let Some(rejects) = header_limit_rejects {
                let _ = rejects.send((actual_size, max_size));
                return Ok(());
            }

            return Err(std::io::Error::other(format!(
                "unexpected s2n/h3 server-side field section rejection: {actual_size} > {max_size}"
            ))
            .into());
        }
        Err(err) => return Err(err.into()),
    }
    if !body.is_empty() {
        stream.send_data(Bytes::from(body)).await?;
    }
    stream.finish().await?;

    Ok(())
}
