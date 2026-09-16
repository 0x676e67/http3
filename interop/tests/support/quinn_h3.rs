use std::{net::SocketAddr, sync::Arc, time::Duration};

use bytes::{Buf, Bytes};
use interop::{
    BoxError, ClientInteropConfig, DEFAULT_INTEROP_CASE, FIELD_SECTION_LIMIT_TEST_MAX,
    INTEROP_PADDING_HEADER_NAME, INTEROP_TEST_TIMEOUT, TestCertificate, generate_test_certificate,
    install_crypto_provider, interop_body, interop_case_from_path, interop_response_header_value,
    run_local_quinn_client_interop_matrix_with_config,
    run_local_quinn_client_max_field_section_size_limit,
};
use quinn::crypto::rustls::QuicServerConfig;
use rustls::pki_types::PrivateKeyDer;
use tokio::sync::mpsc;

type HeaderLimitRejectSender = mpsc::UnboundedSender<(u64, u64)>;

#[derive(Clone, Copy, Debug)]
pub struct ServerConfig;

impl ServerConfig {
    pub fn stateless_qpack() -> Self {
        Self
    }
}

pub async fn run_client_interop(
    server_config: ServerConfig,
    client_config: ClientInteropConfig,
) -> Result<(), BoxError> {
    install_crypto_provider();

    let cert = generate_test_certificate()?;
    let (server_task, server_addr) = start_server(&cert, server_config, None)?;

    let client_result = tokio::time::timeout(
        INTEROP_TEST_TIMEOUT,
        run_local_quinn_client_interop_matrix_with_config(server_addr, &cert, client_config),
    )
    .await;

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
    let (reject_tx, mut reject_rx) = mpsc::unbounded_channel();
    let (server_task, server_addr) = start_server(&cert, server_config, Some(reject_tx))?;

    let client = tokio::time::timeout(
        INTEROP_TEST_TIMEOUT,
        run_local_quinn_client_max_field_section_size_limit(server_addr, &cert, client_config),
    );
    let server_reject = tokio::time::timeout(Duration::from_secs(10), reject_rx.recv());
    let (client_result, server_reject) = tokio::join!(client, server_reject);

    server_task.abort();
    let _ = server_task.await;

    match client_result {
        Ok(Err(_)) => {}
        Ok(Ok(())) => {
            return Err(std::io::Error::other(
                "expected h3/quinn server to reject oversized response headers before send",
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
            "timed out waiting for h3/quinn server-side field section rejection",
        )
    })?
    else {
        return Err(std::io::Error::other(
            "h3/quinn server stopped without reporting field section rejection",
        )
        .into());
    };

    assert_eq!(max_size, FIELD_SECTION_LIMIT_TEST_MAX);
    assert!(
        actual_size > max_size,
        "expected h3/quinn server to reject field section over {max_size}, got {actual_size}"
    );

    Ok(())
}

fn start_server(
    cert: &TestCertificate,
    _config: ServerConfig,
    header_limit_rejects: Option<HeaderLimitRejectSender>,
) -> Result<(tokio::task::JoinHandle<()>, SocketAddr), BoxError> {
    let endpoint = quinn::Endpoint::server(server_config(cert)?, "127.0.0.1:0".parse()?)?;
    let local_addr = endpoint.local_addr()?;

    let server_task = tokio::spawn(async move {
        let timeout = tokio::time::sleep(INTEROP_TEST_TIMEOUT);
        tokio::pin!(timeout);

        loop {
            tokio::select! {
                _ = &mut timeout => break,
                accepted = endpoint.accept() => {
                    let Some(connecting) = accepted else {
                        break;
                    };

                    let header_limit_rejects = header_limit_rejects.clone();
                    tokio::spawn(async move {
                        if let Err(err) = serve_connection(connecting, header_limit_rejects).await {
                            eprintln!("[quinn-h3 server] connection failed: {err:?}");
                        }
                    });
                }
            }
        }
    });

    Ok((server_task, local_addr))
}

fn server_config(cert: &TestCertificate) -> Result<quinn::ServerConfig, BoxError> {
    let cert_der = cert.cert_der();
    let key = PrivateKeyDer::try_from(cert.key_der.clone())?;

    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key)?;

    tls_config.alpn_protocols = vec![b"h3".to_vec()];

    Ok(quinn::ServerConfig::with_crypto(Arc::new(
        QuicServerConfig::try_from(tls_config)?,
    )))
}

async fn serve_connection(
    connecting: quinn::Incoming,
    header_limit_rejects: Option<HeaderLimitRejectSender>,
) -> Result<(), BoxError> {
    let conn = connecting.await?;
    let mut http3_conn = h3::server::Connection::new(h3_quinn::Connection::new(conn)).await?;

    loop {
        match http3_conn.accept().await {
            Ok(Some(resolver)) => {
                let header_limit_rejects = header_limit_rejects.clone();
                tokio::spawn(async move {
                    if let Err(err) = handle_request(resolver, header_limit_rejects).await {
                        eprintln!("[quinn-h3 server] request failed: {err:?}");
                    }
                });
            }
            Ok(None) => break,
            Err(err) => return Err(err.into()),
        }
    }

    Ok(())
}

async fn handle_request<C>(
    resolver: h3::server::RequestResolver<C, Bytes>,
    header_limit_rejects: Option<HeaderLimitRejectSender>,
) -> Result<(), BoxError>
where
    C: h3::quic::Connection<Bytes>,
{
    let (request, mut stream) = resolver.resolve_request().await?;
    let case = request
        .uri()
        .path_and_query()
        .map(|path| path.as_str())
        .and_then(interop_case_from_path)
        .unwrap_or(DEFAULT_INTEROP_CASE);

    // RFC 9114 Section 4.1 allows a server to stop reading a request early,
    // but it should use H3_NO_ERROR when asking the client to stop sending.
    // This test server consumes the request instead, so dropping the Quinn
    // receive stream cannot race the client's clean finish with STOP_SENDING.
    // https://www.rfc-editor.org/rfc/rfc9114.html#section-4.1
    while let Some(mut data) = stream.recv_data().await? {
        data.advance(data.remaining());
    }
    let _ = stream.recv_trailers().await?;

    let body = interop_body(case);
    let status = http::StatusCode::from_u16(case.status)?;
    let content_length = body.len().to_string();

    // RFC 9114 Section 4.1: a response is sent on the same client-initiated
    // bidirectional stream as the request.
    // https://www.rfc-editor.org/rfc/rfc9114.html#section-4.1
    let mut response = http::Response::builder()
        .status(status)
        .header("content-type", "application/octet-stream")
        .header("content-length", content_length);

    if let Some(padding) = interop_response_header_value(case) {
        response = response.header(
            http::HeaderName::from_bytes(INTEROP_PADDING_HEADER_NAME)?,
            http::HeaderValue::from_bytes(&padding)?,
        );
    }

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
                "unexpected h3/quinn server-side field section rejection: {actual_size} > {max_size}"
            ))
            .into());
        }
        Err(err) => return Err(err.into()),
    }

    for chunk in body.chunks(64 * 1024) {
        stream.send_data(Bytes::copy_from_slice(chunk)).await?;
    }

    stream.finish().await?;
    Ok(())
}
