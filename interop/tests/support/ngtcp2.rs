use std::{collections::HashMap, path::Path};

use interop::{
    BoxError, ClientInteropConfig, DEFAULT_INTEROP_CASE, INTEROP_TEST_TIMEOUT,
    generate_test_certificate, install_crypto_provider, interop_body, interop_case_from_path,
    run_local_quinn_client_interop_matrix_with_config,
};
use ngtcp2::{Header as Ngtcp2Header, Http3Event, Http3SettingsExt, nghttp3_settings};
use tokio_ngtcp2::Server;

use super::cert::CertificateFiles;

#[derive(Clone, Copy, Debug)]
pub struct ServerConfig {
    qpack_max_table_capacity: usize,
    qpack_encoder_max_table_capacity: usize,
    qpack_blocked_streams: usize,
}

impl ServerConfig {
    pub fn stateless_qpack() -> Self {
        Self {
            qpack_max_table_capacity: 0,
            qpack_encoder_max_table_capacity: 0,
            qpack_blocked_streams: 0,
        }
    }

    pub fn dynamic_qpack() -> Self {
        Self {
            qpack_max_table_capacity: 4096,
            qpack_encoder_max_table_capacity: 4096,
            qpack_blocked_streams: 100,
        }
    }

    fn h3_settings(self) -> nghttp3_settings {
        let mut settings = nghttp3_settings::default_settings();

        // RFC 9204 Section 5: these SETTINGS values are the endpoint's
        // permission for QPACK dynamic table capacity and blocked streams.
        // https://www.rfc-editor.org/rfc/rfc9204.html#section-5
        settings.qpack_max_dtable_capacity = self.qpack_max_table_capacity;
        settings.qpack_encoder_max_dtable_capacity = self.qpack_encoder_max_table_capacity;
        settings.qpack_blocked_streams = self.qpack_blocked_streams;
        settings
    }
}

pub async fn run_client_interop(
    server_config: ServerConfig,
    client_config: ClientInteropConfig,
) -> Result<(), BoxError> {
    install_crypto_provider();

    let cert = generate_test_certificate()?;
    let cert_files = CertificateFiles::new(&cert)?;
    let (mut server, server_addr) =
        start_server(&cert_files.cert_path, &cert_files.key_path, server_config).await?;

    let server_task = tokio::spawn(async move {
        let mut requests = HashMap::new();
        let _ = tokio::time::timeout(
            INTEROP_TEST_TIMEOUT,
            server.run(move |_, event| match event {
                Http3Event::Header { stream_id, header } => {
                    if header.name_str() == Some(":path")
                        && let Some(path) = header.value_str()
                    {
                        let case = interop_case_from_path(path).unwrap_or(DEFAULT_INTEROP_CASE);
                        requests.insert(stream_id, case);
                    }
                    None
                }
                Http3Event::HeadersEnd { stream_id, .. } => {
                    let case = requests.remove(&stream_id).unwrap_or(DEFAULT_INTEROP_CASE);
                    let body = interop_body(case);
                    let content_length = body.len().to_string();

                    // tokio-ngtcp2 hands this body to nghttp3's data-reader
                    // queue. The wrapper then reports accepted bytes back with
                    // add_write_offset, which is the important part for large
                    // DATA responses.
                    // https://nghttp2.org/nghttp3/nghttp3_conn_add_write_offset.html
                    // RFC 9114 Section 4.1 lets the server send response
                    // HEADERS on the same bidirectional request stream.
                    // https://www.rfc-editor.org/rfc/rfc9114.html#section-4.1
                    Some((
                        vec![
                            Ngtcp2Header::status(case.status),
                            Ngtcp2Header::new(b"content-type", b"application/octet-stream"),
                            Ngtcp2Header::new(b"content-length", content_length.as_bytes()),
                        ],
                        body,
                    ))
                }
                _ => None,
            }),
        )
        .await;
    });

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

async fn start_server(
    cert_path: &Path,
    key_path: &Path,
    config: ServerConfig,
) -> Result<(Server, std::net::SocketAddr), BoxError> {
    let server = Server::bind(
        "127.0.0.1:0".parse().unwrap(),
        cert_path,
        key_path,
        None,
        Some(config.h3_settings()),
    )
    .await?;
    let addr = server.local_addr();
    Ok((server, addr))
}
