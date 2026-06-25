use std::{error::Error, net::SocketAddr, sync::Arc, time::Duration};

use bytes::{Buf, Bytes};
use futures::future;
use rustls::pki_types::CertificateDer;
use tokio::task::JoinHandle;

pub type BoxError = Box<dyn Error + Send + Sync>;

pub const INTEROP_ROUNDS: usize = 3;
pub const INTEROP_CONCURRENCY: usize = 4;
pub const INTEROP_TEST_TIMEOUT: Duration = Duration::from_secs(180);
const DEFAULT_BODY_LEN: usize = 36;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InteropCase {
    pub status: u16,
    pub body_len: usize,
}

// Keep this table intentionally mixed: small bodies catch header-only and
// single-packet paths, while the MiB cases force DATA over many QUIC stream
// writes. That is where backend bugs around flow control, partial writes, and
// FIN delivery have shown up before.
// https://www.rfc-editor.org/rfc/rfc9114.html#section-7.2.1
pub const INTEROP_CASES: &[InteropCase] = &[
    InteropCase {
        status: 200,
        body_len: 0,
    },
    InteropCase {
        status: 200,
        body_len: 1,
    },
    InteropCase {
        status: 201,
        body_len: 1024,
    },
    InteropCase {
        status: 204,
        body_len: 0,
    },
    InteropCase {
        status: 404,
        body_len: 128,
    },
    InteropCase {
        status: 503,
        body_len: 16 * 1024,
    },
    InteropCase {
        status: 200,
        body_len: 32 * 1024,
    },
    InteropCase {
        status: 200,
        body_len: 64 * 1024,
    },
    InteropCase {
        status: 200,
        body_len: 128 * 1024,
    },
    InteropCase {
        status: 200,
        body_len: 256 * 1024,
    },
    InteropCase {
        status: 200,
        body_len: 512 * 1024,
    },
    InteropCase {
        status: 200,
        body_len: 1024 * 1024,
    },
    InteropCase {
        status: 200,
        body_len: 2 * 1024 * 1024,
    },
    InteropCase {
        status: 200,
        body_len: 4 * 1024 * 1024,
    },
    InteropCase {
        status: 200,
        body_len: 8 * 1024 * 1024,
    },
    InteropCase {
        status: 200,
        body_len: 16 * 1024 * 1024,
    },
];

pub const DEFAULT_INTEROP_CASE: InteropCase = InteropCase {
    status: 200,
    body_len: DEFAULT_BODY_LEN,
};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ClientInteropConfig {
    pub qpack_max_table_capacity: Option<u64>,
    pub qpack_blocked_streams: Option<u64>,
}

impl ClientInteropConfig {
    /// Explicitly disables client-side QPACK dynamic-table support.
    ///
    /// RFC 9204 gives both QPACK SETTINGS a default value of zero. Sending
    /// zero here keeps the same protocol state while making the interop matrix
    /// exercise the SETTINGS negotiation path.
    ///
    /// See RFC 9204 Section 5:
    /// <https://www.rfc-editor.org/rfc/rfc9204.html#section-5>
    pub fn stateless_qpack() -> Self {
        Self {
            qpack_max_table_capacity: Some(0),
            qpack_blocked_streams: Some(0),
        }
    }

    /// Enables the client-side QPACK SETTINGS needed for dynamic-table interop.
    ///
    /// See RFC 9204 Section 5:
    /// <https://www.rfc-editor.org/rfc/rfc9204.html#section-5>
    pub fn qpack_dynamic_table() -> Self {
        Self {
            qpack_max_table_capacity: Some(65535),
            qpack_blocked_streams: Some(100),
        }
    }
}

pub fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

pub struct TestCertificate {
    pub cert_pem: String,
    pub key_pem: String,
    cert_der: CertificateDer<'static>,
}

pub fn generate_test_certificate() -> Result<TestCertificate, BoxError> {
    let subject_alt_names = vec!["localhost".to_string(), "127.0.0.1".to_string()];
    let key = rcgen::generate_simple_self_signed(subject_alt_names)?;
    let cert_der = key.cert.der().clone();

    Ok(TestCertificate {
        cert_pem: key.cert.pem(),
        key_pem: key.signing_key.serialize_pem(),
        cert_der,
    })
}

pub fn interop_request_path(case: InteropCase, round: usize, index: usize) -> String {
    format!(
        "/interop/status/{}/body/{}/round/{round}/case/{index}",
        case.status, case.body_len
    )
}

pub fn interop_case_from_path(path: &str) -> Option<InteropCase> {
    let mut parts = path.trim_start_matches('/').split('/');

    match (
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
    ) {
        (Some("interop"), Some("status"), Some(status), Some("body"), Some(body_len)) => {
            Some(InteropCase {
                status: status.parse().ok()?,
                body_len: body_len.parse().ok()?,
            })
        }
        _ => None,
    }
}

pub fn interop_body(case: InteropCase) -> Vec<u8> {
    (0..case.body_len)
        .map(|index| b'a' + ((index + case.status as usize) % 26) as u8)
        .collect()
}

pub fn interop_requests() -> Vec<(InteropCase, String)> {
    let mut requests = Vec::with_capacity(INTEROP_ROUNDS * INTEROP_CASES.len());

    for round in 0..INTEROP_ROUNDS {
        for (index, case) in INTEROP_CASES.iter().copied().enumerate() {
            requests.push((case, interop_request_path(case, round, index)));
        }
    }

    requests
}

pub async fn run_local_quinn_client_interop_matrix_with_config(
    server_addr: SocketAddr,
    cert: &TestCertificate,
    config: ClientInteropConfig,
) -> Result<(), BoxError> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.cert_der.clone())?;

    let mut tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls_config.alpn_protocols = vec![b"h3".to_vec()];

    let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse()?)?;
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)?,
    )));

    let conn = endpoint.connect(server_addr, "localhost")?.await?;
    let quinn_conn = http3_quinn_rs::Connection::new(conn);

    let mut builder = http3_rs::client::builder();
    builder.max_field_section_size(16 * 1024).send_grease(false);

    // RFC 9204 Section 5 defines the QPACK SETTINGS parameters that permit
    // dynamic-table use. Leaving them unset, or setting them to zero, keeps the
    // peer on literal/static-table field sections.
    // https://www.rfc-editor.org/rfc/rfc9204.html#section-5
    if let Some(capacity) = config.qpack_max_table_capacity {
        builder.qpack_max_table_capacity(capacity);
    }
    if let Some(blocked_streams) = config.qpack_blocked_streams {
        builder.qpack_blocked_streams(blocked_streams);
    }

    let (mut driver, send_request) = builder.build(quinn_conn).await?;

    // The http3-rs client makes connection progress from the driver future.
    // Keep it alive while request tasks are waiting on response HEADERS/DATA.
    let driver_task =
        tokio::spawn(async move { future::poll_fn(|cx| driver.poll_close(cx)).await });

    let requests = interop_requests();
    for batch in requests.chunks(INTEROP_CONCURRENCY) {
        let mut handles = Vec::with_capacity(batch.len());

        // Requests in one batch run concurrently. The batch size keeps the test
        // cheap enough for CI while still exercising independent request
        // streams and QPACK blocked-stream accounting.
        for (case, path) in batch.iter().cloned() {
            let mut send_request = send_request.clone();
            let port = server_addr.port();
            let task_path = path.clone();

            let handle = tokio::spawn(async move {
                let expected_status = http::StatusCode::from_u16(case.status)?;
                let req = http::Request::builder()
                    .method(http::Method::GET)
                    .uri(format!("https://localhost:{port}{task_path}"))
                    .body(())?;

                let mut stream: http3_rs::client::RequestStream<
                    http3_quinn_rs::BidiStream<Bytes>,
                    _,
                > = send_request.send_request(req).await?;
                stream.finish().await?;

                let body = read_response(stream, expected_status).await?;
                let expected_body = interop_body(case);
                assert_body_eq(&task_path, &body, &expected_body);
                Ok::<(), BoxError>(())
            });

            handles.push((path, handle));
        }

        wait_for_interop_tasks(batch, handles).await?;
    }

    drop(send_request);

    driver_task.abort();
    endpoint.close(0u32.into(), b"done");
    endpoint.wait_idle().await;

    Ok(())
}

async fn wait_for_interop_tasks(
    batch: &[(InteropCase, String)],
    mut handles: Vec<(String, JoinHandle<Result<(), BoxError>>)>,
) -> Result<(), BoxError> {
    let timeout = interop_batch_timeout(batch);
    let deadline = tokio::time::Instant::now() + timeout;

    while let Some((path, mut handle)) = handles.pop() {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        match tokio::time::timeout(remaining, &mut handle).await {
            Ok(Ok(result)) => result?,
            Ok(Err(err)) => {
                abort_interop_tasks(handles);
                return Err(std::io::Error::other(format!(
                    "interop request task failed for {path}: {err}"
                ))
                .into());
            }
            Err(_) => {
                handle.abort();
                abort_interop_tasks(handles);
                let paths = batch
                    .iter()
                    .map(|(_, path)| path.as_str())
                    .collect::<Vec<_>>()
                    .join(", ");
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!(
                        "timed out waiting for interop response batch of {} after {:?}: {paths}",
                        batch.len(),
                        timeout,
                    ),
                )
                .into());
            }
        }
    }

    Ok(())
}

fn abort_interop_tasks(handles: Vec<(String, JoinHandle<Result<(), BoxError>>)>) {
    for (_, handle) in handles {
        handle.abort();
    }
}

fn assert_body_eq(path: &str, actual: &[u8], expected: &[u8]) {
    assert_eq!(
        actual.len(),
        expected.len(),
        "mismatched response length for {path}"
    );

    if let Some(index) = actual.iter().zip(expected).position(|(a, b)| a != b) {
        panic!(
            "mismatched response byte for {path}: index {index}, actual {}, expected {}",
            actual[index], expected[index]
        );
    }
}

fn interop_batch_timeout(batch: &[(InteropCase, String)]) -> Duration {
    let body_bytes = batch
        .iter()
        .map(|(case, _)| case.body_len as u64)
        .sum::<u64>();
    let body_mib = body_bytes.div_ceil(1024 * 1024);

    // Large-body backends may need several writable notifications to drain all
    // DATA. Scale the timeout with payload size so a real stall is still
    // visible, but slower Windows debug builds do not fail just for 16MiB.
    Duration::from_secs(10 + body_mib * 4)
}

async fn read_response(
    mut stream: http3_rs::client::RequestStream<http3_quinn_rs::BidiStream<Bytes>, Bytes>,
    expected_status: http::StatusCode,
) -> Result<Vec<u8>, BoxError> {
    let response = stream.recv_response().await?;
    let status = response.status();
    assert_eq!(status, expected_status);

    let mut body = Vec::new();
    while let Some(chunk) = stream.recv_data().await? {
        extend_body_from_buf(&mut body, chunk);
    }

    Ok(body)
}

fn extend_body_from_buf<B: Buf>(body: &mut Vec<u8>, mut buf: B) {
    // Buf::chunk() only exposes the current contiguous slice. Drain the whole
    // buffer so vectored receive implementations are checked the same way.
    while buf.has_remaining() {
        let chunk = buf.chunk();
        if chunk.is_empty() {
            break;
        }
        body.extend_from_slice(chunk);
        buf.advance(chunk.len());
    }
}
