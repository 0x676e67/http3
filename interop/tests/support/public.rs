use std::{net::SocketAddr, sync::Arc, time::Duration};

use bytes::{Buf, Bytes};
use futures::future;
use http::header::CONTENT_LENGTH;
use interop::{BoxError, ClientInteropConfig, install_crypto_provider};
use rustls_native_certs::CertificateResult;
use tokio::task::{JoinHandle, JoinSet};

const ALPN_H3: &[u8] = b"h3";
const REAL_CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
const REAL_INTEROP_TIMEOUT: Duration = Duration::from_secs(120);
const REAL_IDLE_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Clone, Copy)]
struct PublicServerTarget {
    name: &'static str,
    uri: &'static str,
    concurrency: &'static [usize],
}

struct PublicServerResponse {
    request_id: usize,
    status: http::StatusCode,
    body_len: usize,
    content_length: Option<u64>,
    content_type: Option<String>,
}

#[derive(Clone, Copy)]
struct PublicClientRun {
    target: PublicServerTarget,
    qpack_name: &'static str,
    qpack_config: ClientInteropConfig,
    grease: GreaseMode,
    concurrency: usize,
}

#[derive(Clone, Copy)]
pub struct GreaseMode {
    name: &'static str,
    send: bool,
}

impl GreaseMode {
    pub const OFF: Self = Self {
        name: "grease-off",
        send: false,
    };

    pub const ON: Self = Self {
        name: "grease-on",
        send: true,
    };
}

const CONCURRENCY_1: &[usize] = &[1];
const CONCURRENCY_1_5_10: &[usize] = &[1, 5, 10];

const PUBLIC_SERVER_TARGETS: &[PublicServerTarget] = &[
    PublicServerTarget {
        name: "nginx",
        uri: "https://quic.nginx.org",
        concurrency: CONCURRENCY_1_5_10,
    },
    PublicServerTarget {
        name: "impersonate",
        uri: "https://fp.impersonate.pro/api/http3",
        concurrency: CONCURRENCY_1_5_10,
    },
    PublicServerTarget {
        name: "cloudflare",
        uri: "https://cloudflare-quic.com",
        concurrency: CONCURRENCY_1_5_10,
    },
    PublicServerTarget {
        name: "google",
        uri: "https://www.google.com/search?hl=id&num=10&q=headless+browser&start=0",
        concurrency: CONCURRENCY_1,
    },
];

pub async fn run_client_interop(
    qpack_name: &'static str,
    qpack_config: ClientInteropConfig,
    grease: GreaseMode,
) -> Result<(), BoxError> {
    install_crypto_provider();

    for target in PUBLIC_SERVER_TARGETS {
        for concurrency in target.concurrency {
            println!(
                "public interop start target={} qpack={} grease={} requests={} uri={}",
                target.name, qpack_name, grease.name, concurrency, target.uri
            );

            tokio::time::timeout(
                REAL_INTEROP_TIMEOUT,
                run_public_server_requests(PublicClientRun {
                    target: *target,
                    qpack_name,
                    qpack_config,
                    grease,
                    concurrency: *concurrency,
                }),
            )
            .await
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!(
                        "timed out public server interop target={} qpack={} grease={} concurrency={} after {:?}",
                        target.name, qpack_name, grease.name, concurrency, REAL_INTEROP_TIMEOUT
                    ),
                )
            })??;
        }
    }

    Ok(())
}

async fn run_public_server_requests(run: PublicClientRun) -> Result<(), BoxError> {
    let uri = run.target.uri.parse::<http::Uri>()?;
    let auth = uri.authority().ok_or("uri must have a host")?.clone();
    let host = auth.host().to_owned();
    let port = auth.port_u16().unwrap_or(443);
    let addrs = lookup_http3_addresses(&host, port).await?;

    let mut last_error = None;

    for addr in addrs {
        match run_public_server_requests_at_addr(run, uri.clone(), &host, addr).await {
            Ok(()) => return Ok(()),
            Err(err) => {
                eprintln!(
                    "public server interop: target={} qpack={} grease={} addr={} failed: {err}",
                    run.target.name, run.qpack_name, run.grease.name, addr
                );
                last_error = Some(err);
            }
        }
    }

    Err(last_error.unwrap_or_else(|| "dns returned no usable addresses".into()))
}

async fn run_public_server_requests_at_addr(
    run: PublicClientRun,
    uri: http::Uri,
    host: &str,
    addr: SocketAddr,
) -> Result<(), BoxError> {
    let mut roots = rustls::RootCertStore::empty();
    let CertificateResult { certs, errors, .. } = rustls_native_certs::load_native_certs();
    for cert in certs {
        if let Err(err) = roots.add(cert) {
            eprintln!("public server interop: failed to parse one native root: {err}");
        }
    }
    for err in errors {
        eprintln!("public server interop: failed to load one native root: {err}");
    }

    let mut tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls_config.enable_early_data = true;
    tls_config.alpn_protocols = vec![ALPN_H3.into()];

    let mut endpoint = http3_quic::quic::Endpoint::client("[::]:0".parse()?)?;
    endpoint.set_default_client_config(http3_quic::quic::ClientConfig::new(Arc::new(
        http3_quic::quic::crypto::rustls::QuicClientConfig::try_from(tls_config)?,
    )));

    let connecting = endpoint.connect(addr, host)?;
    let conn = tokio::time::timeout(REAL_CONNECT_TIMEOUT, connecting)
        .await
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("timed out connecting to {host} at {addr} after {REAL_CONNECT_TIMEOUT:?}"),
            )
        })??;
    let quinn_conn = http3_quic::Connection::new(conn);

    let mut builder = http3::client::builder();
    builder
        .max_field_section_size(262_144)
        .enable_datagram(true)
        .send_grease(run.grease.send);

    // RFC 9114 reserves frame, stream, and SETTINGS codepoints so peers keep
    // ignoring values that are unknown today. Public deployments are worth
    // testing both ways because GREASE often exposes strict parsers.
    // https://www.rfc-editor.org/rfc/rfc9114.html#section-7.2.8
    // https://www.rfc-editor.org/rfc/rfc9114.html#section-6.2.3
    // https://www.rfc-editor.org/rfc/rfc9114.html#section-7.2.4.1

    // RFC 9204 Section 5 is the SETTINGS contract for QPACK dynamic-table use.
    // These public-server tests run both zero SETTINGS and an explicit dynamic
    // table offer because deployments choose different paths.
    // https://www.rfc-editor.org/rfc/rfc9204.html#section-5
    if let Some(capacity) = run.qpack_config.qpack_max_table_capacity {
        builder.qpack_max_table_capacity(capacity);
    }
    if let Some(blocked_streams) = run.qpack_config.qpack_blocked_streams {
        builder.qpack_blocked_streams(blocked_streams);
    }

    let (mut driver, send_request) = builder.build(quinn_conn).await?;
    let driver_task: JoinHandle<_> =
        tokio::spawn(async move { future::poll_fn(|cx| driver.poll_close(cx)).await });

    let mut requests = JoinSet::new();
    for request_id in 0..run.concurrency {
        let send_request = send_request.clone();
        let request_uri = uri.clone();

        requests.spawn(send_public_server_request(
            request_id,
            request_uri,
            send_request,
        ));
    }

    while let Some(result) = requests.join_next().await {
        let response = match result {
            Ok(Ok(response)) => response,
            Ok(Err(err)) => {
                requests.abort_all();
                return Err(err);
            }
            Err(err) => {
                requests.abort_all();
                return Err(std::io::Error::other(format!(
                    "public server interop request task failed: {err}"
                ))
                .into());
            }
        };
        println!(
            "public interop response target={} qpack={} grease={} request={} status={} body_bytes={} content_length={} content_length_match={} content_type={}",
            run.target.name,
            run.qpack_name,
            run.grease.name,
            response.request_id,
            response.status,
            response.body_len,
            format_optional_u64(response.content_length),
            content_length_match_label(response.content_length),
            format_optional_str(response.content_type.as_deref()),
        );
    }

    drop(send_request);
    driver_task.abort();
    endpoint.close(0u32.into(), b"done");
    let _ = tokio::time::timeout(REAL_IDLE_TIMEOUT, endpoint.wait_idle()).await;

    Ok(())
}

async fn send_public_server_request(
    request_id: usize,
    uri: http::Uri,
    mut send_request: http3::client::SendRequest<http3_quic::OpenStreams, Bytes>,
) -> Result<PublicServerResponse, BoxError> {
    let req = http::Request::builder()
        .method(http::Method::GET)
        .uri(uri)
        .body(())?;

    let mut stream: http3::client::RequestStream<http3_quic::BidiStream<Bytes>, _> =
        send_request.send_request(req).await?;
    stream.finish().await?;

    let response = stream.recv_response().await?;
    let status = response.status();
    let headers = response.headers().clone();

    let mut body = Vec::new();
    while let Some(chunk) = stream.recv_data().await? {
        extend_body_from_buf(&mut body, chunk);
    }

    let content_length = parse_content_length(&headers)?;
    if let Some(expected) = content_length {
        let actual = u64::try_from(body.len())?;
        if expected != actual {
            return Err(std::io::Error::other(format!(
                "content-length mismatch for request {request_id}: header={expected}, body={actual}"
            ))
            .into());
        }
    }

    let content_type = headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let body_len = body.len();

    Ok(PublicServerResponse {
        request_id,
        status,
        body_len,
        content_length,
        content_type,
    })
}

async fn lookup_http3_addresses(host: &str, port: u16) -> Result<Vec<SocketAddr>, BoxError> {
    let mut addrs = tokio::net::lookup_host((host, port))
        .await?
        // Public HTTP/3 endpoints often publish IPv6 records before UDP/443 is
        // actually reachable on that path. Keep this suite on IPv4 for now.
        .filter(SocketAddr::is_ipv4)
        .collect::<Vec<_>>();
    addrs.dedup();
    if addrs.is_empty() {
        return Err(format!("dns returned no IPv4 records for {host}:{port}").into());
    }
    Ok(addrs)
}

fn parse_content_length(headers: &http::HeaderMap) -> Result<Option<u64>, BoxError> {
    let mut values = headers.get_all(CONTENT_LENGTH).iter();
    let Some(first) = values.next() else {
        return Ok(None);
    };

    let expected = parse_single_content_length(first)?;
    for value in values {
        let next = parse_single_content_length(value)?;
        if next != expected {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("conflicting content-length values: {expected} and {next}"),
            )
            .into());
        }
    }

    Ok(Some(expected))
}

fn parse_single_content_length(value: &http::HeaderValue) -> Result<u64, BoxError> {
    // Multiple Content-Length field values are only valid when they carry the
    // same decimal value.
    // https://www.rfc-editor.org/rfc/rfc9110.html#section-8.6
    Ok(value.to_str()?.parse::<u64>()?)
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

fn content_length_match_label(value: Option<u64>) -> &'static str {
    if value.is_some() {
        "true"
    } else {
        "not-present"
    }
}

fn format_optional_u64(value: Option<u64>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "not-present".to_string())
}

fn format_optional_str(value: Option<&str>) -> &str {
    value.unwrap_or("not-present")
}
