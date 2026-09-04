//! Single-threaded Rust Client execution and shared `http3`/`h3` request driver.

use std::{
    future::Future,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use http::Uri;
use quinn::crypto::rustls::QuicClientConfig;
use rustls::pki_types::CertificateDer;
use tokio::{
    sync::{mpsc, watch},
    task::{JoinHandle, JoinSet},
};

use super::{
    case::{ALPN_H3, MAX_EXTRA_HEADERS, SERVER_ADDR, SERVER_NAME, workspace_root},
    result::{ClientResult, MEASUREMENT_PROFILE, RESULT_SCHEMA},
};

const REQUEST_URI: &str = "https://localhost:4433/";

#[doc(hidden)]
pub struct ReadyConnection<S> {
    pub sender: S,
    pub driver: JoinHandle<Result<()>>,
    pub quic_connection: quinn::Connection,
}

#[doc(hidden)]
pub trait Adapter: Send + 'static {
    type Sender: Clone + Send + 'static;

    const HTTP3_LIBRARY: &'static str;

    fn connect(
        connection: quinn::Connection,
    ) -> impl Future<Output = Result<ReadyConnection<Self::Sender>>> + Send;

    fn send_request(
        sender: &mut Self::Sender,
        request_uri: Uri,
        expected_body_size: usize,
        extra_headers: usize,
    ) -> impl Future<Output = Result<()>> + Send;
}

#[doc(hidden)]
pub fn run_from_args<A: Adapter>(mut args: impl Iterator<Item = String>) -> Result<()> {
    let requests = parse_positive(&mut args, "requests")?;
    let expected_body_size = parse_nonnegative(&mut args, "expected-body-bytes")?;
    let in_flight = parse_positive(&mut args, "in-flight")?;
    let extra_headers = parse_nonnegative(&mut args, "extra-request-headers")?;
    if in_flight > requests {
        bail!("in-flight requests cannot exceed total requests");
    }
    if extra_headers > MAX_EXTRA_HEADERS {
        bail!("extra request headers cannot exceed {MAX_EXTRA_HEADERS}");
    }
    if let Some(extra) = args.next() {
        bail!("unexpected internal client argument {extra:?}");
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("could not create current-thread client runtime")?;
    let result = runtime.block_on(run_client::<A>(
        requests,
        expected_body_size,
        in_flight,
        extra_headers,
    ))?;

    println!("{}", serde_json::to_string(&result)?);
    Ok(())
}

async fn run_client<A: Adapter>(
    requests: usize,
    expected_body_size: usize,
    in_flight: usize,
    extra_headers: usize,
) -> Result<ClientResult> {
    let expected_bytes = requests
        .checked_mul(expected_body_size)
        .context("total response byte count overflowed usize")?;

    let client_config = client_config()?;
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse()?)?;
    endpoint.set_default_client_config(client_config);
    let connection = connect::<A>(&endpoint).await?;
    let driver = connection.driver;
    let quic_connection = connection.quic_connection;
    let sender_guard = connection.sender;
    let worker_count = requests.min(in_flight);
    let requests_per_worker = requests / worker_count;
    let workers_with_extra_request = requests % worker_count;
    let (prepared_tx, mut prepared_rx) = mpsc::channel(worker_count);
    let (start_tx, start_rx) = watch::channel(false);
    let mut workers = JoinSet::new();
    for worker_index in 0..worker_count {
        let assigned_requests =
            requests_per_worker + usize::from(worker_index < workers_with_extra_request);
        workers.spawn(run_request_worker::<A>(
            sender_guard.clone(),
            assigned_requests,
            expected_body_size,
            extra_headers,
            prepared_tx.clone(),
            start_rx.clone(),
        ));
    }
    drop(prepared_tx);
    drop(start_rx);
    for _ in 0..worker_count {
        prepared_rx
            .recv()
            .await
            .context("request workers exited before reaching the start barrier")?;
    }
    let benchmark_started = Instant::now();
    start_tx
        .send(true)
        .context("request workers exited before the benchmark started")?;

    let mut finished_at = None;
    while let Some(result) = workers.join_next().await {
        let worker_finished_at = result.context("request worker failed")??;
        // Workers overlap, so the batch ends at the latest completion. Summing
        // their durations would double-count parallel request work.
        finished_at = Some(finished_at.map_or(worker_finished_at, |current: Instant| {
            current.max(worker_finished_at)
        }));
    }
    let finished_at = finished_at.context("connection did not run any request workers")?;
    let elapsed = finished_at
        .checked_duration_since(benchmark_started)
        .context("benchmark finish timestamp preceded its start")?;
    let path_max_udp_payload_size = usize::from(quic_connection.stats().path.current_mtu);
    drop(sender_guard);
    drop(quic_connection);

    driver.await.context("HTTP/3 connection driver failed")??;
    endpoint.wait_idle().await;

    Ok(ClientResult {
        schema: RESULT_SCHEMA.to_owned(),
        http3_library: A::HTTP3_LIBRARY.to_owned(),
        quic_backend: "quinn".to_owned(),
        transport_profile: "quinn-default-pmtud".to_owned(),
        measurement_profile: MEASUREMENT_PROFILE.to_owned(),
        path_max_udp_payload_size,
        requests,
        in_flight,
        extra_request_headers: extra_headers,
        response_body_bytes: expected_body_size,
        completed: requests,
        received_bytes: expected_bytes,
        elapsed_ns: duration_ns(elapsed)?,
    })
}

fn client_config() -> Result<quinn::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(CertificateDer::from(std::fs::read(
        workspace_root().join("examples/ca.cert"),
    )?))?;

    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.cipher_suites =
        vec![rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256];
    let mut tls_config = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls_config.alpn_protocols = vec![ALPN_H3.to_vec()];

    Ok(quinn::ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(tls_config)?,
    )))
}

async fn connect<A: Adapter>(endpoint: &quinn::Endpoint) -> Result<ReadyConnection<A::Sender>> {
    let server_addr: SocketAddr = SERVER_ADDR.parse()?;
    let connection = endpoint.connect(server_addr, SERVER_NAME)?.await?;
    let handshake = connection
        .handshake_data()
        .context("QUIC handshake data is unavailable")?
        .downcast::<quinn::crypto::rustls::HandshakeData>()
        .map_err(|_| anyhow::anyhow!("QUIC handshake did not use rustls"))?;
    if handshake.protocol.as_deref() != Some(ALPN_H3) {
        bail!("TLS did not negotiate h3: {:?}", handshake.protocol);
    }
    A::connect(connection).await
}

async fn run_request_worker<A: Adapter>(
    mut sender: A::Sender,
    assigned_requests: usize,
    expected_body_size: usize,
    extra_headers: usize,
    prepared: mpsc::Sender<()>,
    mut start: watch::Receiver<bool>,
) -> Result<Instant> {
    let request_uri = Uri::from_static(REQUEST_URI);
    prepared
        .send(())
        .await
        .context("benchmark controller exited before request worker was prepared")?;
    drop(prepared);
    if !*start.borrow_and_update() {
        start
            .changed()
            .await
            .context("benchmark start barrier closed before release")?;
    }
    for _ in 0..assigned_requests {
        A::send_request(
            &mut sender,
            request_uri.clone(),
            expected_body_size,
            extra_headers,
        )
        .await?;
    }
    // This timestamp defines the throughput denominator. Taking it after
    // JoinSet aggregation would charge Rust-only scheduler unwinding and make
    // the cross-stack comparison unfair.
    Ok(Instant::now())
}

fn parse_positive(args: &mut impl Iterator<Item = String>, name: &str) -> Result<usize> {
    let value = parse_nonnegative(args, name)?;
    if value == 0 {
        bail!("{name} must be greater than zero");
    }
    Ok(value)
}

fn parse_nonnegative(args: &mut impl Iterator<Item = String>, name: &str) -> Result<usize> {
    args.next()
        .with_context(|| format!("missing {name}"))?
        .parse::<usize>()
        .with_context(|| format!("invalid {name}"))
}

fn duration_ns(duration: Duration) -> Result<u64> {
    duration
        .as_nanos()
        .try_into()
        .context("duration exceeded u64 nanoseconds")
}

#[doc(hidden)]
#[macro_export]
macro_rules! client_adapter {
    ($adapter:ident, $http3_crate:ident, $transport:ident, $library:literal) => {
        struct $adapter;

        impl $crate::client::Adapter for $adapter {
            type Sender = $http3_crate::client::SendRequest<$transport::OpenStreams, bytes::Bytes>;

            const HTTP3_LIBRARY: &'static str = $library;

            async fn connect(
                connection: quinn::Connection,
            ) -> anyhow::Result<$crate::client::ReadyConnection<Self::Sender>> {
                let quic_connection = connection.clone();
                let mut builder = $http3_crate::client::builder();
                builder.send_grease(false);
                let (mut connection, sender) = builder
                    .build($transport::Connection::new(connection))
                    .await?;
                let driver = tokio::spawn(async move {
                    let error = std::future::poll_fn(|cx| connection.poll_close(cx)).await;
                    if error.is_h3_no_error() {
                        Ok(())
                    } else {
                        Err(error.into())
                    }
                });
                Ok($crate::client::ReadyConnection {
                    sender,
                    driver,
                    quic_connection,
                })
            }

            async fn send_request(
                sender: &mut Self::Sender,
                request_uri: http::Uri,
                expected_body_size: usize,
                extra_headers: usize,
            ) -> anyhow::Result<()> {
                use anyhow::Context as _;
                use bytes::Buf as _;

                let mut request = http::Request::builder()
                    .method(http::Method::GET)
                    .uri(request_uri);
                for _ in 0..extra_headers {
                    request = request.header(
                        $crate::case::EXTRA_HEADER_NAME.clone(),
                        $crate::case::EXTRA_HEADER_VALUE.clone(),
                    );
                }
                let request = request.body(())?;
                let mut stream = sender.send_request(request).await?;
                stream.finish().await?;

                let response = stream.recv_response().await?;
                if response.version() != http::Version::HTTP_3 {
                    anyhow::bail!("expected HTTP/3 response, got {:?}", response.version());
                }
                if response.status() != http::StatusCode::OK {
                    anyhow::bail!("expected 200 response, got {}", response.status());
                }
                let declared_body_size = response
                    .headers()
                    .get(http::header::CONTENT_LENGTH)
                    .context("response omitted content-length")?
                    .to_str()?
                    .parse::<usize>()?;
                if declared_body_size != expected_body_size {
                    anyhow::bail!(
                        "expected content-length {expected_body_size}, got {declared_body_size}"
                    );
                }

                let mut received = 0usize;
                while let Some(chunk) = stream.recv_data().await? {
                    received = received
                        .checked_add(chunk.remaining())
                        .context("response byte count overflowed usize")?;
                }
                if stream.recv_trailers().await?.is_some() {
                    anyhow::bail!("benchmark response unexpectedly contained trailers");
                }
                if received != expected_body_size {
                    anyhow::bail!("expected {expected_body_size} response bytes, got {received}");
                }

                Ok(())
            }
        }
    };
}
