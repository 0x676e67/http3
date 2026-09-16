//! Rust Client execution and shared `http3`/`h3` request driver.
//!
//! Local scheduling experiments use `HTTP3_BENCH_RUNTIME` and
//! `HTTP3_BENCH_RUST_WORKERS`; defaults remain Tokio current-thread. Keep a
//! separate `CRITERION_HOME` per configuration: runtime is not part of result
//! IDs yet. These switches do not change the native nghttp3 Client.

use std::{
    future::Future,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use http::Uri;
use quinn::crypto::rustls::QuicClientConfig;
use rustls::pki_types::CertificateDer;
use tokio::task::{JoinHandle, JoinSet};

use super::{
    case::{ALPN_H3, SERVER_ADDR, SERVER_NAME, workspace_root},
    headers::{Directions, REQUEST_HEADERS, RESPONSE_HEADERS},
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
        qpack: Directions,
    ) -> impl Future<Output = Result<ReadyConnection<Self::Sender>>> + Send;

    fn send_request(
        sender: &mut Self::Sender,
        request_uri: Uri,
        expected_body_size: usize,
        headers: Directions,
    ) -> impl Future<Output = Result<()>> + Send;
}

#[doc(hidden)]
pub fn run_from_args<A: Adapter>(mut args: impl Iterator<Item = String>) -> Result<()> {
    let requests = parse_positive(&mut args, "requests")?;
    let expected_body_size = parse_nonnegative(&mut args, "expected-body-bytes")?;
    let in_flight = parse_positive(&mut args, "in-flight")?;
    let headers = args
        .next()
        .context("missing header mode")?
        .parse::<Directions>()?;
    let qpack = args
        .next()
        .context("missing QPACK mode")?
        .parse::<Directions>()?;
    if in_flight > requests {
        bail!("in-flight requests cannot exceed total requests");
    }
    if let Some(extra) = args.next() {
        bail!("unexpected internal client argument {extra:?}");
    }
    if A::HTTP3_LIBRARY == "h3" && (qpack.request || qpack.response) {
        bail!("h3 only supports qpack=none in this benchmark");
    }
    // Local contention experiment: change scheduling, not the connection or
    // SendRequest ownership. Keep initialization outside the existing timer.
    let threads = match std::env::var("HTTP3_BENCH_RUST_WORKERS") {
        Ok(value) => value
            .parse::<std::num::NonZeroUsize>()
            .context("HTTP3_BENCH_RUST_WORKERS must be a positive integer")?
            .get(),
        Err(std::env::VarError::NotPresent) => 1,
        Err(error) => return Err(error).context("could not read Rust worker count"),
    };
    let scheduling = match std::env::var("HTTP3_BENCH_RUNTIME") {
        Ok(value) => value,
        Err(std::env::VarError::NotPresent) => "tokio".to_owned(),
        Err(error) => return Err(error).context("could not read Client runtime mode"),
    };
    eprintln!("runtime={scheduling}; workers={threads}; connections=1; sockets=1");
    let result = match scheduling.as_str() {
        "tokio" => {
            let mut builder = if threads == 1 {
                tokio::runtime::Builder::new_current_thread()
            } else {
                let mut builder = tokio::runtime::Builder::new_multi_thread();
                builder.worker_threads(threads).thread_name("http3-worker");
                builder
            };
            let runtime = builder
                .enable_all()
                .build()
                .context("could not create Client runtime")?;
            runtime.block_on(run_client::<A>(
                requests,
                expected_body_size,
                in_flight,
                headers,
                qpack,
                Vec::new(),
            ))
        }
        "no-steal-local" | "no-steal-split" => {
            let runtime = pingora_runtime::NoStealRuntime::new(threads, "http3-no-steal");
            let request_runtimes = if scheduling == "no-steal-split" {
                (0..threads)
                    .map(|index| runtime.get_runtime_at(index).clone())
                    .collect()
            } else {
                Vec::new()
            };
            // Initialize the pool before timing and run Endpoint/connect/driver
            // on worker 0. Direct block_on would run the root on the caller.
            let owner = runtime.get_runtime_at(0);
            let result = owner.block_on(owner.spawn(run_client::<A>(
                requests,
                expected_body_size,
                in_flight,
                headers,
                qpack,
                request_runtimes,
            )));
            runtime.shutdown_timeout(Duration::from_secs(5));
            result.context("NoSteal Client task failed")?
        }
        _ => bail!("unsupported Client runtime {scheduling:?}"),
    }?;

    println!("{}", serde_json::to_string(&result)?);
    Ok(())
}

async fn run_client<A: Adapter>(
    requests: usize,
    expected_body_size: usize,
    in_flight: usize,
    headers: Directions,
    qpack: Directions,
    request_runtimes: Vec<tokio::runtime::Handle>,
) -> Result<ClientResult> {
    let expected_bytes = requests
        .checked_mul(expected_body_size)
        .context("total response byte count overflowed usize")?;

    let client_config = client_config()?;
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse()?)?;
    endpoint.set_default_client_config(client_config);
    let server_addr: SocketAddr = SERVER_ADDR.parse()?;
    let collect_stats = std::env::var_os("HTTP3_BENCH_QUINN_STATS").is_some();
    // Reusable setup (runtime, trust store, TLS configuration and UDP endpoint)
    // is excluded. Include this connection's TLS/QUIC handshake and HTTP/3 setup,
    // batch bookkeeping, requests and joining the completed request workers.
    let benchmark_started = Instant::now();
    let ReadyConnection {
        sender: sender_guard,
        driver,
        quic_connection,
    } = connect::<A>(&endpoint, server_addr, qpack).await?;
    // Optional profiling captures request counters before spawning workers.
    // Its snapshot is inside the timer, so profiling timings are diagnostic only.
    let stats_before = collect_stats.then(|| quic_connection.stats());
    let worker_count = requests.min(in_flight);
    // Each worker starts one request, then takes shared slots to keep the window
    // full like the native Client, even when one worker is slower than the rest.
    let remaining_requests = Arc::new(AtomicUsize::new(requests - worker_count));
    let mut workers = JoinSet::new();
    for index in 0..worker_count {
        let request_worker = run_request_worker::<A>(
            sender_guard.clone(),
            remaining_requests.clone(),
            expected_body_size,
            headers,
        );
        if request_runtimes.is_empty() {
            workers.spawn(request_worker);
        } else {
            // Assign a long-lived worker once, not each individual request.
            // Fixed placement removes stealing but not shared-connection locks.
            workers.spawn_on(
                request_worker,
                &request_runtimes[index % request_runtimes.len()],
            );
        }
    }
    while let Some(result) = workers.join_next().await {
        result.context("request worker failed")??;
    }
    // Measure the whole batch at the caller, including normal task completion.
    // Final statistics, connection shutdown and result formatting stay out.
    let elapsed = benchmark_started.elapsed();
    let stats_after = quic_connection.stats();
    let path_max_udp_payload_size = usize::from(stats_after.path.current_mtu);
    if let Some(stats_before) = stats_before {
        // Collection can follow driver work after the last response; these are
        // diagnostic counts, not an exact trace of the timed interval.
        eprintln!("quinn_before={stats_before:?}\nquinn_after={stats_after:?}");
    }
    drop(sender_guard);
    drop(quic_connection);

    driver.await.context("HTTP/3 connection driver failed")??;
    endpoint.wait_idle().await;

    Ok(ClientResult {
        schema: RESULT_SCHEMA.to_owned(),
        http3_library: A::HTTP3_LIBRARY.to_owned(),
        qpack: qpack.to_string(),
        quic_backend: "quinn".to_owned(),
        transport_profile: "quinn-default-pmtud".to_owned(),
        measurement_profile: MEASUREMENT_PROFILE.to_owned(),
        path_max_udp_payload_size,
        requests,
        in_flight,
        request_headers: if headers.request {
            REQUEST_HEADERS.len()
        } else {
            0
        },
        response_headers: if headers.response {
            RESPONSE_HEADERS.len()
        } else {
            0
        },
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
    // Handshakes are timed: match the native peers instead of inheriting a
    // different classical/post-quantum preference from each TLS provider.
    provider.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::X25519];
    let mut tls_config = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls_config.alpn_protocols = vec![ALPN_H3.to_vec()];

    Ok(quinn::ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(tls_config)?,
    )))
}

async fn connect<A: Adapter>(
    endpoint: &quinn::Endpoint,
    server_addr: SocketAddr,
    qpack: Directions,
) -> Result<ReadyConnection<A::Sender>> {
    let connection = endpoint.connect(server_addr, SERVER_NAME)?.await?;
    let handshake = connection
        .handshake_data()
        .context("QUIC handshake data is unavailable")?
        .downcast::<quinn::crypto::rustls::HandshakeData>()
        .map_err(|_| anyhow::anyhow!("QUIC handshake did not use rustls"))?;
    if handshake.protocol.as_deref() != Some(ALPN_H3) {
        bail!("TLS did not negotiate h3: {:?}", handshake.protocol);
    }
    A::connect(connection, qpack).await
}

async fn run_request_worker<A: Adapter>(
    mut sender: A::Sender,
    remaining_requests: Arc<AtomicUsize>,
    expected_body_size: usize,
    headers: Directions,
) -> Result<()> {
    let request_uri = Uri::from_static(REQUEST_URI);
    loop {
        A::send_request(
            &mut sender,
            request_uri.clone(),
            expected_body_size,
            headers,
        )
        .await?;
        // This counter hands out request slots, not data from another worker.
        // A failed decrement leaves zero intact, even when every worker exits.
        if remaining_requests
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |remaining| {
                remaining.checked_sub(1)
            })
            .is_err()
        {
            break;
        }
    }
    Ok(())
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
    (@configure http3, $builder:ident, $qpack:ident) => {
        if $qpack.request {
            $builder.qpack_encoder_table_capacity($crate::case::QPACK_TABLE_CAPACITY);
        }
        if $qpack.response {
            $builder
                .qpack_max_table_capacity(u64::try_from($crate::case::QPACK_TABLE_CAPACITY)?)
                .qpack_blocked_streams($crate::case::QPACK_BLOCKED_STREAMS);
        }
    };
    (@configure h3, $builder:ident, $qpack:ident) => {
        // The fixed upstream revision only wires stateless QPACK into its Client.
        // Running a dynamic case anyway would silently measure a different mode.
        if $qpack.request || $qpack.response {
            anyhow::bail!("h3 only supports qpack=none in this benchmark");
        }
    };
    ($adapter:ident, $http3_crate:ident, $transport:ident, $library:literal) => {
        struct $adapter;

        impl $crate::client::Adapter for $adapter {
            type Sender = $http3_crate::client::SendRequest<$transport::OpenStreams, bytes::Bytes>;

            const HTTP3_LIBRARY: &'static str = $library;

            async fn connect(
                connection: quinn::Connection,
                qpack: $crate::headers::Directions,
            ) -> anyhow::Result<$crate::client::ReadyConnection<Self::Sender>> {
                let quic_connection = connection.clone();
                let mut builder = $http3_crate::client::builder();
                builder.send_grease(false);
                $crate::client_adapter!(@configure $http3_crate, builder, qpack);
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
                headers: $crate::headers::Directions,
            ) -> anyhow::Result<()> {
                use anyhow::Context as _;
                use bytes::Buf as _;

                let mut request = http::Request::builder()
                    .method(http::Method::GET)
                    .uri(request_uri);
                if headers.request {
                    for (name, value) in &$crate::headers::REQUEST_HEADERS {
                        request = request.header(name.clone(), value.clone());
                    }
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
                $crate::headers::validate_headers(
                    response.headers(),
                    &$crate::headers::RESPONSE_HEADERS,
                    headers.response,
                )
                .context("invalid benchmark response headers")?;
                let mut content_lengths = response
                    .headers()
                    .get_all(http::header::CONTENT_LENGTH)
                    .iter();
                let content_length = content_lengths
                    .next()
                    .context("response omitted content-length")?;
                if content_lengths.next().is_some() {
                    anyhow::bail!("response contained duplicate content-length fields");
                }
                let declared_body_size = content_length.to_str()?.parse::<usize>()?;
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
