//! Isolated http3 and h3 Servers sharing transport, validation, and response handling.

use std::{
    io::{Read, Write},
    sync::Arc,
    thread,
    time::Duration,
};

use anyhow::{Context, Result, bail};
use bytes::Bytes;
use http::StatusCode;
use quinn::crypto::rustls::QuicServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::task::JoinSet;

use super::{
    case::{
        ALPN_H3, Http3Library, SERVER_ADDR, SERVER_MAX_BIDI_STREAMS, SERVER_WORKERS, workspace_root,
    },
    headers::{HeaderMode, REQUEST_HEADERS, RESPONSE_HEADERS, validate_headers},
};

pub(crate) fn run_from_args(mut args: impl Iterator<Item = String>) -> Result<()> {
    let library = match args
        .next()
        .context("missing server HTTP/3 library")?
        .as_str()
    {
        "http3" => Http3Library::Http3,
        "h3" => Http3Library::H3,
        library => bail!("unsupported server HTTP/3 library {library:?}"),
    };
    let body_bytes = args
        .next()
        .context("missing server response body size")?
        .parse::<usize>()
        .context("invalid server response body size")?;
    let headers = args
        .next()
        .context("missing header mode")?
        .parse::<HeaderMode>()?;
    if let Some(extra) = args.next() {
        bail!("unexpected internal server argument {extra:?}");
    }

    // Keep each connection's driver and request tasks on one worker. With work stealing,
    // small writes contend on Quinn's connection lock and can trigger premature packet flushes.
    // https://github.com/quinn-rs/quinn/issues/1433#issuecomment-1292787963
    let runtime = pingora_runtime::NoStealRuntime::new(SERVER_WORKERS, "bench-server");
    let workers = (1..SERVER_WORKERS)
        .map(|index| runtime.get_runtime_at(index).clone())
        .collect::<Vec<_>>();

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    thread::spawn(move || {
        let mut byte = [0u8; 1];
        let _ = std::io::stdin().read(&mut byte);
        let _ = shutdown_tx.send(());
    });
    // Spawn the Server onto the pool; block_on only joins it from the process's main thread.
    // Polling run_server directly here would run its endpoint/accept loop outside the pool.
    // Reserve worker 0 for the Endpoint. Random placement would mix same-runtime and
    // cross-runtime UDP delivery between samples, obscuring Client comparisons.
    let handle = runtime.get_runtime_at(0);
    let result = handle.block_on(handle.spawn(run_server(
        library,
        body_bytes,
        headers,
        shutdown_rx,
        workers,
    )));
    runtime.shutdown_timeout(Duration::from_secs(5));
    result.context("benchmark server task failed")?
}

async fn run_server(
    library: Http3Library,
    body_bytes: usize,
    headers: HeaderMode,
    mut shutdown: tokio::sync::oneshot::Receiver<()>,
    workers: Vec<tokio::runtime::Handle>,
) -> Result<()> {
    if workers.is_empty() {
        bail!("benchmark server needs an Endpoint worker and at least one connection worker");
    }
    let body = Bytes::from(vec![b'A'; body_bytes]);
    let cert = CertificateDer::from(std::fs::read(
        workspace_root().join("examples/server.cert"),
    )?);
    let key = PrivateKeyDer::try_from(std::fs::read(workspace_root().join("examples/server.key"))?)
        .map_err(anyhow::Error::msg)?;
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.cipher_suites =
        vec![rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256];
    let mut tls_config = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)?;
    tls_config.alpn_protocols = vec![ALPN_H3.to_vec()];

    let mut transport_config = quinn::TransportConfig::default();
    transport_config.max_concurrent_bidi_streams(SERVER_MAX_BIDI_STREAMS.into());
    let mut server_config =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls_config)?));
    server_config.transport_config(Arc::new(transport_config));

    let endpoint = quinn::Endpoint::server(server_config, SERVER_ADDR.parse()?)?;
    println!(
        "http3-bench-server-v6 library={library} address={SERVER_ADDR} body_bytes={body_bytes} \
         headers={headers} \
         max_concurrent_bidi_streams={SERVER_MAX_BIDI_STREAMS} transport=quinn \
         runtime=pingora-no-steal workers={SERVER_WORKERS}"
    );
    std::io::stdout().flush()?;

    let mut connections = JoinSet::new();
    let mut next_worker = 0;
    loop {
        tokio::select! {
            _ = &mut shutdown => {
                shutdown_connections(&endpoint, &mut connections).await?;
                return Ok(());
            }
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else {
                    drain_tasks(&mut connections, "benchmark server connection").await?;
                    return Ok(());
                };
                let body = body.clone();
                // Select a worker before incoming.await creates Quinn's ConnectionDriver.
                // Only distribute connections: ordinary Tokio spawns inside serve_connection
                // keep all of its streams on that same current-thread runtime.
                connections.spawn_on(
                    serve_connection(library, incoming, body, headers),
                    &workers[next_worker],
                );
                next_worker = (next_worker + 1) % workers.len();
            }
            completed = connections.join_next(), if !connections.is_empty() => {
                completed
                    .context("benchmark server connection task disappeared")?
                    .context("benchmark server connection task failed")??;
            }
        }
    }
}

async fn shutdown_connections(
    endpoint: &quinn::Endpoint,
    connections: &mut JoinSet<Result<()>>,
) -> Result<()> {
    while let Some(completed) = connections.try_join_next() {
        completed
            .context("benchmark server connection task failed")?
            .context("benchmark server connection failed")?;
    }

    // The controller closes stdin only after a successful Client process. Request validation and
    // response delivery have therefore completed; cancel remaining connection drivers before
    // closing the Endpoint so its local shutdown is not misreported as a Client protocol error.
    connections.abort_all();
    while let Some(completed) = connections.join_next().await {
        match completed {
            Ok(result) => result.context("benchmark server connection failed")?,
            Err(error) if error.is_cancelled() => {}
            Err(error) => return Err(error).context("benchmark server connection task failed"),
        }
    }

    endpoint.close(0u32.into(), b"benchmark complete");
    endpoint.wait_idle().await;
    Ok(())
}

async fn serve_connection(
    library: Http3Library,
    incoming: quinn::Incoming,
    body: Bytes,
    headers: HeaderMode,
) -> Result<()> {
    let connection = incoming.await?;
    match library {
        Http3Library::Http3 => serve_http3_connection(connection, body, headers).await,
        Http3Library::H3 => serve_h3_connection(connection, body, headers).await,
        Http3Library::Nghttp3 => bail!("unsupported server HTTP/3 library {library}"),
    }
}

async fn drain_tasks(tasks: &mut JoinSet<Result<()>>, name: &str) -> Result<()> {
    while let Some(completed) = tasks.join_next().await {
        completed.with_context(|| format!("{name} task failed"))??;
    }
    Ok(())
}

fn validate_request(request: &http::Request<()>, headers: HeaderMode) -> Result<()> {
    if request.version() != http::Version::HTTP_3 {
        bail!("benchmark request used {:?}", request.version());
    }
    if request.method() != http::Method::GET {
        bail!("benchmark request used {}", request.method());
    }
    if request.uri().scheme_str() != Some("https")
        || request.uri().authority().map(http::uri::Authority::as_str) != Some("localhost:4433")
        || request
            .uri()
            .path_and_query()
            .map(http::uri::PathAndQuery::as_str)
            != Some("/")
    {
        bail!("benchmark request used unexpected URI {}", request.uri());
    }
    validate_headers(request.headers(), &REQUEST_HEADERS, headers.request)
        .context("invalid benchmark request headers")
}

// Instantiate the same request lifecycle for both libraries so Server choice
// cannot silently change validation, task scheduling, or response completion.
macro_rules! server_adapter {
    ($serve:ident, $respond:ident, $http3_crate:ident, $transport:ident) => {
        async fn $serve(
            connection: quinn::Connection,
            body: Bytes,
            headers: HeaderMode,
        ) -> Result<()> {
            let mut builder = $http3_crate::server::builder();
            builder.send_grease(false);
            let mut connection = builder
                .build($transport::Connection::new(connection))
                .await?;

            let mut requests = JoinSet::new();
            loop {
                tokio::select! {
                    accepted = connection.accept() => match accepted {
                        Ok(Some(resolver)) => {
                            requests.spawn($respond(resolver, body.clone(), headers));
                        }
                        Ok(None) => {
                            drain_tasks(&mut requests, "benchmark server request").await?;
                            return Ok(());
                        }
                        Err(error) if error.is_h3_no_error() => {
                            drain_tasks(&mut requests, "benchmark server request").await?;
                            return Ok(());
                        }
                        Err(error) => return Err(error.into()),
                    },
                    completed = requests.join_next(), if !requests.is_empty() => {
                        completed
                            .context("benchmark server request task disappeared")?
                            .context("benchmark server request task failed")??;
                    }
                }
            }
        }

        async fn $respond(
            resolver: $http3_crate::server::RequestResolver<$transport::Connection, Bytes>,
            body: Bytes,
            headers: HeaderMode,
        ) -> Result<()> {
            let (request, mut stream) = resolver.resolve_request().await?;
            validate_request(&request, headers)?;
            // Validate the request half before reporting a successful response so a missing FIN
            // cannot be hidden by a Client that exits after receiving the response body.
            if stream.recv_data().await?.is_some() {
                bail!("benchmark request unexpectedly contained a body");
            }
            if stream.recv_trailers().await?.is_some() {
                bail!("benchmark request unexpectedly contained trailers");
            }

            let mut response = http::Response::builder()
                .status(StatusCode::OK)
                .header(http::header::CONTENT_LENGTH, body.len());
            // Both Server libraries send the same fixed response fixture. The
            // directional controls separate request encoding from response decoding.
            if headers.response {
                for (name, value) in &RESPONSE_HEADERS {
                    response = response.header(name.clone(), value.clone());
                }
            }
            let response = response.body(())?;
            stream.send_response(response).await?;
            if !body.is_empty() {
                stream.send_data(body).await?;
            }
            stream.finish().await?;
            Ok(())
        }
    };
}

server_adapter!(serve_http3_connection, respond_http3, http3, http3_quic);
server_adapter!(serve_h3_connection, respond_h3, h3, h3_quinn);
