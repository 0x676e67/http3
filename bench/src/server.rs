//! Isolated http3 and h3 Servers sharing transport, validation, and response handling.

use std::{
    io::{Read, Write},
    sync::Arc,
    thread,
};

use anyhow::{Context, Result, bail};
use bytes::Bytes;
use http::StatusCode;
use quinn::crypto::rustls::QuicServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::task::JoinSet;

use super::case::{
    ALPN_H3, EXTRA_HEADER_NAME, EXTRA_HEADER_VALUE, Http3Library, MAX_EXTRA_HEADERS, SERVER_ADDR,
    SERVER_MAX_BIDI_STREAMS, SERVER_WORKERS, workspace_root,
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
    let extra_headers = args
        .next()
        .context("missing extra request header count")?
        .parse::<usize>()
        .context("invalid extra request header count")?;
    if extra_headers > MAX_EXTRA_HEADERS {
        bail!("extra request headers cannot exceed {MAX_EXTRA_HEADERS}");
    }
    if let Some(extra) = args.next() {
        bail!("unexpected internal server argument {extra:?}");
    }

    let mut runtime = tokio::runtime::Builder::new_multi_thread();
    runtime.worker_threads(SERVER_WORKERS).enable_all();
    let runtime = runtime
        .build()
        .context("could not create benchmark server runtime")?;

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    thread::spawn(move || {
        let mut byte = [0u8; 1];
        let _ = std::io::stdin().read(&mut byte);
        let _ = shutdown_tx.send(());
    });
    runtime.block_on(run_server(library, body_bytes, extra_headers, shutdown_rx))
}

async fn run_server(
    library: Http3Library,
    body_bytes: usize,
    extra_headers: usize,
    mut shutdown: tokio::sync::oneshot::Receiver<()>,
) -> Result<()> {
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
        "http3-bench-server-v4 library={library} address={SERVER_ADDR} body_bytes={body_bytes} \
         extra_request_headers={extra_headers} \
         max_concurrent_bidi_streams={SERVER_MAX_BIDI_STREAMS} transport=quinn \
         workers={SERVER_WORKERS}"
    );
    std::io::stdout().flush()?;

    let mut connections = JoinSet::new();
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
                connections.spawn(serve_connection(library, incoming, body, extra_headers));
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
    extra_headers: usize,
) -> Result<()> {
    let connection = incoming.await?;
    match library {
        Http3Library::Http3 => serve_http3_connection(connection, body, extra_headers).await,
        Http3Library::H3 => serve_h3_connection(connection, body, extra_headers).await,
        Http3Library::Nghttp3 => bail!("unsupported server HTTP/3 library {library}"),
    }
}

async fn drain_tasks(tasks: &mut JoinSet<Result<()>>, name: &str) -> Result<()> {
    while let Some(completed) = tasks.join_next().await {
        completed.with_context(|| format!("{name} task failed"))??;
    }
    Ok(())
}

fn validate_request(request: &http::Request<()>, extra_headers: usize) -> Result<()> {
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
    let benchmark_headers = request.headers().get_all(&EXTRA_HEADER_NAME);
    let actual_extra_headers = benchmark_headers.iter().count();
    if actual_extra_headers != extra_headers {
        bail!(
            "benchmark request contained {actual_extra_headers} extra headers, expected \
             {extra_headers}"
        );
    }
    if benchmark_headers
        .iter()
        .any(|value| value != EXTRA_HEADER_VALUE)
    {
        bail!("benchmark request contained an unexpected extra header value");
    }
    Ok(())
}

// Instantiate the same request lifecycle for both libraries so Server choice
// cannot silently change validation, task scheduling, or response completion.
macro_rules! server_adapter {
    ($serve:ident, $respond:ident, $http3_crate:ident, $transport:ident) => {
        async fn $serve(
            connection: quinn::Connection,
            body: Bytes,
            extra_headers: usize,
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
                            requests.spawn($respond(resolver, body.clone(), extra_headers));
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
            extra_headers: usize,
        ) -> Result<()> {
            let (request, mut stream) = resolver.resolve_request().await?;
            validate_request(&request, extra_headers)?;
            // Validate the request half before reporting a successful response so a missing FIN
            // cannot be hidden by a Client that exits after receiving the response body.
            if stream.recv_data().await?.is_some() {
                bail!("benchmark request unexpectedly contained a body");
            }
            if stream.recv_trailers().await?.is_some() {
                bail!("benchmark request unexpectedly contained trailers");
            }

            let response = http::Response::builder()
                .status(StatusCode::OK)
                .header(http::header::CONTENT_LENGTH, body.len())
                .body(())?;
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
