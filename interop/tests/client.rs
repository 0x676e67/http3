mod support;

use interop::{BoxError, ClientInteropConfig};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ngtcp2_qpack_client_off_server_off() -> Result<(), BoxError> {
    support::ngtcp2::run_client_interop(
        support::ngtcp2::ServerConfig::stateless_qpack(),
        ClientInteropConfig::stateless_qpack(),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ngtcp2_qpack_client_on_server_off() -> Result<(), BoxError> {
    support::ngtcp2::run_client_interop(
        support::ngtcp2::ServerConfig::stateless_qpack(),
        ClientInteropConfig::qpack_dynamic_table(),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ngtcp2_qpack_client_off_server_on() -> Result<(), BoxError> {
    support::ngtcp2::run_client_interop(
        support::ngtcp2::ServerConfig::dynamic_qpack(),
        ClientInteropConfig::stateless_qpack(),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ngtcp2_qpack_client_on_server_on() -> Result<(), BoxError> {
    support::ngtcp2::run_client_interop(
        support::ngtcp2::ServerConfig::dynamic_qpack(),
        ClientInteropConfig::qpack_dynamic_table(),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ngtcp2_max_field_section_size_limit() -> Result<(), BoxError> {
    support::ngtcp2::run_max_field_section_size_limit(
        support::ngtcp2::ServerConfig::stateless_qpack(),
        ClientInteropConfig::stateless_qpack(),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn quiche_qpack_client_off_server_off() -> Result<(), BoxError> {
    support::quiche::run_client_interop(
        support::quiche::ServerConfig::stateless_qpack(),
        ClientInteropConfig::stateless_qpack(),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn quiche_qpack_client_on_server_off() -> Result<(), BoxError> {
    support::quiche::run_client_interop(
        support::quiche::ServerConfig::stateless_qpack(),
        ClientInteropConfig::qpack_dynamic_table(),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn quiche_qpack_client_off_server_on() -> Result<(), BoxError> {
    support::quiche::run_client_interop(
        support::quiche::ServerConfig::dynamic_qpack(),
        ClientInteropConfig::stateless_qpack(),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn quiche_qpack_client_on_server_on() -> Result<(), BoxError> {
    support::quiche::run_client_interop(
        support::quiche::ServerConfig::dynamic_qpack(),
        ClientInteropConfig::qpack_dynamic_table(),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn quiche_max_field_section_size_limit() -> Result<(), BoxError> {
    support::quiche::run_max_field_section_size_limit(
        support::quiche::ServerConfig::stateless_qpack(),
        ClientInteropConfig::stateless_qpack(),
    )
    .await
}

// tquic is not used for the max_field_section_size negative test. Its server
// API refuses to send a field section larger than the client's advertised
// limit and returns `ExcessiveLoad` from `send_headers`, so it cannot exercise
// the client's "received oversized response headers" path.
// https://www.rfc-editor.org/rfc/rfc9114.html#section-4.2.2
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tquic_qpack_client_off_server_off() -> Result<(), BoxError> {
    support::tquic::run_client_interop(
        support::tquic::ServerConfig::stateless_qpack(),
        ClientInteropConfig::stateless_qpack(),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tquic_qpack_client_on_server_off() -> Result<(), BoxError> {
    support::tquic::run_client_interop(
        support::tquic::ServerConfig::stateless_qpack(),
        ClientInteropConfig::qpack_dynamic_table(),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tquic_qpack_client_off_server_on() -> Result<(), BoxError> {
    support::tquic::run_client_interop(
        support::tquic::ServerConfig::dynamic_qpack(),
        ClientInteropConfig::stateless_qpack(),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tquic_qpack_client_on_server_on() -> Result<(), BoxError> {
    support::tquic::run_client_interop(
        support::tquic::ServerConfig::dynamic_qpack(),
        ClientInteropConfig::qpack_dynamic_table(),
    )
    .await
}
