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
async fn ngtcp2_qpack_client_off_server_off_grease_on() -> Result<(), BoxError> {
    support::ngtcp2::run_client_interop(
        support::ngtcp2::ServerConfig::stateless_qpack(),
        ClientInteropConfig::stateless_qpack().with_grease(),
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
async fn ngtcp2_qpack_client_on_server_off_grease_on() -> Result<(), BoxError> {
    support::ngtcp2::run_client_interop(
        support::ngtcp2::ServerConfig::stateless_qpack(),
        ClientInteropConfig::qpack_dynamic_table().with_grease(),
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
async fn ngtcp2_qpack_client_off_server_on_grease_on() -> Result<(), BoxError> {
    support::ngtcp2::run_client_interop(
        support::ngtcp2::ServerConfig::dynamic_qpack(),
        ClientInteropConfig::stateless_qpack().with_grease(),
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
async fn ngtcp2_qpack_client_on_server_on_grease_on() -> Result<(), BoxError> {
    support::ngtcp2::run_client_interop(
        support::ngtcp2::ServerConfig::dynamic_qpack(),
        ClientInteropConfig::qpack_dynamic_table().with_grease(),
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
async fn quiche_qpack_client_off_server_off_grease_on() -> Result<(), BoxError> {
    support::quiche::run_client_interop(
        support::quiche::ServerConfig::stateless_qpack(),
        ClientInteropConfig::stateless_qpack().with_grease(),
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
async fn quiche_qpack_client_on_server_off_grease_on() -> Result<(), BoxError> {
    support::quiche::run_client_interop(
        support::quiche::ServerConfig::stateless_qpack(),
        ClientInteropConfig::qpack_dynamic_table().with_grease(),
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
async fn quiche_qpack_client_off_server_on_grease_on() -> Result<(), BoxError> {
    support::quiche::run_client_interop(
        support::quiche::ServerConfig::dynamic_qpack(),
        ClientInteropConfig::stateless_qpack().with_grease(),
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
async fn quiche_qpack_client_on_server_on_grease_on() -> Result<(), BoxError> {
    support::quiche::run_client_interop(
        support::quiche::ServerConfig::dynamic_qpack(),
        ClientInteropConfig::qpack_dynamic_table().with_grease(),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tquic_qpack_client_off_server_off() -> Result<(), BoxError> {
    support::tquic::run_client_interop(
        support::tquic::ServerConfig::stateless_qpack(),
        ClientInteropConfig::stateless_qpack(),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tquic_qpack_client_off_server_off_grease_on() -> Result<(), BoxError> {
    support::tquic::run_client_interop(
        support::tquic::ServerConfig::stateless_qpack(),
        ClientInteropConfig::stateless_qpack().with_grease(),
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
async fn tquic_qpack_client_on_server_off_grease_on() -> Result<(), BoxError> {
    support::tquic::run_client_interop(
        support::tquic::ServerConfig::stateless_qpack(),
        ClientInteropConfig::qpack_dynamic_table().with_grease(),
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
async fn tquic_qpack_client_off_server_on_grease_on() -> Result<(), BoxError> {
    support::tquic::run_client_interop(
        support::tquic::ServerConfig::dynamic_qpack(),
        ClientInteropConfig::stateless_qpack().with_grease(),
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tquic_qpack_client_on_server_on_grease_on() -> Result<(), BoxError> {
    support::tquic::run_client_interop(
        support::tquic::ServerConfig::dynamic_qpack(),
        ClientInteropConfig::qpack_dynamic_table().with_grease(),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real HTTP/3 interop tests need public network access"]
async fn public_servers_qpack_stateless_grease_off() -> Result<(), BoxError> {
    support::public::run_client_interop(
        "qpack-stateless",
        ClientInteropConfig::stateless_qpack(),
        support::public::GreaseMode::OFF,
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real HTTP/3 interop tests need public network access"]
async fn public_servers_qpack_stateless_grease_on() -> Result<(), BoxError> {
    support::public::run_client_interop(
        "qpack-stateless",
        ClientInteropConfig::stateless_qpack(),
        support::public::GreaseMode::ON,
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real HTTP/3 interop tests need public network access"]
async fn public_servers_qpack_dynamic_grease_off() -> Result<(), BoxError> {
    support::public::run_client_interop(
        "qpack-dynamic",
        ClientInteropConfig::qpack_dynamic_table(),
        support::public::GreaseMode::OFF,
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real HTTP/3 interop tests need public network access"]
async fn public_servers_qpack_dynamic_grease_on() -> Result<(), BoxError> {
    support::public::run_client_interop(
        "qpack-dynamic",
        ClientInteropConfig::qpack_dynamic_table(),
        support::public::GreaseMode::ON,
    )
    .await
}
