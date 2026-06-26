mod support;

use interop::{BoxError, ClientInteropConfig};

macro_rules! local_interop_test {
    ($name:ident, $backend:ident, $server_config:expr, $client_config:expr) => {
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn $name() -> Result<(), BoxError> {
            support::$backend::run_client_interop($server_config, $client_config).await
        }
    };
}

// The ngtcp2/nghttp3 wrapper stays on safe HTTP/3 APIs here. It currently does
// not expose a server-side hook for reserved SETTINGS, frames, or stream types,
// so this backend only covers client-side GREASE behavior.
// https://www.rfc-editor.org/rfc/rfc9114.html#section-9
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ngtcp2_qpack_client_off_server_off() -> Result<(), BoxError> {
    support::ngtcp2::run_client_interop(
        support::ngtcp2::ServerConfig::stateless_qpack(),
        ClientInteropConfig::stateless_qpack(),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ngtcp2_qpack_client_off_server_off_client_grease_on() -> Result<(), BoxError> {
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
async fn ngtcp2_qpack_client_on_server_off_client_grease_on() -> Result<(), BoxError> {
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
async fn ngtcp2_qpack_client_off_server_on_client_grease_on() -> Result<(), BoxError> {
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
async fn ngtcp2_qpack_client_on_server_on_client_grease_on() -> Result<(), BoxError> {
    support::ngtcp2::run_client_interop(
        support::ngtcp2::ServerConfig::dynamic_qpack(),
        ClientInteropConfig::qpack_dynamic_table().with_grease(),
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
async fn quiche_qpack_client_off_server_off_client_grease_on() -> Result<(), BoxError> {
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
async fn quiche_qpack_client_on_server_off_client_grease_on() -> Result<(), BoxError> {
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
async fn quiche_qpack_client_off_server_on_client_grease_on() -> Result<(), BoxError> {
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
async fn quiche_qpack_client_on_server_on_client_grease_on() -> Result<(), BoxError> {
    support::quiche::run_client_interop(
        support::quiche::ServerConfig::dynamic_qpack(),
        ClientInteropConfig::qpack_dynamic_table().with_grease(),
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

local_interop_test!(
    quiche_qpack_client_off_server_off_server_grease_on,
    quiche,
    support::quiche::ServerConfig::stateless_qpack().with_grease(),
    ClientInteropConfig::stateless_qpack()
);

local_interop_test!(
    quiche_qpack_client_off_server_off_client_and_server_grease_on,
    quiche,
    support::quiche::ServerConfig::stateless_qpack().with_grease(),
    ClientInteropConfig::stateless_qpack().with_grease()
);

local_interop_test!(
    quiche_qpack_client_on_server_off_server_grease_on,
    quiche,
    support::quiche::ServerConfig::stateless_qpack().with_grease(),
    ClientInteropConfig::qpack_dynamic_table()
);

local_interop_test!(
    quiche_qpack_client_on_server_off_client_and_server_grease_on,
    quiche,
    support::quiche::ServerConfig::stateless_qpack().with_grease(),
    ClientInteropConfig::qpack_dynamic_table().with_grease()
);

local_interop_test!(
    quiche_qpack_client_off_server_on_server_grease_on,
    quiche,
    support::quiche::ServerConfig::dynamic_qpack().with_grease(),
    ClientInteropConfig::stateless_qpack()
);

local_interop_test!(
    quiche_qpack_client_off_server_on_client_and_server_grease_on,
    quiche,
    support::quiche::ServerConfig::dynamic_qpack().with_grease(),
    ClientInteropConfig::stateless_qpack().with_grease()
);

local_interop_test!(
    quiche_qpack_client_on_server_on_server_grease_on,
    quiche,
    support::quiche::ServerConfig::dynamic_qpack().with_grease(),
    ClientInteropConfig::qpack_dynamic_table()
);

local_interop_test!(
    quiche_qpack_client_on_server_on_client_and_server_grease_on,
    quiche,
    support::quiche::ServerConfig::dynamic_qpack().with_grease(),
    ClientInteropConfig::qpack_dynamic_table().with_grease()
);

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
async fn tquic_qpack_client_off_server_off_client_grease_on() -> Result<(), BoxError> {
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
async fn tquic_qpack_client_on_server_off_client_grease_on() -> Result<(), BoxError> {
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
async fn tquic_qpack_client_off_server_on_client_grease_on() -> Result<(), BoxError> {
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
async fn tquic_qpack_client_on_server_on_client_grease_on() -> Result<(), BoxError> {
    support::tquic::run_client_interop(
        support::tquic::ServerConfig::dynamic_qpack(),
        ClientInteropConfig::qpack_dynamic_table().with_grease(),
    )
    .await
}

local_interop_test!(
    tquic_qpack_client_off_server_off_server_grease_on,
    tquic,
    support::tquic::ServerConfig::stateless_qpack().with_grease(),
    ClientInteropConfig::stateless_qpack()
);

local_interop_test!(
    tquic_qpack_client_off_server_off_client_and_server_grease_on,
    tquic,
    support::tquic::ServerConfig::stateless_qpack().with_grease(),
    ClientInteropConfig::stateless_qpack().with_grease()
);

local_interop_test!(
    tquic_qpack_client_on_server_off_server_grease_on,
    tquic,
    support::tquic::ServerConfig::stateless_qpack().with_grease(),
    ClientInteropConfig::qpack_dynamic_table()
);

local_interop_test!(
    tquic_qpack_client_on_server_off_client_and_server_grease_on,
    tquic,
    support::tquic::ServerConfig::stateless_qpack().with_grease(),
    ClientInteropConfig::qpack_dynamic_table().with_grease()
);

local_interop_test!(
    tquic_qpack_client_off_server_on_server_grease_on,
    tquic,
    support::tquic::ServerConfig::dynamic_qpack().with_grease(),
    ClientInteropConfig::stateless_qpack()
);

local_interop_test!(
    tquic_qpack_client_off_server_on_client_and_server_grease_on,
    tquic,
    support::tquic::ServerConfig::dynamic_qpack().with_grease(),
    ClientInteropConfig::stateless_qpack().with_grease()
);

local_interop_test!(
    tquic_qpack_client_on_server_on_server_grease_on,
    tquic,
    support::tquic::ServerConfig::dynamic_qpack().with_grease(),
    ClientInteropConfig::qpack_dynamic_table()
);

local_interop_test!(
    tquic_qpack_client_on_server_on_client_and_server_grease_on,
    tquic,
    support::tquic::ServerConfig::dynamic_qpack().with_grease(),
    ClientInteropConfig::qpack_dynamic_table().with_grease()
);

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
