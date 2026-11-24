//! HTTP/3 client and server
#![deny(missing_docs, clippy::self_named_module_files)]
#![allow(clippy::derive_partial_eq_without_eq)]

pub mod client;

mod config;
//pub mod error;
pub mod ext;
pub mod quic;

pub mod server;

//pub use error::Error;

mod buf;

mod shared_state;

#[cfg(feature = "unstable")]
pub use shared_state::{ConnectionState, SharedState};

pub mod error;

cfg_select! {
    feature = "unstable" => {
        #[allow(missing_docs)]
        pub mod connection;
        #[allow(missing_docs)]
        pub mod frame;
        #[allow(missing_docs)]
        pub mod proto;
        #[allow(dead_code, missing_docs)]
        pub mod qpack;
        #[allow(missing_docs)]
        pub mod stream;
        #[allow(missing_docs)]
        pub mod webtransport;
    }
    _ => {
        mod connection;
        mod frame;
        mod proto;
        #[allow(dead_code)]
        mod qpack;
        mod stream;
        mod webtransport;
    }
}

#[cfg(feature = "unstable")]
pub use proto::frame::{ExperimentalSettings, ExperimentalSettingsBuilder};
pub use proto::{
    frame::{SettingId, SettingsOrder, SettingsOrderBuilder},
    headers::{PseudoHeaderSensitivity, PseudoId, PseudoOrder, PseudoOrderBuilder},
};

#[cfg(test)]
mod tests;
#[cfg(test)]
extern crate self as http3;
