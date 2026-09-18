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

#[cfg(feature = "unstable")]
#[allow(missing_docs)]
pub mod connection;
#[cfg(feature = "unstable")]
#[allow(missing_docs)]
pub mod frame;
#[cfg(feature = "unstable")]
#[allow(missing_docs)]
pub mod proto;
#[cfg(feature = "unstable")]
#[allow(dead_code, missing_docs)]
pub mod qpack;
#[cfg(feature = "unstable")]
#[allow(missing_docs)]
pub mod stream;
#[cfg(feature = "unstable")]
#[allow(missing_docs)]
pub mod webtransport;

#[cfg(not(feature = "unstable"))]
mod connection;
#[cfg(not(feature = "unstable"))]
mod frame;
#[cfg(not(feature = "unstable"))]
mod proto;
#[cfg(not(feature = "unstable"))]
#[allow(dead_code)]
mod qpack;
#[cfg(not(feature = "unstable"))]
mod stream;
#[cfg(not(feature = "unstable"))]
mod webtransport;

pub use proto::{
    frame::SettingId,
    headers::{PseudoHeaderSensitivity, PseudoId, PseudoOrder, PseudoOrderBuilder},
};

#[cfg(test)]
mod tests;
#[cfg(test)]
extern crate self as http3;
