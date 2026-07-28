//! Error handling logic and types for the `http3` crate.

mod codes;

#[cfg(feature = "unstable")]
pub mod connection_error_creators;
#[cfg(not(feature = "unstable"))]
pub(crate) mod connection_error_creators;

#[cfg(feature = "unstable")]
pub mod internal_error;
#[cfg(not(feature = "unstable"))]
pub(crate) mod internal_error;

// Todo better module names
#[allow(clippy::module_inception)]
mod error;

pub use codes::Code;
pub use error::{ConnectionError, LocalError, StreamError};
