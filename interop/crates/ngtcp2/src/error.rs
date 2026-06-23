use std::ffi::CStr;
use std::fmt;

/// Error type for ngtcp2/nghttp3 operations.
#[derive(Debug)]
pub enum Error {
    /// An ngtcp2 error.
    Ngtcp2(String, i32),

    /// An nghttp3 error.
    Nghttp3(String, i32),

    /// Invalid argument.
    InvalidArgument(String),

    /// The provided buffer is too small.
    BufferTooSmall,

    /// The stream was not found.
    StreamNotFound(i64),

    /// The connection is closing.
    ConnectionClosing,

    /// The stream is blocked by flow control.
    StreamDataBlocked(i64),

    /// The stream's write side is shut down.
    StreamShutWr(i64),

    /// Internal error.
    Internal(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Ngtcp2(msg, code) => write!(f, "ngtcp2 error: {} ({})", msg, code),
            Error::Nghttp3(msg, code) => write!(f, "nghttp3 error: {} ({})", msg, code),
            Error::InvalidArgument(msg) => write!(f, "invalid argument: {}", msg),
            Error::BufferTooSmall => write!(f, "buffer too small"),
            Error::StreamNotFound(id) => write!(f, "stream not found: {}", id),
            Error::ConnectionClosing => write!(f, "connection is closing"),
            Error::StreamDataBlocked(id) => write!(f, "stream data blocked: {}", id),
            Error::StreamShutWr(id) => write!(f, "stream shut wr: {}", id),
            Error::Internal(msg) => write!(f, "internal error: {}", msg),
        }
    }
}

impl std::error::Error for Error {}

/// Result alias used by this crate.
pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    /// Builds an error from an ngtcp2 error code.
    pub fn from_ngtcp2(code: libc::c_int) -> Self {
        let msg = unsafe {
            let ptr = ngtcp2_sys::ngtcp2_strerror(code);
            if ptr.is_null() {
                "unknown error".to_string()
            } else {
                CStr::from_ptr(ptr).to_string_lossy().into_owned()
            }
        };
        Error::Ngtcp2(msg, code)
    }

    /// Builds an error from an nghttp3 error code.
    pub fn from_nghttp3(code: libc::c_int) -> Self {
        let msg = unsafe {
            let ptr = nghttp3_sys::nghttp3_strerror(code);
            if ptr.is_null() {
                "unknown error".to_string()
            } else {
                CStr::from_ptr(ptr).to_string_lossy().into_owned()
            }
        };
        Error::Nghttp3(msg, code)
    }
}

/// Checks an ngtcp2 return code.
pub fn check_ngtcp2(code: libc::c_int) -> Result<()> {
    if code < 0 {
        Err(Error::from_ngtcp2(code))
    } else {
        Ok(())
    }
}

/// Checks an nghttp3 return code.
pub fn check_nghttp3(code: libc::c_int) -> Result<()> {
    if code < 0 {
        Err(Error::from_nghttp3(code))
    } else {
        Ok(())
    }
}
