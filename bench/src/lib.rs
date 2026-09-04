//! Internal API shared by the benchmark controller and isolated role executables.

use std::ffi::{CString, OsString, c_char, c_int};

pub mod case;
#[doc(hidden)]
pub mod client;
pub mod result;
mod server;

/// Runs an isolated Rust Client selected by its compile-time adapter.
#[doc(hidden)]
pub fn run_client<A: client::Adapter>(args: impl Iterator<Item = String>) -> anyhow::Result<()> {
    client::run_from_args::<A>(args)
}

/// Runs the isolated HTTP/3 Server shared by all compared Clients.
pub fn run_server(args: impl Iterator<Item = String>) -> anyhow::Result<()> {
    server::run_from_args(args)
}

unsafe extern "C" {
    fn http3_bench_nghttp3_main(argc: c_int, argv: *mut *mut c_char) -> c_int;
}

/// Runs the native nghttp3/ngtcp2 Client compiled by this package's build script.
#[doc(hidden)]
pub fn run_nghttp3_client(args: impl Iterator<Item = OsString>) -> anyhow::Result<c_int> {
    let mut encoded = vec![CString::new("http3-bench-nghttp3-client")?];
    for argument in args {
        encoded.push(CString::new(argument.to_string_lossy().as_bytes())?);
    }
    let argc = c_int::try_from(encoded.len()).map_err(|_| anyhow::anyhow!("too many arguments"))?;
    let mut argv = encoded
        .iter_mut()
        .map(|argument| argument.as_ptr().cast_mut())
        .collect::<Vec<_>>();
    argv.push(std::ptr::null_mut());

    // Referencing the sys crates makes Cargo propagate their complete native
    // link contracts to this executable. The C entry point repeats the version
    // checks before initializing either library.
    unsafe {
        let _ = aws_lc_sys::OpenSSL_version(0);
        let _ = nghttp3_sys::nghttp3_version(0);
        let _ = ngtcp2_sys::ngtcp2_version(0);
    }

    // The C entry point reads argv synchronously and does not retain or mutate
    // any pointer, so every CString remains alive for the complete call.
    Ok(unsafe { http3_bench_nghttp3_main(argc, argv.as_mut_ptr()) })
}
