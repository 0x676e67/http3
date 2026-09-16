//! Internal API shared by the benchmark controller and its isolated process roles.

use std::{
    ffi::{CString, OsString, c_char, c_int},
    sync::Mutex,
};

pub mod case;
#[doc(hidden)]
pub mod client;
pub mod headers;
pub mod result;

/// Runs an isolated Rust Client selected by its compile-time adapter.
#[doc(hidden)]
pub fn run_client<A: client::Adapter>(args: impl Iterator<Item = String>) -> anyhow::Result<()> {
    client::run_from_args::<A>(args)
}

/// Runs the isolated native nghttp3/ngtcp2 Server.
pub fn run_server(args: impl Iterator<Item = OsString>) -> anyhow::Result<c_int> {
    run_native(args, true)
}

unsafe extern "C" {
    fn http3_bench_nghttp3_main(argc: c_int, argv: *mut *mut c_char) -> c_int;
    fn http3_bench_nghttp3_server_main(argc: c_int, argv: *mut *mut c_char) -> c_int;
}

static NATIVE_LOCK: Mutex<()> = Mutex::new(());

/// Runs the native nghttp3/ngtcp2 Client compiled by this package's build script.
#[doc(hidden)]
pub fn run_nghttp3_client(args: impl Iterator<Item = OsString>) -> anyhow::Result<c_int> {
    run_native(args, false)
}

fn run_native(args: impl Iterator<Item = OsString>, server: bool) -> anyhow::Result<c_int> {
    // The C adapter owns process-wide socket and timer state. Serialize the
    // complete call so this safe wrapper cannot expose that state concurrently.
    let _guard = NATIVE_LOCK
        .lock()
        .map_err(|_| anyhow::anyhow!("native benchmark lock was poisoned"))?;
    let mut encoded = vec![CString::new("nghttp3")?];
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
    // SAFETY: these version queries require no input pointers and return
    // library-owned static data. The entry points check the exact versions.
    unsafe {
        let _ = aws_lc_sys::OpenSSL_version(0);
        let _ = nghttp3_sys::nghttp3_version(0);
        let _ = ngtcp2_sys::ngtcp2_version(0);
    }

    // SAFETY: both entry points read argv synchronously without retaining or
    // mutating pointers. The CStrings and null-terminated argv outlive the call,
    // and NATIVE_LOCK prevents concurrent access to the C process-wide state.
    Ok(unsafe {
        if server {
            http3_bench_nghttp3_server_main(argc, argv.as_mut_ptr())
        } else {
            http3_bench_nghttp3_main(argc, argv.as_mut_ptr())
        }
    })
}
