//! nghttp3 FFI bindings.
//!
//! This crate provides low-level FFI bindings to the nghttp3 C library.

#![allow(
    non_snake_case,
    non_upper_case_globals,
    non_camel_case_types,
    dead_code,
    clippy::all
)]

include!("bindings.rs");

// Implement Send/Sync for nghttp3_vec.
// SAFETY: nghttp3_vec is used only during writev_stream calls, and pointer
// lifetimes end within that call. Async callers copy the data and then discard
// the pointer, so moving the value between threads is safe.
unsafe impl Send for nghttp3_vec {}
unsafe impl Sync for nghttp3_vec {}
