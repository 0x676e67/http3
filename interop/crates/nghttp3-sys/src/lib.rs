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

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

// Implement Send for nghttp3_vec.
// SAFETY: nghttp3_vec is only moved as an owned value while driving one
// connection. Shared cross-thread access would require stronger guarantees from
// the pointed-to storage, so this crate intentionally does not implement Sync.
unsafe impl Send for nghttp3_vec {}
