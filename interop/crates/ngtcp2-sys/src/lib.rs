//! ngtcp2 FFI bindings.
//!
//! This crate provides low-level FFI bindings to the ngtcp2 C library.

#![allow(
    non_snake_case,
    non_upper_case_globals,
    non_camel_case_types,
    dead_code,
    clippy::all
)]

include!("bindings.rs");
