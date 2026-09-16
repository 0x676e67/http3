# nghttp3-sys

[![crates.io](https://img.shields.io/crates/v/nghttp3-sys.svg)](https://crates.io/crates/nghttp3-sys)
[![docs.rs](https://docs.rs/nghttp3-sys/badge.svg)](https://docs.rs/nghttp3-sys)

Rust FFI bindings to [nghttp3](https://github.com/ngtcp2/nghttp3).

This crate builds the bundled nghttp3 source with CMake and generates bindings
for the current Cargo target.

## Release support

The current supported releases are `nghttp3-sys` 0.2 and nghttp3 1.18.

This crate is maintained in the
[http3](https://github.com/0x676e67/http3) repository. New versions are
released from time to time.

## Build requirements

- CMake
- A C compiler such as GCC, Clang, or MSVC
- libclang
