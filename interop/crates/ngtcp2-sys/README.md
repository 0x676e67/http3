# ngtcp2-sys

[![crates.io](https://img.shields.io/crates/v/ngtcp2-sys.svg)](https://crates.io/crates/ngtcp2-sys)
[![docs.rs](https://docs.rs/ngtcp2-sys/badge.svg)](https://docs.rs/ngtcp2-sys)

Rust FFI bindings to [ngtcp2](https://github.com/ngtcp2/ngtcp2).

This crate builds the bundled ngtcp2 source with CMake and generates bindings
for the current Cargo target. It uses aws-lc as its TLS backend.

## Release support

The current supported releases are `ngtcp2-sys` 0.2 and ngtcp2 1.25.

This crate is maintained in the
[http3](https://github.com/0x676e67/http3) repository. New versions are
released from time to time.

## Build requirements

- CMake
- A C compiler such as GCC, Clang, or MSVC
- libclang
- Go, required to build aws-lc
