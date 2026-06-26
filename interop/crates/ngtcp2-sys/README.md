# ngtcp2-sys

Rust FFI bindings for [ngtcp2](https://github.com/ngtcp2/ngtcp2).

## Scope

This crate is maintained only for the
[0x676e67/http3-rs](https://github.com/0x676e67/http3-rs) interoperability
test suite. It builds the bundled ngtcp2 source and exposes low-level bindings
used by local QUIC/HTTP/3 server backends.

It is not intended or recommended for production applications.

## Features

- Builds ngtcp2 from the bundled source tree.
- Uses CMake for the native build.
- Uses aws-lc as the TLS backend.
- Generates Rust bindings for the current Cargo target.

## Build Requirements

- CMake
- A C compiler such as gcc, clang, or MSVC
- libclang, required by bindgen
- Go, required to build aws-lc
