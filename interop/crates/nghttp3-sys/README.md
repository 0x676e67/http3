# nghttp3-sys

Rust FFI bindings for [nghttp3](https://github.com/ngtcp2/nghttp3).

## Scope

This crate is maintained only for the
[0x676e67/http3-rs](https://github.com/0x676e67/http3-rs) interoperability
test suite. It builds the bundled nghttp3 source and exposes low-level bindings
used by local HTTP/3 server backends.

It is not intended or recommended for production applications.

## Features

- Builds nghttp3 from the bundled source tree.
- Uses CMake for the native build.
- Generates Rust bindings for the current Cargo target.

## Build Requirements

- CMake
- A C compiler such as gcc, clang, or MSVC
- libclang, required by bindgen
