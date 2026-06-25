# ngtcp2

Rust wrapper library for [ngtcp2](https://github.com/ngtcp2/ngtcp2) and
[nghttp3](https://github.com/ngtcp2/nghttp3).

## Scope

This crate is maintained only for the
[0x676e67/http3-rs](https://github.com/0x676e67/http3-rs) interoperability
test suite. It wraps the local `ngtcp2-sys` and `nghttp3-sys` crates with a
small Rust API for client/server interop backends.

It is not intended or recommended for production applications.

## Features

- Integrates ngtcp2 QUIC with nghttp3 HTTP/3.
- Uses aws-lc as the TLS backend.
- Provides the Rust API needed by the interop tests.

## Dependencies

- `ngtcp2-sys` - ngtcp2 FFI bindings.
- `nghttp3-sys` - nghttp3 FFI bindings.
- `aws-lc-rs` - TLS cryptography.
