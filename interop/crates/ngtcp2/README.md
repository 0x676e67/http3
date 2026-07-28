# ngtcp2

Rust wrapper library for [ngtcp2](https://github.com/ngtcp2/ngtcp2) and
[nghttp3](https://github.com/ngtcp2/nghttp3).

## Scope

This crate is maintained in the
[http3](https://github.com/0x676e67/http3) repository. It wraps
`ngtcp2-sys` and `nghttp3-sys` with a small Rust API for HTTP/3 clients and
servers.

## Features

- Integrates ngtcp2 QUIC with nghttp3 HTTP/3.
- Uses aws-lc as the TLS backend.
- Provides a Rust API for building HTTP/3 clients and servers.

## Dependencies

- `ngtcp2-sys` - ngtcp2 FFI bindings.
- `nghttp3-sys` - nghttp3 FFI bindings.
- `aws-lc-rs` - TLS cryptography.
