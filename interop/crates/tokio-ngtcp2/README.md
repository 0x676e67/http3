# tokio-ngtcp2

Tokio async runtime integration for the `ngtcp2` Rust wrapper.

## Scope

This crate is maintained in the
[http3-rs](https://github.com/0x676e67/http3-rs) repository. It adapts the
`ngtcp2` wrapper to Tokio for asynchronous HTTP/3 clients and servers.

## Features

- Tokio async runtime integration.
- Async I/O support for the local ngtcp2/nghttp3 wrapper.

## Dependencies

- `ngtcp2` - ngtcp2/nghttp3 wrapper.
- `tokio` - async runtime.
