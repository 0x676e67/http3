# tokio-ngtcp2

Tokio async runtime integration for the local ngtcp2/nghttp3 wrapper.

## Scope

This crate is maintained only for the
[0x676e67/http3-rs](https://github.com/0x676e67/http3-rs) interoperability
test suite. It adapts the local `ngtcp2` wrapper to Tokio so the interop tests
can run ngtcp2/nghttp3 HTTP/3 servers.

It is not intended or recommended for production applications.

## Features

- Tokio async runtime integration.
- Async I/O support for the local ngtcp2/nghttp3 wrapper.

## Dependencies

- `ngtcp2` - ngtcp2/nghttp3 wrapper.
- `tokio` - async runtime.
