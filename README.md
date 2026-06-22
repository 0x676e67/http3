# http3-rs

A Tokio aware, [HTTP/3](https://www.rfc-editor.org/rfc/rfc9114.html) implementation for Rust.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/0x676e67/http3-rs/actions/workflows/CI.yml/badge.svg)](https://github.com/0x676e67/http3-rs/actions/workflows/CI.yml)
[![Crates.io](https://img.shields.io/crates/v/http3-rs.svg)](https://crates.io/crates/http3-rs)
[![Documentation](https://docs.rs/http3-rs/badge.svg)][docs]

More information about this crate can be found in the [crate documentation][docs].

[docs]: https://docs.rs/http3-rs

## Features

- Client [HTTP/3](https://www.rfc-editor.org/rfc/rfc9114.html) implementation.
- Implements the full [HTTP/3](https://www.rfc-editor.org/rfc/rfc9114.html) and [QPACK](https://www.rfc-editor.org/rfc/rfc9204.html) specifications.
- Works with different QUIC transport implementations.
- Focus on performance, interoperability, and correctness.

## Usage

To use `http3-rs`, first add this to your `Cargo.toml`:

```toml
[dependencies]
http3-rs = "0.0.8"
```

Next, add this to your crate:

```rust
use http3_rs::client::Connection;

fn main() {
    // ...
}
```

## Accolades

The project is based on a fork of [h3](https://github.com/hyperium/h3).
