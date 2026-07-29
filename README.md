# http3

A Tokio aware, HTTP/3 implementation for Rust.

[![CI](https://github.com/0x676e67/http3/actions/workflows/CI.yml/badge.svg)](https://github.com/0x676e67/http3/actions/workflows/CI.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Crates.io](https://img.shields.io/crates/v/http3.svg)](https://crates.io/crates/http3)

More information about this crate can be found in the [crate documentation][docs].

[docs]: https://docs.rs/http3

## Features

- Client [HTTP/3](https://www.rfc-editor.org/rfc/rfc9114.html) implementation.
- Implements the full [HTTP/3](https://www.rfc-editor.org/rfc/rfc9114.html) specifications.
- Implements [RFC 9204](https://www.rfc-editor.org/rfc/rfc9204.html) QPACK. It supports dynamic table.
- Works with different QUIC transport implementations.
- Passes HTTP/3 interoperability tests.
- Focus on performance, interoperability, and correctness.
- Built on [Tokio](https://tokio.rs).

## Usage

To use `http3`, first add this to your `Cargo.toml`:

```toml
[dependencies]
http3 = "0.0.8"
```

Next, add this to your crate:

```rust
use http3::client::Connection;

fn main() {
    // ...
}
```

## License

Licensed under either of Apache License, Version 2.0 ([LICENSE](./LICENSE) or http://www.apache.org/licenses/LICENSE-2.0).

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the [Apache-2.0](./LICENSE) license, shall be licensed as above, without any additional terms or conditions.

## Accolades

The project is based on a fork of [h3](https://github.com/hyperium/h3).
