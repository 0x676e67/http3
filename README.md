# http3


[![CI](https://github.com/0x676e67/http3/actions/workflows/CI.yml/badge.svg)](https://github.com/0x676e67/http3/actions/workflows/CI.yml)
[![GitHub License](https://img.shields.io/github/license/0x676e67/http3)](https://github.com/0x676e67/http3/blob/main/LICENSE)
[![Crates.io](https://img.shields.io/crates/v/http3.svg)](https://crates.io/crates/http3)

A [Tokio][tokio] aware, HTTP/3 implementation for Rust.

## Features

- [HTTP/3](https://www.rfc-editor.org/rfc/rfc9114.html) implementation.
- Implements the full [HTTP/3](https://www.rfc-editor.org/rfc/rfc9114.html) specifications.
- Implements [RFC 9204](https://www.rfc-editor.org/rfc/rfc9204.html) QPACK. It supports dynamic table.
- Works with different QUIC transport implementations.
- Passes HTTP/3 interoperability tests.
- Focus on performance, interoperability, and correctness.
- Continues the [h3](https://github.com/hyperium/h3) codebase, tracking upstream changes.

## Usage

To use `http3`, first add this to your `Cargo.toml`:

```toml
[dependencies]
http3 = "0.1.1"
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

[docs]: https://docs.rs/http3
[tokio]: https://github.com/tokio-rs/tokio
[H3]: https://github.com/hyperium/h3
