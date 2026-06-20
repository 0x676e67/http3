# http3-quinn-rs

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](../LICENSE)
[![CI](https://github.com/0x676e67/http3-rs/actions/workflows/CI.yml/badge.svg)](https://github.com/0x676e67/http3-rs/actions/workflows/CI.yml)
[![Crates.io](https://img.shields.io/crates/v/http3-quinn-rs.svg)](https://crates.io/crates/http3-quinn-rs)
[![Documentation](https://docs.rs/http3-quinn-rs/badge.svg)](https://docs.rs/http3-quinn-rs)

QUIC transport implementation for [http3-rs](https://github.com/0x676e67/http3-rs) based on [Quinn](https://github.com/quinn-rs/quinn).

## Overview

`http3-quinn-rs` integrates the `http3-rs` HTTP/3 implementation with the `quinn` QUIC transport library.

## Features

- Complete implementation of the `http3-rs` QUIC transport traits
- Full support for HTTP/3 client and server functionality
- Optional tracing support
- Optional datagram support

## License

This project is licensed under the [MIT license](../LICENSE).

## See Also

- [http3-rs](https://github.com/0x676e67/http3-rs) - The core HTTP/3 implementation
- [Quinn](https://github.com/quinn-rs/quinn) - The QUIC implementation used by this crate
