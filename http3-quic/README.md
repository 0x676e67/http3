# http3-quic

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](../LICENSE)
[![CI](https://github.com/0x676e67/http3/actions/workflows/CI.yml/badge.svg)](https://github.com/0x676e67/http3/actions/workflows/CI.yml)
[![Crates.io](https://img.shields.io/crates/v/http3-quic.svg)](https://crates.io/crates/http3-quic)
[![Documentation](https://docs.rs/http3-quic/badge.svg)](https://docs.rs/http3-quic)

Transport adapter for [http3](https://github.com/0x676e67/http3) using the [quic](https://crates.io/crates/quic) crate.

## Overview

`http3-quic` uses `quic` directly, without a backend selection feature.
Pass a `quic::Connection` to `http3_quic::Connection::new` and enable the
runtime and TLS features needed by your application on the `quic` dependency.

The workspace currently pins a tested Git revision of `quic`. Publishing this
adapter to crates.io requires a corresponding `quic` release first.

## Features

- Complete implementation of the `http3` QUIC transport traits
- Full support for HTTP/3 client and server functionality
- Optional tracing support
- Optional datagram support

## License

This project is licensed under the [MIT license](../LICENSE).
