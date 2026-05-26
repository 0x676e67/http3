# http3-rs

An async HTTP/3 implementation.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

This crate provides an [HTTP/3][spec] implementation that is generic over a provided QUIC transport. This allows the project to focus on just HTTP/3, while letting users pick their QUIC implementation based on their specific needs. It includes client and server APIs.

[spec]: https://www.rfc-editor.org/rfc/rfc9114

## Accolades

The project is based on a fork of [h3](https://github.com/hyperium/h3).
