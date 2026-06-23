# ngtcp2-sys

Rust FFI bindings for ngtcp2.

## Overview

[ngtcp2](https://github.com/ngtcp2/ngtcp2) is a QUIC library written in C. This
crate builds ngtcp2 and exposes low-level FFI bindings for Rust.

## Features

- Automatically clones and builds the ngtcp2 source.
- Cross-platform build through CMake.
- Uses aws-lc as the TLS backend.
- Includes generated bindings, so libclang is not needed for normal builds.

## Build Requirements

- CMake
- C compiler such as gcc or clang
- Go, required to build aws-lc

## Regenerating Bindings

Regenerate bindings after updating the ngtcp2 version:

```bash
cargo build -p ngtcp2-sys --features overwrite
```

Note: the `overwrite` feature requires libclang.

## ngtcp2 License

<https://github.com/ngtcp2/ngtcp2/blob/main/COPYING>

```text
The MIT License

Copyright (c) 2019 nghttp3 contributors

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
```

## License

Apache License 2.0

```text
Copyright 2026-2026, Shiguredo Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
