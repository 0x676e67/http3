# HTTP/3 Interop

Local interoperability tests for the `http3-rs` Quinn client.

The tests run the same client against several HTTP/3 server backends:
ngtcp2/nghttp3, quiche, and tquic. The ngtcp2/nghttp3 wrappers live in
`interop/crates/`, so the suite does not rely on a separate HTTP/3 test repo at
build time.

```bash
cargo test -p interop
```

The interop workflow also runs the real public-server checks. They are ignored
by default for local `cargo test` because they need external network access:

```bash
cargo test -p interop --test client -- --ignored --nocapture --test-threads=1
```

Each backend runs the same response matrix: several status codes, empty and
large bodies, bounded concurrent requests, and QPACK SETTINGS combinations with
client/server dynamic tables enabled and disabled. The local matrix runs
client-side HTTP/3 GREASE for every backend. quiche and tquic also run
server-side GREASE cases; ngtcp2/nghttp3 is kept to its safe wrapper API and
currently has no server-side reserved HTTP/3 element hook.

The server helpers are expected to work on Windows and Unix-like hosts. The
vendored ngtcp2/nghttp3 build applies small MSVC patches in `build.rs` while
keeping the checked-in Rust wrappers close to upstream.
