# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1](https://github.com/0x676e67/http3/compare/v0.0.8...http3-v0.1.1) - 2026-09-18

### Added

- *(bench)* add Criterion HTTP/3 client comparison
- *(bench)* bound CI request batches
- *(bench)* add multi-header concurrency cases
- *(bench)* compare clients with http3 and h3 servers
- *(bench)* add Criterion HTTP/3 client comparison ([#74](https://github.com/0x676e67/http3/pull/74))

### Fixed

- *(ngtcp2, nghttp3)* fix Windows MSVC CRT interop build warning ([#38](https://github.com/0x676e67/http3/pull/38))
- *(qpack)* reject overflowing delta base ([#39](https://github.com/0x676e67/http3/pull/39))
- *(qpack)* accept full blocked streams setting range ([#40](https://github.com/0x676e67/http3/pull/40))
- *(qpack)* release blocked streams on decoder updates ([#41](https://github.com/0x676e67/http3/pull/41))
- *(qpack)* close decoder compliance gaps
- *(interop)* use published crates and drain h3 requests ([#44](https://github.com/0x676e67/http3/pull/44))
- *(datagram)* preserve quarter stream id ([#51](https://github.com/0x676e67/http3/pull/51))
- *(qpack)* reject invalid negative delta base ([#52](https://github.com/0x676e67/http3/pull/52))
- *(qpack)* publish errors before waking waiters ([#53](https://github.com/0x676e67/http3/pull/53))
- *(ci)* use default Cargo Dependabot strategy
- *(ci)* prevent Dependabot examples binary inference ([#59](https://github.com/0x676e67/http3/pull/59))
- *(qpack)* validate insert count increments ([#62](https://github.com/0x676e67/http3/pull/62))
- *(qpack)* drive peer decoder stream ([#63](https://github.com/0x676e67/http3/pull/63))
- *(server)* drive peer QPACK encoder stream ([#64](https://github.com/0x676e67/http3/pull/64))
- *(qpack)* clarify zero required insert count semantics ([#65](https://github.com/0x676e67/http3/pull/65))
- *(qpack)* publish errors before waking waiters
- *(qpack)* track decoder feedback per field section
- *(qpack)* harden decoder driver error handling
- *(qpack)* harden decoder protocol boundaries
- *(qpack)* gate stateless decoder export
- *(qpack)* preserve decoder state metadata ([#70](https://github.com/0x676e67/http3/pull/70))
- *(bench)* align native UDP batching with Quinn
- *(bench)* tighten fairness and reporting
- *(bench)* compare clients per body case
- *(qpack)* release completed encoder instruction batches
- reject oversized received header maps without panicking ([#86](https://github.com/0x676e67/http3/pull/86))
- validate received pseudo-header context and ordering ([#87](https://github.com/0x676e67/http3/pull/87))
- *(client)* reset client request stream on drop ([#5](https://github.com/0x676e67/http3/pull/5))

### Other

- add license badge to README.md
- update dependabot configuration for new ecosystems ([#23](https://github.com/0x676e67/http3/pull/23))
- add QPACK support to features list in README
- fix typo in README description
- *(http3, client)* add server interop tests ([#21](https://github.com/0x676e67/http3/pull/21))
- *(http3, client)* add real-server interop tests ([#22](https://github.com/0x676e67/http3/pull/22))
- *(http3, client)* add real GREASE interop tests ([#25](https://github.com/0x676e67/http3/pull/25))
- *(interop)* tighten ngtcp2 FFI safety boundaries ([#27](https://github.com/0x676e67/http3/pull/27))
- *(http3, client)* add GREASE interop tests ([#28](https://github.com/0x676e67/http3/pull/28))
- merge branch 'main' into fix-qpack-decoder-compliance
- *(interop)* join local interop request tasks concurrently ([#30](https://github.com/0x676e67/http3/pull/30))
- *(interop)* join public server request tasks concurrently ([#29](https://github.com/0x676e67/http3/pull/29))
- bump actions/checkout from 5 to 7 ([#24](https://github.com/0x676e67/http3/pull/24))
- *(qpack)* cover invalid post-base required count
- test(http3, client): Add max field section size interop tests ([#26](https://github.com/0x676e67/http3/pull/26))
- *(header)* optimize HeaderValue creation via zero-copy sharing ([#33](https://github.com/0x676e67/http3/pull/33))
- limit default workspace members
- *(interop)* add s2n h3 server backend ([#34](https://github.com/0x676e67/http3/pull/34))
- *(interop)* add quinn h3 server backend ([#37](https://github.com/0x676e67/http3/pull/37))
- *(qpack)* accept zero capacity update at zero limit ([#42](https://github.com/0x676e67/http3/pull/42))
- fmt
- *(qpack)* clarify decoder behavior
- *(interop)* update ngtcp2 crates to 0.2.0 ([#43](https://github.com/0x676e67/http3/pull/43))
- crates for `http3` fork ([#45](https://github.com/0x676e67/http3/pull/45))
- *(feature)* rename third-party backend flag to `unstable` ([#46](https://github.com/0x676e67/http3/pull/46))
- fix formatting for new contributors section in .cliff.toml
- *(deps)* update dependencies ([#47](https://github.com/0x676e67/http3/pull/47))
- add documentation link to README
- update README.md
- unify workspace license ([#48](https://github.com/0x676e67/http3/pull/48))
- *(examples)* add client skip-verify flag ([#49](https://github.com/0x676e67/http3/pull/49))
- cleanup whitespace warning
- *(qpack)* avoid retaining decoder access wakers ([#54](https://github.com/0x676e67/http3/pull/54))
- *(buf)* cache remaining byte count ([#55](https://github.com/0x676e67/http3/pull/55))
- modify Dependabot settings for Cargo
- *(qpack)* avoid decoder lookup map maintenance ([#57](https://github.com/0x676e67/http3/pull/57))
- *(interop)* remove yanked s2n h3 backend ([#58](https://github.com/0x676e67/http3/pull/58))
- *(qpack)* preserve fragmented literal decode progress ([#56](https://github.com/0x676e67/http3/pull/56))
- *(deps)* track Cargo.lock ([#61](https://github.com/0x676e67/http3/pull/61))
- *(deps)* update rcgen requirement from =0.14.5 to =0.14.9 ([#60](https://github.com/0x676e67/http3/pull/60))
- use nightly rustfmt
- update Cargo.lock
- *(qpack)* correct protocol terminology ([#71](https://github.com/0x676e67/http3/pull/71))
- *(client)* optimize HTTP/3 hot paths
- *(qpack)* unify borrowed and owned header fields
- *(headers)* unify borrowed header iteration
- *(qpack)* unify field section decoding
- potential fix for pull request finding
- *(quinn)* sync test receive stream adapter
- *(qpack)* encode Huffman strings directly
- *(bench)* focus single-connection comparison
- *(bench)* remove auxiliary role binaries
- *(qpack)* flatten Huffman decoding
- *(qpack)* compact Huffman encode tables
- *(qpack)* fuse static name and value lookup
- *(bench)* simplify benchmark dependencies
- *(qpack)* retain h2 encoder license notice
- *(client)* reuse request QPACK encode buffer
- *(qpack)* specialize request paths and add dynamic encoding
- *(headers)* use pre-parsed host name
- formatting of HTTP/3 feature description
- compare fixed browser headers in both directions
- add opt-in Linux client CPU profiling
- keep QUIC connections on no-steal server workers
- remove unreachable worker validation
- profile 1 KiB client scheduling with Quinn snapshots
- add native server and static/dynamic QPACK matrix ([#77](https://github.com/0x676e67/http3/pull/77))
- support macOS and fixed-runtime client comparisons
- reduce QPACK codec and client driver overhead
- show benchmark notes once above concurrency tables
- *(qpack)* explain field section blocking check
- *(deps)* bump smallvec from 1.15.2 to 1.16.0 ([#81](https://github.com/0x676e67/http3/pull/81))
- *(deps)* bump actions/upload-artifact from 4 to 7 ([#78](https://github.com/0x676e67/http3/pull/78))
- *(deps)* bump aws-lc-rs from 1.17.3 to 1.18.1 ([#80](https://github.com/0x676e67/http3/pull/80))
- raise workspace MSRV to Rust 1.98 ([#93](https://github.com/0x676e67/http3/pull/93))
- wait for both peers during graceful shutdown ([#94](https://github.com/0x676e67/http3/pull/94))
- add GitHub Actions workflow for Release-plz
- *(http3-quic)* use `quic` as the only `http3-quic` backend ([#95](https://github.com/0x676e67/http3/pull/95))
- fix release-plz
- add 0.1.0 release notes
- *(http3-datagram)* rename readme.md to README.md
- manage crate versions from the workspace
- *(deps)* update chacha20 to a version that is not yanked
- *(release-plz)* verify publishable crates before publishing

## [unreleased]

### 🚀 Features

- Expose 0-RTT detection at stream level (#323)
- *(h3)* Add pseudo-header ordering support for HTTP/3 impersonation
- *(h3)* Add settings ordering and arbitrary settings support
- *(h3)* Add QPACK settings support for HTTP/3 impersonation
- *(h3)* Make SettingId and constants public with doc comments
- *(client,qpack)* Implement qpack dynamic table decoder (#1)

### 🐛 Bug Fixes

- *(client)* Correct behavior of standard CONNECT (#322)
- *(h3)* Always append GREASE last, use u32 random value matching Chromium
- *(client, qpack)* Wait for missing refs without lost wakeups (#17)
- *(ngtcp2, nghttp3)* Fix Windows MSVC CRT interop build warning (#38)
- *(interop)* Use published crates and drain h3 requests (#44)

### 💼 Other

- *(deps)* Update dependencies

### 🚜 Refactor

- Rename crates for http3-rs fork
- Crates for `http3` fork (#45)
- *(feature)* Rename third-party backend flag to `unstable` (#46)

### ⚡ Performance

- *(header)* Optimize HeaderValue creation via zero-copy sharing (#33)

### 🧪 Testing

- *(http3, client)* Add server interop tests (#21)
- *(http3, client)* Add real-server interop tests (#22)
- *(http3, client)* Add real GREASE interop tests (#25)
- *(interop)* Tighten ngtcp2 FFI safety boundaries (#27)
- *(http3, client)* Add GREASE interop tests (#28)
- *(interop)* Join local interop request tasks concurrently (#30)
- *(interop)* Join public server request tasks concurrently (#29)
- *(interop)* Add s2n h3 server backend (#34)
- *(interop)* Remove the yanked s2n-quic-h3 server backend
- *(interop)* Add quinn h3 server backend (#37)

### ⚙️ Miscellaneous Tasks

- Bump h3-quinn msrv job to 1.74.1 (#320)
- Update dependencies (#318)
- Trim unused dependencies, replace `futures` with `futures-util` (#324)
- *(h3-quinn)* Use quinn git dependency
- Update Rust baseline and workflow tooling
- Use latest nightly for fuzzing
- Keep nightly jobs current
- Update dependabot configuration for new ecosystems (#23)
- Limit default workspace members
- *(interop)* Update ngtcp2 crates to 0.2.0 (#43)
## [h3-quinn-v0.0.9] - 2025-03-18

### 💼 Other

- Fix usage of a private StreamId field (#290)
## [h3-v0.0.7] - 2025-03-15

### 🐛 Bug Fixes

- Typo (#257)

### 🧪 Testing

- Ignore docs for test-util send_settings

### ⚙️ Miscellaneous Tasks

- Bump pinned nightly version
- Bump h3-quinn msrv to 1.71
- Add .duvet/config.toml (#278)
## [h3-v0.0.6] - 2024-07-01

### ⚙️ Miscellaneous Tasks

- Update h3spec to version 0.1.10 (#245)
## [h3-v0.0.3] - 2023-10-23

### 💼 Other

- Actually encode extensions in header (#204)
## [h3-quinn-v0.0.3] - 2023-05-16

### 💼 Other

- Update Rustls to 0.21.0, Quinn to 0.10. (#190)
## [h3-v0.0.2] - 2023-04-11

### 💼 Other

- Update to Quinn 0.9

### 🚜 Refactor

- Fix clippy warnings (#180)

### 📚 Documentation

- *(readme)* Wrong link for PROPOSAL.md (#172)

### ⚙️ Miscellaneous Tasks

- Update nightly version for CI (#179)
## [h3-quinn-v0.0.1] - 2023-03-09

### 📚 Documentation

- Add release/publish process (#166)
## [h3-v0.0.1] - 2023-03-09

### 💼 Other

- :BidiStream own trait bound
- Add clippy lint job
- Add wait_idle async method (#102)
- Add CLI option to client to use sslkeylogfile (#130)

### ⚙️ Miscellaneous Tasks

- Add a single step to depend PRs on (#100)
- Use published duvet (#123)
