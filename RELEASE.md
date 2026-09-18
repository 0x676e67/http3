# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0](https://github.com/0x676e67/http3/compare/http3-v0.0.8...http3-v0.1.0) - 2026-09-18

### Added

- *(client,qpack)* implement qpack dynamic table decoder ([#1](https://github.com/0x676e67/http3/pull/1))

### Fixed

- *(client)* reset client request stream on drop ([#5](https://github.com/0x676e67/http3/pull/5))
- validate received pseudo-header context and ordering ([#87](https://github.com/0x676e67/http3/pull/87))
- reject oversized received header maps without panicking ([#86](https://github.com/0x676e67/http3/pull/86))
- *(qpack)* release completed encoder instruction batches
- *(qpack)* preserve decoder state metadata ([#70](https://github.com/0x676e67/http3/pull/70))
- *(qpack)* gate stateless decoder export
- *(qpack)* harden decoder protocol boundaries
- *(qpack)* harden decoder driver error handling
- *(qpack)* track decoder feedback per field section
- *(qpack)* clarify zero required insert count semantics ([#65](https://github.com/0x676e67/http3/pull/65))
- *(server)* drive peer QPACK encoder stream ([#64](https://github.com/0x676e67/http3/pull/64))
- *(qpack)* drive peer decoder stream ([#63](https://github.com/0x676e67/http3/pull/63))
- *(qpack)* validate insert count increments ([#62](https://github.com/0x676e67/http3/pull/62))
- *(qpack)* publish errors before waking waiters ([#53](https://github.com/0x676e67/http3/pull/53))
- *(qpack)* reject invalid negative delta base ([#52](https://github.com/0x676e67/http3/pull/52))
- *(client, qpack)* wait for missing refs without lost wakeups ([#17](https://github.com/0x676e67/http3/pull/17))

### Other

- fix release-plz
- wait for both peers during graceful shutdown ([#94](https://github.com/0x676e67/http3/pull/94))
- raise workspace MSRV to Rust 1.98 ([#93](https://github.com/0x676e67/http3/pull/93))
- *(qpack)* explain field section blocking check
- fmt
- reduce QPACK codec and client driver overhead
- Merge branch 'feat-qpack-huffman-bufmut' into feat-client-io-optimization
- Merge branch 'main' into feat-qpack-huffman-bufmut
- Update README.md
- Formatting of HTTP/3 feature description
- *(quinn)* sync test receive stream adapter
- Potential fix for pull request finding
- *(qpack)* unify field section decoding
- *(headers)* unify borrowed header iteration
- *(qpack)* unify borrowed and owned header fields
- *(client)* optimize HTTP/3 hot paths
- *(qpack)* correct protocol terminology ([#71](https://github.com/0x676e67/http3/pull/71))
- Merge pull request #67 from 0x676e67/fix-qpack-decoder-feedback-state
- *(qpack)* preserve fragmented literal decode progress ([#56](https://github.com/0x676e67/http3/pull/56))
- *(qpack)* avoid decoder lookup map maintenance ([#57](https://github.com/0x676e67/http3/pull/57))
- *(buf)* cache remaining byte count ([#55](https://github.com/0x676e67/http3/pull/55))
- *(qpack)* avoid retaining decoder access wakers ([#54](https://github.com/0x676e67/http3/pull/54))
- Merge branch 'main' into fix-qpack-decoder-compliance
- unify workspace license ([#48](https://github.com/0x676e67/http3/pull/48))
- Update README.md
- Add documentation link to README
- *(deps)* update dependencies ([#47](https://github.com/0x676e67/http3/pull/47))
- *(feature)* rename third-party backend flag to `unstable` ([#46](https://github.com/0x676e67/http3/pull/46))
- crates for `http3` fork ([#45](https://github.com/0x676e67/http3/pull/45))
- *(header)* optimize HeaderValue creation via zero-copy sharing ([#33](https://github.com/0x676e67/http3/pull/33))
- *(http3, client)* add server interop tests ([#21](https://github.com/0x676e67/http3/pull/21))
- Fix typo in README description
- Add QPACK support to features list in README
- Add license badge to README.md
- Update README with License and Contribution sections
- Update README
- Update README.md
- Update stream.rs
- Update frame.rs
- keep nightly jobs current
- update Rust baseline and workflow tooling
- rename crates for http3-rs fork
- Revise README to enhance project description
- Fix formatting issue in README.md
- Update README.md
- Update README.md
- Fix create/crate typo README ([#326](https://github.com/0x676e67/http3/pull/326))
- Refactor Error handling to fix bugs ([#271](https://github.com/0x676e67/http3/pull/271))
- Update README to include MsQuic support and interoperability testing details ([#276](https://github.com/0x676e67/http3/pull/276))
- *(readme)* wrong link for PROPOSAL.md ([#172](https://github.com/0x676e67/http3/pull/172))
- runtime independent ([#162](https://github.com/0x676e67/http3/pull/162))
- document the duvet usage in h3 ([#131](https://github.com/0x676e67/http3/pull/131))
- Fix doc links ([#132](https://github.com/0x676e67/http3/pull/132))
- server examples - handle errors correct ([#128](https://github.com/0x676e67/http3/pull/128))
- Document everything ([#126](https://github.com/0x676e67/http3/pull/126))
- update links to rfc ([#106](https://github.com/0x676e67/http3/pull/106))
- Update README.md ([#91](https://github.com/0x676e67/http3/pull/91))
- Fix readme typo ([#89](https://github.com/0x676e67/http3/pull/89))
- improve README ([#88](https://github.com/0x676e67/http3/pull/88))
- Add LICENSE
- init
- Initial commit
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
