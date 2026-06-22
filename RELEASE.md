## [unreleased]

### 🚀 Features

- Expose 0-RTT detection at stream level (#323)
- *(h3)* Add pseudo-header ordering support for HTTP/3 impersonation
- *(h3)* Add settings ordering and arbitrary settings support
- *(h3)* Add QPACK settings support for HTTP/3 impersonation
- *(h3)* Make SettingId and constants public with doc comments

### 🐛 Bug Fixes

- *(client)* Correct behavior of standard CONNECT (#322)
- *(h3)* Always append GREASE last, use u32 random value matching Chromium

### 🚜 Refactor

- Rename crates for http3-rs fork

### ⚙️ Miscellaneous Tasks

- Bump h3-quinn msrv job to 1.74.1 (#320)
- Update dependencies (#318)
- Trim unused dependencies, replace `futures` with `futures-util` (#324)
- *(h3-quinn)* Use quinn git dependency
- Update Rust baseline and workflow tooling
- Use latest nightly for fuzzing
- Keep nightly jobs current
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
