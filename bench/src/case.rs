//! Benchmark workload, HTTP/3 library selection, and workspace configuration.

use std::{fmt, path::PathBuf, time::Duration};

use anyhow::Result;

use super::headers::HeaderMode;
pub const SERVER_ADDR: &str = "127.0.0.1:4433";
pub const SERVER_WORKERS: usize = 8;
/// Leaves stream-credit headroom above the supported Client concurrency without
/// making Quinn prebuild an impractically large remote-stream state table.
pub const SERVER_MAX_BIDI_STREAMS: u32 = 1000;
pub const MAX_BODY_BYTES: usize = 100 * 1024 * 1024;
pub const MAX_REQUESTS: usize = 20_000;
pub const DEFAULT_BODY_BYTES: [usize; 9] = [
    0,
    1024,
    10 * 1024,
    64 * 1024,
    128 * 1024,
    1024 * 1024,
    2 * 1024 * 1024,
    4 * 1024 * 1024,
    MAX_BODY_BYTES,
];
pub(crate) const SERVER_NAME: &str = "localhost";
pub(crate) const ALPN_H3: &[u8] = b"h3";

pub fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..")
}

#[derive(Clone, Copy, Debug)]
pub struct Case {
    pub body_bytes: usize,
    pub requests: usize,
    pub in_flight: usize,
    pub headers: HeaderMode,
}

impl Case {
    pub fn for_body(body_bytes: usize) -> Self {
        let requests = (640 * 1024 * 1024_usize)
            .checked_div(body_bytes)
            .unwrap_or(MAX_REQUESTS)
            .clamp(32, MAX_REQUESTS);
        let in_flight = (64 * 1024 * 1024_usize)
            .checked_div(body_bytes)
            .unwrap_or(100)
            .clamp(4, 100);
        Self {
            body_bytes,
            requests,
            in_flight,
            headers: HeaderMode {
                request: true,
                response: true,
            },
        }
    }

    pub const fn measurement_time(self) -> Duration {
        if self.body_bytes < MAX_BODY_BYTES {
            Duration::from_secs(30)
        } else {
            Duration::from_secs(60)
        }
    }

    pub fn expected_bytes(self) -> Result<usize> {
        self.requests
            .checked_mul(self.body_bytes)
            .ok_or_else(|| anyhow::anyhow!("total response byte count overflowed usize"))
    }
}

impl fmt::Display for Case {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        const KIB: usize = 1024;
        const MIB: usize = 1024 * KIB;

        // Criterion requires globally unique benchmark IDs. Use the largest
        // exact IEC unit so nearby byte counts cannot collide through rounded
        // human-readable output.
        if self.body_bytes == 0 {
            formatter.write_str("0 B")
        } else if self.body_bytes.is_multiple_of(MIB) {
            write!(formatter, "{} MiB", self.body_bytes / MIB)
        } else if self.body_bytes.is_multiple_of(KIB) {
            write!(formatter, "{} KiB", self.body_bytes / KIB)
        } else {
            write!(formatter, "{} B", self.body_bytes)
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Http3Library {
    Http3,
    H3,
    Nghttp3,
}

impl Http3Library {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Http3 => "http3",
            Self::H3 => "h3",
            Self::Nghttp3 => "nghttp3",
        }
    }
}

impl fmt::Display for Http3Library {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.name())
    }
}
