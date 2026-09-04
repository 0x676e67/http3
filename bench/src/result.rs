//! Compact child-process result contract and controller-side validation.

use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use super::case::{Case, Http3Library};

pub(crate) const RESULT_SCHEMA: &str = "http3-client-bench-v11";

/// Timed region shared by every Client implementation.
pub const MEASUREMENT_PROFILE: &str = "post-local-setup-to-last-complete-response";

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClientResult {
    pub(crate) schema: String,
    pub(crate) http3_library: String,
    pub(crate) quic_backend: String,
    pub(crate) transport_profile: String,
    pub(crate) measurement_profile: String,
    pub(crate) requests: usize,
    pub(crate) in_flight: usize,
    pub(crate) extra_request_headers: usize,
    pub(crate) response_body_bytes: usize,
    pub(crate) completed: usize,
    pub(crate) received_bytes: usize,
    pub(crate) elapsed_ns: u64,
    pub(crate) path_max_udp_payload_size: usize,
}

impl ClientResult {
    pub fn parse(stdout: &[u8]) -> Result<Self> {
        let stdout = std::str::from_utf8(stdout).context("client stdout was not UTF-8")?;
        let mut lines = stdout.lines().filter(|line| !line.trim().is_empty());
        let line = lines
            .next()
            .context("client did not write a benchmark result")?;
        if lines.next().is_some() {
            bail!("client wrote more than one non-empty stdout line: {stdout:?}");
        }
        serde_json::from_str(line).context("client wrote an invalid benchmark result")
    }

    pub fn validate(&self, library: Http3Library, case: Case) -> Result<Duration> {
        check_eq("schema", &self.schema, RESULT_SCHEMA)?;
        check_eq("http3_library", &self.http3_library, library.name())?;
        let expected_backend = match library {
            Http3Library::Http3 | Http3Library::H3 => "quinn",
            Http3Library::Nghttp3 => "ngtcp2",
        };
        check_eq("quic_backend", &self.quic_backend, expected_backend)?;
        let expected_transport_profile = match library {
            Http3Library::Http3 | Http3Library::H3 => "quinn-default-pmtud",
            Http3Library::Nghttp3 => "ngtcp2-1350b-1mib-stream-10mib-connection",
        };
        check_eq(
            "transport_profile",
            &self.transport_profile,
            expected_transport_profile,
        )?;
        check_eq(
            "measurement_profile",
            &self.measurement_profile,
            MEASUREMENT_PROFILE,
        )?;
        check_number("requests", self.requests, case.requests)?;
        check_number("in_flight", self.in_flight, case.in_flight)?;
        check_number(
            "extra_request_headers",
            self.extra_request_headers,
            case.extra_headers,
        )?;
        check_number(
            "response_body_bytes",
            self.response_body_bytes,
            case.body_bytes,
        )?;
        check_number("completed", self.completed, case.requests)?;
        check_number(
            "received_bytes",
            self.received_bytes,
            case.expected_bytes()?,
        )?;
        if !(1200..=65_527).contains(&self.path_max_udp_payload_size) {
            bail!(
                "client reported invalid path MTU {}",
                self.path_max_udp_payload_size
            );
        }
        if self.elapsed_ns == 0 {
            bail!("client reported a zero-length measured interval");
        }
        Ok(Duration::from_nanos(self.elapsed_ns))
    }
}

fn check_eq(name: &str, actual: &str, expected: &str) -> Result<()> {
    if actual != expected {
        bail!("expected {name}={expected:?}, got {actual:?}");
    }
    Ok(())
}

fn check_number(name: &str, actual: usize, expected: usize) -> Result<()> {
    if actual != expected {
        bail!("expected {name}={expected}, got {actual}");
    }
    Ok(())
}
