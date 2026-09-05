//! Fixed browser-shaped fields and directional QPACK workload selection.

use std::{fmt, str::FromStr};

use anyhow::{Result, bail};
use http::{HeaderMap, HeaderName, HeaderValue};

// Rust and C share the browser/application request and designed response fixtures.
include!(concat!(env!("OUT_DIR"), "/headers.rs"));

#[derive(Clone, Copy, Debug)]
pub struct HeaderMode {
    pub request: bool,
    pub response: bool,
}

impl FromStr for HeaderMode {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        let (request, response) = match value {
            "none" => (false, false),
            "request" => (true, false),
            "response" => (false, true),
            "both" => (true, true),
            _ => bail!(
                "unsupported header mode {value:?}; expected none, request, response, or both"
            ),
        };
        Ok(Self { request, response })
    }
}

impl fmt::Display for HeaderMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match (self.request, self.response) {
            (false, false) => "none",
            (true, false) => "request",
            (false, true) => "response",
            (true, true) => "both",
        })
    }
}

/// Verifies one exact field per template entry, or its absence in the control case.
pub fn validate_headers(
    headers: &HeaderMap,
    template: &[(HeaderName, HeaderValue)],
    enabled: bool,
) -> Result<()> {
    for (name, expected) in template {
        let mut values = headers.get_all(name).iter();
        if enabled {
            if values.next() != Some(expected) || values.next().is_some() {
                bail!("expected exactly one matching {name} field");
            }
        } else if values.next().is_some() {
            bail!("unexpected {name} field in the header-free control");
        }
    }
    Ok(())
}
