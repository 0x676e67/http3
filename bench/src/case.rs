//! Benchmark topology, workload, HTTP/3 library selection, and workspace configuration.

use std::{fmt, path::PathBuf, time::Duration};

use anyhow::{Result, bail};
use bytesize::ByteSize;

pub const SERVER_ADDR: &str = "127.0.0.1:4433";
pub const SERVER_WORKERS: usize = 8;
pub(crate) const SERVER_NAME: &str = "localhost";
pub(crate) const ALPN_H3: &[u8] = b"h3";

pub fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..")
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Topology {
    pub connections: usize,
    pub sockets: usize,
}

impl Topology {
    pub const ALL: [Self; 2] = [
        Self {
            connections: 1,
            sockets: 1,
        },
        Self {
            connections: 4,
            sockets: 1,
        },
    ];

    pub fn new(connections: usize, sockets: usize) -> Result<Self> {
        if connections == 0 {
            bail!("topology must contain at least one connection");
        }
        if sockets == 0 {
            bail!("topology must contain at least one UDP socket");
        }
        if sockets > connections {
            bail!("topology cannot assign {connections} connections across {sockets} UDP sockets");
        }
        Ok(Self {
            connections,
            sockets,
        })
    }

    pub(crate) const fn endpoint_for_connection(self, connection: usize) -> usize {
        connection % self.sockets
    }
}

impl fmt::Display for Topology {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}-connection{}-{}-socket{}",
            self.connections,
            if self.connections == 1 { "" } else { "s" },
            self.sockets,
            if self.sockets == 1 { "" } else { "s" }
        )
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Workload {
    pub body_bytes: usize,
}

impl Workload {
    pub const DEFAULT: [Self; 9] = [
        Self { body_bytes: 0 },
        Self { body_bytes: 1024 },
        Self {
            body_bytes: 10 * 1024,
        },
        Self {
            body_bytes: 64 * 1024,
        },
        Self {
            body_bytes: 128 * 1024,
        },
        Self {
            body_bytes: 1024 * 1024,
        },
        Self {
            body_bytes: 2 * 1024 * 1024,
        },
        Self {
            body_bytes: 4 * 1024 * 1024,
        },
        Self {
            body_bytes: 100 * 1024 * 1024,
        },
    ];

    pub fn new(body_bytes: usize) -> Result<Self> {
        if body_bytes > 100 * 1024 * 1024 {
            bail!("response body cannot exceed 100 MiB");
        }
        Ok(Self { body_bytes })
    }

    pub const fn measurement_time(self) -> Duration {
        if self.body_bytes < 100 * 1024 * 1024 {
            Duration::from_secs(30)
        } else {
            Duration::from_secs(60)
        }
    }

    pub fn for_topology(self, topology: Topology) -> Result<Case> {
        let topology = Topology::new(topology.connections, topology.sockets)?;
        let connections = topology.connections;
        let total_requests = (640 * 1024 * 1024_usize)
            .checked_div(self.body_bytes)
            .unwrap_or(200_000)
            .clamp(32, 200_000);
        let total_in_flight = (64 * 1024 * 1024_usize)
            .checked_div(self.body_bytes)
            .unwrap_or(100)
            .clamp(4, 100);
        if !total_requests.is_multiple_of(connections)
            || !total_in_flight.is_multiple_of(connections)
        {
            bail!(
                "{self} does not divide {total_requests} requests and {total_in_flight} in-flight \
                 requests evenly across {connections} connections"
            );
        }

        Ok(Case {
            topology,
            workload: self,
            requests_per_connection: total_requests / connections,
            in_flight_per_connection: total_in_flight / connections,
        })
    }
}

impl fmt::Display for Workload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        ByteSize::b(self.body_bytes as u64)
            .display()
            .iec()
            .fmt(formatter)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Case {
    pub topology: Topology,
    pub workload: Workload,
    pub requests_per_connection: usize,
    pub in_flight_per_connection: usize,
}

impl Case {
    pub fn expected_requests(self) -> Result<usize> {
        self.topology
            .connections
            .checked_mul(self.requests_per_connection)
            .ok_or_else(|| anyhow::anyhow!("total request count overflowed usize"))
    }

    pub fn expected_bytes(self) -> Result<usize> {
        self.expected_requests()?
            .checked_mul(self.workload.body_bytes)
            .ok_or_else(|| anyhow::anyhow!("total response byte count overflowed usize"))
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
