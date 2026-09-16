//! Tokio-based I/O implementation.
//!
//! Integrates ngtcp2/nghttp3 with Tokio and provides async HTTP/3 client/server
//! wrappers.

mod client;
mod server;

pub use client::Client;
pub use server::Server;

use std::net::SocketAddr;
use std::time::Instant;

use tokio::net::UdpSocket;

/// UDP socket wrapper.
pub(crate) struct Socket {
    inner: UdpSocket,
    local_addr: SocketAddr,
}

impl Socket {
    /// Binds a new socket.
    pub async fn bind(addr: SocketAddr) -> std::io::Result<Self> {
        let inner = UdpSocket::bind(addr).await?;
        let local_addr = inner.local_addr()?;
        Ok(Self { inner, local_addr })
    }

    /// Returns the local address.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Sends data.
    #[allow(dead_code)]
    pub async fn send_to(&self, buf: &[u8], target: SocketAddr) -> std::io::Result<usize> {
        self.inner.send_to(buf, target).await
    }

    /// Receives data.
    pub async fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        self.inner.recv_from(buf).await
    }
}

/// Returns a timestamp in nanoseconds.
#[allow(dead_code)]
pub(crate) fn timestamp() -> u64 {
    static START: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    let start = START.get_or_init(Instant::now);
    start.elapsed().as_nanos() as u64
}
