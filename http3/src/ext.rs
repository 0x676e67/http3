//! Extensions for the HTTP/3 protocol.

use std::str::FromStr;

use http::HeaderValue;

/// Describes the `:protocol` pseudo-header for extended connect
///
/// See: <https://www.rfc-editor.org/rfc/rfc8441#section-4>
#[derive(Copy, PartialEq, Debug, Clone)]
pub struct Protocol(ProtocolInner);

impl Protocol {
    /// WebTransport protocol
    pub const WEB_TRANSPORT: Protocol = Protocol(ProtocolInner::WebTransport);
    /// RFC 9298 protocol
    pub const CONNECT_UDP: Protocol = Protocol(ProtocolInner::ConnectUdp);
    /// RFC 9484 protocol
    pub const CONNECT_IP: Protocol = Protocol(ProtocolInner::ConnectIp);
    /// RFC 9220 (WebSocket) protocol
    pub const WEBSOCKET: Protocol = Protocol(ProtocolInner::WebSocket);

    /// Return a &str representation of the `:protocol` pseudo-header value
    #[inline]
    pub fn as_str(&self) -> &str {
        match self.0 {
            ProtocolInner::WebTransport => "webtransport",
            ProtocolInner::ConnectUdp => "connect-udp",
            ProtocolInner::ConnectIp => "connect-ip",
            ProtocolInner::WebSocket => "websocket",
        }
    }
}

#[derive(Copy, PartialEq, Debug, Clone)]
enum ProtocolInner {
    WebTransport,
    ConnectUdp,
    ConnectIp,
    WebSocket,
}

/// Error when parsing the protocol
pub struct InvalidProtocol;

impl FromStr for Protocol {
    type Err = InvalidProtocol;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "webtransport" => Ok(Self(ProtocolInner::WebTransport)),
            "connect-udp" => Ok(Self(ProtocolInner::ConnectUdp)),
            "connect-ip" => Ok(Self(ProtocolInner::ConnectIp)),
            "websocket" => Ok(Self(ProtocolInner::WebSocket)),
            _ => Err(InvalidProtocol),
        }
    }
}

/// Priority Field Value of a request's PRIORITY_UPDATE frame, set as a request extension.
///
/// The value is written verbatim on the control stream just before the request's HEADERS,
/// but QUIC does not order the two streams. A busy control stream queues the frame for the
/// connection driver, so it may follow the HEADERS, or drops it once the bounded queue is
/// full. The `priority` header stays with the caller. A server MAY close the connection if
/// the value is not a Structured Fields Dictionary.
/// See [RFC 9218, Section 7](https://www.rfc-editor.org/rfc/rfc9218.html#section-7).
///
/// ```
/// use http::{HeaderValue, Request};
/// use http3::ext::PriorityUpdate;
///
/// // Chrome sends the value as header and frame; Firefox sends only the header.
/// let priority = HeaderValue::from_static("u=0, i");
/// let request = Request::get("https://www.example.com/")
///     .header("priority", priority.clone())
///     .extension(PriorityUpdate::new(priority))
///     .body(())?;
/// # Ok::<_, http::Error>(())
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PriorityUpdate(HeaderValue);

// ===== impl PriorityUpdate =====

impl PriorityUpdate {
    /// Wraps a Priority Field Value such as `u=0, i`.
    pub const fn new(value: HeaderValue) -> Self {
        Self(value)
    }

    /// Returns the value as written to the frame.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}
