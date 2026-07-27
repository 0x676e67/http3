use std::net::SocketAddr;

// ============================================================================
// QUIC version constants
// ============================================================================
//
// ngtcp2.h defines NGTCP2_PROTO_VER_V1/V2 as macros containing casts:
//   #define NGTCP2_PROTO_VER_V1 ((uint32_t)0x00000001u)
//   #define NGTCP2_PROTO_VER_V2 ((uint32_t)0x6b3343cfu)
//
// bindgen can turn simple literal macros (`#define FOO 42`) into Rust
// constants, but it does not emit constants for macros containing cast
// expressions such as `((uint32_t)...)`. Define the equivalent values here.

/// QUIC v1 (RFC 9000)
pub const NGTCP2_PROTO_VER_V1: u32 = 0x00000001;
/// QUIC v2 (RFC 9369)
pub const NGTCP2_PROTO_VER_V2: u32 = 0x6b3343cf;

/// QUIC version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u32)]
pub enum QuicVersion {
    /// QUIC v1 (RFC 9000)
    #[default]
    V1 = NGTCP2_PROTO_VER_V1,
    /// QUIC v2 (RFC 9369)
    V2 = NGTCP2_PROTO_VER_V2,
}

// ============================================================================
// Connection IDs
// ============================================================================
//
// `ngtcp2_cid` is a C struct with a fixed-size byte array and a length field.
// A `Vec<u8>` gives Rust callers a natural variable-length representation,
// derive support for Clone/PartialEq/Eq/Hash, and a memory-safe interface.

/// QUIC connection ID.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ConnectionId {
    data: Vec<u8>,
}

impl ConnectionId {
    /// Creates a new connection ID.
    pub fn new(data: &[u8]) -> Option<Self> {
        let min = ngtcp2_sys::NGTCP2_MIN_CIDLEN as usize;
        let max = ngtcp2_sys::NGTCP2_MAX_CIDLEN as usize;
        if data.len() < min || data.len() > max {
            return None;
        }
        Some(Self {
            data: data.to_vec(),
        })
    }

    /// Generates a random connection ID.
    pub fn random(len: usize) -> Option<Self> {
        let min = ngtcp2_sys::NGTCP2_MIN_CIDLEN as usize;
        let max = ngtcp2_sys::NGTCP2_MAX_CIDLEN as usize;
        if len < min || len > max {
            return None;
        }
        let mut data = vec![0u8; len];
        aws_lc_rs::rand::fill(&mut data).ok()?;
        Some(Self { data })
    }

    /// Returns the raw bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Returns the length.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns whether the ID is empty.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl std::fmt::Debug for ConnectionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ConnectionId(")?;
        for b in &self.data {
            write!(f, "{:02x}", b)?;
        }
        write!(f, ")")
    }
}

impl std::fmt::Display for ConnectionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for b in &self.data {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}

// ============================================================================
// Path information
// ============================================================================
//
// `ngtcp2_path` points to `ngtcp2_addr`, which in turn stores raw `sockaddr*`
// pointers. Expose a type-safe Rust interface through `SocketAddr`.

/// Local and remote path information.
#[derive(Debug, Clone)]
pub struct PathInfo {
    /// Local address.
    pub local: SocketAddr,
    /// Remote address.
    pub remote: SocketAddr,
}

// ============================================================================
// Packet information
// ============================================================================
//
// `ngtcp2_pkt_info` is a simple C struct containing only the ECN field. Define
// a Rust struct at the FFI boundary so callers get idiomatic traits such as
// `Default`.

/// QUIC packet metadata.
#[derive(Debug, Clone, Copy, Default)]
pub struct PacketInfo {
    /// ECN marking.
    pub ecn: u8,
}

// ============================================================================
// Stream-related types
// ============================================================================
//
// ngtcp2/nghttp3 use `int64_t` for stream IDs. Type aliases keep the wrapper
// API easier to read.
//
// ngtcp2 derives stream type and initiator from stream ID bits:
// - bit 0: 0 = client initiated, 1 = server initiated
// - bit 1: 0 = bidirectional, 1 = unidirectional
// Rust enums keep that interpretation type-safe.

/// QUIC stream ID.
pub type StreamId = i64;

/// QUIC stream type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamType {
    /// Bidirectional stream.
    Bidirectional,
    /// Unidirectional stream.
    Unidirectional,
}

impl StreamType {
    /// Derives the type from a stream ID.
    pub fn from_stream_id(stream_id: StreamId) -> Self {
        if stream_id & 0x2 == 0 {
            Self::Bidirectional
        } else {
            Self::Unidirectional
        }
    }
}

/// Stream initiator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamDirection {
    /// Client initiated.
    ClientInitiated,
    /// Server initiated.
    ServerInitiated,
}

impl StreamDirection {
    /// Derives the initiator from a stream ID.
    pub fn from_stream_id(stream_id: StreamId) -> Self {
        if stream_id & 0x1 == 0 {
            Self::ClientInitiated
        } else {
            Self::ServerInitiated
        }
    }
}

// ============================================================================
// HTTP/3 headers
// ============================================================================
//
// `nghttp3_nv` stores raw `uint8_t*` pointers and lengths for names and values.
// Owning `Vec<u8>` fields make the Rust wrapper memory-safe, explicit about
// ownership, and naturally Clone/Debug. Helper constructors cover the common
// pseudo-headers such as `:method` and `:path`.

/// HTTP/3 header field.
#[derive(Debug, Clone)]
pub struct Header {
    /// Header name.
    pub name: Vec<u8>,
    /// Header value.
    pub value: Vec<u8>,
}

impl Header {
    /// Creates a new header field.
    pub fn new(name: impl Into<Vec<u8>>, value: impl Into<Vec<u8>>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
        }
    }

    /// `:method` pseudo-header.
    pub fn method(method: &str) -> Self {
        Self::new(b":method".to_vec(), method.as_bytes().to_vec())
    }

    /// `:scheme` pseudo-header.
    pub fn scheme(scheme: &str) -> Self {
        Self::new(b":scheme".to_vec(), scheme.as_bytes().to_vec())
    }

    /// `:authority` pseudo-header.
    pub fn authority(authority: &str) -> Self {
        Self::new(b":authority".to_vec(), authority.as_bytes().to_vec())
    }

    /// `:path` pseudo-header.
    pub fn path(path: &str) -> Self {
        Self::new(b":path".to_vec(), path.as_bytes().to_vec())
    }

    /// `:status` pseudo-header.
    pub fn status(status: u16) -> Self {
        Self::new(b":status".to_vec(), status.to_string().into_bytes())
    }

    /// Returns the header name as UTF-8.
    pub fn name_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.name).ok()
    }

    /// Returns the header value as UTF-8.
    pub fn value_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.value).ok()
    }
}

// ============================================================================
// HTTP/3 events
// ============================================================================
//
// nghttp3 exposes a callback-based API. This wrapper accumulates callbacks as
// enum events and lets callers poll them later, which fits async code,
// Sans-I/O style integration, and event-driven control flow.

/// HTTP/3 event emitted by the wrapper.
#[derive(Debug)]
pub enum Http3Event {
    /// Header block started.
    HeadersBegin { stream_id: StreamId },
    /// Header field received.
    Header { stream_id: StreamId, header: Header },
    /// Header block completed.
    HeadersEnd { stream_id: StreamId, fin: bool },
    /// DATA received.
    Data { stream_id: StreamId, data: Vec<u8> },
    /// Stream ended.
    StreamEnd { stream_id: StreamId },
    /// Stream closed.
    StreamClose {
        stream_id: StreamId,
        error_code: u64,
    },
    /// Stream reset.
    Reset {
        stream_id: StreamId,
        error_code: u64,
    },
    /// Trailer block started.
    TrailersBegin { stream_id: StreamId },
    /// Trailer field received.
    Trailer { stream_id: StreamId, header: Header },
    /// Trailer block completed.
    TrailersEnd { stream_id: StreamId },
}
