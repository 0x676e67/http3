//! HTTP/3 client builder

use std::{
    marker::PhantomData,
    sync::{atomic::AtomicUsize, Arc},
};

use bytes::{Buf, Bytes};

use crate::{
    config::Config,
    connection::ConnectionInner,
    error::ConnectionError,
    proto::frame::SettingId,
    quic::{self},
    shared_state::SharedState,
};

use super::connection::{Connection, SendRequest};

/// Start building a new HTTP/3 client
pub fn builder() -> Builder {
    Builder::new()
}

/// Create a new HTTP/3 client with default settings
pub async fn new<C, O>(
    conn: C,
) -> Result<(Connection<C, Bytes>, SendRequest<O, Bytes>), ConnectionError>
where
    C: quic::Connection<Bytes, OpenStreams = O>,
    O: quic::OpenStreams<Bytes>,
{
    //= https://www.rfc-editor.org/rfc/rfc9114#section-3.3
    //= type=implication
    //# Clients SHOULD NOT open more than one HTTP/3 connection to a given IP
    //# address and UDP port, where the IP address and port might be derived
    //# from a URI, a selected alternative service ([ALTSVC]), a configured
    //# proxy, or name resolution of any of these.
    Builder::new().build(conn).await
}

/// HTTP/3 client builder
///
/// Set the configuration for a new client.
///
/// # Examples
/// ```rust
/// # use http3_rs::quic;
/// # async fn doc<C, O, B>(quic: C)
/// # where
/// #   C: quic::Connection<B, OpenStreams = O>,
/// #   O: quic::OpenStreams<B>,
/// #   B: bytes::Buf,
/// # {
/// let http3_conn = http3_rs::client::builder()
///     .max_field_section_size(8192)
///     .build(quic)
///     .await
///     .expect("Failed to build connection");
/// # }
/// ```
pub struct Builder {
    config: Config,
}

impl Builder {
    pub(super) fn new() -> Self {
        Builder {
            config: Default::default(),
        }
    }

    // Not public API, just used in unit tests
    #[doc(hidden)]
    #[cfg(test)]
    pub fn send_settings(&mut self, value: bool) -> &mut Self {
        self.config.send_settings = value;
        self
    }

    /// Set the maximum header size this client is willing to accept
    ///
    /// See [header size constraints] section of the specification for details.
    ///
    /// [header size constraints]: https://www.rfc-editor.org/rfc/rfc9114.html#name-header-size-constraints
    pub fn max_field_section_size(&mut self, value: u64) -> &mut Self {
        self.config.settings.max_field_section_size = value;
        self
    }

    /// Just like in HTTP/2, HTTP/3 also uses the concept of "grease"
    /// to prevent potential interoperability issues in the future.
    /// In HTTP/3, the concept of grease is used to ensure that the protocol can evolve
    /// and accommodate future changes without breaking existing implementations.
    pub fn send_grease(&mut self, enabled: bool) -> &mut Self {
        self.config.send_grease = enabled;
        self
    }

    /// Indicates that the client supports HTTP/3 datagrams
    ///
    /// See: <https://www.rfc-editor.org/rfc/rfc9297#section-2.1.1>
    pub fn enable_datagram(&mut self, enabled: bool) -> &mut Self {
        self.config.settings.enable_datagram = enabled;
        self
    }

    /// Enables the extended CONNECT protocol required for various HTTP/3 extensions.
    pub fn enable_extended_connect(&mut self, value: bool) -> &mut Self {
        self.config.settings.enable_extended_connect = value;
        self
    }

    /// Set the QPACK dynamic table capacity the encoder is permitted to use, in bytes.
    ///
    /// Sent as `SETTINGS_QPACK_MAX_TABLE_CAPACITY` (0x1). A value of `0` (default)
    /// means the encoder must not use the dynamic table.
    pub fn qpack_max_table_capacity(&mut self, value: u64) -> &mut Self {
        self.config.settings.qpack_max_table_capacity = value;
        self
    }

    /// Set the maximum number of blocked streams the QPACK decoder is willing to tolerate.
    ///
    /// Sent as `SETTINGS_QPACK_BLOCKED_STREAMS` (0x7). A value of `0` (default)
    /// means the decoder does not support blocking.
    pub fn qpack_blocked_streams(&mut self, value: u64) -> &mut Self {
        self.config.settings.qpack_blocked_streams = value;
        self
    }

    /// Set the exact order of settings in the SETTINGS frame.
    ///
    /// Each `SettingId` in the list will be encoded in that order. Values are
    /// resolved from known config settings (e.g. `max_field_section_size`) or
    /// from entries added via [`extra_setting`](Self::extra_setting).
    ///
    /// When `send_grease` is enabled (the default), a GREASE entry is always
    /// appended after all ordered settings — do not include it in this list.
    pub fn settings_order(&mut self, order: Vec<SettingId>) -> &mut Self {
        self.config.settings_order = Some(order);
        self
    }

    /// Add an arbitrary (id, value) setting entry.
    ///
    /// Used for browser-specific unknown settings, controlled GREASE, or any
    /// setting ID not covered by the typed builder methods.
    pub fn extra_setting(&mut self, id: SettingId, value: u64) -> &mut Self {
        self.config.extra_settings.push((id, value));
        self
    }

    /// Create a new HTTP/3 client from a `quic` connection
    pub async fn build<C, O, B>(
        &mut self,
        quic: C,
    ) -> Result<(Connection<C, B>, SendRequest<O, B>), ConnectionError>
    where
        C: quic::Connection<B, OpenStreams = O>,
        O: quic::OpenStreams<B>,
        B: Buf,
    {
        let open = quic.opener();
        let shared = SharedState::default();

        let conn_state = Arc::new(shared);
        let max_field_section_size = self.config.settings.max_field_section_size;
        let send_grease_frame = self.config.send_grease;

        let inner = ConnectionInner::new(quic, conn_state.clone(), self.config.clone()).await?;
        let send_request = SendRequest {
            open,
            conn_state,
            max_field_section_size,
            sender_count: Arc::new(AtomicUsize::new(1)),
            send_grease_frame,
            _buf: PhantomData,
        };

        Ok((
            Connection {
                inner,
                sent_closing: None,
                recv_closing: None,
            },
            send_request,
        ))
    }
}
