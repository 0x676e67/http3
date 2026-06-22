//! HTTP/3 client builder

use std::{
    marker::PhantomData,
    sync::{Arc, atomic::AtomicUsize},
};

use bytes::{Buf, Bytes};

use crate::{
    config::Config,
    connection::ConnectionInner,
    error::ConnectionError,
    proto::frame::SettingId,
    quic::{self},
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
    /// Sent as `SETTINGS_QPACK_MAX_TABLE_CAPACITY` (0x1). When this is not called,
    /// the setting is omitted and the protocol default of `0` applies. Passing `0`
    /// explicitly sends the setting with value `0`.
    pub fn qpack_max_table_capacity<T: Into<Option<u64>>>(&mut self, value: T) -> &mut Self {
        self.config.settings.qpack_max_table_capacity = value.into();
        self
    }

    /// Set the maximum number of blocked streams the QPACK decoder is willing to tolerate.
    ///
    /// Sent as `SETTINGS_QPACK_BLOCKED_STREAMS` (0x7). When this is not called,
    /// the setting is omitted and the protocol default of `0` applies. Passing `0`
    /// explicitly sends the setting with value `0`.
    pub fn qpack_blocked_streams<T: Into<Option<u64>>>(&mut self, value: T) -> &mut Self {
        self.config.settings.qpack_blocked_streams = value.into();
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
        let inner = ConnectionInner::new(quic, self.config.clone()).await?;
        let send_request = SendRequest {
            open,
            conn_state: inner.shared.clone(),
            decoder: inner.qpack_decoder(),
            max_field_section_size: self.config.settings.max_field_section_size,
            sender_count: Arc::new(AtomicUsize::new(1)),
            send_grease_frame: self.config.send_grease,
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
