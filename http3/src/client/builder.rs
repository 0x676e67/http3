//! HTTP/3 client builder

use std::marker::PhantomData;

use bytes::{Buf, Bytes, BytesMut};

use super::connection::{Connection, SendRequest};
#[cfg(feature = "unstable")]
use crate::proto::frame::ExperimentalSettings;
use crate::{
    PseudoOrder,
    config::Config,
    connection::ConnectionInner,
    error::ConnectionError,
    proto::frame::SettingsOrder,
    quic::{self},
};

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
/// # use http3::quic;
/// # async fn doc<C, O, B>(quic: C)
/// # where
/// #   C: quic::Connection<B, OpenStreams = O>,
/// #   O: quic::OpenStreams<B>,
/// #   B: bytes::Buf,
/// # {
/// let http3_conn = http3::client::builder()
///     .max_field_section_size(8192)
///     .build(quic)
///     .await
///     .expect("Failed to build connection");
/// # }
/// ```
pub struct Builder {
    config: Config,
    pseudo_order: Option<PseudoOrder>,
}

impl Builder {
    pub(super) fn new() -> Self {
        Builder {
            config: Default::default(),
            pseudo_order: None,
        }
    }

    // Not public API, just used in unit tests
    #[doc(hidden)]
    #[cfg(test)]
    pub fn send_settings(&mut self, value: bool) -> &mut Self {
        self.config.send_settings = value;
        self
    }

    /// Sets the largest uncompressed field section this client will accept.
    ///
    /// The value is advertised to the server as
    /// `SETTINGS_MAX_FIELD_SECTION_SIZE`. Each field contributes its name and
    /// value lengths plus 32 bytes. By default, the client advertises the
    /// largest value the setting can encode.
    ///
    /// See [RFC 9114 Section 4.2.2](https://www.rfc-editor.org/rfc/rfc9114.html#section-4.2.2).
    pub fn max_field_section_size(&mut self, value: u64) -> &mut Self {
        self.config.settings.max_field_section_size = value;
        self
    }

    /// Limits compressed QPACK input buffered before a field section is decoded.
    ///
    /// This is a local memory limit, not an HTTP/3 setting. It applies to an
    /// encoded HEADERS payload and to one encoded string on the peer's QPACK
    /// encoder stream. The default is 16 MiB.
    ///
    /// See [RFC 9204, Section 7.3](https://www.rfc-editor.org/rfc/rfc9204.html#section-7.3)
    /// and [Section 7.4](https://www.rfc-editor.org/rfc/rfc9204.html#section-7.4).
    pub fn max_qpack_decode_buffer_size(&mut self, value: usize) -> &mut Self {
        self.config.qpack_decode_buffer_size = value;
        self
    }

    /// Set the maximum dynamic-table capacity used to encode requests.
    ///
    /// The default is `0`, which keeps request encoding stateless. A non-zero
    /// value enables dynamic request compression after the peer advertises a
    /// non-zero `SETTINGS_QPACK_MAX_TABLE_CAPACITY`; the smaller value is used.
    /// This does not change the decoder capacity advertised by
    /// [`qpack_max_table_capacity`](Self::qpack_max_table_capacity).
    ///
    /// See [RFC 9204, Section 3.2.3](https://www.rfc-editor.org/rfc/rfc9204.html#section-3.2.3)
    /// and [Section 5](https://www.rfc-editor.org/rfc/rfc9204.html#section-5).
    pub fn qpack_encoder_table_capacity(&mut self, value: usize) -> &mut Self {
        self.config.qpack_encoder_table_capacity = value;
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
    ///
    /// HTTP/3 encodes this setting as a QUIC variable-length integer, so values
    /// can range up to `2^62 - 1`. The value must also fit the target's address
    /// space; connection setup rejects a capacity the decoder cannot represent.
    /// Set no more table memory than the decoder can hold for this connection.
    ///
    /// See [RFC 9204, Section 3.2.3](https://www.rfc-editor.org/rfc/rfc9204.html#section-3.2.3),
    /// [Section 7.4](https://www.rfc-editor.org/rfc/rfc9204.html#section-7.4),
    /// and [RFC 9114, Section 7.2.4](https://www.rfc-editor.org/rfc/rfc9114.html#section-7.2.4).
    pub fn qpack_max_table_capacity<T: Into<Option<u64>>>(&mut self, value: T) -> &mut Self {
        self.config.settings.qpack_max_table_capacity = value.into();
        self
    }

    /// Set the maximum number of blocked streams the QPACK decoder is willing to tolerate.
    ///
    /// Sent as `SETTINGS_QPACK_BLOCKED_STREAMS` (0x7). When this is not called,
    /// the setting is omitted and the protocol default of `0` applies. Passing `0`
    /// explicitly sends the setting with value `0`.
    ///
    /// HTTP/3 encodes this setting as a QUIC variable-length integer, and QPACK
    /// sets no smaller limit. Each blocked stream needs decoder bookkeeping, so
    /// choose a value that fits the connection's memory budget.
    ///
    /// See [RFC 9204, Section 2.1.2](https://www.rfc-editor.org/rfc/rfc9204.html#section-2.1.2),
    /// [Section 7.3](https://www.rfc-editor.org/rfc/rfc9204.html#section-7.3), and
    /// [RFC 9114, Section 7.2.4](https://www.rfc-editor.org/rfc/rfc9114.html#section-7.2.4).
    pub fn qpack_blocked_streams<T: Into<Option<u64>>>(&mut self, value: T) -> &mut Self {
        self.config.settings.qpack_blocked_streams = value.into();
        self
    }

    /// Sets the exact order of the SETTINGS frame sent by this client.
    ///
    /// Only identifiers in `order` are sent, in that order. Values come from the
    /// typed builder methods (e.g. [`max_field_section_size`](Self::max_field_section_size))
    /// or from experimental settings (`unstable` feature); identifiers without a
    /// value are skipped. Without an order, known settings use the default order
    /// and experimental settings follow them.
    ///
    /// When `send_grease` is enabled (the default), a GREASE entry is always
    /// appended after the ordered settings — do not include it in `order`.
    ///
    /// ```
    /// use http3::{SettingId, SettingsOrder, client};
    ///
    /// let mut builder = client::builder();
    /// builder.settings_order(
    ///     SettingsOrder::builder()
    ///         .extend([
    ///             SettingId::QPACK_MAX_TABLE_CAPACITY,
    ///             SettingId::MAX_HEADER_LIST_SIZE,
    ///             SettingId::QPACK_MAX_BLOCKED_STREAMS,
    ///             SettingId::H3_DATAGRAM,
    ///         ])
    ///         .build(),
    /// );
    /// ```
    pub fn settings_order(&mut self, order: SettingsOrder) -> &mut Self {
        self.config.settings_order = Some(order);
        self
    }

    /// Sets extension settings not covered by the typed builder methods.
    ///
    /// Used for browser-specific settings or controlled GREASE. Replaces any
    /// experimental settings set before. Identifiers and values must fit a QUIC
    /// variable-length integer, or connection setup fails.
    ///
    /// With a [`settings_order`](Self::settings_order), an experimental setting
    /// is sent only when its identifier is listed:
    ///
    /// ```
    /// use http3::{ExperimentalSettings, SettingId, SettingsOrder, client};
    ///
    /// let datagram = SettingId::H3_SETTING_ENABLE_DATAGRAM_CHROME_SPECIFIC;
    /// let mut builder = client::builder();
    /// builder
    ///     .experimental_settings(ExperimentalSettings::builder().push(datagram, 1).build())
    ///     .settings_order(
    ///         SettingsOrder::builder()
    ///             .extend([SettingId::MAX_HEADER_LIST_SIZE, datagram])
    ///             .build(),
    ///     );
    /// ```
    //
    // - Experimental feature – subject to removal without notice
    #[cfg(feature = "unstable")]
    pub fn experimental_settings(
        &mut self,
        experimental_settings: ExperimentalSettings,
    ) -> &mut Self {
        self.config.experimental_settings = experimental_settings;
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
            decoder: inner.dynamic_qpack_decoder(),
            encoder: inner.dynamic_qpack_encoder(),
            max_field_section_size: self.config.settings.max_field_section_size,
            max_qpack_decode_buffer_size: self.config.qpack_decode_buffer_size,
            send_grease_frame: self.config.send_grease,
            qpack_encode_buffer: BytesMut::new(),
            pseudo_order: self.pseudo_order.clone(),
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

    /// Sets the pseudo-header order for every request on connections built by this builder.
    ///
    /// Without this setting, requests use [`PseudoOrder::default`]: `:method`,
    /// `:scheme`, `:authority`, `:path`, then `:protocol`. Fields absent from a
    /// request are skipped. All pseudo-headers precede regular fields, as
    /// required by [RFC 9114 Section 4.3].
    ///
    /// This is a local encoding preference, not an HTTP/3 SETTINGS parameter.
    /// A `PseudoOrder` in request extensions is ignored; configure it here instead.
    /// Changing this builder does not affect connections already built from it.
    ///
    /// [RFC 9114 Section 4.3]: https://www.rfc-editor.org/rfc/rfc9114.html#section-4.3
    ///
    /// ```
    /// use http3::{PseudoId, PseudoOrder, client};
    ///
    /// let mut builder = client::builder();
    /// builder.pseudo_order(
    ///     PseudoOrder::builder()
    ///         .extend([PseudoId::Method, PseudoId::Authority, PseudoId::Scheme, PseudoId::Path])
    ///         .build(),
    /// );
    /// ```
    pub fn pseudo_order(&mut self, order: PseudoOrder) -> &mut Self {
        self.pseudo_order = Some(order);
        self
    }
}
