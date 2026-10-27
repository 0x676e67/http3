use std::convert::TryFrom;

use crate::proto::{frame, varint::VarInt};

pub(crate) const DEFAULT_QPACK_DECODE_BUFFER_SIZE: usize = 16 * 1024 * 1024;

/// Configures the HTTP/3 connection
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Config {
    /// Just like in HTTP/2, HTTP/3 also uses the concept of "grease"
    /// to prevent potential interoperability issues in the future.
    /// In HTTP/3, the concept of grease is used to ensure that the protocol can evolve
    /// and accommodate future changes without breaking existing implementations.
    pub(crate) send_grease: bool,

    #[cfg(test)]
    pub(crate) send_settings: bool,

    /// Exact order of the local SETTINGS frame. When `None`, known settings use
    /// `SettingId::DEFAULT_IDS` and experimental settings follow them.
    pub(crate) settings_order: Option<frame::SettingsOrder>,

    /// Extension settings without a typed field, such as browser-specific
    /// settings or controlled GREASE.
    #[cfg(feature = "unstable")]
    pub(crate) experimental_settings: frame::ExperimentalSettings,

    /// Maximum compressed QPACK input retained while decoding one field
    /// section or encoder-stream string.
    pub(crate) qpack_decode_buffer_size: usize,

    /// Maximum dynamic-table capacity this endpoint's QPACK encoder may use.
    ///
    /// This is a local memory and compression policy. The effective capacity is
    /// also limited by the peer's `SETTINGS_QPACK_MAX_TABLE_CAPACITY` value.
    pub(crate) qpack_encoder_table_capacity: usize,

    /// HTTP/3 Settings
    pub settings: Settings,
}

/// HTTP/3 Settings
#[derive(Debug, Clone, Copy)]
pub struct Settings {
    /// Largest uncompressed field section this endpoint is willing to accept.
    ///
    /// Each field contributes its name and value lengths plus 32 bytes. The
    /// value is advertised as `SETTINGS_MAX_FIELD_SECTION_SIZE`. Omitting the
    /// setting means unlimited; this implementation advertises the largest
    /// QUIC variable-length integer by default.
    ///
    /// See [RFC 9114 Section 4.2.2](https://www.rfc-editor.org/rfc/rfc9114.html#section-4.2.2)
    /// and [Section 7.2.4.1](https://www.rfc-editor.org/rfc/rfc9114.html#section-7.2.4.1).
    pub(crate) max_field_section_size: u64,

    /// <https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http3/#section-3.1>
    /// Sets `SETTINGS_ENABLE_WEBTRANSPORT` if enabled
    pub(crate) enable_webtransport: bool,
    /// <https://www.rfc-editor.org/info/rfc8441> defines an extended CONNECT method in Section 4,
    /// enabled by the SETTINGS_ENABLE_CONNECT_PROTOCOL parameter.
    /// That parameter is only defined for HTTP/2.
    /// for extended CONNECT in HTTP/3; instead, the SETTINGS_ENABLE_WEBTRANSPORT setting implies
    /// that an endpoint supports extended CONNECT.
    pub(crate) enable_extended_connect: bool,
    /// Enable HTTP Datagrams, see <https://datatracker.ietf.org/doc/rfc9297/> for details
    pub(crate) enable_datagram: bool,
    /// The maximum number of concurrent streams that can be opened by the peer.
    pub(crate) max_webtransport_sessions: u64,

    /// QPACK dynamic table capacity the encoder is permitted to use, in bytes.
    /// Sent as SETTINGS_QPACK_MAX_TABLE_CAPACITY (0x1).
    /// When unset, the setting is omitted and the protocol default of 0 applies.
    ///
    /// See [RFC 9204 Section 5](https://www.rfc-editor.org/rfc/rfc9204.html#section-5).
    pub(crate) qpack_max_table_capacity: Option<u64>,

    /// Maximum number of blocked streams the decoder is willing to tolerate.
    /// Sent as SETTINGS_QPACK_BLOCKED_STREAMS (0x7).
    ///
    /// See [RFC 9204 Section 5](https://www.rfc-editor.org/rfc/rfc9204.html#section-5).
    /// When unset, the setting is omitted and the protocol default of 0 applies.
    pub(crate) qpack_blocked_streams: Option<u64>,
}

impl From<&frame::Settings> for Settings {
    fn from(settings: &frame::Settings) -> Self {
        let defaults: Self = Default::default();
        Self {
            max_field_section_size: settings
                .get(frame::SettingId::MAX_HEADER_LIST_SIZE)
                .unwrap_or(defaults.max_field_section_size),
            enable_webtransport: settings
                .get(frame::SettingId::ENABLE_WEBTRANSPORT)
                .map(|value| value != 0)
                .unwrap_or(defaults.enable_webtransport),
            max_webtransport_sessions: settings
                .get(frame::SettingId::WEBTRANSPORT_MAX_SESSIONS)
                .unwrap_or(defaults.max_webtransport_sessions),
            enable_datagram: settings
                .get(frame::SettingId::H3_DATAGRAM)
                .map(|value| value != 0)
                .unwrap_or(defaults.enable_datagram),
            enable_extended_connect: settings
                .get(frame::SettingId::ENABLE_CONNECT_PROTOCOL)
                .map(|value| value != 0)
                .unwrap_or(defaults.enable_extended_connect),
            qpack_max_table_capacity: settings.get(frame::SettingId::QPACK_MAX_TABLE_CAPACITY),
            qpack_blocked_streams: settings.get(frame::SettingId::QPACK_MAX_BLOCKED_STREAMS),
        }
    }
}

impl Config {
    /// Resolve the value for a given setting ID from known settings fields
    /// or experimental settings.
    fn resolve_setting_value(&self, id: &frame::SettingId) -> Option<u64> {
        match *id {
            frame::SettingId::MAX_HEADER_LIST_SIZE => Some(self.settings.max_field_section_size),
            frame::SettingId::ENABLE_CONNECT_PROTOCOL => {
                Some(self.settings.enable_extended_connect as u64)
            }
            frame::SettingId::ENABLE_WEBTRANSPORT => Some(self.settings.enable_webtransport as u64),
            frame::SettingId::H3_DATAGRAM => Some(self.settings.enable_datagram as u64),
            frame::SettingId::WEBTRANSPORT_MAX_SESSIONS => {
                Some(self.settings.max_webtransport_sessions)
            }
            frame::SettingId::QPACK_MAX_TABLE_CAPACITY => self.settings.qpack_max_table_capacity,
            frame::SettingId::QPACK_MAX_BLOCKED_STREAMS => self.settings.qpack_blocked_streams,
            #[cfg(feature = "unstable")]
            _ => self.experimental_settings.get(*id),
            #[cfg(not(feature = "unstable"))]
            _ => None,
        }
    }
}

impl TryFrom<Config> for frame::Settings {
    type Error = frame::SettingsError;
    fn try_from(value: Config) -> Result<Self, Self::Error> {
        let mut settings = frame::Settings::default();

        let ids = match &value.settings_order {
            Some(order) => order.into_iter(),
            None => frame::SettingId::DEFAULT_IDS.iter(),
        };
        for id in ids {
            if let Some(val) = value.resolve_setting_value(id) {
                settings.insert(*id, val)?;
            }
        }

        // Without an explicit order, experimental settings follow the known ones.
        #[cfg(feature = "unstable")]
        if value.settings_order.is_none() {
            for (id, val) in &value.experimental_settings {
                settings.insert(*id, *val)?;
            }
        }

        // GREASE settings are reserved by RFC 9114 Section 7.2.4.1.
        // https://www.rfc-editor.org/rfc/rfc9114.html#section-7.2.4.1
        //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.4.1
        //# Setting identifiers of the format 0x1f * N + 0x21 for non-negative
        //# integer values of N are reserved to exercise the requirement that
        //# unknown identifiers be ignored.  Such settings have no defined
        //# meaning.  Endpoints SHOULD include at least one such setting in their
        //# SETTINGS frame.

        //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.4.1
        //# Setting identifiers that were defined in [HTTP/2] where there is no
        //# corresponding HTTP/3 setting have also been reserved
        //# (Section 11.2.2).  These reserved settings MUST NOT be sent, and
        //# their receipt MUST be treated as a connection error of type
        //# H3_SETTINGS_ERROR.

        // GREASE is always appended last, matching Chromium's behavior.
        // The value is a random u32, matching Chromium's implementation:
        //   uint32_t result;
        //   QuicRandom::GetInstance()->RandBytes(&result, sizeof(result));
        //   settings.values[setting_id] = result;
        if value.send_grease {
            match settings.insert(frame::SettingId::grease(), fastrand::u32(..) as u64) {
                Ok(_) => (),
                Err(_err) => {
                    #[cfg(feature = "tracing")]
                    tracing::warn!("Error when adding the grease Setting. Reason {}", _err);
                }
            }
        }

        Ok(settings)
    }
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            max_field_section_size: VarInt::MAX.0,
            enable_webtransport: false,
            enable_extended_connect: false,
            enable_datagram: false,
            max_webtransport_sessions: 0,
            qpack_max_table_capacity: None,
            qpack_blocked_streams: None,
        }
    }
}

impl Settings {
    /// <https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http3/#section-3.1>
    /// Sets `SETTINGS_ENABLE_WEBTRANSPORT` if enabled
    pub fn enable_webtransport(&self) -> bool {
        self.enable_webtransport
    }

    /// Enable HTTP Datagrams, see <https://datatracker.ietf.org/doc/rfc9297/> for details
    pub fn enable_datagram(&self) -> bool {
        self.enable_datagram
    }

    /// <https://www.rfc-editor.org/info/rfc8441> defines an extended CONNECT method in Section 4,
    /// enabled by the SETTINGS_ENABLE_CONNECT_PROTOCOL parameter.
    /// That parameter is only defined for HTTP/2.
    /// for extended CONNECT in HTTP/3; instead, the SETTINGS_ENABLE_WEBTRANSPORT setting implies
    /// that an endpoint supports extended CONNECT.
    pub fn enable_extended_connect(&self) -> bool {
        self.enable_extended_connect
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            send_grease: true,
            #[cfg(test)]
            send_settings: true,
            settings_order: None,
            #[cfg(feature = "unstable")]
            experimental_settings: Default::default(),
            qpack_decode_buffer_size: DEFAULT_QPACK_DECODE_BUFFER_SIZE,
            qpack_encoder_table_capacity: 0,
            settings: Default::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::frame::SettingId;

    fn settings(entries: &[(SettingId, u64)]) -> frame::Settings {
        let mut settings = frame::Settings::default();
        for &(id, value) in entries {
            settings.insert(id, value).unwrap();
        }
        settings
    }

    #[test]
    fn settings_frame_follows_configured_order() {
        let mut config = Config {
            send_grease: false,
            ..Config::default()
        };
        config.settings.qpack_max_table_capacity = Some(64);

        assert_eq!(
            frame::Settings::try_from(config.clone()).unwrap(),
            settings(&[
                (SettingId::MAX_HEADER_LIST_SIZE, VarInt::MAX.0),
                (SettingId::ENABLE_CONNECT_PROTOCOL, 0),
                (SettingId::ENABLE_WEBTRANSPORT, 0),
                (SettingId::H3_DATAGRAM, 0),
                (SettingId::WEBTRANSPORT_MAX_SESSIONS, 0),
                (SettingId::QPACK_MAX_TABLE_CAPACITY, 64),
            ])
        );

        // Only listed settings with a value are sent, each once.
        config.settings_order = Some(
            frame::SettingsOrder::builder()
                .extend([
                    SettingId::QPACK_MAX_TABLE_CAPACITY,
                    SettingId::QPACK_MAX_BLOCKED_STREAMS,
                    SettingId::MAX_HEADER_LIST_SIZE,
                    SettingId::QPACK_MAX_TABLE_CAPACITY,
                ])
                .build(),
        );
        assert_eq!(
            frame::Settings::try_from(config).unwrap(),
            settings(&[
                (SettingId::QPACK_MAX_TABLE_CAPACITY, 64),
                (SettingId::MAX_HEADER_LIST_SIZE, VarInt::MAX.0),
            ])
        );
    }

    #[cfg(feature = "unstable")]
    #[test]
    fn experimental_settings_skip_known_reserved_and_duplicate_ids() {
        let chrome_datagram = SettingId::H3_SETTING_ENABLE_DATAGRAM_CHROME_SPECIFIC;
        let mut config = Config {
            send_grease: false,
            experimental_settings: frame::ExperimentalSettings::builder()
                .push(chrome_datagram, 1)
                .push(chrome_datagram, 2)
                .push(SettingId::QPACK_MAX_BLOCKED_STREAMS, 9)
                .push(SettingId(0x02), 1)
                .build(),
            ..Config::default()
        };

        let wire = frame::Settings::try_from(config.clone()).unwrap();
        assert_eq!(wire.get(chrome_datagram), Some(1));
        assert_eq!(wire.get(SettingId::QPACK_MAX_BLOCKED_STREAMS), None);

        config.settings_order = Some(
            frame::SettingsOrder::builder()
                .extend([chrome_datagram, SettingId::MAX_HEADER_LIST_SIZE])
                .build(),
        );
        assert_eq!(
            frame::Settings::try_from(config).unwrap(),
            settings(&[
                (chrome_datagram, 1),
                (SettingId::MAX_HEADER_LIST_SIZE, VarInt::MAX.0),
            ])
        );
    }
}
