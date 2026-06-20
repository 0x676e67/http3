use std::convert::TryFrom;

use crate::proto::{frame, varint::VarInt};

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

    /// When set, controls the exact order of settings in the SETTINGS frame.
    /// Each entry in the list specifies a SettingId whose value will be resolved
    /// from known settings fields or `extra_settings`. When `None`, the default
    /// insertion order is used.
    pub(crate) settings_order: Option<Vec<frame::SettingId>>,

    /// Arbitrary (id, value) setting entries for browser-specific unknown settings
    /// or controlled GREASE. These are used when `settings_order` references IDs
    /// not covered by the known `Settings` fields, or appended at the end in
    /// default mode.
    pub(crate) extra_settings: Vec<(frame::SettingId, u64)>,

    /// HTTP/3 Settings
    pub settings: Settings,
}

/// HTTP/3 Settings
#[derive(Debug, Clone, Copy)]
pub struct Settings {
    /// The MAX_FIELD_SECTION_SIZE in HTTP/3 refers to the maximum size of the dynamic table used in HPACK compression.
    /// HPACK is the compression algorithm used in HTTP/3 to reduce the size of the header fields in HTTP requests and responses.

    /// In HTTP/3, the MAX_FIELD_SECTION_SIZE is set to 12.
    /// This means that the dynamic table used for HPACK compression can have a maximum size of 2^12 bytes, which is 4KB.
    pub(crate) max_field_section_size: u64,

    /// https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http3/#section-3.1
    /// Sets `SETTINGS_ENABLE_WEBTRANSPORT` if enabled
    pub(crate) enable_webtransport: bool,
    /// https://www.rfc-editor.org/info/rfc8441 defines an extended CONNECT method in Section 4,
    /// enabled by the SETTINGS_ENABLE_CONNECT_PROTOCOL parameter.
    /// That parameter is only defined for HTTP/2.
    /// for extended CONNECT in HTTP/3; instead, the SETTINGS_ENABLE_WEBTRANSPORT setting implies that an endpoint supports extended CONNECT.
    pub(crate) enable_extended_connect: bool,
    /// Enable HTTP Datagrams, see https://datatracker.ietf.org/doc/rfc9297/ for details
    pub(crate) enable_datagram: bool,
    /// The maximum number of concurrent streams that can be opened by the peer.
    pub(crate) max_webtransport_sessions: u64,

    /// QPACK dynamic table capacity the encoder is permitted to use, in bytes.
    /// Sent as SETTINGS_QPACK_MAX_TABLE_CAPACITY (0x1).
    /// When unset, the setting is omitted and the protocol default of 0 applies.
    pub(crate) qpack_max_table_capacity: Option<u64>,

    /// Maximum number of blocked streams the decoder is willing to tolerate.
    /// Sent as SETTINGS_QPACK_BLOCKED_STREAMS (0x7).
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
    /// or extra_settings.
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
            _ => self
                .extra_settings
                .iter()
                .find(|(sid, _)| sid == id)
                .map(|(_, v)| *v),
        }
    }
}

impl TryFrom<Config> for frame::Settings {
    type Error = frame::SettingsError;
    fn try_from(value: Config) -> Result<Self, Self::Error> {
        let mut settings = frame::Settings::default();

        if let Some(ref order) = value.settings_order {
            // Impersonation mode: insert settings in the exact specified order.
            for id in order {
                if let Some(val) = value.resolve_setting_value(id) {
                    settings.insert(*id, val)?;
                }
            }
        } else {
            // Default mode: existing behavior.
            settings.insert(
                frame::SettingId::MAX_HEADER_LIST_SIZE,
                value.settings.max_field_section_size,
            )?;
            settings.insert(
                frame::SettingId::ENABLE_CONNECT_PROTOCOL,
                value.settings.enable_extended_connect as u64,
            )?;
            settings.insert(
                frame::SettingId::ENABLE_WEBTRANSPORT,
                value.settings.enable_webtransport as u64,
            )?;
            settings.insert(
                frame::SettingId::H3_DATAGRAM,
                value.settings.enable_datagram as u64,
            )?;
            settings.insert(
                frame::SettingId::WEBTRANSPORT_MAX_SESSIONS,
                value.settings.max_webtransport_sessions,
            )?;
            if let Some(value) = value.settings.qpack_max_table_capacity {
                settings.insert(frame::SettingId::QPACK_MAX_TABLE_CAPACITY, value)?;
            }
            if let Some(value) = value.settings.qpack_blocked_streams {
                settings.insert(frame::SettingId::QPACK_MAX_BLOCKED_STREAMS, value)?;
            }

            // Append extra settings at the end in default mode
            for (id, val) in &value.extra_settings {
                settings.insert(*id, *val)?;
            }
        }

        //  Grease Settings (https://www.rfc-editor.org/rfc/rfc9114.html#name-defined-settings-parameters)
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
    /// https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http3/#section-3.1
    /// Sets `SETTINGS_ENABLE_WEBTRANSPORT` if enabled
    pub fn enable_webtransport(&self) -> bool {
        self.enable_webtransport
    }

    /// Enable HTTP Datagrams, see https://datatracker.ietf.org/doc/rfc9297/ for details
    pub fn enable_datagram(&self) -> bool {
        self.enable_datagram
    }

    /// https://www.rfc-editor.org/info/rfc8441 defines an extended CONNECT method in Section 4,
    /// enabled by the SETTINGS_ENABLE_CONNECT_PROTOCOL parameter.
    /// That parameter is only defined for HTTP/2.
    /// for extended CONNECT in HTTP/3; instead, the SETTINGS_ENABLE_WEBTRANSPORT setting implies that an endpoint supports extended CONNECT.
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
            extra_settings: Vec::new(),
            settings: Default::default(),
        }
    }
}
