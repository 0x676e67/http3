use std::borrow::Cow;

use super::field::HeaderField;

#[derive(Debug, PartialEq)]
pub enum Error {
    Unknown(usize),
}

pub struct StaticTable {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StaticLookup {
    Indexed(usize),
    Name(usize),
    NotFound,
}

impl StaticTable {
    pub fn get(index: usize) -> Result<&'static HeaderField<'static>, Error> {
        match PREDEFINED_HEADERS.get(index) {
            Some(f) => Ok(f),
            None => Err(Error::Unknown(index)),
        }
    }

    pub fn find(field: &HeaderField<'_>) -> Option<usize> {
        match Self::lookup(&field.name, &field.value) {
            StaticLookup::Indexed(index) => Some(index),
            StaticLookup::Name(_) | StaticLookup::NotFound => None,
        }
    }

    pub(crate) fn lookup(name: &[u8], value: &[u8]) -> StaticLookup {
        let Some(name_index) = Self::find_name(name) else {
            return StaticLookup::NotFound;
        };

        let index = match (name_index, value) {
            (0, b"") => 0,
            (1, b"/") => 1,
            (2, b"0") => 2,
            (3, b"") => 3,
            (4, b"0") => 4,
            (5, b"") => 5,
            (6, b"") => 6,
            (7, b"") => 7,
            (8, b"") => 8,
            (9, b"") => 9,
            (10, b"") => 10,
            (11, b"") => 11,
            (12, b"") => 12,
            (13, b"") => 13,
            (14, b"") => 14,
            (15, b"CONNECT") => 15,
            (15, b"DELETE") => 16,
            (15, b"GET") => 17,
            (15, b"HEAD") => 18,
            (15, b"OPTIONS") => 19,
            (15, b"POST") => 20,
            (15, b"PUT") => 21,
            (22, b"http") => 22,
            (22, b"https") => 23,
            (24, b"103") => 24,
            (24, b"200") => 25,
            (24, b"304") => 26,
            (24, b"404") => 27,
            (24, b"503") => 28,
            (29, b"*/*") => 29,
            (29, b"application/dns-message") => 30,
            (31, b"gzip, deflate, br") => 31,
            (32, b"bytes") => 32,
            (33, b"cache-control") => 33,
            (33, b"content-type") => 34,
            (35, b"*") => 35,
            (36, b"max-age=0") => 36,
            (36, b"max-age=2592000") => 37,
            (36, b"max-age=604800") => 38,
            (36, b"no-cache") => 39,
            (36, b"no-store") => 40,
            (36, b"public, max-age=31536000") => 41,
            (42, b"br") => 42,
            (42, b"gzip") => 43,
            (44, b"application/dns-message") => 44,
            (44, b"application/javascript") => 45,
            (44, b"application/json") => 46,
            (44, b"application/x-www-form-urlencoded") => 47,
            (44, b"image/gif") => 48,
            (44, b"image/jpeg") => 49,
            (44, b"image/png") => 50,
            (44, b"text/css") => 51,
            (44, b"text/html; charset=utf-8") => 52,
            (44, b"text/plain") => 53,
            (44, b"text/plain;charset=utf-8") => 54,
            (55, b"bytes=0-") => 55,
            (56, b"max-age=31536000") => 56,
            (56, b"max-age=31536000; includesubdomains") => 57,
            (56, b"max-age=31536000; includesubdomains; preload") => 58,
            (59, b"accept-encoding") => 59,
            (59, b"origin") => 60,
            (61, b"nosniff") => 61,
            (62, b"1; mode=block") => 62,
            (24, b"100") => 63,
            (24, b"204") => 64,
            (24, b"206") => 65,
            (24, b"302") => 66,
            (24, b"400") => 67,
            (24, b"403") => 68,
            (24, b"421") => 69,
            (24, b"425") => 70,
            (24, b"500") => 71,
            (72, b"") => 72,
            (73, b"FALSE") => 73,
            (73, b"TRUE") => 74,
            (33, b"*") => 75,
            (76, b"get") => 76,
            (76, b"get, post, options") => 77,
            (76, b"options") => 78,
            (79, b"content-length") => 79,
            (80, b"content-type") => 80,
            (81, b"get") => 81,
            (81, b"post") => 82,
            (83, b"clear") => 83,
            (84, b"") => 84,
            (85, b"script-src 'none'; object-src 'none'; base-uri 'none'") => 85,
            (86, b"1") => 86,
            (87, b"") => 87,
            (88, b"") => 88,
            (89, b"") => 89,
            (90, b"") => 90,
            (91, b"prefetch") => 91,
            (92, b"") => 92,
            (93, b"*") => 93,
            (94, b"1") => 94,
            (95, b"") => 95,
            (96, b"") => 96,
            (97, b"deny") => 97,
            (97, b"sameorigin") => 98,
            _ => return StaticLookup::Name(name_index),
        };

        StaticLookup::Indexed(index)
    }

    pub fn find_name(name: &[u8]) -> Option<usize> {
        match name {
            b":authority" => Some(0),
            b":path" => Some(1),
            b"age" => Some(2),
            b"content-disposition" => Some(3),
            b"content-length" => Some(4),
            b"cookie" => Some(5),
            b"date" => Some(6),
            b"etag" => Some(7),
            b"if-modified-since" => Some(8),
            b"if-none-match" => Some(9),
            b"last-modified" => Some(10),
            b"link" => Some(11),
            b"location" => Some(12),
            b"referer" => Some(13),
            b"set-cookie" => Some(14),
            b":method" => Some(15),
            b":scheme" => Some(22),
            b":status" => Some(24),
            b"accept" => Some(29),
            b"accept-encoding" => Some(31),
            b"accept-ranges" => Some(32),
            b"access-control-allow-headers" => Some(33),
            b"access-control-allow-origin" => Some(35),
            b"cache-control" => Some(36),
            b"content-encoding" => Some(42),
            b"content-type" => Some(44),
            b"range" => Some(55),
            b"strict-transport-security" => Some(56),
            b"vary" => Some(59),
            b"x-content-type-options" => Some(61),
            b"x-xss-protection" => Some(62),
            b"accept-language" => Some(72),
            b"access-control-allow-credentials" => Some(73),
            b"access-control-allow-methods" => Some(76),
            b"access-control-expose-headers" => Some(79),
            b"access-control-request-headers" => Some(80),
            b"access-control-request-method" => Some(81),
            b"alt-svc" => Some(83),
            b"authorization" => Some(84),
            b"content-security-policy" => Some(85),
            b"early-data" => Some(86),
            b"expect-ct" => Some(87),
            b"forwarded" => Some(88),
            b"if-range" => Some(89),
            b"origin" => Some(90),
            b"purpose" => Some(91),
            b"server" => Some(92),
            b"timing-allow-origin" => Some(93),
            b"upgrade-insecure-requests" => Some(94),
            b"user-agent" => Some(95),
            b"x-forwarded-for" => Some(96),
            b"x-frame-options" => Some(97),
            _ => None,
        }
    }
}

macro_rules! decl_fields {
    [ $( ($key:expr, $value:expr) ),* ] => {
        [
            $(
            HeaderField {
                name: Cow::Borrowed($key),
                value: Cow::Borrowed($value),
                sensitive: false,
            },
        )* ]
    }
}

const PREDEFINED_HEADERS: [HeaderField<'static>; 99] = decl_fields![
    (b":authority", b""),
    (b":path", b"/"),
    (b"age", b"0"),
    (b"content-disposition", b""),
    (b"content-length", b"0"),
    (b"cookie", b""),
    (b"date", b""),
    (b"etag", b""),
    (b"if-modified-since", b""),
    (b"if-none-match", b""),
    (b"last-modified", b""),
    (b"link", b""),
    (b"location", b""),
    (b"referer", b""),
    (b"set-cookie", b""),
    (b":method", b"CONNECT"),
    (b":method", b"DELETE"),
    (b":method", b"GET"),
    (b":method", b"HEAD"),
    (b":method", b"OPTIONS"),
    (b":method", b"POST"),
    (b":method", b"PUT"),
    (b":scheme", b"http"),
    (b":scheme", b"https"),
    (b":status", b"103"),
    (b":status", b"200"),
    (b":status", b"304"),
    (b":status", b"404"),
    (b":status", b"503"),
    (b"accept", b"*/*"),
    (b"accept", b"application/dns-message"),
    (b"accept-encoding", b"gzip, deflate, br"),
    (b"accept-ranges", b"bytes"),
    (b"access-control-allow-headers", b"cache-control"),
    (b"access-control-allow-headers", b"content-type"),
    (b"access-control-allow-origin", b"*"),
    (b"cache-control", b"max-age=0"),
    (b"cache-control", b"max-age=2592000"),
    (b"cache-control", b"max-age=604800"),
    (b"cache-control", b"no-cache"),
    (b"cache-control", b"no-store"),
    (b"cache-control", b"public, max-age=31536000"),
    (b"content-encoding", b"br"),
    (b"content-encoding", b"gzip"),
    (b"content-type", b"application/dns-message"),
    (b"content-type", b"application/javascript"),
    (b"content-type", b"application/json"),
    (b"content-type", b"application/x-www-form-urlencoded"),
    (b"content-type", b"image/gif"),
    (b"content-type", b"image/jpeg"),
    (b"content-type", b"image/png"),
    (b"content-type", b"text/css"),
    (b"content-type", b"text/html; charset=utf-8"),
    (b"content-type", b"text/plain"),
    (b"content-type", b"text/plain;charset=utf-8"),
    (b"range", b"bytes=0-"),
    (b"strict-transport-security", b"max-age=31536000"),
    (
        b"strict-transport-security",
        b"max-age=31536000; includesubdomains"
    ),
    (
        b"strict-transport-security",
        b"max-age=31536000; includesubdomains; preload"
    ),
    (b"vary", b"accept-encoding"),
    (b"vary", b"origin"),
    (b"x-content-type-options", b"nosniff"),
    (b"x-xss-protection", b"1; mode=block"),
    (b":status", b"100"),
    (b":status", b"204"),
    (b":status", b"206"),
    (b":status", b"302"),
    (b":status", b"400"),
    (b":status", b"403"),
    (b":status", b"421"),
    (b":status", b"425"),
    (b":status", b"500"),
    (b"accept-language", b""),
    (b"access-control-allow-credentials", b"FALSE"),
    (b"access-control-allow-credentials", b"TRUE"),
    (b"access-control-allow-headers", b"*"),
    (b"access-control-allow-methods", b"get"),
    (b"access-control-allow-methods", b"get, post, options"),
    (b"access-control-allow-methods", b"options"),
    (b"access-control-expose-headers", b"content-length"),
    (b"access-control-request-headers", b"content-type"),
    (b"access-control-request-method", b"get"),
    (b"access-control-request-method", b"post"),
    (b"alt-svc", b"clear"),
    (b"authorization", b""),
    (
        b"content-security-policy",
        b"script-src 'none'; object-src 'none'; base-uri 'none'"
    ),
    (b"early-data", b"1"),
    (b"expect-ct", b""),
    (b"forwarded", b""),
    (b"if-range", b""),
    (b"origin", b""),
    (b"purpose", b"prefetch"),
    (b"server", b""),
    (b"timing-allow-origin", b"*"),
    (b"upgrade-insecure-requests", b"1"),
    (b"user-agent", b""),
    (b"x-forwarded-for", b""),
    (b"x-frame-options", b"deny"),
    (b"x-frame-options", b"sameorigin")
];

#[cfg(test)]
mod tests {
    use super::*;

    /**
     * https://www.rfc-editor.org/rfc/rfc9204.html#section-3.1
     *  3.1.  Static Table
     *  [...]
     *  Note the QPACK static table is indexed from 0, whereas the HPACK
     *  static table is indexed from 1.
     */
    #[test]
    fn test_static_table_index_is_0_based() {
        assert_eq!(StaticTable::get(0), Ok(&HeaderField::new(":authority", "")));
    }

    #[test]
    fn test_static_table_is_full() {
        assert_eq!(PREDEFINED_HEADERS.len(), 99);
    }

    #[test]
    fn test_static_table_can_get_field() {
        assert_eq!(
            StaticTable::get(98),
            Ok(&HeaderField::new("x-frame-options", "sameorigin"))
        );
    }

    #[test]
    fn invalid_index() {
        assert_eq!(StaticTable::get(99), Err(Error::Unknown(99)));
    }

    #[test]
    fn find_by_name() {
        assert_eq!(StaticTable::find_name(b"last-modified"), Some(10usize));
        assert_eq!(StaticTable::find_name(b"does-not-exist"), None);
    }

    #[test]
    fn find() {
        for (index, field) in PREDEFINED_HEADERS.iter().enumerate() {
            assert_eq!(StaticTable::find(field), Some(index));

            let name_index = StaticTable::find_name(&field.name).unwrap();
            assert_eq!(
                StaticTable::lookup(&field.name, b"not-a-static-value"),
                StaticLookup::Name(name_index)
            );
        }

        assert_eq!(StaticTable::find(&HeaderField::new("foo", "bar")), None);
        assert_eq!(StaticTable::lookup(b"foo", b"bar"), StaticLookup::NotFound);
    }
}
