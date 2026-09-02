use std::{
    borrow::Cow,
    fmt::{Display, Formatter},
};

/**
 * https://tools.ietf.org/html/rfc7541
 * 4.1.  Calculating Table Size
 */
pub const ESTIMATED_OVERHEAD_BYTES: usize = 32;

/// A QPACK header field that can own or borrow its name and value.
#[derive(Debug, PartialEq, Clone, Hash, Eq)]
pub struct HeaderField<'a> {
    pub name: Cow<'a, [u8]>,
    pub value: Cow<'a, [u8]>,
    /// Whether this field must use a literal representation when forwarded.
    pub sensitive: bool,
}

impl HeaderField<'static> {
    pub fn new<T, S>(name: T, value: S) -> Self
    where
        T: Into<Vec<u8>>,
        S: Into<Vec<u8>>,
    {
        HeaderField {
            name: Cow::Owned(name.into()),
            value: Cow::Owned(value.into()),
            sensitive: false,
        }
    }
}

impl<'a> HeaderField<'a> {
    pub(crate) fn borrowed(name: &'a [u8], value: &'a [u8], sensitive: bool) -> Self {
        Self {
            name: Cow::Borrowed(name),
            value: Cow::Borrowed(value),
            sensitive,
        }
    }

    pub fn mem_size(&self) -> usize {
        self.name.len() + self.value.len() + ESTIMATED_OVERHEAD_BYTES
    }

    pub fn with_value<T>(&self, value: T) -> Self
    where
        T: Into<Vec<u8>>,
    {
        Self {
            name: self.name.clone(),
            value: Cow::Owned(value.into()),
            sensitive: self.sensitive,
        }
    }

    /// Marks the field as sensitive for compression.
    ///
    /// This carries QPACK's never-indexed bit through the HTTP header model so
    /// an intermediary can preserve the peer's literal-only instruction when
    /// forwarding the field.
    ///
    /// See [RFC 9204, Section 4.5.4](https://www.rfc-editor.org/rfc/rfc9204.html#section-4.5.4).
    pub fn set_sensitive(&mut self, sensitive: bool) {
        self.sensitive = sensitive;
    }

    /// Returns whether this field must remain a never-indexed literal.
    pub fn is_sensitive(&self) -> bool {
        self.sensitive
    }

    /// Returns this field with the requested compression sensitivity.
    pub fn with_sensitive(mut self, sensitive: bool) -> Self {
        self.set_sensitive(sensitive);
        self
    }

    pub fn into_inner(self) -> (Cow<'a, [u8]>, Cow<'a, [u8]>) {
        (self.name, self.value)
    }
}

impl<'a, 'b: 'a> AsRef<HeaderField<'a>> for HeaderField<'b> {
    fn as_ref(&self) -> &HeaderField<'a> {
        self
    }
}

impl Display for HeaderField<'_> {
    fn fmt(&self, f: &mut Formatter) -> Result<(), std::fmt::Error> {
        write!(
            f,
            "\"{}\": \"{}\"",
            String::from_utf8_lossy(&self.name),
            String::from_utf8_lossy(&self.value)
        )?;
        Ok(())
    }
}

impl From<HeaderField<'_>> for String {
    fn from(field: HeaderField<'_>) -> String {
        format!(
            "{}\t{}",
            String::from_utf8_lossy(&field.name),
            String::from_utf8_lossy(&field.value)
        )
    }
}

impl<N, V> From<(N, V)> for HeaderField<'static>
where
    N: AsRef<[u8]>,
    V: AsRef<[u8]>,
{
    fn from(header: (N, V)) -> Self {
        let (name, value) = header;
        Self {
            // Generic tuple conversion produces an owned field. Borrowed HTTP
            // header iteration constructs `HeaderField<'_>` directly.
            name: Cow::Owned(Vec::from(name.as_ref())),
            value: Cow::Owned(Vec::from(value.as_ref())),
            sensitive: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /**
     * https://tools.ietf.org/html/rfc7541#section-4.1
     * "The size of an entry is the sum of its name's length in octets (as
     *  defined in Section 5.2), its value's length in octets, and 32."
     * "The size of an entry is calculated using the length of its name and
     *  value without any Huffman encoding applied."
     */
    #[test]
    fn test_field_size_is_offset_by_32() {
        let field = HeaderField {
            name: Cow::Borrowed(b"Name"),
            value: Cow::Borrowed(b"Value"),
            sensitive: false,
        };
        assert_eq!(field.mem_size(), 4 + 5 + 32);
    }

    #[test]
    fn with_value() {
        let field = HeaderField {
            name: Cow::Borrowed(b"Name"),
            value: Cow::Borrowed(b"Value"),
            sensitive: true,
        };
        assert_eq!(
            field.with_value("New value"),
            HeaderField {
                name: Cow::Borrowed(b"Name"),
                value: Cow::Borrowed(b"New value"),
                sensitive: true,
            }
        );
    }
}
