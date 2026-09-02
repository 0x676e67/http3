use std::{
    borrow::Cow,
    convert::TryFrom,
    fmt,
    iter::{IntoIterator, Iterator},
    str::FromStr,
};

use http::{
    Extensions, HeaderMap, Method, StatusCode,
    header::{self, HeaderName, HeaderValue},
    uri::{self, Authority, Parts, PathAndQuery, Scheme, Uri},
};
use smallvec::SmallVec;

use crate::{ext::Protocol, qpack::HeaderField};

define_enum_with_values! {
    /// Represents the order of HTTP/3 pseudo-header fields in the header block.
    ///
    /// HTTP/3 pseudo-header fields are a set of predefined header fields that start with ':'.
    /// The order of these fields in a header block is significant for fingerprinting purposes.
    /// This enum defines the possible pseudo-header fields and their default order.
    @U8
    pub enum PseudoId {
        /// The `:method` pseudo-header field.
        Method => 0x0001,
        /// The `:scheme` pseudo-header field.
        Scheme => 0x0002,
        /// The `:authority` pseudo-header field.
        Authority => 0x0003,
        /// The `:path` pseudo-header field.
        Path => 0x0004,
        /// The `:protocol` pseudo-header field.
        Protocol => 0x0005,
        /// The `:status` pseudo-header field.
        Status => 0x0006,
    }
}

/// Represents the order of HTTP/3 pseudo-header fields in a header block.
///
/// This structure maintains an ordered list of pseudo-header fields (such as `:method`, `:scheme`,
/// etc.) for use when encoding HTTP/3 header blocks. The order of pseudo-headers can be configured
/// to match specific browser fingerprints (e.g. Chrome uses "masp" = Method, Authority, Scheme,
/// Path; Firefox uses "msap" = Method, Scheme, Authority, Path).
///
/// Typically, a `PseudoOrder` is constructed using the [`PseudoOrderBuilder`] to enforce uniqueness
/// and correct ordering.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct PseudoOrder {
    ids: [PseudoId; PseudoId::DEFAULT_STACK_SIZE],
}

/// A builder for constructing a [`PseudoOrder`].
#[derive(Debug)]
pub struct PseudoOrderBuilder {
    ids: SmallVec<[PseudoId; PseudoId::DEFAULT_STACK_SIZE]>,
    mask: u8,
}

/// Preserves QPACK's never-indexed marker for pseudo-header fields.
///
/// Decoded regular fields carry this information through
/// [`HeaderValue::is_sensitive`]. Pseudo-header fields have no corresponding
/// `HeaderValue`, so this value is stored in [`http::Extensions`] when a
/// request or response is received and read again when it is forwarded.
///
/// See [RFC 9204 Section 7.1.3](https://www.rfc-editor.org/rfc/rfc9204.html#section-7.1.3).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PseudoHeaderSensitivity {
    mask: u8,
}

impl PseudoHeaderSensitivity {
    /// Marks a pseudo-header field as sensitive or non-sensitive.
    pub fn set_sensitive(&mut self, id: PseudoId, sensitive: bool) {
        if sensitive {
            self.mask |= id.mask_id();
        } else {
            self.mask &= !id.mask_id();
        }
    }

    /// Returns whether the pseudo-header field must remain never-indexed.
    pub fn is_sensitive(&self, id: PseudoId) -> bool {
        self.mask & id.mask_id() != 0
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.mask == 0
    }
}

// ===== impl PseudoOrder =====

impl PseudoOrder {
    /// Creates a new [`PseudoOrderBuilder`].
    #[inline]
    pub fn builder() -> PseudoOrderBuilder {
        PseudoOrderBuilder {
            ids: SmallVec::new(),
            mask: 0,
        }
    }
}

impl Default for PseudoOrder {
    #[inline]
    fn default() -> Self {
        PseudoOrder {
            ids: PseudoId::DEFAULT_IDS,
        }
    }
}

impl<'a> IntoIterator for &'a PseudoOrder {
    type Item = &'a PseudoId;
    type IntoIter = std::slice::Iter<'a, PseudoId>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.ids.iter()
    }
}

// ===== impl PseudoOrderBuilder =====

impl PseudoOrderBuilder {
    /// Pushes a pseudo-header ID to the order, ignoring duplicates.
    pub fn push(mut self, id: PseudoId) -> Self {
        let mask_id = id.mask_id();
        if mask_id != 0 && self.mask & mask_id == 0 {
            self.mask |= mask_id;
            self.ids.push(id);
        }
        self
    }

    /// Extends the order with multiple pseudo-header IDs.
    pub fn extend(mut self, iter: impl IntoIterator<Item = PseudoId>) -> Self {
        for id in iter {
            self = self.push(id);
        }
        self
    }

    /// Builds the [`PseudoOrder`], filling in any missing IDs from the default order.
    pub fn build(mut self) -> PseudoOrder {
        if self.ids.len() != PseudoId::DEFAULT_IDS.len() {
            self = self.extend(PseudoId::DEFAULT_IDS);
        }

        let mut ids = PseudoId::DEFAULT_IDS;
        for (target, source) in ids.iter_mut().zip(self.ids) {
            *target = source;
        }
        PseudoOrder { ids }
    }
}

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq, Clone))]
pub struct Header {
    pseudo: Pseudo,
    fields: HeaderMap,
}

#[allow(clippy::len_without_is_empty)]
impl Header {
    /// Creates a new `Header` frame data suitable for sending a request
    pub fn request(
        method: Method,
        uri: Uri,
        fields: HeaderMap,
        ext: Extensions,
    ) -> Result<Self, HeaderError> {
        match (uri.authority(), fields.get("host")) {
            (None, None) => Err(HeaderError::MissingAuthority),
            (Some(a), Some(h)) if a.as_str() != h => Err(HeaderError::ContradictedAuthority),
            _ => Ok(Self {
                pseudo: Pseudo::request(method, uri, ext),
                fields,
            }),
        }
    }

    pub fn response(status: StatusCode, fields: HeaderMap, ext: Extensions) -> Self {
        Self {
            pseudo: Pseudo::response(status, ext),
            fields,
        }
    }

    pub fn trailer(fields: HeaderMap) -> Self {
        Self {
            //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3
            //# Pseudo-header fields MUST NOT appear in trailer
            //# sections.
            pseudo: Pseudo::default(),
            fields,
        }
    }

    pub fn into_request_parts(
        self,
    ) -> Result<
        (
            Method,
            Uri,
            Option<Protocol>,
            HeaderMap,
            PseudoHeaderSensitivity,
        ),
        HeaderError,
    > {
        let mut uri = Uri::builder();

        if let Some(path) = self.pseudo.path {
            uri = uri.path_and_query(path.as_str().as_bytes());
        }

        if let Some(scheme) = self.pseudo.scheme {
            uri = uri.scheme(scheme.as_str().as_bytes());
        }

        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
        //# If the :scheme pseudo-header field identifies a scheme that has a
        //# mandatory authority component (including "http" and "https"), the
        //# request MUST contain either an :authority pseudo-header field or a
        //# Host header field.

        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
        //= type=TODO
        //# If the scheme does not have a mandatory authority component and none
        //# is provided in the request target, the request MUST NOT contain the
        //# :authority pseudo-header or Host header fields.
        match (self.pseudo.authority, self.fields.get("host")) {
            (None, None) => return Err(HeaderError::MissingAuthority),
            (Some(a), None) => uri = uri.authority(a.as_str().as_bytes()),
            (None, Some(h)) => uri = uri.authority(h.as_bytes()),
            //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
            //# If both fields are present, they MUST contain the same value.
            (Some(a), Some(h)) if a.as_str() != h => {
                return Err(HeaderError::ContradictedAuthority);
            }
            (Some(_), Some(h)) => uri = uri.authority(h.as_bytes()),
        }

        Ok((
            self.pseudo.method.ok_or(HeaderError::MissingMethod)?,
            // When empty host field is built into an uri it fails
            //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
            //# If these fields are present, they MUST NOT be
            //# empty.
            uri.build().map_err(HeaderError::InvalidRequest)?,
            self.pseudo.protocol,
            self.fields,
            PseudoHeaderSensitivity {
                mask: self.pseudo.sensitive,
            },
        ))
    }

    pub fn into_response_parts(
        self,
    ) -> Result<(StatusCode, HeaderMap, PseudoHeaderSensitivity), HeaderError> {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.2
        //= type=implication
        //# For responses, a single ":status" pseudo-header field is defined that
        //# carries the HTTP status code; see Section 15 of [HTTP].  This pseudo-
        //# header field MUST be included in all responses; otherwise, the
        //# response is malformed (see Section 4.1.2).
        Ok((
            self.pseudo.status.ok_or(HeaderError::MissingStatus)?,
            self.fields,
            PseudoHeaderSensitivity {
                mask: self.pseudo.sensitive,
            },
        ))
    }

    pub fn into_fields(self) -> HeaderMap {
        self.fields
    }

    pub fn len(&self) -> usize {
        self.pseudo.len() + self.fields.len()
    }

    pub fn size(&self) -> usize {
        self.pseudo.len() + self.fields.len()
    }

    /// Borrows the normalized field section without materializing owned QPACK
    /// fields. Pseudo-header order and sensitivity match [`HeaderIter`].
    pub(crate) fn iter_ref(&self) -> HeaderIterRef<'_> {
        HeaderIterRef {
            pseudo: &self.pseudo,
            pseudo_order_index: 0,
            fields: self.fields.iter(),
        }
    }

    /// Sets the pseudo-header field order for this header block.
    pub fn set_pseudo_order(&mut self, order: PseudoOrder) {
        self.pseudo.order = Some(order);
    }

    #[cfg(test)]
    pub(crate) fn authory_mut(&mut self) -> &mut Option<Authority> {
        &mut self.pseudo.authority
    }
}

impl IntoIterator for Header {
    type Item = HeaderField<'static>;
    type IntoIter = HeaderIter;
    fn into_iter(self) -> Self::IntoIter {
        HeaderIter {
            pseudo: Some(self.pseudo),
            pseudo_order_index: 0,
            last_header_name: None,
            fields: self.fields.into_iter(),
        }
    }
}

pub struct HeaderIter {
    pseudo: Option<Pseudo>,
    pseudo_order_index: u8,
    last_header_name: Option<HeaderName>,
    fields: header::IntoIter<HeaderValue>,
}

pub(crate) struct HeaderIterRef<'a> {
    pseudo: &'a Pseudo,
    pseudo_order_index: usize,
    fields: header::Iter<'a, HeaderValue>,
}

impl<'a> Iterator for HeaderIterRef<'a> {
    type Item = HeaderField<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        // Pseudo-header fields always precede regular fields. Missing fields
        // are skipped so the same order works for requests and responses.
        while self.pseudo_order_index < PseudoId::DEFAULT_STACK_SIZE {
            let index = self.pseudo_order_index;
            self.pseudo_order_index += 1;
            let id = self
                .pseudo
                .order
                .as_ref()
                .map_or(PseudoId::DEFAULT_IDS[index], |order| order.ids[index]);
            if let Some(field) = self.pseudo.field_ref(id) {
                return Some(field);
            }
        }

        self.fields.next().map(|(name, value)| {
            HeaderField::borrowed(
                name.as_str().as_bytes(),
                value.as_bytes(),
                value.is_sensitive(),
            )
        })
    }
}

impl Iterator for HeaderIter {
    type Item = HeaderField<'static>;

    fn next(&mut self) -> Option<Self::Item> {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3
        //# All pseudo-header fields MUST appear in the header section before
        //# regular header fields.
        if let Some(ref mut pseudo) = self.pseudo {
            if pseudo.order.is_none() {
                if let Some(field) = pseudo.take_field(PseudoId::Method) {
                    return Some(field);
                }
                if let Some(field) = pseudo.take_field(PseudoId::Scheme) {
                    return Some(field);
                }
                if let Some(field) = pseudo.take_field(PseudoId::Authority) {
                    return Some(field);
                }
                if let Some(field) = pseudo.take_field(PseudoId::Path) {
                    return Some(field);
                }
                if let Some(field) = pseudo.take_field(PseudoId::Status) {
                    return Some(field);
                }
                if let Some(field) = pseudo.take_field(PseudoId::Protocol) {
                    return Some(field);
                }
            } else {
                while let Some(pseudo_type) = pseudo
                    .order
                    .as_ref()
                    .and_then(|order| order.ids.get(usize::from(self.pseudo_order_index)))
                    .copied()
                {
                    self.pseudo_order_index += 1;
                    if let Some(field) = pseudo.take_field(pseudo_type) {
                        return Some(field);
                    }
                }
            }
        }

        self.pseudo = None;

        for (new_header_name, header_value) in self.fields.by_ref() {
            if let Some(new) = new_header_name {
                self.last_header_name = Some(new);
            }
            if let (Some(n), v) = (&self.last_header_name, header_value) {
                return Some(
                    HeaderField::from((n.as_str(), v.as_bytes())).with_sensitive(v.is_sensitive()),
                );
            }
        }

        None
    }
}

impl TryFrom<Vec<HeaderField<'static>>> for Header {
    type Error = HeaderError;
    fn try_from(headers: Vec<HeaderField<'static>>) -> Result<Self, Self::Error> {
        let mut fields = HeaderMap::with_capacity(headers.len());
        let mut pseudo = Pseudo::default();

        for field in headers.into_iter() {
            let sensitive = field.is_sensitive();
            let (name, value) = field.into_inner();
            match Field::parse(name, value)? {
                Field::Method(m) => {
                    pseudo.method = Some(m);
                    pseudo.len += 1;
                    pseudo.set_sensitive(PseudoId::Method, sensitive);
                }
                Field::Scheme(s) => {
                    pseudo.scheme = Some(s);
                    pseudo.len += 1;
                    pseudo.set_sensitive(PseudoId::Scheme, sensitive);
                }
                Field::Authority(a) => {
                    pseudo.authority = Some(a);
                    pseudo.len += 1;
                    pseudo.set_sensitive(PseudoId::Authority, sensitive);
                }
                Field::Path(p) => {
                    pseudo.path = Some(p);
                    pseudo.len += 1;
                    pseudo.set_sensitive(PseudoId::Path, sensitive);
                }
                Field::Status(s) => {
                    pseudo.status = Some(s);
                    pseudo.len += 1;
                    pseudo.set_sensitive(PseudoId::Status, sensitive);
                }
                Field::Header((n, mut v)) => {
                    v.set_sensitive(sensitive);
                    fields.append(n, v);
                }
                Field::Protocol(p) => {
                    pseudo.protocol = Some(p);
                    pseudo.len += 1;
                    pseudo.set_sensitive(PseudoId::Protocol, sensitive);
                }
            }
        }

        Ok(Header { pseudo, fields })
    }
}

enum Field {
    Method(Method),
    Scheme(Scheme),
    Authority(Authority),
    Path(PathAndQuery),
    Status(StatusCode),
    Protocol(Protocol),
    Header((HeaderName, HeaderValue)),
}

impl Field {
    fn parse(name: Cow<'static, [u8]>, value: Cow<'static, [u8]>) -> Result<Self, HeaderError> {
        let name = name.as_ref();
        if name.is_empty() {
            return Err(HeaderError::InvalidHeaderName("name is empty".into()));
        }

        //= https://www.rfc-editor.org/rfc/rfc9114#section-10.3
        //# Requests or responses containing invalid field names MUST be treated
        //# as malformed.

        //= https://www.rfc-editor.org/rfc/rfc9114#section-10.3
        //# Any request or response that contains a
        //# character not permitted in a field value MUST be treated as
        //# malformed.

        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.2
        //= type=implication
        //# A request or
        //# response containing uppercase characters in field names MUST be
        //# treated as malformed.

        if name[0] != b':' {
            let shared_value = match value {
                Cow::Borrowed(value) => bytes::Bytes::from_static(value),
                Cow::Owned(value) => bytes::Bytes::from(value),
            };
            let diagnostic = shared_value.clone();
            return Ok(Field::Header((
                HeaderName::from_lowercase(name).map_err(|_| HeaderError::invalid_name(name))?,
                HeaderValue::from_maybe_shared(shared_value)
                    .map_err(|_| HeaderError::invalid_value(name, diagnostic))?,
            )));
        }

        Ok(match name {
            b":scheme" => Field::Scheme(try_value(name, value)?),
            //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
            //# If these fields are present, they MUST NOT be
            //# empty.
            b":authority" => Field::Authority(try_value(name, value)?),
            b":path" => Field::Path(try_value(name, value)?),
            b":method" => Field::Method(
                Method::from_bytes(value.as_ref())
                    .map_err(|_| HeaderError::invalid_value(name, value))?,
            ),
            b":status" => Field::Status(
                StatusCode::from_bytes(value.as_ref())
                    .map_err(|_| HeaderError::invalid_value(name, value))?,
            ),
            b":protocol" => Field::Protocol(try_value(name, value)?),
            _ => return Err(HeaderError::invalid_name(name)),
        })
    }
}

fn try_value<N, V, R>(name: N, value: V) -> Result<R, HeaderError>
where
    N: AsRef<[u8]>,
    V: AsRef<[u8]>,
    R: FromStr,
{
    let (name, value) = (name.as_ref(), value.as_ref());
    let s = std::str::from_utf8(value).map_err(|_| HeaderError::invalid_value(name, value))?;
    R::from_str(s).map_err(|_| HeaderError::invalid_value(name, value))
}

/// Pseudo-header fields have the same purpose as data from the first line of HTTP/1.X,
/// but are conveyed along with other headers. For example ':method' and ':path' in a
/// request, and ':status' in a response. They must be placed before all other fields,
/// start with ':', and be lowercase.
/// See RFC7540 section 8.1.2.1. for more details.
#[derive(Debug, Default)]
#[cfg_attr(test, derive(PartialEq, Clone))]
struct Pseudo {
    //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3
    //= type=implication
    //# Endpoints MUST NOT
    //# generate pseudo-header fields other than those defined in this
    //# document.

    // Request
    method: Option<Method>,
    scheme: Option<Scheme>,
    authority: Option<Authority>,
    path: Option<PathAndQuery>,

    // Response
    status: Option<StatusCode>,

    protocol: Option<Protocol>,

    // Pseudo-header field order
    order: Option<PseudoOrder>,

    // QPACK never-indexed bits for pseudo-header fields. Regular fields carry
    // the same metadata through `HeaderValue::is_sensitive`.
    sensitive: u8,

    len: usize,
}

#[allow(clippy::len_without_is_empty)]
impl Pseudo {
    fn request(method: Method, uri: Uri, ext: Extensions) -> Self {
        let Parts {
            scheme,
            authority,
            path_and_query,
            ..
        } = uri::Parts::from(uri);

        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
        //= type=implication
        //# This pseudo-header field MUST NOT be empty for "http" or "https"
        //# URIs; "http" or "https" URIs that do not contain a path component
        //# MUST include a value of / (ASCII 0x2f).
        let path = path_and_query.map_or_else(
            || PathAndQuery::from_static("/"),
            |path| {
                if path.path().is_empty() && method != Method::OPTIONS {
                    PathAndQuery::from_static("/")
                } else {
                    path
                }
            },
        );

        // If the method is connect, the `:protocol` pseudo-header MAY be defined
        //
        // See: [https://www.rfc-editor.org/rfc/rfc8441#section-4]
        let protocol = if method == Method::CONNECT {
            ext.get::<Protocol>().copied()
        } else {
            None
        };

        // For standard CONNECT (that is, without :protocol pseudo-header) scheme and path
        // are not set. See: [https://www.rfc-editor.org/rfc/rfc9114#section-4.4]
        let (scheme, path) = if method == Method::CONNECT && protocol.is_none() {
            (None, None)
        } else {
            (scheme.or(Some(Scheme::HTTPS)), Some(path))
        };

        let len = 3 + authority.is_some() as usize + protocol.is_some() as usize;

        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3
        //= type=implication
        //# Pseudo-header fields defined for requests MUST NOT appear
        //# in responses; pseudo-header fields defined for responses MUST NOT
        //# appear in requests.

        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
        //= type=implication
        //# All HTTP/3 requests MUST include exactly one value for the :method,
        //# :scheme, and :path pseudo-header fields, unless the request is a
        //# CONNECT request; see Section 4.4.
        // Extract pseudo-header order from extensions, if provided.
        let order = ext.get::<PseudoOrder>().cloned();
        let sensitive = ext
            .get::<PseudoHeaderSensitivity>()
            .copied()
            .unwrap_or_default()
            .mask;

        Self {
            method: Some(method),
            scheme,
            authority,
            path,
            status: None,
            protocol,
            order,
            sensitive,
            len,
        }
    }

    fn response(status: StatusCode, ext: Extensions) -> Self {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3
        //= type=implication
        //# Pseudo-header fields defined for requests MUST NOT appear
        //# in responses; pseudo-header fields defined for responses MUST NOT
        //# appear in requests.
        Pseudo {
            method: None,
            scheme: None,
            authority: None,
            path: None,
            status: Some(status),
            protocol: None,
            order: None,
            sensitive: ext
                .get::<PseudoHeaderSensitivity>()
                .copied()
                .unwrap_or_default()
                .mask,
            len: 1,
        }
    }

    fn len(&self) -> usize {
        self.len
    }

    fn set_sensitive(&mut self, id: PseudoId, sensitive: bool) {
        if sensitive {
            self.sensitive |= id.mask_id();
        } else {
            self.sensitive &= !id.mask_id();
        }
    }

    fn is_sensitive(&self, id: PseudoId) -> bool {
        self.sensitive & id.mask_id() != 0
    }

    #[inline]
    fn take_field(&mut self, id: PseudoId) -> Option<HeaderField<'static>> {
        match id {
            PseudoId::Method => self.method.take().map(|method| {
                HeaderField::from((":method", method.as_str()))
                    .with_sensitive(self.is_sensitive(id))
            }),
            PseudoId::Scheme => self.scheme.take().map(|scheme| {
                HeaderField::from((":scheme", scheme.as_str().as_bytes()))
                    .with_sensitive(self.is_sensitive(id))
            }),
            PseudoId::Authority => self.authority.take().map(|authority| {
                HeaderField::from((":authority", authority.as_str().as_bytes()))
                    .with_sensitive(self.is_sensitive(id))
            }),
            PseudoId::Path => self.path.take().map(|path| {
                HeaderField::from((":path", path.as_str().as_bytes()))
                    .with_sensitive(self.is_sensitive(id))
            }),
            PseudoId::Status => self.status.take().map(|status| {
                HeaderField::from((":status", status.as_str()))
                    .with_sensitive(self.is_sensitive(id))
            }),
            PseudoId::Protocol => self.protocol.take().map(|protocol| {
                HeaderField::from((":protocol", protocol.as_str().as_bytes()))
                    .with_sensitive(self.is_sensitive(id))
            }),
        }
    }

    #[inline]
    fn field_ref(&self, id: PseudoId) -> Option<HeaderField<'_>> {
        let (name, value): (&[u8], &[u8]) = match id {
            PseudoId::Method => (b":method", self.method.as_ref()?.as_str().as_bytes()),
            PseudoId::Scheme => (b":scheme", self.scheme.as_ref()?.as_str().as_bytes()),
            PseudoId::Authority => (b":authority", self.authority.as_ref()?.as_str().as_bytes()),
            PseudoId::Path => (b":path", self.path.as_ref()?.as_str().as_bytes()),
            PseudoId::Status => (b":status", self.status.as_ref()?.as_str().as_bytes()),
            PseudoId::Protocol => (b":protocol", self.protocol.as_ref()?.as_str().as_bytes()),
        };
        Some(HeaderField::borrowed(name, value, self.is_sensitive(id)))
    }
}

#[derive(Debug)]
pub enum HeaderError {
    InvalidHeaderName(String),
    InvalidHeaderValue(String),
    InvalidRequest(http::Error),
    MissingMethod,
    MissingStatus,
    MissingAuthority,
    ContradictedAuthority,
}

impl HeaderError {
    fn invalid_name<N>(name: N) -> Self
    where
        N: AsRef<[u8]>,
    {
        HeaderError::InvalidHeaderName(format!("{:?}", name.as_ref()))
    }

    fn invalid_value<N, V>(name: N, value: V) -> Self
    where
        N: AsRef<[u8]>,
        V: AsRef<[u8]>,
    {
        HeaderError::InvalidHeaderValue(format!(
            "{:?} {:?}",
            String::from_utf8_lossy(name.as_ref()),
            value.as_ref()
        ))
    }
}

impl std::error::Error for HeaderError {}

impl fmt::Display for HeaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HeaderError::InvalidHeaderName(h) => write!(f, "invalid header name: {}", h),
            HeaderError::InvalidHeaderValue(v) => write!(f, "invalid header value: {}", v),
            HeaderError::InvalidRequest(r) => write!(f, "invalid request: {}", r),
            HeaderError::MissingMethod => write!(f, "missing method in request headers"),
            HeaderError::MissingStatus => write!(f, "missing status in response headers"),
            HeaderError::MissingAuthority => write!(f, "missing authority"),
            HeaderError::ContradictedAuthority => {
                write!(f, "uri and authority field are in contradiction")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use bytes::BytesMut;

    use super::*;
    use crate::qpack;

    fn assert_ref_encoding_matches_owned(headers: Header) {
        let mut owned = BytesMut::new();
        let owned_size = qpack::encode_stateless(&mut owned, headers.clone()).unwrap();

        let mut borrowed = BytesMut::new();
        let borrowed_size = qpack::encode_stateless(&mut borrowed, headers.iter_ref()).unwrap();

        assert_eq!(borrowed, owned);
        assert_eq!(borrowed_size, owned_size);
    }

    #[test]
    fn request_has_no_authority_nor_host() {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
        //= type=test
        //# If the :scheme pseudo-header field identifies a scheme that has a
        //# mandatory authority component (including "http" and "https"), the
        //# request MUST contain either an :authority pseudo-header field or a
        //# Host header field.
        let headers = Header::try_from(vec![(b":method", Method::GET.as_str()).into()]).unwrap();
        assert!(headers.pseudo.authority.is_none());
        assert_matches!(
            headers.into_request_parts(),
            Err(HeaderError::MissingAuthority)
        );
    }

    #[test]
    fn request_has_empty_authority() {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
        //= type=test
        //# If these fields are present, they MUST NOT be
        //# empty.
        assert_matches!(
            Header::try_from(vec![
                (b":method", Method::GET.as_str()).into(),
                (b":authority", b"").into(),
            ]),
            Err(HeaderError::InvalidHeaderValue(_))
        );
    }

    #[test]
    fn request_has_empty_host() {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
        //= type=test
        //# If these fields are present, they MUST NOT be
        //# empty.
        let headers = Header::try_from(vec![
            (b":method", Method::GET.as_str()).into(),
            (b"host", b"").into(),
        ])
        .unwrap();
        assert_matches!(
            headers.into_request_parts(),
            Err(HeaderError::InvalidRequest(_))
        );
    }

    #[test]
    fn request_has_authority() {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
        //= type=test
        //# If the :scheme pseudo-header field identifies a scheme that has a
        //# mandatory authority component (including "http" and "https"), the
        //# request MUST contain either an :authority pseudo-header field or a
        //# Host header field.
        let headers = Header::try_from(vec![
            (b":method", Method::GET.as_str()).into(),
            (b":authority", b"test.com").into(),
        ])
        .unwrap();
        assert_matches!(headers.into_request_parts(), Ok(_));
    }

    #[test]
    fn request_has_host() {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
        //= type=test
        //# If the :scheme pseudo-header field identifies a scheme that has a
        //# mandatory authority component (including "http" and "https"), the
        //# request MUST contain either an :authority pseudo-header field or a
        //# Host header field.
        let headers = Header::try_from(vec![
            (b":method", Method::GET.as_str()).into(),
            (b"host", b"test.com").into(),
        ])
        .unwrap();
        assert!(headers.pseudo.authority.is_none());
        assert_matches!(headers.into_request_parts(), Ok(_));
    }

    #[test]
    fn request_has_same_host_and_authority() {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
        //= type=test
        //# If both fields are present, they MUST contain the same value.
        let headers = Header::try_from(vec![
            (b":method", Method::GET.as_str()).into(),
            (b":authority", b"test.com").into(),
            (b"host", b"test.com").into(),
        ])
        .unwrap();
        assert_matches!(headers.into_request_parts(), Ok(_));
    }
    #[test]
    fn request_has_different_host_and_authority() {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.3.1
        //= type=test
        //# If both fields are present, they MUST contain the same value.
        let headers = Header::try_from(vec![
            (b":method", Method::GET.as_str()).into(),
            (b":authority", b"authority.com").into(),
            (b"host", b"host.com").into(),
        ])
        .unwrap();
        assert_matches!(
            headers.into_request_parts(),
            Err(HeaderError::ContradictedAuthority)
        );
    }

    #[test]
    fn preserves_duplicate_headers() {
        let headers = Header::try_from(vec![
            (b":method", Method::GET.as_str()).into(),
            (b":authority", b"test.com").into(),
            (b"set-cookie", b"foo=foo").into(),
            (b"set-cookie", b"bar=bar").into(),
            (b"other-header", b"other-header-value").into(),
        ])
        .unwrap();

        assert_eq!(
            headers
                .clone()
                .into_iter()
                .filter(|h| h.name.as_ref() == b"set-cookie")
                .collect::<Vec<_>>(),
            vec![
                HeaderField {
                    name: std::borrow::Cow::Borrowed(b"set-cookie"),
                    value: std::borrow::Cow::Borrowed(b"foo=foo"),
                    sensitive: false,
                },
                HeaderField {
                    name: std::borrow::Cow::Borrowed(b"set-cookie"),
                    value: std::borrow::Cow::Borrowed(b"bar=bar"),
                    sensitive: false,
                }
            ]
        );
        assert_eq!(
            headers
                .into_iter()
                .filter(|h| h.name.as_ref() == b"other-header")
                .collect::<Vec<_>>(),
            vec![HeaderField {
                name: std::borrow::Cow::Borrowed(b"other-header"),
                value: std::borrow::Cow::Borrowed(b"other-header-value"),
                sensitive: false,
            },]
        );
    }

    #[test]
    fn decoded_regular_fields_preserve_borrowed_and_owned_values() {
        let mut owned = Vec::with_capacity(64);
        owned.extend_from_slice(b"owned-value");
        let owned_ptr = owned.as_ptr();
        let borrowed_ptr = b"0".as_ptr();
        let headers = Header::try_from(vec![
            HeaderField {
                name: Cow::Borrowed(b":status"),
                value: Cow::Borrowed(b"200"),
                sensitive: false,
            },
            HeaderField {
                name: Cow::Borrowed(b"content-length"),
                value: Cow::Borrowed(b"0"),
                sensitive: true,
            },
            HeaderField {
                name: Cow::Borrowed(b"x-owned"),
                value: Cow::Owned(owned),
                sensitive: false,
            },
        ])
        .unwrap();

        let (status, fields, _) = headers.into_response_parts().unwrap();

        assert_eq!(status, StatusCode::OK);
        assert_eq!(fields["content-length"], "0");
        assert!(fields["content-length"].is_sensitive());
        assert_eq!(fields["x-owned"], "owned-value");
        assert_eq!(fields["content-length"].as_bytes().as_ptr(), borrowed_ptr);
        assert_eq!(fields["x-owned"].as_bytes().as_ptr(), owned_ptr);
    }

    #[test]
    fn decoded_regular_field_errors_preserve_diagnostics() {
        let borrowed = Header::try_from(vec![HeaderField {
            name: Cow::Borrowed(b"x-invalid"),
            value: Cow::Borrowed(b"bad\nvalue"),
            sensitive: false,
        }])
        .unwrap_err();
        let owned = Header::try_from(vec![HeaderField {
            name: Cow::Owned(b"x-invalid".to_vec()),
            value: Cow::Owned(b"bad\nvalue".to_vec()),
            sensitive: false,
        }])
        .unwrap_err();

        assert_matches!(borrowed, HeaderError::InvalidHeaderValue(_));
        assert_matches!(owned, HeaderError::InvalidHeaderValue(_));
        assert_eq!(borrowed.to_string(), owned.to_string());
    }

    #[test]
    fn request_pseudo_sensitivity_survives_http_parts() {
        let headers = Header::try_from(vec![
            HeaderField::from((b":method", b"GET")).with_sensitive(true),
            HeaderField::from((b":scheme", b"https")),
            HeaderField::from((b":authority", b"example.com")),
            HeaderField::from((b":path", b"/")),
        ])
        .unwrap();
        let (method, uri, _protocol, fields, sensitivity) = headers.into_request_parts().unwrap();

        assert!(sensitivity.is_sensitive(PseudoId::Method));

        let mut extensions = Extensions::new();
        extensions.insert(sensitivity);
        let forwarded = Header::request(method, uri, fields, extensions).unwrap();
        let method = forwarded
            .into_iter()
            .find(|field| field.name.as_ref() == b":method")
            .unwrap();

        assert!(method.is_sensitive());
    }

    #[test]
    fn response_pseudo_sensitivity_survives_http_parts() {
        let headers = Header::try_from(vec![
            HeaderField::from((b":status", b"200")).with_sensitive(true),
        ])
        .unwrap();
        let (status, fields, sensitivity) = headers.into_response_parts().unwrap();

        assert!(sensitivity.is_sensitive(PseudoId::Status));

        let mut extensions = Extensions::new();
        extensions.insert(sensitivity);
        let forwarded = Header::response(status, fields, extensions);
        let status = forwarded
            .into_iter()
            .find(|field| field.name.as_ref() == b":status")
            .unwrap();

        assert!(status.is_sensitive());
    }

    #[test]
    fn test_pseudo_order_default() {
        let order = PseudoOrder::builder().build();
        assert_eq!(order.ids.len(), PseudoId::DEFAULT_STACK_SIZE);
        assert_eq!(order.ids, PseudoId::DEFAULT_IDS);
        assert!(std::mem::size_of::<PseudoOrder>() <= 8);
        assert!(std::mem::size_of::<Option<PseudoOrder>>() <= 8);
    }

    #[test]
    fn test_pseudo_order_duplicate() {
        let order = PseudoOrder::builder()
            .push(PseudoId::Scheme)
            .push(PseudoId::Scheme)
            .build();

        assert_eq!(order.ids.len(), PseudoId::DEFAULT_IDS.len());
        assert_eq!(order.ids[0], PseudoId::Scheme);
        assert_ne!(order.ids[1], PseudoId::Scheme);
    }

    #[test]
    fn test_pseudo_order_custom_chrome_masp() {
        // Chrome uses "masp" order: Method, Authority, Scheme, Path
        let order = PseudoOrder::builder()
            .push(PseudoId::Method)
            .push(PseudoId::Authority)
            .push(PseudoId::Scheme)
            .push(PseudoId::Path)
            .build();

        let mut headers = Header::request(
            Method::GET,
            Uri::from_static("https://example.com/test"),
            HeaderMap::new(),
            Extensions::default(),
        )
        .unwrap();
        headers.set_pseudo_order(order);

        let pseudo_fields: Vec<_> = headers
            .into_iter()
            .filter(|h| h.name.as_ref().starts_with(b":"))
            .map(|h| String::from_utf8_lossy(h.name.as_ref()).into_owned())
            .collect();

        assert_eq!(
            pseudo_fields,
            vec![":method", ":authority", ":scheme", ":path"]
        );
    }

    #[test]
    fn test_pseudo_order_custom_firefox_msap() {
        // Firefox uses "msap" order: Method, Scheme, Authority, Path
        let order = PseudoOrder::builder()
            .push(PseudoId::Method)
            .push(PseudoId::Scheme)
            .push(PseudoId::Authority)
            .push(PseudoId::Path)
            .build();

        let mut headers = Header::request(
            Method::GET,
            Uri::from_static("https://example.com/test"),
            HeaderMap::new(),
            Extensions::default(),
        )
        .unwrap();
        headers.set_pseudo_order(order);

        let pseudo_fields: Vec<_> = headers
            .into_iter()
            .filter(|h| h.name.as_ref().starts_with(b":"))
            .map(|h| String::from_utf8_lossy(h.name.as_ref()).into_owned())
            .collect();

        assert_eq!(
            pseudo_fields,
            vec![":method", ":scheme", ":authority", ":path"]
        );
    }

    #[test]
    fn test_pseudo_order_default_unchanged() {
        // Default order should match the original hardcoded behavior
        let headers = Header::request(
            Method::GET,
            Uri::from_static("https://example.com/test"),
            HeaderMap::new(),
            Extensions::default(),
        )
        .unwrap();

        let pseudo_fields: Vec<_> = headers
            .into_iter()
            .filter(|h| h.name.as_ref().starts_with(b":"))
            .map(|h| String::from_utf8_lossy(h.name.as_ref()).into_owned())
            .collect();

        assert_eq!(
            pseudo_fields,
            vec![":method", ":scheme", ":authority", ":path"]
        );
    }

    #[test]
    fn borrowed_encoding_matches_owned_for_request_variants() {
        assert_ref_encoding_matches_owned(
            Header::request(
                Method::GET,
                Uri::from_static("https://example.com/resource"),
                HeaderMap::new(),
                Extensions::default(),
            )
            .unwrap(),
        );

        let mut fields = HeaderMap::new();
        let mut sensitive = HeaderValue::from_static("first");
        sensitive.set_sensitive(true);
        fields.append("x-repeated", sensitive);
        fields.append("x-repeated", HeaderValue::from_static("second"));
        let mut extensions = Extensions::default();
        extensions.insert(
            PseudoOrder::builder()
                .push(PseudoId::Authority)
                .push(PseudoId::Method)
                .push(PseudoId::Path)
                .push(PseudoId::Scheme)
                .build(),
        );
        let mut pseudo_sensitivity = PseudoHeaderSensitivity::default();
        pseudo_sensitivity.set_sensitive(PseudoId::Authority, true);
        extensions.insert(pseudo_sensitivity);
        assert_ref_encoding_matches_owned(
            Header::request(
                Method::GET,
                Uri::from_static("https://example.com/custom"),
                fields,
                extensions,
            )
            .unwrap(),
        );

        assert_ref_encoding_matches_owned(
            Header::request(
                Method::CONNECT,
                Uri::from_static("https://example.com"),
                HeaderMap::new(),
                Extensions::default(),
            )
            .unwrap(),
        );

        let mut extensions = Extensions::default();
        extensions.insert(Protocol::WEBSOCKET);
        assert_ref_encoding_matches_owned(
            Header::request(
                Method::CONNECT,
                Uri::from_static("https://example.com/chat"),
                HeaderMap::new(),
                extensions,
            )
            .unwrap(),
        );
    }
}
