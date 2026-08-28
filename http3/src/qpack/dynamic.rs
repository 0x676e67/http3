use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet, HashMap, VecDeque, hash_map::Entry},
};

use super::{field::HeaderField, static_::StaticTable};
use crate::qpack::vas::{self, VirtualAddressSpace};

#[derive(Debug, PartialEq)]
pub enum Error {
    BadRelativeIndex(usize),
    BadPostbaseIndex(usize),
    BadIndex(usize),
    MaxTableSizeReached,
    MaximumTableSizeTooLarge,
    UnknownStreamId(u64),
    NoTrackingData,
    InvalidTrackingCount,
    InvalidInsertCountIncrement,
    AddressSpaceOverflow,
}

pub struct DynamicTableDecoder<'a> {
    table: &'a DynamicTable,
    base: usize,
    required_ref: usize,
}

impl<'a> DynamicTableDecoder<'a> {
    pub(super) fn get_relative(&self, index: usize) -> Result<&HeaderField, Error> {
        // A field section cannot reference an insertion newer than its declared
        // Required Insert Count.
        // https://www.rfc-editor.org/rfc/rfc9204.html#section-4.5.1.1
        let absolute = self
            .base
            .checked_sub(index)
            .filter(|absolute| *absolute != 0 && *absolute <= self.required_ref)
            .ok_or(Error::BadRelativeIndex(index))?;
        let real_index = self.table.vas.relative_base(self.base, index)?;
        debug_assert_eq!(self.table.vas.index(real_index), Ok(absolute));
        self.table
            .fields
            .get(real_index)
            .ok_or(Error::BadIndex(real_index))
    }

    pub(super) fn get_postbase(&self, index: usize) -> Result<&HeaderField, Error> {
        // Post-base references are also bounded by Required Insert Count.
        // https://www.rfc-editor.org/rfc/rfc9204.html#section-4.5.1.1
        self.base
            .checked_add(index)
            .and_then(|absolute| absolute.checked_add(1))
            .filter(|absolute| *absolute <= self.required_ref)
            .ok_or(Error::BadPostbaseIndex(index))?;
        let real_index = self.table.vas.post_base(self.base, index)?;
        self.table
            .fields
            .get(real_index)
            .ok_or(Error::BadIndex(real_index))
    }
}

pub struct DynamicTableEncoder<'a> {
    table: &'a mut DynamicTable,
    base: usize,
    committed: bool,
    stream_id: u64,
    allow_blocking: bool,
    block_refs: HashMap<usize, usize>,
}

impl<'a> Drop for DynamicTableEncoder<'a> {
    fn drop(&mut self) {
        if !self.committed {
            let refs = std::mem::take(&mut self.block_refs);
            let _ = self.table.release_refs(&refs);
        }
    }
}

impl<'a> DynamicTableEncoder<'a> {
    pub(super) fn max_size(&self) -> usize {
        self.table.max_size
    }

    pub(super) fn base(&self) -> usize {
        self.base
    }

    pub(super) fn total_inserted(&self) -> usize {
        self.table.total_inserted()
    }

    pub(super) fn commit(&mut self, required_insert_count: usize) {
        // A zero Required Insert Count never produces a Section
        // Acknowledgment, so only dynamic field sections belong in this queue.
        // https://www.rfc-editor.org/rfc/rfc9204.html#section-4.4.1
        if required_insert_count != 0 {
            let refs = std::mem::take(&mut self.block_refs);
            self.table
                .track_block(self.stream_id, required_insert_count, refs);
        }
        self.committed = true;
    }

    pub(super) fn find(&mut self, field: &HeaderField) -> DynamicLookupResult {
        self.lookup_result(self.table.field_map.get(field).cloned())
    }

    fn lookup_result(&mut self, absolute: Option<usize>) -> DynamicLookupResult {
        match absolute {
            Some(absolute)
                if (absolute <= self.table.largest_known_received || self.allow_blocking)
                    && absolute <= self.base =>
            {
                self.track_ref(absolute);
                DynamicLookupResult::Relative {
                    index: self.base - absolute,
                    absolute,
                }
            }
            Some(absolute)
                if (absolute <= self.table.largest_known_received || self.allow_blocking)
                    && absolute > self.base =>
            {
                self.track_ref(absolute);
                DynamicLookupResult::PostBase {
                    index: absolute - self.base - 1,
                    absolute,
                }
            }
            _ => DynamicLookupResult::NotFound,
        }
    }

    pub(super) fn insert(&mut self, field: &HeaderField) -> Result<DynamicInsertionResult, Error> {
        // A newly inserted entry is not known to the decoder yet. Referencing
        // it is allowed only when this stream can consume a blocked-stream
        // slot (or already consumes one).
        // https://www.rfc-editor.org/rfc/rfc9204.html#section-2.1.2
        if !self.allow_blocking {
            return Ok(DynamicInsertionResult::NotInserted(
                self.find_name(&field.name),
            ));
        }

        let index = match self.table.insert(field.clone()) {
            Ok(Some(index)) => index,
            Err(Error::MaxTableSizeReached) | Ok(None) => {
                return Ok(DynamicInsertionResult::NotInserted(
                    self.find_name(&field.name),
                ));
            }
            Err(e) => return Err(e),
        };
        self.track_ref(index);

        let field_index = match self.table.field_map.entry(field.clone()) {
            Entry::Occupied(mut e) => {
                let ref_index = e.insert(index);
                self.table
                    .name_map
                    .entry(field.name.clone())
                    .and_modify(|i| *i = index);

                Some((
                    ref_index,
                    DynamicInsertionResult::Duplicated {
                        relative: index - ref_index - 1,
                        postbase: index - self.base - 1,
                        absolute: index,
                    },
                ))
            }
            Entry::Vacant(e) => {
                e.insert(index);
                None
            }
        };

        if let Some((ref_index, result)) = field_index {
            self.track_ref(ref_index);
            return Ok(result);
        }

        if let Some(static_idx) = StaticTable::find_name(&field.name) {
            return Ok(DynamicInsertionResult::InsertedWithStaticNameRef {
                postbase: index - self.base - 1,
                index: static_idx,
                absolute: index,
            });
        }

        let result = match self.table.name_map.entry(field.name.clone()) {
            Entry::Occupied(mut e) => {
                let ref_index = e.insert(index);
                self.track_ref(ref_index);

                DynamicInsertionResult::InsertedWithNameRef {
                    postbase: index - self.base - 1,
                    relative: index - ref_index - 1,
                    absolute: index,
                }
            }
            Entry::Vacant(e) => {
                e.insert(index);
                DynamicInsertionResult::Inserted {
                    postbase: index - self.base - 1,
                    absolute: index,
                }
            }
        };
        Ok(result)
    }

    pub(super) fn find_name(&mut self, name: &[u8]) -> DynamicLookupResult {
        if let Some(index) = StaticTable::find_name(name) {
            return DynamicLookupResult::Static(index);
        }

        self.lookup_result(self.table.name_map.get(name).cloned())
    }

    fn track_ref(&mut self, reference: usize) {
        self.block_refs
            .entry(reference)
            .and_modify(|c| *c += 1)
            .or_insert(1);
        self.table.track_ref(reference);
    }
}

#[derive(Debug, PartialEq)]
pub enum DynamicLookupResult {
    Static(usize),
    Relative { index: usize, absolute: usize },
    PostBase { index: usize, absolute: usize },
    NotFound,
}

#[derive(Debug, PartialEq)]
pub enum DynamicInsertionResult {
    Inserted {
        postbase: usize,
        absolute: usize,
    },
    Duplicated {
        relative: usize,
        postbase: usize,
        absolute: usize,
    },
    InsertedWithNameRef {
        postbase: usize,
        relative: usize,
        absolute: usize,
    },
    InsertedWithStaticNameRef {
        postbase: usize,
        index: usize,
        absolute: usize,
    },
    NotInserted(DynamicLookupResult),
}

#[derive(Debug)]
struct TrackedFieldSection {
    required_insert_count: usize,
    refs: HashMap<usize, usize>,
}

#[derive(Debug, Default)]
struct TrackedStream {
    field_sections: VecDeque<TrackedFieldSection>,
    max_required_insert_count: usize,
}

impl TrackedStream {
    fn push(&mut self, field_section: TrackedFieldSection) {
        self.max_required_insert_count = self
            .max_required_insert_count
            .max(field_section.required_insert_count);
        self.field_sections.push_back(field_section);
    }

    fn pop_front(&mut self) -> Option<TrackedFieldSection> {
        let field_section = self.field_sections.pop_front()?;
        // If this was the maximum, acknowledging it advances KRC to at least
        // this value, so every lower remaining count is already unblocked. A
        // later count above KRC will also be above this cached value.
        if self.field_sections.is_empty() {
            self.max_required_insert_count = 0;
        }
        Some(field_section)
    }

    fn is_empty(&self) -> bool {
        self.field_sections.is_empty()
    }
}

#[derive(Default)]
pub struct DynamicTable {
    fields: VecDeque<HeaderField>,
    curr_size: usize,
    max_size: usize,
    vas: VirtualAddressSpace,
    field_map: HashMap<HeaderField, usize>,
    name_map: HashMap<Cow<'static, [u8]>, usize>,
    track_map: BTreeMap<usize, usize>,
    track_blocks: HashMap<u64, TrackedStream>,
    largest_known_received: usize,
    blocked_max: u64,
    // Ordered by Required Insert Count so decoder feedback can release all
    // newly unblocked streams without scanning every tracked stream.
    blocked_streams: BTreeSet<(usize, u64)>,
}

impl DynamicTable {
    pub fn new() -> DynamicTable {
        DynamicTable::default()
    }

    pub fn decoder(&self, base: usize, required_ref: usize) -> DynamicTableDecoder<'_> {
        DynamicTableDecoder {
            table: self,
            base,
            required_ref,
        }
    }

    pub fn encoder(&mut self, stream_id: u64) -> DynamicTableEncoder<'_> {
        for (idx, field) in self.fields.iter().enumerate() {
            self.name_map
                .insert(field.name.clone(), self.vas.index(idx).unwrap());
            self.field_map
                .insert(field.clone(), self.vas.index(idx).unwrap());
        }

        let allow_blocking = self.stream_is_blocked(stream_id) || !self.blocked_limit_reached();

        DynamicTableEncoder {
            base: self.vas.largest_ref(),
            table: self,
            block_refs: HashMap::new(),
            committed: false,
            stream_id,
            allow_blocking,
        }
    }

    /// Sets the number of streams the peer permits this encoder to risk blocking.
    ///
    /// HTTP/3 carries this setting as a QUIC variable-length integer, and QPACK
    /// sets no smaller limit. Callers can use a lower value to bound the memory
    /// needed to track outstanding references.
    ///
    /// See [RFC 9204, Section 2.1.2](https://www.rfc-editor.org/rfc/rfc9204.html#section-2.1.2),
    /// [Section 7.3](https://www.rfc-editor.org/rfc/rfc9204.html#section-7.3), and
    /// [RFC 9114, Section 7.2.4](https://www.rfc-editor.org/rfc/rfc9114.html#section-7.2.4).
    pub fn set_max_blocked(&mut self, max: u64) -> Result<(), Error> {
        // TODO handle existing data
        self.blocked_max = max;
        Ok(())
    }

    pub fn set_max_size(&mut self, size: usize) -> Result<(), Error> {
        if size >= self.max_size {
            self.max_size = size;
            return Ok(());
        }

        let required = self.max_size - size;

        if let Some(to_evict) = self.can_free(required)? {
            self.evict(to_evict)?;
        }

        self.max_size = size;
        Ok(())
    }

    pub(super) fn put(&mut self, field: HeaderField) -> Result<(), Error> {
        let index = match self.insert(field.clone())? {
            Some(index) => index,
            None => return Ok(()),
        };

        self.update_maps(field, index);
        Ok(())
    }

    /// Adds an entry received from the peer's encoder stream.
    ///
    /// A decoder resolves dynamic references by index, so it does not populate
    /// the field and name maps used by `DynamicTableEncoder`. Decoded field
    /// bytes remain independently owned; sharing slices of a connection receive
    /// buffer here could retain a much larger allocation for the table's
    /// lifetime, as seen in <https://github.com/hyperium/h2/issues/923>.
    ///
    /// See [RFC 9204, Section 3.2](https://www.rfc-editor.org/rfc/rfc9204.html#section-3.2)
    /// and [Section 3.2.3](https://www.rfc-editor.org/rfc/rfc9204.html#section-3.2.3).
    pub(super) fn put_decoder(&mut self, field: HeaderField) -> Result<(), Error> {
        self.insert(field)?.ok_or(Error::MaxTableSizeReached)?;
        Ok(())
    }

    fn update_maps(&mut self, field: HeaderField, index: usize) {
        self.field_map
            .entry(field.clone())
            .and_modify(|e| *e = index)
            .or_insert(index);

        if StaticTable::find_name(&field.name).is_some() {
            return;
        }

        self.name_map
            .entry(field.name.clone())
            .and_modify(|e| *e = index)
            .or_insert(index);
    }

    pub(super) fn get_relative(&self, index: usize) -> Result<&HeaderField, Error> {
        let real_index = self.vas.relative(index)?;
        self.fields
            .get(real_index)
            .ok_or(Error::BadIndex(real_index))
    }

    pub(super) fn total_inserted(&self) -> usize {
        self.vas.total_inserted()
    }

    #[cfg(test)]
    pub(crate) fn set_empty_insert_count_for_test(&mut self, insert_count: usize) {
        assert!(self.fields.is_empty());
        self.vas = VirtualAddressSpace::with_counters(insert_count, insert_count, 0);
    }

    /// Applies a Section Acknowledgment to the earliest outstanding dynamic
    /// field section on `stream_id`.
    ///
    /// The acknowledged Required Insert Count can advance the Known Received
    /// Count. Only this field section's references are released; later field
    /// sections on the same stream remain outstanding.
    ///
    /// See [RFC 9204, Section 2.1.4](https://www.rfc-editor.org/rfc/rfc9204.html#section-2.1.4)
    /// and [Section 2.2.2.1](https://www.rfc-editor.org/rfc/rfc9204.html#section-2.2.2.1).
    pub(super) fn acknowledge_section(&mut self, stream_id: u64) -> Result<(), Error> {
        let required_insert_count = {
            let stream = self
                .track_blocks
                .get(&stream_id)
                .ok_or(Error::UnknownStreamId(stream_id))?;
            let field_section = stream.field_sections.front().ok_or(Error::NoTrackingData)?;
            self.validate_refs(&field_section.refs)?;
            field_section.required_insert_count
        };

        if required_insert_count > self.total_inserted() {
            return Err(Error::InvalidTrackingCount);
        }

        let (previous_required, current_required, field_section, stream_empty) = {
            let stream = self
                .track_blocks
                .get_mut(&stream_id)
                .ok_or(Error::UnknownStreamId(stream_id))?;
            let previous_required = stream.max_required_insert_count;
            let field_section = stream.pop_front().ok_or(Error::NoTrackingData)?;
            (
                previous_required,
                stream.max_required_insert_count,
                field_section,
                stream.is_empty(),
            )
        };

        self.advance_largest_received(required_insert_count);
        self.replace_blocked_requirement(stream_id, previous_required, current_required);
        self.release_refs_validated(&field_section.refs);

        if stream_empty {
            self.track_blocks.remove(&stream_id);
        }
        Ok(())
    }

    /// Releases every outstanding dynamic-table reference on `stream_id`.
    ///
    /// Stream Cancellation covers all field sections on the stream, not only
    /// response headers and trailers. A cancellation for a stream without
    /// outstanding dynamic references is harmless.
    ///
    /// See [RFC 9204, Section 2.2.2.2](https://www.rfc-editor.org/rfc/rfc9204.html#section-2.2.2.2)
    /// and [Section 4.4.2](https://www.rfc-editor.org/rfc/rfc9204.html#section-4.4.2).
    pub(super) fn cancel_stream(&mut self, stream_id: u64) -> Result<(), Error> {
        let Some(stream) = self.track_blocks.get(&stream_id) else {
            return Ok(());
        };

        let mut refs = HashMap::new();
        for field_section in &stream.field_sections {
            for (&reference, &count) in &field_section.refs {
                let tracked = refs.entry(reference).or_insert(0usize);
                *tracked = tracked
                    .checked_add(count)
                    .ok_or(Error::InvalidTrackingCount)?;
            }
        }
        self.validate_refs(&refs)?;

        let previous_required = stream.max_required_insert_count;
        self.track_blocks.remove(&stream_id);
        self.blocked_streams.remove(&(previous_required, stream_id));
        self.release_refs_validated(&refs);
        Ok(())
    }

    fn insert(&mut self, field: HeaderField) -> Result<Option<usize>, Error> {
        if self.max_size == 0 {
            return Ok(None);
        }

        let to_evict = match self.can_free(field.mem_size())? {
            None => return Ok(None),
            Some(to_evict) => to_evict,
        };

        // Check the lifetime insertion limit before eviction or table mutation.
        // An implementation can limit accepted integer values, but exceeding
        // that limit on the encoder stream is a connection error.
        // https://www.rfc-editor.org/rfc/rfc9204.html#section-7.4
        self.vas.ensure_can_add()?;
        self.evict(to_evict)?;

        self.curr_size += field.mem_size();
        self.fields.push_back(field);
        let absolute = self.vas.add()?;

        Ok(Some(absolute))
    }

    fn evict(&mut self, to_evict: usize) -> Result<(), Error> {
        for _ in 0..to_evict {
            let field = self.fields.pop_front().ok_or(Error::MaxTableSizeReached)?; //TODO better type
            self.curr_size -= field.mem_size();

            self.vas.drop()?;

            if !self.name_map.is_empty()
                && self
                    .name_map
                    .get(field.name.as_ref())
                    .is_some_and(|index| self.vas.evicted(*index))
            {
                self.name_map.remove(field.name.as_ref());
            }

            if !self.field_map.is_empty()
                && self
                    .field_map
                    .get(&field)
                    .is_some_and(|index| self.vas.evicted(*index))
            {
                self.field_map.remove(&field);
            }
        }
        Ok(())
    }

    fn can_free(&mut self, required: usize) -> Result<Option<usize>, Error> {
        if required > self.max_size {
            return Err(Error::MaxTableSizeReached);
        }

        if self.max_size - self.curr_size >= required {
            return Ok(Some(0));
        }
        let lower_bound = self.max_size - required;

        let mut hypothetic_mem_size = self.curr_size;
        let mut evictable = 0;

        for (idx, to_evict) in self.fields.iter().enumerate() {
            if hypothetic_mem_size <= lower_bound {
                break;
            }

            if self.is_tracked(self.vas.index(idx).unwrap()) {
                // TODO handle out of bounds error
                break;
            }

            evictable += 1;
            hypothetic_mem_size -= to_evict.mem_size();
        }

        if required <= self.max_size - hypothetic_mem_size {
            Ok(Some(evictable))
        } else {
            Ok(None)
        }
    }

    fn track_ref(&mut self, reference: usize) {
        self.track_map
            .entry(reference)
            .and_modify(|c| *c += 1)
            .or_insert(1);
    }

    fn is_tracked(&self, reference: usize) -> bool {
        matches!(self.track_map.get(&reference), Some(count) if *count > 0)
    }

    fn track_block(
        &mut self,
        stream_id: u64,
        required_insert_count: usize,
        refs: HashMap<usize, usize>,
    ) {
        let (previous_required, current_required) = {
            let stream = self.track_blocks.entry(stream_id).or_default();
            let previous_required = stream.max_required_insert_count;
            stream.push(TrackedFieldSection {
                required_insert_count,
                refs,
            });
            (previous_required, stream.max_required_insert_count)
        };
        self.replace_blocked_requirement(stream_id, previous_required, current_required);
    }

    fn validate_refs(&self, refs: &HashMap<usize, usize>) -> Result<(), Error> {
        for (&reference, &count) in refs {
            if self
                .track_map
                .get(&reference)
                .is_none_or(|tracked| *tracked < count)
            {
                return Err(Error::InvalidTrackingCount);
            }
        }
        Ok(())
    }

    fn release_refs(&mut self, refs: &HashMap<usize, usize>) -> Result<(), Error> {
        self.validate_refs(refs)?;
        self.release_refs_validated(refs);
        Ok(())
    }

    fn release_refs_validated(&mut self, refs: &HashMap<usize, usize>) {
        for (&reference, &count) in refs {
            let remove = if let Some(tracked) = self.track_map.get_mut(&reference) {
                *tracked -= count;
                *tracked == 0
            } else {
                false
            };
            if remove {
                self.track_map.remove(&reference);
            }
        }
    }

    fn stream_is_blocked(&self, stream_id: u64) -> bool {
        self.track_blocks
            .get(&stream_id)
            .is_some_and(|stream| stream.max_required_insert_count > self.largest_known_received)
    }

    fn blocked_limit_reached(&self) -> bool {
        usize::try_from(self.blocked_max)
            .is_ok_and(|blocked_max| self.blocked_streams.len() >= blocked_max)
    }

    fn replace_blocked_requirement(
        &mut self,
        stream_id: u64,
        previous_required: usize,
        current_required: usize,
    ) {
        if previous_required > self.largest_known_received {
            self.blocked_streams.remove(&(previous_required, stream_id));
        }
        if current_required > self.largest_known_received {
            self.blocked_streams.insert((current_required, stream_id));
        }
    }

    fn advance_largest_received(&mut self, largest_known_received: usize) {
        if largest_known_received <= self.largest_known_received {
            return;
        }

        self.largest_known_received = largest_known_received;
        while self
            .blocked_streams
            .first()
            .is_some_and(|(required, _)| *required <= largest_known_received)
        {
            self.blocked_streams.pop_first();
        }
    }

    /// Applies an Insert Count Increment received from the decoder.
    ///
    /// Zero is invalid, and the resulting Known Received Count cannot exceed
    /// the number of insertions sent by this encoder. Validation happens before
    /// the table is changed. Either case is a `QPACK_DECODER_STREAM_ERROR`.
    ///
    /// See [RFC 9204, Section 4.4.3](https://www.rfc-editor.org/rfc/rfc9204.html#section-4.4.3).
    pub fn update_largest_received(&mut self, increment: usize) -> Result<(), Error> {
        if increment == 0 {
            return Err(Error::InvalidInsertCountIncrement);
        }

        let largest_known_received = self
            .largest_known_received
            .checked_add(increment)
            .filter(|count| *count <= self.total_inserted())
            .ok_or(Error::InvalidInsertCountIncrement)?;

        self.advance_largest_received(largest_known_received);
        Ok(())
    }

    pub(super) fn max_mem_size(&self) -> usize {
        self.max_size
    }
}

impl From<vas::Error> for Error {
    fn from(e: vas::Error) -> Self {
        match e {
            vas::Error::RelativeIndex(e) => Error::BadRelativeIndex(e),
            vas::Error::PostbaseIndex(e) => Error::BadPostbaseIndex(e),
            vas::Error::Index(e) => Error::BadIndex(e),
            vas::Error::AddressSpaceOverflow => Error::AddressSpaceOverflow,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::identity_op)]

    use super::*;
    use crate::qpack::{static_::StaticTable, tests::helpers::build_table};

    const STREAM_ID: u64 = 0x4;

    // Test on table size
    /**
     * https://tools.ietf.org/html/rfc7541#section-4.1
     * "The size of the dynamic table is the sum of the size of its entries."
     */
    #[test]
    fn test_table_size_is_sum_of_its_entries() {
        let mut table = build_table();

        let fields: [(&'static str, &'static str); 2] = [
            ("Name", "Value"),
            ("Another-Name", ""), // no value
        ];
        let table_size = 4 + 5 + 12 + 0 + /* ESTIMATED_OVERHEAD_BYTES */ 32 * 2;

        for pair in fields.iter() {
            let field = HeaderField::new(pair.0, pair.1);
            table.insert(field).unwrap();
        }

        assert_eq!(table.curr_size, table_size);
    }

    #[test]
    fn table_capacity_accepts_one_gibibyte() {
        let mut table = build_table();
        let capacity = 1usize << 30;

        // The decoder's advertised setting is the limit on dynamic table capacity.
        // https://www.rfc-editor.org/rfc/rfc9204.html#section-3.2.3
        assert_eq!(table.set_max_size(capacity), Ok(()));
        assert_eq!(table.max_mem_size(), capacity);
    }

    /**
     * https://www.rfc-editor.org/rfc/rfc9204.html#name-dynamic-table-capacity-and-
     * "This mechanism can be used to completely clear entries from the
     *  dynamic table by setting a maximum size of 0, which can subsequently
     *  be restored."
     */
    #[test]
    fn test_maximum_table_size_can_reach_zero() {
        let mut table = build_table();
        let res_change = table.set_max_size(0);
        assert!(res_change.is_ok());
        assert_eq!(table.max_mem_size(), 0);
    }

    // Test duplicated fields

    /**
     * https://www.rfc-editor.org/rfc/rfc9204.html#name-dynamic-table
     * "The dynamic table can contain duplicate entries (i.e., entries with
     *  the same name and same value).  Therefore, duplicate entries MUST NOT
     *  be treated as an error by a decoder."
     */
    #[test]
    fn test_table_supports_duplicated_entries() {
        let mut table = build_table();
        table.insert(HeaderField::new("Name", "Value")).unwrap();
        table.insert(HeaderField::new("Name", "Value")).unwrap();
        assert_eq!(table.fields.len(), 2);
    }

    // Test adding fields

    /** functional test */
    #[test]
    fn test_add_field_fitting_free_space() {
        let mut table = build_table();

        table.insert(HeaderField::new("Name", "Value")).unwrap();
        assert_eq!(table.fields.len(), 1);
    }

    #[test]
    fn insertion_limit_is_checked_before_table_mutation() {
        let mut table = DynamicTable::new();
        table.set_max_size(64).unwrap();
        table.set_empty_insert_count_for_test(usize::MAX);

        assert_eq!(
            table.put_decoder(HeaderField::new("name", "value")),
            Err(Error::AddressSpaceOverflow)
        );
        assert_eq!(table.total_inserted(), usize::MAX);
        assert!(table.fields.is_empty());
        assert_eq!(table.curr_size, 0);
    }

    /** functional test */
    #[test]
    fn test_add_field_reduce_free_space() {
        let mut table = build_table();

        let field = HeaderField::new("Name", "Value");
        table.insert(field.clone()).unwrap();
        assert_eq!(table.curr_size, field.mem_size());
    }

    /**
     * https://www.rfc-editor.org/rfc/rfc9204.html#name-dynamic-table-capacity-and-
     * "Before a new entry is added to the dynamic table, entries are evicted
     *  from the end of the dynamic table until the size of the dynamic table
     *  is less than or equal to (maximum size - new entry size) or until the
     *  table is empty."
     */
    #[test]
    fn test_add_field_drop_older_fields_to_have_enough_space() {
        let mut table = build_table();

        table.insert(HeaderField::new("Name-A", "Value-A")).unwrap();
        table.insert(HeaderField::new("Name-B", "Value-B")).unwrap();
        let perfect_size = table.curr_size;
        assert!(table.set_max_size(perfect_size).is_ok());

        let field = HeaderField::new("Name-Large", "Value-Large");
        table.insert(field).unwrap();

        assert_eq!(table.fields.len(), 1);
        assert_eq!(
            table.fields.front(),
            Some(&HeaderField::new("Name-Large", "Value-Large"))
        );
    }

    /**
     * https://www.rfc-editor.org/rfc/rfc9204.html#name-dynamic-table-capacity-and-
     * "It is an error if the encoder attempts to add an entry that is
     * larger than the dynamic table capacity; the decoder MUST treat
     * this as a connection error of type QPACK_ENCODER_STREAM_ERROR."
     */
    #[test]
    fn test_try_add_field_larger_than_maximum_size() {
        let mut table = build_table();

        table.insert(HeaderField::new("Name-A", "Value-A")).unwrap();
        let perfect_size = table.curr_size;
        assert!(table.set_max_size(perfect_size).is_ok());

        let field = HeaderField::new("Name-Large", "Value-Large");
        assert_eq!(table.insert(field), Err(Error::MaxTableSizeReached));
    }

    fn insert_fields(table: &mut DynamicTable, fields: Vec<HeaderField>) {
        for field in fields {
            table.insert(field).unwrap();
        }
    }

    /**
     * https://www.rfc-editor.org/rfc/rfc9204.html#name-dynamic-table-capacity-and-
     * "This mechanism can be used to completely clear entries from the
     *  dynamic table by setting a maximum size of 0, which can subsequently
     *  be restored."
     */
    #[test]
    fn test_set_maximum_table_size_to_zero_clear_entries() {
        let mut table = build_table();
        insert_fields(
            &mut table,
            vec![
                HeaderField::new("Name", "Value"),
                HeaderField::new("Name", "Value"),
            ],
        );
        assert_eq!(table.fields.len(), 2);

        table.set_max_size(0).unwrap();
        assert_eq!(table.fields.len(), 0);
    }

    /** functional test */
    #[test]
    fn test_eviction_is_fifo() {
        let mut table = build_table();

        insert_fields(
            &mut table,
            vec![
                HeaderField::new("Name-A", "Value-A"),
                HeaderField::new("Name-B", "Value-B"),
            ],
        );
        let perfect_size = table.curr_size;
        assert!(table.set_max_size(perfect_size).is_ok());

        insert_fields(&mut table, vec![HeaderField::new("Name-C", "Value-C")]);

        assert_eq!(
            table.fields.front(),
            Some(&HeaderField::new("Name-B", "Value-B"))
        );
        assert_eq!(
            table.fields.get(1),
            Some(&HeaderField::new("Name-C", "Value-C"))
        );
        assert_eq!(table.fields.get(2), None);
    }

    #[test]
    fn encoder_build() {
        let mut table = build_table();
        let field_a = HeaderField::new("Name-A", "Value-A");
        let field_b = HeaderField::new("Name-B", "Value-B");
        insert_fields(&mut table, vec![field_a.clone(), field_b.clone()]);

        let encoder = table.encoder(STREAM_ID);
        assert_eq!(encoder.base, 2);
        assert_eq!(encoder.table.name_map.len(), 2);
        assert_eq!(encoder.table.field_map.len(), 2);
        assert_eq!(encoder.table.name_map.get(&field_a.name).copied(), Some(1));
        assert_eq!(encoder.table.name_map.get(&field_b.name).copied(), Some(2));
        assert_eq!(encoder.table.field_map.get(&field_a).copied(), Some(1));
        assert_eq!(encoder.table.field_map.get(&field_b).copied(), Some(2));
    }

    #[test]
    fn encoder_find_relative() {
        let mut table = build_table();
        let field_a = HeaderField::new("Name-A", "Value-A");
        let field_b = HeaderField::new("Name-B", "Value-B");
        insert_fields(&mut table, vec![field_a.clone(), field_b.clone()]);

        let mut encoder = table.encoder(STREAM_ID);
        assert_eq!(
            encoder.find(&field_a),
            DynamicLookupResult::Relative {
                index: 1,
                absolute: 1
            }
        );
        assert_eq!(
            encoder.find(&field_b),
            DynamicLookupResult::Relative {
                index: 0,
                absolute: 2
            }
        );
        assert_eq!(
            encoder.find(&HeaderField::new("Name-C", "Value-C")),
            DynamicLookupResult::NotFound
        );
        assert_eq!(
            encoder.find_name(&field_a.name),
            DynamicLookupResult::Relative {
                index: 1,
                absolute: 1
            }
        );
        assert_eq!(
            encoder.find_name(&field_b.name),
            DynamicLookupResult::Relative {
                index: 0,
                absolute: 2
            }
        );
        assert_eq!(
            encoder.find_name(&b"Name-C"[..]),
            DynamicLookupResult::NotFound
        );
    }

    #[test]
    fn encoder_insert() {
        let mut table = build_table();
        let field_a = HeaderField::new("Name-A", "Value-A");
        let field_b = HeaderField::new("Name-B", "Value-B");
        insert_fields(&mut table, vec![field_a.clone(), field_b.clone()]);

        let mut encoder = table.encoder(STREAM_ID);
        assert_eq!(
            encoder.insert(&field_a),
            Ok(DynamicInsertionResult::Duplicated {
                postbase: 0,
                relative: 1,
                absolute: 3
            })
        );
        assert_eq!(
            encoder.insert(&field_b.with_value("New Value-B")),
            Ok(DynamicInsertionResult::InsertedWithNameRef {
                postbase: 1,
                relative: 1,
                absolute: 4,
            })
        );
        assert_eq!(
            encoder.insert(&field_b.with_value("Newer Value-B")),
            Ok(DynamicInsertionResult::InsertedWithNameRef {
                postbase: 2,
                relative: 0,
                absolute: 5,
            })
        );

        let field_c = HeaderField::new("Name-C", "Value-C");
        assert_eq!(
            encoder.insert(&field_c),
            Ok(DynamicInsertionResult::Inserted {
                postbase: 3,
                absolute: 6,
            })
        );

        assert_eq!(encoder.table.fields.len(), 6);

        assert_eq!(
            encoder.table.fields,
            &[
                field_a.clone(),
                field_b.clone(),
                field_a.clone(),
                field_b.with_value("New Value-B"),
                field_b.with_value("Newer Value-B"),
                field_c
            ]
        );
        assert_eq!(encoder.table.name_map.get(&field_a.name).copied(), Some(3));
        assert_eq!(encoder.table.name_map.get(&field_b.name).copied(), Some(5));
        assert_eq!(encoder.table.field_map.get(&field_a).copied(), Some(3));
        assert_eq!(encoder.table.field_map.get(&field_b).copied(), Some(2));
        assert_eq!(
            encoder
                .table
                .field_map
                .get(&field_b.with_value("New Value-B"))
                .copied(),
            Some(4)
        );
        assert_eq!(
            encoder
                .table
                .field_map
                .get(&field_b.with_value("Newer Value-B"))
                .copied(),
            Some(5)
        );
    }

    #[test]
    fn encode_insert_in_empty() {
        let mut table = build_table();
        let field_a = HeaderField::new("Name-A", "Value-A");

        let mut encoder = table.encoder(STREAM_ID);
        assert_eq!(
            encoder.insert(&field_a),
            Ok(DynamicInsertionResult::Inserted {
                postbase: 0,
                absolute: 1,
            })
        );

        assert_eq!(encoder.table.fields.len(), 1);
        assert_eq!(encoder.table.fields, std::slice::from_ref(&field_a));
        assert_eq!(encoder.table.name_map.get(&field_a.name).copied(), Some(1));
        assert_eq!(encoder.table.field_map.get(&field_a).copied(), Some(1));
    }

    #[test]
    fn insert_static() {
        let mut table = build_table();
        let field = HeaderField::new(":method", "Value-A");
        table.insert(field.clone()).unwrap();

        assert_eq!(StaticTable::find_name(&field.name), Some(15));
        let mut encoder = table.encoder(STREAM_ID);
        assert_eq!(
            encoder.insert(&field),
            Ok(DynamicInsertionResult::Duplicated {
                relative: 0,
                postbase: 0,
                absolute: 2
            })
        );
        assert_eq!(
            encoder.insert(&field.with_value("Value-B")),
            Ok(DynamicInsertionResult::InsertedWithStaticNameRef {
                postbase: 1,
                index: 15,
                absolute: 3
            })
        );
        assert_eq!(
            encoder.insert(&HeaderField::new(":path", "/baz")),
            Ok(DynamicInsertionResult::InsertedWithStaticNameRef {
                postbase: 2,
                index: 1,
                absolute: 4,
            })
        );
        assert_eq!(encoder.table.fields.len(), 4);
    }

    #[test]
    fn cannot_insert_field_greater_than_total_size() {
        let mut table = build_table();
        table.set_max_size(33).unwrap();
        let mut encoder = table.encoder(4);
        assert_eq!(
            encoder.insert(&HeaderField::new("foo", "bar")),
            Ok(DynamicInsertionResult::NotInserted(
                DynamicLookupResult::NotFound
            ))
        );
    }

    #[test]
    fn encoder_maps_are_cleaned_on_eviction() {
        let mut table = build_table();
        table.set_max_size(64).unwrap();

        {
            let mut encoder = table.encoder(4);
            assert_eq!(
                encoder.insert(&HeaderField::new("foo", "bar")),
                Ok(DynamicInsertionResult::Inserted {
                    postbase: 0,
                    absolute: 1
                })
            );
            encoder.commit(1);
        }
        table.acknowledge_section(4).unwrap();

        {
            let mut encoder = table.encoder(4);
            assert_eq!(
                encoder.insert(&HeaderField::new("foo2", "bar")),
                Ok(DynamicInsertionResult::Inserted {
                    postbase: 0,
                    absolute: 2
                })
            );
            assert_eq!(
                encoder.find(&HeaderField::new("foo", "bar")),
                DynamicLookupResult::NotFound
            );
            assert_eq!(encoder.find_name(b"foo"), DynamicLookupResult::NotFound);
            encoder.commit(2);
        }
    }

    #[test]
    fn encoder_can_evict_unreferenced() {
        let mut table = build_table();
        table.set_max_size(63).unwrap();
        table.insert(HeaderField::new("foo", "bar")).unwrap();

        assert_eq!(table.fields.len(), 1);
        assert_eq!(
            table.encoder(4).insert(&HeaderField::new("baz", "quxx")),
            Ok(DynamicInsertionResult::Inserted {
                postbase: 0,
                absolute: 2,
            })
        );
        assert_eq!(table.fields.len(), 1);
    }

    #[test]
    fn encoder_insertion_tracks_ref() {
        let mut table = build_table();
        let mut encoder = table.encoder(4);
        assert_eq!(
            encoder.insert(&HeaderField::new("baz", "quxx")),
            Ok(DynamicInsertionResult::Inserted {
                postbase: 0,
                absolute: 1,
            })
        );
        assert_eq!(encoder.table.track_map.get(&1).copied(), Some(1));
        assert_eq!(encoder.block_refs.get(&1).copied(), Some(1));
    }

    #[test]
    fn encoder_insertion_refs_committed() {
        let mut table = build_table();
        let stream_id = 42;
        {
            let mut encoder = table.encoder(stream_id);
            for idx in 1..4 {
                encoder
                    .insert(&HeaderField::new(format!("foo{}", idx), "quxx"))
                    .unwrap();
            }
            assert_eq!(encoder.block_refs.len(), 3);
            encoder.commit(3);
        }

        for idx in 1..4 {
            assert!(table.is_tracked(idx));
            assert_eq!(table.track_map.get(&1), Some(&1));
        }
        let track_blocks = table.track_blocks;
        let block = track_blocks
            .get(&stream_id)
            .unwrap()
            .field_sections
            .front()
            .unwrap();
        assert_eq!(block.required_insert_count, 3);
        assert_eq!(block.refs.get(&1), Some(&1));
        assert_eq!(block.refs.get(&2), Some(&1));
        assert_eq!(block.refs.get(&3), Some(&1));
    }

    #[test]
    fn encoder_insertion_refs_not_committed() {
        let mut table = build_table();
        table.track_blocks = HashMap::new();
        let stream_id = 42;
        {
            let mut encoder = table.encoder(stream_id);
            for idx in 1..4 {
                encoder
                    .insert(&HeaderField::new(format!("foo{}", idx), "quxx"))
                    .unwrap();
            }
            assert_eq!(encoder.block_refs.len(), 3);
        } // dropped without ::commit()

        assert_eq!(table.track_map.len(), 0);
        assert_eq!(table.track_blocks.len(), 0);
    }

    #[test]
    fn encoder_insertion_with_ref_tracks_both() {
        let mut table = build_table();
        table.insert(HeaderField::new("foo", "bar")).unwrap();
        table.track_blocks = HashMap::new();

        let stream_id = 42;
        let mut encoder = table.encoder(stream_id);
        assert_eq!(
            encoder.insert(&HeaderField::new("foo", "quxx")),
            Ok(DynamicInsertionResult::InsertedWithNameRef {
                postbase: 0,
                relative: 0,
                absolute: 2,
            })
        );

        assert_eq!(encoder.table.track_map.get(&1), Some(&1));
        assert_eq!(encoder.table.track_map.get(&2), Some(&1));
        assert_eq!(encoder.block_refs.get(&1), Some(&1));
        assert_eq!(encoder.block_refs.get(&2), Some(&1));
    }

    #[test]
    fn encoder_ref_count_are_incremented() {
        let mut table = build_table();
        table.insert(HeaderField::new("foo", "bar")).unwrap();
        table.track_blocks = HashMap::new();
        table.track_ref(1);

        let stream_id = 42;
        {
            let mut encoder = table.encoder(stream_id);
            encoder.track_ref(1);
            encoder.track_ref(2);
            encoder.track_ref(2);

            assert_eq!(encoder.table.track_map.get(&1), Some(&2));
            assert_eq!(encoder.table.track_map.get(&2), Some(&2));
            assert_eq!(encoder.block_refs.get(&1), Some(&1));
            assert_eq!(encoder.block_refs.get(&2), Some(&2));
        }

        // Dropping an uncommitted field section releases its references.
        assert_eq!(table.track_map.get(&1), Some(&1));
        assert_eq!(table.track_map.get(&2), None);
    }

    #[test]
    fn encoder_does_not_evict_referenced() {
        let mut table = build_table();
        table.set_max_size(95).unwrap();
        table.insert(HeaderField::new("foo", "bar")).unwrap();

        let stream_id = 42;
        let mut encoder = table.encoder(stream_id);
        assert_eq!(
            encoder.insert(&HeaderField::new("foo", "quxx")),
            Ok(DynamicInsertionResult::InsertedWithNameRef {
                postbase: 0,
                relative: 0,
                absolute: 2,
            })
        );
        assert!(encoder.table.is_tracked(1));
        assert_eq!(
            encoder.insert(&HeaderField::new("foo", "baz")),
            Ok(DynamicInsertionResult::NotInserted(
                DynamicLookupResult::PostBase {
                    index: 0,
                    absolute: 2,
                }
            ))
        );
        assert_eq!(encoder.table.fields.len(), 2);
    }

    fn tracked_table(stream_id: u64) -> DynamicTable {
        let mut table = build_table();
        table.track_blocks = HashMap::new();
        {
            let mut encoder = table.encoder(stream_id);
            for idx in 1..4 {
                encoder
                    .insert(&HeaderField::new(format!("foo{}", idx), "quxx"))
                    .unwrap();
            }
            assert_eq!(encoder.block_refs.len(), 3);
            encoder.commit(3);
        }
        table
    }

    #[test]
    fn acknowledge_section() {
        let mut table = tracked_table(42);
        assert_eq!(table.track_map.len(), 3);
        assert_eq!(table.track_blocks.len(), 1);
        table.acknowledge_section(42).unwrap();
        assert_eq!(table.track_map.len(), 0);
        assert_eq!(table.track_blocks.len(), 0);
        assert_eq!(table.largest_known_received, 3);
        assert!(table.blocked_streams.is_empty());
    }

    #[test]
    fn acknowledge_section_rejects_missing_reference_count() {
        let mut table = tracked_table(42);
        table.track_map.remove(&2);
        assert_eq!(
            table.acknowledge_section(42),
            Err(Error::InvalidTrackingCount)
        );
    }

    #[test]
    fn acknowledge_section_rejects_wrong_reference_count() {
        let mut table = tracked_table(42);
        table.track_blocks.entry(42).and_modify(|x| {
            x.field_sections
                .get_mut(0)
                .unwrap()
                .refs
                .entry(2)
                .and_modify(|c| *c += 1);
        });
        assert_eq!(
            table.acknowledge_section(42),
            Err(Error::InvalidTrackingCount)
        );
    }

    #[test]
    fn acknowledge_section_rejects_unknown_stream() {
        let mut table = tracked_table(41);
        assert_eq!(
            table.acknowledge_section(42),
            Err(Error::UnknownStreamId(42))
        );
    }

    #[test]
    fn acknowledgments_follow_field_section_order() {
        const STREAM_ID: u64 = 42;
        let mut table = tracked_table(STREAM_ID);
        {
            // encode trailers
            let mut encoder = table.encoder(STREAM_ID);
            for idx in 4..=9 {
                encoder
                    .insert(&HeaderField::new(format!("foo{}", idx), "quxx"))
                    .unwrap();
            }
            assert_eq!(encoder.block_refs.len(), 6);
            encoder.commit(9);
        }
        assert_eq!(table.blocked_streams.len(), 1);
        assert_eq!(table.acknowledge_section(STREAM_ID), Ok(()));
        assert_eq!(table.largest_known_received, 3);
        assert!(!table.is_tracked(3));
        assert!(table.is_tracked(5));
        assert!(table.blocked_streams.contains(&(9, STREAM_ID)));
        assert_eq!(table.acknowledge_section(STREAM_ID), Ok(()));
        assert_eq!(table.largest_known_received, 9);
        assert!(!table.is_tracked(9));
        assert_eq!(
            table.acknowledge_section(STREAM_ID),
            Err(Error::UnknownStreamId(STREAM_ID))
        );
    }

    #[test]
    fn put_updates_maps() {
        let mut table = tracked_table(42);
        assert_eq!(table.name_map.len(), 3);
        assert_eq!(table.field_map.len(), 3);

        table.put(HeaderField::new("foo", "bar")).unwrap();
        assert_eq!(table.name_map.len(), 4);
        assert_eq!(table.field_map.len(), 4);

        let field = HeaderField::new("foo1", "quxx");
        table.put(field.clone()).unwrap();
        assert_eq!(table.name_map.len(), 4);
        assert_eq!(table.field_map.len(), 4);
        assert_eq!(table.name_map.get(&b"foo1"[..]), Some(&5usize));
        assert_eq!(table.field_map.get(&field), Some(&5usize));
    }

    #[test]
    fn decoder_insert_avoids_encoder_lookup_maps() {
        let mut table = DynamicTable::new();
        table
            .set_max_size(HeaderField::new("a", "1").mem_size())
            .unwrap();

        table.put_decoder(HeaderField::new("a", "1")).unwrap();
        let latest = HeaderField::new("b", "2");
        table.put_decoder(latest.clone()).unwrap();

        // Decoder references use table positions. Evicting an older entry does
        // not require the encoder's field or name lookup maps.
        // https://www.rfc-editor.org/rfc/rfc9204.html#section-3.2.2
        assert_eq!(table.fields.len(), 1);
        assert_eq!(table.get_relative(0), Ok(&latest));
        assert!(table.field_map.is_empty());
        assert!(table.name_map.is_empty());
    }

    #[test]
    fn zero_required_insert_count_is_not_queued_for_acknowledgment() {
        let mut table = build_table();

        table.encoder(42).commit(0);

        assert!(table.track_blocks.is_empty());
        assert_eq!(
            table.acknowledge_section(42),
            Err(Error::UnknownStreamId(42))
        );
    }

    #[test]
    fn multiple_field_sections_block_one_stream_and_acknowledge_in_order() {
        let mut table = build_table();
        table.set_max_blocked(1).unwrap();

        {
            let mut encoder = table.encoder(42);
            assert!(matches!(
                encoder.insert(&HeaderField::new("first", "value")),
                Ok(DynamicInsertionResult::Inserted { absolute: 1, .. })
            ));
            encoder.commit(1);
        }
        {
            // The stream already consumes the only blocked-stream slot, so a
            // later field section on it may still reference a new insertion.
            let mut encoder = table.encoder(42);
            assert!(matches!(
                encoder.insert(&HeaderField::new("second", "value")),
                Ok(DynamicInsertionResult::Inserted { absolute: 2, .. })
            ));
            encoder.commit(2);
        }

        assert_eq!(table.blocked_streams.len(), 1);
        assert!(table.blocked_streams.contains(&(2, 42)));
        assert_eq!(table.track_blocks[&42].field_sections.len(), 2);

        table.acknowledge_section(42).unwrap();
        assert_eq!(table.largest_known_received, 1);
        assert_eq!(table.track_blocks[&42].field_sections.len(), 1);
        assert!(table.blocked_streams.contains(&(2, 42)));
        assert!(!table.is_tracked(1));
        assert!(table.is_tracked(2));

        table.acknowledge_section(42).unwrap();
        assert_eq!(table.largest_known_received, 2);
        assert!(table.track_blocks.is_empty());
        assert!(table.blocked_streams.is_empty());
        assert!(table.track_map.is_empty());
    }

    #[test]
    fn stream_cancellation_releases_every_field_section_and_blocked_slot() {
        let mut table = build_table();
        table.set_max_blocked(1).unwrap();

        for absolute in 1..=3 {
            let mut encoder = table.encoder(42);
            assert!(matches!(
                encoder.insert(&HeaderField::new(format!("field{absolute}"), "value")),
                Ok(DynamicInsertionResult::Inserted {
                    absolute: inserted,
                    ..
                }) if inserted == absolute
            ));
            encoder.commit(absolute);
        }

        assert_eq!(table.track_blocks[&42].field_sections.len(), 3);
        assert_eq!(table.blocked_streams.len(), 1);
        table.cancel_stream(42).unwrap();
        assert!(table.track_blocks.is_empty());
        assert!(table.track_map.is_empty());
        assert!(table.blocked_streams.is_empty());

        // Cancellation does not acknowledge insertions, but it frees the
        // blocked-stream slot for another stream.
        assert_eq!(table.largest_known_received, 0);
        assert!(matches!(
            table
                .encoder(44)
                .insert(&HeaderField::new("replacement", "value")),
            Ok(DynamicInsertionResult::Inserted { absolute: 4, .. })
        ));
        assert_eq!(table.cancel_stream(42), Ok(()));
    }

    #[test]
    fn acknowledged_entries_can_be_referenced_without_a_blocked_slot() {
        let mut table = build_table();
        let field = HeaderField::new("known", "value");
        table.put(field.clone()).unwrap();
        table.update_largest_received(1).unwrap();
        table.set_max_blocked(0).unwrap();

        assert_eq!(
            table.encoder(42).find(&field),
            DynamicLookupResult::Relative {
                index: 0,
                absolute: 1,
            }
        );
    }

    #[test]
    fn blocked_stream_registered() {
        let mut table = tracked_table(42);
        table.set_max_blocked(100).unwrap();

        assert_eq!(table.blocked_streams.len(), 1);
        assert!(table.blocked_streams.contains(&(3, 42)));
    }

    #[test]
    fn blocked_stream_not_registered() {
        let mut table = tracked_table(42);
        table.set_max_blocked(100).unwrap();

        table
            .encoder(44)
            .insert(&HeaderField::new("foo", "bar"))
            .unwrap();
        // encoder dropped without commit

        assert_eq!(table.blocked_streams.len(), 1);
        assert!(table.blocked_streams.contains(&(3, 42)));
    }

    #[test]
    fn blocked_stream_register_accumulate() {
        let mut table = tracked_table(42);
        table.set_max_blocked(100).unwrap();

        {
            let mut encoder = table.encoder(44);

            assert_eq!(
                encoder.find(&HeaderField::new("foo3", "quxx")),
                DynamicLookupResult::Relative {
                    index: 0,
                    absolute: 3,
                }
            );
            // This field section references foo3 (absolute index 3).
            encoder.commit(3);
        }

        assert_eq!(table.blocked_streams.len(), 2);
        assert!(table.blocked_streams.contains(&(3, 42)));
        assert!(table.blocked_streams.contains(&(3, 44)));
    }

    #[test]
    fn blocked_stream_register_put_smaller() {
        let mut table = tracked_table(42);
        table.set_max_blocked(100).unwrap();

        {
            let mut encoder = table.encoder(44);
            assert_eq!(
                encoder.find(&HeaderField::new("foo2", "quxx")),
                DynamicLookupResult::Relative {
                    index: 1,
                    absolute: 2,
                }
            );
            encoder.commit(2);
        }

        assert_eq!(table.blocked_streams.len(), 2);
        assert!(table.blocked_streams.contains(&(2, 44)));
    }

    #[test]
    fn blocked_stream_register_put_larger() {
        let mut table = tracked_table(42);
        table.set_max_blocked(100).unwrap();
        table.put(HeaderField::new("foo4", "quxx")).unwrap();
        table.put(HeaderField::new("foo5", "quxx")).unwrap();

        {
            let mut encoder = table.encoder(44);
            assert_eq!(
                encoder.find(&HeaderField::new("foo5", "quxx")),
                DynamicLookupResult::Relative {
                    index: 0,
                    absolute: 5,
                }
            );
            encoder.commit(5);
        }

        assert_eq!(table.blocked_streams.len(), 2);
        assert!(table.blocked_streams.contains(&(5, 44)));
    }

    #[test]
    fn unblock_stream_smaller() {
        let mut table = tracked_table(42);
        table.set_max_blocked(100).unwrap();

        {
            let mut encoder = table.encoder(44);
            assert_eq!(
                encoder.find(&HeaderField::new("foo2", "quxx")),
                DynamicLookupResult::Relative {
                    index: 1,
                    absolute: 2,
                }
            );
            encoder.commit(2);
        }

        assert_eq!(table.blocked_streams.len(), 2);
        assert!(table.blocked_streams.contains(&(2, 44)));

        table.update_largest_received(2).unwrap();

        assert_eq!(table.blocked_streams.len(), 1);
        assert!(!table.blocked_streams.contains(&(2, 44)));
        assert!(table.blocked_streams.contains(&(3, 42)));
    }

    #[test]
    fn unblock_stream_larger() {
        let mut table = tracked_table(42);
        table.set_max_blocked(100).unwrap();
        table.put(HeaderField::new("foo4", "quxx")).unwrap();
        table.put(HeaderField::new("foo5", "quxx")).unwrap();

        {
            let mut encoder = table.encoder(44);
            assert!(matches!(
                encoder.find(&HeaderField::new("foo2", "quxx")),
                DynamicLookupResult::Relative { absolute: 2, .. }
            ));
            encoder.commit(2);
        }
        {
            let mut encoder = table.encoder(46);
            assert!(matches!(
                encoder.find(&HeaderField::new("foo5", "quxx")),
                DynamicLookupResult::Relative { absolute: 5, .. }
            ));
            encoder.commit(5);
        }

        assert_eq!(table.blocked_streams.len(), 3);
        assert!(table.blocked_streams.contains(&(2, 44)));
        assert!(table.blocked_streams.contains(&(3, 42)));
        assert!(table.blocked_streams.contains(&(5, 46)));

        table.update_largest_received(5).unwrap();

        assert!(table.blocked_streams.is_empty());
    }

    #[test]
    fn unblock_stream_decrement() {
        let mut table = tracked_table(42);
        table.set_max_blocked(100).unwrap();

        {
            let mut encoder = table.encoder(44);
            assert!(matches!(
                encoder.find(&HeaderField::new("foo3", "quxx")),
                DynamicLookupResult::Relative { absolute: 3, .. }
            ));
            encoder.commit(3);
        }

        assert_eq!(table.blocked_streams.len(), 2);
        assert!(table.blocked_streams.contains(&(3, 42)));
        assert!(table.blocked_streams.contains(&(3, 44)));

        // Only three insertions were sent. A larger value would violate the
        // Insert Count Increment limit in RFC 9204 Section 4.4.3.
        // https://www.rfc-editor.org/rfc/rfc9204.html#section-4.4.3
        table.update_largest_received(3).unwrap();

        assert!(table.blocked_streams.is_empty());
    }

    #[test]
    fn no_insert_when_max_blocked_0() {
        let mut table = build_table();
        table.set_max_blocked(0).unwrap();

        assert_eq!(
            table.encoder(44).insert(&HeaderField::new("foo", "bar")),
            Ok(DynamicInsertionResult::NotInserted(
                DynamicLookupResult::NotFound
            ))
        );
    }

    #[test]
    fn blocked_stream_limit_accepts_full_settings_range() {
        let mut table = DynamicTable::new();
        let max = crate::proto::varint::VarInt::MAX.into_inner();

        assert_eq!(table.set_max_blocked(max), Ok(()));
        assert_eq!(table.blocked_max, max);
    }

    #[test]
    fn no_insert_after_max_blocked_reached() {
        let mut table = tracked_table(42);
        table.set_max_blocked(2).unwrap();

        {
            let mut encoder = table.encoder(44);
            assert_eq!(
                encoder.insert(&HeaderField::new("foo", "bar")),
                Ok(DynamicInsertionResult::Inserted {
                    postbase: 0,
                    absolute: 4
                })
            );
            encoder.commit(4);
        }

        assert_eq!(table.blocked_streams.len(), 2);

        let mut encoder = table.encoder(46);
        assert_eq!(
            encoder.insert(&HeaderField::new("foo99", "bar")),
            Ok(DynamicInsertionResult::NotInserted(
                DynamicLookupResult::NotFound
            ))
        );
    }

    #[test]
    fn insert_again_after_encoder_ack() {
        let mut table = tracked_table(42);
        table.set_max_blocked(1).unwrap();

        assert_eq!(table.blocked_streams.len(), 1);

        {
            let mut encoder = table.encoder(44);
            assert_eq!(
                encoder.insert(&HeaderField::new("foo99", "bar")),
                Ok(DynamicInsertionResult::NotInserted(
                    DynamicLookupResult::NotFound
                ))
            );
            encoder.commit(0);
        }

        table.update_largest_received(3).unwrap();
        assert!(table.blocked_streams.is_empty());

        let mut encoder = table.encoder(46);
        assert_eq!(
            encoder.insert(&HeaderField::new("foo", "bar")),
            Ok(DynamicInsertionResult::Inserted {
                postbase: 0,
                absolute: 4
            })
        );
    }

    #[test]
    fn overflowing_insert_count_increment_does_not_mutate_table() {
        let mut table = tracked_table(42);
        table.update_largest_received(1).unwrap();

        assert_eq!(
            table.update_largest_received(usize::MAX),
            Err(Error::InvalidInsertCountIncrement)
        );
        assert_eq!(table.largest_known_received, 1);
        assert_eq!(table.blocked_streams.len(), 1);
    }
}
