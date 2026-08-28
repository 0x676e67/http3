/*
 * https://www.rfc-editor.org/rfc/rfc9204.html#name-absolute-indexing
 * https://www.rfc-editor.org/rfc/rfc9204.html#name-relative-indexing
 * https://www.rfc-editor.org/rfc/rfc9204.html#name-post-base-indexing
 */

/*
 *  # Virtually infinite address space mapper.
 *
 *  It can be described as an infinitive growable list, with a visibility
 *  window that can only move in the direction of insertion.
 *
 *  Origin          Visible window
 *  /\         /===========^===========\
 *  ++++-------+ - + - + - + - + - + - +
 *  ||||       |   |   |   |   |   |   |  ==> Grow direction
 *  ++++-------+ - + - + - + - + - + - +
 *  \================v==================/
 *           Full Virtual Space
 *
 *
 *  QPACK indexing is 1-based for absolute index, and 0-based for relative's.
 *  Container (ex: list) indexing is 0-based.
 *
 *
 *  # Basics
 *
 *  inserted: number of insertion
 *  dropped : number of drop
 *  delta   : count of available elements
 *
 *  abs: absolute index
 *  rel: relative index
 *  pos: real index in memory container
 *  pst: post-base relative index (only with base index)
 *
 *    first      oldest              latest
 *    element    insertion           insertion
 *    (not       available           available
 *    available) |                   |
 *    |          |                   |
 *    v          v                   v
 *  + - +------+ - + - + - + - + - + - +  inserted: 21
 *  | a |      | p | q | r | s | t | u |  dropped: 15
 *  + - +------+ - + - + - + - + - + - +  delta: 21 - 15: 6 ^          ^                   ^ | |
 *    |
 * abs:-      abs:16              abs:21
 * rel:-      rel:5               rel:0
 * pos:-      pos:0               pos:6
 *
 *
 * # Base index
 * A base index can arbitrary shift the relative index.
 * The base index itself is an absolute index.
 *
 *                       base index: 17
 *                       |
 *                       v
 *  + - +------+ - + - + - + - + - + - +  inserted: 21
 *  | a |      | p | q | r | s | t | u |  dropped: 15
 *  + - +------+ - + - + - + - + - + - +  delta: 21 - 15: 6 ^          ^       ^           ^ | |
 *    |           |
 * abs:-      abs:16  abs:18      abs:21
 * rel:-      rel:2   rel:0       rel:-
 * pst:-      pst:-   pst:-       pst:2
 * pos:-      pos:0   pos:2       pos:6
 */

pub type RelativeIndex = usize;
pub type AbsoluteIndex = usize;

#[derive(Debug, PartialEq)]
pub enum Error {
    RelativeIndex(usize),
    PostbaseIndex(usize),
    Index(usize),
    AddressSpaceOverflow,
}

#[derive(Debug, Default)]
pub struct VirtualAddressSpace {
    inserted: usize,
    dropped: usize,
    delta: usize,
}

impl VirtualAddressSpace {
    #[cfg(test)]
    pub(crate) fn with_counters(inserted: usize, dropped: usize, delta: usize) -> Self {
        Self {
            inserted,
            dropped,
            delta,
        }
    }

    /// Checks whether another absolute index can be represented locally.
    ///
    /// QPACK does not bound the lifetime Total Number of Inserts. This
    /// implementation accepts it through `usize::MAX` and rejects the next
    /// encoder-stream insertion instead of wrapping the address space.
    ///
    /// See [RFC 9204, Section 7.4](https://www.rfc-editor.org/rfc/rfc9204.html#section-7.4).
    pub fn ensure_can_add(&self) -> Result<(), Error> {
        self.inserted
            .checked_add(1)
            .and_then(|_| self.delta.checked_add(1))
            .map(|_| ())
            .ok_or(Error::AddressSpaceOverflow)
    }

    pub fn add(&mut self) -> Result<AbsoluteIndex, Error> {
        let inserted = self
            .inserted
            .checked_add(1)
            .ok_or(Error::AddressSpaceOverflow)?;
        let delta = self
            .delta
            .checked_add(1)
            .ok_or(Error::AddressSpaceOverflow)?;

        self.inserted = inserted;
        self.delta = delta;
        Ok(inserted)
    }

    pub fn drop(&mut self) -> Result<(), Error> {
        let dropped = self
            .dropped
            .checked_add(1)
            .filter(|dropped| *dropped <= self.inserted)
            .ok_or(Error::AddressSpaceOverflow)?;
        let delta = self
            .delta
            .checked_sub(1)
            .ok_or(Error::AddressSpaceOverflow)?;

        self.dropped = dropped;
        self.delta = delta;
        Ok(())
    }

    pub fn relative(&self, index: RelativeIndex) -> Result<usize, Error> {
        self.inserted
            .checked_sub(index)
            .filter(|absolute| self.delta != 0 && *absolute > self.dropped)
            .and_then(|absolute| {
                self.dropped
                    .checked_add(1)
                    .and_then(|first| absolute.checked_sub(first))
            })
            .ok_or(Error::RelativeIndex(index))
    }

    pub fn evicted(&self, index: AbsoluteIndex) -> bool {
        index != 0 && index <= self.dropped
    }

    pub fn relative_base(&self, base: usize, index: RelativeIndex) -> Result<usize, Error> {
        base.checked_sub(index)
            .filter(|absolute| self.delta != 0 && *absolute > self.dropped)
            .and_then(|absolute| {
                self.dropped
                    .checked_add(1)
                    .and_then(|first| absolute.checked_sub(first))
            })
            .ok_or(Error::RelativeIndex(index))
    }

    pub fn post_base(&self, base: usize, index: RelativeIndex) -> Result<usize, Error> {
        base.checked_add(index)
            .filter(|absolute| {
                self.delta != 0 && *absolute < self.inserted && *absolute >= self.dropped
            })
            .and_then(|absolute| absolute.checked_sub(self.dropped))
            .ok_or(Error::PostbaseIndex(index))
    }

    pub fn index(&self, index: usize) -> Result<usize, Error> {
        if index >= self.delta {
            Err(Error::Index(index))
        } else {
            index
                .checked_add(self.dropped)
                .and_then(|absolute| absolute.checked_add(1))
                .ok_or(Error::Index(index))
        }
    }

    pub fn largest_ref(&self) -> usize {
        self.delta
    }

    pub fn total_inserted(&self) -> usize {
        self.inserted
    }
}

#[cfg(test)]
mod tests {
    use proptest::proptest;

    use super::*;

    #[test]
    fn test_no_relative_index_when_empty() {
        let vas = VirtualAddressSpace::default();
        let res = vas.relative_base(0, 0);
        assert_eq!(res, Err(Error::RelativeIndex(0)));
    }

    #[test]
    fn test_relative_underflow_protected() {
        let mut vas = VirtualAddressSpace::default();
        vas.add().unwrap();
        assert_eq!(vas.relative(2), Err(Error::RelativeIndex(2)));
    }

    proptest! {
        #[test]
        fn test_first_insertion_without_drop(
            ref count in 1..2200usize
        ) {
            let mut vas = VirtualAddressSpace::default();
            vas.add().unwrap();
            (1..*count).for_each(|_| { vas.add().unwrap(); });

            assert_eq!(vas.relative_base(*count, count - 1), Ok(0), "{:?}", vas);
        }

        #[test]
        fn test_first_insertion_with_drop(
            ref count in 2..2200usize
        ) {
            let mut vas = VirtualAddressSpace::default();
            vas.add().unwrap();
            (1..*count).for_each(|_| { vas.add().unwrap(); });
            (0..*count - 1).for_each(|_| vas.drop().unwrap());

            assert_eq!(vas.relative_base(*count, count - 1), Err(Error::RelativeIndex(count - 1)), "{:?}", vas);
        }

        #[test]
        fn test_last_insertion_without_drop(
            ref count in 1..2200usize
        ) {
            let mut vas = VirtualAddressSpace::default();
            (1..*count).for_each(|_| { vas.add().unwrap(); });
            vas.add().unwrap();

            assert_eq!(vas.relative_base(*count, 0), Ok(count -1),
                       "{:?}", vas);
        }

        #[test]
        fn test_last_insertion_with_drop(
            ref count in 2..2200usize
        ) {
            let mut vas = VirtualAddressSpace::default();
            (0..*count - 1).for_each(|_| { vas.add().unwrap(); });
            vas.add().unwrap();
            (0..*count - 1).for_each(|_| { vas.drop().unwrap(); });

            assert_eq!(vas.relative_base(*count, 0), Ok(0),
                       "{:?}", vas);
        }
    }

    #[test]
    fn test_post_base_index() {
        /*
         * Base index: D
         * Target value: B
         *
         * VAS: ]GFEDCBA]
         * abs:  1234567
         * rel:  3210---
         * pst:  ----012
         * pos:  0123456
         */
        let mut vas = VirtualAddressSpace::default();
        (0..7).for_each(|_| {
            vas.add().unwrap();
        });

        assert_eq!(vas.post_base(4, 1), Ok(5));
    }

    #[test]
    fn largest_ref() {
        let mut vas = VirtualAddressSpace::default();
        (0..7).for_each(|_| {
            vas.add().unwrap();
        });
        assert_eq!(vas.largest_ref(), 7);
    }

    #[test]
    fn relative() {
        let mut vas = VirtualAddressSpace::default();

        (0..7).for_each(|_| {
            vas.add().unwrap();
        });

        assert_eq!(vas.relative(0), Ok(6));
        assert_eq!(vas.relative(1), Ok(5));
        assert_eq!(vas.relative(6), Ok(0));
        assert_eq!(vas.relative(7), Err(Error::RelativeIndex(7)));
    }

    #[test]
    fn absolute_from_real_index() {
        let mut vas = VirtualAddressSpace::default();
        assert_eq!(vas.index(0), Err(Error::Index(0)));
        vas.add().unwrap();
        assert_eq!(vas.index(0), Ok(1));
        vas.add().unwrap();
        vas.drop().unwrap();
        assert_eq!(vas.index(0), Ok(2));
        vas.drop().unwrap();
        assert_eq!(vas.index(0), Err(Error::Index(0)));
        vas.add().unwrap();
        vas.add().unwrap();
        assert_eq!(vas.index(0), Ok(3));
        assert_eq!(vas.index(1), Ok(4));
        assert_eq!(vas.index(2), Err(Error::Index(2)));
    }

    #[test]
    fn evicted() {
        let mut vas = VirtualAddressSpace::default();
        assert!(!vas.evicted(0));
        assert!(!vas.evicted(1));
        vas.add().unwrap();
        vas.add().unwrap();
        assert!(!vas.evicted(1));
        vas.drop().unwrap();
        assert!(!vas.evicted(0));
        assert!(vas.evicted(1));
        assert!(!vas.evicted(2));
        vas.drop().unwrap();
        assert!(vas.evicted(2));
    }

    #[test]
    fn cumulative_insert_count_does_not_wrap() {
        let mut vas = VirtualAddressSpace::with_counters(usize::MAX, usize::MAX, 0);

        assert_eq!(vas.ensure_can_add(), Err(Error::AddressSpaceOverflow));
        assert_eq!(vas.add(), Err(Error::AddressSpaceOverflow));
        assert_eq!(vas.total_inserted(), usize::MAX);
        assert_eq!(vas.delta, 0);
    }

    #[test]
    fn live_entry_at_insert_limit_keeps_valid_indexes() {
        let mut vas = VirtualAddressSpace::with_counters(usize::MAX, usize::MAX - 1, 1);

        assert_eq!(vas.relative(0), Ok(0));
        assert_eq!(vas.relative_base(usize::MAX, 0), Ok(0));
        assert_eq!(vas.post_base(usize::MAX - 1, 0), Ok(0));
        assert_eq!(vas.index(0), Ok(usize::MAX));
        assert_eq!(vas.add(), Err(Error::AddressSpaceOverflow));

        vas.drop().unwrap();
        assert_eq!(vas.total_inserted(), usize::MAX);
        assert_eq!(vas.delta, 0);
    }

    #[test]
    fn dropping_an_empty_address_space_is_rejected_without_mutation() {
        let mut vas = VirtualAddressSpace::default();

        assert_eq!(vas.drop(), Err(Error::AddressSpaceOverflow));
        assert_eq!(vas.total_inserted(), 0);
        assert_eq!(vas.dropped, 0);
        assert_eq!(vas.delta, 0);
    }
}
