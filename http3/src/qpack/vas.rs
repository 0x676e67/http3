/*
 * Maps QPACK's growing insertion sequence onto positions in the retained
 * dynamic-table window.
 *
 * RFC absolute indices start at zero. This mapper stores one-based insertion
 * numbers because Required Insert Count and Base are counts: insertion number
 * N corresponds to RFC absolute index N - 1. Relative and post-base indices,
 * along with the backing container positions, start at zero.
 *
 * For example, after 21 insertions and 15 evictions, insertion numbers 16
 * through 21 occupy container positions 0 through 5. Relative index 0 selects
 * insertion 21. With Base 17, relative index 0 selects insertion 17 and
 * post-base index 0 selects insertion 18.
 *
 * https://www.rfc-editor.org/rfc/rfc9204.html#section-3.2.4
 * https://www.rfc-editor.org/rfc/rfc9204.html#section-3.2.5
 * https://www.rfc-editor.org/rfc/rfc9204.html#section-3.2.6
 * https://www.rfc-editor.org/rfc/rfc9204.html#section-4.5.1.2
 */

pub type RelativeIndex = usize;
/// Internal one-based insertion number, equal to the RFC absolute index plus one.
pub type AbsoluteIndex = usize;

#[derive(Debug, PartialEq)]
pub enum Error {
    RelativeIndex(usize),
    PostbaseIndex(usize),
    Index(usize),
}

#[derive(Debug, Default)]
pub struct VirtualAddressSpace {
    inserted: usize,
    dropped: usize,
    delta: usize,
}

impl VirtualAddressSpace {
    pub fn add(&mut self) -> AbsoluteIndex {
        self.inserted += 1;
        self.delta += 1;
        self.inserted
    }

    pub fn drop(&mut self) {
        self.dropped += 1;
        self.delta -= 1;
    }

    pub fn relative(&self, index: RelativeIndex) -> Result<usize, Error> {
        if self.inserted < index || self.delta == 0 || self.inserted - index <= self.dropped {
            Err(Error::RelativeIndex(index))
        } else {
            Ok(self.inserted - self.dropped - index - 1)
        }
    }

    pub fn evicted(&self, index: AbsoluteIndex) -> bool {
        index != 0 && index <= self.dropped
    }

    pub fn relative_base(&self, base: usize, index: RelativeIndex) -> Result<usize, Error> {
        if self.delta == 0 || index > base || base - index <= self.dropped {
            Err(Error::RelativeIndex(index))
        } else {
            Ok(base - self.dropped - index - 1)
        }
    }

    pub fn post_base(&self, base: usize, index: RelativeIndex) -> Result<usize, Error> {
        if self.delta == 0 || base + index >= self.inserted || base + index < self.dropped {
            Err(Error::PostbaseIndex(index))
        } else {
            Ok(base + index - self.dropped)
        }
    }

    pub fn index(&self, index: usize) -> Result<usize, Error> {
        if index >= self.delta {
            Err(Error::Index(index))
        } else {
            Ok(index + self.dropped + 1)
        }
    }

    pub fn largest_ref(&self) -> usize {
        self.inserted - self.dropped
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
        vas.add();
        assert_eq!(vas.relative(2), Err(Error::RelativeIndex(2)));
    }

    proptest! {
        #[test]
        fn test_first_insertion_without_drop(
            ref count in 1..2200usize
        ) {
            let mut vas = VirtualAddressSpace::default();
            vas.add();
            (1..*count).for_each(|_| { vas.add(); });

            assert_eq!(vas.relative_base(*count, count - 1), Ok(0), "{:?}", vas);
        }

        #[test]
        fn test_first_insertion_with_drop(
            ref count in 2..2200usize
        ) {
            let mut vas = VirtualAddressSpace::default();
            vas.add();
            (1..*count).for_each(|_| { vas.add(); });
            (0..*count - 1).for_each(|_| vas.drop());

            assert_eq!(vas.relative_base(*count, count - 1), Err(Error::RelativeIndex(count - 1)), "{:?}", vas);
        }

        #[test]
        fn test_last_insertion_without_drop(
            ref count in 1..2200usize
        ) {
            let mut vas = VirtualAddressSpace::default();
            (1..*count).for_each(|_| { vas.add(); });
            vas.add();

            assert_eq!(vas.relative_base(*count, 0), Ok(count -1),
                       "{:?}", vas);
        }

        #[test]
        fn test_last_insertion_with_drop(
            ref count in 2..2200usize
        ) {
            let mut vas = VirtualAddressSpace::default();
            (0..*count - 1).for_each(|_| { vas.add(); });
            vas.add();
            (0..*count - 1).for_each(|_| { vas.drop(); });

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
            vas.add();
        });

        assert_eq!(vas.post_base(4, 1), Ok(5));
    }

    #[test]
    fn largest_ref() {
        let mut vas = VirtualAddressSpace::default();
        (0..7).for_each(|_| {
            vas.add();
        });
        assert_eq!(vas.largest_ref(), 7);
    }

    #[test]
    fn relative() {
        let mut vas = VirtualAddressSpace::default();

        (0..7).for_each(|_| {
            vas.add();
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
        vas.add();
        assert_eq!(vas.index(0), Ok(1));
        vas.add();
        vas.drop();
        assert_eq!(vas.index(0), Ok(2));
        vas.drop();
        assert_eq!(vas.index(0), Err(Error::Index(0)));
        vas.add();
        vas.add();
        assert_eq!(vas.index(0), Ok(3));
        assert_eq!(vas.index(1), Ok(4));
        assert_eq!(vas.index(2), Err(Error::Index(2)));
    }

    #[test]
    fn evicted() {
        let mut vas = VirtualAddressSpace::default();
        assert!(!vas.evicted(0));
        assert!(!vas.evicted(1));
        vas.add();
        vas.add();
        assert!(!vas.evicted(1));
        vas.drop();
        assert!(!vas.evicted(0));
        assert!(vas.evicted(1));
        assert!(!vas.evicted(2));
        vas.drop();
        assert!(vas.evicted(2));
    }
}
