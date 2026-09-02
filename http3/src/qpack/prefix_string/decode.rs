// Independently implemented from RFC 7541 Appendix B and this crate's encoder codebook.
// Performance background and license references:
// https://github.com/hyperium/h2/pull/927
// https://github.com/hyperium/h2/commit/62f878b218406964952f958462a9cc34f74061e6
// https://github.com/hyperium/h2/blob/62f878b218406964952f958462a9cc34f74061e6/LICENSE

#[cfg(test)]
use super::BitWindow;
use super::encode::HPACK_STRING as ENCODE_TABLE;

#[derive(Debug, PartialEq)]
pub enum Error {
    #[cfg(test)]
    MissingBits(BitWindow),
    #[cfg(test)]
    Unhandled(BitWindow, usize),
    Eos,
    InvalidPadding(usize),
}

#[cfg(test)]
mod oracle {
    use super::{BitWindow, Error};

    #[derive(Clone, Debug)]
    enum DecodeValue {
        Partial(&'static HuffmanDecoder),
        Sym(u8),
    }

    #[derive(Clone, Debug)]
    struct HuffmanDecoder {
        lookup: usize,
        table: &'static [DecodeValue],
        eos: bool,
    }

    impl HuffmanDecoder {
        fn fetch_value(&self, bit_pos: &mut BitWindow, input: &[u8]) -> Option<u32> {
            match read_bits(input, bit_pos.byte, bit_pos.bit, bit_pos.count) {
                Ok(value) => Some(value as u32),
                Err(()) => None,
            }
        }

        fn decode_next(&self, bit_pos: &mut BitWindow, input: &[u8]) -> Result<Option<u8>, Error> {
            if self.eos {
                return Err(Error::Eos);
            }

            bit_pos.forwards(self.lookup);

            let value = match self.fetch_value(bit_pos, input) {
                Some(value) => value as usize,
                None => return Ok(None),
            };

            let at_value = match (self.table).get(value) {
                Some(x) => x,
                None => return Err(Error::Unhandled(bit_pos.clone(), value)),
            };

            match at_value {
                DecodeValue::Sym(x) => Ok(Some(*x)),
                DecodeValue::Partial(d) => d.decode_next(bit_pos, input),
            }
        }
    }

    /// Read `len` bits from the `src` slice at the specified position
    ///
    /// Never read more than 8 bits at a time. `bit_offset` may be larger than 8.
    pub(super) fn read_bits(
        src: &[u8],
        mut byte_offset: usize,
        mut bit_offset: usize,
        len: usize,
    ) -> Result<u8, ()> {
        let total_bits = src.len().checked_mul(8).ok_or(())?;
        let end = byte_offset
            .checked_mul(8)
            .and_then(|offset| offset.checked_add(bit_offset))
            .and_then(|offset| offset.checked_add(len))
            .ok_or(())?;
        if len == 0 || len > 8 || total_bits < end {
            return Err(());
        }

        // Deal with `bit_offset` > 8
        byte_offset += bit_offset / 8;
        bit_offset -= (bit_offset / 8) * 8;

        Ok(if bit_offset + len <= 8 {
            // Read all the bits from a single byte
            (src[byte_offset] << bit_offset) >> (8 - len)
        } else {
            // The range of bits spans over 2 bytes
            let mut result = (src[byte_offset] as u16) << 8;
            result |= src[byte_offset + 1] as u16;
            ((result << bit_offset) >> (16 - len)) as u8
        })
    }

    macro_rules! bits_decode {
    // general way
    (
        lookup: $count:expr, [
        $($sym:expr,)*
        $(=> $sub:ident,)* ]
    ) => {
        HuffmanDecoder {
            lookup: $count,
            table: &[
                $( DecodeValue::Sym($sym), )*
                $( DecodeValue::Partial(&$sub), )*
            ],
            eos: false,
        }
    };
    // 2-final
    ( $first:expr, $second:expr ) => {
        HuffmanDecoder {
            lookup: 1,
            table: &[
                DecodeValue::Sym($first),
                DecodeValue::Sym($second),
            ],
            eos: false,
        }
    };
    // 4-final
    ( $first:expr, $second:expr, $third:expr, $fourth:expr ) => {
        HuffmanDecoder {
            lookup: 2,
            table: &[
                DecodeValue::Sym($first),
                DecodeValue::Sym($second),
                DecodeValue::Sym($third),
                DecodeValue::Sym($fourth),
            ],
            eos: false,
        }
    };
    // 2-final-partial
    ( $first:expr, => $second:ident ) => {
        HuffmanDecoder {
            lookup: 1,
            table: &[
                DecodeValue::Sym($first),
                DecodeValue::Partial(&$second),
            ],
            eos: false,
        }
    };
    // 2-partial
    ( => $first:ident, => $second:ident ) => {
        HuffmanDecoder {
            lookup: 1,
            table: &[
                DecodeValue::Partial(&$first),
                DecodeValue::Partial(&$second),
            ],
            eos: false,
        }
    };
    // 4-partial
    ( => $first:ident, => $second:ident,
      => $third:ident, => $fourth:ident ) => {
        HuffmanDecoder {
            lookup: 2,
            table: &[
                DecodeValue::Partial(&$first),
                DecodeValue::Partial(&$second),
                DecodeValue::Partial(&$third),
                DecodeValue::Partial(&$fourth),
            ],
            eos: false,
        }
    };
    [ $( $name:ident => ( $($value:tt)* ), )* ] => {
        $( static $name: HuffmanDecoder = bits_decode!( $( $value )* ); )*
    };
}

    static EOF: HuffmanDecoder = HuffmanDecoder {
        lookup: 0,
        table: &[],
        eos: true,
    };

    #[rustfmt::skip]
bits_decode![
    HPACK_STRING => (
        lookup: 5, [ b'0', b'1', b'2', b'a', b'c', b'e', b'i', b'o', b's', b't',
        => END0_01010, => END0_01011, => END0_01100, => END0_01101,
        => END0_01110, => END0_01111, => END0_10000, => END0_10001,
        => END0_10010, => END0_10011, => END0_10100, => END0_10101,
        => END0_10110, => END0_10111, => END0_11000, => END0_11001,
        => END0_11010, => END0_11011, => END0_11100, => END0_11101,
        => END0_11110, => END0_11111,
        ]),
    END0_01010 => ( 32 , b'%'),
    END0_01011 => (b'-' , b'.'),
    END0_01100 => (b'/' , b'3'),
    END0_01101 => (b'4' , b'5'),
    END0_01110 => (b'6' , b'7'),
    END0_01111 => (b'8' , b'9'),
    END0_10000 => (b'=' , b'A'),
    END0_10001 => (b'_' , b'b'),
    END0_10010 => (b'd' , b'f'),
    END0_10011 => (b'g' , b'h'),
    END0_10100 => (b'l' , b'm'),
    END0_10101 => (b'n' , b'p'),
    END0_10110 => (b'r' , b'u'),
    END0_10111 => (b':', b'B', b'C', b'D'),
    END0_11000 => (b'E', b'F', b'G', b'H'),
    END0_11001 => (b'I', b'J', b'K', b'L'),
    END0_11010 => (b'M', b'N', b'O', b'P'),
    END0_11011 => (b'Q', b'R', b'S', b'T'),
    END0_11100 => (b'U', b'V', b'W', b'Y'),
    END0_11101 => (b'j', b'k', b'q', b'v'),
    END0_11110 => (b'w', b'x', b'y', b'z'),
    END0_11111 => (=> END5_00, => END5_01, => END5_10, => END5_11),
    END5_00 => (b'&' , b'*'),
    END5_01 => (b',', 59),
    END5_10 => (b'X' , b'Z'),
    END5_11 => (=> END7_0, => END7_1),
    END7_0 => (b'!', b'"', b'(', b')'),
    END7_1 => (=> END8_0, => END8_1),
    END8_0 => (b'?', => END9A_1),
    END9A_1 => (b'\'' , b'+'),
    END8_1 => (lookup: 2, [b'|', => END9B_01, => END9B_10, => END9B_11,]),
    END9B_01 => (b'#' , b'>'),
    END9B_10 => (0, b'$', b'@', b'['),
    END9B_11 => (lookup: 2, [b']', b'~', => END13_10, => END13_11,]),
    END13_10 => (b'^', b'}'),
    END13_11 => (=> END14_0, => END14_1),
    END14_0 => (b'<', b'`'),
    END14_1 => (b'{', => END15_1),
    END15_1 =>
    (lookup: 4, [ b'\\', 195, 208, => END19_0011,
     => END19_0100, => END19_0101, => END19_0110, => END19_0111,
     => END19_1000, => END19_1001, => END19_1010, => END19_1011,
     => END19_1100, => END19_1101, => END19_1110, => END19_1111,
    ]),
    END19_0011 => (128, 130),
    END19_0100 => (131, 162),
    END19_0101 => (184, 194),
    END19_0110 => (224, 226),
    END19_0111 => (153, 161, 167, 172),
    END19_1000 => (176, 177, 179, 209),
    END19_1001 => (216, 217, 227, 229),
    END19_1010 => (lookup: 2, [230, => END19_1010_01, => END19_1010_10,
                   => END19_1010_11,]),
    END19_1010_01 => (129, 132),
    END19_1010_10 => (133, 134),
    END19_1010_11 => (136, 146),
    END19_1011 => (lookup: 3, [154, 156, 160, 163, 164, 169, 170, 173,]),
    END19_1100 => (lookup: 3, [178, 181, 185, 186, 187, 189, 190, 196,]),
    END19_1101 => (lookup: 3, [198, 228, 232, 233,
                   => END23A_100, => END23A_101,
                   => END23A_110, => END23A_111,]),
    END23A_100 => (  1, 135),
    END23A_101 => (137, 138),
    END23A_110 => (139, 140),
    END23A_111 => (141, 143),
    END19_1110 => (lookup: 4, [147, 149, 150, 151, 152, 155, 157, 158,
                   165, 166, 168, 174, 175, 180, 182, 183,]),
    END19_1111 => (lookup: 4, [188, 191, 197, 231, 239,
                   => END23B_0101, => END23B_0110, => END23B_0111,
                   => END23B_1000, => END23B_1001, => END23B_1010,
                   => END23B_1011, => END23B_1100, => END23B_1101,
                   => END23B_1110, => END23B_1111,]),
    END23B_0101 => (  9, 142),
    END23B_0110 => (144, 145),
    END23B_0111 => (148, 159),
    END23B_1000 => (171, 206),
    END23B_1001 => (215, 225),
    END23B_1010 => (236, 237),
    END23B_1011 => (199, 207, 234, 235),
    END23B_1100 => (lookup: 3, [192, 193, 200, 201, 202, 205, 210, 213,]),
    END23B_1101 => (lookup: 3, [218, 219, 238, 240, 242, 243, 255,
                    => END27A_111,]),
    END27A_111 => (203, 204),
    END23B_1110 => (lookup: 4, [211, 212, 214, 221, 222, 223, 241, 244,
                    245, 246, 247, 248, 250, 251, 252, 253,]),
    END23B_1111 => (lookup: 4, [ 254, => END27B_0001, => END27B_0010,
                    => END27B_0011, => END27B_0100, => END27B_0101,
                    => END27B_0110, => END27B_0111, => END27B_1000,
                    => END27B_1001, => END27B_1010, => END27B_1011,
                    => END27B_1100, => END27B_1101, => END27B_1110,
                    => END27B_1111,]),
    END27B_0001 => (2, 3),
    END27B_0010 => (4, 5),
    END27B_0011 => (6, 7),
    END27B_0100 => (8, 11),
    END27B_0101 => (12, 14),
    END27B_0110 => (15, 16),
    END27B_0111 => (17, 18),
    END27B_1000 => (19, 20),
    END27B_1001 => (21, 23),
    END27B_1010 => (24, 25),
    END27B_1011 => (26, 27),
    END27B_1100 => (28, 29),
    END27B_1101 => (30, 31),
    END27B_1110 => (127, 220),
    END27B_1111 => (lookup: 1, [249, => END31_1,]),
    END31_1 => (lookup: 2, [10, 13, 22, => EOF,]),
    ];

    pub struct DecodeIter<'a> {
        bit_pos: BitWindow,
        content: &'a [u8],
        symbol_end: usize,
        finished: bool,
    }

    impl<'a> Iterator for DecodeIter<'a> {
        type Item = Result<u8, Error>;

        fn next(&mut self) -> Option<Self::Item> {
            if self.finished {
                return None;
            }

            match HPACK_STRING.decode_next(&mut self.bit_pos, self.content) {
                Ok(Some(x)) => match self.bit_pos.end() {
                    Some(end) => {
                        self.symbol_end = end;
                        Some(Ok(x))
                    }
                    None => {
                        self.finished = true;
                        Some(Err(Error::MissingBits(self.bit_pos.clone())))
                    }
                },
                Err(err) => {
                    self.finished = true;
                    Some(Err(err))
                }
                Ok(None) => {
                    self.finished = true;
                    let total_bits = match self.content.len().checked_mul(8) {
                        Some(total_bits) => total_bits,
                        None => return Some(Err(Error::MissingBits(self.bit_pos.clone()))),
                    };
                    let padding = match total_bits.checked_sub(self.symbol_end) {
                        Some(padding) => padding,
                        None => return Some(Err(Error::MissingBits(self.bit_pos.clone()))),
                    };
                    if padding == 0 {
                        return None;
                    }
                    // QPACK uses the HPACK Huffman code unchanged. The EOS symbol is
                    // forbidden in strings, and padding is at most seven one bits.
                    // https://www.rfc-editor.org/rfc/rfc9204.html#section-4.1.2
                    // https://www.rfc-editor.org/rfc/rfc7541.html#section-5.2
                    if padding > 7 {
                        return Some(Err(Error::InvalidPadding(padding)));
                    }

                    let padding_bits = match read_bits(
                        self.content,
                        self.symbol_end / 8,
                        self.symbol_end % 8,
                        padding,
                    ) {
                        Ok(bits) => bits,
                        Err(()) => return Some(Err(Error::MissingBits(self.bit_pos.clone()))),
                    };
                    let expected = ((1u16 << padding) - 1) as u8;
                    if padding_bits == expected {
                        None
                    } else {
                        Some(Err(Error::InvalidPadding(padding)))
                    }
                }
            }
        }
    }

    pub trait HpackStringDecode {
        fn hpack_decode(&self) -> DecodeIter<'_>;
    }

    impl HpackStringDecode for Vec<u8> {
        fn hpack_decode(&self) -> DecodeIter<'_> {
            self.as_slice().hpack_decode()
        }
    }

    impl HpackStringDecode for [u8] {
        fn hpack_decode(&self) -> DecodeIter<'_> {
            DecodeIter {
                bit_pos: BitWindow::new(),
                content: self,
                symbol_end: 0,
                finished: false,
            }
        }
    }

    pub(super) fn decode(content: &[u8]) -> Result<Vec<u8>, Error> {
        content.hpack_decode().collect()
    }
}

const FAST_BITS: u8 = 10;
const FAST_TABLE_LEN: usize = 1 << FAST_BITS;
const TRIE_NODE_COUNT: usize = 256;
const TRIE_LEAF: u16 = 1 << 15;
const TRIE_EMPTY: u16 = u16::MAX;
const EOS_SYMBOL: u16 = 256;
const EOS_BITS: u32 = (1 << 30) - 1;
const EOS_BIT_COUNT: usize = 30;

struct DecoderTables {
    fast: [u16; FAST_TABLE_LEN],
    trie: [[u16; 2]; TRIE_NODE_COUNT],
}

static DECODER_TABLES: DecoderTables = build_tables();

const fn code_for(symbol: usize) -> (u32, usize) {
    if symbol < ENCODE_TABLE.len() {
        let code = ENCODE_TABLE[symbol];
        (code.bits, code.bit_count)
    } else {
        (EOS_BITS, EOS_BIT_COUNT)
    }
}

const fn build_trie() -> [[u16; 2]; TRIE_NODE_COUNT] {
    let mut trie = [[TRIE_EMPTY; 2]; TRIE_NODE_COUNT];
    let mut next_node = 1usize;
    let mut symbol = 0usize;

    while symbol <= ENCODE_TABLE.len() {
        let (bits, bit_count) = code_for(symbol);
        let mut remaining = bit_count;
        let mut node = 0usize;

        while remaining != 0 {
            remaining -= 1;
            let branch = ((bits >> remaining) & 1) as usize;
            if remaining == 0 {
                assert!(trie[node][branch] == TRIE_EMPTY);
                trie[node][branch] = TRIE_LEAF | symbol as u16;
            } else {
                let edge = trie[node][branch];
                if edge == TRIE_EMPTY {
                    assert!(next_node < TRIE_NODE_COUNT);
                    trie[node][branch] = next_node as u16;
                    node = next_node;
                    next_node += 1;
                } else {
                    assert!(edge & TRIE_LEAF == 0);
                    assert!((edge as usize) < TRIE_NODE_COUNT);
                    node = edge as usize;
                }
            }
        }
        symbol += 1;
    }

    assert!(next_node == TRIE_NODE_COUNT);
    trie
}

const fn build_tables() -> DecoderTables {
    let trie = build_trie();
    let mut fast = [TRIE_EMPTY; FAST_TABLE_LEN];
    let mut prefix = 0usize;

    while prefix < FAST_TABLE_LEN {
        let mut node = 0usize;
        let mut used = 0u8;
        let mut terminal = false;

        while used < FAST_BITS {
            let shift = FAST_BITS - used - 1;
            let branch = (prefix >> shift) & 1;
            let edge = trie[node][branch];
            used += 1;

            if edge == TRIE_EMPTY {
                terminal = true;
                break;
            }
            if edge & TRIE_LEAF != 0 {
                let symbol = edge & (TRIE_LEAF - 1);
                if symbol < EOS_SYMBOL {
                    fast[prefix] = (used as u16) << 8 | symbol;
                }
                terminal = true;
                break;
            }
            node = edge as usize;
        }

        if !terminal {
            fast[prefix] = TRIE_LEAF | node as u16;
        }
        assert!(fast[prefix] != TRIE_EMPTY);
        prefix += 1;
    }

    DecoderTables { fast, trie }
}

enum Decoded {
    Symbol { symbol: u16, bit_count: u8 },
    Incomplete,
}

fn decode_symbol(bits: u64, bit_count: u8) -> Decoded {
    let (mut node, mut used) = if bit_count >= FAST_BITS {
        let prefix = (bits >> (64 - FAST_BITS)) as usize;
        let entry = DECODER_TABLES.fast[prefix];
        if entry == TRIE_EMPTY {
            return Decoded::Incomplete;
        }
        if entry & TRIE_LEAF == 0 {
            let encoded_count = entry >> 8;
            let Ok(encoded_count) = u8::try_from(encoded_count) else {
                return Decoded::Incomplete;
            };
            return Decoded::Symbol {
                symbol: entry & u16::from(u8::MAX),
                bit_count: encoded_count,
            };
        }
        (usize::from(entry & (TRIE_LEAF - 1)), FAST_BITS)
    } else {
        (0usize, 0u8)
    };

    while used < bit_count {
        let shift = 63 - u32::from(used);
        let branch = ((bits >> shift) & 1) as usize;
        let edge = DECODER_TABLES.trie[node][branch];
        used += 1;

        if edge == TRIE_EMPTY {
            return Decoded::Incomplete;
        }
        if edge & TRIE_LEAF != 0 {
            return Decoded::Symbol {
                symbol: edge & (TRIE_LEAF - 1),
                bit_count: used,
            };
        }
        node = usize::from(edge);
    }

    Decoded::Incomplete
}

pub struct DecodeIter<'a> {
    content: &'a [u8],
    byte_pos: usize,
    bits: u64,
    bit_count: u8,
    #[cfg(test)]
    symbol_end: usize,
    finished: bool,
}

impl DecodeIter<'_> {
    fn refill(&mut self) {
        if self.bit_count == 0 {
            let Some(remaining) = self.content.get(self.byte_pos..) else {
                return;
            };
            if let [a, b, c, d, e, f, g, h, ..] = remaining {
                self.bits = u64::from_be_bytes([*a, *b, *c, *d, *e, *f, *g, *h]);
                self.bit_count = 64;
                self.byte_pos += 8;
                return;
            }
        }

        if self.bit_count <= 32 {
            let Some(remaining) = self.content.get(self.byte_pos..) else {
                return;
            };
            if let [a, b, c, d, ..] = remaining {
                let value = u64::from(u32::from_be_bytes([*a, *b, *c, *d]));
                self.bits |= value << u32::from(32 - self.bit_count);
                self.bit_count += 32;
                self.byte_pos += 4;
            }
        }

        while self.bit_count < EOS_BIT_COUNT as u8 {
            let Some(byte) = self.content.get(self.byte_pos).copied() else {
                break;
            };
            self.bits |= u64::from(byte) << u32::from(56 - self.bit_count);
            self.bit_count += 8;
            self.byte_pos += 1;
        }
    }

    fn consume(&mut self, count: u8) -> bool {
        if count == 0 || count >= 64 {
            return false;
        }
        let Some(remaining) = self.bit_count.checked_sub(count) else {
            return false;
        };
        self.bits <<= u32::from(count);
        self.bit_count = remaining;
        #[cfg(test)]
        {
            self.symbol_end = self.symbol_end.saturating_add(usize::from(count));
        }
        true
    }

    fn remaining_bits(&self) -> usize {
        let Some(unread_bytes) = self.content.len().checked_sub(self.byte_pos) else {
            return usize::MAX;
        };
        let Some(unread_bits) = unread_bytes.checked_mul(8) else {
            return usize::MAX;
        };
        match unread_bits.checked_add(usize::from(self.bit_count)) {
            Some(remaining) => remaining,
            None => usize::MAX,
        }
    }

    fn finish_tail(&mut self) -> Option<Result<u8, Error>> {
        self.finished = true;
        let padding = self.remaining_bits();
        if padding == 0 {
            return None;
        }
        if padding > 7 {
            return Some(Err(Error::InvalidPadding(padding)));
        }

        let shift = 64 - padding;
        let expected = u64::MAX << shift;
        if self.bits & expected == expected {
            None
        } else {
            Some(Err(Error::InvalidPadding(padding)))
        }
    }
}

impl Iterator for DecodeIter<'_> {
    type Item = Result<u8, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }

        self.refill();
        if self.bit_count == 0 {
            self.finished = true;
            return None;
        }

        match decode_symbol(self.bits, self.bit_count) {
            Decoded::Symbol {
                symbol: EOS_SYMBOL, ..
            } => {
                self.finished = true;
                Some(Err(Error::Eos))
            }
            Decoded::Symbol { symbol, bit_count } => {
                let Ok(symbol) = u8::try_from(symbol) else {
                    self.finished = true;
                    return Some(Err(Error::Eos));
                };
                if self.consume(bit_count) {
                    Some(Ok(symbol))
                } else {
                    self.finish_tail()
                }
            }
            Decoded::Incomplete => self.finish_tail(),
        }
    }
}

pub trait HpackStringDecode {
    fn hpack_decode(&self) -> DecodeIter<'_>;
}

impl HpackStringDecode for Vec<u8> {
    fn hpack_decode(&self) -> DecodeIter<'_> {
        self.as_slice().hpack_decode()
    }
}

impl HpackStringDecode for [u8] {
    fn hpack_decode(&self) -> DecodeIter<'_> {
        DecodeIter {
            content: self,
            byte_pos: 0,
            bits: 0,
            bit_count: 0,
            #[cfg(test)]
            symbol_end: 0,
            finished: false,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::identity_op)]

    use super::*;
    use crate::qpack::prefix_string::HpackStringEncode;

    #[test]
    fn test_read_bits() {
        // Basic case (within one byte, aligned with start)
        assert_eq!(oracle::read_bits(&[0b1010_1010], 0, 0, 5), Ok(0b1_0101));
        // Within one byte, aligned with end of byte
        assert_eq!(oracle::read_bits(&[0b1010_1010], 0, 3, 5), Ok(0b1010));
        // Within one byte, unaligned with either side
        assert_eq!(oracle::read_bits(&[0b1010_1010], 0, 3, 3), Ok(0b10));
        // `len` == 0
        assert_eq!(oracle::read_bits(&[0b1010_1010], 0, 0, 0), Err(()));
        // `len` > 8
        assert_eq!(oracle::read_bits(&[0b1010_1010], 0, 0, 9), Err(()));

        // `bit_offset` > 7
        assert_eq!(
            oracle::read_bits(&[0b1010_1010, 0b1010_1010], 0, 8, 8),
            Ok(0b1010_1010)
        );
        // Read spanning two bytes
        assert_eq!(
            oracle::read_bits(&[0b1010_1010, 0b1010_1010], 0, 4, 8),
            Ok(0b1010_1010)
        );
        // Read with non-zero `byte_offset`
        assert_eq!(
            oracle::read_bits(&[0b1010_1010, 0b1010_1010], 1, 0, 5),
            Ok(0b1_0101)
        );
        // Read with `bit_offset` > 7, unaligned with either side
        assert_eq!(
            oracle::read_bits(&[0b1010_1010, 0b1010_1010], 0, 10, 5),
            Ok(0b1_0101)
        );
        // Read with `bit_offset` > 7 past end of input slice
        assert_eq!(
            oracle::read_bits(&[0b1010_1010, 0b1010_1010], 0, 16, 5),
            Err(())
        );
    }

    macro_rules! decoding {
        [ $( $code:expr => $( $byte:expr ),* ; )* ] => { $( {
            let bytes = vec![$( $byte ),*];
            let res: Result<Vec<_>, Error> = bytes.hpack_decode().collect();
            assert_eq!(res, Ok(vec![$code]), "fail to decode {}", $code);
        } )* }
    }

    /**
     * https://tools.ietf.org/html/rfc7541
     * Appendix B.  Huffman Code
     */
    #[test]
    #[allow(clippy::cognitive_complexity)]
    fn test_decode_single_value() {
        decoding![
            48 => (0b0_0000 << 3) | /* padding */ 0b111; // '0'
        49 => (0b0_0001 << 3) | /* padding */ 0b111; // '1'
        50 => (0b0_0010 << 3) | /* padding */ 0b111; // '2'
        97 => (0b0_0011 << 3) | /* padding */ 0b111; // 'a'
        99 => (0b0_0100 << 3) | /* padding */ 0b111; // 'c'
        101 => (0b0_0101 << 3) | /* padding */ 0b111; // 'e'
        105 => (0b0_0110 << 3) | /* padding */ 0b111; // 'i'
        111 => (0b0_0111 << 3) | /* padding */ 0b111; // 'o'
        115 => (0b0_1000 << 3) | /* padding */ 0b111; // 's'
        116 => (0b0_1001 << 3) | /* padding */ 0b111; // 't'
        32 => (0b01_0100 << 2) | /* padding */ 0b11;
        37 => (0b01_0101 << 2) | /* padding */ 0b11; // '%'
        45 => (0b01_0110 << 2) | /* padding */ 0b11; // '-'
        46 => (0b01_0111 << 2) | /* padding */ 0b11; // '.'
        47 => (0b01_1000 << 2) | /* padding */ 0b11; // '/'
        51 => (0b01_1001 << 2) | /* padding */ 0b11; // '3'
        52 => (0b01_1010 << 2) | /* padding */ 0b11; // '4'
        53 => (0b01_1011 << 2) | /* padding */ 0b11; // '5'
        54 => (0b01_1100 << 2) | /* padding */ 0b11; // '6'
        55 => (0b01_1101 << 2) | /* padding */ 0b11; // '7'
        56 => (0b01_1110 << 2) | /* padding */ 0b11; // '8'
        57 => (0b01_1111 << 2) | /* padding */ 0b11; // '9'
        61 => (0b10_0000 << 2) | /* padding */ 0b11; // '='
        65 => (0b10_0001 << 2) | /* padding */ 0b11; // 'A'
        95 => (0b10_0010 << 2) | /* padding */ 0b11; // '_'
        98 => (0b10_0011 << 2) | /* padding */ 0b11; // 'b'
        100 => (0b10_0100 << 2) | /* padding */ 0b11; // 'd'
        102 => (0b10_0101 << 2) | /* padding */ 0b11; // 'f'
        103 => (0b10_0110 << 2) | /* padding */ 0b11; // 'g'
        104 => (0b10_0111 << 2) | /* padding */ 0b11; // 'h'
        108 => (0b10_1000 << 2) | /* padding */ 0b11; // 'l'
        109 => (0b10_1001 << 2) | /* padding */ 0b11; // 'm'
        110 => (0b10_1010 << 2) | /* padding */ 0b11; // 'n'
        112 => (0b10_1011 << 2) | /* padding */ 0b11; // 'p'
        114 => (0b10_1100 << 2) | /* padding */ 0b11; // 'r'
        117 => (0b10_1101 << 2) | /* padding */ 0b11; // 'u'
        58 => (0b101_1100 << 1) | /* padding */ 0b1; // ':'
        66 => (0b101_1101 << 1) | /* padding */ 0b1; // 'B'
        67 => (0b101_1110 << 1) | /* padding */ 0b1; // 'C'
        68 => (0b101_1111 << 1) | /* padding */ 0b1; // 'D'
        69 => (0b110_0000 << 1) | /* padding */ 0b1; // 'E'
        70 => (0b110_0001 << 1) | /* padding */ 0b1; // 'F'
        71 => (0b110_0010 << 1) | /* padding */ 0b1; // 'G'
        72 => (0b110_0011 << 1) | /* padding */ 0b1; // 'H'
        73 => (0b110_0100 << 1) | /* padding */ 0b1; // 'I'
        74 => (0b110_0101 << 1) | /* padding */ 0b1; // 'J'
        75 => (0b110_0110 << 1) | /* padding */ 0b1; // 'K'
        76 => (0b110_0111 << 1) | /* padding */ 0b1; // 'L'
        77 => (0b110_1000 << 1) | /* padding */ 0b1; // 'M'
        78 => (0b110_1001 << 1) | /* padding */ 0b1; // 'N'
        79 => (0b110_1010 << 1) | /* padding */ 0b1; // 'O'
        80 => (0b110_1011 << 1) | /* padding */ 0b1; // 'P'
        81 => (0b110_1100 << 1) | /* padding */ 0b1; // 'Q'
        82 => (0b110_1101 << 1) | /* padding */ 0b1; // 'R'
        83 => (0b110_1110 << 1) | /* padding */ 0b1; // 'S'
        84 => (0b110_1111 << 1) | /* padding */ 0b1; // 'T'
        85 => (0b111_0000 << 1) | /* padding */ 0b1; // 'U'
        86 => (0b111_0001 << 1) | /* padding */ 0b1; // 'V'
        87 => (0b111_0010 << 1) | /* padding */ 0b1; // 'W'
        89 => (0b111_0011 << 1) | /* padding */ 0b1; // 'Y'
        106 => (0b111_0100 << 1) | /* padding */ 0b1; // 'j'
        107 => (0b111_0101 << 1) | /* padding */ 0b1; // 'k'
        113 => (0b111_0110 << 1) | /* padding */ 0b1; // 'q'
        118 => (0b111_0111 << 1) | /* padding */ 0b1; // 'v'
        119 => (0b111_1000 << 1) | /* padding */ 0b1; // 'w'
        120 => (0b111_1001 << 1) | /* padding */ 0b1; // 'x'
        121 => (0b111_1010 << 1) | /* padding */ 0b1; // 'y'
        122 => (0b111_1011 << 1) | /* padding */ 0b1; // 'z'
        38 => 0b1111_1000; // '&'
        42 => 0b1111_1001; // '*'
        44 => 0b1111_1010; // ','
        59 => 0b1111_1011;
        88 => 0b1111_1100; // 'X'
        90 => 0b1111_1101; // 'Z'
        33 => 0b1111_1110, (0b00 << 6) | /* padding */ 0b11_1111; // '!'
        34 => 0b1111_1110, (0b01 << 6) | /* padding */ 0b11_1111; // '"'
        40 => 0b1111_1110, (0b10 << 6) | /* padding */ 0b11_1111; // '('
        41 => 0b1111_1110, (0b11 << 6) | /* padding */ 0b11_1111; // ')'
        63 => 0b1111_1111, (0b00 << 6) | /* padding */ 0b11_1111; // '?'
        39 => 0b1111_1111, (0b010 << 5) | /* padding */ 0b11111; // '''
        43 => 0b1111_1111, (0b011 << 5) | /* padding */ 0b11111; // '+'
        124 => 0b1111_1111, (0b100 << 5) | /* padding */ 0b11111; // '|'
        35 => 0b1111_1111, (0b1010 << 4) | /* padding */ 0b1111; // '#'
        62 => 0b1111_1111, (0b1011 << 4) | /* padding */ 0b1111; // '>'
        0 => 0b1111_1111, (0b11000 << 3) | /* padding */ 0b111;
        36 => 0b1111_1111, (0b11001 << 3) | /* padding */ 0b111; // '$'
        64 => 0b1111_1111, (0b11010 << 3) | /* padding */ 0b111; // '@'
        91 => 0b1111_1111, (0b11011 << 3) | /* padding */ 0b111; // '['
        93 => 0b1111_1111, (0b11100 << 3) | /* padding */ 0b111; // ']'
        126 => 0b1111_1111, (0b11101 << 3) | /* padding */ 0b111; // '~'
        94 => 0b1111_1111, (0b11_1100 << 2) | /* padding */ 0b11; // '^'
        125 => 0b1111_1111, (0b11_1101 << 2) | /* padding */ 0b11; // '}'
        60 => 0b1111_1111, (0b111_1100 << 1) | /* padding */ 0b1; // '<'
        96 => 0b1111_1111, (0b111_1101 << 1) | /* padding */ 0b1; // '`'
        123 => 0b1111_1111, (0b111_1110 << 1) | /* padding */ 0b1; // '{'
        92 => 0b1111_1111, 0b1111_1110, (0b000 << 5) | /* padding */ 0b11111; // '\'
        195 => 0b1111_1111, 0b1111_1110, (0b001 << 5) | /* padding */ 0b11111;
        208 => 0b1111_1111, 0b1111_1110, (0b010 << 5) | /* padding */ 0b11111;
        128 => 0b1111_1111, 0b1111_1110, (0b0110 << 4) | /* padding */ 0b1111;
        130 => 0b1111_1111, 0b1111_1110, (0b0111 << 4) | /* padding */ 0b1111;
        131 => 0b1111_1111, 0b1111_1110, (0b1000 << 4) | /* padding */ 0b1111;
        162 => 0b1111_1111, 0b1111_1110, (0b1001 << 4) | /* padding */ 0b1111;
        184 => 0b1111_1111, 0b1111_1110, (0b1010 << 4) | /* padding */ 0b1111;
        194 => 0b1111_1111, 0b1111_1110, (0b1011 << 4) | /* padding */ 0b1111;
        224 => 0b1111_1111, 0b1111_1110, (0b1100 << 4) | /* padding */ 0b1111;
        226 => 0b1111_1111, 0b1111_1110, (0b1101 << 4) | /* padding */ 0b1111;
        153 => 0b1111_1111, 0b1111_1110, (0b11100 << 3) | /* padding */ 0b111;
        161 => 0b1111_1111, 0b1111_1110, (0b11101 << 3) | /* padding */ 0b111;
        167 => 0b1111_1111, 0b1111_1110, (0b11110 << 3) | /* padding */ 0b111;
        172 => 0b1111_1111, 0b1111_1110, (0b11111 << 3) | /* padding */ 0b111;
        176 => 0b1111_1111, 0b1111_1111, (0b00000 << 3) | /* padding */ 0b111;
        177 => 0b1111_1111, 0b1111_1111, (0b00001 << 3) | /* padding */ 0b111;
        179 => 0b1111_1111, 0b1111_1111, (0b00010 << 3) | /* padding */ 0b111;
        209 => 0b1111_1111, 0b1111_1111, (0b00011 << 3) | /* padding */ 0b111;
        216 => 0b1111_1111, 0b1111_1111, (0b00100 << 3) | /* padding */ 0b111;
        217 => 0b1111_1111, 0b1111_1111, (0b00101 << 3) | /* padding */ 0b111;
        227 => 0b1111_1111, 0b1111_1111, (0b00110 << 3) | /* padding */ 0b111;
        229 => 0b1111_1111, 0b1111_1111, (0b00111 << 3) | /* padding */ 0b111;
        230 => 0b1111_1111, 0b1111_1111, (0b01000 << 3) | /* padding */ 0b111;
        129 => 0b1111_1111, 0b1111_1111, (0b01_0010 << 2) | /* padding */ 0b11;
        132 => 0b1111_1111, 0b1111_1111, (0b01_0011 << 2) | /* padding */ 0b11;
        133 => 0b1111_1111, 0b1111_1111, (0b01_0100 << 2) | /* padding */ 0b11;
        134 => 0b1111_1111, 0b1111_1111, (0b01_0101 << 2) | /* padding */ 0b11;
        136 => 0b1111_1111, 0b1111_1111, (0b01_0110 << 2) | /* padding */ 0b11;
        146 => 0b1111_1111, 0b1111_1111, (0b01_0111 << 2) | /* padding */ 0b11;
        154 => 0b1111_1111, 0b1111_1111, (0b01_1000 << 2) | /* padding */ 0b11;
        156 => 0b1111_1111, 0b1111_1111, (0b01_1001 << 2) | /* padding */ 0b11;
        160 => 0b1111_1111, 0b1111_1111, (0b01_1010 << 2) | /* padding */ 0b11;
        163 => 0b1111_1111, 0b1111_1111, (0b01_1011 << 2) | /* padding */ 0b11;
        164 => 0b1111_1111, 0b1111_1111, (0b01_1100 << 2) | /* padding */ 0b11;
        169 => 0b1111_1111, 0b1111_1111, (0b01_1101 << 2) | /* padding */ 0b11;
        170 => 0b1111_1111, 0b1111_1111, (0b01_1110 << 2) | /* padding */ 0b11;
        173 => 0b1111_1111, 0b1111_1111, (0b01_1111 << 2) | /* padding */ 0b11;
        178 => 0b1111_1111, 0b1111_1111, (0b10_0000 << 2) | /* padding */ 0b11;
        181 => 0b1111_1111, 0b1111_1111, (0b10_0001 << 2) | /* padding */ 0b11;
        185 => 0b1111_1111, 0b1111_1111, (0b10_0010 << 2) | /* padding */ 0b11;
        186 => 0b1111_1111, 0b1111_1111, (0b10_0011 << 2) | /* padding */ 0b11;
        187 => 0b1111_1111, 0b1111_1111, (0b10_0100 << 2) | /* padding */ 0b11;
        189 => 0b1111_1111, 0b1111_1111, (0b10_0101 << 2) | /* padding */ 0b11;
        190 => 0b1111_1111, 0b1111_1111, (0b10_0110 << 2) | /* padding */ 0b11;
        196 => 0b1111_1111, 0b1111_1111, (0b10_0111 << 2) | /* padding */ 0b11;
        198 => 0b1111_1111, 0b1111_1111, (0b10_1000 << 2) | /* padding */ 0b11;
        228 => 0b1111_1111, 0b1111_1111, (0b10_1001 << 2) | /* padding */ 0b11;
        232 => 0b1111_1111, 0b1111_1111, (0b10_1010 << 2) | /* padding */ 0b11;
        233 => 0b1111_1111, 0b1111_1111, (0b10_1011 << 2) | /* padding */ 0b11;
        1 => 0b1111_1111, 0b1111_1111, (0b101_1000 << 1) | /* padding */ 0b1;
        135 => 0b1111_1111, 0b1111_1111, (0b101_1001 << 1) | /* padding */ 0b1;
        137 => 0b1111_1111, 0b1111_1111, (0b101_1010 << 1) | /* padding */ 0b1;
        138 => 0b1111_1111, 0b1111_1111, (0b101_1011 << 1) | /* padding */ 0b1;
        139 => 0b1111_1111, 0b1111_1111, (0b101_1100 << 1) | /* padding */ 0b1;
        140 => 0b1111_1111, 0b1111_1111, (0b101_1101 << 1) | /* padding */ 0b1;
        141 => 0b1111_1111, 0b1111_1111, (0b101_1110 << 1) | /* padding */ 0b1;
        143 => 0b1111_1111, 0b1111_1111, (0b101_1111 << 1) | /* padding */ 0b1;
        147 => 0b1111_1111, 0b1111_1111, (0b110_0000 << 1) | /* padding */ 0b1;
        149 => 0b1111_1111, 0b1111_1111, (0b110_0001 << 1) | /* padding */ 0b1;
        150 => 0b1111_1111, 0b1111_1111, (0b110_0010 << 1) | /* padding */ 0b1;
        151 => 0b1111_1111, 0b1111_1111, (0b110_0011 << 1) | /* padding */ 0b1;
        152 => 0b1111_1111, 0b1111_1111, (0b110_0100 << 1) | /* padding */ 0b1;
        155 => 0b1111_1111, 0b1111_1111, (0b110_0101 << 1) | /* padding */ 0b1;
        157 => 0b1111_1111, 0b1111_1111, (0b110_0110 << 1) | /* padding */ 0b1;
        158 => 0b1111_1111, 0b1111_1111, (0b110_0111 << 1) | /* padding */ 0b1;
        165 => 0b1111_1111, 0b1111_1111, (0b110_1000 << 1) | /* padding */ 0b1;
        166 => 0b1111_1111, 0b1111_1111, (0b110_1001 << 1) | /* padding */ 0b1;
        168 => 0b1111_1111, 0b1111_1111, (0b110_1010 << 1) | /* padding */ 0b1;
        174 => 0b1111_1111, 0b1111_1111, (0b110_1011 << 1) | /* padding */ 0b1;
        175 => 0b1111_1111, 0b1111_1111, (0b110_1100 << 1) | /* padding */ 0b1;
        180 => 0b1111_1111, 0b1111_1111, (0b110_1101 << 1) | /* padding */ 0b1;
        182 => 0b1111_1111, 0b1111_1111, (0b110_1110 << 1) | /* padding */ 0b1;
        183 => 0b1111_1111, 0b1111_1111, (0b110_1111 << 1) | /* padding */ 0b1;
        188 => 0b1111_1111, 0b1111_1111, (0b111_0000 << 1) | /* padding */ 0b1;
        191 => 0b1111_1111, 0b1111_1111, (0b111_0001 << 1) | /* padding */ 0b1;
        197 => 0b1111_1111, 0b1111_1111, (0b111_0010 << 1) | /* padding */ 0b1;
        231 => 0b1111_1111, 0b1111_1111, (0b111_0011 << 1) | /* padding */ 0b1;
        239 => 0b1111_1111, 0b1111_1111, (0b111_0100 << 1) | /* padding */ 0b1;
        9 => 0b1111_1111, 0b1111_1111, 0b1110_1010;
        142 => 0b1111_1111, 0b1111_1111, 0b1110_1011;
        144 => 0b1111_1111, 0b1111_1111, 0b1110_1100;
        145 => 0b1111_1111, 0b1111_1111, 0b1110_1101;
        148 => 0b1111_1111, 0b1111_1111, 0b1110_1110;
        159 => 0b1111_1111, 0b1111_1111, 0b1110_1111;
        171 => 0b1111_1111, 0b1111_1111, 0b1111_0000;
        206 => 0b1111_1111, 0b1111_1111, 0b1111_0001;
        215 => 0b1111_1111, 0b1111_1111, 0b1111_0010;
        225 => 0b1111_1111, 0b1111_1111, 0b1111_0011;
        236 => 0b1111_1111, 0b1111_1111, 0b1111_0100;
        237 => 0b1111_1111, 0b1111_1111, 0b1111_0101;
        199 => 0b1111_1111, 0b1111_1111, 0b1111_0110, (0b0 << 7) | /* padding */ 0b111_1111;
        207 => 0b1111_1111, 0b1111_1111, 0b1111_0110, (0b1 << 7) | /* padding */ 0b111_1111;
        234 => 0b1111_1111, 0b1111_1111, 0b1111_0111, (0b0 << 7) | /* padding */ 0b111_1111;
        235 => 0b1111_1111, 0b1111_1111, 0b1111_0111, (0b1 << 7) | /* padding */ 0b111_1111;
        192 => 0b1111_1111, 0b1111_1111, 0b1111_1000, (0b00 << 6) | /* padding */ 0b11_1111;
        193 => 0b1111_1111, 0b1111_1111, 0b1111_1000, (0b01 << 6) | /* padding */ 0b11_1111;
        200 => 0b1111_1111, 0b1111_1111, 0b1111_1000, (0b10 << 6) | /* padding */ 0b11_1111;
        201 => 0b1111_1111, 0b1111_1111, 0b1111_1000, (0b11 << 6) | /* padding */ 0b11_1111;
        202 => 0b1111_1111, 0b1111_1111, 0b1111_1001, (0b00 << 6) | /* padding */ 0b11_1111;
        205 => 0b1111_1111, 0b1111_1111, 0b1111_1001, (0b01 << 6) | /* padding */ 0b11_1111;
        210 => 0b1111_1111, 0b1111_1111, 0b1111_1001, (0b10 << 6) | /* padding */ 0b11_1111;
        213 => 0b1111_1111, 0b1111_1111, 0b1111_1001, (0b11 << 6) | /* padding */ 0b11_1111;
        218 => 0b1111_1111, 0b1111_1111, 0b1111_1010, (0b00 << 6) | /* padding */ 0b11_1111;
        219 => 0b1111_1111, 0b1111_1111, 0b1111_1010, (0b01 << 6) | /* padding */ 0b11_1111;
        238 => 0b1111_1111, 0b1111_1111, 0b1111_1010, (0b10 << 6) | /* padding */ 0b11_1111;
        240 => 0b1111_1111, 0b1111_1111, 0b1111_1010, (0b11 << 6) | /* padding */ 0b11_1111;
        242 => 0b1111_1111, 0b1111_1111, 0b1111_1011, (0b00 << 6) | /* padding */ 0b11_1111;
        243 => 0b1111_1111, 0b1111_1111, 0b1111_1011, (0b01 << 6) | /* padding */ 0b11_1111;
        255 => 0b1111_1111, 0b1111_1111, 0b1111_1011, (0b10 << 6) | /* padding */ 0b11_1111;
        203 => 0b1111_1111, 0b1111_1111, 0b1111_1011, (0b110 << 5) | /* padding */ 0b11111;
        204 => 0b1111_1111, 0b1111_1111, 0b1111_1011, (0b111 << 5) | /* padding */ 0b11111;
        211 => 0b1111_1111, 0b1111_1111, 0b1111_1100, (0b000 << 5) | /* padding */ 0b11111;
        212 => 0b1111_1111, 0b1111_1111, 0b1111_1100, (0b001 << 5) | /* padding */ 0b11111;
        214 => 0b1111_1111, 0b1111_1111, 0b1111_1100, (0b010 << 5) | /* padding */ 0b11111;
        221 => 0b1111_1111, 0b1111_1111, 0b1111_1100, (0b011 << 5) | /* padding */ 0b11111;
        222 => 0b1111_1111, 0b1111_1111, 0b1111_1100, (0b100 << 5) | /* padding */ 0b11111;
        223 => 0b1111_1111, 0b1111_1111, 0b1111_1100, (0b101 << 5) | /* padding */ 0b11111;
        241 => 0b1111_1111, 0b1111_1111, 0b1111_1100, (0b110 << 5) | /* padding */ 0b11111;
        244 => 0b1111_1111, 0b1111_1111, 0b1111_1100, (0b111 << 5) | /* padding */ 0b11111;
        245 => 0b1111_1111, 0b1111_1111, 0b1111_1101, (0b000 << 5) | /* padding */ 0b11111;
        246 => 0b1111_1111, 0b1111_1111, 0b1111_1101, (0b001 << 5) | /* padding */ 0b11111;
        247 => 0b1111_1111, 0b1111_1111, 0b1111_1101, (0b010 << 5) | /* padding */ 0b11111;
        248 => 0b1111_1111, 0b1111_1111, 0b1111_1101, (0b011 << 5) | /* padding */ 0b11111;
        250 => 0b1111_1111, 0b1111_1111, 0b1111_1101, (0b100 << 5) | /* padding */ 0b11111;
        251 => 0b1111_1111, 0b1111_1111, 0b1111_1101, (0b101 << 5) | /* padding */ 0b11111;
        252 => 0b1111_1111, 0b1111_1111, 0b1111_1101, (0b110 << 5) | /* padding */ 0b11111;
        253 => 0b1111_1111, 0b1111_1111, 0b1111_1101, (0b111 << 5) | /* padding */ 0b11111;
        254 => 0b1111_1111, 0b1111_1111, 0b1111_1110, (0b000 << 5) | /* padding */ 0b11111;
        2 => 0b1111_1111, 0b1111_1111, 0b1111_1110, (0b0010 << 4) | /* padding */ 0b1111;
        3 => 0b1111_1111, 0b1111_1111, 0b1111_1110, (0b0011 << 4) | /* padding */ 0b1111;
        4 => 0b1111_1111, 0b1111_1111, 0b1111_1110, (0b0100 << 4) | /* padding */ 0b1111;
        5 => 0b1111_1111, 0b1111_1111, 0b1111_1110, (0b0101 << 4) | /* padding */ 0b1111;
        6 => 0b1111_1111, 0b1111_1111, 0b1111_1110, (0b0110 << 4) | /* padding */ 0b1111;
        7 => 0b1111_1111, 0b1111_1111, 0b1111_1110, (0b0111 << 4) | /* padding */ 0b1111;
        8 => 0b1111_1111, 0b1111_1111, 0b1111_1110, (0b1000 << 4) | /* padding */ 0b1111;
        11 => 0b1111_1111, 0b1111_1111, 0b1111_1110, (0b1001 << 4) | /* padding */ 0b1111;
        12 => 0b1111_1111, 0b1111_1111, 0b1111_1110, (0b1010 << 4) | /* padding */ 0b1111;
        14 => 0b1111_1111, 0b1111_1111, 0b1111_1110, (0b1011 << 4) | /* padding */ 0b1111;
        15 => 0b1111_1111, 0b1111_1111, 0b1111_1110, (0b1100 << 4) | /* padding */ 0b1111;
        16 => 0b1111_1111, 0b1111_1111, 0b1111_1110, (0b1101 << 4) | /* padding */ 0b1111;
        17 => 0b1111_1111, 0b1111_1111, 0b1111_1110, (0b1110 << 4) | /* padding */ 0b1111;
        18 => 0b1111_1111, 0b1111_1111, 0b1111_1110, (0b1111 << 4) | /* padding */ 0b1111;
        19 => 0b1111_1111, 0b1111_1111, 0b1111_1111, (0b0000 << 4) | /* padding */ 0b1111;
        20 => 0b1111_1111, 0b1111_1111, 0b1111_1111, (0b0001 << 4) | /* padding */ 0b1111;
        21 => 0b1111_1111, 0b1111_1111, 0b1111_1111, (0b0010 << 4) | /* padding */ 0b1111;
        23 => 0b1111_1111, 0b1111_1111, 0b1111_1111, (0b0011 << 4) | /* padding */ 0b1111;
        24 => 0b1111_1111, 0b1111_1111, 0b1111_1111, (0b0100 << 4) | /* padding */ 0b1111;
        25 => 0b1111_1111, 0b1111_1111, 0b1111_1111, (0b0101 << 4) | /* padding */ 0b1111;
        26 => 0b1111_1111, 0b1111_1111, 0b1111_1111, (0b0110 << 4) | /* padding */ 0b1111;
        27 => 0b1111_1111, 0b1111_1111, 0b1111_1111, (0b0111 << 4) | /* padding */ 0b1111;
        28 => 0b1111_1111, 0b1111_1111, 0b1111_1111, (0b1000 << 4) | /* padding */ 0b1111;
        29 => 0b1111_1111, 0b1111_1111, 0b1111_1111, (0b1001 << 4) | /* padding */ 0b1111;
        30 => 0b1111_1111, 0b1111_1111, 0b1111_1111, (0b1010 << 4) | /* padding */ 0b1111;
        31 => 0b1111_1111, 0b1111_1111, 0b1111_1111, (0b1011 << 4) | /* padding */ 0b1111;
        127 => 0b1111_1111, 0b1111_1111, 0b1111_1111, (0b1100 << 4) | /* padding */ 0b1111;
        220 => 0b1111_1111, 0b1111_1111, 0b1111_1111, (0b1101 << 4) | /* padding */ 0b1111;
        249 => 0b1111_1111, 0b1111_1111, 0b1111_1111, (0b1110 << 4) | /* padding */ 0b1111;
        10 => 0b1111_1111, 0b1111_1111, 0b1111_1111, (0b11_1100 << 2) | /* padding */ 0b11;
        13 => 0b1111_1111, 0b1111_1111, 0b1111_1111, (0b11_1101 << 2) | /* padding */ 0b11;
        22 => 0b1111_1111, 0b1111_1111, 0b1111_1111, (0b11_1110 << 2) | /* padding */ 0b11;
        // 256 => 0b1111_1111, 0b1111_1111, 0b1111_1111, (0b11_1111 << 2) | /* padding */ 0b11;
        ];
    }

    #[test]
    fn exact_byte_code_has_no_padding() {
        let encoded = vec![0b1111_1000];
        let mut decoded = encoded.hpack_decode();

        assert_eq!(decoded.next(), Some(Ok(b'&')));
        assert_eq!(decoded.symbol_end, 8);
        assert_eq!(decoded.next(), None);
    }

    #[test]
    fn rejects_invalid_huffman_terminators() {
        let invalid_padding: Result<Vec<_>, Error> = vec![0b0001_1010].hpack_decode().collect();
        assert_eq!(invalid_padding, Err(Error::InvalidPadding(3)));

        let overlong_padding: Result<Vec<_>, Error> =
            vec![0b1111_1000, 0b1111_1111].hpack_decode().collect();
        assert_eq!(overlong_padding, Err(Error::InvalidPadding(8)));

        let eos: Result<Vec<_>, Error> = vec![0xff, 0xff, 0xff, 0xff].hpack_decode().collect();
        assert_eq!(eos, Err(Error::Eos));

        let eos_followed_by_data: Result<Vec<_>, Error> =
            vec![0xff, 0xff, 0xff, 0xfc].hpack_decode().collect();
        assert_eq!(eos_followed_by_data, Err(Error::Eos));

        let encoded = vec![0xff, 0xff, 0xff, 0xfc];
        let mut decoded = encoded.hpack_decode();
        assert_eq!(decoded.next(), Some(Err(Error::Eos)));
        assert_eq!(decoded.next(), None);
    }

    #[test]
    fn accepts_zero_through_seven_padding_bits() {
        // These symbols have code lengths of 8, 7, 6, 5, 12, 11, 10,
        // and 25 bits, respectively.
        for symbol in [b'&', b'B', b' ', b'a', b'#', b'\'', b'!', 199] {
            let encoded = vec![symbol].hpack_encode().unwrap();
            let decoded: Result<Vec<_>, Error> = encoded.hpack_decode().collect();
            assert_eq!(decoded, Ok(vec![symbol]));
        }
    }

    #[test]
    fn every_accepted_short_input_is_canonical() {
        for value in 0u16..=u16::MAX {
            let bytes = value.to_be_bytes();
            for encoded in [&bytes[..1], &bytes[..]] {
                let decoded: Result<Vec<_>, Error> = encoded.to_vec().hpack_decode().collect();
                if let Ok(decoded) = decoded {
                    assert_eq!(decoded.hpack_encode().unwrap(), encoded);
                }
            }
        }
    }

    #[test]
    fn fast_decoder_matches_recursive_oracle_for_short_inputs() {
        assert_eq!(
            <[u8]>::hpack_decode(&[]).collect::<Result<Vec<_>, _>>(),
            oracle::decode(&[])
        );

        for value in 0u16..=u16::MAX {
            let bytes = value.to_be_bytes();
            for encoded in [&bytes[..1], &bytes[..]] {
                let decoded: Result<Vec<_>, Error> = encoded.hpack_decode().collect();
                assert_eq!(decoded, oracle::decode(encoded), "input {encoded:02x?}");
            }
        }
    }

    /**
     * https://tools.ietf.org/html/rfc7541
     * Appendix B.  Huffman Code
     */
    #[test]
    fn test_decode_all_code_joined() {
        let bytes = vec![
            // 0     |11111111|11000
            0b1111_1111,
            (0b11000 << 3)
                // 1     |11111111|11111111|1011000
                + 0b111,
            0b1111_1111,
            0b1111_1101,
            (0b1000 << 4)
                // 2     |11111111|11111111|11111110|0010
                + 0b1111,
            0b1111_1111,
            0b1111_1111,
            0b1110_0010,
            // 3     |11111111|11111111|11111110|0011
            0b1111_1111,
            0b1111_1111,
            0b1111_1110,
            (0b0011 << 4)
                // 4     |11111111|11111111|11111110|0100
                + 0b1111,
            0b1111_1111,
            0b1111_1111,
            0b1110_0100,
            // 5     |11111111|11111111|11111110|0101
            0b1111_1111,
            0b1111_1111,
            0b1111_1110,
            (0b0101 << 4)
                // 6     |11111111|11111111|11111110|0110
                + 0b1111,
            0b1111_1111,
            0b1111_1111,
            0b1110_0110,
            // 7     |11111111|11111111|11111110|0111
            0b1111_1111,
            0b1111_1111,
            0b1111_1110,
            (0b0111 << 4)
                // 8     |11111111|11111111|11111110|1000
                + 0b1111,
            0b1111_1111,
            0b1111_1111,
            0b1110_1000,
            // 9     |11111111|11111111|11101010
            0b1111_1111,
            0b1111_1111,
            0b1110_1010,
            // 10     |11111111|11111111|11111111|111100
            0b1111_1111,
            0b1111_1111,
            0b1111_1111,
            (0b11_1100 << 2)
                // 11     |11111111|11111111|11111110|1001
                + 0b11,
            0b1111_1111,
            0b1111_1111,
            0b1111_1010,
            (0b01 << 6)
                // 12     |11111111|11111111|11111110|1010
                + 0b11_1111,
            0b1111_1111,
            0b1111_1111,
            (0b10_1010 << 2)
                // 13     |11111111|11111111|11111111|111101
                + 0b11,
            0b1111_1111,
            0b1111_1111,
            0b1111_1111,
            (0b1101 << 4)
                // 14     |11111111|11111111|11111110|1011
                + 0b1111,
            0b1111_1111,
            0b1111_1111,
            0b1110_1011,
            // 15     |11111111|11111111|11111110|1100
            0b1111_1111,
            0b1111_1111,
            0b1111_1110,
            (0b1100 << 4)
                // 16     |11111111|11111111|11111110|1101
                + 0b1111,
            0b1111_1111,
            0b1111_1111,
            0b1110_1101,
            // 17     |11111111|11111111|11111110|1110
            0b1111_1111,
            0b1111_1111,
            0b1111_1110,
            (0b1110 << 4)
                // 18     |11111111|11111111|11111110|1111
                + 0b1111,
            0b1111_1111,
            0b1111_1111,
            0b1110_1111,
            // 19     |11111111|11111111|11111111|0000
            0b1111_1111,
            0b1111_1111,
            0b1111_1111,
            (0b0000 << 4)
                // 20     |11111111|11111111|11111111|0001
                + 0b1111,
            0b1111_1111,
            0b1111_1111,
            0b1111_0001,
            // 21     |11111111|11111111|11111111|0010
            0b1111_1111,
            0b1111_1111,
            0b1111_1111,
            (0b0010 << 4)
                // 22     |11111111|11111111|11111111|111110
                + 0b1111,
            0b1111_1111,
            0b1111_1111,
            0b1111_1111,
            (0b10 << 6)
                // 23     |11111111|11111111|11111111|0011
                + 0b11_1111,
            0b1111_1111,
            0b1111_1111,
            (0b11_0011 << 2)
                // 24     |11111111|11111111|11111111|0100
                + 0b11,
            0b1111_1111,
            0b1111_1111,
            0b1111_1101,
            (0b00 << 6)
                // 25     |11111111|11111111|11111111|0101
                + 0b11_1111,
            0b1111_1111,
            0b1111_1111,
            (0b11_0101 << 2)
                // 26     |11111111|11111111|11111111|0110
                + 0b11,
            0b1111_1111,
            0b1111_1111,
            0b1111_1101,
            (0b10 << 6)
                // 27     |11111111|11111111|11111111|0111
                + 0b11_1111,
            0b1111_1111,
            0b1111_1111,
            (0b11_0111 << 2)
                // 28     |11111111|11111111|11111111|1000
                + 0b11,
            0b1111_1111,
            0b1111_1111,
            0b1111_1110,
            (0b00 << 6)
                // 29     |11111111|11111111|11111111|1001
                + 0b11_1111,
            0b1111_1111,
            0b1111_1111,
            (0b11_1001 << 2)
                // 30     |11111111|11111111|11111111|1010
                + 0b11,
            0b1111_1111,
            0b1111_1111,
            0b1111_1110,
            (0b10 << 6)
                // 31     |11111111|11111111|11111111|1011
                + 0b11_1111,
            0b1111_1111,
            0b1111_1111,
            (0b11_1011 << 2)
                // 32     |010100
                + 0b01,
            (0b0100 << 4)
                // 33 -!- |11111110|00
                + 0b1111,
            (0b11_1000 << 2)
                // 34 -;- |11111110|01
                + 0b11,
            0b1111_1001,
            // 35 -#- |11111111|1010
            0b1111_1111,
            (0b1010 << 4)
                // 36 -$- |11111111|11001
                + 0b1111,
            0b1111_1100,
            (0b1 << 7)
                // 37 -%- |010101
                + (0b01_0101 << 1)
                // 38 -&- |11111000
                + 0b1,
            (0b111_1000 << 1)
                // 39 -'- |11111111|010
                + 0b1,
            0b1111_1110,
            (0b10 << 6)
                // 40 -(- |11111110|10
                + 0b11_1111,
            (0b1010 << 4)
                // 41 -)- |11111110|11
                + 0b1111,
            (0b11_1011 << 2)
                // 42 -*- |11111001
                + 0b11,
            (0b11_1001 << 2)
                // 43 -+- |11111111|011
                + 0b11,
            0b1111_1101,
            (0b1 << 7)
                // 44 -,- |11111010
                + 0b111_1101,
            (0b0 << 7)
                // 45 --- |010110
                + (0b01_0110 << 1)
                // 46 -.- |010111
                + 0b0,
            (0b10111 << 3)
                // 47 -/- |011000
                + 0b011,
            (0b000 << 5)
                // 48 -0- |00000
                + 0b00000,
            // 49 -1- |00001
            (0b00001 << 3)
                // 50 -2- |00010
                + 0b000,
            (0b10 << 6)
                // 51 -3- |011001
                + 0b01_1001,
            // 52 -4- |011010
            (0b01_1010 << 2)
                // 53 -5- |011011
                + 0b01,
            (0b1011 << 4)
                // 54 -6- |011100
                + 0b0111,
            (0b00 << 6)
                // 55 -7- |011101
                + 0b01_1101,
            // 56 -8- |011110
            (0b01_1110 << 2)
                // 57 -9- |011111
                + 0b01,
            (0b1111 << 4)
                // 58 -:- |1011100
                + 0b1011,
            (0b100 << 5)
                // 59     |11111011
                + 0b11111,
            (0b011 << 5)
                // 60 -<- |11111111|1111100
                + 0b11111,
            0b1111_1111,
            (0b00 << 6)
                // 61 -=- |100000
                + 0b10_0000,
            // 62 ->- |11111111|1011
            0b1111_1111,
            (0b1011 << 4)
                // 63 -?- |11111111|00
                + 0b1111,
            (0b11_1100 << 2)
                // 64 -@- |11111111|11010
                + 0b11,
            0b1111_1111,
            (0b010 << 5)
                // 65 -A- |100001
                + 0b10000,
            (0b1 << 7)
                // 66 -B- |1011101
                + 0b101_1101,
            // 67 -C- |1011110
            (0b101_1110 << 1)
                // 68 -D- |1011111
                + 0b1,
            (0b01_1111 << 2)
                // 69 -E- |1100000
                + 0b11,
            (0b00000 << 3)
                // 70 -F- |1100001
                + 0b110,
            (0b0001 << 4)
                // 71 -G- |1100010
                + 0b1100,
            (0b010 << 5)
                // 72 -H- |1100011
                + 0b11000,
            (0b11 << 6)
                // 73 -I- |1100100
                + 0b11_0010,
            (0b0 << 7)
                // 74 -J- |1100101
                + 0b110_0101,
            // 75 -K- |1100110
            (0b110_0110 << 1)
                // 76 -L- |1100111
                + 0b1,
            (0b10_0111 << 2)
                // 77 -M- |1101000
                + 0b11,
            (0b01000 << 3)
                // 78 -N- |1101001
                + 0b110,
            (0b1001 << 4)
                // 79 -O- |1101010
                + 0b1101,
            (0b010 << 5)
                // 80 -P- |1101011
                + 0b11010,
            (0b11 << 6)
                // 81 -Q- |1101100
                + 0b11_0110,
            (0b0 << 7)
                // 82 -R- |1101101
                + 0b110_1101,
            // 83 -S- |1101110
            (0b110_1110 << 1)
                // 84 -T- |1101111
                + 0b1,
            (0b10_1111 << 2)
                // 85 -U- |1110000
                + 0b11,
            (0b10000 << 3)
                // 86 -V- |1110001
                + 0b111,
            (0b0001 << 4)
                // 87 -W- |1110010
                + 0b1110,
            (0b010 << 5)
                // 88 -X- |11111100
                + 0b11111,
            (0b100 << 5)
                // 89 -Y- |1110011
                + 0b11100,
            (0b11 << 6)
                // 90 -Z- |11111101
                + 0b11_1111,
            (0b01 << 6)
                // 91 -[- |11111111|11011
                + 0b11_1111,
            (0b111_1011 << 1)
                // 92 -\- |11111111|11111110|000
                + 0b1,
            0b1111_1111,
            0b1111_1100,
            (0b00 << 6)
                // 93 -]- |11111111|11100
                + 0b11_1111,
            (0b111_1100 << 1)
                // 94 -^- |11111111|111100
                + 0b1,
            0b1111_1111,
            (0b11100 << 3)
                // 95 -_- |100010
                + 0b100,
            (0b010 << 5)
                // 96 -`- |11111111|1111101
                + 0b11111,
            0b1111_1111,
            (0b01 << 6)
                // 97 -a- |00011
                + (0b00011 << 1)
                // 98 -b- |100011
                + 0b1,
            (0b00011 << 3)
                // 99 -c- |00100
                + 0b001,
            (0b00 << 6)
                // 100 -d- |100100
                + 0b10_0100,
            // 101 -e- |00101
            (0b00101 << 3)
                // 102 -f- |100101
                + 0b100,
            (0b101 << 5)
                // 103 -g- |100110
                + 0b10011,
            (0b0 << 7)
                // 104 -h- |100111
                + (0b10_0111 << 1)
                // 105 -i- |00110
                + 0b0,
            (0b0110 << 4)
                // 106 -j- |1110100
                + 0b1110,
            (0b100 << 5)
                // 107 -k- |1110101
                + 0b11101,
            (0b01 << 6)
                // 108 -l- |101000
                + 0b10_1000,
            // 109 -m- |101001
            (0b10_1001 << 2)
                // 110 -n- |101010
                + 0b10,
            (0b1010 << 4)
                // 111 -o- |00111
                + 0b0011,
            (0b1 << 7)
                // 112 -p- |101011
                + (0b10_1011 << 1)
                // 113 -q- |1110110
                + 0b1,
            (0b11_0110 << 2)
                // 114 -r- |101100
                + 0b10,
            (0b1100 << 4)
                // 115 -s- |01000
                + 0b0100,
            (0b0 << 7)
                // 116 -t- |01001
                + (0b01001 << 2)
                // 117 -u- |101101
                + 0b10,
            (0b1101 << 4)
                // 118 -v- |1110111
                + 0b1110,
            (0b111 << 5)
                // 119 -w- |1111000
                + 0b11110,
            (0b00 << 6)
                // 120 -x- |1111001
                + 0b11_1100,
            (0b1 << 7)
                // 121 -y- |1111010
                + 0b111_1010,
            // 122 -z- |1111011
            (0b111_1011 << 1)
                // 123 -{- |11111111|1111110
                + 0b1,
            0b1111_1111,
            (0b11_1110 << 2)
                // 124 -|- |11111111|100
                + 0b11,
            0b1111_1110,
            (0b0 << 7)
                // 125 -}- |11111111|111101
                + 0b111_1111,
            (0b111_1101 << 1)
                // 126 -~- |11111111|11101
                + 0b1,
            0b1111_1111,
            (0b1101 << 4)
                // 127     |11111111|11111111|11111111|1100
                + 0b1111,
            0b1111_1111,
            0b1111_1111,
            0b1111_1100,
            // 128     |11111111|11111110|0110
            0b1111_1111,
            0b1111_1110,
            (0b0110 << 4)
                // 129     |11111111|11111111|010010
                + 0b1111,
            0b1111_1111,
            0b1111_0100,
            (0b10 << 6)
                // 130     |11111111|11111110|0111
                + 0b11_1111,
            0b1111_1111,
            (0b10_0111 << 2)
                // 131     |11111111|11111110|1000
                + 0b11,
            0b1111_1111,
            0b1111_1010,
            (0b00 << 6)
                // 132     |11111111|11111111|010011
                + 0b11_1111,
            0b1111_1111,
            0b1101_0011,
            // 133     |11111111|11111111|010100
            0b1111_1111,
            0b1111_1111,
            (0b01_0100 << 2)
                // 134     |11111111|11111111|010101
                + 0b11,
            0b1111_1111,
            0b1111_1101,
            (0b0101 << 4)
                // 135     |11111111|11111111|1011001
                + 0b1111,
            0b1111_1111,
            0b1111_1011,
            (0b001 << 5)
                // 136     |11111111|11111111|010110
                + 0b11111,
            0b1111_1111,
            0b1110_1011,
            (0b0 << 7)
                // 137     |11111111|11111111|1011010
                + 0b111_1111,
            0b1111_1111,
            0b1101_1010,
            // 138     |11111111|11111111|1011011
            0b1111_1111,
            0b1111_1111,
            (0b101_1011 << 1)
                // 139     |11111111|11111111|1011100
                + 0b1,
            0b1111_1111,
            0b1111_1111,
            (0b01_1100 << 2)
                // 140     |11111111|11111111|1011101
                + 0b11,
            0b1111_1111,
            0b1111_1110,
            (0b11101 << 3)
                // 141     |11111111|11111111|1011110
                + 0b111,
            0b1111_1111,
            0b1111_1101,
            (0b1110 << 4)
                // 142     |11111111|11111111|11101011
                + 0b1111,
            0b1111_1111,
            0b1111_1110,
            (0b1011 << 4)
                // 143     |11111111|11111111|1011111
                + 0b1111,
            0b1111_1111,
            0b1111_1011,
            (0b111 << 5)
                // 144     |11111111|11111111|11101100
                + 0b11111,
            0b1111_1111,
            0b1111_1101,
            (0b100 << 5)
                // 145     |11111111|11111111|11101101
                + 0b11111,
            0b1111_1111,
            0b1111_1101,
            (0b101 << 5)
                // 146     |11111111|11111111|010111
                + 0b11111,
            0b1111_1111,
            0b1110_1011,
            (0b1 << 7)
                // 147     |11111111|11111111|1100000
                + 0b111_1111,
            0b1111_1111,
            0b1110_0000,
            // 148     |11111111|11111111|11101110
            0b1111_1111,
            0b1111_1111,
            0b1110_1110,
            // 149     |11111111|11111111|1100001
            0b1111_1111,
            0b1111_1111,
            (0b110_0001 << 1)
                // 150     |11111111|11111111|1100010
                + 0b1,
            0b1111_1111,
            0b1111_1111,
            (0b10_0010 << 2)
                // 151     |11111111|11111111|1100011
                + 0b11,
            0b1111_1111,
            0b1111_1111,
            (0b00011 << 3)
                // 152     |11111111|11111111|1100100
                + 0b111,
            0b1111_1111,
            0b1111_1110,
            (0b0100 << 4)
                // 153     |11111111|11111110|11100
                + 0b1111,
            0b1111_1111,
            0b1110_1110,
            (0b0 << 7)
                // 154     |11111111|11111111|011000
                + 0b111_1111,
            0b1111_1111,
            (0b101_1000 << 1)
                // 155     |11111111|11111111|1100101
                + 0b1,
            0b1111_1111,
            0b1111_1111,
            (0b10_0101 << 2)
                // 156     |11111111|11111111|011001
                + 0b11,
            0b1111_1111,
            0b1111_1101,
            (0b1001 << 4)
                // 157     |11111111|11111111|1100110
                + 0b1111,
            0b1111_1111,
            0b1111_1100,
            (0b110 << 5)
                // 158     |11111111|11111111|1100111
                + 0b11111,
            0b1111_1111,
            0b1111_1001,
            (0b11 << 6)
                // 159     |11111111|11111111|11101111
                + 0b11_1111,
            0b1111_1111,
            0b1111_1011,
            (0b11 << 6)
                // 160     |11111111|11111111|011010
                + 0b11_1111,
            0b1111_1111,
            0b1101_1010,
            // 161     |11111111|11111110|11101
            0b1111_1111,
            0b1111_1110,
            (0b11101 << 3)
                // 162     |11111111|11111110|1001
                + 0b111,
            0b1111_1111,
            0b1111_0100,
            (0b1 << 7)
                // 163     |11111111|11111111|011011
                + 0b111_1111,
            0b1111_1111,
            (0b101_1011 << 1)
                // 164     |11111111|11111111|011100
                + 0b1,
            0b1111_1111,
            0b1111_1110,
            (0b11100 << 3)
                // 165     |11111111|11111111|1101000
                + 0b111,
            0b1111_1111,
            0b1111_1110,
            (0b1000 << 4)
                // 166     |11111111|11111111|1101001
                + 0b1111,
            0b1111_1111,
            0b1111_1101,
            (0b001 << 5)
                // 167     |11111111|11111110|11110
                + 0b11111,
            0b1111_1111,
            0b1101_1110,
            // 168     |11111111|11111111|1101010
            0b1111_1111,
            0b1111_1111,
            (0b110_1010 << 1)
                // 169     |11111111|11111111|011101
                + 0b1,
            0b1111_1111,
            0b1111_1110,
            (0b11101 << 3)
                // 170     |11111111|11111111|011110
                + 0b111,
            0b1111_1111,
            0b1111_1011,
            (0b110 << 5)
                // 171     |11111111|11111111|11110000
                + 0b11111,
            0b1111_1111,
            0b1111_1110,
            (0b000 << 5)
                // 172     |11111111|11111110|11111
                + 0b11111,
            0b1111_1111,
            0b1101_1111,
            // 173     |11111111|11111111|011111
            0b1111_1111,
            0b1111_1111,
            (0b01_1111 << 2)
                // 174     |11111111|11111111|1101011
                + 0b11,
            0b1111_1111,
            0b1111_1111,
            (0b01011 << 3)
                // 175     |11111111|11111111|1101100
                + 0b111,
            0b1111_1111,
            0b1111_1110,
            (0b1100 << 4)
                // 176     |11111111|11111111|00000
                + 0b1111,
            0b1111_1111,
            0b1111_0000,
            (0b0 << 7)
                // 177     |11111111|11111111|00001
                + 0b111_1111,
            0b1111_1111,
            (0b10_0001 << 2)
                // 178     |11111111|11111111|100000
                + 0b11,
            0b1111_1111,
            0b1111_1110,
            (0b0000 << 4)
                // 179     |11111111|11111111|00010
                + 0b1111,
            0b1111_1111,
            0b1111_0001,
            (0b0 << 7)
                // 180     |11111111|11111111|1101101
                + 0b111_1111,
            0b1111_1111,
            0b1110_1101,
            // 181     |11111111|11111111|100001
            0b1111_1111,
            0b1111_1111,
            (0b10_0001 << 2)
                // 182     |11111111|11111111|1101110
                + 0b11,
            0b1111_1111,
            0b1111_1111,
            (0b01110 << 3)
                // 183     |11111111|11111111|1101111
                + 0b111,
            0b1111_1111,
            0b1111_1110,
            (0b1111 << 4)
                // 184     |11111111|11111110|1010
                + 0b1111,
            0b1111_1111,
            0b1110_1010,
            // 185     |11111111|11111111|100010
            0b1111_1111,
            0b1111_1111,
            (0b10_0010 << 2)
                // 186     |11111111|11111111|100011
                + 0b11,
            0b1111_1111,
            0b1111_1110,
            (0b0011 << 4)
                // 187     |11111111|11111111|100100
                + 0b1111,
            0b1111_1111,
            0b1111_1001,
            (0b00 << 6)
                // 188     |11111111|11111111|1110000
                + 0b11_1111,
            0b1111_1111,
            0b1111_1000,
            (0b0 << 7)
                // 189     |11111111|11111111|100101
                + 0b111_1111,
            0b1111_1111,
            (0b110_0101 << 1)
                // 190     |11111111|11111111|100110
                + 0b1,
            0b1111_1111,
            0b1111_1111,
            (0b00110 << 3)
                // 191     |11111111|11111111|1110001
                + 0b111,
            0b1111_1111,
            0b1111_1111,
            (0b0001 << 4)
                // 192     |11111111|11111111|11111000|00
                + 0b1111,
            0b1111_1111,
            0b1111_1111,
            (0b10_0000 << 2)
                // 193     |11111111|11111111|11111000|01
                + 0b11,
            0b1111_1111,
            0b1111_1111,
            0b1110_0001,
            // 194     |11111111|11111110|1011
            0b1111_1111,
            0b1111_1110,
            (0b1011 << 4)
                // 195     |11111111|11111110|001
                + 0b1111,
            0b1111_1111,
            (0b111_0001 << 1)
                // 196     |11111111|11111111|100111
                + 0b1,
            0b1111_1111,
            0b1111_1111,
            (0b00111 << 3)
                // 197     |11111111|11111111|1110010
                + 0b111,
            0b1111_1111,
            0b1111_1111,
            (0b0010 << 4)
                // 198     |11111111|11111111|101000
                + 0b1111,
            0b1111_1111,
            0b1111_1010,
            (0b00 << 6)
                // 199     |11111111|11111111|11110110|0
                + 0b11_1111,
            0b1111_1111,
            0b1111_1101,
            (0b100 << 5)
                // 200     |11111111|11111111|11111000|10
                + 0b11111,
            0b1111_1111,
            0b1111_1111,
            (0b00010 << 3)
                // 201     |11111111|11111111|11111000|11
                + 0b111,
            0b1111_1111,
            0b1111_1111,
            (0b110_0011 << 1)
                // 202     |11111111|11111111|11111001|00
                + 0b1,
            0b1111_1111,
            0b1111_1111,
            0b1111_0010,
            (0b0 << 7)
                // 203     |11111111|11111111|11111011|110
                + 0b111_1111,
            0b1111_1111,
            0b1111_1101,
            (0b1110 << 4)
                // 204     |11111111|11111111|11111011|111
                + 0b1111,
            0b1111_1111,
            0b1111_1111,
            (0b101_1111 << 1)
                // 205     |11111111|11111111|11111001|01
                + 0b1,
            0b1111_1111,
            0b1111_1111,
            0b1111_0010,
            (0b1 << 7)
                // 206     |11111111|11111111|11110001
                + 0b111_1111,
            0b1111_1111,
            0b1111_1000,
            (0b1 << 7)
                // 207     |11111111|11111111|11110110|1
                + 0b111_1111,
            0b1111_1111,
            0b1111_1011,
            (0b01 << 6)
                // 208     |11111111|11111110|010
                + 0b11_1111,
            0b1111_1111,
            (0b10010 << 3)
                // 209     |11111111|11111111|00011
                + 0b111,
            0b1111_1111,
            0b1111_1000,
            (0b11 << 6)
                // 210     |11111111|11111111|11111001|10
                + 0b11_1111,
            0b1111_1111,
            0b1111_1110,
            (0b0110 << 4)
                // 211     |11111111|11111111|11111100|000
                + 0b1111,
            0b1111_1111,
            0b1111_1111,
            (0b110_0000 << 1)
                // 212     |11111111|11111111|11111100|001
                + 0b1,
            0b1111_1111,
            0b1111_1111,
            0b1111_1000,
            (0b01 << 6)
                // 213     |11111111|11111111|11111001|11
                + 0b11_1111,
            0b1111_1111,
            0b1111_1110,
            (0b0111 << 4)
                // 214     |11111111|11111111|11111100|010
                + 0b1111,
            0b1111_1111,
            0b1111_1111,
            (0b110_0010 << 1)
                // 215     |11111111|11111111|11110010
                + 0b1,
            0b1111_1111,
            0b1111_1111,
            (0b111_0010 << 1)
                // 216     |11111111|11111111|00100
                + 0b1,
            0b1111_1111,
            0b1111_1110,
            (0b0100 << 4)
                // 217     |11111111|11111111|00101
                + 0b1111,
            0b1111_1111,
            0b1111_0010,
            (0b1 << 7)
                // 218     |11111111|11111111|11111010|00
                + 0b111_1111,
            0b1111_1111,
            0b1111_1101,
            (0b000 << 5)
                // 219     |11111111|11111111|11111010|01
                + 0b11111,
            0b1111_1111,
            0b1111_1111,
            (0b01001 << 3)
                // 220     |11111111|11111111|11111111|1101
                + 0b111,
            0b1111_1111,
            0b1111_1111,
            0b1111_1110,
            (0b1 << 7)
                // 221     |11111111|11111111|11111100|011
                + 0b111_1111,
            0b1111_1111,
            0b1111_1110,
            (0b0011 << 4)
                // 222     |11111111|11111111|11111100|100
                + 0b1111,
            0b1111_1111,
            0b1111_1111,
            (0b110_0100 << 1)
                // 223     |11111111|11111111|11111100|101
                + 0b1,
            0b1111_1111,
            0b1111_1111,
            0b1111_1001,
            (0b01 << 6)
                // 224     |11111111|11111110|1100
                + 0b11_1111,
            0b1111_1111,
            (0b10_1100 << 2)
                // 225     |11111111|11111111|11110011
                + 0b11,
            0b1111_1111,
            0b1111_1111,
            (0b11_0011 << 2)
                // 226     |11111111|11111110|1101
                + 0b11,
            0b1111_1111,
            0b1111_1011,
            (0b01 << 6)
                // 227     |11111111|11111111|00110
                + 0b11_1111,
            0b1111_1111,
            (0b110_0110 << 1)
                // 228     |11111111|11111111|101001
                + 0b1,
            0b1111_1111,
            0b1111_1111,
            (0b01001 << 3)
                // 229     |11111111|11111111|00111
                + 0b111,
            0b1111_1111,
            0b1111_1001,
            (0b11 << 6)
                // 230     |11111111|11111111|01000
                + 0b11_1111,
            0b1111_1111,
            (0b110_1000 << 1)
                // 231     |11111111|11111111|1110011
                + 0b1,
            0b1111_1111,
            0b1111_1111,
            (0b11_0011 << 2)
                // 232     |11111111|11111111|101010
                + 0b11,
            0b1111_1111,
            0b1111_1110,
            (0b1010 << 4)
                // 233     |11111111|11111111|101011
                + 0b1111,
            0b1111_1111,
            0b1111_1010,
            (0b11 << 6)
                // 234     |11111111|11111111|11110111|0
                + 0b11_1111,
            0b1111_1111,
            0b1111_1101,
            (0b110 << 5)
                // 235     |11111111|11111111|11110111|1
                + 0b11111,
            0b1111_1111,
            0b1111_1110,
            (0b1111 << 4)
                // 236     |11111111|11111111|11110100
                + 0b1111,
            0b1111_1111,
            0b1111_1111,
            (0b0100 << 4)
                // 237     |11111111|11111111|11110101
                + 0b1111,
            0b1111_1111,
            0b1111_1111,
            (0b0101 << 4)
                // 238     |11111111|11111111|11111010|10
                + 0b1111,
            0b1111_1111,
            0b1111_1111,
            (0b10_1010 << 2)
                // 239     |11111111|11111111|1110100
                + 0b11,
            0b1111_1111,
            0b1111_1111,
            (0b10100 << 3)
                // 240     |11111111|11111111|11111010|11
                + 0b111,
            0b1111_1111,
            0b1111_1111,
            (0b110_1011 << 1)
                // 241     |11111111|11111111|11111100|110
                + 0b1,
            0b1111_1111,
            0b1111_1111,
            0b1111_1001,
            (0b10 << 6)
                // 242     |11111111|11111111|11111011|00
                + 0b11_1111,
            0b1111_1111,
            0b1111_1110,
            (0b1100 << 4)
                // 243     |11111111|11111111|11111011|01
                + 0b1111,
            0b1111_1111,
            0b1111_1111,
            (0b10_1101 << 2)
                // 244     |11111111|11111111|11111100|111
                + 0b11,
            0b1111_1111,
            0b1111_1111,
            0b1111_0011,
            (0b1 << 7)
                // 245     |11111111|11111111|11111101|000
                + 0b111_1111,
            0b1111_1111,
            0b1111_1110,
            (0b1000 << 4)
                // 246     |11111111|11111111|11111101|001
                + 0b1111,
            0b1111_1111,
            0b1111_1111,
            (0b110_1001 << 1)
                // 247     |11111111|11111111|11111101|010
                + 0b1,
            0b1111_1111,
            0b1111_1111,
            0b1111_1010,
            (0b10 << 6)
                // 248     |11111111|11111111|11111101|011
                + 0b11_1111,
            0b1111_1111,
            0b1111_1111,
            (0b01011 << 3)
                // 249     |11111111|11111111|11111111|1110
                + 0b111,
            0b1111_1111,
            0b1111_1111,
            0b1111_1111,
            (0b0 << 7)
                // 250     |11111111|11111111|11111101|100
                + 0b111_1111,
            0b1111_1111,
            0b1111_1110,
            (0b1100 << 4)
                // 251     |11111111|11111111|11111101|101
                + 0b1111,
            0b1111_1111,
            0b1111_1111,
            (0b110_1101 << 1)
                // 252     |11111111|11111111|11111101|110
                + 0b1,
            0b1111_1111,
            0b1111_1111,
            0b1111_1011,
            (0b10 << 6)
                // 253     |11111111|11111111|11111101|111
                + 0b11_1111,
            0b1111_1111,
            0b1111_1111,
            (0b01111 << 3)
                // 254     |11111111|11111111|11111110|000
                + 0b111,
            0b1111_1111,
            0b1111_1111,
            0b1111_0000,
            // 255     |11111111|11111111|11111011|10
            0b1111_1111,
            0b1111_1111,
            0b1111_1011,
            (0b10 << 6)
                // pad symbol 255 to the next byte boundary
                + 0b11_1111,
        ];
        let expected = (0u8..=255).collect();
        let res: Result<Vec<_>, Error> = bytes.hpack_decode().collect();
        assert_eq!(res, oracle::decode(&bytes));
        assert_eq!(res, Ok(expected));
    }
}
