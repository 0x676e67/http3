use std::{collections::VecDeque, io::IoSlice};

use bytes::{Buf, Bytes, BytesMut};

#[derive(Debug)]
pub(crate) struct BufList<T> {
    bufs: VecDeque<T>,
    remaining: usize,
}

impl<T: Buf> BufList<T> {
    pub(crate) fn new() -> BufList<T> {
        BufList {
            bufs: VecDeque::new(),
            remaining: 0,
        }
    }

    #[inline]
    pub(crate) fn push(&mut self, buf: T) {
        debug_assert!(buf.has_remaining());
        self.remaining = self.remaining.saturating_add(buf.remaining());
        self.bufs.push_back(buf);
    }

    pub fn cursor(&self) -> Cursor<'_, T> {
        Cursor {
            buf: self,
            pos_total: 0,
            index: 0,
            pos_front: 0,
        }
    }
}

impl BufList<Bytes> {
    pub fn take_first_chunk(&mut self) -> Option<Bytes> {
        let chunk = self.bufs.pop_front()?;
        self.remaining = self.remaining.saturating_sub(chunk.remaining());
        Some(chunk)
    }

    pub fn take_chunk(&mut self, max_len: usize) -> Option<Bytes> {
        let front = self.bufs.front_mut()?;
        let chunk = if max_len >= front.remaining() {
            self.bufs.pop_front()?
        } else {
            front.split_to(max_len)
        };
        self.remaining = self.remaining.saturating_sub(chunk.remaining());
        Some(chunk)
    }

    pub fn push_bytes<T>(&mut self, buf: &mut T)
    where
        T: Buf,
    {
        debug_assert!(buf.has_remaining());
        self.push(buf.copy_to_bytes(buf.remaining()))
    }

    /// Consumes `len` bytes, returning an existing `Bytes` chunk or slice without
    /// copying whenever the range lies within the front chunk.
    ///
    /// Returns `None` without mutating the buffer if fewer than `len` bytes remain.
    pub(crate) fn take_bytes(&mut self, len: usize) -> Option<Bytes> {
        if len > self.remaining {
            return None;
        }
        if len == 0 {
            return Some(Bytes::new());
        }

        if let Some(front) = self.bufs.front_mut() {
            let front_len = front.remaining();
            if len == front_len {
                if let Some(chunk) = self.bufs.pop_front() {
                    self.remaining = self.remaining.saturating_sub(len);
                    return Some(chunk);
                }
            } else if len < front_len {
                let chunk = front.split_to(len);
                self.remaining = self.remaining.saturating_sub(len);
                return Some(chunk);
            }
        }

        let mut out = BytesMut::with_capacity(len);
        let mut needed = len;
        while needed > 0 {
            let Some(chunk) = self.take_chunk(needed) else {
                break;
            };
            needed = needed.saturating_sub(chunk.len());
            out.extend_from_slice(&chunk);
        }
        Some(out.freeze())
    }
}

#[cfg(test)]
impl<T: Buf> From<T> for BufList<T> {
    fn from(b: T) -> Self {
        let mut buf = Self::new();
        buf.push(b);
        buf
    }
}

impl<T: Buf> Buf for BufList<T> {
    #[inline]
    fn remaining(&self) -> usize {
        self.remaining
    }

    #[inline]
    fn chunk(&self) -> &[u8] {
        self.bufs.front().map(Buf::chunk).unwrap_or_default()
    }

    #[inline]
    fn advance(&mut self, mut cnt: usize) {
        assert!(cnt <= self.remaining, "cannot advance past the buffer");
        self.remaining -= cnt;

        while cnt > 0 {
            {
                let front = &mut self.bufs[0];
                let rem = front.remaining();
                if rem > cnt {
                    front.advance(cnt);
                    return;
                } else {
                    front.advance(rem);
                    cnt -= rem;
                }
            }
            self.bufs.pop_front();
        }
    }

    #[inline]
    fn chunks_vectored<'t>(&'t self, dst: &mut [IoSlice<'t>]) -> usize {
        if dst.is_empty() {
            return 0;
        }
        let mut vecs = 0;
        for buf in &self.bufs {
            vecs += buf.chunks_vectored(&mut dst[vecs..]);
            if vecs == dst.len() {
                break;
            }
        }
        vecs
    }
}

#[derive(Clone)]
pub struct Cursor<'a, B> {
    buf: &'a BufList<B>,
    pos_total: usize, // position amongst all bytes
    pos_front: usize, // position in the current front buffer
    index: usize,     // current front buffer index
}

impl<'a, B: Buf> Cursor<'a, B> {
    pub fn position(&self) -> usize {
        self.pos_total
    }
}

impl<'a, B: Buf> Buf for Cursor<'a, B> {
    #[inline]
    fn remaining(&self) -> usize {
        self.buf.remaining() - self.pos_total
    }

    #[inline]
    fn chunk(&self) -> &[u8] {
        &self.buf.bufs[self.index].chunk()[self.pos_front..]
    }

    #[inline]
    fn advance(&mut self, mut cnt: usize) {
        assert!(cnt <= self.buf.remaining() - self.pos_total);
        while cnt > 0 {
            {
                let front = &self.buf.bufs[self.index];
                let rem = front.remaining() - self.pos_front;
                if rem > cnt {
                    self.pos_total += cnt;
                    self.pos_front += cnt;
                    return;
                } else {
                    self.pos_total += rem;
                    self.pos_front = 0;
                    cnt -= rem;
                }
            }
            self.index += 1;
        }
    }

    #[inline]
    fn chunks_vectored<'t>(&'t self, dst: &mut [IoSlice<'t>]) -> usize {
        self.buf.chunks_vectored(dst)
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::*;

    #[test]
    fn cursor_advance() {
        let buf = BufList::from(Bytes::from_static(&[1u8, 2, 3, 4]));
        let mut cur = buf.cursor();
        cur.advance(2);
        assert_eq!(cur.remaining(), 2);
        cur.advance(2);
        assert_eq!(cur.remaining(), 0);
    }

    #[test]
    fn remaining_tracks_buffer_mutations() {
        let mut buf = BufList::new();
        buf.push(Bytes::from_static(b"abc"));
        buf.push(Bytes::from_static(b"de"));
        assert_eq!(buf.remaining(), 5);

        assert_eq!(buf.take_chunk(2), Some(Bytes::from_static(b"ab")));
        assert_eq!(buf.remaining(), 3);

        buf.advance(2);
        assert_eq!(buf.remaining(), 1);

        assert_eq!(buf.take_first_chunk(), Some(Bytes::from_static(b"e")));
        assert_eq!(buf.remaining(), 0);
    }

    #[test]
    fn take_chunk_and_take_bytes_avoid_copying_contiguous_chunks() {
        let whole = Bytes::from(b"hello".to_vec());
        let whole_ptr = whole.as_ptr();
        let mut buf = BufList::from(whole);
        let taken = buf.take_chunk(16).unwrap();
        assert_eq!(taken.as_ptr(), whole_ptr);
        assert_eq!(buf.remaining(), 0);

        let combined = Bytes::from(b"abcdef".to_vec());
        let combined_ptr = combined.as_ptr();
        let mut buf = BufList::from(combined);
        assert!(buf.take_bytes(7).is_none());
        assert_eq!(buf.remaining(), 6);
        let prefix = buf.take_bytes(3).unwrap();
        assert_eq!(&prefix[..], b"abc");
        assert_eq!(prefix.as_ptr(), combined_ptr);
        let rest = buf.take_bytes(3).unwrap();
        assert_eq!(&rest[..], b"def");
        assert_eq!(rest.as_ptr(), combined_ptr.wrapping_add(3));
        assert_eq!(buf.remaining(), 0);

        // Multi-chunk take_bytes concatenates seamlessly.
        let mut fragmented = BufList::new();
        fragmented.push(Bytes::from_static(b"ab"));
        fragmented.push(Bytes::from_static(b"cde"));
        assert_eq!(fragmented.take_bytes(0), Some(Bytes::new()));
        assert_eq!(fragmented.take_bytes(4), Some(Bytes::from_static(b"abcd")));
        assert_eq!(fragmented.take_bytes(1), Some(Bytes::from_static(b"e")));
        assert_eq!(fragmented.remaining(), 0);
    }
}
