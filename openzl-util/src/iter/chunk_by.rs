//! Chunking Iterator

// TODO: Add optimized implementations for other methods/iterators.

use crate::into_array_unchecked;
use alloc::vec::Vec;
use core::iter::FusedIterator;

/// Chunking Iterator
///
/// This `struct` is created by the [`chunk_by`] method on [`IteratorExt`].
/// See its documentation for more.
///
/// [`chunk_by`]: crate::iter::IteratorExt::chunk_by
/// [`IteratorExt`]: crate::iter::IteratorExt
#[derive(Clone)]
#[must_use = "iterators are lazy and do nothing unless consumed"]
pub struct ChunkBy<I, const N: usize>
where
    I: Iterator,
{
    /// Base Iterator
    iter: I,

    /// Remainder
    remainder: Option<Vec<I::Item>>,
}

impl<I, const N: usize> ChunkBy<I, N>
where
    I: Iterator,
{
    /// Builds a new [`ChunkBy`] iterator.
    #[inline]
    pub(super) fn new(iter: I) -> Self {
        Self {
            iter,
            remainder: None,
        }
    }

    /// Returns the remainder of the iterator after consuming all of the chunks.
    ///
    /// # Panics
    ///
    /// This method panics if all of the chunks have not been consumed yet. To check if the chunks
    /// have been consumed, call [`Iterator::next`] on `self` to see if it returns `None`.
    #[inline]
    pub fn remainder(self) -> Vec<I::Item> {
        self.remainder.unwrap()
    }
}

impl<I, const N: usize> Iterator for ChunkBy<I, N>
where
    I: Iterator,
{
    type Item = [I::Item; N];

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if self.remainder.is_some() {
            return None;
        }
        let mut vec = Vec::with_capacity(N);
        for _ in 0..N {
            match self.iter.next() {
                Some(next) => vec.push(next),
                _ => {
                    self.remainder = Some(vec);
                    return None;
                }
            }
        }
        Some(into_array_unchecked(vec))
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        let (min, max) = self.iter.size_hint();
        (min / N, max.map(|m| m / N))
    }
}

impl<I, const N: usize> FusedIterator for ChunkBy<I, N> where I: Iterator {}
