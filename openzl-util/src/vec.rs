// Copyright 2019-2022 Manta Network.
// This file is part of manta-rs.
//
// manta-rs is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// manta-rs is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with manta-rs.  If not, see <http://www.gnu.org/licenses/>.

//! Vectors

use crate::create_seal;
use core::iter::{once, repeat_with};

#[doc(inline)]
pub use alloc::vec::*;

create_seal! {}

impl<T> sealed::Sealed for Vec<T> {}

/// Vector Extension Trait
pub trait VecExt<T>: From<Vec<T>> + Into<Vec<T>> + sealed::Sealed + Sized {
    /// Returns the `n`th element of `self`, dropping the rest of the vector.
    #[inline]
    fn take(self, n: usize) -> T {
        let mut vec = self.into();
        vec.truncate(n + 1);
        vec.remove(n)
    }

    /// Returns the first element of `self`, dropping the rest of the vector.
    #[inline]
    fn take_first(self) -> T {
        self.take(0)
    }

    /// Allocates a vector of length `n` and initializes with `f`.
    #[inline]
    fn allocate_with<F>(n: usize, f: F) -> Self
    where
        F: FnMut() -> T,
    {
        let mut vec = Vec::with_capacity(n);
        vec.resize_with(n, f);
        vec.into()
    }

    /// Allocates a vector of length `n` and tries to initialize it with `f`, returning an error if
    /// `f` ever fails.
    #[inline]
    fn try_allocate_with<E, F>(n: usize, f: F) -> Result<Self, E>
    where
        F: FnMut(usize) -> Result<T, E>,
    {
        (0..n).map(f).collect::<Result<Vec<_>, _>>().map(Into::into)
    }
}

impl<T> VecExt<T> for Vec<T> {}

/// Chunks `slice` into vectors of length `width` and pads the last vector with `default`
/// if its length is less than `width`.
///
/// # Panics
///
/// Panics if `width` is `0`.
#[inline]
pub fn padded_chunks_with<T, F>(slice: &[T], width: usize, default: F) -> Vec<Vec<T>>
where
    T: Clone,
    F: FnMut() -> T,
{
    let chunks = slice.chunks_exact(width);
    let remainder = chunks.remainder();
    chunks
        .map(Vec::from)
        .chain(once(
            remainder
                .iter()
                .cloned()
                .chain(repeat_with(default).take(width - remainder.len()))
                .collect(),
        ))
        .collect()
}

/// Chunks `slice` into vectors of length `width` and pads the last vector if its length
/// is less than `width`.
///
/// # Panics
///
/// Panics if `width` is `0`.
#[inline]
pub fn padded_chunks<T>(slice: &[T], width: usize) -> Vec<Vec<T>>
where
    T: Clone + Default,
{
    padded_chunks_with(slice, width, Default::default)
}

/// Returns `true` if all elements of `slice` return `false` when compared with `eq`.
///
/// # Partial Equivalence Relation
///
/// The `eq` function _must_ satisfy all the requirements for a [`PartialEq`] implementation.
#[inline]
pub fn all_unequal<T, F>(slice: &[T], mut eq: F) -> bool
where
    F: FnMut(&T, &T) -> bool,
{
    for (i, x) in slice.iter().enumerate() {
        if slice.iter().skip(i + 1).any(|y| eq(x, y)) {
            return false;
        }
    }
    true
}
