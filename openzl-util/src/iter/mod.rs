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

//! Iteration Utilities

#[cfg(feature = "serde")]
use crate::serde::{Deserialize, Serialize};

#[doc(inline)]
pub use core::iter::*;

pub mod finder;

#[cfg(feature = "alloc")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "alloc")))]
pub mod chunk_by;

#[cfg(all(feature = "std", feature = "crossbeam-channel"))]
#[cfg_attr(doc_cfg, doc(cfg(all(feature = "std", feature = "crossbeam-channel"))))]
pub mod select_all;

pub use finder::Finder;

#[cfg(feature = "alloc")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "alloc")))]
pub use chunk_by::ChunkBy;

#[cfg(all(feature = "std", feature = "crossbeam-channel"))]
#[cfg_attr(doc_cfg, doc(cfg(all(feature = "std", feature = "crossbeam-channel"))))]
pub use select_all::SelectAll;

/// Iterator Extensions
pub trait IteratorExt: Iterator {
    /// Searches for an element of an iterator that the `finder` matches with, returning the mapped
    /// value from `f`.
    #[inline]
    fn find_with<T, F, R>(&mut self, finder: &mut Finder<T>, f: F) -> Option<R>
    where
        F: FnMut(&mut T, Self::Item) -> Option<R>,
    {
        finder.find(self, f)
    }

    /// Returns an iterator over chunks of size `N` from `iter`.
    ///
    /// # Note
    ///
    /// This is an alternative to [`ChunksExact`] but it works for any iterator and the
    /// chunk size must be known at compile time.
    ///
    /// [`ChunksExact`]: core::slice::ChunksExact
    #[cfg(feature = "alloc")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "alloc")))]
    #[inline]
    fn chunk_by<const N: usize>(self) -> ChunkBy<Self, N>
    where
        Self: Sized,
    {
        ChunkBy::new(self)
    }

    /// Selects items from each iterator in `self` in parallel.
    #[cfg(all(feature = "std", feature = "crossbeam-channel", feature = "rayon"))]
    #[cfg_attr(
        doc_cfg,
        doc(cfg(all(feature = "std", feature = "crossbeam-channel", feature = "rayon")))
    )]
    #[inline]
    fn select_all<'s, I>(self, scope: &rayon::Scope<'s>) -> SelectAll<I::Item>
    where
        Self: ExactSizeIterator<Item = I> + Sized,
        I: IntoIterator,
        I::IntoIter: 's + Send,
        I::Item: Send,
    {
        SelectAll::spawn(self, scope)
    }

    /// Folds every element into an accumulator by applying an operation, returning the final result.
    ///
    /// This function differs from [`Iterator::fold`] because its initial state is borrowed instead
    /// of owned. This means that we have to return `Option<B>` in case the iterator is empty.
    #[inline]
    fn fold_ref<B, F>(mut self, init: &B, mut f: F) -> Option<B>
    where
        Self: Sized,
        F: FnMut(&B, Self::Item) -> B,
    {
        self.next()
            .map(move |first| self.fold(f(init, first), move |acc, n| f(&acc, n)))
    }
}

impl<I> IteratorExt for I where I: Iterator {}

/// Borrowing Iterator Trait
pub trait IterRef<'i, I = &'i Self> {
    /// Borrowed Item Type
    type Item;

    /// Iterator Type
    type IntoIter: Iterator<Item = Self::Item>;

    /// Borrowing Iterator Type
    type Iter: IntoIterator<Item = Self::Item, IntoIter = Self::IntoIter>;

    /// Converts `this` into the iterator type.
    fn iter(this: I) -> Self::Iter;
}

impl<'i, I> IterRef<'i> for I
where
    I: ?Sized,
    for<'t> &'t Self: IntoIterator,
{
    type Item = <&'i Self as IntoIterator>::Item;
    type IntoIter = <&'i Self as IntoIterator>::IntoIter;
    type Iter = &'i Self;

    #[inline]
    fn iter(this: &'i Self) -> Self::Iter {
        this
    }
}

/// Item Type for [`IterRef`]
pub type RefItem<'t, T> = <T as IterRef<'t, &'t T>>::Item;

/// Borrowing Iterator Type for [`IterRef`]
pub type RefIter<'t, T> = <T as IterRef<'t, &'t T>>::Iter;

/// Exact Size Iteration Type
pub trait ExactSizeIterRef<'i, I = &'i Self> {
    /// Item Type
    type Item;

    /// Iterator Type
    type IntoIter: ExactSizeIterator<Item = Self::Item>;
}

impl<'i, I> ExactSizeIterRef<'i> for I
where
    for<'t> &'t Self: IntoIterator,
    <&'i Self as IntoIterator>::IntoIter: ExactSizeIterator,
{
    type Item = <&'i Self as IntoIterator>::Item;
    type IntoIter = <&'i Self as IntoIterator>::IntoIter;
}

/// Iterable Type
///
/// This `trait` is implemented for any type that has a borrowing [`IntoIterator`] implementation
/// for any reference of that type.
pub trait Iterable: for<'i> IterRef<'i> {
    /// Returns the iterator for `self`.
    #[inline]
    fn iter(&self) -> <RefIter<Self> as IntoIterator>::IntoIter {
        <Self as IterRef<'_>>::iter(self).into_iter()
    }

    /// Returns the converting iterator for `self`.
    #[inline]
    fn convert_iter<'t, T>(&'t self) -> ConvertItemRefMap<'t, T, Self>
    where
        Self: ConvertItemRef<'t, T, Item = RefItem<'t, Self>>,
    {
        self.iter().map(|item| Self::convert_item(item))
    }
}

impl<T> Iterable for T where T: for<'i> IterRef<'i> + ?Sized {}

/// Exact Size Iterable
pub trait ExactSizeIterable:
    for<'i> IterRef<'i, IntoIter = <Self as ExactSizeIterRef<'i>>::IntoIter>
    + for<'i> ExactSizeIterRef<'i, Item = RefItem<'i, Self>>
{
}

impl<I> ExactSizeIterable for I where
    I: for<'i> IterRef<'i, IntoIter = <Self as ExactSizeIterRef<'i>>::IntoIter>
        + for<'i> ExactSizeIterRef<'i, Item = RefItem<'i, Self>>
{
}

/// [`ConvertItemRef`] Map Type
pub type ConvertItemRefMap<'t, T, I> =
    Map<<RefIter<'t, I> as IntoIterator>::IntoIter, fn(RefItem<'t, I>) -> T>;

/// Item Type Converter
pub trait ConvertItemRef<'i, T, I = &'i Self> {
    /// Item Type
    type Item: Into<T>;

    /// Converts `item` into an element of type `T`.
    #[inline]
    fn convert_item(item: Self::Item) -> T {
        item.into()
    }
}

impl<'i, T, I> ConvertItemRef<'i, T> for I
where
    I: ?Sized,
    for<'t> &'t Self: IntoIterator,
    <&'i Self as IntoIterator>::Item: Into<T>,
{
    type Item = <&'i Self as IntoIterator>::Item;
}

/// Borrow Iterator
pub trait BorrowIterator<T>: for<'i> IterRef<'i, Item = &'i T> {}

impl<T, I> BorrowIterator<T> for I where I: for<'i> IterRef<'i, Item = &'i T> {}

/// For-Each Collector
///
/// In the same way that `() : FromIterator<()>` which just calls [`Iterator::for_each`] internally,
/// this `struct` does the same but for `FromIterator<T>` for all `T`.
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "crate::serde", deny_unknown_fields)
)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ForEach;

impl<T> FromIterator<T> for ForEach {
    #[inline]
    fn from_iter<I>(iter: I) -> Self
    where
        I: IntoIterator<Item = T>,
    {
        iter.into_iter().for_each(|_| {});
        Self
    }
}
