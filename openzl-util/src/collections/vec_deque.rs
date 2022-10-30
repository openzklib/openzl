//! A double-ended queue (deque) implemented with a growable ring buffer.

use crate::{array::BoxArray, collections::VecDeque};

#[cfg(all(feature = "serde-alloc", feature = "serde-array"))]
use crate::serde::{Deserialize, Serialize};

#[doc(inline)]
pub use alloc::collections::vec_deque::*;

/// Multi-[`VecDeque`]
#[cfg_attr(
    all(feature = "serde-alloc", feature = "serde-array"),
    derive(Deserialize, Serialize),
    serde(
        bound(deserialize = "T: Deserialize<'de>", serialize = "T: Serialize"),
        crate = "crate::serde",
        deny_unknown_fields
    )
)]
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct MultiVecDeque<T, const N: usize>(BoxArray<VecDeque<T>, N>);

impl<T, const N: usize> MultiVecDeque<T, N> {
    /// Builds a new empty [`MultiVecDeque`].
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns a shared reference to the [`VecDeque`] at the given `level`.
    #[inline]
    pub fn at_level(&self, level: usize) -> &VecDeque<T> {
        &self.0[level]
    }

    /// Returns a mutable reference to the [`VecDeque`] at the given `level`.
    #[inline]
    pub fn at_level_mut(&mut self, level: usize) -> &mut VecDeque<T> {
        &mut self.0[level]
    }

    /// Returns the total number of elements in `self`.
    #[inline]
    pub fn len(&self) -> usize {
        self.0.iter().map(VecDeque::len).sum()
    }

    /// Returns `true` if `self` has no elements.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.0.iter().all(VecDeque::is_empty)
    }

    /// Returns a shared reference to the element at the given `index` in `self`.
    #[inline]
    pub fn get(&self, mut index: usize) -> Option<&T> {
        for level in self.0.iter() {
            match level.get(index) {
                None => index -= level.len(),
                item => return item,
            }
        }
        None
    }

    /// Returns a mutable reference to the element at the given `index` in `self`.
    #[inline]
    pub fn get_mut(&mut self, mut index: usize) -> Option<&mut T> {
        for level in self.0.iter_mut() {
            let len = level.len();
            match level.get_mut(index) {
                None => index -= len,
                item => return item,
            }
        }
        None
    }

    /// Returns a shared reference to the first element in the deque.
    #[inline]
    pub fn front(&self) -> Option<&T> {
        self.0.iter().find_map(VecDeque::front)
    }

    /// Returns a mutable reference to the first element in the deque.
    #[inline]
    pub fn front_mut(&mut self) -> Option<&mut T> {
        self.0.iter_mut().find_map(VecDeque::front_mut)
    }

    /// Returns `true` if `item` is at the front of the deque.
    #[inline]
    pub fn is_front(&self, item: &T) -> bool
    where
        T: PartialEq,
    {
        self.is_front_with(item, PartialEq::eq)
    }

    /// Returns `true` if `item` is at the front of the deque using `eq` to compare elements of type
    /// `T`.
    #[inline]
    pub fn is_front_with<F>(&self, item: &T, eq: F) -> bool
    where
        F: FnOnce(&T, &T) -> bool,
    {
        if let Some(front) = self.front() {
            eq(front, item)
        } else {
            false
        }
    }

    /// Returns the number of elements before the [`VecDeque`] at the given `level`.
    #[inline]
    fn leading_element_count(&self, level: usize) -> usize {
        self.0[0..level].iter().map(VecDeque::len).sum::<usize>()
    }

    /// Finds the position of `item` assuming it was inserted at the given `level`.
    #[inline]
    pub fn position(&self, level: usize, item: &T) -> Option<usize>
    where
        T: PartialEq,
    {
        self.position_with(level, item, PartialEq::eq)
    }

    /// Finds the position of `item` assuming it was inserted at the given `level` using `eq` to
    /// compare elements of type `T`.
    #[inline]
    pub fn position_with<F>(&self, level: usize, item: &T, mut eq: F) -> Option<usize>
    where
        F: FnMut(&T, &T) -> bool,
    {
        Some(self.0[level].iter().position(|x| eq(x, item))? + self.leading_element_count(level))
    }

    /// Pushes `item` to the back of the deque at the given `level`.
    ///
    /// # Note
    ///
    /// This method is an alias for `self.at_level_mut(level).push_back(item)`.
    #[inline]
    pub fn push_back(&mut self, level: usize, item: T) {
        self.0[level].push_back(item)
    }

    /// Removes the element at the front of the deque if `self` is not empty.
    #[inline]
    pub fn pop_front(&mut self) -> Option<T> {
        self.0.iter_mut().find_map(VecDeque::pop_front)
    }

    /// Pushes back `item` at `level` if `item` is missing. Returns the position
    /// of `item` in both cases.
    #[inline]
    pub fn push_back_if_missing(&mut self, level: usize, item: T) -> usize
    where
        T: PartialEq,
    {
        match self.position(level, &item) {
            Some(position) => position,
            None => {
                self.push_back(level, item);
                self.leading_element_count(level) + self.0[level].len() - 1
            }
        }
    }
}

impl<T, const N: usize> Default for MultiVecDeque<T, N> {
    #[inline]
    fn default() -> Self {
        Self(Default::default())
    }
}
