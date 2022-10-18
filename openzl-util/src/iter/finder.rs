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

//! Iterator Search Utilities

/// Stateful Finder
///
/// This `struct` is an alternative to [`Iterator::find_map`] whenever the closure has some concrete
/// state that is used during each round of the iteration.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Finder<T> {
    /// Possible Internal State
    state: Option<T>,
}

impl<T> Finder<T> {
    /// Builds a new [`Finder`] with `state`.
    #[inline]
    pub fn new(state: T) -> Self {
        Self { state: Some(state) }
    }

    /// Returns `true` if a match was found at some point.
    #[inline]
    pub fn found(&self) -> bool {
        self.state.is_none()
    }

    /// Calls `f` on the internal state of `self` if a match has not been found until now. `None` is
    /// returned if a match was found in a previous round.
    #[inline]
    pub fn next<F, R>(&mut self, f: F) -> Option<R>
    where
        F: FnOnce(&mut T) -> Option<R>,
    {
        if let Some(mut state) = self.state.take() {
            match f(&mut state) {
                Some(result) => return Some(result),
                _ => self.state = Some(state),
            }
        }
        None
    }

    /// Iterates over `iter` looking for the first call of `f` that returns `Some`, returning its
    /// output value.
    #[inline]
    pub fn find<F, I, R>(&mut self, iter: I, mut f: F) -> Option<R>
    where
        I: IntoIterator,
        F: FnMut(&mut T, I::Item) -> Option<R>,
    {
        iter.into_iter().find_map(|i| self.next(|t| f(t, i)))
    }

    /// Returns the internal state of the [`Finder`].
    #[inline]
    pub fn into_inner(self) -> Option<T> {
        self.state
    }
}
