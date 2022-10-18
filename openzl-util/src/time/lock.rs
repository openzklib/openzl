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

//! Time-synchronized and Time-locked Data

use crate::time::{Duration, Instant};
use core::{mem, ops::Deref};

#[cfg(feature = "serde")]
use crate::serde::{Deserialize, Serialize};

/// Timed Data
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "crate::serde", deny_unknown_fields)
)]
#[derive(Copy, Debug, Eq, Hash, PartialEq)]
pub struct Timed<T> {
    /// Value
    value: T,

    /// Instant
    #[cfg_attr(feature = "serde", serde(skip, default = "Instant::now"))]
    instant: Instant,
}

impl<T> Timed<T> {
    /// Builds a new [`Timed`] object over `value`.
    #[inline]
    pub fn new(value: T) -> Self {
        Self::new_unchecked(value, Instant::now())
    }

    /// Builds a new [`Timed`] object over `value` created at the given `instant` without checking
    /// that `instant` is [`Instant::now`].
    #[inline]
    pub const fn new_unchecked(value: T, instant: Instant) -> Self {
        Self { instant, value }
    }

    /// Returns a shared reference to the underlying data.
    #[inline]
    pub const fn get(&self) -> &T {
        &self.value
    }

    /// Returns the last [`Instant`] that `self` was modified. See [`elapsed`](Self::elapsed) to get
    /// the amount of time since the last modification.
    #[inline]
    pub const fn modified_at(&self) -> Instant {
        self.instant
    }

    /// Returns the amount of time that has elapsed since the last modification of the underlying
    /// value. See [`modified_at`](Self::modified_at) to get the [`Instant`] of the last
    /// modification.
    #[inline]
    pub fn elapsed(&self) -> Duration {
        self.instant.elapsed()
    }

    /// Returns `true` if the amount of time elapsed since the last modification is larger than the
    /// `timeout`.
    #[inline]
    pub fn has_expired(&self, timeout: Duration) -> bool {
        self.elapsed() >= timeout
    }

    /// Resets the modification time to the value returned by [`Instant::now`].
    #[inline]
    pub fn tap(&mut self) {
        self.instant = Instant::now();
    }

    /// Sets the internal value to `value` returning the old value.
    #[inline]
    pub fn set(&mut self, value: T) -> T {
        self.mutate(move |t| mem::replace(t, value))
    }

    /// Mutates the internal value using `f`, resetting the modification time to [`Instant::now`].
    #[inline]
    pub fn mutate<F, R>(&mut self, f: F) -> R
    where
        F: FnOnce(&mut T) -> R,
    {
        self.mutate_timed(move |value, _| f(value))
    }

    /// Mutates the internal value with the [`Instant`] of the last modification to `self`,
    /// resetting the modification time to [`Instant::now`].
    #[inline]
    pub fn mutate_timed<F, R>(&mut self, f: F) -> R
    where
        F: FnOnce(&mut T, Instant) -> R,
    {
        let result = f(&mut self.value, self.instant);
        self.tap();
        result
    }

    /// Mutates the internal value using `f` if the amount of time since the last modification to
    /// `self` was longer than `timeout`.
    #[inline]
    pub fn mutate_if_expired<F, R>(&mut self, timeout: Duration, f: F) -> Option<R>
    where
        F: FnOnce(&mut T) -> R,
    {
        if self.has_expired(timeout) {
            Some(self.mutate(f))
        } else {
            None
        }
    }

    /// Sets the internal value to `value` if the amount of time since the last modification to
    /// `self` was longer than `timeout`.
    #[inline]
    pub fn set_if_expired(&mut self, timeout: Duration, value: T) -> Option<T> {
        self.set_with_if_expired(timeout, move || value)
    }

    /// Sets the internal value using `value` if the amount of time since the last modification to
    /// `self` was longer than `timeout`.
    #[inline]
    pub fn set_with_if_expired<F>(&mut self, timeout: Duration, value: F) -> Option<T>
    where
        F: FnOnce() -> T,
    {
        self.mutate_if_expired(timeout, move |t| mem::replace(t, value()))
    }

    /// Returns the underlying timed value, dropping `self`.
    #[inline]
    pub fn into_inner(self) -> T {
        self.value
    }

    /// Returns the underlying timed value and its last modification time, dropping `self`.
    #[inline]
    pub fn into_pair(self) -> (T, Instant) {
        (self.value, self.instant)
    }
}

impl<T> AsRef<T> for Timed<T> {
    #[inline]
    fn as_ref(&self) -> &T {
        self.get()
    }
}

impl<T> Clone for Timed<T>
where
    T: Clone,
{
    /// Clones the underlying data, creating a new [`Timed`] object with a new creation time set to
    /// the return value of [`Instant::now`].
    #[inline]
    fn clone(&self) -> Self {
        Self::new(self.value.clone())
    }
}

impl<T> Default for Timed<T>
where
    T: Default,
{
    /// Builds a new [`Timed`] object from the default value of `T` and the current time returned by
    /// [`Instant::now`].
    #[inline]
    fn default() -> Self {
        Self::new(Default::default())
    }
}

impl<T> Deref for Timed<T> {
    type Target = T;

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.get()
    }
}

impl<T> From<Timed<T>> for (T, Instant) {
    #[inline]
    fn from(timed: Timed<T>) -> Self {
        timed.into_pair()
    }
}
