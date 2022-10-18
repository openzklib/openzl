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

//! Comparison Utilities

/// Independence Context
pub trait IndependenceContext {
    /// Default Independence Value
    const DEFAULT: bool;
}

/// Default True
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DefaultTrue;

impl IndependenceContext for DefaultTrue {
    const DEFAULT: bool = true;
}

/// Default False
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DefaultFalse;

impl IndependenceContext for DefaultFalse {
    const DEFAULT: bool = false;
}

/// Independence Relation
pub trait Independence<C>
where
    C: IndependenceContext + ?Sized,
{
    /// Determines if `fst` and `snd` are independent.
    ///
    /// # Implementation Note
    ///
    /// By default two values are given the independence value [`C::DEFAULT`] as specified on the
    /// `trait` parameter.
    ///
    /// [`C::DEFAULT`]: IndependenceContext::DEFAULT
    #[inline]
    fn is_independent(&self, rhs: &Self) -> bool {
        let _ = rhs;
        C::DEFAULT
    }

    /// Returns the negation of the [`is_independent`](Self::is_independent) method.
    #[inline]
    fn is_related(&self, rhs: &Self) -> bool {
        !self.is_independent(rhs)
    }
}

impl<C, T> Independence<C> for &T
where
    C: IndependenceContext + ?Sized,
    T: Independence<C> + ?Sized,
{
    #[inline]
    fn is_independent(&self, rhs: &Self) -> bool {
        (*self).is_independent(rhs)
    }
}
