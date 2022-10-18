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

//! Utility Macros

/// Asserts that all the elements in `$tail` have the same length as `$head`.
#[macro_export]
macro_rules! assert_all_eq_len {
    ([$head:expr, $($tail:expr),+ $(,)?]) => {{
        $(
            assert_eq!(
                $head.len(),
                $tail.len(),
            );
        )+
    }};
    ([$head:expr, $($tail:expr),+], $($arg:tt)+) => {{
        let __format = core::format_args!($($arg)+);
        $(
            assert_eq!(
                $head.len(),
                $tail.len(),
                "{}", __format,
            );
        )+
    }};
}

/// Implements [`From`]`<$from>` for an enum `$to`, choosing the `$kind` variant.
#[macro_export]
macro_rules! from_variant {
    ($to:ty, $kind:ident, $from:ty) => {
        impl From<$from> for $to {
            #[inline]
            fn from(t: $from) -> Self {
                Self::$kind(t)
            }
        }
    };
}

/// Calls the `into_iter` method on `$e` or the `into_par_iter` Rayon method if the `rayon` feature
/// is enabled.
#[macro_export]
macro_rules! cfg_into_iter {
    ($e:expr) => {{
        #[cfg(feature = "rayon")]
        {
            use $crate::rayon::iter::IntoParallelIterator as _;
            $e.into_par_iter()
        }
        #[cfg(not(feature = "rayon"))]
        $e.into_iter()
    }};
    ($e:expr, $min_len:expr) => {{
        #[cfg(feature = "rayon")]
        {
            use $crate::rayon::iter::IntoParallelIterator as _;
            $e.into_par_iter().with_min_len($min_len)
        }
        #[cfg(not(feature = "rayon"))]
        $e.into_iter()
    }};
}

/// Calls the `iter` method on `$e` or the `par_iter` Rayon method if the `rayon` feature is
/// enabled.
#[macro_export]
macro_rules! cfg_iter {
    ($e:expr) => {{
        #[cfg(feature = "rayon")]
        {
            use $crate::rayon::iter::IntoParallelRefIterator as _;
            $e.par_iter()
        }
        #[cfg(not(feature = "rayon"))]
        $e.iter()
    }};
    ($e:expr, $min_len:expr) => {{
        #[cfg(feature = "rayon")]
        {
            use $crate::rayon::iter::IntoParallelRefIterator as _;
            $e.par_iter().with_min_len($min_len)
        }
        #[cfg(not(feature = "rayon"))]
        $e.iter()
    }};
}

/// Calls the `iter_mut` method on `$e` or the `par_iter_mut` Rayon method if the `rayon` feature is
/// enabled.
#[macro_export]
macro_rules! cfg_iter_mut {
    ($e:expr) => {{
        #[cfg(feature = "rayon")]
        {
            use $crate::rayon::iter::IntoParallelRefMutIterator as _;
            $e.par_iter_mut()
        }
        #[cfg(not(feature = "rayon"))]
        $e.iter_mut()
    }};
    ($e:expr, $min_len:expr) => {{
        #[cfg(feature = "rayon")]
        {
            use $crate::rayon::iter::IntoParallelRefMutIterator as _;
            $e.par_iter_mut().with_min_len($min_len)
        }
        #[cfg(not(feature = "rayon"))]
        $e.iter_mut()
    }};
}

/// Calls the `chunks` method on `$e` or the `par_chunks` Rayon method if the `rayon` feature is
/// enabled.
#[macro_export]
macro_rules! cfg_chunks {
    ($e:expr, $size:expr) => {{
        #[cfg(feature = "rayon")]
        {
            use $crate::rayon::iter::ParallelIterator as _;
            $e.par_chunks($size)
        }
        #[cfg(not(feature = "rayon"))]
        $e.chunks($size)
    }};
}

/// Calls the `chunks_mut` method on `$e` or the `par_chunks_mut` Rayon method if the `rayon`
/// feature is enabled.
#[macro_export]
macro_rules! cfg_chunks_mut {
    ($e:expr, $size:expr) => {{
        #[cfg(feature = "rayon")]
        {
            use $crate::rayon::iter::ParallelIterator as _;
            $e.par_chunks_mut($size)
        }
        #[cfg(not(feature = "rayon"))]
        $e.chunks_mut($size)
    }};
}

/// Calls the `fold` method on `$e` or the `reduce` Rayon method if the `rayon` feature is enabled.
#[macro_export]
macro_rules! cfg_reduce {
    ($e:expr, $default:expr, $op:expr) => {{
        #[cfg(feature = "rayon")]
        {
            use $crate::rayon::iter::ParallelIterator as _;
            $e.reduce($default, $op)
        }
        #[cfg(not(feature = "rayon"))]
        $e.fold($default(), $op)
    }};
}
