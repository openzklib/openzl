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

//! Utilities for Manipulating Bytes

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

/// Counts the number of bytes required to encode a number with the given number of `bits`.
#[inline]
pub const fn byte_count(bits: u32) -> u32 {
    (bits / 8) + (((bits % 8) != 0) as u32)
}

/// Size Limit
pub trait SizeLimit {
    /// Maximum Number of Bytes Required to Represent [`Self`]
    ///
    /// If this trait is implemented, then we know that [`Self`] can fit inside a byte array of the
    /// following type: `[u8; Self::SIZE]`.
    const SIZE: usize;
}

/// Exact From Bytes Conversion
pub trait FromBytes<const SIZE: usize> {
    /// Converts an array of `bytes` into an element of type [`Self`].
    fn from_bytes(bytes: [u8; SIZE]) -> Self;
}

/// Exact Into Bytes Conversion
pub trait IntoBytes<const SIZE: usize> {
    /// Converts `self` into its byte array representation of the given `SIZE`.
    fn into_bytes(self) -> [u8; SIZE];
}

/// Exact Bytes Conversion
pub trait Bytes<const SIZE: usize>: FromBytes<SIZE> + IntoBytes<SIZE> {}

impl<B, const SIZE: usize> Bytes<SIZE> for B where B: FromBytes<SIZE> + IntoBytes<SIZE> {}

/// Byte Vector Conversion
#[cfg(feature = "alloc")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "alloc")))]
pub trait AsBytes {
    /// Returns an owned byte representation of `self`.
    fn as_bytes(&self) -> Vec<u8>;
}

/// Implements [`Bytes`] and [`AsBytes`] for the primitive `$type` of a given `$size` using
/// `from_le_bytes` and `to_le_bytes` for little-endian conversion.
macro_rules! impl_bytes_primitive {
    ($type:tt, $size:expr) => {
        impl FromBytes<$size> for $type {
            #[inline]
            fn from_bytes(bytes: [u8; $size]) -> Self {
                Self::from_le_bytes(bytes)
            }
        }

        impl IntoBytes<$size> for $type {
            #[inline]
            fn into_bytes(self) -> [u8; $size] {
                self.to_le_bytes()
            }
        }

        #[cfg(feature = "alloc")]
        #[cfg_attr(doc_cfg, doc(cfg(feature = "alloc")))]
        impl AsBytes for $type {
            #[inline]
            fn as_bytes(&self) -> Vec<u8> {
                self.to_le_bytes().to_vec()
            }
        }
    };
    ($($type:tt),* $(,)?) => {
        $(impl_bytes_primitive!($type, { ($type::BITS / 8) as usize });)*
    };
}

impl_bytes_primitive!(i8, i16, i32, i64, i128, isize, u8, u16, u32, u64, u128, usize);
impl_bytes_primitive!(f32, 4);
impl_bytes_primitive!(f64, 8);

impl IntoBytes<4> for char {
    #[inline]
    fn into_bytes(self) -> [u8; 4] {
        (self as u32).into_bytes()
    }
}

impl<const N: usize> FromBytes<N> for [u8; N] {
    #[inline]
    fn from_bytes(bytes: [u8; N]) -> Self {
        bytes
    }
}

impl<const N: usize> IntoBytes<N> for [u8; N] {
    #[inline]
    fn into_bytes(self) -> [u8; N] {
        self
    }
}
