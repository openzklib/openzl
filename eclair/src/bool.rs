//! Structures over Booleans
//!
//! For many of the standard Rust operations we need access to some simulation of the primitive
//! types. In this module, we define the access interfaces needed to simulate the [`bool`] type with
//! [`Bool`].

use crate::{cmp::PartialEq, Has, Type};

#[cfg(feature = "alloc")]
use openzl_util::{
    iter::IteratorExt,
    vec::{Vec, VecExt},
};

/// Boolean Type Inside of the Compiler
pub type Bool<COM = ()> = Type<COM, bool>;

/// Assertion
pub trait Assert: Has<bool> {
    /// Asserts that `bit` reduces to `true`.
    fn assert(&mut self, bit: &Bool<Self>);

    /// Asserts that all the items in the `iter` reduce to `true`.
    #[inline]
    fn assert_all<'b, I>(&mut self, iter: I)
    where
        Self: Assert,
        Bool<Self>: 'b,
        I: IntoIterator<Item = &'b Bool<Self>>,
    {
        iter.into_iter().for_each(move |b| self.assert(b));
    }
}

impl Assert for () {
    #[inline]
    fn assert(&mut self, bit: &bool) {
        assert!(bit)
    }
}

/// Equality Assertion
pub trait AssertEq: Assert {
    /// Asserts that `lhs` and `rhs` are equal.
    #[inline]
    fn assert_eq<T, Rhs>(&mut self, lhs: &T, rhs: &Rhs)
    where
        T: PartialEq<Rhs, Self>,
    {
        T::assert_equal(lhs, rhs, self);
    }

    /// Asserts that all the elements in `iter` are equal to some `base` element.
    #[inline]
    fn assert_all_eq_to_base<'t, T, Rhs, I>(&mut self, base: &'t T, iter: I)
    where
        T: PartialEq<Rhs, Self>,
        Rhs: 't,
        I: IntoIterator<Item = &'t Rhs>,
    {
        for item in iter {
            self.assert_eq(base, item);
        }
    }

    /// Asserts that all the elements in `iter` are equal.
    #[inline]
    fn assert_all_eq<'t, T, I>(&mut self, iter: I)
    where
        T: 't + PartialEq<T, Self>,
        I: IntoIterator<Item = &'t T>,
    {
        let mut iter = iter.into_iter();
        if let Some(base) = iter.next() {
            self.assert_all_eq_to_base(base, iter);
        }
    }
}

impl<COM> AssertEq for COM where COM: Assert {}

/// Bit Decomposition
pub trait BitDecomposition<COM = ()>
where
    COM: Has<bool> + ?Sized,
{
    /// Error Type
    type Error;

    /// Returns the little-endian bit representation of `self`, with trailing zeroes.
    fn to_bits_le(&self, compiler: &mut COM) -> Result<Vec<Bool<COM>>, Self::Error>;
}

impl BitDecomposition for bool {
    type Error = ();

    #[inline]
    fn to_bits_le(&self, _: &mut ()) -> Result<Vec<bool>, Self::Error> {
        Ok([*self].to_vec())
    }
}

/// Implements [`BitDecomposition`] for the given `$type`.
macro_rules! impl_bit_decomposition {
    ($($type:tt),* $(,)?) => {
        $(
            impl BitDecomposition for $type {
                type Error = ();

                #[inline]
                fn to_bits_le(&self, _: &mut ()) -> Result<Vec<bool>, Self::Error> {
                    let mut bits = Vec::new();
                    for byte in (*self).to_le_bytes() {
                        for i in 0..8 {
                            let power = 1 << i;
                            bits.push((power & byte) > 0)
                        }
                    }
                    Ok(bits)
                }
            }
        )*
    }
}

impl_bit_decomposition!(u8, u16, u32, u64, u128, i8, i16, i32, i64, i128);

/// Conditional Selection
pub trait ConditionalSelect<COM = ()>: Sized
where
    COM: Has<bool> + ?Sized,
{
    /// Selects `true_value` when `bit == true` and `false_value` when `bit == false`.
    fn select(bit: &Bool<COM>, true_value: &Self, false_value: &Self, compiler: &mut COM) -> Self;

    /// Selects an element from `table` by repeated iteration of `select` over `bits`.
    /// The `bits` are ordered from most significant to least significant, forming unsigned
    /// integers in binary representation which are understood as the `table` indices.
    #[cfg(feature = "alloc")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "alloc")))]
    #[inline]
    fn select_from_table<'s, B, T>(bits: B, table: T, compiler: &mut COM) -> Self
    where
        Self: 's + Clone,
        Bool<COM>: 's,
        B: IntoIterator<Item = &'s Bool<COM>>,
        B::IntoIter: ExactSizeIterator,
        T: IntoIterator<Item = &'s Self>,
        T::IntoIter: ExactSizeIterator,
    {
        let mut table = table.into_iter();
        let mut bits = bits.into_iter();
        assert_eq!(
            table.len(),
            1 << bits.len(),
            "Table length must equal 2^(number of bits)."
        );
        if let Some(first_bit) = bits.next() {
            let mut table = table
                .chunk_by()
                .map(|[x, y]| Self::select(first_bit, y, x, compiler))
                .collect::<Vec<_>>();
            for bit in bits {
                table = table
                    .into_iter()
                    .chunk_by()
                    .map(|[x, y]| Self::select(bit, &y, &x, compiler))
                    .collect();
            }
            table.take_first()
        } else {
            table
                .next()
                .expect("Table of length 1 always has one element.")
                .clone()
        }
    }
}

/// Implements [`ConditionalSelect`] for the given `$type`.
macro_rules! impl_conditional_select {
    ($($type:tt),* $(,)?) => {
        $(
            impl ConditionalSelect for $type {
                #[inline]
                fn select(bit: &Bool, true_value: &Self, false_value: &Self, _: &mut ()) -> Self {
                    if *bit {
                        true_value.clone()
                    } else {
                        false_value.clone()
                    }
                }
            }
        )*
    }
}

impl_conditional_select!(bool, u8, u16, u32, u64, u128, i8, i16, i32, i64, i128);

/// Conditional Swap
pub trait ConditionalSwap<COM = ()>: Sized
where
    COM: Has<bool> + ?Sized,
{
    /// Swaps `lhs` and `rhs` whenever `bit == true` and keeps them in the same order when `bit ==
    /// false`.
    fn swap(bit: &Bool<COM>, lhs: &Self, rhs: &Self, compiler: &mut COM) -> (Self, Self);
}
