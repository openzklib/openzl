//! Numeric Types and Traits

use crate::{
    alloc::{Allocator, Variable},
    bool::{Assert, BitDecomposition, Bool, ConditionalSelect, ConditionalSwap},
    cmp::PartialEq,
    ops::{Add, AddAssign, Mul, MulAssign, Not},
    Has,
};
use core::{borrow::Borrow, ops::Deref};
use rust_alloc::vec::Vec;

/// Additive Identity
pub trait Zero<COM = ()> {
    /// Verification Type
    type Verification;

    /// Returns the additive identity for `Self`.
    fn zero(compiler: &mut COM) -> Self;

    /// Returns a truthy value if `self` is equal to the additive identity.
    fn is_zero(&self, compiler: &mut COM) -> Self::Verification;
}

impl Zero for bool {
    type Verification = bool;

    #[inline]
    fn zero(_: &mut ()) -> Self {
        false
    }

    #[inline]
    fn is_zero(&self, _: &mut ()) -> Self::Verification {
        !(*self)
    }
}

/// Multiplicative Identity
pub trait One<COM = ()> {
    /// Verification Type
    type Verification;

    /// Returns the multiplicative identity for `Self`.
    fn one(compiler: &mut COM) -> Self;

    /// Returns a truthy value if `self` is equal to the multiplicative identity.
    fn is_one(&self, compiler: &mut COM) -> Self::Verification;
}

impl One for bool {
    type Verification = bool;

    #[inline]
    fn one(_: &mut ()) -> Self {
        true
    }

    #[inline]
    fn is_one(&self, _: &mut ()) -> Self::Verification {
        *self
    }
}

/// Defines an implementation for [`Zero`] and [`One`] for integers.
macro_rules! define_zero_one {
    ($($type:tt),* $(,)?) => {
        $(
            impl Zero for $type {
                type Verification = bool;

                #[inline]
                fn zero(_: &mut ()) -> Self {
                    0
                }

                #[inline]
                fn is_zero(&self, compiler: &mut ()) -> Self::Verification {
                    *self == Self::zero(compiler)
                }
            }

            impl One for $type {
                type Verification = bool;

                #[inline]
                fn one(_: &mut ()) -> Self {
                    1
                }

                #[inline]
                fn is_one(&self, compiler: &mut ()) -> Self::Verification {
                    *self == Self::one(compiler)
                }
            }
        )*
    }
}

define_zero_one!(u8, u16, u32, u64, u128, i8, i16, i32, i64, i128);

/// Within-Bit-Range Assertion
///
/// # Restrictions
///
/// This `trait` assumes that `BITS > 0` and does not currently support `BITS = 0`. In this case
/// we would have an assertion that `x < 2^0 = 1` which is just that `x = 0` in most systems. For
/// this usecase, the [`Zero`] `trait` should be considered instead.
pub trait AssertWithinBitRange<T, const BITS: usize> {
    /// Asserts that `value` is smaller than `2^BITS`.
    fn assert_within_range(&mut self, value: &T);
}

/// Unsigned Integer
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct UnsignedInteger<T, const BITS: usize>(T);

impl<T, const BITS: usize> UnsignedInteger<T, BITS> {
    /// Builds a new [`UnsignedInteger`] over `value` asserting that it does not exceed `BITS`-many
    /// bits. See [`new_unchecked`](Self::new_unchecked) for an unchecked constructor for
    /// [`UnsignedInteger`].
    #[inline]
    pub fn new<COM>(value: T, compiler: &mut COM) -> Self
    where
        COM: AssertWithinBitRange<T, BITS>,
    {
        compiler.assert_within_range(&value);
        Self::new_unchecked(value)
    }

    /// Builds a new [`UnsignedInteger`] over `value` **without** asserting that it does not exceed
    /// `BITS`-many bits. See [`new`](Self::new) for a checked constructor for [`UnsignedInteger`].
    #[inline]
    pub fn new_unchecked(value: T) -> Self {
        Self(value)
    }

    /// Consumes `self` returning the underlying value.
    #[inline]
    pub fn into_inner(self) -> T {
        self.0
    }

    /// Mutates the underlying value of `self` with `f`, asserting that after mutation the value is
    /// still within the `BITS` range. See [`mutate_unchecked`](Self::mutate_unchecked) for an
    /// unchecked mutation method.
    #[inline]
    pub fn mutate<F, U, COM>(&mut self, f: F, compiler: &mut COM) -> U
    where
        COM: AssertWithinBitRange<T, BITS>,
        F: FnOnce(&mut T, &mut COM) -> U,
    {
        let output = f(&mut self.0, compiler);
        compiler.assert_within_range(&self.0);
        output
    }

    /// Mutates the underlying value of `self` with `f` **without** asserting that after mutation
    /// the value is still within the `BITS` range. See [`mutate`](Self::mutate) for a checked
    /// mutation method.
    #[inline]
    pub fn mutate_unchecked<F, U>(&mut self, f: F) -> U
    where
        F: FnOnce(&mut T) -> U,
    {
        f(&mut self.0)
    }
}

impl<T, const BITS: usize> AsRef<T> for UnsignedInteger<T, BITS> {
    #[inline]
    fn as_ref(&self) -> &T {
        &self.0
    }
}

impl<T, const BITS: usize> Borrow<T> for UnsignedInteger<T, BITS> {
    #[inline]
    fn borrow(&self) -> &T {
        &self.0
    }
}

impl<T, const BITS: usize> Deref for UnsignedInteger<T, BITS> {
    type Target = T;

    #[inline]
    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T, COM, const BITS: usize> Add<Self, COM> for UnsignedInteger<T, BITS>
where
    T: Add<T, COM>,
    COM: AssertWithinBitRange<T::Output, BITS>,
{
    type Output = UnsignedInteger<T::Output, BITS>;

    #[inline]
    fn add(self, rhs: Self, compiler: &mut COM) -> Self::Output {
        Self::Output::new(self.0.add(rhs.0, compiler), compiler)
    }
}

impl<T, COM, const BITS: usize> AddAssign<Self, COM> for UnsignedInteger<T, BITS>
where
    COM: AssertWithinBitRange<T, BITS>,
    T: AddAssign<T, COM>,
{
    #[inline]
    fn add_assign(&mut self, rhs: Self, compiler: &mut COM) {
        self.mutate(|lhs, compiler| lhs.add_assign(rhs.0, compiler), compiler);
    }
}

impl<T, COM, const BITS: usize> Mul<Self, COM> for UnsignedInteger<T, BITS>
where
    T: Mul<T, COM>,
    COM: AssertWithinBitRange<T::Output, BITS>,
{
    type Output = UnsignedInteger<T::Output, BITS>;

    #[inline]
    fn mul(self, rhs: Self, compiler: &mut COM) -> Self::Output {
        Self::Output::new(self.0.mul(rhs.0, compiler), compiler)
    }
}

impl<T, COM, const BITS: usize> MulAssign<Self, COM> for UnsignedInteger<T, BITS>
where
    T: MulAssign<T, COM>,
    COM: AssertWithinBitRange<T, BITS>,
{
    #[inline]
    fn mul_assign(&mut self, rhs: Self, compiler: &mut COM) {
        self.mutate(|lhs, compiler| lhs.mul_assign(rhs.0, compiler), compiler);
    }
}

impl<T, const BITS: usize, COM> AssertWithinBitRange<UnsignedInteger<T, BITS>, BITS> for COM
where
    COM: AssertWithinBitRange<T, BITS>,
{
    #[inline]
    fn assert_within_range(&mut self, value: &UnsignedInteger<T, BITS>) {
        self.assert_within_range(&value.0)
    }
}

impl<T, const BITS: usize, COM> Zero<COM> for UnsignedInteger<T, BITS>
where
    T: Zero<COM>,
{
    type Verification = T::Verification;

    #[inline]
    fn zero(compiler: &mut COM) -> Self {
        Self::new_unchecked(T::zero(compiler))
    }

    #[inline]
    fn is_zero(&self, compiler: &mut COM) -> Self::Verification {
        self.0.is_zero(compiler)
    }
}

impl<T, const BITS: usize, COM> One<COM> for UnsignedInteger<T, BITS>
where
    T: One<COM>,
{
    type Verification = T::Verification;

    #[inline]
    fn one(compiler: &mut COM) -> Self {
        Self::new_unchecked(T::one(compiler))
    }

    #[inline]
    fn is_one(&self, compiler: &mut COM) -> Self::Verification {
        self.0.is_one(compiler)
    }
}

impl<T, const BITS: usize, COM> PartialEq<Self, COM> for UnsignedInteger<T, BITS>
where
    COM: Has<bool>,
    T: PartialEq<T, COM>,
{
    #[inline]
    fn eq(&self, rhs: &Self, compiler: &mut COM) -> Bool<COM> {
        self.0.eq(&rhs.0, compiler)
    }

    #[inline]
    fn ne(&self, rhs: &Self, compiler: &mut COM) -> Bool<COM>
    where
        Bool<COM>: Not<COM, Output = Bool<COM>>,
    {
        self.0.ne(&rhs.0, compiler)
    }

    #[inline]
    fn assert_equal(&self, rhs: &Self, compiler: &mut COM)
    where
        COM: Assert,
    {
        self.0.assert_equal(&rhs.0, compiler)
    }
}

impl<T, const BITS: usize, COM> BitDecomposition<COM> for UnsignedInteger<T, BITS>
where
    COM: Has<bool>,
    T: BitDecomposition<COM>,
{
    #[inline]
    fn to_bits_le(&self, compiler: &mut COM) -> Vec<Bool<COM>> {
        self.0.to_bits_le(compiler)
    }
}

impl<T, const BITS: usize, COM> ConditionalSelect<COM> for UnsignedInteger<T, BITS>
where
    COM: Has<bool>,
    T: ConditionalSelect<COM>,
{
    #[inline]
    fn select(bit: &Bool<COM>, true_value: &Self, false_value: &Self, compiler: &mut COM) -> Self {
        Self::new_unchecked(T::select(bit, &true_value.0, &false_value.0, compiler))
    }
}

impl<T, const BITS: usize, COM> ConditionalSwap<COM> for UnsignedInteger<T, BITS>
where
    COM: Has<bool>,
    T: ConditionalSwap<COM>,
{
    #[inline]
    fn swap(bit: &Bool<COM>, lhs: &Self, rhs: &Self, compiler: &mut COM) -> (Self, Self) {
        let (lhs, rhs) = T::swap(bit, &lhs.0, &rhs.0, compiler);
        (Self::new_unchecked(lhs), Self::new_unchecked(rhs))
    }
}

/// Defines [`UnsignedInteger`] types for the given number of `$bits`.
macro_rules! define_uint {
    ($($name:ident, $bits:expr),* $(,)?) => {
        $(
            #[doc = "Unsigned Integer Type with"]
            #[doc = stringify!($bits)]
            #[doc = "Bits"]
            pub type $name<T> = UnsignedInteger<T, $bits>;
        )*
    }
}

define_uint!(
    U8, 8, U9, 9, U10, 10, U11, 11, U12, 12, U13, 13, U14, 14, U15, 15, U16, 16, U32, 32, U64, 64,
    U65, 65, U66, 66, U67, 67, U68, 68, U69, 69, U70, 70, U80, 80, U90, 90, U100, 100, U110, 100,
    U111, 111, U112, 112, U113, 113, U114, 114, U115, 115, U116, 116, U117, 117, U118, 118, U119,
    119, U120, 120, U121, 121, U122, 122, U123, 123, U124, 124, U125, 125, U126, 126, U127, 127,
    U128, 128, U129, 129, U130, 130, U131, 131, U132, 132, U133, 133, U134, 134, U135, 135, U136,
    136, U137, 137, U138, 138, U139, 139, U140, 140, U150, 150, U160, 160, U170, 170, U180, 180,
    U190, 190, U200, 200, U210, 210, U220, 220, U230, 230, U240, 240, U250, 250, U251, 251, U252,
    252, U253, 253, U254, 254, U255, 255, U256, 256,
);

/// Defines [`Variable`] allocation implementation for [`UnsignedInteger`] whenever it has a native
/// Rust counterpart.
macro_rules! define_uint_allocation {
    ($($type:tt, $bits:expr),* $(,)?) => {
        $(
            impl<T, M, COM> Variable<M, COM> for UnsignedInteger<T, $bits>
            where
                COM: AssertWithinBitRange<T, $bits>,
                T: Variable<M, COM>,
                T::Type: From<$type>,
            {
                type Type = $type;

                #[inline]
                fn new_unknown(compiler: &mut COM) -> Self {
                    Self::new(compiler.allocate_unknown(), compiler)
                }

                #[inline]
                fn new_known(this: &Self::Type, compiler: &mut COM) -> Self {
                    Self::new(compiler.allocate_known(&(*this).into()), compiler)
                }
            }
        )*
    };
}

define_uint_allocation!(u8, 8, u16, 16, u32, 32, u64, 64, u128, 128);
