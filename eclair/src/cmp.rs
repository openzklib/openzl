//! Comparison

use crate::{
    alloc::{Allocate, Constant},
    bool::{Assert, AssertEq, Bool},
    ops::{BitAnd, Not},
    Has,
};
use core::cmp;
use openzl_util::Array;

#[cfg(feature = "alloc")]
use {
    openzl_util::BoxArray,
    rust_alloc::{boxed::Box, vec::Vec},
};

/// Partial Equivalence Relations
pub trait PartialEq<Rhs, COM = ()>
where
    Rhs: ?Sized,
    COM: Has<bool> + ?Sized,
{
    /// Returns `true` if `self` and `rhs` are equal.
    fn eq(&self, rhs: &Rhs, compiler: &mut COM) -> Bool<COM>;

    /// Returns `true` if `self` and `rhs` are not equal.
    #[inline]
    fn ne(&self, other: &Rhs, compiler: &mut COM) -> Bool<COM>
    where
        Bool<COM>: Not<COM, Output = Bool<COM>>,
    {
        self.eq(other, compiler).not(compiler)
    }

    /// Asserts that `self` and `rhs` are equal.
    ///
    /// # Implementation Note
    ///
    /// This method is an optimization path for the case when comparing for equality and then
    /// asserting is more expensive than a custom assertion.
    #[inline]
    fn assert_equal(&self, rhs: &Rhs, compiler: &mut COM)
    where
        COM: Assert,
    {
        let are_equal = self.eq(rhs, compiler);
        compiler.assert(&are_equal);
    }
}

/// Partial Equivalence Relation Compiler Reflection
pub trait HasPartialEq<L, R>: Has<bool> {
    /// Returns `true` if `lhs` and `rhs` are equal inside of the `self` compiler.
    fn eq(&mut self, lhs: &L, rhs: &R) -> Bool<Self>;

    /// Returns `true` if `lhs` and `rhs` are not equal inside of the `self` compiler.
    #[inline]
    fn ne(&mut self, lhs: &L, rhs: &R) -> Bool<Self>
    where
        Bool<Self>: Not<Self, Output = Bool<Self>>,
    {
        self.eq(lhs, rhs).not(self)
    }

    /// Asserts that `lhs` and `rhs` are equal inside of the `self` compiler..
    ///
    /// # Implementation Note
    ///
    /// This method is an optimization path for the case when comparing for equality and then
    /// asserting is more expensive than a custom assertion.
    #[inline]
    fn assert_equal(&mut self, lhs: &L, rhs: &R)
    where
        Self: Assert,
    {
        let are_equal = self.eq(lhs, rhs);
        self.assert(&are_equal);
    }
}

impl<COM, L, R> HasPartialEq<L, R> for COM
where
    L: PartialEq<R, COM>,
    COM: Has<bool>,
{
    #[inline]
    fn eq(&mut self, lhs: &L, rhs: &R) -> Bool<Self> {
        lhs.eq(rhs, self)
    }
}

/// Implements [`PartialEq`] for the given `$type`.
macro_rules! impl_partial_eq {
    ($($type:tt),* $(,)?) => {
        $(
            impl<Rhs> PartialEq<Rhs> for $type
            where
                $type: cmp::PartialEq<Rhs>,
            {
                #[inline]
                fn eq(&self, rhs: &Rhs, _: &mut ()) -> bool {
                    cmp::PartialEq::eq(self, rhs)
                }

                #[inline]
                fn ne(&self, rhs: &Rhs, _: &mut ()) -> bool {
                    cmp::PartialEq::ne(self, rhs)
                }
            }
        )*
    };
}

impl_partial_eq!(bool, u8, u16, u32, u64, u128, i8, i16, i32, i64, i128);

#[cfg(feature = "alloc")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "alloc")))]
impl<T, Rhs, COM> PartialEq<Vec<Rhs>, COM> for Vec<T>
where
    COM: Has<bool>,
    Bool<COM>: Constant<COM, Type = bool> + BitAnd<Bool<COM>, COM, Output = Bool<COM>>,
    T: PartialEq<Rhs, COM>,
{
    #[inline]
    fn eq(&self, rhs: &Vec<Rhs>, compiler: &mut COM) -> Bool<COM> {
        if self.len() != rhs.len() {
            false.as_constant(compiler)
        } else {
            let mut are_equal = true.as_constant::<Bool<COM>>(compiler);
            for (lhs, rhs) in self.iter().zip(rhs) {
                are_equal = are_equal.bitand(lhs.eq(rhs, compiler), compiler);
            }
            are_equal
        }
    }

    #[inline]
    fn assert_equal(&self, rhs: &Vec<Rhs>, compiler: &mut COM)
    where
        COM: Assert,
    {
        if self.len() != rhs.len() {
            let not_equal = false.as_constant(compiler);
            compiler.assert(&not_equal);
        } else {
            for (lhs, rhs) in self.iter().zip(rhs) {
                compiler.assert_eq(lhs, rhs);
            }
        }
    }
}

#[cfg(feature = "alloc")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "alloc")))]
impl<T, Rhs, COM> PartialEq<Box<[Rhs]>, COM> for Box<[T]>
where
    COM: Has<bool>,
    Bool<COM>: Constant<COM, Type = bool> + BitAnd<Bool<COM>, COM, Output = Bool<COM>>,
    T: PartialEq<Rhs, COM>,
{
    #[inline]
    fn eq(&self, rhs: &Box<[Rhs]>, compiler: &mut COM) -> Bool<COM> {
        if self.len() != rhs.len() {
            false.as_constant(compiler)
        } else {
            let mut are_equal = true.as_constant::<Bool<COM>>(compiler);
            for (lhs, rhs) in self.iter().zip(rhs.iter()) {
                are_equal = are_equal.bitand(lhs.eq(rhs, compiler), compiler);
            }
            are_equal
        }
    }

    #[inline]
    fn assert_equal(&self, rhs: &Box<[Rhs]>, compiler: &mut COM)
    where
        COM: Assert,
    {
        if self.len() != rhs.len() {
            let not_equal = false.as_constant(compiler);
            compiler.assert(&not_equal);
        } else {
            for (lhs, rhs) in self.iter().zip(rhs.iter()) {
                compiler.assert_eq(lhs, rhs);
            }
        }
    }
}

impl<T, Rhs, const N: usize, COM> PartialEq<Array<Rhs, N>, COM> for Array<T, N>
where
    COM: Has<bool>,
    Bool<COM>: Constant<COM, Type = bool> + BitAnd<Bool<COM>, COM, Output = Bool<COM>>,
    T: PartialEq<Rhs, COM>,
{
    #[inline]
    fn eq(&self, rhs: &Array<Rhs, N>, compiler: &mut COM) -> Bool<COM> {
        let mut are_equal = true.as_constant::<Bool<COM>>(compiler);
        for (lhs, rhs) in self.iter().zip(rhs) {
            are_equal = are_equal.bitand(lhs.eq(rhs, compiler), compiler);
        }
        are_equal
    }

    #[inline]
    fn assert_equal(&self, rhs: &Array<Rhs, N>, compiler: &mut COM)
    where
        COM: Assert,
    {
        for (lhs, rhs) in self.iter().zip(rhs) {
            compiler.assert_eq(lhs, rhs);
        }
    }
}

#[cfg(feature = "alloc")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "alloc")))]
impl<T, Rhs, const N: usize, COM> PartialEq<BoxArray<Rhs, N>, COM> for BoxArray<T, N>
where
    COM: Has<bool>,
    Bool<COM>: Constant<COM, Type = bool> + BitAnd<Bool<COM>, COM, Output = Bool<COM>>,
    T: PartialEq<Rhs, COM>,
{
    #[inline]
    fn eq(&self, rhs: &BoxArray<Rhs, N>, compiler: &mut COM) -> Bool<COM> {
        let mut are_equal = true.as_constant::<Bool<COM>>(compiler);
        for (lhs, rhs) in self.iter().zip(rhs) {
            are_equal = are_equal.bitand(lhs.eq(rhs, compiler), compiler);
        }
        are_equal
    }

    #[inline]
    fn assert_equal(&self, rhs: &BoxArray<Rhs, N>, compiler: &mut COM)
    where
        COM: Assert,
    {
        for (lhs, rhs) in self.iter().zip(rhs) {
            compiler.assert_eq(lhs, rhs);
        }
    }
}

/// Equality
pub trait Eq<COM = ()>: PartialEq<Self, COM>
where
    COM: Has<bool>,
{
}

/// Equality Compiler Reflection
pub trait HasEq<T>: HasPartialEq<T, T> {}

impl<COM, T> HasEq<T> for COM
where
    T: Eq<COM>,
    COM: Has<bool>,
{
}
