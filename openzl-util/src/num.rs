//! Numeric Utilities

/// Tries to convert `n` into a `usize` depending on how big the `usize` type is.
#[inline]
pub const fn u64_as_usize(n: u64) -> Result<usize, u64> {
    if n <= usize::MAX as u64 {
        Ok(n as usize)
    } else {
        Err(n)
    }
}

/// Ceiling Operation
pub trait Ceil<T> {
    /// Returns the smallest integer greater than or equal to `self` cast into `T`.
    fn ceil(self) -> T;
}

#[cfg(feature = "std")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "std")))]
impl Ceil<usize> for f32 {
    #[inline]
    fn ceil(self) -> usize {
        self.ceil() as usize
    }
}

#[cfg(feature = "std")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "std")))]
impl Ceil<usize> for f64 {
    #[inline]
    fn ceil(self) -> usize {
        self.ceil() as usize
    }
}

/// Checked Addition
pub trait CheckedAdd<Rhs = Self> {
    /// Output Type
    type Output;

    /// Checked integer addition. Computes `self + rhs`, returning `None` if overflow occurred.
    fn checked_add(self, rhs: Rhs) -> Option<Self::Output>;
}

/// Checked Subtraction
pub trait CheckedSub<Rhs = Self> {
    /// Output Type
    type Output;

    /// Checked integer subtraction. Computes `self - rhs`, returning `None` if overflow occurred.
    fn checked_sub(self, rhs: Rhs) -> Option<Self::Output>;
}

/// Checked Increment
pub trait CheckedIncrement {
    /// Increments `self` returning `None` if it would overflow.
    fn checked_increment(&mut self) -> Option<&mut Self>;
}

/// Checked Decrement
pub trait CheckedDecrement {
    /// Decrements `self` returning `None` if it would overflow.
    fn checked_decrement(&mut self) -> Option<&mut Self>;
}

/// Implements checked operations for the native integer `$type`.
macro_rules! impl_checked {
    ($($type:tt),* $(,)?) => {
        $(
            impl CheckedAdd for $type {
                type Output = Self;

                #[inline]
                fn checked_add(self, rhs: Self) -> Option<Self::Output> {
                    self.checked_add(rhs)
                }
            }

            impl CheckedSub for $type {
                type Output = Self;

                #[inline]
                fn checked_sub(self, rhs: Self) -> Option<Self::Output> {
                    self.checked_sub(rhs)
                }
            }

            impl CheckedIncrement for $type {
                #[inline]
                fn checked_increment(&mut self) -> Option<&mut Self> {
                    *self = self.checked_add(1)?;
                    Some(self)
                }
            }

            impl CheckedDecrement for $type {
                #[inline]
                fn checked_decrement(&mut self) -> Option<&mut Self> {
                    *self = self.checked_sub(1)?;
                    Some(self)
                }
            }
        )*
    };
}

impl_checked!(i8, i16, i32, i64, i128, u8, u16, u32, u64, u128);

impl<A> CheckedAdd for &A
where
    A: Clone + CheckedAdd,
{
    type Output = A::Output;

    #[inline]
    fn checked_add(self, rhs: Self) -> Option<Self::Output> {
        self.clone().checked_add(rhs.clone())
    }
}

impl<A> CheckedSub for &A
where
    A: Clone + CheckedSub,
{
    type Output = A::Output;

    #[inline]
    fn checked_sub(self, rhs: Self) -> Option<Self::Output> {
        self.clone().checked_sub(rhs.clone())
    }
}
