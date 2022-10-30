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
