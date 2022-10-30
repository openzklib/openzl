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
