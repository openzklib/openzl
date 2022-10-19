//! Operations Utilities

use core::ops;

#[cfg(feature = "serde")]
use crate::serde::{Deserialize, Serialize};

/// Used to tell an operation whether it should exit early or go on as usual.
///
/// This is an alternative definition and mostly drop-in replacement for [`core::ops::ControlFlow`]
/// but may diverge from the standard library interface over time.
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "crate::serde", deny_unknown_fields)
)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[must_use]
pub enum ControlFlow<B = (), C = ()> {
    /// Move on to the next phase of the operation as normal.
    Continue(C),

    /// Exit the operation without running subsequent phases.
    Break(B),
}

impl<B, C> ControlFlow<B, C> {
    /// Returns `true` if this is a [`Break`](Self::Break) variant.
    #[inline]
    pub const fn is_break(&self) -> bool {
        matches!(self, Self::Break(_))
    }

    /// Returns `true` if this is a [`Continue`](Self::Continue) variant.
    #[inline]
    pub const fn is_continue(&self) -> bool {
        matches!(self, Self::Continue(_))
    }

    /// Converts the [`ControlFlow`] into an [`Option`] which is [`Some`] if `self` is
    /// [`Break`](Self::Break) and [`None`] otherwise.
    #[inline]
    pub fn break_value(self) -> Option<B> {
        match self {
            Self::Break(b) => Some(b),
            _ => None,
        }
    }

    /// Maps [`ControlFlow<B, C>`] to [`ControlFlow<T, C>`] by applying `f` to the break value when
    /// it exists.
    #[inline]
    pub fn map_break<T, F>(self, f: F) -> ControlFlow<T, C>
    where
        F: FnOnce(B) -> T,
    {
        match self {
            Self::Continue(c) => ControlFlow::Continue(c),
            Self::Break(b) => ControlFlow::Break(f(b)),
        }
    }
}

impl<B> ControlFlow<B, ()> {
    /// Continue Constant
    pub const CONTINUE: Self = Self::Continue(());
}

impl<C> ControlFlow<(), C> {
    /// Break Constant
    pub const BREAK: Self = Self::Break(());
}

impl ControlFlow {
    /// Returns a [`ControlFlow`] with [`BREAK`](Self::BREAK) if `should_break` is `true` and
    /// [`CONTINUE`](Self::CONTINUE) otherwise.
    #[inline]
    pub fn should_break(should_break: bool) -> Self {
        if should_break {
            Self::BREAK
        } else {
            Self::CONTINUE
        }
    }

    /// Returns a [`ControlFlow`] with [`CONTINUE`](Self::CONTINUE) if `should_continue` is `true`
    /// and [`BREAK`](Self::BREAK) otherwise.
    #[inline]
    pub fn should_continue(should_continue: bool) -> Self {
        if should_continue {
            Self::CONTINUE
        } else {
            Self::BREAK
        }
    }
}

impl<B, C> From<ops::ControlFlow<B, C>> for ControlFlow<B, C> {
    #[inline]
    fn from(flow: ops::ControlFlow<B, C>) -> Self {
        match flow {
            ops::ControlFlow::Continue(c) => Self::Continue(c),
            ops::ControlFlow::Break(b) => Self::Break(b),
        }
    }
}

impl<B, C> From<ControlFlow<B, C>> for ops::ControlFlow<B, C> {
    #[inline]
    fn from(flow: ControlFlow<B, C>) -> Self {
        match flow {
            ControlFlow::Continue(c) => Self::Continue(c),
            ControlFlow::Break(b) => Self::Break(b),
        }
    }
}
