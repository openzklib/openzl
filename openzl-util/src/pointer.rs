//! Pointer Utilities

use core::borrow::Borrow;

#[cfg(feature = "alloc")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "alloc")))]
use alloc::{rc::Weak as WeakRc, sync::Weak as WeakArc};

#[cfg(feature = "alloc")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "alloc")))]
pub use alloc::{rc::Rc, sync::Arc};

/// Pointer Family
pub trait PointerFamily<T> {
    /// Strong Pointer
    type Strong: Borrow<T>;

    /// Weak Pointer
    type Weak: Default;

    /// Returns a new strong pointer holding `base`.
    fn new(base: T) -> Self::Strong;

    /// Claims ownership of the underlying owned value from `strong`.
    ///
    /// # Panics
    ///
    /// This method can only panic if there are other outstanding strong pointers. This method
    /// will still succeed if there are other outstanding weak pointers, but they will all be
    /// disassociated to `strong`.
    fn claim(strong: Self::Strong) -> T;

    /// Returns a new weak pointer to `strong`.
    fn downgrade(strong: &Self::Strong) -> Self::Weak;

    /// Tries to upgrade `weak` to a strong pointer, returning `None` if there is no strong
    /// pointer associated to `weak`.
    fn upgrade(weak: &Self::Weak) -> Option<Self::Strong>;

    /// Checks if two strong pointers point to the same allocation.
    fn strong_ptr_eq(lhs: &Self::Strong, rhs: &Self::Strong) -> bool;
}

/// Implements [`PointerFamily`] for `$type` with `$strong` and `$weak` pointers.
macro_rules! impl_pointer_family {
    ($type:ty, $strong:ident, $weak:ident) => {
        #[cfg(feature = "alloc")]
        #[cfg_attr(doc_cfg, doc(cfg(feature = "alloc")))]
        impl<T> PointerFamily<T> for $type {
            type Strong = $strong<T>;
            type Weak = $weak<T>;

            #[inline]
            fn new(base: T) -> Self::Strong {
                $strong::new(base)
            }

            #[inline]
            fn claim(strong: Self::Strong) -> T {
                $strong::try_unwrap(strong).ok().unwrap()
            }

            #[inline]
            fn downgrade(strong: &Self::Strong) -> Self::Weak {
                $strong::downgrade(strong)
            }

            #[inline]
            fn upgrade(weak: &Self::Weak) -> Option<Self::Strong> {
                weak.upgrade()
            }

            #[inline]
            fn strong_ptr_eq(lhs: &Self::Strong, rhs: &Self::Strong) -> bool {
                $strong::ptr_eq(lhs, rhs)
            }
        }
    };
}

/// Single-Threaded Pointer Family
///
/// This is the pointer family for [`Rc`].
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SingleThreaded;

impl_pointer_family!(SingleThreaded, Rc, WeakRc);

/// Thread-Safe Pointer Family
///
/// This is the pointer family for [`Arc`].
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ThreadSafe;

impl_pointer_family!(ThreadSafe, Arc, WeakArc);

/// No-Pointer Pointer Family
///
/// This is the pointer family for a raw value, and does not do any reference counting.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NoPointer;

impl<T> PointerFamily<T> for NoPointer {
    type Strong = T;
    type Weak = ();

    #[inline]
    fn new(base: T) -> Self::Strong {
        base
    }

    #[inline]
    fn claim(strong: Self::Strong) -> T {
        strong
    }

    #[inline]
    fn downgrade(strong: &Self::Strong) -> Self::Weak {
        let _ = strong;
    }

    #[inline]
    fn upgrade(weak: &Self::Weak) -> Option<Self::Strong> {
        let _ = weak;
        None
    }

    #[inline]
    fn strong_ptr_eq(lhs: &Self::Strong, rhs: &Self::Strong) -> bool {
        core::ptr::eq(lhs, rhs)
    }
}
