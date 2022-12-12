//! Utilities

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(doc_cfg, feature(doc_cfg))]
#![forbid(rustdoc::broken_intra_doc_links)]
#![forbid(missing_docs)]

#[cfg(feature = "alloc")]
extern crate alloc;

mod array;
mod bytes;
mod macros;
mod sealed;

pub mod cmp;
pub mod codec;
pub mod convert;
pub mod future;
pub mod http;
pub mod iter;
pub mod num;
pub mod ops;
pub mod persistence;
pub mod pointer;
pub mod rand;
pub mod time;

#[cfg(feature = "alloc")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "alloc")))]
pub mod collections;

#[cfg(feature = "alloc")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "alloc")))]
pub mod vec;

pub use array::*;
pub use bytes::*;
pub use sealed::*;

pub use derivative;

#[cfg(feature = "serde")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "serde")))]
#[doc(inline)]
pub use serde;

#[cfg(feature = "serde")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "serde")))]
#[doc(inline)]
pub use serde_with;

#[cfg(feature = "rayon")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "rayon")))]
#[doc(inline)]
pub use rayon;

/// Type Identity Reflection Mechanism
pub trait IsType {
    /// Type Equal to `Self`
    type Type: ?Sized;
}

impl<T> IsType for T
where
    T: ?Sized,
{
    type Type = T;
}
