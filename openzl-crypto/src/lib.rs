//! OpenZL Cryptographic Primitives Library

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(doc_cfg, feature(doc_cfg))]
#![forbid(rustdoc::broken_intra_doc_links)]
#![forbid(missing_docs)]

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod accumulator;
pub mod algebra;
pub mod constraint;
pub mod encryption;
pub mod hash;
pub mod key;
pub mod password;
pub mod permutation;
pub mod signature;

#[cfg(feature = "alloc")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "alloc")))]
pub mod merkle_tree;

#[cfg(feature = "alloc")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "alloc")))]
pub mod poseidon;

#[doc(inline)]
pub use openzl_derive::*;

/// Non-Native Compiler Marker Trait
///
/// See [`eclair::NonNative`] for why we need this construction.
pub trait NonNative {}
