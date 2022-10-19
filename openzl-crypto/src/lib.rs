//! OpenZL Cryptographic Primitives Library

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(doc_cfg, feature(doc_cfg))]
#![forbid(rustdoc::broken_intra_doc_links)]
#![forbid(missing_docs)]

#[cfg(feature = "alloc")]
extern crate alloc;

// pub mod accumulator;
pub mod algebra;
// pub mod commitment;
// pub mod constraint;
// pub mod encryption;
pub mod hash;
pub mod key;
// pub mod merkle_tree;
// pub mod password;
// pub mod permutation;
pub mod signature;

/* TODO:
#[cfg(feature = "arkworks")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "arkworks")))]
pub mod arkworks;

#[cfg(feature = "dalek")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "dalek")))]
pub mod dalek;
*/

#[doc(inline)]
pub use openzl_derive::*;
