//! Plonky2 OpenZL Plugin

#![cfg_attr(not(any(feature = "std", test)), no_std)]
#![cfg_attr(doc_cfg, feature(doc_cfg))]
#![forbid(rustdoc::broken_intra_doc_links)]
#![forbid(missing_docs)]

extern crate alloc;

pub mod base;
pub mod bool;
pub mod compiler;
pub mod field;
pub mod poseidon;

#[doc(inline)]
pub use starky;
