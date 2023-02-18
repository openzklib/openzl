//! Halo2 OpenZL Plugin

#![cfg_attr(not(any(feature = "std", test)), no_std)]
#![cfg_attr(doc_cfg, feature(doc_cfg))]
#![forbid(rustdoc::broken_intra_doc_links)]
#![forbid(missing_docs)]

extern crate alloc;

#[doc(inline)]
pub use halo2_gadgets as gadgets;

#[doc(inline)]
pub use halo2_proofs as proofs;

pub mod compiler;
