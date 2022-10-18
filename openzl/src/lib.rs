//! OpenZL

#![cfg_attr(not(any(feature = "std", test)), no_std)]
#![cfg_attr(doc_cfg, feature(doc_cfg))]
#![forbid(rustdoc::broken_intra_doc_links)]
#![forbid(missing_docs)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[doc(inline)]
pub use openzl_util as util;
