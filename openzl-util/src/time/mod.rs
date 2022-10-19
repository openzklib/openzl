//! Temporal quantification.

pub use core::time::*;

#[cfg(feature = "std")]
pub use std::time::*;

#[cfg(feature = "std")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "std")))]
pub mod lock;
