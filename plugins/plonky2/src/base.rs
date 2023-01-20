//! Plonky2 Base Library

#[doc(inline)]
pub use plonky2::*;

#[cfg(feature = "ecdsa")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "ecdsa")))]
pub use plonky2_ecdsa as ecdsa;
