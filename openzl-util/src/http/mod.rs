//! HTTP Utilities

#[cfg(all(feature = "serde", feature = "tide"))]
#[cfg_attr(doc_cfg, doc(cfg(all(feature = "serde", feature = "tide"))))]
pub mod tide;

#[cfg(feature = "reqwest")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "reqwest")))]
pub mod reqwest;
