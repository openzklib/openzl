//! `eclair`: **E**mbedded **C**ircuit **L**anguage **A**nd **I**ntermediate **R**epresentation

#![cfg_attr(not(any(feature = "std", test)), no_std)]
#![cfg_attr(doc_cfg, feature(doc_cfg))]
#![forbid(rustdoc::broken_intra_doc_links)]
#![forbid(missing_docs)]

extern crate alloc;
