//! Arkworks OpenZL Plugin

#![cfg_attr(not(any(feature = "std", test)), no_std)]
#![cfg_attr(doc_cfg, feature(doc_cfg))]
#![forbid(rustdoc::broken_intra_doc_links)]
#![forbid(missing_docs)]

extern crate alloc;

pub use ark_ec as ec;
pub use ark_r1cs_std as r1cs_std;
pub use ark_relations as relations;

#[cfg(feature = "ark-bls12-377")]
pub use ark_bls12_377 as bls12_377;

#[cfg(feature = "ark-bls12-381")]
pub use ark_bls12_381 as bls12_381;

#[cfg(feature = "ark-bn254")]
pub use ark_bn254 as bn254;

#[cfg(feature = "ark-ed-on-bls12-381")]
pub use ark_ed_on_bls12_377 as ed_on_bls12_377;

#[cfg(feature = "ark-ed-on-bls12-381")]
pub use ark_ed_on_bls12_381 as ed_on_bls12_381;

#[cfg(feature = "ark-ed-on-bn254")]
pub use ark_ed_on_bn254 as ed_on_bn254;

pub mod algebra;
pub mod constraint;
pub mod ff;
pub mod pairing;
pub mod rand;
pub mod ratio;
pub mod serialize;

#[cfg(feature = "alloc")]
pub mod poseidon;
