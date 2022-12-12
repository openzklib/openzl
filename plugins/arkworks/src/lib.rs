//! Arkworks OpenZL Plugin

#![cfg_attr(not(any(feature = "std", test)), no_std)]
#![cfg_attr(doc_cfg, feature(doc_cfg))]
#![forbid(rustdoc::broken_intra_doc_links)]
#![forbid(missing_docs)]

extern crate alloc;

#[cfg(all(not(feature = "std"), feature = "ark-std"))]
pub use ark_std as std;

#[cfg(feature = "bls12-377")]
pub use bls12_377;

#[cfg(feature = "bls12-381")]
pub use bls12_381;

#[cfg(feature = "bn254")]
pub use bn254;

#[cfg(feature = "bw6-761")]
pub use bw6_761;

#[cfg(feature = "cp6-782")]
pub use cp6_782;

#[cfg(feature = "ec")]
pub use ec;

#[cfg(feature = "ed-on-bls12-377")]
pub use ed_on_bls12_377;

#[cfg(feature = "ed-on-bls12-381")]
pub use ed_on_bls12_381;

#[cfg(feature = "ed-on-bn254")]
pub use ed_on_bn254;

#[cfg(feature = "ed-on-bw6-761")]
pub use ed_on_bw6_761;

#[cfg(feature = "ed-on-cp6-782")]
pub use ed_on_cp6_782;

#[cfg(feature = "ed-on-mnt4-298")]
pub use ed_on_mnt4_298;

#[cfg(feature = "ed-on-mnt4-753")]
pub use ed_on_mnt4_753;

#[cfg(feature = "gm17")]
pub use gm17;

#[cfg(feature = "groth16")]
pub use groth16;

#[cfg(feature = "mnt4-298")]
pub use mnt4_298;

#[cfg(feature = "mnt4-753")]
pub use mnt4_753;

#[cfg(feature = "mnt6-298")]
pub use mnt6_298;

#[cfg(feature = "mnt6-753")]
pub use mnt6_753;

#[cfg(feature = "pallas")]
pub use pallas;

#[cfg(feature = "poly")]
pub use poly;

#[cfg(feature = "poly-commit")]
pub use poly_commit;

#[cfg(feature = "r1cs-std")]
pub use r1cs_std;

#[cfg(feature = "relations")]
pub use relations;

#[cfg(feature = "snark")]
pub use snark;

#[cfg(feature = "sponge")]
pub use sponge;

#[cfg(feature = "vesta")]
pub use vesta;

pub mod rand;

#[cfg(feature = "algebra")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "algebra")))]
pub mod algebra;

#[cfg(feature = "constraint")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "constraint")))]
pub mod constraint;

#[cfg(feature = "ff")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "ff")))]
pub mod ff;

#[cfg(all(feature = "ec", feature = "ff"))]
#[cfg_attr(doc_cfg, doc(cfg(all(feature = "ec", feature = "ff"))))]
pub mod pairing;

#[cfg(all(feature = "alloc", feature = "constraint"))]
#[cfg_attr(doc_cfg, doc(cfg(all(feature = "alloc", feature = "constraint"))))]
pub mod poseidon;

#[cfg(feature = "algebra")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "algebra")))]
pub mod ratio;

#[cfg(feature = "serialize")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "serialize")))]
pub mod serialize;

#[cfg(feature = "ark-groth16")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "ark-groth16")))]
pub mod groth16;
