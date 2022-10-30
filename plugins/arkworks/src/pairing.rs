//! Pairing Utilities

use crate::{
    ec::{AffineCurve, PairingEngine},
    ff::PrimeField,
};
use core::iter;

/// Pairing Configuration
pub trait Pairing {
    /// Underlying Scalar Field
    type Scalar: PrimeField;

    /// First Group of the Pairing
    type G1: AffineCurve<ScalarField = Self::Scalar> + Into<Self::G1Prepared>;

    /// First Group Pairing-Prepared Point
    type G1Prepared;

    /// Second Group of the Pairing
    type G2: AffineCurve<ScalarField = Self::Scalar> + Into<Self::G2Prepared>;

    /// Second Group Pairing-Prepared Point
    type G2Prepared;

    /// Pairing Engine Type
    type Pairing: PairingEngine<
        G1Affine = Self::G1,
        G2Affine = Self::G2,
        G1Prepared = Self::G1Prepared,
        G2Prepared = Self::G2Prepared,
    >;

    /// Returns the base G1 generator for this configuration.
    fn g1_prime_subgroup_generator() -> Self::G1;

    /// Returns the base G2 generator for this configuration.
    fn g2_prime_subgroup_generator() -> Self::G2;
}

/// Pair from a [`PairingEngine`]
pub type Pair<P> = (
    <P as PairingEngine>::G1Prepared,
    <P as PairingEngine>::G2Prepared,
);

/// Pairing Engine Extension
pub trait PairingEngineExt: PairingEngine {
    /// Evaluates the pairing function on `pair`.
    #[inline]
    fn eval(pair: &Pair<Self>) -> Self::Fqk {
        Self::product_of_pairings(iter::once(pair))
    }

    /// Checks if `lhs` and `rhs` evaluate to the same point under the pairing function.
    #[inline]
    fn has_same(lhs: &Pair<Self>, rhs: &Pair<Self>) -> bool {
        Self::eval(lhs) == Self::eval(rhs)
    }

    /// Checks if `lhs` and `rhs` evaluate to the same point under the pairing function, returning
    /// `Some` with prepared points if the pairing outcome is the same. This function checks if
    /// there exists an `r` such that `(r * lhs.0 == rhs.0) && (lhs.1 == r * rhs.1)`.
    #[inline]
    fn same<L1, L2, R1, R2>(lhs: (L1, L2), rhs: (R1, R2)) -> Option<(Pair<Self>, Pair<Self>)>
    where
        L1: Into<Self::G1Prepared>,
        L2: Into<Self::G2Prepared>,
        R1: Into<Self::G1Prepared>,
        R2: Into<Self::G2Prepared>,
    {
        let lhs = (lhs.0.into(), lhs.1.into());
        let rhs = (rhs.0.into(), rhs.1.into());
        Self::has_same(&lhs, &rhs).then_some((lhs, rhs))
    }

    /// Checks if the ratio of `(lhs.0, lhs.1)` from `G1` is the same as the ratio of
    /// `(lhs.0, lhs.1)` from `G2`.
    #[inline]
    fn same_ratio<L1, L2, R1, R2>(lhs: (L1, R1), rhs: (L2, R2)) -> bool
    where
        L1: Into<Self::G1Prepared>,
        L2: Into<Self::G2Prepared>,
        R1: Into<Self::G1Prepared>,
        R2: Into<Self::G2Prepared>,
    {
        Self::has_same(&(lhs.0.into(), rhs.1.into()), &(lhs.1.into(), rhs.0.into()))
    }
}

impl<E> PairingEngineExt for E where E: PairingEngine {}

/// Testing Framework
#[cfg(any(feature = "test", test))]
#[cfg_attr(doc_cfg, doc(cfg(any(feature = "test", test))))]
pub mod test {
    use super::*;
    use crate::ec::ProjectiveCurve;

    #[cfg(test)]
    use openzl_util::rand::{OsRng, Rand};

    /// Asserts that `g1` and `g1*scalar` are in the same ratio as `g2` and `g2*scalar`.
    #[inline]
    pub fn assert_valid_pairing_ratio<E>(g1: E::G1Affine, g2: E::G2Affine, scalar: E::Fr)
    where
        E: PairingEngine,
    {
        assert!(E::same(
            (g1, g2.mul(scalar).into_affine()),
            (g1.mul(scalar).into_affine(), g2)
        )
        .is_some());
    }

    /// Checks that BLS12-381 has a valid pairing ratio.
    #[cfg(feature = "ark-bls12-381")]
    #[test]
    fn bls12_381_has_valid_pairing_ratio() {
        let mut rng = OsRng;
        assert_valid_pairing_ratio::<crate::arkworks::bls12_381::Bls12_381>(
            rng.gen(),
            rng.gen(),
            rng.gen(),
        );
    }

    /// Checks that BN254 has a valid pairing ratio.
    #[cfg(feature = "ark-bn254")]
    #[test]
    fn bn254_has_valid_pairing_ratio() {
        let mut rng = OsRng;
        assert_valid_pairing_ratio::<crate::arkworks::bn254::Bn254>(
            rng.gen(),
            rng.gen(),
            rng.gen(),
        );
    }
}
