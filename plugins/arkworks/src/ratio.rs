//! Ratio Proofs

use crate::{
    ec::{AffineCurve, ProjectiveCurve},
    ff::{PrimeField, UniformRand, Zero},
    pairing::{Pairing, PairingEngineExt},
    serialize::{CanonicalDeserialize, CanonicalSerialize, Read, SerializationError, Write},
};
use openzl_util::{
    derivative,
    rand::{CryptoRng, RngCore},
};

/// Hash to Group Trait for Ratio Proof
pub trait HashToGroup<P, C>
where
    P: Pairing + ?Sized,
{
    /// Hashes `challenge` and `ratio` into a group point.
    fn hash(&self, challenge: &C, ratio: (&P::G1, &P::G1)) -> P::G2;
}

/// Prepared Ratio Type
///
/// # Note
///
/// Expected format is `((g1, r * g1), (r * g2, g2))` given curve points
/// [`g1`](Pairing::G1Prepared), [`g2`](Pairing::G2Prepared) and a scalar [`r`](Pairing::Scalar).
pub type PreparedRatio<P> = (
    (<P as Pairing>::G1Prepared, <P as Pairing>::G1Prepared),
    (<P as Pairing>::G2Prepared, <P as Pairing>::G2Prepared),
);

/// Pairing Ratio Proof of Knowledge
#[derive(derivative::Derivative, CanonicalDeserialize, CanonicalSerialize)]
#[derivative(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct RatioProof<P>
where
    P: Pairing + ?Sized,
{
    /// Ratio in G1 of the form `(g1, r * g1)` given a curve point [`g1`](Pairing::G1) and
    /// a scalar [`r`](Pairing::Scalar)
    pub ratio: (P::G1, P::G1),

    /// Matching Point in G2 of the form [`r * g2`](Pairing::G2) given a challenge point
    /// [`g2`](Pairing::G2) and a scalar [`r`](Pairing::Scalar)
    pub matching_point: P::G2,
}

impl<P> RatioProof<P>
where
    P: Pairing + ?Sized,
{
    /// Builds a [`RatioProof`] for `scalar` against `challenge`.
    #[inline]
    pub fn prove<H, C, R>(
        hasher: &H,
        challenge: &C,
        scalar: &P::Scalar,
        rng: &mut R,
    ) -> Option<Self>
    where
        H: HashToGroup<P, C>,
        R: CryptoRng + RngCore + ?Sized,
    {
        let g1_point = <P::G1 as AffineCurve>::Projective::rand(rng);
        if g1_point.is_zero() {
            return None;
        }
        let scaled_g1_point = g1_point.mul(scalar.into_repr());
        if scaled_g1_point.is_zero() {
            return None;
        }
        let g1_point = g1_point.into_affine();
        let scaled_g1_point = scaled_g1_point.into_affine();
        let g2_point = Self::challenge_point(hasher, challenge, (&g1_point, &scaled_g1_point));
        if g2_point.is_zero() {
            return None;
        }
        let scaled_g2_point = g2_point.mul(*scalar);
        if scaled_g2_point.is_zero() {
            return None;
        }
        Some(Self {
            ratio: (g1_point, scaled_g1_point),
            matching_point: scaled_g2_point.into_affine(),
        })
    }

    /// Computes the challenge point that corresponds with the given `challenge`.
    #[inline]
    pub fn challenge_point<H, C>(hasher: &H, challenge: &C, ratio: (&P::G1, &P::G1)) -> P::G2
    where
        H: HashToGroup<P, C>,
    {
        hasher.hash(challenge, (ratio.0, ratio.1))
    }

    /// Verifies that `self` is a valid ratio proof-of-knowledge, returning the ratio of the
    /// underlying scalar.
    #[inline]
    pub fn verify<H, C>(self, hasher: &H, challenge: &C) -> Option<PreparedRatio<P>>
    where
        H: HashToGroup<P, C>,
    {
        let challenge_point =
            Self::challenge_point(hasher, challenge, (&self.ratio.0, &self.ratio.1));
        let ((ratio_0, matching_point), (ratio_1, challenge_point)) = P::Pairing::same(
            (self.ratio.0, self.matching_point),
            (self.ratio.1, challenge_point),
        )?;
        Some(((ratio_0, ratio_1), (matching_point, challenge_point)))
    }
}

/// Testing Framework
#[cfg(feature = "test")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "test")))]
pub mod test {
    use super::*;

    /// Asserts that generating a ratio proof always produces a valid result.
    #[inline]
    pub fn assert_valid_ratio_proof<P, C, H, R>(
        hasher: &H,
        challenge: &C,
        scalar: &P::Scalar,
        rng: &mut R,
    ) where
        P: Pairing,
        H: HashToGroup<P, C>,
        R: CryptoRng + RngCore + ?Sized,
    {
        RatioProof::prove(hasher, challenge, scalar, rng)
            .expect("Proving a ratio proof should be correct.")
            .verify(hasher, challenge)
            .expect("Verifying a ratio proof should be correct.");
    }
}
