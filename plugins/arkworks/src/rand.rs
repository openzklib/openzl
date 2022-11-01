//! Arkworks Random Sampling Implementations

use crate::{
    ec::{
        models::{
            short_weierstrass_jacobian, twisted_edwards_extended, SWModelParameters,
            TEModelParameters,
        },
        AffineCurve, ProjectiveCurve,
    },
    ff::{Fp256, Fp320, Fp384, Fp448, Fp64, Fp768, Fp832, UniformRand},
};
use openzl_util::rand::{RngCore, Sample};

/// Standard Distribution
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Standard;

/// Builds a [`Sample`] implementation for `$projective` and `$affine` curves over the `$P` model.
macro_rules! sample_curve {
    ($P:tt, $trait:tt, $projective:path, $affine:path $(,)?) => {
        impl<$P> Sample<Standard> for $projective
        where
            $P: $trait,
        {
            #[inline]
            fn sample<R>(distribution: Standard, rng: &mut R) -> Self
            where
                R: RngCore + ?Sized,
            {
                let _ = distribution;
                Self::rand(rng)
            }
        }

        impl<$P> Sample<Standard> for $affine
        where
            $P: $trait,
        {
            #[inline]
            fn sample<R>(distribution: Standard, rng: &mut R) -> Self
            where
                R: RngCore + ?Sized,
            {
                <Self as AffineCurve>::Projective::sample(distribution, rng).into_affine()
            }
        }
    };
}

sample_curve!(
    P,
    SWModelParameters,
    short_weierstrass_jacobian::GroupProjective<P>,
    short_weierstrass_jacobian::GroupAffine<P>,
);

sample_curve!(
    P,
    TEModelParameters,
    twisted_edwards_extended::GroupProjective<P>,
    twisted_edwards_extended::GroupAffine<P>,
);

/// Builds a [`Sample`] implementation for all the `$fp` types.
macro_rules! sample_fp {
    ($($fp:tt),* $(,)?) => {
        $(
            impl<P> Sample<Standard> for $fp<P>
            where
                $fp<P>: UniformRand,
            {
                #[inline]
                fn sample<R>(distribution: Standard, rng: &mut R) -> Self
                where
                    R: RngCore + ?Sized,
                {
                    let _ = distribution;
                    Self::rand(rng)
                }
            }
        )*
    };
}

sample_fp!(Fp64, Fp256, Fp320, Fp384, Fp448, Fp768, Fp832);
