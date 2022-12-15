//! Arkworks Random Sampling Implementations

#[cfg(feature = "ec")]
use crate::ec::{
    models::{
        short_weierstrass_jacobian, twisted_edwards_extended, SWModelParameters, TEModelParameters,
    },
    AffineCurve, ProjectiveCurve,
};

#[cfg(feature = "ff")]
use crate::ff::{Fp256, Fp320, Fp384, Fp448, Fp64, Fp768, Fp832, UniformRand};

pub use openzl_util::rand::*;

/// Standard Distribution
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Standard;

/// Builds a [`Sample`] implementation for `$projective` and `$affine` curves over the `$P` model.
#[cfg(feature = "ec")]
macro_rules! sample_curve {
    ($P:tt, $trait:tt, $projective:path, $affine:path $(,)?) => {
        #[cfg(feature = "ec")]
        #[cfg_attr(doc_cfg, doc(cfg(feature = "ec")))]
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

        #[cfg(feature = "ec")]
        #[cfg_attr(doc_cfg, doc(cfg(feature = "ec")))]
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

#[cfg(feature = "ec")]
sample_curve!(
    P,
    SWModelParameters,
    short_weierstrass_jacobian::GroupProjective<P>,
    short_weierstrass_jacobian::GroupAffine<P>,
);

#[cfg(feature = "ec")]
sample_curve!(
    P,
    TEModelParameters,
    twisted_edwards_extended::GroupProjective<P>,
    twisted_edwards_extended::GroupAffine<P>,
);

/// Builds a [`Sample`] implementation for all the `$fp` types.
#[cfg(feature = "ff")]
macro_rules! sample_fp {
    ($($fp:tt),* $(,)?) => {
        $(
            #[cfg(feature = "ff")]
            #[cfg_attr(doc_cfg, doc(cfg(feature = "ff")))]
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

#[cfg(feature = "ff")]
sample_fp!(Fp64, Fp256, Fp320, Fp384, Fp448, Fp768, Fp832);
