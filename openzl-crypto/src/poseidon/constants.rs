// Copyright 2019-2022 Manta Network.
// This file is part of manta-rs.
//
// manta-rs is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// manta-rs is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with manta-rs.  If not, see <http://www.gnu.org/licenses/>.

//! Poseidon Permutation Round Numbers

use crate::poseidon::Field;

#[cfg(feature = "std")]
use {openzl_util::num::Ceil, security::SecurityCondition};

/// Poseidon Security Parameters
///
/// See the [`Specification`](super::Specification) for more on how these constants are part of the
/// Poseidon Permutation algorithm.
///
/// # Safety
///
/// The constants that are specified to be "secure" in this `struct` have only been guaranteed to
/// work for BLS12-381.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Constants {
    /// Width of the Internal Poseidon State
    pub width: usize,

    /// Number of Full Rounds
    pub full_rounds: usize,

    /// Number of Partial Rounds
    pub partial_rounds: usize,
}

impl Constants {
    /// Poseidon Prime Field Modulus Bit Count
    ///
    /// This constant is denoted `n` in the Poseidon paper where `n = ceil(log2(p))`.
    pub const MODULUS_BITS: usize = 255;

    /// Security Level in Bits
    ///
    /// This constant is denoted `M` in the Poseidon paper.
    pub const SECURITY_LEVEL: usize = 128;

    /// Computes constants for a Poseidon implementation that achieves [`SECURITY_LEVEL`] bits of
    /// security according to the claims in the Poseidon paper and current cryptanalytic efforts.
    ///
    /// [`SECURITY_LEVEL`]: Self::SECURITY_LEVEL
    #[cfg(feature = "std")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "std")))]
    #[inline]
    pub fn from_arity(arity: usize) -> Self {
        let mut constants = Self {
            width: arity + 1,
            full_rounds: 0,
            partial_rounds: 0,
        };
        let mut minimum_sbox_count = usize::MAX;
        for mut rf in (2..=1000).step_by(2) {
            for mut rp in 4..200 {
                if (Self {
                    width: constants.width,
                    full_rounds: rf,
                    partial_rounds: rp,
                })
                .are_secure()
                {
                    rf += 2;
                    rp = (1.075 * rp as f32).ceil() as usize;
                    let sbox_count = constants.width * rf + rp;
                    if sbox_count < minimum_sbox_count
                        || (sbox_count == minimum_sbox_count && rf < constants.full_rounds)
                    {
                        constants.full_rounds = rf;
                        constants.partial_rounds = rp;
                        minimum_sbox_count = sbox_count;
                    }
                }
            }
        }
        constants
    }

    /// Computes strengthened secure constants for a Poseidon permutaton of the given `arity`. See
    /// [`strengthened`](Self::strengthened) for more on the security strengthening technique.
    #[cfg(feature = "std")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "std")))]
    #[inline]
    pub fn from_arity_strengthened(arity: usize) -> Self {
        Self::from_arity(arity).strengthened()
    }

    /// Computes strengthened constants from `self`, increasing the number of partial rounds by 25%.
    ///
    /// # Security
    ///
    /// In case of newly-discovered attacks, we may need more rounds to achieve the same level of
    /// security. This option exists so we can preemptively create circuits in order to switch to
    /// them quickly if needed. A note from Dmitry Khovratovich:
    ///
    /// > A realistic alternative is to increase the number of partial rounds by `25%`. Then, it is
    /// unlikely that a new attack breaks through this number, but even if this happends then the
    /// complexity is almost surely above `2^64`, and you will be safe.
    #[cfg(feature = "std")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "std")))]
    #[inline]
    pub fn strengthened(self) -> Self {
        Self {
            width: self.width,
            full_rounds: self.full_rounds,
            partial_rounds: Ceil::ceil(self.partial_rounds as f64 * 1.25),
        }
    }

    /// Converts a [`Field`] into [`Constants`].
    #[inline]
    pub fn from_specification<F>() -> Self
    where
        F: Field,
    {
        Self {
            width: F::WIDTH,
            full_rounds: F::FULL_ROUNDS,
            partial_rounds: F::PARTIAL_ROUNDS,
        }
    }

    /// Returns `true` if `self` are secure constants under the conditions set out in the Poseidon
    /// paper. See [`security`] for more.
    #[cfg(feature = "std")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "std")))]
    #[inline]
    pub fn are_secure(self) -> bool {
        security::Full::is_secure(
            self.full_rounds,
            self.width as f32,
            self.partial_rounds as f32,
            Self::MODULUS_BITS as f32,
            Self::SECURITY_LEVEL as f32,
        )
    }
}

/// Security
pub mod security {
    #[cfg(feature = "std")]
    use {core::cmp, openzl_util::num::Ceil};

    /// Security Conditions
    ///
    /// This `trait` is defined for each known attack on Poseidon. Details of these attacks is
    /// present in section 5.5 of the Poseidon paper.
    pub trait SecurityCondition {
        /// Computes the lower bound on the secure number of full rounds required for a poseidon
        /// with `width` and `partial_rounds` constants and `n` prime field modulus bits for `m`
        /// bits of security.
        fn full_rounds_lower_bound(width: f32, partial_rounds: f32, n: f32, m: f32) -> usize;

        /// Returns `true` if Poseidon with constants given by `full_rounds`, `width`,
        /// `partial_rounds` are safe over a prime field with modulus bits `n` and target security
        /// of `m` bits.
        #[inline]
        fn is_secure(full_rounds: usize, width: f32, partial_rounds: f32, n: f32, m: f32) -> bool {
            full_rounds >= Self::full_rounds_lower_bound(width, partial_rounds, n, m)
        }
    }

    /// Statistical Attack
    #[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
    pub struct StatisticalAttack;

    impl SecurityCondition for StatisticalAttack {
        #[inline]
        fn full_rounds_lower_bound(width: f32, _: f32, n: f32, m: f32) -> usize {
            if m <= (n - 3.0) * (width + 1.0) {
                6
            } else {
                10
            }
        }
    }

    /// Interpolation Attack
    #[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
    pub struct InterpolationAttack;

    #[cfg(feature = "std")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "std")))]
    impl SecurityCondition for InterpolationAttack {
        #[inline]
        fn full_rounds_lower_bound(width: f32, partial_rounds: f32, _: f32, m: f32) -> usize {
            Ceil::ceil(0.43 * m + width.log2() - partial_rounds)
        }
    }

    /// Grobner Basis Full Permutation Attack
    #[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
    pub struct GrobnerBasisFullPermutationAttack;

    #[cfg(feature = "std")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "std")))]
    impl SecurityCondition for GrobnerBasisFullPermutationAttack {
        #[inline]
        fn full_rounds_lower_bound(_: f32, partial_rounds: f32, n: f32, _: f32) -> usize {
            Ceil::ceil(0.21 * n - partial_rounds)
        }
    }

    /// Grobner Basis Partial SBox Attack
    #[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
    pub struct GrobnerBasisPartialSBoxAttack;

    #[cfg(feature = "std")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "std")))]
    impl SecurityCondition for GrobnerBasisPartialSBoxAttack {
        #[inline]
        fn full_rounds_lower_bound(width: f32, partial_rounds: f32, n: f32, _: f32) -> usize {
            Ceil::ceil((0.14 * n - 1.0 - partial_rounds) / (width - 1.0))
        }
    }

    /// Full Security Condition for the known Attacks on Poseidon
    ///
    /// The list of known attacks includes:
    /// - [`StatisticalAttack`]
    /// - [`InterpolationAttack`]
    /// - [`GrobnerBasisFullPermutationAttack`]
    /// - [`GrobnerBasisPartialSBoxAttack`]
    #[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
    pub struct Full;

    #[cfg(feature = "std")]
    #[cfg_attr(doc_cfg, doc(cfg(feature = "std")))]
    impl SecurityCondition for Full {
        #[inline]
        fn full_rounds_lower_bound(width: f32, partial_rounds: f32, n: f32, m: f32) -> usize {
            let statistical =
                StatisticalAttack::full_rounds_lower_bound(width, partial_rounds, n, m);
            let interpolation =
                InterpolationAttack::full_rounds_lower_bound(width, partial_rounds, n, m);
            let grobner_basis_full_permutation =
                GrobnerBasisFullPermutationAttack::full_rounds_lower_bound(
                    width,
                    partial_rounds,
                    n,
                    m,
                );
            let grobner_basis_partial_sbox_attack =
                GrobnerBasisPartialSBoxAttack::full_rounds_lower_bound(width, partial_rounds, n, m);
            cmp::max(
                statistical,
                cmp::max(
                    interpolation,
                    cmp::max(
                        grobner_basis_full_permutation,
                        grobner_basis_partial_sbox_attack,
                    ),
                ),
            )
        }
    }
}

/// Testing Suite
#[cfg(test)]
mod test {
    use super::*;

    /// Tests if the constants match the known constant values.
    #[test]
    fn constants_match_known_values() {
        let known_values = [
            (1, 55),
            (2, 55),
            (3, 56),
            (4, 56),
            (5, 56),
            (6, 56),
            (7, 57),
            (8, 57),
            (9, 57),
            (10, 57),
            (11, 57),
            (12, 57),
            (13, 57),
            (14, 57),
            (15, 59),
            (16, 59),
            (24, 59),
            (36, 60),
            (64, 61),
        ];
        for (arity, partial_rounds) in known_values {
            let constants = Constants::from_arity(arity);
            assert!(constants.are_secure(), "Constants should be secure.");
            assert!(
                constants.strengthened().are_secure(),
                "Strengthened Constants should be secure."
            );
            assert_eq!(
                constants.full_rounds, 8,
                "Full rounds should match the known value."
            );
            assert_eq!(
                constants.partial_rounds, partial_rounds,
                "Partial rounds should match the known value."
            );
        }
    }
}
