//! Hash Functions

/// Hash Function
pub trait HashFunction<COM = ()> {
    /// Input Type
    type Input: ?Sized;

    /// Output Type
    type Output;

    /// Computes the hash over `input`.
    fn hash(&self, input: &Self::Input, compiler: &mut COM) -> Self::Output;
}

impl<H, COM> HashFunction<COM> for &H
where
    H: HashFunction<COM>,
{
    type Input = H::Input;
    type Output = H::Output;

    #[inline]
    fn hash(&self, input: &Self::Input, compiler: &mut COM) -> Self::Output {
        (*self).hash(input, compiler)
    }
}

/// Binary Hash Function
pub trait BinaryHashFunction<COM = ()> {
    /// Left Input Type
    type Left: ?Sized;

    /// Right Input Type
    type Right: ?Sized;

    /// Output Type
    type Output;

    /// Computes the hash over `lhs` and `rhs`.
    fn hash(&self, lhs: &Self::Left, rhs: &Self::Right, compiler: &mut COM) -> Self::Output;
}

/// Array Hash Function
pub trait ArrayHashFunction<const ARITY: usize, COM = ()> {
    /// Input Type
    type Input: ?Sized;

    /// Output Type
    type Output;

    /// Computes the hash over `input`.
    fn hash(&self, input: [&Self::Input; ARITY], compiler: &mut COM) -> Self::Output;
}

/// Array Hashing Utilities
pub mod array {
    use super::*;
    use core::marker::PhantomData;

    #[cfg(feature = "serde")]
    use openzl_util::serde::{Deserialize, Serialize};

    /// Converts `hasher` from an [`ArrayHashFunction`] into a [`HashFunction`].
    #[inline]
    pub fn as_unary<H, COM>(hasher: H) -> AsUnary<H, COM>
    where
        H: ArrayHashFunction<1, COM>,
    {
        AsUnary::new(hasher)
    }

    /// Unary Hash Function Converter
    #[cfg_attr(
        feature = "serde",
        derive(Deserialize, Serialize),
        serde(crate = "openzl_util::serde", deny_unknown_fields)
    )]
    #[derive(derivative::Derivative)]
    #[derivative(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
    pub struct AsUnary<H, COM = ()>
    where
        H: ArrayHashFunction<1, COM>,
    {
        /// Array Hasher
        hasher: H,

        /// Type Parameter Marker
        __: PhantomData<COM>,
    }

    impl<H, COM> AsUnary<H, COM>
    where
        H: ArrayHashFunction<1, COM>,
    {
        /// Builds a new [`HashFunction`] implementation out of an [`ArrayHashFunction`]
        /// implementation `hasher`.
        #[inline]
        pub fn new(hasher: H) -> Self {
            Self {
                hasher,
                __: PhantomData,
            }
        }
    }

    impl<H, COM> HashFunction<COM> for AsUnary<H, COM>
    where
        H: ArrayHashFunction<1, COM>,
    {
        type Input = H::Input;
        type Output = H::Output;

        #[inline]
        fn hash(&self, input: &Self::Input, compiler: &mut COM) -> Self::Output {
            self.hasher.hash([input], compiler)
        }
    }
}

/// Security Assumptions
///
/// The following outlines some standard security assumptions for hash functions. These security
/// properties can be attached to general types that don't exactly conform to the hash function
/// `trait`s to describe the same cryptographic assumptions or guarantees given by the type.
pub mod security {
    /// Preimage Resistance
    ///
    /// For a hash function `H` and an output `y`, it should be infeasible to find a preimage `x`
    /// such that the following function returns `true`:
    ///
    /// ```text
    /// fn is_preimage(x: H::Input, y: H::Output) -> bool {
    ///     H(x) == h
    /// }
    /// ```
    pub trait PreimageResistance {}

    /// Second Preimage Resistance
    ///
    /// For a hash function `H` and an input `x_1`, it should be infeasible to find a another input
    /// `x_2` such that the following function returns `true`:
    ///
    /// ```text
    /// fn is_collision(x_1: H::Input, x_2: H::Input) -> bool {
    ///     (x_1 != x_2) && (H(x_1) == H(x_2))
    /// }
    /// ```
    pub trait SecondPreimageResistance {}

    /// Collision Resistance
    ///
    /// For a hash function `H` it should be infeasible to find two inputs `x_1` and `x_2` such that
    /// the following function returns `true`:
    ///
    /// ```text
    /// fn is_collision(x_1: H::Input, x_2: H::Input) -> bool {
    ///     (x_1 != x_2) && (H(x_1) == H(x_2))
    /// }
    /// ```
    ///
    /// # Strength
    ///
    /// Note this is a stronger assumption than [`SecondPreimageResistance`] since we are not
    /// requiring that the attacker find a second preimage of a given input `x_1`, they only need to
    /// find any collision for any input to break this assumption.
    pub trait CollisionResistance: SecondPreimageResistance {}
}
