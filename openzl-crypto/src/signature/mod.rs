//! Signature Schemes
//!
//! A signature scheme is made up of these three `trait`s:
//!
//! - [`Derive`]
//! - [`Sign`]
//! - [`Verify`]
//!
//! with the following completeness property:
//!
//! For all possible inputs, the following function returns `true`:
//!
//! ```text
//! fn is_valid(signing_key: SigningKey, randomness: Randomness, message: Message) -> bool {
//!     verify(derive(signing_key), message, sign(randomness, signing_key, message))
//! }
//! ```
//!
//! See the [`correctness`](test::correctness) test for more.

use crate::component;
use core::{fmt::Debug, hash::Hash};
use openzl_util::derivative;

#[cfg(feature = "serde")]
use openzl_util::serde::{Deserialize, Serialize};

pub mod convert;

/// Signing Key
#[component]
pub type SigningKey;

/// Verifying Key
#[component]
pub type VerifyingKey;

/// Message
#[component]
pub type Message;

/// Signature
#[component]
pub type Signature;

/// Randomness
#[component]
pub type Randomness;

/// Signed Message
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "openzl_util::serde", deny_unknown_fields)
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "T::Signature: Clone, T::Message: Clone"),
    Copy(bound = "T::Signature: Copy, T::Message: Copy"),
    Debug(bound = "T::Signature: Debug, T::Message: Debug"),
    Default(bound = "T::Signature: Default, T::Message: Default"),
    Eq(bound = "T::Signature: Eq, T::Message: Eq"),
    Hash(bound = "T::Signature: Hash, T::Message: Hash"),
    PartialEq(bound = "T::Signature: PartialEq, T::Message: PartialEq")
)]
pub struct SignedMessage<T>
where
    T: MessageType + SignatureType,
{
    /// Signature
    pub signature: T::Signature,

    /// Message
    pub message: T::Message,
}

impl<T> SignedMessage<T>
where
    T: MessageType + SignatureType,
{
    /// Generates a new [`SignedMessage`] by signing `message` with `signing_key`.
    #[inline]
    pub fn new<COM>(
        parameters: &T,
        signing_key: &T::SigningKey,
        randomness: &T::Randomness,
        message: T::Message,
        compiler: &mut COM,
    ) -> Self
    where
        T: Sign<COM>,
    {
        Self::new_unchecked(
            parameters.sign(signing_key, randomness, &message, compiler),
            message,
        )
    }

    /// Builds a new [`SignedMessage`] without checking that `signature` is valid over `message`.
    #[inline]
    pub fn new_unchecked(signature: T::Signature, message: T::Message) -> Self {
        Self { signature, message }
    }
}

/// Signature Verifying Key Derivation Function
pub trait Derive<COM = ()>: SigningKeyType + VerifyingKeyType {
    /// Derives the verifying key from `signing_key`.
    ///
    /// This function is used by the signer to generate their [`VerifyingKey`] that is sent to the
    /// verifier to check that the signature was valid.
    ///
    /// [`VerifyingKey`]: VerifyingKeyType::VerifyingKey
    fn derive(&self, signing_key: &Self::SigningKey, compiler: &mut COM) -> Self::VerifyingKey;
}

impl<D, COM> Derive<COM> for &D
where
    D: Derive<COM>,
{
    #[inline]
    fn derive(&self, signing_key: &Self::SigningKey, compiler: &mut COM) -> Self::VerifyingKey {
        (*self).derive(signing_key, compiler)
    }
}

/// Signature Creation
pub trait Sign<COM = ()>: MessageType + RandomnessType + SignatureType + SigningKeyType {
    /// Signs `message` with the `signing_key` using `randomness` to hide the signature.
    fn sign(
        &self,
        signing_key: &Self::SigningKey,
        randomness: &Self::Randomness,
        message: &Self::Message,
        compiler: &mut COM,
    ) -> Self::Signature;
}

impl<S, COM> Sign<COM> for &S
where
    S: Sign<COM>,
{
    #[inline]
    fn sign(
        &self,
        signing_key: &Self::SigningKey,
        randomness: &Self::Randomness,
        message: &Self::Message,
        compiler: &mut COM,
    ) -> Self::Signature {
        (*self).sign(signing_key, randomness, message, compiler)
    }
}

/// Signature Verification
pub trait Verify<COM = ()>: MessageType + SignatureType + VerifyingKeyType {
    /// Verification Result Type
    ///
    /// This type is typically either [`bool`], a [`Result`] type, or a compiler variable
    /// representing either of those concrete types.
    type Verification;

    /// Verifies that the `signature` of `message` was signed with the signing key deriving
    /// `verifying_key`.
    ///
    /// For correctness of the signature, `verifying_key` should have come from a call to
    /// [`Derive::derive`], performed by the signer.
    fn verify(
        &self,
        verifying_key: &Self::VerifyingKey,
        message: &Self::Message,
        signature: &Self::Signature,
        compiler: &mut COM,
    ) -> Self::Verification;
}

impl<V, COM> Verify<COM> for &V
where
    V: Verify<COM>,
{
    type Verification = V::Verification;

    #[inline]
    fn verify(
        &self,
        verifying_key: &Self::VerifyingKey,
        message: &Self::Message,
        signature: &Self::Signature,
        compiler: &mut COM,
    ) -> Self::Verification {
        (*self).verify(verifying_key, message, signature, compiler)
    }
}

/// Schnorr Signatures
pub mod schnorr {
    use super::*;
    use crate::{
        algebra::{
            security::DiscreteLogarithmHardness, Group as _, HasGenerator, Ring, ScalarMul,
            ScalarMulGroup,
        },
        hash::security::PreimageResistance,
    };
    use core::{cmp, fmt::Debug, hash::Hash, marker::PhantomData};
    use eclair::{
        alloc::{Const, Constant},
        bool::Bool,
        cmp::PartialEq,
        Has,
    };
    use openzl_util::rand::{Rand, RngCore, Sample};

    /// Schnorr Signature Hash Function
    pub trait HashFunction<COM = ()>: PreimageResistance {
        /// Scalar Type
        type Scalar: Ring<COM>;

        /// Group Type
        type Group: ScalarMulGroup<Self::Scalar, COM, Output = Self::Group>
            + DiscreteLogarithmHardness;

        /// Message Type
        type Message;

        /// Hashes `message` along with `verifying_key` and `nonce_point` into a scalar of type
        /// [`Scalar`](Self::Scalar).
        fn hash(
            &self,
            verifying_key: &Self::Group,
            nonce_point: &Self::Group,
            message: &Self::Message,
            compiler: &mut COM,
        ) -> Self::Scalar;
    }

    /// Scalar Type
    pub type Scalar<H, COM = ()> = <H as HashFunction<COM>>::Scalar;

    /// Group Type
    pub type Group<H, COM = ()> = <H as HashFunction<COM>>::Group;

    /// Message Type
    pub type Message<H, COM = ()> = <H as HashFunction<COM>>::Message;

    /// Schnorr Signature
    #[derive(derivative::Derivative)]
    #[derivative(
        Clone(bound = "S: Clone, G: Clone"),
        Copy(bound = "S: Copy, G: Copy"),
        Debug(bound = "S: Debug, G: Debug"),
        Eq(bound = "S: Eq, G: Eq"),
        Hash(bound = "S: Hash, G: Hash"),
        PartialEq(bound = "S: cmp::PartialEq, G: cmp::PartialEq")
    )]
    pub struct Signature<S, G> {
        /// Scalar
        ///
        /// This scalar is the hash output multiplied by the secret key, blinded by the nonce
        /// factor.
        pub scalar: S,

        /// Nonce Point
        ///
        /// This point is the generator of the Schnorr group multiplied by the secret nonce.
        pub nonce_point: G,
    }

    /// Schnorr Signature Scheme
    #[derive(derivative::Derivative)]
    #[derivative(
        Clone(bound = "H:Clone, H::Group: Clone"),
        Copy(bound = "H: Copy, H::Group: Copy"),
        Debug(bound = "H: Debug, H::Group: Debug"),
        Eq(bound = "H: Eq, H::Group: Eq"),
        Hash(bound = "H: Hash, H::Group: Hash"),
        PartialEq(bound = "H: cmp::PartialEq, H::Group: cmp::PartialEq")
    )]
    pub struct Schnorr<H, COM = ()>
    where
        H: HashFunction<COM>,
    {
        /// Schnorr Hash Function
        pub hash_function: H,

        /// Schnorr Group Generator
        pub generator: H::Group,

        /// Type Parameter Marker
        __: PhantomData<COM>,
    }

    impl<H, COM> Schnorr<H, COM>
    where
        H: HashFunction<COM>,
    {
        /// Builds a new [`Schnorr`] signature scheme over `hash_function` and `generator`.
        #[inline]
        pub fn new(hash_function: H, generator: H::Group) -> Self {
            Self {
                hash_function,
                generator,
                __: PhantomData,
            }
        }
    }

    impl<H, COM> HasGenerator<H::Group, COM> for Schnorr<H, COM>
    where
        H: HashFunction<COM>,
    {
        type Generator = H::Group;

        #[inline]
        fn generator(&self) -> &Self::Generator {
            &self.generator
        }
    }

    impl<H, DG, DH> Sample<(DH, DG)> for Schnorr<H>
    where
        H: HashFunction + Sample<DH>,
        H::Group: Sample<DG>,
    {
        #[inline]
        fn sample<R>(distribution: (DH, DG), rng: &mut R) -> Self
        where
            R: RngCore + ?Sized,
        {
            Self::new(rng.sample(distribution.0), rng.sample(distribution.1))
        }
    }

    impl<H, COM> SigningKeyType for Schnorr<H, COM>
    where
        H: HashFunction<COM>,
    {
        type SigningKey = H::Scalar;
    }

    impl<H, COM> VerifyingKeyType for Schnorr<H, COM>
    where
        H: HashFunction<COM>,
    {
        type VerifyingKey = H::Group;
    }

    impl<H, COM> MessageType for Schnorr<H, COM>
    where
        H: HashFunction<COM>,
    {
        type Message = H::Message;
    }

    impl<H, COM> SignatureType for Schnorr<H, COM>
    where
        H: HashFunction<COM>,
    {
        type Signature = Signature<H::Scalar, H::Group>;
    }

    impl<H, COM> RandomnessType for Schnorr<H, COM>
    where
        H: HashFunction<COM>,
    {
        type Randomness = H::Scalar;
    }

    impl<H, COM> Derive<COM> for Schnorr<H, COM>
    where
        H: HashFunction<COM>,
    {
        #[inline]
        fn derive(&self, signing_key: &Self::SigningKey, compiler: &mut COM) -> Self::VerifyingKey {
            self.generator.scalar_mul(signing_key, compiler)
        }
    }

    impl<H, COM> Sign<COM> for Schnorr<H, COM>
    where
        H: HashFunction<COM>,
    {
        #[inline]
        fn sign(
            &self,
            signing_key: &Self::SigningKey,
            randomness: &Self::Randomness,
            message: &Self::Message,
            compiler: &mut COM,
        ) -> Self::Signature {
            let nonce_point = self.generator.scalar_mul(randomness, compiler);
            Signature {
                scalar: randomness.add(
                    &signing_key.mul(
                        &self.hash_function.hash(
                            &self.generator.scalar_mul(signing_key, compiler),
                            &nonce_point,
                            message,
                            compiler,
                        ),
                        compiler,
                    ),
                    compiler,
                ),
                nonce_point,
            }
        }
    }

    impl<H, COM> Verify<COM> for Schnorr<H, COM>
    where
        COM: Has<bool>,
        H: HashFunction<COM>,
        H::Group: PartialEq<H::Group, COM>,
    {
        type Verification = Bool<COM>;

        #[inline]
        fn verify(
            &self,
            verifying_key: &Self::VerifyingKey,
            message: &Self::Message,
            signature: &Self::Signature,
            compiler: &mut COM,
        ) -> Self::Verification {
            let Signature {
                scalar,
                nonce_point,
            } = signature;
            self.generator.scalar_mul(scalar, compiler).eq(
                &nonce_point.add(
                    &verifying_key.scalar_mul(
                        &self
                            .hash_function
                            .hash(verifying_key, nonce_point, message, compiler),
                        compiler,
                    ),
                    compiler,
                ),
                compiler,
            )
        }
    }

    impl<H, COM> Constant<COM> for Schnorr<H, COM>
    where
        H: Constant<COM> + HashFunction<COM>,
        H::Type: HashFunction<Group = Const<H::Group, COM>>,
        H::Group: Constant<COM>,
        Const<H::Group, COM>: ScalarMulGroup<H::Scalar> + DiscreteLogarithmHardness,
    {
        type Type = Schnorr<H::Type>;

        #[inline]
        fn new_constant(this: &Self::Type, compiler: &mut COM) -> Self {
            Self::new(
                H::new_constant(&this.hash_function, compiler),
                H::Group::new_constant(&this.generator, compiler),
            )
        }
    }
}

/// Testing Framework
#[cfg(feature = "test")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "test")))]
pub mod test {
    use super::*;

    /// Verifies that `scheme` produces self-consistent results on the given `signing_key`,
    /// `randomness`, and `message`.
    #[inline]
    pub fn correctness<S, COM>(
        scheme: &S,
        signing_key: &S::SigningKey,
        randomness: &S::Randomness,
        message: &S::Message,
        compiler: &mut COM,
    ) -> S::Verification
    where
        S: Derive<COM> + Sign<COM> + Verify<COM>,
    {
        scheme.verify(
            &scheme.derive(signing_key, compiler),
            message,
            &scheme.sign(signing_key, randomness, message, compiler),
            compiler,
        )
    }
}
