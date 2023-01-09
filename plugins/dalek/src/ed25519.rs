//! Dalek Cryptography [`ed25519`](ed25519_dalek) Backend

use core::marker::PhantomData;
use openzl_crypto::signature::{
    MessageType, RandomnessType, Sign, SignatureType, SigningKeyType, Verify, VerifyingKeyType,
};
use openzl_util::{
    derivative,
    rand::{CryptoRng, Rand, RngCore},
    Array, AsBytes,
};

pub use ed25519_dalek::*;

/// Implements byte conversion from an array of bytes of length `$len` into the given `$type`. These
/// implementations are prefered over the ones provided by [`ed25519_dalek`] because they have no
/// error branch.
macro_rules! byte_conversion {
    ($name:ident, $type:tt, $len:ident) => {
        #[doc = "Converts the `bytes` fixed-length array into [`"]
        #[doc = stringify!($type)]
        #[doc = "`]."]
        ///
        /// # Note
        ///
        /// We don't need to return an error here because `bytes` already has the correct length.
        #[inline]
        pub fn $name(bytes: [u8; $len]) -> $type {
            match $type::from_bytes(&bytes) {
                Ok(value) => value,
                _ => unreachable!(concat!(
                    "We are guaranteed the correct number of bytes from `",
                    stringify!($len),
                    "`."
                )),
            }
        }
    };
}

byte_conversion!(secret_key_from_bytes, SecretKey, SECRET_KEY_LENGTH);
byte_conversion!(public_key_from_bytes, PublicKey, PUBLIC_KEY_LENGTH);
byte_conversion!(signature_from_bytes, Signature, SIGNATURE_LENGTH);

/// Clones the `secret_key` by serializing and then deserializing.
#[inline]
pub fn clone_secret_key(secret_key: &SecretKey) -> SecretKey {
    secret_key_from_bytes(secret_key.to_bytes())
}

/// Generates a [`Keypair`] from `secret_key`.
#[inline]
pub fn keypair(secret_key: &SecretKey) -> Keypair {
    Keypair {
        public: secret_key.into(),
        secret: clone_secret_key(secret_key),
    }
}

/// Generates a [`SecretKey`] from `rng`.
#[inline]
pub fn generate_secret_key<R>(rng: &mut R) -> SecretKey
where
    R: CryptoRng + RngCore,
{
    secret_key_from_bytes(rng.gen())
}

/// Generates a [`Keypair`] from `rng`.
#[inline]
pub fn generate_keypair<R>(rng: &mut R) -> Keypair
where
    R: CryptoRng + RngCore,
{
    let secret_key = generate_secret_key(rng);
    Keypair {
        public: (&secret_key).into(),
        secret: secret_key,
    }
}

/// Edwards Curve Signature Scheme for the `Curve25519` Elliptic Curve
#[derive(derivative::Derivative)]
#[derivative(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Ed25519<M>(PhantomData<M>);

impl<M> MessageType for Ed25519<M> {
    type Message = M;
}

impl<M> RandomnessType for Ed25519<M> {
    /// Empty Randomness
    ///
    /// The [`ed25519_dalek`] crate provides randomness internally so we set it as `()` here.
    type Randomness = ();
}

impl<M> SignatureType for Ed25519<M> {
    type Signature = Signature;
}

impl<M> SigningKeyType for Ed25519<M> {
    type SigningKey = SecretKey;
}

impl<M> VerifyingKeyType for Ed25519<M> {
    type VerifyingKey = Array<u8, 32>;
}

impl<M> Sign for Ed25519<M>
where
    M: AsBytes,
{
    #[inline]
    fn sign(
        &self,
        signing_key: &Self::SigningKey,
        randomness: &Self::Randomness,
        message: &Self::Message,
        compiler: &mut (),
    ) -> Self::Signature {
        let _ = (randomness, compiler);
        keypair(signing_key).sign(&message.as_bytes())
    }
}

impl<M> Verify for Ed25519<M>
where
    M: AsBytes,
{
    type Verification = Result<(), SignatureError>;

    #[inline]
    fn verify(
        &self,
        verifying_key: &Self::VerifyingKey,
        message: &Self::Message,
        signature: &Self::Signature,
        compiler: &mut (),
    ) -> Self::Verification {
        let _ = compiler;
        let verifying_key = PublicKey::from_bytes(verifying_key.as_slice())?;
        verifying_key.verify(&message.as_bytes(), signature)
    }
}
