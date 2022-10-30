//! Signature Scheme Message Conversion Primitives and Adapters

use crate::signature::{
    Derive, MessageType, RandomnessType, Sign, SignatureType, SigningKeyType, Verify,
    VerifyingKeyType,
};
use core::marker::PhantomData;
use eclair::alloc::Constant;
use openzl_util::{
    codec::{Decode, DecodeError, Encode, Read, Write},
    derivative,
    rand::{Rand, RngCore, Sample},
};

#[cfg(feature = "serde")]
use openzl_util::serde::{Deserialize, Serialize};

/// Forward Conversion
///
/// When signing a message over [`TargetMessage`] we can apply the [`as_target`] conversion function
/// to objects of type [`Message`] to make them compatible with signing.
///
/// [`TargetMessage`]: Self::TargetMessage
/// [`as_target`]: Self::as_target
/// [`Message`]: MessageType::Message
pub trait Forward<COM = ()>: MessageType {
    /// Target Message Type
    type TargetMessage;

    /// Converts `source` into the [`TargetMessage`](Self::TargetMessage) type.
    fn as_target(source: &Self::Message, compiler: &mut COM) -> Self::TargetMessage;
}

/// Message-Converting Signature Scheme Adapter
///
/// In many applications we may have some structured message data that feeds into a generic
/// signature scheme over some unstructured type (like signing a bit-string message). This converter
/// can be used to convert between the message types for conversion before signing. This `struct`
/// utilizes the [`Forward`] `trait` to give the definition of the conversion. The `C` type on this
/// `struct` is the converter that implements [`Forward`].
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "openzl_util::serde", deny_unknown_fields)
)]
#[derive(derivative::Derivative)]
#[derivative(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Converter<S, C> {
    /// Base Signature Scheme
    pub base: S,

    /// Type Parameter Marker
    __: PhantomData<C>,
}

impl<S, C> Converter<S, C> {
    /// Builds a new [`Converter`] over `base`.
    #[inline]
    pub fn new(base: S) -> Self {
        Self {
            base,
            __: PhantomData,
        }
    }

    /// Returns the inner signature scheme from `self`.
    #[inline]
    pub fn into_inner(self) -> S {
        self.base
    }
}

impl<S, C> SigningKeyType for Converter<S, C>
where
    S: SigningKeyType,
{
    type SigningKey = S::SigningKey;
}

impl<S, C> VerifyingKeyType for Converter<S, C>
where
    S: VerifyingKeyType,
{
    type VerifyingKey = S::VerifyingKey;
}

impl<S, C> MessageType for Converter<S, C>
where
    C: MessageType,
{
    type Message = C::Message;
}

impl<S, C> SignatureType for Converter<S, C>
where
    S: SignatureType,
{
    type Signature = S::Signature;
}

impl<S, C> RandomnessType for Converter<S, C>
where
    S: RandomnessType,
{
    type Randomness = S::Randomness;
}

impl<S, C, COM> Derive<COM> for Converter<S, C>
where
    S: Derive<COM>,
{
    #[inline]
    fn derive(&self, signing_key: &Self::SigningKey, compiler: &mut COM) -> Self::VerifyingKey {
        self.base.derive(signing_key, compiler)
    }
}

impl<S, C, COM> Sign<COM> for Converter<S, C>
where
    S: Sign<COM, Message = C::TargetMessage>,
    C: Forward<COM>,
{
    #[inline]
    fn sign(
        &self,
        signing_key: &Self::SigningKey,
        randomness: &Self::Randomness,
        message: &Self::Message,
        compiler: &mut COM,
    ) -> Self::Signature {
        self.base.sign(
            signing_key,
            randomness,
            &C::as_target(message, compiler),
            compiler,
        )
    }
}

impl<S, C, COM> Verify<COM> for Converter<S, C>
where
    S: Verify<COM, Message = C::TargetMessage>,
    C: Forward<COM>,
{
    type Verification = S::Verification;

    #[inline]
    fn verify(
        &self,
        verifying_key: &Self::VerifyingKey,
        message: &Self::Message,
        signature: &Self::Signature,
        compiler: &mut COM,
    ) -> Self::Verification {
        self.base.verify(
            verifying_key,
            &C::as_target(message, compiler),
            signature,
            compiler,
        )
    }
}

impl<S, C, COM> Constant<COM> for Converter<S, C>
where
    S: Constant<COM>,
    C: Constant<COM>,
{
    type Type = Converter<S::Type, C::Type>;

    #[inline]
    fn new_constant(this: &Self::Type, compiler: &mut COM) -> Self {
        Self::new(Constant::new_constant(&this.base, compiler))
    }
}

impl<S, C> Decode for Converter<S, C>
where
    S: Decode,
{
    type Error = S::Error;

    #[inline]
    fn decode<R>(mut reader: R) -> Result<Self, DecodeError<R::Error, Self::Error>>
    where
        R: Read,
    {
        Ok(Self::new(Decode::decode(&mut reader)?))
    }
}

impl<S, C> Encode for Converter<S, C>
where
    S: Encode,
{
    #[inline]
    fn encode<W>(&self, mut writer: W) -> Result<(), W::Error>
    where
        W: Write,
    {
        self.base.encode(&mut writer)?;
        Ok(())
    }
}

impl<S, C, D> Sample<D> for Converter<S, C>
where
    S: Sample<D>,
{
    #[inline]
    fn sample<R>(distribution: D, rng: &mut R) -> Self
    where
        R: RngCore + ?Sized,
    {
        Self::new(rng.sample(distribution))
    }
}
