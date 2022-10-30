//! Encryption Scheme Plaintext Conversion Primitives and Adapters

use crate::encryption::{
    CiphertextType, Decrypt, DecryptedPlaintextType, DecryptionKeyType, Derive, Encrypt,
    EncryptionKeyType, HeaderType, PlaintextType, RandomnessType,
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
/// When encrypting over [`TargetPlaintext`] we can apply the [`as_target`] conversion function to
/// objects of type [`Plaintext`] to make them compatible with encryption.
///
/// [`TargetPlaintext`]: Self::TargetPlaintext
/// [`as_target`]: Self::as_target
/// [`Plaintext`]: PlaintextType::Plaintext
pub trait Forward<COM = ()>: PlaintextType {
    /// Target Plaintext Type
    type TargetPlaintext;

    /// Converts `source` into the [`TargetPlaintext`](Self::TargetPlaintext) type.
    fn as_target(source: &Self::Plaintext, compiler: &mut COM) -> Self::TargetPlaintext;
}

/// Reverse Conversion
///
/// When decrypting with result [`TargetDecryptedPlaintext`] we can apply the [`into_source`]
/// conversion function to get objects of type [`DecryptedPlaintext`] from the result of a
/// decryption.
///
/// [`TargetDecryptedPlaintext`]: Self::TargetDecryptedPlaintext
/// [`into_source`]: Self::into_source
/// [`DecryptedPlaintext`]: DecryptedPlaintextType::DecryptedPlaintext
pub trait Reverse<COM = ()>: DecryptedPlaintextType {
    /// Target Decrypted Plaintext Type
    type TargetDecryptedPlaintext;

    /// Converts `target` into the source [`DecryptedPlaintext`] type.
    ///
    /// [`DecryptedPlaintext`]: DecryptedPlaintextType::DecryptedPlaintext
    fn into_source(
        target: Self::TargetDecryptedPlaintext,
        compiler: &mut COM,
    ) -> Self::DecryptedPlaintext;
}

/// Plaintext-Converting Encryption Scheme Adapter
///
/// In many applications we may have some structured plaintext data that feeds into a generic
/// encryption scheme over some unstructured type (like encryption over bit-strings). This converter
/// can be used to convert between the plaintext types for conversion before encryption and after
/// decryption. This `struct` utilizes the [`Forward`] (before encryption) and [`Reverse`] (after
/// decryption) `trait`s to give the definition of the conversion. The `C` type on this `struct` is
/// the converter that implements [`Forward`] and/or [`Reverse`].
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "openzl_util::serde", deny_unknown_fields)
)]
#[derive(derivative::Derivative)]
#[derivative(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Converter<E, C> {
    /// Base Encryption Scheme
    pub base: E,

    /// Type Parameter Marker
    __: PhantomData<C>,
}

impl<E, C> Converter<E, C> {
    /// Builds a new [`Converter`] over `base`.
    #[inline]
    pub fn new(base: E) -> Self {
        Self {
            base,
            __: PhantomData,
        }
    }

    /// Returns the inner encryption scheme from `self`.
    #[inline]
    pub fn into_inner(self) -> E {
        self.base
    }
}

impl<E, C> HeaderType for Converter<E, C>
where
    E: HeaderType,
{
    type Header = E::Header;
}

impl<E, C> CiphertextType for Converter<E, C>
where
    E: CiphertextType,
{
    type Ciphertext = E::Ciphertext;
}

impl<E, C> EncryptionKeyType for Converter<E, C>
where
    E: EncryptionKeyType,
{
    type EncryptionKey = E::EncryptionKey;
}

impl<E, C> DecryptionKeyType for Converter<E, C>
where
    E: DecryptionKeyType,
{
    type DecryptionKey = E::DecryptionKey;
}

impl<E, C> PlaintextType for Converter<E, C>
where
    C: PlaintextType,
{
    type Plaintext = C::Plaintext;
}

impl<E, C> RandomnessType for Converter<E, C>
where
    E: RandomnessType,
{
    type Randomness = E::Randomness;
}

impl<E, C> DecryptedPlaintextType for Converter<E, C>
where
    C: DecryptedPlaintextType,
{
    type DecryptedPlaintext = C::DecryptedPlaintext;
}

impl<E, C, COM> Derive<COM> for Converter<E, C>
where
    E: Derive<COM>,
{
    #[inline]
    fn derive(
        &self,
        decryption_key: &Self::DecryptionKey,
        compiler: &mut COM,
    ) -> Self::EncryptionKey {
        self.base.derive(decryption_key, compiler)
    }
}

impl<E, C, COM> Encrypt<COM> for Converter<E, C>
where
    E: Encrypt<COM>,
    C: Forward<COM, TargetPlaintext = E::Plaintext>,
{
    #[inline]
    fn encrypt(
        &self,
        encryption_key: &Self::EncryptionKey,
        randomness: &Self::Randomness,
        header: &Self::Header,
        plaintext: &Self::Plaintext,
        compiler: &mut COM,
    ) -> Self::Ciphertext {
        self.base.encrypt(
            encryption_key,
            randomness,
            header,
            &C::as_target(plaintext, compiler),
            compiler,
        )
    }
}

impl<E, C, COM> Decrypt<COM> for Converter<E, C>
where
    E: Decrypt<COM>,
    C: Reverse<COM, TargetDecryptedPlaintext = E::DecryptedPlaintext>,
{
    #[inline]
    fn decrypt(
        &self,
        decryption_key: &Self::DecryptionKey,
        header: &Self::Header,
        ciphertext: &Self::Ciphertext,
        compiler: &mut COM,
    ) -> Self::DecryptedPlaintext {
        C::into_source(
            self.base
                .decrypt(decryption_key, header, ciphertext, compiler),
            compiler,
        )
    }
}

impl<E, C, COM> Constant<COM> for Converter<E, C>
where
    E: Constant<COM>,
    C: Constant<COM>,
{
    type Type = Converter<E::Type, C::Type>;

    #[inline]
    fn new_constant(this: &Self::Type, compiler: &mut COM) -> Self {
        Self::new(Constant::new_constant(&this.base, compiler))
    }
}

impl<E, C> Decode for Converter<E, C>
where
    E: Decode,
{
    type Error = E::Error;

    #[inline]
    fn decode<R>(mut reader: R) -> Result<Self, DecodeError<R::Error, Self::Error>>
    where
        R: Read,
    {
        Ok(Self::new(Decode::decode(&mut reader)?))
    }
}

impl<E, C> Encode for Converter<E, C>
where
    E: Encode,
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

impl<E, C, D> Sample<D> for Converter<E, C>
where
    E: Sample<D>,
{
    #[inline]
    fn sample<R>(distribution: D, rng: &mut R) -> Self
    where
        R: RngCore + ?Sized,
    {
        Self::new(rng.sample(distribution))
    }
}
