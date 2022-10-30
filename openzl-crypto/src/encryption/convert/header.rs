//! Encryption Header Conversion Primitives and Adapters

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

/// Header Conversion
pub trait Header<COM = ()>: HeaderType {
    /// Target Header Type
    type TargetHeader;

    /// Converts `source` into the [`TargetHeader`](Self::TargetHeader) type.
    fn as_target(source: &Self::Header, compiler: &mut COM) -> Self::TargetHeader;
}

/// Header-Converting Encryption Scheme Adapter
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
    C: HeaderType,
{
    type Header = C::Header;
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
    E: PlaintextType,
{
    type Plaintext = E::Plaintext;
}

impl<E, C> RandomnessType for Converter<E, C>
where
    E: RandomnessType,
{
    type Randomness = E::Randomness;
}

impl<E, C> DecryptedPlaintextType for Converter<E, C>
where
    E: DecryptedPlaintextType,
{
    type DecryptedPlaintext = E::DecryptedPlaintext;
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
    C: Header<COM, TargetHeader = E::Header>,
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
            &C::as_target(header, compiler),
            plaintext,
            compiler,
        )
    }
}

impl<E, C, COM> Decrypt<COM> for Converter<E, C>
where
    E: Decrypt<COM>,
    C: Header<COM, TargetHeader = E::Header>,
{
    #[inline]
    fn decrypt(
        &self,
        decryption_key: &Self::DecryptionKey,
        header: &Self::Header,
        ciphertext: &Self::Ciphertext,
        compiler: &mut COM,
    ) -> Self::DecryptedPlaintext {
        self.base.decrypt(
            decryption_key,
            &C::as_target(header, compiler),
            ciphertext,
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
