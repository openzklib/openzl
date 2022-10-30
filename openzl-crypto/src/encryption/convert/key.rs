//! Encryption and Decryption Key Conversion Primitives and Adapters

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

/// Encryption Key Conversion
pub trait Encryption<COM = ()>: EncryptionKeyType {
    /// Target Encryption Key Type
    type TargetEncryptionKey;

    /// Converts `source` into the [`TargetEncryptionKey`](Self::TargetEncryptionKey) type.
    fn as_target(source: &Self::EncryptionKey, compiler: &mut COM) -> Self::TargetEncryptionKey;
}

/// Decryption Key Conversion
pub trait Decryption<COM = ()>: DecryptionKeyType {
    /// Target Decryption Key Type
    type TargetDecryptionKey;

    /// Converts `source` into the [`TargetDecryptionKey`](Self::TargetDecryptionKey) type.
    fn as_target(source: &Self::DecryptionKey, compiler: &mut COM) -> Self::TargetDecryptionKey;
}

/// Key-Converting Encryption Scheme Adapter
///
/// In many applications we may have some encryption schemes that are layered on top of each other
/// where one cipher generates a key for a base cipher. If the key spaces are not exactly equal, we
/// need some mechanism to convert between them.
///
/// For example, instantiations of a [`hybrid`] encryption scheme will use the key-agreement scheme
/// to generate a shared secret between the encryptor and the decryptor, which should be the
/// underlying key for the base encryption scheme. However, in most cases, the key-agreement scheme
/// has the wrong key-size for the base encryption (i.e. ECDH + AES), so we need a key-derivation
/// function to convert the keys. This [`Converter`] type facilitates the conversion between these
/// key spaces.
///
/// [`hybrid`]: crate::encryption::hybrid
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
    C: EncryptionKeyType,
{
    type EncryptionKey = C::EncryptionKey;
}

impl<E, C> DecryptionKeyType for Converter<E, C>
where
    C: DecryptionKeyType,
{
    type DecryptionKey = C::DecryptionKey;
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
    E: Derive<COM, DecryptionKey = C::DecryptionKey, EncryptionKey = C::EncryptionKey>,
    C: DecryptionKeyType + EncryptionKeyType,
{
    /// For key-derivation, we don't assume any structure on the underlying keys that would allow
    /// derivation, so we use the trivial structure where the converter's decryption key and
    /// encryption key are the same as those as the base encryption scheme.
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
    C: Encryption<COM, TargetEncryptionKey = E::EncryptionKey>,
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
            &C::as_target(encryption_key, compiler),
            randomness,
            header,
            plaintext,
            compiler,
        )
    }
}

impl<E, C, COM> Decrypt<COM> for Converter<E, C>
where
    E: Decrypt<COM>,
    C: Decryption<COM, TargetDecryptionKey = E::DecryptionKey>,
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
            &C::as_target(decryption_key, compiler),
            header,
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
