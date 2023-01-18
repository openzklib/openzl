//! Hybrid Public-Key Encryption
//!
//! For encrypting against the same [`EncryptionKey`] and [`DecryptionKey`] we may want to use a
//! key-exchange protocol in order to generate these keys as unique shared secrets. The [`Hybrid`]
//! encryption scheme inlines this complexity into the encryption interfaces.

use crate::{
    constraint::{HasInput, Input},
    encryption::{
        self, CiphertextType, Decrypt, DecryptedPlaintextType, DecryptionKeyType, Derive, Encrypt,
        EncryptedMessage, EncryptionKeyType, HeaderType, PlaintextType, RandomnessType,
    },
    key::agreement::{
        self, EphemeralPublicKey, EphemeralPublicKeyType, EphemeralSecretKey,
        EphemeralSecretKeyType, PublicKeyType, SecretKeyType,
    },
};
use core::{fmt::Debug, hash::Hash};
use eclair::{
    self,
    alloc::{
        mode::{Derived, Public, Secret},
        Allocate, Allocator, Constant, Variable,
    },
    bool::{Assert, AssertEq, Bool},
    ops::BitAnd,
    Has,
};
use openzl_util::{
    codec::{Decode, DecodeError, Encode, Read, Write},
    derivative,
    rand::{Rand, RngCore, Sample},
};

#[cfg(feature = "serde")]
use openzl_util::serde::{Deserialize, Serialize};

/// Encryption Key
pub type EncryptionKey<K> = <K as PublicKeyType>::PublicKey;

/// Decryption Key
pub type DecryptionKey<K> = <K as SecretKeyType>::SecretKey;

/// Encryption Randomness
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "openzl_util::serde", deny_unknown_fields)
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "K::EphemeralSecretKey: Clone, E::Randomness: Clone"),
    Copy(bound = "K::EphemeralSecretKey: Copy, E::Randomness: Copy"),
    Debug(bound = "K::EphemeralSecretKey: Debug, E::Randomness: Debug"),
    Default(bound = "K::EphemeralSecretKey: Default, E::Randomness: Default"),
    Eq(bound = "K::EphemeralSecretKey: Eq, E::Randomness: Eq"),
    Hash(bound = "K::EphemeralSecretKey: Hash, E::Randomness: Hash"),
    PartialEq(bound = "K::EphemeralSecretKey: PartialEq, E::Randomness: PartialEq")
)]
pub struct Randomness<K, E>
where
    K: EphemeralSecretKeyType,
    E: RandomnessType,
{
    /// Ephemeral Secret Key
    pub ephemeral_secret_key: K::EphemeralSecretKey,

    /// Base Encryption Randomness
    pub randomness: E::Randomness,
}

impl<K, E> Randomness<K, E>
where
    K: EphemeralSecretKeyType,
    E: RandomnessType,
{
    /// Builds a new [`Randomness`] from `ephemeral_secret_key` and `randomness`.
    #[inline]
    pub fn new(ephemeral_secret_key: K::EphemeralSecretKey, randomness: E::Randomness) -> Self {
        Self {
            ephemeral_secret_key,
            randomness,
        }
    }

    /// Builds a new [`Randomness`] from `ephemeral_secret_key` whenever the base encryption scheme
    /// has no [`Randomness`] type (i.e. uses `()` as its [`Randomness`] type).
    ///
    /// [`Randomness`]: RandomnessType::Randomness
    #[inline]
    pub fn from_key(ephemeral_secret_key: K::EphemeralSecretKey) -> Self
    where
        E: RandomnessType<Randomness = ()>,
    {
        Self::new(ephemeral_secret_key, ())
    }
}

impl<K, E, DESK, DR> Sample<(DESK, DR)> for Randomness<K, E>
where
    K: EphemeralSecretKeyType,
    E: RandomnessType,
    K::EphemeralSecretKey: Sample<DESK>,
    E::Randomness: Sample<DR>,
{
    #[inline]
    fn sample<R>(distribution: (DESK, DR), rng: &mut R) -> Self
    where
        R: RngCore + ?Sized,
    {
        Self::new(rng.sample(distribution.0), rng.sample(distribution.1))
    }
}

impl<K, E, COM> Variable<Secret, COM> for Randomness<K, E>
where
    K: EphemeralSecretKeyType + Constant<COM>,
    E: RandomnessType + Constant<COM>,
    K::EphemeralSecretKey: Variable<Secret, COM, Type = EphemeralSecretKey<K::Type>>,
    E::Randomness: Variable<Secret, COM, Type = encryption::Randomness<E::Type>>,
    K::Type: EphemeralSecretKeyType,
    E::Type: RandomnessType,
{
    type Type = Randomness<K::Type, E::Type>;

    #[inline]
    fn new_unknown(compiler: &mut COM) -> Self {
        Variable::<Derived<(Secret, Secret)>, COM>::new_unknown(compiler)
    }

    #[inline]
    fn new_known(this: &Self::Type, compiler: &mut COM) -> Self {
        Variable::<Derived<(Secret, Secret)>, COM>::new_known(this, compiler)
    }
}

impl<K, E, ESK, R, COM> Variable<Derived<(ESK, R)>, COM> for Randomness<K, E>
where
    K: EphemeralSecretKeyType + Constant<COM>,
    E: RandomnessType + Constant<COM>,
    K::EphemeralSecretKey: Variable<ESK, COM, Type = EphemeralSecretKey<K::Type>>,
    E::Randomness: Variable<R, COM, Type = encryption::Randomness<E::Type>>,
    K::Type: EphemeralSecretKeyType,
    E::Type: RandomnessType,
{
    type Type = Randomness<K::Type, E::Type>;

    #[inline]
    fn new_unknown(compiler: &mut COM) -> Self {
        Self::new(compiler.allocate_unknown(), compiler.allocate_unknown())
    }

    #[inline]
    fn new_known(this: &Self::Type, compiler: &mut COM) -> Self {
        Self::new(
            this.ephemeral_secret_key.as_known(compiler),
            this.randomness.as_known(compiler),
        )
    }
}

/// Full Ciphertext
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "openzl_util::serde", deny_unknown_fields)
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "K::EphemeralPublicKey: Clone, E::Ciphertext: Clone"),
    Copy(bound = "K::EphemeralPublicKey: Copy, E::Ciphertext: Copy"),
    Debug(bound = "K::EphemeralPublicKey: Debug, E::Ciphertext: Debug"),
    Default(bound = "K::EphemeralPublicKey: Default, E::Ciphertext: Default"),
    Hash(bound = "K::EphemeralPublicKey: Hash, E::Ciphertext: Hash")
)]
pub struct Ciphertext<K, E>
where
    K: EphemeralPublicKeyType,
    E: CiphertextType,
{
    /// Ephemeral Public Key
    pub ephemeral_public_key: K::EphemeralPublicKey,

    /// Base Encryption Ciphertext
    pub ciphertext: E::Ciphertext,
}

impl<K, E> Ciphertext<K, E>
where
    K: EphemeralPublicKeyType,
    E: CiphertextType,
{
    /// Builds a new [`Ciphertext`] from `ephemeral_public_key` and `ciphertext`.
    #[inline]
    pub fn new(ephemeral_public_key: K::EphemeralPublicKey, ciphertext: E::Ciphertext) -> Self {
        Self {
            ephemeral_public_key,
            ciphertext,
        }
    }
}

impl<K, E, DEPK, DC> Sample<(DEPK, DC)> for Ciphertext<K, E>
where
    K: EphemeralPublicKeyType,
    E: CiphertextType,
    K::EphemeralPublicKey: Sample<DEPK>,
    E::Ciphertext: Sample<DC>,
{
    #[inline]
    fn sample<R>(distribution: (DEPK, DC), rng: &mut R) -> Self
    where
        R: RngCore + ?Sized,
    {
        Self::new(rng.sample(distribution.0), rng.sample(distribution.1))
    }
}

impl<K, E, COM> eclair::cmp::PartialEq<Self, COM> for Ciphertext<K, E>
where
    COM: Has<bool>,
    Bool<COM>: BitAnd<Bool<COM>, COM, Output = Bool<COM>>,
    K: EphemeralPublicKeyType,
    E: CiphertextType,
    K::EphemeralPublicKey: eclair::cmp::PartialEq<K::EphemeralPublicKey, COM>,
    E::Ciphertext: eclair::cmp::PartialEq<E::Ciphertext, COM>,
{
    #[inline]
    fn eq(&self, rhs: &Self, compiler: &mut COM) -> Bool<COM> {
        self.ephemeral_public_key
            .eq(&rhs.ephemeral_public_key, compiler)
            .bitand(self.ciphertext.eq(&rhs.ciphertext, compiler), compiler)
    }

    #[inline]
    fn assert_equal(&self, rhs: &Self, compiler: &mut COM)
    where
        COM: Assert,
    {
        compiler.assert_eq(&self.ephemeral_public_key, &rhs.ephemeral_public_key);
        compiler.assert_eq(&self.ciphertext, &rhs.ciphertext);
    }
}

impl<K, E, COM> Variable<Public, COM> for Ciphertext<K, E>
where
    K: EphemeralPublicKeyType + Constant<COM>,
    E: CiphertextType + Constant<COM>,
    K::EphemeralPublicKey: Variable<Public, COM, Type = EphemeralPublicKey<K::Type>>,
    E::Ciphertext: Variable<Public, COM, Type = encryption::Ciphertext<E::Type>>,
    K::Type: EphemeralPublicKeyType,
    E::Type: CiphertextType,
{
    type Type = Ciphertext<K::Type, E::Type>;

    #[inline]
    fn new_unknown(compiler: &mut COM) -> Self {
        Variable::<Derived<(Public, Public)>, COM>::new_unknown(compiler)
    }

    #[inline]
    fn new_known(this: &Self::Type, compiler: &mut COM) -> Self {
        Variable::<Derived<(Public, Public)>, COM>::new_known(this, compiler)
    }
}

impl<K, E, EPK, C, COM> Variable<Derived<(EPK, C)>, COM> for Ciphertext<K, E>
where
    K: EphemeralPublicKeyType + Constant<COM>,
    E: CiphertextType + Constant<COM>,
    K::EphemeralPublicKey: Variable<EPK, COM, Type = EphemeralPublicKey<K::Type>>,
    E::Ciphertext: Variable<C, COM, Type = encryption::Ciphertext<E::Type>>,
    K::Type: EphemeralPublicKeyType,
    E::Type: CiphertextType,
{
    type Type = Ciphertext<K::Type, E::Type>;

    #[inline]
    fn new_unknown(compiler: &mut COM) -> Self {
        Self::new(compiler.allocate_unknown(), compiler.allocate_unknown())
    }

    #[inline]
    fn new_known(this: &Self::Type, compiler: &mut COM) -> Self {
        Self::new(
            this.ephemeral_public_key.as_known(compiler),
            this.ciphertext.as_known(compiler),
        )
    }
}

impl<K, E> Encode for Ciphertext<K, E>
where
    K: EphemeralPublicKeyType,
    K::EphemeralPublicKey: Encode,
    E: CiphertextType,
    E::Ciphertext: Encode,
{
    #[inline]
    fn encode<W>(&self, mut writer: W) -> Result<(), W::Error>
    where
        W: Write,
    {
        self.ephemeral_public_key.encode(&mut writer)?;
        self.ciphertext.encode(&mut writer)?;
        Ok(())
    }
}

impl<K, E, P> Input<P> for Ciphertext<K, E>
where
    K: EphemeralPublicKeyType,
    E: CiphertextType,
    P: HasInput<K::EphemeralPublicKey> + HasInput<E::Ciphertext> + ?Sized,
{
    #[inline]
    fn extend(&self, input: &mut P::Input) {
        P::extend(input, &self.ephemeral_public_key);
        P::extend(input, &self.ciphertext);
    }
}

/// Hybrid Encryption Scheme
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "openzl_util::serde", deny_unknown_fields)
)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct Hybrid<K, E> {
    /// Key Agreement Scheme
    pub key_agreement_scheme: K,

    /// Base Encryption Scheme
    pub encryption_scheme: E,
}

impl<K, E> Hybrid<K, E> {
    /// Builds a new [`Hybrid`] encryption scheme from `key_agreement_scheme` and a base
    /// `encryption_scheme`.
    #[inline]
    pub fn new(key_agreement_scheme: K, encryption_scheme: E) -> Self {
        Self {
            key_agreement_scheme,
            encryption_scheme,
        }
    }
}

impl<K, E> EncryptedMessage<Hybrid<K, E>>
where
    K: EphemeralPublicKeyType,
    E: CiphertextType + HeaderType,
{
    /// Returns the ephemeral public key associated to `self`, stored in its ciphertext.
    #[inline]
    pub fn ephemeral_public_key(&self) -> &K::EphemeralPublicKey {
        &self.ciphertext.ephemeral_public_key
    }
}

#[component]
impl<K, E> Hybrid<K, E> {
    type Header = E::Header where E: HeaderType;
    type Ciphertext = Ciphertext<K, E> where K: EphemeralPublicKeyType, E: CiphertextType;
    type EncryptionKey = EncryptionKey<K> where K: PublicKeyType;
    type DecryptionKey = DecryptionKey<K> where K: SecretKeyType;
    type Plaintext = E::Plaintext where E: PlaintextType;
    type Randomness = Randomness<K, E> where K: EphemeralSecretKeyType, E: RandomnessType;
    type DecryptedPlaintext = E::DecryptedPlaintext where E: DecryptedPlaintextType;
}

impl<K, E> HeaderType for Hybrid<K, E>
where
    E: HeaderType,
{
    type Header = E::Header;
}

impl<K, E> CiphertextType for Hybrid<K, E>
where
    K: EphemeralPublicKeyType,
    E: CiphertextType,
{
    type Ciphertext = Ciphertext<K, E>;
}

impl<K, E> EncryptionKeyType for Hybrid<K, E>
where
    K: PublicKeyType,
{
    type EncryptionKey = EncryptionKey<K>;
}

impl<K, E> DecryptionKeyType for Hybrid<K, E>
where
    K: SecretKeyType,
{
    type DecryptionKey = DecryptionKey<K>;
}

impl<K, E> PlaintextType for Hybrid<K, E>
where
    E: PlaintextType,
{
    type Plaintext = E::Plaintext;
}

impl<K, E> RandomnessType for Hybrid<K, E>
where
    K: EphemeralSecretKeyType,
    E: RandomnessType,
{
    type Randomness = Randomness<K, E>;
}

impl<K, E> DecryptedPlaintextType for Hybrid<K, E>
where
    E: DecryptedPlaintextType,
{
    type DecryptedPlaintext = E::DecryptedPlaintext;
}

impl<K, E, COM> Derive<COM> for Hybrid<K, E>
where
    K: agreement::Derive<COM>,
{
    #[inline]
    fn derive(
        &self,
        decryption_key: &Self::DecryptionKey,
        compiler: &mut COM,
    ) -> Self::EncryptionKey {
        self.key_agreement_scheme.derive(decryption_key, compiler)
    }
}

impl<K, E, COM> Encrypt<COM> for Hybrid<K, E>
where
    K: agreement::DeriveEphemeral<COM> + agreement::GenerateSecret<COM>,
    E: Encrypt<COM, EncryptionKey = K::SharedSecret>,
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
        Ciphertext {
            ephemeral_public_key: self
                .key_agreement_scheme
                .derive_ephemeral(&randomness.ephemeral_secret_key, compiler),
            ciphertext: self.encryption_scheme.encrypt(
                &self.key_agreement_scheme.generate_secret(
                    encryption_key,
                    &randomness.ephemeral_secret_key,
                    compiler,
                ),
                &randomness.randomness,
                header,
                plaintext,
                compiler,
            ),
        }
    }
}

impl<K, E, COM> Decrypt<COM> for Hybrid<K, E>
where
    K: agreement::ReconstructSecret<COM>,
    E: Decrypt<COM, DecryptionKey = K::SharedSecret>,
{
    #[inline]
    fn decrypt(
        &self,
        decryption_key: &Self::DecryptionKey,
        header: &Self::Header,
        ciphertext: &Self::Ciphertext,
        compiler: &mut COM,
    ) -> Self::DecryptedPlaintext {
        self.encryption_scheme.decrypt(
            &self.key_agreement_scheme.reconstruct_secret(
                &ciphertext.ephemeral_public_key,
                decryption_key,
                compiler,
            ),
            header,
            &ciphertext.ciphertext,
            compiler,
        )
    }
}

impl<K, E> Decode for Hybrid<K, E>
where
    K: Decode,
    E: Decode,
{
    type Error = ();

    #[inline]
    fn decode<R>(mut reader: R) -> Result<Self, DecodeError<R::Error, Self::Error>>
    where
        R: Read,
    {
        Ok(Self::new(
            Decode::decode(&mut reader).map_err(|err| err.map_decode(|_| ()))?,
            Decode::decode(&mut reader).map_err(|err| err.map_decode(|_| ()))?,
        ))
    }
}

impl<K, E> Encode for Hybrid<K, E>
where
    K: Encode,
    E: Encode,
{
    #[inline]
    fn encode<W>(&self, mut writer: W) -> Result<(), W::Error>
    where
        W: Write,
    {
        self.key_agreement_scheme.encode(&mut writer)?;
        self.encryption_scheme.encode(&mut writer)?;
        Ok(())
    }
}

impl<K, E, DK, DE> Sample<(DK, DE)> for Hybrid<K, E>
where
    K: Sample<DK>,
    E: Sample<DE>,
{
    #[inline]
    fn sample<R>(distribution: (DK, DE), rng: &mut R) -> Self
    where
        R: RngCore + ?Sized,
    {
        Self::new(rng.sample(distribution.0), rng.sample(distribution.1))
    }
}

impl<K, E, COM> Constant<COM> for Hybrid<K, E>
where
    K: Constant<COM>,
    E: Constant<COM>,
{
    type Type = Hybrid<K::Type, E::Type>;

    #[inline]
    fn new_constant(this: &Self::Type, compiler: &mut COM) -> Self {
        Self::new(
            this.key_agreement_scheme.as_constant(compiler),
            this.encryption_scheme.as_constant(compiler),
        )
    }
}
