//! Encryption Primitives
//!
//! The encryption abstractions are organized into a two categories, a set of type `trait`s and a
//! set of behavior `trait`s which require those types to be implemented. See the [`Encrypt`] and
//! [`Decrypt`] `trait`s for more.

use crate::{
    component,
    constraint::{HasInput, Input, ProofSystem},
};
use core::{fmt::Debug, hash::Hash, marker::PhantomData};
use eclair::{
    self,
    alloc::{
        mode::{Derived, Public},
        Allocate, Allocator, Constant, Var, Variable,
    },
    bool::{Assert, AssertEq, Bool},
    ops::BitAnd,
    Has,
};
use openzl_util::{
    codec::{Encode, Write},
    derivative,
    rand::{Rand, RngCore, Sample},
};

#[cfg(feature = "serde")]
use openzl_util::serde::{Deserialize, Serialize};

pub mod convert;
pub mod hybrid;

/// Encryption Header
///
/// The encryption header contains information that must be available at both encryption and
/// decryption. Common headers include nonces and associated data, but cannot, for example, include
/// private randomness that is only available at encryption. In that case, one should use the
/// [`Randomness`] type. The header is also not encrypted as a consequence of being available at
/// both encryption and decryption, only the [`Plaintext`] is encrypted. See [`EncryptionTypes`] for
/// more details on types that are required for encryption.
///
/// [`Randomness`]: RandomnessType::Randomness
/// [`Plaintext`]: PlaintextType::Plaintext
#[component]
pub type Header;

/// Ciphertext
///
/// The ciphertext type represents the piece of the encrypt-decrypt interface that contains the
/// hidden information that can be created by encryption and is required for opening by decryption.
/// For [`hybrid`] and/or authenticating protocols this will also include ephemeral keys, tags, or
/// other metadata, not just the raw ciphertext. See the [`Encrypt::encrypt`] and
/// [`Decrypt::decrypt`] methods for more.
#[component]
pub type Ciphertext;

/// Encryption Key
///
/// The encryption key is the information required to produce a valid ciphertext that is targeted
/// towards some [`DecryptionKey`](DecryptionKeyType::DecryptionKey). In the case when the
/// decryption key is linked by some computable protocol to the encryption key, [`Derive`] should be
/// implemented to facilitate this derivation.
#[component]
pub type EncryptionKey;

/// Decryption Key
///
/// The decryption key is the information required to open a valid ciphertext that was encrypted
/// with the [`EncryptionKey`](EncryptionKeyType::EncryptionKey) that was targeted towards it. In
/// the case when the decryption key is linked by some computable protocol to the encryption key,
/// [`Derive`] should be implemented to facilitate this derivation.
#[component]
pub type DecryptionKey;

/// Plaintext
///
/// The core payload of the encryption/decryption protocol. All the information in the plaintext
/// should be kept secret and not be deducible from the [`Ciphertext`]. For associated data that
/// does not go in the [`Ciphertext`] use [`Header`] instead.
///
/// [`Ciphertext`]: CiphertextType::Ciphertext
/// [`Header`]: HeaderType::Header
#[component]
pub type Plaintext;

/// Randomness
///
/// The randomness type allows us to inject some extra randomness to hide repeated encryptions
/// with the same key and same plaintext, independent of the nonce stored in the [`Header`]. In
/// this case, note that [`Randomness`] is not available to the [`Decrypt::decrypt`] method.
///
/// [`Header`]: HeaderType::Header
/// [`Randomness`]: Self::Randomness
#[component]
pub type Randomness;

/// Decrypted Plaintext
///
/// For decryption, we not only get out some data resembling the [`Plaintext`], but also
/// authentication tags and other metadata in order to determine if the decryption succeeded if it
/// is fallible. In general, we cannot assume that [`DecryptedPlaintext`] and [`Plaintext`] are the
/// same type or if they are the same type, are the same value.
///
/// [`Plaintext`]: PlaintextType::Plaintext
/// [`DecryptedPlaintext`]: Self::DecryptedPlaintext
#[component]
pub type DecryptedPlaintext;

/// Encryption Key Derivation
///
/// For protocols that can derive the [`EncryptionKey`] from the [`DecryptionKey`], this `trait` can
/// be used to specify the derivation algorithm. The [`DecryptionKey`] should be kept secret
/// relative to the [`EncryptionKey`] so if they are the same key, then some key exchange protocol
/// should be used to derive the [`DecryptionKey`] as some shared secret. See [`hybrid`] for more.
///
/// [`EncryptionKey`]: EncryptionKeyType::EncryptionKey
/// [`DecryptionKey`]: DecryptionKeyType::DecryptionKey
pub trait Derive<COM = ()>: DecryptionKeyType + EncryptionKeyType {
    /// Derives an [`EncryptionKey`](EncryptionKeyType::EncryptionKey) from `decryption_key`.
    fn derive(
        &self,
        decryption_key: &Self::DecryptionKey,
        compiler: &mut COM,
    ) -> Self::EncryptionKey;
}

impl<T, COM> Derive<COM> for &T
where
    T: Derive<COM>,
{
    #[inline]
    fn derive(
        &self,
        decryption_key: &Self::DecryptionKey,
        compiler: &mut COM,
    ) -> Self::EncryptionKey {
        (*self).derive(decryption_key, compiler)
    }
}

/// Encryption Types
///
/// This `trait` encapsulates all the types required for [`Encrypt::encrypt`].
pub trait EncryptionTypes:
    CiphertextType + EncryptionKeyType + HeaderType + PlaintextType + RandomnessType
{
}

impl<T> EncryptionTypes for T where
    T: CiphertextType + EncryptionKeyType + HeaderType + PlaintextType + RandomnessType
{
}

/// Encryption
pub trait Encrypt<COM = ()>: EncryptionTypes {
    /// Encrypts `plaintext` with the `encryption_key` and the one-time encryption `randomness`,
    /// including `header`, but not necessarily encrypting it.
    fn encrypt(
        &self,
        encryption_key: &Self::EncryptionKey,
        randomness: &Self::Randomness,
        header: &Self::Header,
        plaintext: &Self::Plaintext,
        compiler: &mut COM,
    ) -> Self::Ciphertext;

    /// Computes ciphertext using [`encrypt`](Self::encrypt) and stores the result in an
    /// [`EncryptedMessage`].
    #[inline]
    fn encrypt_into(
        &self,
        encryption_key: &Self::EncryptionKey,
        randomness: &Self::Randomness,
        header: Self::Header,
        plaintext: &Self::Plaintext,
        compiler: &mut COM,
    ) -> EncryptedMessage<Self> {
        EncryptedMessage {
            ciphertext: self.encrypt(encryption_key, randomness, &header, plaintext, compiler),
            header,
        }
    }
}

impl<T, COM> Encrypt<COM> for &T
where
    T: Encrypt<COM>,
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
        (*self).encrypt(encryption_key, randomness, header, plaintext, compiler)
    }
}

/// Decryption Types
///
/// This `trait` encapsulates all the types required for [`Decrypt::decrypt`].
pub trait DecryptionTypes:
    CiphertextType + DecryptedPlaintextType + DecryptionKeyType + HeaderType
{
}

impl<T> DecryptionTypes for T where
    T: CiphertextType + DecryptedPlaintextType + DecryptionKeyType + HeaderType
{
}

/// Decryption
pub trait Decrypt<COM = ()>: DecryptionTypes {
    /// Decrypts the `ciphertext` with `decryption_key`.
    fn decrypt(
        &self,
        decryption_key: &Self::DecryptionKey,
        header: &Self::Header,
        ciphertext: &Self::Ciphertext,
        compiler: &mut COM,
    ) -> Self::DecryptedPlaintext;
}

impl<T, COM> Decrypt<COM> for &T
where
    T: Decrypt<COM>,
{
    #[inline]
    fn decrypt(
        &self,
        decryption_key: &Self::DecryptionKey,
        header: &Self::Header,
        ciphertext: &Self::Ciphertext,
        compiler: &mut COM,
    ) -> Self::DecryptedPlaintext {
        (*self).decrypt(decryption_key, header, ciphertext, compiler)
    }
}

/// Empty Header
#[derive(derivative::Derivative)]
#[derivative(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EmptyHeader<COM = ()>(PhantomData<COM>);

impl<COM> Constant<COM> for EmptyHeader<COM> {
    type Type = EmptyHeader;

    #[inline]
    fn new_constant(this: &Self::Type, compiler: &mut COM) -> Self {
        let _ = (this, compiler);
        Self::default()
    }
}

impl<M, COM> Variable<M, COM> for EmptyHeader<COM> {
    type Type = EmptyHeader;

    #[inline]
    fn new_unknown(compiler: &mut COM) -> Self {
        let _ = compiler;
        Self::default()
    }

    #[inline]
    fn new_known(this: &Self::Type, compiler: &mut COM) -> Self {
        let _ = (this, compiler);
        Self::default()
    }
}

impl<COM> eclair::cmp::PartialEq<Self, COM> for EmptyHeader<COM>
where
    COM: Has<bool>,
    Bool<COM>: Constant<COM, Type = bool>,
{
    #[inline]
    fn eq(&self, rhs: &Self, compiler: &mut COM) -> Bool<COM> {
        let _ = rhs;
        Bool::<COM>::new_constant(&true, compiler)
    }

    #[inline]
    fn ne(&self, rhs: &Self, compiler: &mut COM) -> Bool<COM> {
        let _ = rhs;
        Bool::<COM>::new_constant(&false, compiler)
    }

    #[inline]
    fn assert_equal(&self, rhs: &Self, compiler: &mut COM) {
        let _ = (rhs, compiler);
    }
}

impl Encode for EmptyHeader {
    #[inline]
    fn encode<W>(&self, writer: W) -> Result<(), W::Error>
    where
        W: Write,
    {
        let _ = writer;
        Ok(())
    }
}

impl<P> Input<P> for EmptyHeader
where
    P: ProofSystem + ?Sized,
{
    #[inline]
    fn extend(&self, input: &mut P::Input) {
        let _ = input;
    }
}

/// Unsafe Empty Output
///
/// For protocols that need some unconstrained behavior in-circuit, we can use this
/// type to return from the computation.
#[derive(derivative::Derivative)]
#[derivative(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct UnsafeOutput<T, COM = ()>(PhantomData<(T, COM)>);

impl<T, COM> Constant<COM> for UnsafeOutput<T, COM> {
    type Type = T;

    #[inline]
    fn new_constant(this: &Self::Type, compiler: &mut COM) -> Self {
        let _ = (this, compiler);
        Self::default()
    }
}

impl<T, M, COM> Variable<M, COM> for UnsafeOutput<T, COM> {
    type Type = T;

    #[inline]
    fn new_unknown(compiler: &mut COM) -> Self {
        let _ = compiler;
        Self::default()
    }

    #[inline]
    fn new_known(this: &Self::Type, compiler: &mut COM) -> Self {
        let _ = (this, compiler);
        Self::default()
    }
}

impl<T, COM> eclair::cmp::PartialEq<Self, COM> for UnsafeOutput<T, COM>
where
    COM: Has<bool>,
    Bool<COM>: Constant<COM, Type = bool>,
{
    #[inline]
    fn eq(&self, rhs: &Self, compiler: &mut COM) -> Bool<COM> {
        let _ = rhs;
        Bool::<COM>::new_constant(&true, compiler)
    }

    #[inline]
    fn ne(&self, rhs: &Self, compiler: &mut COM) -> Bool<COM> {
        let _ = rhs;
        Bool::<COM>::new_constant(&false, compiler)
    }

    #[inline]
    fn assert_equal(&self, rhs: &Self, compiler: &mut COM) {
        let _ = (rhs, compiler);
    }
}

impl<T> Encode for UnsafeOutput<T> {
    #[inline]
    fn encode<W>(&self, writer: W) -> Result<(), W::Error>
    where
        W: Write,
    {
        let _ = writer;
        Ok(())
    }
}

impl<P, T> Input<P> for UnsafeOutput<T>
where
    P: ProofSystem + ?Sized,
{
    #[inline]
    fn extend(&self, input: &mut P::Input) {
        let _ = input;
    }
}

/// Empty Encryption Scheme returning [`UnsafeOutput`].
#[derive(derivative::Derivative)]
#[derivative(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct UnsafeNoEncrypt<E, COM = ()>(PhantomData<(E, COM)>);

impl<E, COM> Constant<COM> for UnsafeNoEncrypt<E, COM>
where
    E: Constant<COM>,
{
    type Type = E::Type;

    #[inline]
    fn new_constant(this: &Self::Type, compiler: &mut COM) -> Self {
        let _ = (this, compiler);
        Self::default()
    }
}

impl<E, COM> RandomnessType for UnsafeNoEncrypt<E, COM>
where
    E: RandomnessType,
{
    type Randomness = E::Randomness;
}

impl<E, COM> PlaintextType for UnsafeNoEncrypt<E, COM>
where
    E: PlaintextType,
{
    type Plaintext = E::Plaintext;
}

impl<E, COM> HeaderType for UnsafeNoEncrypt<E, COM>
where
    E: HeaderType,
{
    type Header = E::Header;
}

impl<E, COM> EncryptionKeyType for UnsafeNoEncrypt<E, COM>
where
    E: EncryptionKeyType,
{
    type EncryptionKey = E::EncryptionKey;
}

impl<E, COM> CiphertextType for UnsafeNoEncrypt<E, COM>
where
    E: CiphertextType,
{
    type Ciphertext = UnsafeOutput<E::Ciphertext, COM>;
}

impl<E, COM> Encrypt<COM> for UnsafeNoEncrypt<E, COM>
where
    E: EncryptionTypes,
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
        let _ = (encryption_key, randomness, header, plaintext, compiler);
        UnsafeOutput::default()
    }
}

/// Message
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "openzl_util::serde", deny_unknown_fields)
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "E::Header: Clone, E::Plaintext: Clone"),
    Copy(bound = "E::Header: Copy, E::Plaintext: Copy"),
    Debug(bound = "E::Header: Debug, E::Plaintext: Debug"),
    Default(bound = "E::Header: Default, E::Plaintext: Default"),
    Eq(bound = "E::Header: Eq, E::Plaintext: Eq"),
    Hash(bound = "E::Header: Hash, E::Plaintext: Hash"),
    PartialEq(bound = "E::Header: PartialEq, E::Plaintext: PartialEq")
)]
pub struct Message<E>
where
    E: HeaderType + PlaintextType,
{
    /// Header
    pub header: E::Header,

    /// Plaintext
    pub plaintext: E::Plaintext,
}

impl<E> Message<E>
where
    E: HeaderType + PlaintextType,
{
    /// Builds a new [`Message`] from `header` and `plaintext`.
    #[inline]
    pub fn new(header: E::Header, plaintext: E::Plaintext) -> Self {
        Self { header, plaintext }
    }

    /// Encrypts `self` against the given `cipher` using `key` and `randomness`.
    #[inline]
    pub fn encrypt<COM>(
        self,
        cipher: &E,
        key: &E::EncryptionKey,
        randomness: &E::Randomness,
        compiler: &mut COM,
    ) -> EncryptedMessage<E>
    where
        E: Encrypt<COM>,
    {
        cipher.encrypt_into(key, randomness, self.header, &self.plaintext, compiler)
    }
}

impl<E, H, P> Sample<(H, P)> for Message<E>
where
    E: HeaderType + PlaintextType,
    E::Header: Sample<H>,
    E::Plaintext: Sample<P>,
{
    #[inline]
    fn sample<R>(distribution: (H, P), rng: &mut R) -> Self
    where
        R: RngCore + ?Sized,
    {
        Self::new(rng.sample(distribution.0), rng.sample(distribution.1))
    }
}

impl<E, H, P, COM> Variable<Derived<(H, P)>, COM> for Message<E>
where
    E: HeaderType + PlaintextType + Constant<COM>,
    E::Header: Variable<H, COM>,
    E::Plaintext: Variable<P, COM>,
    E::Type: HeaderType<Header = Var<E::Header, H, COM>>
        + PlaintextType<Plaintext = Var<E::Plaintext, P, COM>>,
{
    type Type = Message<E::Type>;

    #[inline]
    fn new_unknown(compiler: &mut COM) -> Self {
        Self::new(compiler.allocate_unknown(), compiler.allocate_unknown())
    }

    #[inline]
    fn new_known(this: &Self::Type, compiler: &mut COM) -> Self {
        Self::new(
            this.header.as_known(compiler),
            this.plaintext.as_known(compiler),
        )
    }
}

/// Encrypted Message
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "openzl_util::serde", deny_unknown_fields)
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "E::Header: Clone, E::Ciphertext: Clone"),
    Copy(bound = "E::Header: Copy, E::Ciphertext: Copy"),
    Debug(bound = "E::Header: Debug, E::Ciphertext: Debug"),
    Default(bound = "E::Header: Default, E::Ciphertext: Default"),
    Hash(bound = "E::Header: Hash, E::Ciphertext: Hash")
)]
pub struct EncryptedMessage<E>
where
    E: CiphertextType + HeaderType + ?Sized,
{
    /// Header
    pub header: E::Header,

    /// Ciphertext
    pub ciphertext: E::Ciphertext,
}

impl<E> EncryptedMessage<E>
where
    E: CiphertextType + HeaderType + ?Sized,
{
    /// Builds a new [`EncryptedMessage`] from `header` and `ciphertext`.
    #[inline]
    pub fn new(header: E::Header, ciphertext: E::Ciphertext) -> Self {
        Self { header, ciphertext }
    }

    /// Decrypts `self` against the given `cipher` using `key`.
    #[inline]
    pub fn decrypt<COM>(
        &self,
        cipher: &E,
        key: &E::DecryptionKey,
        compiler: &mut COM,
    ) -> E::DecryptedPlaintext
    where
        E: Decrypt<COM>,
    {
        cipher.decrypt(key, &self.header, &self.ciphertext, compiler)
    }

    /// Converts the [`EncryptedMessage`] into the new cipher `F` converting the ciphertext and
    /// header.
    #[inline]
    pub fn into<F>(self) -> EncryptedMessage<F>
    where
        F: CiphertextType + HeaderType + ?Sized,
        E::Ciphertext: Into<F::Ciphertext>,
        E::Header: Into<F::Header>,
    {
        EncryptedMessage::new(self.header.into(), self.ciphertext.into())
    }
}

impl<E, COM> eclair::cmp::PartialEq<Self, COM> for EncryptedMessage<E>
where
    E: CiphertextType + HeaderType + ?Sized,
    COM: Has<bool>,
    Bool<COM>: BitAnd<Bool<COM>, COM, Output = Bool<COM>>,
    E::Ciphertext: eclair::cmp::PartialEq<E::Ciphertext, COM>,
    E::Header: eclair::cmp::PartialEq<E::Header, COM>,
{
    #[inline]
    fn eq(&self, rhs: &Self, compiler: &mut COM) -> Bool<COM> {
        self.header
            .eq(&rhs.header, compiler)
            .bitand(self.ciphertext.eq(&rhs.ciphertext, compiler), compiler)
    }

    #[inline]
    fn assert_equal(&self, rhs: &Self, compiler: &mut COM)
    where
        COM: Assert,
    {
        compiler.assert_eq(&self.header, &rhs.header);
        compiler.assert_eq(&self.ciphertext, &rhs.ciphertext);
    }
}

impl<E, COM> eclair::cmp::Eq<COM> for EncryptedMessage<E>
where
    E: CiphertextType + HeaderType + ?Sized,
    COM: Has<bool>,
    Bool<COM>: BitAnd<Bool<COM>, COM, Output = Bool<COM>>,
    E::Ciphertext: eclair::cmp::Eq<COM>,
    E::Header: eclair::cmp::Eq<COM>,
{
}

impl<E, H, C, COM> Variable<Derived<(H, C)>, COM> for EncryptedMessage<E>
where
    E: CiphertextType + HeaderType + Constant<COM>,
    E::Header: Variable<H, COM>,
    E::Ciphertext: Variable<C, COM>,
    E::Type: CiphertextType<Ciphertext = Var<E::Ciphertext, C, COM>>
        + HeaderType<Header = Var<E::Header, H, COM>>,
{
    type Type = EncryptedMessage<E::Type>;

    #[inline]
    fn new_unknown(compiler: &mut COM) -> Self {
        Self::new(compiler.allocate_unknown(), compiler.allocate_unknown())
    }

    #[inline]
    fn new_known(this: &Self::Type, compiler: &mut COM) -> Self {
        Self::new(
            this.header.as_known(compiler),
            this.ciphertext.as_known(compiler),
        )
    }
}

impl<E, COM> Variable<Public, COM> for EncryptedMessage<E>
where
    E: CiphertextType + HeaderType + Constant<COM>,
    E::Header: Variable<Public, COM>,
    E::Ciphertext: Variable<Public, COM>,
    E::Type: CiphertextType<Ciphertext = Var<E::Ciphertext, Public, COM>>
        + HeaderType<Header = Var<E::Header, Public, COM>>,
{
    type Type = EncryptedMessage<E::Type>;

    #[inline]
    fn new_unknown(compiler: &mut COM) -> Self {
        Variable::<Derived<(Public, Public)>, _>::new_unknown(compiler)
    }

    #[inline]
    fn new_known(this: &Self::Type, compiler: &mut COM) -> Self {
        Variable::<Derived<(Public, Public)>, _>::new_known(this, compiler)
    }
}

impl<E, H, C> Sample<(H, C)> for EncryptedMessage<E>
where
    E: CiphertextType + HeaderType,
    E::Header: Sample<H>,
    E::Ciphertext: Sample<C>,
{
    #[inline]
    fn sample<R>(distribution: (H, C), rng: &mut R) -> Self
    where
        R: RngCore + ?Sized,
    {
        Self::new(rng.sample(distribution.0), rng.sample(distribution.1))
    }
}

impl<E> Encode for EncryptedMessage<E>
where
    E: CiphertextType + HeaderType,
    E::Header: Encode,
    E::Ciphertext: Encode,
{
    #[inline]
    fn encode<W>(&self, mut writer: W) -> Result<(), W::Error>
    where
        W: Write,
    {
        self.header.encode(&mut writer)?;
        self.ciphertext.encode(&mut writer)?;
        Ok(())
    }
}

impl<E, P> Input<P> for EncryptedMessage<E>
where
    E: CiphertextType + HeaderType,
    P: HasInput<E::Header> + HasInput<E::Ciphertext> + ?Sized,
{
    #[inline]
    fn extend(&self, input: &mut P::Input) {
        P::extend(input, &self.header);
        P::extend(input, &self.ciphertext);
    }
}

/// Testing Framework
#[cfg(feature = "test")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "test")))]
pub mod test {
    use super::*;

    /// Tests if encryption of `plaintext` using `encryption_key` and `randomness` returns the
    /// original `plaintext` on decryption using `decryption_key`. The `assert_same` function is
    /// used to assert that the two plaintexts are the same.
    #[inline]
    pub fn correctness<E, F>(
        cipher: &E,
        encryption_key: &E::EncryptionKey,
        decryption_key: &E::DecryptionKey,
        randomness: &E::Randomness,
        header: &E::Header,
        plaintext: &E::Plaintext,
        assert_same: F,
    ) where
        E: Decrypt + Encrypt,
        F: FnOnce(&E::Plaintext, &E::DecryptedPlaintext),
    {
        assert_same(
            plaintext,
            &cipher.decrypt(
                decryption_key,
                header,
                &cipher.encrypt(encryption_key, randomness, header, plaintext, &mut ()),
                &mut (),
            ),
        )
    }

    /// Derives an [`EncryptionKey`](EncryptionKeyType::EncryptionKey) from `decryption_key` and
    /// then runs the [`correctness`] assertion test.
    #[inline]
    pub fn correctness_with_derive<E, F>(
        cipher: &E,
        decryption_key: &E::DecryptionKey,
        randomness: &E::Randomness,
        header: &E::Header,
        plaintext: &E::Plaintext,
        assert_same: F,
    ) where
        E: Decrypt + Derive + Encrypt,
        F: FnOnce(&E::Plaintext, &E::DecryptedPlaintext),
    {
        correctness(
            cipher,
            &cipher.derive(decryption_key, &mut ()),
            decryption_key,
            randomness,
            header,
            plaintext,
            assert_same,
        )
    }
}
