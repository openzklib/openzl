//! Key Agreement Schemes

use crate::component;

/// Secret Key
#[component]
pub type SecretKey;

/// Ephemeral Secret Key
#[component]
pub type EphemeralSecretKey;

/// Public Key
#[component]
pub type PublicKey;

/// Ephemeral Public Key
#[component]
pub type EphemeralPublicKey;

/// Shared Secret
#[component]
pub type SharedSecret;

/// Public Key Derivation
pub trait Derive<COM = ()>: PublicKeyType + SecretKeyType {
    /// Derives a [`PublicKey`](PublicKeyType::PublicKey) from `secret_key`.
    fn derive(&self, secret_key: &Self::SecretKey, compiler: &mut COM) -> Self::PublicKey;
}

impl<K, COM> Derive<COM> for &K
where
    K: Derive<COM>,
{
    #[inline]
    fn derive(&self, secret_key: &Self::SecretKey, compiler: &mut COM) -> Self::PublicKey {
        (*self).derive(secret_key, compiler)
    }
}

/// Ephemeral Public Key Derivation
pub trait DeriveEphemeral<COM = ()>: EphemeralPublicKeyType + EphemeralSecretKeyType {
    /// Derives a [`EphemeralPublicKey`](EphemeralPublicKeyType::EphemeralPublicKey) from
    /// `ephemeral_secret_key`.
    fn derive_ephemeral(
        &self,
        ephemeral_secret_key: &Self::EphemeralSecretKey,
        compiler: &mut COM,
    ) -> Self::EphemeralPublicKey;
}

impl<K, COM> DeriveEphemeral<COM> for &K
where
    K: DeriveEphemeral<COM>,
{
    #[inline]
    fn derive_ephemeral(
        &self,
        ephemeral_secret_key: &Self::EphemeralSecretKey,
        compiler: &mut COM,
    ) -> Self::EphemeralPublicKey {
        (*self).derive_ephemeral(ephemeral_secret_key, compiler)
    }
}

/// Key Agreement Secret Generation
pub trait GenerateSecret<COM = ()>:
    EphemeralSecretKeyType + PublicKeyType + SharedSecretType
{
    /// Performs the agreement protocol on `public_key` and `ephemeral_secret_key` to arrive at the
    /// [`SharedSecret`](SharedSecretType::SharedSecret).
    fn generate_secret(
        &self,
        public_key: &Self::PublicKey,
        ephemeral_secret_key: &Self::EphemeralSecretKey,
        compiler: &mut COM,
    ) -> Self::SharedSecret;
}

impl<K, COM> GenerateSecret<COM> for &K
where
    K: GenerateSecret<COM>,
{
    #[inline]
    fn generate_secret(
        &self,
        public_key: &Self::PublicKey,
        ephemeral_secret_key: &Self::EphemeralSecretKey,
        compiler: &mut COM,
    ) -> Self::SharedSecret {
        (*self).generate_secret(public_key, ephemeral_secret_key, compiler)
    }
}

/// Key Agreement
pub trait Agree<COM = ()>: PublicKeyType + SecretKeyType + SharedSecretType {
    /// Performs the agreement protocol on `public_key` and `secret_key` to arrive at the
    /// [`SharedSecret`](SharedSecretType::SharedSecret).
    fn agree(
        &self,
        public_key: &Self::PublicKey,
        secret_key: &Self::SecretKey,
        compiler: &mut COM,
    ) -> Self::SharedSecret;
}

impl<K, COM> Agree<COM> for &K
where
    K: Agree<COM>,
{
    #[inline]
    fn agree(
        &self,
        public_key: &Self::PublicKey,
        secret_key: &Self::SecretKey,
        compiler: &mut COM,
    ) -> Self::SharedSecret {
        (*self).agree(public_key, secret_key, compiler)
    }
}

/// Key Agreement Secret Reconstruction
pub trait ReconstructSecret<COM = ()>:
    EphemeralPublicKeyType + SecretKeyType + SharedSecretType
{
    /// Performs the agreement protocol on `ephemeral_public_key` and `secret_key` to arrive at the
    /// [`SharedSecret`](SharedSecretType::SharedSecret).
    fn reconstruct_secret(
        &self,
        ephemeral_public_key: &Self::EphemeralPublicKey,
        secret_key: &Self::SecretKey,
        compiler: &mut COM,
    ) -> Self::SharedSecret;
}

impl<K, COM> ReconstructSecret<COM> for &K
where
    K: ReconstructSecret<COM>,
{
    #[inline]
    fn reconstruct_secret(
        &self,
        ephemeral_public_key: &Self::EphemeralPublicKey,
        secret_key: &Self::SecretKey,
        compiler: &mut COM,
    ) -> Self::SharedSecret {
        (*self).reconstruct_secret(ephemeral_public_key, secret_key, compiler)
    }
}

/// Testing Framework
#[cfg(feature = "test")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "test")))]
pub mod test {
    use super::*;
    use eclair::{
        bool::{Assert, AssertEq},
        cmp::PartialEq,
    };

    /// Tests if the `agreement` property is satisfied for `K`.
    #[inline]
    pub fn agreement<K, COM>(scheme: &K, lhs: &K::SecretKey, rhs: &K::SecretKey, compiler: &mut COM)
    where
        COM: Assert,
        K: Agree<COM> + Derive<COM>,
        K::SharedSecret: PartialEq<K::SharedSecret, COM>,
    {
        let fst = scheme.agree(&scheme.derive(rhs, compiler), lhs, compiler);
        let snd = scheme.agree(&scheme.derive(lhs, compiler), rhs, compiler);
        compiler.assert_eq(&fst, &snd);
    }

    /// Tests if the `agreement` property with ephemeral keys is satisfied for `K`.
    #[inline]
    pub fn agreement_ephemeral<K, COM>(
        scheme: &K,
        secret_key: &K::SecretKey,
        ephemeral_secret_key: &K::EphemeralSecretKey,
        compiler: &mut COM,
    ) where
        COM: Assert,
        K: Derive<COM> + DeriveEphemeral<COM> + GenerateSecret<COM> + ReconstructSecret<COM>,
        K::SharedSecret: PartialEq<K::SharedSecret, COM>,
    {
        let public_key = scheme.derive(secret_key, compiler);
        let ephemeral_public_key = scheme.derive_ephemeral(ephemeral_secret_key, compiler);
        let generated_secret = scheme.generate_secret(&public_key, ephemeral_secret_key, compiler);
        let reconstructed_secret =
            scheme.reconstruct_secret(&ephemeral_public_key, secret_key, compiler);
        compiler.assert_eq(&generated_secret, &reconstructed_secret);
    }
}
