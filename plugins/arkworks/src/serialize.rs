//! Arkworks Canonical Serialization and Deserialization

#[cfg(feature = "serde")]
use {
    alloc::vec::Vec,
    openzl_util::serde::{de, ser, Deserialize, Deserializer, Serialize, Serializer},
};

#[doc(inline)]
pub use ark_serialize::*;

/// Serializes `data` using the [`CanonicalSerialize`] format with `S` as the [`Serializer`].
#[cfg(feature = "serde")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "serde")))]
#[inline]
pub fn canonical_serialize<T, S>(data: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    T: CanonicalSerialize,
    S: Serializer,
{
    let mut bytes = Vec::new();
    data.serialize(&mut bytes).map_err(ser::Error::custom)?;
    Serialize::serialize(&bytes, serializer)
}

/// Serializes `data` using the [`CanonicalSerialize`] format with `S` as the [`Serializer`] in uncompressed form.
#[cfg(feature = "serde")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "serde")))]
#[inline]
pub fn canonical_serialize_uncompressed<T, S>(data: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    T: CanonicalSerialize,
    S: Serializer,
{
    let mut bytes = Vec::new();
    data.serialize_uncompressed(&mut bytes)
        .map_err(ser::Error::custom)?;
    Serialize::serialize(&bytes, serializer)
}

/// Deserializes data of type `T` using the [`CanonicalDeserialize`] format with `D` as the
/// [`Deserializer`].
#[cfg(feature = "serde")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "serde")))]
#[inline]
pub fn canonical_deserialize<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: CanonicalDeserialize,
{
    let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
    CanonicalDeserialize::deserialize(bytes.as_slice()).map_err(de::Error::custom)
}

/// Deserializes data of type `T` using the [`CanonicalDeserialize`] format with `D` as the
/// [`Deserializer`] without checking for correctness.
#[cfg(feature = "serde")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "serde")))]
#[inline]
pub fn canonical_deserialize_unchecked<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: CanonicalDeserialize,
{
    let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
    CanonicalDeserialize::deserialize_unchecked(bytes.as_slice()).map_err(de::Error::custom)
}
