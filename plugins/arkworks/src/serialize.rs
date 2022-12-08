//! Arkworks Canonical Serialize and Deserialize Backend

use ark_std::io::{self, Error, ErrorKind};
use openzl_util::codec::{self, ReadExactError};

#[cfg(feature = "serde")]
use {
    alloc::vec::Vec,
    openzl_util::serde::{de, ser, Deserialize, Deserializer, Serialize, Serializer},
};

#[doc(inline)]
pub use ark_serialize::*;

/// Serialization Hook
pub trait HasSerialization<'s>: 's {
    /// Serialize Type
    type Serialize: CanonicalSerialize + From<&'s Self>;
}

/// Deserialization Hook
pub trait HasDeserialization: Sized {
    /// Deserialize Type
    type Deserialize: CanonicalDeserialize + Into<Self>;
}

/// Arkworks Reader
pub struct ArkReader<R>
where
    R: codec::Read,
{
    /// Reader State
    state: Result<R, R::Error>,
}

impl<R> ArkReader<R>
where
    R: codec::Read,
{
    /// Builds a new [`ArkReader`] from `reader`.
    #[inline]
    pub fn new(reader: R) -> Self {
        Self { state: Ok(reader) }
    }

    /// Updates the internal reader state by performing the `f` computation.
    #[inline]
    fn update<T, F>(&mut self, f: F) -> Option<T>
    where
        F: FnOnce(&mut R) -> Result<T, R::Error>,
    {
        if let Ok(reader) = self.state.as_mut() {
            match f(reader) {
                Ok(value) => return Some(value),
                Err(err) => self.state = Err(err),
            }
        }
        None
    }

    /// Returns the reader state back or an error if it occured during any [`Read`](io::Read)
    /// methods.
    #[inline]
    pub fn finish(self) -> Result<R, R::Error> {
        self.state
    }
}

impl<R> io::Read for ArkReader<R>
where
    R: codec::Read,
{
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        self.update(|reader| reader.read(buf))
            .ok_or_else(|| Error::new(ErrorKind::Other, "Reading Error"))
    }

    #[inline]
    fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), Error> {
        match self.update(|reader| match reader.read_exact(buf) {
            Ok(value) => Ok(Ok(value)),
            Err(ReadExactError::Read(err)) => Err(err),
            Err(ReadExactError::UnexpectedEnd(err)) => Ok(Err(err)),
        }) {
            Some(Ok(_)) => Ok(()),
            Some(Err(_)) => Err(Error::new(
                ErrorKind::UnexpectedEof,
                "Unexpected end of buffer.",
            )),
            _ => Err(Error::new(ErrorKind::Other, "Reading Error")),
        }
    }
}

/// Arkworks Writer
pub struct ArkWriter<W>
where
    W: codec::Write,
{
    /// Writer State
    state: Result<W, W::Error>,
}

impl<W> ArkWriter<W>
where
    W: codec::Write,
{
    /// Builds a new [`ArkWriter`] from `writer`.
    #[inline]
    pub fn new(writer: W) -> Self {
        Self { state: Ok(writer) }
    }

    /// Updates the internal writer state by performing the `f` computation.
    #[inline]
    fn update<T, F>(&mut self, f: F) -> Option<T>
    where
        F: FnOnce(&mut W) -> Result<T, W::Error>,
    {
        if let Ok(writer) = self.state.as_mut() {
            match f(writer) {
                Ok(value) => return Some(value),
                Err(err) => self.state = Err(err),
            }
        }
        None
    }

    /// Returns the writer state back or an error if it occured during any [`Write`](io::Write)
    /// methods.
    #[inline]
    pub fn finish(self) -> Result<W, W::Error> {
        self.state
    }
}

impl<W> io::Write for ArkWriter<W>
where
    W: codec::Write,
{
    #[inline]
    fn write(&mut self, mut buf: &[u8]) -> Result<usize, Error> {
        self.update(|writer| writer.write(&mut buf))
            .ok_or_else(|| Error::new(ErrorKind::Other, "Writing Error"))
    }

    #[inline]
    fn flush(&mut self) -> Result<(), Error> {
        // NOTE: We can't necessarily do better than this for now, unfortunately.
        Ok(())
    }

    #[inline]
    fn write_all(&mut self, mut buf: &[u8]) -> Result<(), Error> {
        self.update(|writer| writer.write(&mut buf))
            .map(|_| ())
            .ok_or_else(|| Error::new(ErrorKind::Other, "Writing Error"))
    }
}

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
