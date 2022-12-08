// Copyright 2019-2022 Manta Network.
// This file is part of manta-rs.
//
// manta-rs is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// manta-rs is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with manta-rs.  If not, see <http://www.gnu.org/licenses/>.

//! Field Element Wrapper

use crate::ff::{Field, FpParameters, PrimeField, ToConstraintField};
use alloc::vec::Vec;
use core::iter;
use eclair::{
    self,
    bool::{Bool, ConditionalSelect},
};
use openzl_crypto::{
    algebra::{Group, Ring},
    constraint::{Input, ProofSystem},
};
use openzl_util::{
    byte_count,
    rand::{RngCore, Sample},
    SizeLimit,
};

#[cfg(feature = "serde")]
use {
    crate::serialize::{ArkReader, ArkWriter, SerializationError},
    openzl_util::codec::{Decode, DecodeError, Encode, Read, Write},
    openzl_util::serde::{Deserialize, Serialize, Serializer},
};

/// Field Element
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(
        bound(deserialize = "", serialize = ""),
        crate = "openzl_util::serde",
        deny_unknown_fields,
        try_from = "Vec<u8>"
    )
)]
#[derive(derivative::Derivative)]
#[derivative(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Fp<F>(
    /// Field Element
    #[cfg_attr(
        feature = "serde",
        serde(serialize_with = "serialize_field_element::<F, _>")
    )]
    pub F,
)
where
    F: Field;

impl<F> From<u128> for Fp<F>
where
    F: Field,
{
    #[inline]
    fn from(value: u128) -> Self {
        Self(value.into())
    }
}

impl<F> ToConstraintField<F> for Fp<F>
where
    F: PrimeField,
{
    #[inline]
    fn to_field_elements(&self) -> Option<Vec<F>> {
        self.0.to_field_elements()
    }
}

impl<F, P> Input<P> for Fp<F>
where
    F: Field,
    P: ProofSystem + ?Sized,
    P::Input: Extend<F>,
{
    #[inline]
    fn extend(&self, input: &mut P::Input) {
        input.extend(iter::once(self.0))
    }
}

#[cfg(feature = "serde")]
impl<F> Decode for Fp<F>
where
    F: Field,
{
    type Error = SerializationError;

    #[inline]
    fn decode<R>(reader: R) -> Result<Self, DecodeError<R::Error, Self::Error>>
    where
        R: Read,
    {
        let mut reader = ArkReader::new(reader);
        match F::deserialize(&mut reader) {
            Ok(value) => reader
                .finish()
                .map(move |_| Self(value))
                .map_err(DecodeError::Read),
            Err(err) => Err(DecodeError::Decode(err)),
        }
    }
}

#[cfg(feature = "serde")]
impl<F> Encode for Fp<F>
where
    F: Field,
{
    #[inline]
    fn encode<W>(&self, writer: W) -> Result<(), W::Error>
    where
        W: Write,
    {
        let mut writer = ArkWriter::new(writer);
        let _ = self.0.serialize(&mut writer);
        writer.finish().map(move |_| ())
    }
}

impl<F> eclair::cmp::PartialEq<Self> for Fp<F>
where
    F: Field,
{
    #[inline]
    fn eq(&self, rhs: &Self, _: &mut ()) -> bool {
        PartialEq::eq(self, rhs)
    }
}

impl<F> eclair::num::Zero for Fp<F>
where
    F: Field,
{
    type Verification = bool;

    #[inline]
    fn zero(_: &mut ()) -> Self {
        Self(F::zero())
    }

    #[inline]
    fn is_zero(&self, _: &mut ()) -> Self::Verification {
        self.0.is_zero()
    }
}

impl<F> eclair::num::One for Fp<F>
where
    F: Field,
{
    type Verification = bool;

    #[inline]
    fn one(_: &mut ()) -> Self {
        Self(F::one())
    }

    #[inline]
    fn is_one(&self, _: &mut ()) -> Self::Verification {
        self.0.is_one()
    }
}

impl<F> ConditionalSelect for Fp<F>
where
    F: Field,
{
    #[inline]
    fn select(bit: &Bool, true_value: &Self, false_value: &Self, _: &mut ()) -> Self {
        if *bit {
            *true_value
        } else {
            *false_value
        }
    }
}

impl<F> Sample for Fp<F>
where
    F: Field,
{
    #[inline]
    fn sample<R>(_: (), rng: &mut R) -> Self
    where
        R: RngCore + ?Sized,
    {
        Self(F::rand(rng))
    }
}

impl<F> Group for Fp<F>
where
    F: Field,
{
    #[inline]
    fn add(&self, rhs: &Self, _: &mut ()) -> Self {
        Self(self.0 + rhs.0)
    }
}

impl<F> Ring for Fp<F>
where
    F: Field,
{
    #[inline]
    fn mul(&self, rhs: &Self, _: &mut ()) -> Self {
        Self(self.0 * rhs.0)
    }
}

impl<F> SizeLimit for Fp<F>
where
    F: PrimeField,
{
    const SIZE: usize = byte_count(<F::Params as FpParameters>::MODULUS_BITS) as usize;
}

#[cfg(feature = "serde")]
impl<F> TryFrom<Vec<u8>> for Fp<F>
where
    F: Field,
{
    type Error = SerializationError;

    #[inline]
    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        Self::from_vec(bytes)
    }
}

/// Converts `element` into its canonical byte-representation.
#[cfg(feature = "serde")]
#[inline]
pub fn field_element_as_bytes<F>(element: &F) -> Vec<u8>
where
    F: Field,
{
    Fp(*element).to_vec()
}

/// Uses `serializer` to serialize `element`.
#[cfg(feature = "serde")]
#[inline]
fn serialize_field_element<F, S>(element: &F, serializer: S) -> Result<S::Ok, S::Error>
where
    F: Field,
    S: Serializer,
{
    serializer.serialize_bytes(&field_element_as_bytes(element))
}
