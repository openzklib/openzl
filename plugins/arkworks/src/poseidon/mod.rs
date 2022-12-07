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

//! Poseidon Arkworks Backend

use crate::{
    constraint::{fp::Fp, FpVar, R1CS},
    ff::{BigInteger, FpParameters, PrimeField},
};
use eclair::alloc::Constant;
use openzl_crypto::poseidon::{
    encryption::BlockElement, hash::DomainTag, Constants, NativeField, FieldGeneration,
    ParameterFieldType,
};

#[cfg(feature = "ark-bn254")]
pub mod config;

#[cfg(test)]
pub mod test;

/// Compiler Type.
type Compiler<S> = R1CS<<S as Specification>::Field>;

/// Poseidon Permutation Specification.
pub trait Specification: Constants {
    /// Field Type
    type Field: PrimeField;

    /// S-BOX Exponenet
    const SBOX_EXPONENT: u64;
}

impl<F> NativeField for Fp<F>
where
    F: PrimeField,
{
    #[inline]
    fn zero() -> Self {
        Self(F::zero())
    }

    #[inline]
    fn is_zero(&self) -> bool {
        self.0 == F::zero()
    }

    #[inline]
    fn one() -> Self {
        Self(F::one())
    }

    #[inline]
    fn add(&self, rhs: &Self) -> Self {
        Self(self.0 + rhs.0)
    }

    #[inline]
    fn add_assign(&mut self, rhs: &Self) {
        self.0 += rhs.0;
    }

    #[inline]
    fn sub(&self, rhs: &Self) -> Self {
        Self(self.0 - rhs.0)
    }

    #[inline]
    fn mul(&self, rhs: &Self) -> Self {
        Self(self.0 * rhs.0)
    }

    #[inline]
    fn inverse(&self) -> Option<Self> {
        self.0.inverse().map(Self)
    }
}

impl<F> FieldGeneration for Fp<F>
where
    F: PrimeField,
{
    const MODULUS_BITS: usize = F::Params::MODULUS_BITS as usize;

    #[inline]
    fn try_from_bits_be(bits: &[bool]) -> Option<Self> {
        F::from_repr(F::BigInt::from_bits_be(bits)).map(Self)
    }

    #[inline]
    fn from_u64(elem: u64) -> Self {
        Self(F::from(elem))
    }
}

impl<F> BlockElement for Fp<F>
where
    F: PrimeField,
{
    #[inline]
    fn add(&self, rhs: &Self, _: &mut ()) -> Self {
        Self(self.0 + rhs.0)
    }

    #[inline]
    fn sub(&self, rhs: &Self, _: &mut ()) -> Self {
        Self(self.0 - rhs.0)
    }
}

impl<F> BlockElement<R1CS<F>> for FpVar<F>
where
    F: PrimeField,
{
    #[inline]
    fn add(&self, rhs: &Self, _: &mut R1CS<F>) -> Self {
        self + rhs
    }

    #[inline]
    fn sub(&self, rhs: &Self, _: &mut R1CS<F>) -> Self {
        self - rhs
    }
}

/// Domain tag as 2^arity - 1
pub struct TwoPowerMinusOneDomainTag;

impl<COM> Constant<COM> for TwoPowerMinusOneDomainTag {
    type Type = Self;

    #[inline]
    fn new_constant(this: &Self::Type, compiler: &mut COM) -> Self {
        let _ = (this, compiler);
        Self
    }
}

impl<S> DomainTag<S> for TwoPowerMinusOneDomainTag
where
    S: Specification + ParameterFieldType<ParameterField = Fp<S::Field>>,
{
    #[inline]
    fn domain_tag() -> Fp<<S as Specification>::Field> {
        Fp(S::Field::from(((1 << (S::WIDTH - 1)) - 1) as u128))
    }
}
