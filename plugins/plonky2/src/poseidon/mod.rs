//! Poseidon Plonky2 Backend

use crate::{
    base::{field::goldilocks_field::GoldilocksField, util::bits_u64},
    compiler::Compiler as PlonkCompiler,
    field::{Extendable, Field, Fp, RichField},
};
use alloc::vec::Vec;
use core::marker::PhantomData;
use eclair::{
    alloc::Constant,
    ops::{Add, Mul, Sub},
};
use num_bigint::BigUint;
use openzl_crypto::poseidon::{
    self, encryption::BlockElement, hash::DomainTag, Constants, FieldGeneration, NativeField,
    ParameterFieldType, SBoxExponent,
};
use openzl_util::derivative;
use plonky2::field::types::Field as _;

/// Compiler Type.
type Compiler<S, const D: usize> = PlonkCompiler<<S as Specification>::Field, D>;

/// Poseidon Permutation Specification.
pub trait Specification: Constants + SBoxExponent {
    /// Field Type
    type Field: RichField;
}

impl<F> NativeField for Fp<F>
where
    F: RichField,
{
    #[inline]
    fn zero() -> Self {
        Self(F::ZERO)
    }

    #[inline]
    fn is_zero(&self) -> bool {
        self.0 == F::ZERO
    }

    #[inline]
    fn one() -> Self {
        Self(F::ONE)
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
        self.0.try_inverse().map(Self)
    }
}

impl<F> FieldGeneration for Fp<F>
where
    F: RichField,
{
    const MODULUS_BITS: usize = F::BITS;

    #[inline]
    fn try_from_bits_be(bits: &[bool]) -> Option<Self> {
        let mut bytes = Vec::new();
        let mut acc: u8 = 0;
        let mut bits = bits.to_vec();
        bits.reverse();
        for bits8 in bits.chunks(8) {
            for bit in bits8.iter().rev() {
                acc <<= 1;
                acc += *bit as u8;
            }
            bytes.push(acc);
            acc = 0;
        }
        Some(Self(F::from_noncanonical_biguint(BigUint::from_bytes_be(
            &bytes,
        ))))
    }

    #[inline]
    fn from_u32(elem: u32) -> Self {
        Self(F::from_canonical_u32(elem))
    }
}

impl<F> BlockElement for Fp<F>
where
    F: RichField,
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

impl<F, const D: usize> BlockElement<PlonkCompiler<F, D>> for Field<F, D>
where
    F: RichField + Extendable<D>,
{
    #[inline]
    fn add(&self, rhs: &Self, compiler: &mut PlonkCompiler<F, D>) -> Self {
        Add::add(*self, *rhs, compiler)
    }

    #[inline]
    fn sub(&self, rhs: &Self, compiler: &mut PlonkCompiler<F, D>) -> Self {
        Sub::sub(*self, *rhs, compiler)
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
    S::Field: From<u32>,
{
    #[inline]
    fn domain_tag() -> Fp<<S as Specification>::Field> {
        Fp(S::Field::from(((1 << (S::WIDTH - 1)) - 1) as u32))
    }
}

/// Poseidon Specification Configuration
#[derive(derivative::Derivative)]
#[derivative(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Spec<F, const D: usize, const ARITY: usize>(PhantomData<F>);

impl<F, const D: usize, const ARITY: usize> Specification for Spec<F, D, ARITY>
where
    F: RichField + Extendable<D>,
    Self: poseidon::Constants + SBoxExponent,
{
    type Field = F;
}

impl<F, const D: usize, const ARITY: usize, COM> Constant<COM> for Spec<F, D, ARITY>
where
    F: RichField + Extendable<D>,
{
    type Type = Self;

    #[inline]
    fn new_constant(this: &Self::Type, compiler: &mut COM) -> Self {
        let _ = (this, compiler);
        Self(PhantomData)
    }
}

impl<F, const D: usize, const ARITY: usize> ParameterFieldType for Spec<F, D, ARITY>
where
    Self: Specification,
    F: RichField + Extendable<D>,
{
    type ParameterField = Fp<<Self as Specification>::Field>;
}

impl<F, const D: usize, const ARITY: usize> poseidon::Field for Spec<F, D, ARITY>
where
    Self: Specification,
    F: RichField + Extendable<D>,
{
    type Field = Fp<<Self as Specification>::Field>;

    #[inline]
    fn add(lhs: &Self::Field, rhs: &Self::Field, _: &mut ()) -> Self::Field {
        Fp(lhs.0 + rhs.0)
    }

    #[inline]
    fn add_const(lhs: &Self::Field, rhs: &Self::ParameterField, _: &mut ()) -> Self::Field {
        Fp(lhs.0 + rhs.0)
    }

    #[inline]
    fn mul(lhs: &Self::Field, rhs: &Self::Field, _: &mut ()) -> Self::Field {
        Fp(lhs.0 * rhs.0)
    }

    #[inline]
    fn mul_const(lhs: &Self::Field, rhs: &Self::ParameterField, _: &mut ()) -> Self::Field {
        Fp(lhs.0 * rhs.0)
    }

    #[inline]
    fn add_assign(lhs: &mut Self::Field, rhs: &Self::Field, _: &mut ()) {
        lhs.0 += rhs.0;
    }

    #[inline]
    fn add_const_assign(lhs: &mut Self::Field, rhs: &Self::ParameterField, _: &mut ()) {
        lhs.0 += rhs.0;
    }

    #[inline]
    fn from_parameter(point: Self::ParameterField, _: &mut ()) -> Self::Field {
        point
    }
}

impl<F, const D: usize, const ARITY: usize> poseidon::Field<Compiler<Self, D>> for Spec<F, D, ARITY>
where
    Self: Specification,
    F: RichField + Extendable<D>,
    <Self as Specification>::Field: Extendable<D>,
{
    type Field = Field<<Self as Specification>::Field, D>;

    #[inline]
    fn add(lhs: &Self::Field, rhs: &Self::Field, compiler: &mut Compiler<Self, D>) -> Self::Field {
        lhs.add(rhs, compiler)
    }

    #[inline]
    fn add_const(
        lhs: &Self::Field,
        rhs: &Self::ParameterField,
        compiler: &mut Compiler<Self, D>,
    ) -> Self::Field {
        lhs.add(&Field::new_constant(&rhs.0, compiler), compiler)
    }

    #[inline]
    fn mul(lhs: &Self::Field, rhs: &Self::Field, compiler: &mut Compiler<Self, D>) -> Self::Field {
        lhs.mul(*rhs, compiler)
    }

    #[inline]
    fn mul_const(
        lhs: &Self::Field,
        rhs: &Self::ParameterField,
        compiler: &mut Compiler<Self, D>,
    ) -> Self::Field {
        lhs.mul(Field::new_constant(&rhs.0, compiler), compiler)
    }

    #[inline]
    fn add_assign(lhs: &mut Self::Field, rhs: &Self::Field, compiler: &mut Compiler<Self, D>) {
        *lhs = lhs.add(*rhs, compiler);
    }

    #[inline]
    fn add_const_assign(
        lhs: &mut Self::Field,
        rhs: &Self::ParameterField,
        compiler: &mut Compiler<Self, D>,
    ) {
        *lhs = lhs.add(Field::new_constant(&rhs.0, compiler), compiler);
    }

    #[inline]
    fn from_parameter(
        point: Self::ParameterField,
        compiler: &mut Compiler<Self, D>,
    ) -> Self::Field {
        Field::new_constant(&point.0, compiler)
    }
}

impl<F, const D: usize, const ARITY: usize> poseidon::Specification for Spec<F, D, ARITY>
where
    Self: Specification,
    F: RichField + Extendable<D>,
{
    #[inline]
    fn apply_sbox(point: &mut Self::Field, _: &mut ()) {
        point.0 = point.0.exp_u64(Self::SBOX_EXPONENT);
    }
}

impl<F, const D: usize, const ARITY: usize> poseidon::Specification<Compiler<Self, D>>
    for Spec<F, D, ARITY>
where
    Self: Specification,
    F: RichField + Extendable<D>,
    <Self as Specification>::Field: Extendable<D>,
{
    #[inline]
    fn apply_sbox(point: &mut Self::Field, compiler: &mut Compiler<Self, D>) {
        let mut current = *point;
        let mut product = Field::new(compiler.builder.one());

        for j in 0..bits_u64(Self::SBOX_EXPONENT) {
            if (Self::SBOX_EXPONENT >> j & 1) != 0 {
                product = product.mul(current, compiler);
            }
            current = current.mul(current, compiler)
        }
        *point = product
    }
}

impl<const D: usize, const ARITY: usize> poseidon::SBoxExponent
    for Spec<GoldilocksField, D, ARITY>
{
    const SBOX_EXPONENT: u64 = 7;
}

impl<const D: usize> poseidon::Constants for Spec<GoldilocksField, D, 7> {
    const WIDTH: usize = 8;
    const FULL_ROUNDS: usize = 8;
    const PARTIAL_ROUNDS: usize = 22;
}

impl<const D: usize> poseidon::Constants for Spec<GoldilocksField, D, 11> {
    const WIDTH: usize = 12;
    const FULL_ROUNDS: usize = 8;
    const PARTIAL_ROUNDS: usize = 22;
}
