//! Poseidon Arkworks Backend

use crate::{
    constraint::{fp::Fp, FpVar, R1CS},
    ff::{BigInteger, Field, FpParameters, PrimeField},
    r1cs_std::fields::FieldVar,
};
use core::marker::PhantomData;
use eclair::alloc::Constant;
use openzl_crypto::poseidon::{
    self,
    encryption::BlockElement,
    hash::{DomainTag, Hasher},
    Constants, FieldGeneration, NativeField, ParameterFieldType,
};

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

/// Poseidon Specification Configuration
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Spec<F, const ARITY: usize>(PhantomData<F>)
where
    F: PrimeField;

impl<F, const ARITY: usize> Specification for Spec<F, ARITY>
where
    F: PrimeField,
    Self: poseidon::Constants,
{
    type Field = F;

    const SBOX_EXPONENT: u64 = 5;
}

impl<F, const ARITY: usize, COM> Constant<COM> for Spec<F, ARITY>
where
    F: PrimeField,
{
    type Type = Self;

    #[inline]
    fn new_constant(this: &Self::Type, compiler: &mut COM) -> Self {
        let _ = (this, compiler);
        Self(PhantomData)
    }
}

impl<F, const ARITY: usize> ParameterFieldType for Spec<F, ARITY>
where
    Self: Specification,
    F: PrimeField,
{
    type ParameterField = Fp<<Self as Specification>::Field>;
}

// impl<F, COM, const ARITY: usize> ArrayHashFunction<ARITY, COM> for Spec<F, ARITY>
// where F: PrimeField {
//     type Input = F;

//     type Output = F;

//     fn hash(&self, input: [&Self::Input; ARITY], compiler: &mut COM) -> Self::Output {
//         let mut state = State::new()
//         todo!()
//     }
// }

impl<F, const ARITY: usize> poseidon::Field for Spec<F, ARITY>
where
    Self: Specification,
    F: PrimeField,
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
    fn from_parameter(point: Self::ParameterField) -> Self::Field {
        point
    }
}

impl<F, const ARITY: usize> poseidon::Field<Compiler<Self>> for Spec<F, ARITY>
where
    Self: Specification,
    F: PrimeField,
{
    type Field = FpVar<<Self as Specification>::Field>;

    #[inline]
    fn add(lhs: &Self::Field, rhs: &Self::Field, _: &mut Compiler<Self>) -> Self::Field {
        lhs + rhs
    }

    #[inline]
    fn add_const(
        lhs: &Self::Field,
        rhs: &Self::ParameterField,
        _: &mut Compiler<Self>,
    ) -> Self::Field {
        lhs + FpVar::Constant(rhs.0)
    }

    #[inline]
    fn mul(lhs: &Self::Field, rhs: &Self::Field, _: &mut Compiler<Self>) -> Self::Field {
        lhs * rhs
    }

    #[inline]
    fn mul_const(
        lhs: &Self::Field,
        rhs: &Self::ParameterField,
        _: &mut Compiler<Self>,
    ) -> Self::Field {
        lhs * FpVar::Constant(rhs.0)
    }

    #[inline]
    fn add_assign(lhs: &mut Self::Field, rhs: &Self::Field, _: &mut Compiler<Self>) {
        *lhs += rhs;
    }

    #[inline]
    fn add_const_assign(lhs: &mut Self::Field, rhs: &Self::ParameterField, _: &mut Compiler<Self>) {
        *lhs += FpVar::Constant(rhs.0)
    }

    #[inline]
    fn from_parameter(point: Self::ParameterField) -> Self::Field {
        FpVar::Constant(point.0)
    }
}

impl<F, const ARITY: usize> poseidon::Specification for Spec<F, ARITY>
where
    Self: Specification,
    F: PrimeField,
{
    #[inline]
    fn apply_sbox(point: &mut Self::Field, _: &mut ()) {
        point.0 = point.0.pow([Self::SBOX_EXPONENT, 0, 0, 0]);
    }
}

impl<F, const ARITY: usize> poseidon::Specification<Compiler<Self>> for Spec<F, ARITY>
where
    Self: Specification,
    F: PrimeField,
{
    #[inline]
    fn apply_sbox(point: &mut Self::Field, _: &mut Compiler<Self>) {
        *point = point
            .pow_by_constant([Self::SBOX_EXPONENT])
            .expect("Exponentiation is not allowed to fail.");
    }
}

impl poseidon::Constants for Spec<bn254::Fr, 2> {
    const WIDTH: usize = 3;
    const FULL_ROUNDS: usize = 8;
    const PARTIAL_ROUNDS: usize = 55;
}

impl poseidon::Constants for Spec<bn254::Fr, 3> {
    const WIDTH: usize = 4;
    const FULL_ROUNDS: usize = 8;
    const PARTIAL_ROUNDS: usize = 55;
}

impl poseidon::Constants for Spec<bn254::Fr, 4> {
    const WIDTH: usize = 5;
    const FULL_ROUNDS: usize = 8;
    const PARTIAL_ROUNDS: usize = 56;
}

impl poseidon::Constants for Spec<bn254::Fr, 5> {
    const WIDTH: usize = 6;
    const FULL_ROUNDS: usize = 8;
    const PARTIAL_ROUNDS: usize = 56;
}

/// Hasher for Poseidon Permutation over Bn254 Scalar Field
pub type Bn254Hasher<const ARITY: usize> =
    Hasher<Spec<bn254::Fr, ARITY>, TwoPowerMinusOneDomainTag, ARITY>;
