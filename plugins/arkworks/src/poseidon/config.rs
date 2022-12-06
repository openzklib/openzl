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

//! Poseidon Configuration

use crate::poseidon::{Compiler, Specification};
use crate::constraint::{fp::Fp, FpVar};
use crate::ff::Field;
use crate::r1cs_std::fields::FieldVar;
use eclair::alloc::Constant;
use openzl_crypto::poseidon::{self, ParameterFieldType};

/// Bn254 Scalar Field
pub type ConstraintField = ark_bn254::Fr;

/// Poseidon Specification Configuration
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Spec<const ARITY: usize>;

impl poseidon::Constants for Spec<2> {
    const WIDTH: usize = 3;
    const FULL_ROUNDS: usize = 8;
    const PARTIAL_ROUNDS: usize = 55;
}

impl poseidon::Constants for Spec<3> {
    const WIDTH: usize = 4;
    const FULL_ROUNDS: usize = 8;
    const PARTIAL_ROUNDS: usize = 55;
}

impl poseidon::Constants for Spec<4> {
    const WIDTH: usize = 5;
    const FULL_ROUNDS: usize = 8;
    const PARTIAL_ROUNDS: usize = 56;
}

impl poseidon::Constants for Spec<5> {
    const WIDTH: usize = 6;
    const FULL_ROUNDS: usize = 8;
    const PARTIAL_ROUNDS: usize = 56;
}

impl<const ARITY: usize> Specification for Spec<ARITY>
where
    Self: poseidon::Constants,
{
    type Field = ConstraintField;

    const SBOX_EXPONENT: u64 = 5;
}

impl<const ARITY: usize, COM> Constant<COM> for Spec<ARITY> {
    type Type = Self;

    #[inline]
    fn new_constant(this: &Self::Type, compiler: &mut COM) -> Self {
        let _ = (this, compiler);
        Self
    }
}

impl<const ARITY: usize> ParameterFieldType for Spec<ARITY>
where
    Self: Specification,
{
    type ParameterField = Fp<<Self as Specification>::Field>;
}

impl<const ARITY: usize> poseidon::Specification for Spec<ARITY>
where
    Self: Specification,
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
    fn apply_sbox(point: &mut Self::Field, _: &mut ()) {
        point.0 = point.0.pow([Self::SBOX_EXPONENT, 0, 0, 0]);
    }

    #[inline]
    fn from_parameter(point: Self::ParameterField) -> Self::Field {
        point
    }
}

impl<const ARITY: usize> poseidon::Specification<Compiler<Self>> for Spec<ARITY>
where
    Self: Specification,
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
    fn apply_sbox(point: &mut Self::Field, _: &mut Compiler<Self>) {
        *point = point
            .pow_by_constant([Self::SBOX_EXPONENT])
            .expect("Exponentiation is not allowed to fail.");
    }

    #[inline]
    fn from_parameter(point: Self::ParameterField) -> Self::Field {
        FpVar::Constant(point.0)
    }
}

/// Arity 2 Poseidon Specification
pub type Spec2 = Spec<2>;

/// Arity 3 Poseidon Specification
pub type Spec3 = Spec<3>;

/// Arity 4 Poseidon Specification
pub type Spec4 = Spec<4>;

/// Arity 5 Poseidon Specification
pub type Spec5 = Spec<5>;

/// Testing Framework
#[cfg(test)]
pub mod test {
    use super::*;
    use crate::constraint::fp::Fp;
    use alloc::boxed::Box;
    use openzl_crypto::{
        encryption::{Decrypt, Encrypt},
        poseidon::{
            encryption::{BlockArray, FixedDuplexer, PlaintextBlock},
            Constants,
        },
    };
    use openzl_util::rand::{OsRng, Sample};

    /// Tests Poseidon duplexer encryption works.
    #[test]
    fn poseidon_duplexer_test() {
        const N: usize = 3;
        let mut rng = OsRng;
        let duplexer = FixedDuplexer::<1, Spec<N>>::gen(&mut rng);
        let field_elements = <[Fp<ConstraintField>; Spec::<N>::WIDTH - 1]>::gen(&mut rng);
        let plaintext_block = PlaintextBlock(Box::new(field_elements));
        let plaintext = BlockArray::<_, 1>([plaintext_block].into());
        let mut key = Vec::new();
        let key_element_1 = Fp::<ConstraintField>::gen(&mut rng);
        let key_element_2 = Fp::<ConstraintField>::gen(&mut rng);
        key.push(key_element_1);
        key.push(key_element_2);
        let header = vec![];
        let ciphertext = duplexer.encrypt(&key, &(), &header, &plaintext, &mut ());
        let (tag_matches, decrypted_plaintext) =
            duplexer.decrypt(&key, &header, &ciphertext, &mut ());
        assert!(tag_matches, "Tag doesn't match");
        assert_eq!(
            plaintext, decrypted_plaintext,
            "Decrypted plaintext is not equal to original one."
        );
    }
}
