//! Concrete Poseidon Implementation over Bn254 using Arkworks

use crate::poseidon::{Constants, Permutation, Specification, State};
use arkworks::{
    bn254::Fr,
    ff::{BigInteger, Field, PrimeField, Zero},
};
use core::marker::PhantomData;
use openzl_crypto::{
    hash::ArrayHashFunction,
    poseidon::{
        mds::MdsMatrices, round_constants::generate_round_constants, FieldGeneration, NativeField,
    },
};

/// Poseidon Permutation for native computation
#[derive(Debug)]
pub struct NativePoseidon<C>(PhantomData<C>);

impl<C> Constants for NativePoseidon<C>
where
    C: Constants,
{
    const WIDTH: usize = C::WIDTH;
    const FULL_ROUNDS: usize = C::FULL_ROUNDS;
    const PARTIAL_ROUNDS: usize = C::PARTIAL_ROUNDS;
}

/// Constants for Arity 2
#[derive(Debug)]
pub struct Arity2;

impl Constants for Arity2 {
    const WIDTH: usize = 3;
    const FULL_ROUNDS: usize = 8;
    const PARTIAL_ROUNDS: usize = 55;
}

impl<C> Specification for NativePoseidon<C>
where
    C: Constants,
{
    type Field = Fr;
    type ParameterField = Fr;

    fn zero(_: &mut ()) -> Self::Field {
        Fr::zero()
    }

    fn add(lhs: &Self::Field, rhs: &Self::Field, _: &mut ()) -> Self::Field {
        *lhs + rhs
    }

    fn add_const(lhs: &Self::Field, rhs: &Self::ParameterField, _: &mut ()) -> Self::Field {
        *lhs + rhs
    }

    fn mul(lhs: &Self::Field, rhs: &Self::Field, _: &mut ()) -> Self::Field {
        *lhs * rhs
    }

    fn mul_const(lhs: &Self::Field, rhs: &Self::ParameterField, _: &mut ()) -> Self::Field {
        *lhs * rhs
    }

    fn add_assign(lhs: &mut Self::Field, rhs: &Self::Field, _: &mut ()) {
        *lhs = *lhs + rhs
    }

    fn add_const_assign(lhs: &mut Self::Field, rhs: &Self::ParameterField, _: &mut ()) {
        *lhs = *lhs + rhs
    }

    fn apply_sbox(point: &mut Self::Field, _: &mut ()) {
        *point = point.pow([5u64])
    }

    fn from_parameter(point: Self::ParameterField) -> Self::Field {
        point
    }
}

type Poseidon2 = NativePoseidon<Arity2>;

pub fn concrete_permutation() -> Permutation<Poseidon2> {
    let additive_round_keys: Vec<Fr> = generate_round_constants::<BlsScalar>(3, 8, 55)
        .iter()
        .map(|c| c.0)
        .collect();
    let mds_matrix: Vec<Fr> = MdsMatrices::<BlsScalar>::generate_mds(3)
        .0
        .iter()
        .flatten()
        .map(|c| c.0)
        .collect();
    Permutation::new(additive_round_keys.into(), mds_matrix.into())
}

/// An arity-2 Poseidon hasher for Bn254 points
pub type Poseidon2Hasher = Permutation<Poseidon2>;

impl ArrayHashFunction<2> for Poseidon2Hasher {
    type Input = Fr;
    type Output = Fr;

    fn hash(&self, input: [&Self::Input; 2], _: &mut ()) -> Self::Output {
        let domain_tag = Fr::zero();
        let mut state = Vec::from([domain_tag]);
        state.push(*input[0]);
        state.push(*input[1]);
        let mut state = State::<Poseidon2>::new(state.into());
        self.permute(&mut state, &mut ());
        state.0[0]
    }
}


// TODO: Proof-related implementations