//! Tutorial for Poseidon Permutation

use core::{marker::PhantomData, mem, slice};

#[cfg(all(feature = "alloc", feature = "bn254", feature = "groth16"))]
pub mod arkworks;

/// Poseidon Specification
///
/// This trait defines basic arithmetic operations we use to define the Poseidon permutation.
pub trait Specification<COM = ()>: Constants {
    /// Field Type used for Permutation State
    type Field;

    /// Field Type used for Permutation Parameters
    type ParameterField;

    /// Returns the zero element of the field.
    fn zero(compiler: &mut COM) -> Self::Field;

    /// Adds two field elements together.
    fn add(lhs: &Self::Field, rhs: &Self::Field, compiler: &mut COM) -> Self::Field;

    /// Adds a field element `lhs` with a constant `rhs`
    fn add_const(lhs: &Self::Field, rhs: &Self::ParameterField, compiler: &mut COM) -> Self::Field;

    /// Multiplies two field elements together.
    fn mul(lhs: &Self::Field, rhs: &Self::Field, compiler: &mut COM) -> Self::Field;

    /// Multiplies a field element `lhs` with a constant `rhs`
    fn mul_const(lhs: &Self::Field, rhs: &Self::ParameterField, compiler: &mut COM) -> Self::Field;

    /// Adds the `rhs` field element to `lhs` field element, updating the value in `lhs`
    fn add_assign(lhs: &mut Self::Field, rhs: &Self::Field, compiler: &mut COM);

    /// Adds the `rhs` constant to `lhs` field element, updating the value in `lhs`
    fn add_const_assign(lhs: &mut Self::Field, rhs: &Self::ParameterField, compiler: &mut COM);

    /// Applies the S-BOX to `point`.
    fn apply_sbox(point: &mut Self::Field, compiler: &mut COM);

    /// Converts a constant parameter `point` for permutation state.
    fn from_parameter(point: Self::ParameterField) -> Self::Field;
}

pub trait Constants {
    /// Width of the Permutation
    ///
    /// This number is the total number `t` of field elements in the state which is `F^t`.
    const WIDTH: usize;

    /// Number of Full Rounds
    ///
    /// The total number of full rounds in the Poseidon permutation, including the first set of full
    /// rounds and then the second set after the partial rounds.
    const FULL_ROUNDS: usize;

    /// Number of Partial Rounds
    const PARTIAL_ROUNDS: usize;

    /// Half Number of Full Rounds
    ///
    /// Poseidon Hash first has [`HALF_FULL_ROUNDS`]-many full rounds in the beginning,
    /// followed by [`PARTIAL_ROUNDS`]-many partial rounds in the middle, and finally
    /// [`HALF_FULL_ROUNDS`]-many full rounds at the end.
    ///
    /// [`HALF_FULL_ROUNDS`]: Self::HALF_FULL_ROUNDS
    /// [`PARTIAL_ROUNDS`]: Constants::PARTIAL_ROUNDS
    const HALF_FULL_ROUNDS: usize = Self::FULL_ROUNDS / 2;

    /// Total Number of Rounds
    const ROUNDS: usize = Self::FULL_ROUNDS + Self::PARTIAL_ROUNDS;

    /// Number of Entries in the MDS Matrix
    const MDS_MATRIX_SIZE: usize = Self::WIDTH * Self::WIDTH;

    /// Total Number of Additive Rounds Keys
    const ADDITIVE_ROUND_KEYS_COUNT: usize = Self::ROUNDS * Self::WIDTH;
}

/// The state vector that a Poseidon permutation acts on.
#[derive(Debug)]
pub struct State<S, COM = ()>(Box<[S::Field]>)
where
    S: Specification<COM>;

impl<S, COM> State<S, COM>
where
    S: Specification<COM>,
{
    /// Builds a new [`State`] from `state`.
    #[inline]
    pub fn new(state: Box<[S::Field]>) -> Self {
        assert_eq!(state.len(), S::WIDTH);
        Self(state)
    }

    /// Returns a slice iterator over the state.
    #[inline]
    pub fn iter(&self) -> slice::Iter<S::Field> {
        self.0.iter()
    }

    /// Returns a mutable slice iterator over the state.
    #[inline]
    pub fn iter_mut(&mut self) -> slice::IterMut<S::Field> {
        self.0.iter_mut()
    }
}

/// The constant parameters defining a particular instance
/// of the Poseidon permutation.
pub struct Permutation<S, COM = ()>
where
    S: Specification<COM>,
{
    /// Additive Round Keys
    additive_round_keys: Box<[S::ParameterField]>,

    /// MDS Matrix
    mds_matrix: Box<[S::ParameterField]>,

    /// Type Parameter Marker
    __: PhantomData<COM>,
}

impl<S, COM> Permutation<S, COM>
where
    S: Specification<COM>,
{
    /// Builds a new [`Permutation`] from `additive_round_keys` and `mds_matrix`.
    ///
    /// # Panics
    ///
    /// This method panics if the input vectors are not the correct size for the specified
    /// [`Specification`].
    #[inline]
    pub fn new(
        additive_round_keys: Box<[S::ParameterField]>,
        mds_matrix: Box<[S::ParameterField]>,
    ) -> Self {
        assert_eq!(
            additive_round_keys.len(),
            S::ADDITIVE_ROUND_KEYS_COUNT,
            "Additive Rounds Keys are not the correct size."
        );
        assert_eq!(
            mds_matrix.len(),
            S::MDS_MATRIX_SIZE,
            "MDS Matrix is not the correct size."
        );
        Self {
            additive_round_keys,
            mds_matrix,
            __: PhantomData,
        }
    }

    /// Returns the additive keys for the given `round`.
    #[inline]
    pub fn additive_keys(&self, round: usize) -> &[S::ParameterField] {
        let start = round * S::WIDTH;
        &self.additive_round_keys[start..start + S::WIDTH]
    }

    /// Computes the MDS matrix multiplication against the `state`.
    #[inline]
    pub fn mds_matrix_multiply(&self, state: &mut State<S, COM>, compiler: &mut COM) {
        let mut next = Vec::with_capacity(S::WIDTH);
        for i in 0..S::WIDTH {
            // NOTE: clippy false-positive: Without `collect`, the two closures in `map` and
            //       `reduce` will have simultaneous `&mut` access to `compiler`. Adding `collect`
            //       allows `map` to be done before `reduce`.
            #[allow(clippy::needless_collect)]
            let linear_combination = state
                .iter()
                .enumerate()
                .map(|(j, elem)| S::mul_const(elem, &self.mds_matrix[S::WIDTH * i + j], compiler))
                .collect::<Vec<_>>();
            next.push(
                linear_combination
                    .into_iter()
                    .reduce(|acc, next| S::add(&acc, &next, compiler))
                    .unwrap(),
            );
        }
        mem::swap(&mut next.into_boxed_slice(), &mut state.0);
    }

    /// Computes a full round at the given `round` index on the internal permutation `state`.
    #[inline]
    pub fn full_round(&self, round: usize, state: &mut State<S, COM>, compiler: &mut COM) {
        let keys = self.additive_keys(round);
        for (i, elem) in state.iter_mut().enumerate() {
            S::add_const_assign(elem, &keys[i], compiler);
            S::apply_sbox(elem, compiler);
        }
        self.mds_matrix_multiply(state, compiler);
    }

    /// Computes a partial round at the given `round` index on the internal permutation `state`.
    #[inline]
    pub fn partial_round(&self, round: usize, state: &mut State<S, COM>, compiler: &mut COM) {
        let keys = self.additive_keys(round);
        for (i, elem) in state.iter_mut().enumerate() {
            S::add_const_assign(elem, &keys[i], compiler);
        }
        S::apply_sbox(&mut state.0[0], compiler);
        self.mds_matrix_multiply(state, compiler);
    }

    /// Computes the full permutation without the first round.
    #[inline]
    fn permute(&self, state: &mut State<S, COM>, compiler: &mut COM) {
        for round in 0..S::HALF_FULL_ROUNDS {
            self.full_round(round, state, compiler);
        }
        for round in S::HALF_FULL_ROUNDS..(S::HALF_FULL_ROUNDS + S::PARTIAL_ROUNDS) {
            self.partial_round(round, state, compiler);
        }
        for round in (S::HALF_FULL_ROUNDS + S::PARTIAL_ROUNDS)..(S::FULL_ROUNDS + S::PARTIAL_ROUNDS)
        {
            self.full_round(round, state, compiler);
        }
    }
}

/// Demonstration of native computation with comparison to
/// a test value.
#[cfg(all(feature = "alloc", feature = "bls12-381"))]
pub mod bls12_381 {
    use super::*;
    use ::arkworks::{
        bls12_381::Fr,
        ff::{field_new, BigInteger, Field, PrimeField, Zero},
    };
    use openzl_crypto::poseidon::{
        mds::MdsMatrices, round_constants::generate_round_constants, FieldGeneration, NativeField,
    };
    // import what was here from poseidon::arkworks now

    #[test]
    fn poseidon_arity_2() {
        let round_keys: Vec<Fr> = generate_round_constants::<BlsScalar>(3, 8, 55)
            .iter()
            .map(|c| c.0)
            .collect();
        let mds_matrix: Vec<Fr> = MdsMatrices::<BlsScalar>::generate_mds(3)
            .0
            .iter()
            .flatten()
            .map(|c| c.0)
            .collect();

        let poseidon2_permutation =
            Permutation::<Poseidon2>::new(round_keys.into(), mds_matrix.into());

        let mut state =
            State::<Poseidon2>::new([Fr::from(3u8), Fr::from(1u8), Fr::from(2u8)].into());
        // The known output value for input [3, 1, 2]
        let expected: Vec<Fr> = vec![
            field_new!(
                Fr,
                "1808609226548932412441401219270714120272118151392880709881321306315053574086"
            ),
            field_new!(
                Fr,
                "13469396364901763595452591099956641926259481376691266681656453586107981422876"
            ),
            field_new!(
                Fr,
                "28037046374767189790502007352434539884533225547205397602914398240898150312947"
            ),
        ];

        poseidon2_permutation.permute(&mut state, &mut ());
        assert_eq!(state.0.to_vec(), expected);
    }
}
