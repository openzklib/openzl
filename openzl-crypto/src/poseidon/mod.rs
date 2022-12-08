//! Poseidon Permutation Implementation

use crate::{
    permutation::PseudorandomPermutation,
    poseidon::{
        matrix::MatrixOperations, mds::MdsMatrices, round_constants::generate_round_constants,
    },
};
use alloc::{boxed::Box, vec::Vec};
use core::{fmt::Debug, hash::Hash, iter, marker::PhantomData, mem, slice};
use eclair::alloc::{Allocate, Const, Constant};
use openzl_util::{
    codec::{Decode, DecodeError, Encode, Read, Write},
    rand::{Rand, RngCore, Sample},
};

#[cfg(feature = "serde")]
use openzl_util::serde::{Deserialize, Serialize};

pub mod constants;
pub mod encryption;
pub mod hash;
pub mod lfsr;
pub mod matrix;
pub mod mds;
pub mod preprocessing;
pub mod round_constants;

/// Field Element
///
/// This trait is intended to represent arithmetic operations performed on native
/// field elements, specifically the constant parameters of a Poseidon permutation.
/// See [`Field`] for arithmetic operations that may be performed in-circuit.
pub trait NativeField {
    /// Returns the additive identity of the field.
    fn zero() -> Self;

    /// Checks if the field element equals the result of calling [`zero`](Self::zero).
    fn is_zero(&self) -> bool;

    /// Returns the multiplicative identity of the field.
    fn one() -> Self;

    /// Adds two field elements together.
    fn add(&self, rhs: &Self) -> Self;

    /// Adds the `rhs` field element to the `self` field element, storing the value in `self`.
    fn add_assign(&mut self, rhs: &Self);

    /// Multiplies two field elements together.
    fn mul(&self, rhs: &Self) -> Self;

    /// Subtracts `rhs` from `lhs`.
    fn sub(&self, rhs: &Self) -> Self;

    /// Computes the multiplicative inverse of a field element.
    fn inverse(&self) -> Option<Self>
    where
        Self: Sized;
}

/// Field Element Generation
pub trait FieldGeneration {
    /// Number of bits of modulus of the field.
    const MODULUS_BITS: usize;

    /// Converts a `u64` value to a field element.
    fn from_u64(elem: u64) -> Self;

    /// Converts from `bits` into a field element in big endian order, returning `None` if `bits`
    /// are out of range.
    fn try_from_bits_be(bits: &[bool]) -> Option<Self>
    where
        Self: Sized;
}

/// Poseidon Constants
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

/// Parameter Field Type
pub trait ParameterFieldType {
    /// Field Type used for Constant Parameters
    type ParameterField;
}

/// Poseidon Permutation Field
pub trait Field<COM = ()>: Constants + ParameterFieldType {
    /// Field Type used for Permutation State
    type Field;

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

/// Poseidon Permutation Specification
///
/// This trait includes a blanket implementation of `mds_matrix_multiply` that may
/// not be optimal for all choices of `COM`. In particular, Plonk-like arithmetizations
/// should implement `mds_matrix_multiply` in a way that minimizes the cost of
/// linear combinations.
pub trait Specification<F, COM = ()>: Sized
where
    F: Field<COM>,
{
    /// Returns a reference to the additive keys for the given `round`.
    ///
    /// It is the responsibility of the implementor to ensure that this
    /// slice has size `F::WIDTH`.
    fn additive_keys(&self, round: usize) -> &[F::ParameterField];

    /// Returns a reference to the (flattened) MDS Matrix of the permutation.
    ///
    /// It is the responsibility of the implementor to ensure that this
    /// slice has size `F::WIDTH * F::WIDTH`.
    fn mds_matrix(&self) -> &[F::ParameterField];

    /// Computes the MDS matrix multiplication against the `state`.
    #[inline]
    fn mds_matrix_multiply(&self, state: &mut State<F, COM>, compiler: &mut COM) {
        let mds_matrix = self.mds_matrix();
        let mut next = Vec::with_capacity(F::WIDTH);
        for i in 0..F::WIDTH {
            // NOTE: clippy false-positive: Without `collect`, the two closures in `map` and
            //       `reduce` will have simultaneous `&mut` access to `compiler`. Adding `collect`
            //       allows `map` to be done before `reduce`.
            #[allow(clippy::needless_collect)]
            let linear_combination = state
                .iter()
                .enumerate()
                .map(|(j, elem)| F::mul_const(elem, &mds_matrix[F::WIDTH * i + j], compiler))
                .collect::<Vec<_>>();
            next.push(
                linear_combination
                    .into_iter()
                    .reduce(|acc, next| F::add(&acc, &next, compiler))
                    .unwrap(),
            );
        }
        mem::swap(&mut next.into_boxed_slice(), &mut state.0);
    }

    /// Computes a full round at the given `round` index on the internal permutation `state`.
    #[inline]
    fn full_round(&self, round: usize, state: &mut State<F, COM>, compiler: &mut COM) {
        let keys = self.additive_keys(round);
        for (i, elem) in state.iter_mut().enumerate() {
            F::add_const_assign(elem, &keys[i], compiler);
            F::apply_sbox(elem, compiler);
        }
        self.mds_matrix_multiply(state, compiler);
    }

    /// Computes a partial round at the given `round` index on the internal permutation `state`.
    #[inline]
    fn partial_round(&self, round: usize, state: &mut State<F, COM>, compiler: &mut COM) {
        let keys = self.additive_keys(round);
        for (i, elem) in state.iter_mut().enumerate() {
            F::add_const_assign(elem, &keys[i], compiler);
        }
        F::apply_sbox(&mut state.0[0], compiler);
        self.mds_matrix_multiply(state, compiler);
    }

    /// Computes the full permutation without the first round.
    #[inline]
    fn permute_without_first_round(&self, state: &mut State<F, COM>, compiler: &mut COM) {
        for round in 1..F::HALF_FULL_ROUNDS {
            self.full_round(round, state, compiler);
        }
        for round in F::HALF_FULL_ROUNDS..(F::HALF_FULL_ROUNDS + F::PARTIAL_ROUNDS) {
            self.partial_round(round, state, compiler);
        }
        for round in (F::HALF_FULL_ROUNDS + F::PARTIAL_ROUNDS)..(F::FULL_ROUNDS + F::PARTIAL_ROUNDS)
        {
            self.full_round(round, state, compiler);
        }
    }

    /// Computes the first round borrowing the `input` and `domain_tag` returning the [`State`]
    /// after the first round. This method does not check that `N + 1 = S::WIDTH`.
    #[inline]
    fn first_round_with_domain_tag_unchecked<const N: usize>(
        &self,
        domain_tag: &F::Field,
        input: [&F::Field; N],
        compiler: &mut COM,
    ) -> State<F, COM> {
        let mut state = Vec::with_capacity(F::WIDTH);
        let additive_round_keys = self.additive_keys(0);
        for (i, point) in iter::once(domain_tag).chain(input).enumerate() {
            let mut elem = F::add_const(point, &additive_round_keys[i], compiler);
            F::apply_sbox(&mut elem, compiler);
            state.push(elem);
        }
        let mut state = State(state.into_boxed_slice());
        self.mds_matrix_multiply(&mut state, compiler);
        state
    }
}

/// Poseidon Internal State
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(
        bound(
            deserialize = "F::Field: Deserialize<'de>",
            serialize = "F::Field: Serialize"
        ),
        crate = "openzl_util::serde",
        deny_unknown_fields
    )
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "F::Field: Clone"),
    Debug(bound = "F::Field: Debug"),
    Eq(bound = "F::Field: Eq"),
    Hash(bound = "F::Field: Hash"),
    PartialEq(bound = "F::Field: PartialEq")
)]
pub struct State<F, COM = ()>(Box<[F::Field]>)
where
    F: Field<COM>;

impl<F, COM> State<F, COM>
where
    F: Field<COM>,
{
    /// Builds a new [`State`] from `state`.
    #[inline]
    pub fn new(state: Box<[F::Field]>) -> Self {
        assert_eq!(state.len(), F::WIDTH);
        Self(state)
    }

    /// Returns a slice iterator over the state.
    #[inline]
    pub fn iter(&self) -> slice::Iter<F::Field> {
        self.0.iter()
    }

    /// Returns a mutable slice iterator over the state.
    #[inline]
    pub fn iter_mut(&mut self) -> slice::IterMut<F::Field> {
        self.0.iter_mut()
    }
}

impl<F, COM> Constant<COM> for State<F, COM>
where
    F: Field<COM> + Constant<COM>,
    F::Field: Constant<COM>,
    F::Type: Field<Field = Const<F::Field, COM>>,
{
    type Type = State<F::Type>;

    #[inline]
    fn new_constant(this: &Self::Type, compiler: &mut COM) -> Self {
        Self(this.0.as_constant(compiler))
    }
}

impl<F> Decode for State<F>
where
    F: Field,
    F::Field: Decode,
{
    type Error = Option<<F::Field as Decode>::Error>;

    #[inline]
    fn decode<R>(reader: R) -> Result<Self, DecodeError<R::Error, Self::Error>>
    where
        R: Read,
    {
        Ok(Self(Decode::decode(reader)?))
    }
}

impl<F> Encode for State<F>
where
    F: Field,
    F::Field: Encode,
{
    #[inline]
    fn encode<W>(&self, writer: W) -> Result<(), W::Error>
    where
        W: Write,
    {
        self.0.encode(writer)
    }
}

impl<F, D> Sample<D> for State<F>
where
    F: Field,
    F::Field: Sample<D>,
    D: Clone,
{
    #[inline]
    fn sample<R>(distribution: D, rng: &mut R) -> Self
    where
        R: RngCore + ?Sized,
    {
        Self(
            iter::repeat_with(|| rng.sample(distribution.clone()))
                .take(F::WIDTH)
                .collect(),
        )
    }
}

/// Poseidon Permutation
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(
        bound(
            deserialize = "F::ParameterField: Deserialize<'de>",
            serialize = "F::ParameterField: Serialize"
        ),
        crate = "openzl_util::serde",
        deny_unknown_fields
    )
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "F::ParameterField: Clone"),
    Debug(bound = "F::ParameterField: Debug"),
    Eq(bound = "F::ParameterField: Eq"),
    Hash(bound = "F::ParameterField: Hash"),
    PartialEq(bound = "F::ParameterField: PartialEq")
)]
pub struct Permutation<F, COM = ()>
where
    F: Field<COM>,
{
    /// Additive Round Keys
    additive_round_keys: Box<[F::ParameterField]>,

    /// MDS Matrix
    mds_matrix: Box<[F::ParameterField]>,

    /// Type Parameter Marker
    __: PhantomData<COM>,
}

impl<F, COM> Permutation<F, COM>
where
    F: Field<COM>,
{
    /// Builds a new [`Permutation`] from `additive_round_keys` and `mds_matrix`.
    ///
    /// # Panics
    ///
    /// This method panics if the input vectors are not the correct size for the specified
    /// [`Specification`].
    #[inline]
    pub fn new(
        additive_round_keys: Box<[F::ParameterField]>,
        mds_matrix: Box<[F::ParameterField]>,
    ) -> Self {
        assert_eq!(
            additive_round_keys.len(),
            F::ADDITIVE_ROUND_KEYS_COUNT,
            "Additive Rounds Keys are not the correct size."
        );
        assert_eq!(
            mds_matrix.len(),
            F::MDS_MATRIX_SIZE,
            "MDS Matrix is not the correct size."
        );
        Self::new_unchecked(additive_round_keys, mds_matrix)
    }

    /// Builds a new [`Permutation`] from `additive_round_keys` and `mds_matrix` without
    /// checking their sizes.
    #[inline]
    fn new_unchecked(
        additive_round_keys: Box<[F::ParameterField]>,
        mds_matrix: Box<[F::ParameterField]>,
    ) -> Self {
        Self {
            additive_round_keys,
            mds_matrix,
            __: PhantomData,
        }
    }
}

impl<F, COM> Specification<F, COM> for Permutation<F, COM>
where
    F: Field<COM>,
{
    #[inline]
    fn additive_keys(&self, round: usize) -> &[F::ParameterField] {
        let start = round * F::WIDTH;
        &self.additive_round_keys[start..start + F::WIDTH]
    }

    #[inline]
    fn mds_matrix(&self) -> &[<F>::ParameterField] {
        &self.mds_matrix
    }
}

impl<F, COM> Constant<COM> for Permutation<F, COM>
where
    F: Field<COM> + Constant<COM>,
    F::Type: Field<ParameterField = Const<F::ParameterField, COM>>,
    F::ParameterField: Constant<COM>,
{
    type Type = Permutation<F::Type>;

    #[inline]
    fn new_constant(this: &Self::Type, compiler: &mut COM) -> Self {
        Self::new_unchecked(
            this.additive_round_keys
                .iter()
                .map(|e| e.as_constant(compiler))
                .collect(),
            this.mds_matrix
                .iter()
                .map(|e| e.as_constant(compiler))
                .collect(),
        )
    }
}

impl<F, COM> Decode for Permutation<F, COM>
where
    F: Field<COM>,
    F::ParameterField: Decode,
{
    type Error = <F::ParameterField as Decode>::Error;

    #[inline]
    fn decode<R>(mut reader: R) -> Result<Self, DecodeError<R::Error, Self::Error>>
    where
        R: Read,
    {
        Ok(Self::new_unchecked(
            (0..F::ADDITIVE_ROUND_KEYS_COUNT)
                .map(|_| Decode::decode(&mut reader))
                .collect::<Result<_, _>>()?,
            (0..F::MDS_MATRIX_SIZE)
                .map(|_| Decode::decode(&mut reader))
                .collect::<Result<_, _>>()?,
        ))
    }
}

impl<F, COM> Encode for Permutation<F, COM>
where
    F: Field<COM>,
    F::ParameterField: Encode,
{
    #[inline]
    fn encode<W>(&self, mut writer: W) -> Result<(), W::Error>
    where
        W: Write,
    {
        for key in self.additive_round_keys.iter() {
            key.encode(&mut writer)?;
        }
        for entry in self.mds_matrix.iter() {
            entry.encode(&mut writer)?;
        }
        Ok(())
    }
}

impl<F, COM> PseudorandomPermutation<COM> for Permutation<F, COM>
where
    F: Field<COM>,
{
    type Domain = State<F, COM>;

    #[inline]
    fn permute(&self, state: &mut Self::Domain, compiler: &mut COM) {
        self.full_round(0, state, compiler);
        self.permute_without_first_round(state, compiler);
    }
}

impl<F, COM> Sample for Permutation<F, COM>
where
    F: Field<COM>,
    F::ParameterField: NativeField + FieldGeneration,
{
    #[inline]
    fn sample<R>(distribution: (), rng: &mut R) -> Self
    where
        R: RngCore + ?Sized,
    {
        let _ = (distribution, rng);
        Self::new_unchecked(
            generate_round_constants(F::WIDTH, F::FULL_ROUNDS, F::PARTIAL_ROUNDS)
                .into_boxed_slice(),
            MdsMatrices::generate_mds(F::WIDTH)
                .to_row_major()
                .into_boxed_slice(),
        )
    }
}
