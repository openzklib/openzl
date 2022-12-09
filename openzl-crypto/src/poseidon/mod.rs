//! Poseidon Permutation Implementation

use crate::{
    component,
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
    derivative,
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
#[component]
pub type ParameterField;

/// Poseidon Permutation Field
pub trait Field<COM = ()>: ParameterFieldType {
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

    /// Converts a constant parameter `point` for permutation state.
    fn from_parameter(point: Self::ParameterField) -> Self::Field;
}

/// Poseidon Permutation Specification
///
/// Implementation Note
/// 
/// This trait includes a blanket implementation of [`mds_matrix_multiply`] that may
/// not be optimal for all choices of `COM`. In particular, Plonk-like arithmetizations
/// should implement [`mds_matrix_multiply`] in a way that minimizes the cost of
/// linear combinations.
/// 
/// [`mds_matrix_multiply`]: Self::mds_matrix_multiply
pub trait Specification<COM = ()>: Field<COM> + Constants + Sized // need sized?
{
    /// Applies the S-BOX to `point`.
    fn apply_sbox(point: &mut Self::Field, compiler: &mut COM);

    /// Computes the MDS matrix multiplication against the `state`.
    ///
    /// The argument `mds_matrix` is assumed to be the flattening of a matrix
    /// of size `Self::WIDTH * Self::WIDTH`.
    #[inline]
    fn mds_matrix_multiply(
        mds_matrix: &[Self::ParameterField],
        state: &mut State<Self, COM>,
        compiler: &mut COM,
    ) {
        let mut next = Vec::with_capacity(Self::WIDTH);
        for i in 0..Self::WIDTH {
            // NOTE: clippy false-positive: Without `collect`, the two closures in `map` and
            //       `reduce` will have simultaneous `&mut` access to `compiler`. Adding `collect`
            //       allows `map` to be done before `reduce`.
            #[allow(clippy::needless_collect)]
            let linear_combination = state
                .iter()
                .enumerate()
                .map(|(j, elem)| Self::mul_const(elem, &mds_matrix[Self::WIDTH * i + j], compiler))
                .collect::<Vec<_>>();
            next.push(
                linear_combination
                    .into_iter()
                    .reduce(|acc, next| Self::add(&acc, &next, compiler))
                    .unwrap(),
            );
        }
        mem::swap(&mut next.into_boxed_slice(), &mut state.0);
    }

    /// Computes a full round on the internal permutation `state`.
    #[inline]
    fn full_round(
        additive_keys_current_round: &[Self::ParameterField],
        mds_matrix: &[Self::ParameterField],
        state: &mut State<Self, COM>,
        compiler: &mut COM,
    ) {
        for (i, elem) in state.iter_mut().enumerate() {
            Self::add_const_assign(elem, &additive_keys_current_round[i], compiler);
            Self::apply_sbox(elem, compiler);
        }
        Self::mds_matrix_multiply(mds_matrix, state, compiler);
    }

    /// Computes a partial round on the internal permutation `state`.
    #[inline]
    fn partial_round(
        additive_keys_current_round: &[Self::ParameterField],
        mds_matrix: &[Self::ParameterField],
        state: &mut State<Self, COM>,
        compiler: &mut COM,
    ) {
        for (i, elem) in state.iter_mut().enumerate() {
            Self::add_const_assign(elem, &additive_keys_current_round[i], compiler);
        }
        Self::apply_sbox(&mut state.0[0], compiler);
        Self::mds_matrix_multiply(mds_matrix, state, compiler);
    }

    /// Computes the full permutation without the first round.
    ///
    /// Unlike [`full_round`] and [`partial_round`] this takes the
    /// full array of additive round constants for the permutation.
    /// 
    /// [`full_round`]: Self::full_round
    /// [`partial_round`]: Self::partial_round
    #[inline]
    fn permute_without_first_round(
        additive_round_keys: &[Self::ParameterField],
        mds_matrix: &[Self::ParameterField],
        state: &mut State<Self, COM>,
        compiler: &mut COM,
    ) {
        for round in 1..Self::HALF_FULL_ROUNDS {
            Self::full_round(
                additive_keys::<Self, Self, COM>(additive_round_keys, round),
                mds_matrix,
                state,
                compiler,
            );
        }
        for round in Self::HALF_FULL_ROUNDS..(Self::HALF_FULL_ROUNDS + Self::PARTIAL_ROUNDS) {
            Self::partial_round(
                additive_keys::<Self, Self, COM>(additive_round_keys, round),
                mds_matrix,
                state,
                compiler,
            );
        }
        for round in (Self::HALF_FULL_ROUNDS + Self::PARTIAL_ROUNDS)
            ..(Self::FULL_ROUNDS + Self::PARTIAL_ROUNDS)
        {
            Self::full_round(
                additive_keys::<Self, Self, COM>(additive_round_keys, round),
                mds_matrix,
                state,
                compiler,
            );
        }
    }

    /// Computes the first round borrowing the `input` and `domain_tag` returning the [`State`]
    /// after the first round. This method does not check that `N + 1 = S::WIDTH`.
    #[inline]
    fn first_round_with_domain_tag_unchecked<const N: usize>(
        domain_tag: &Self::Field,
        additive_keys_current_round: &[Self::ParameterField],
        mds_matrix: &[Self::ParameterField],
        input: [&Self::Field; N],
        compiler: &mut COM,
    ) -> State<Self, COM> {
        let mut state = Vec::with_capacity(Self::WIDTH);
        for (i, point) in iter::once(domain_tag).chain(input).enumerate() {
            let mut elem = Self::add_const(point, &additive_keys_current_round[i], compiler);
            Self::apply_sbox(&mut elem, compiler);
            state.push(elem);
        }
        let mut state = State(state.into_boxed_slice());
        Self::mds_matrix_multiply(mds_matrix, &mut state, compiler);
        state
    }
}

/// Given the array of all additive round keys, returns only those
/// which are relevant to the given round.
#[inline]
pub fn additive_keys<C, F, COM>(
    additive_round_keys: &[F::ParameterField],
    round: usize,
) -> &[F::ParameterField]
where
    C: Constants,
    F: Field<COM>,
{
    let start = round * C::WIDTH;
    &additive_round_keys[start..start + C::WIDTH]
}

/// Poseidon Internal State
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(
        bound(
            deserialize = "S::Field: Deserialize<'de>",
            serialize = "S::Field: Serialize"
        ),
        crate = "openzl_util::serde",
        deny_unknown_fields
    )
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "S::Field: Clone"),
    Debug(bound = "S::Field: Debug"),
    Eq(bound = "S::Field: Eq"),
    Hash(bound = "S::Field: Hash"),
    PartialEq(bound = "S::Field: PartialEq")
)]
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

impl<S, COM> Constant<COM> for State<S, COM>
where
    S: Specification<COM> + Constant<COM>,
    S::Field: Constant<COM>,
    S::Type: Specification<Field = Const<S::Field, COM>>,
{
    type Type = State<S::Type>;

    #[inline]
    fn new_constant(this: &Self::Type, compiler: &mut COM) -> Self {
        Self(this.0.as_constant(compiler))
    }
}

impl<S> Decode for State<S>
where
    S: Specification,
    S::Field: Decode,
{
    type Error = Option<<S::Field as Decode>::Error>;

    #[inline]
    fn decode<R>(reader: R) -> Result<Self, DecodeError<R::Error, Self::Error>>
    where
        R: Read,
    {
        Ok(Self(Decode::decode(reader)?))
    }
}

impl<S> Encode for State<S>
where
    S: Specification,
    S::Field: Encode,
{
    #[inline]
    fn encode<W>(&self, writer: W) -> Result<(), W::Error>
    where
        W: Write,
    {
        self.0.encode(writer)
    }
}

impl<S, D> Sample<D> for State<S>
where
    S: Specification,
    S::Field: Sample<D>,
    D: Clone,
{
    #[inline]
    fn sample<R>(distribution: D, rng: &mut R) -> Self
    where
        R: RngCore + ?Sized,
    {
        Self(
            iter::repeat_with(|| rng.sample(distribution.clone()))
                .take(S::WIDTH)
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
            deserialize = "S::ParameterField: Deserialize<'de>",
            serialize = "S::ParameterField: Serialize"
        ),
        crate = "openzl_util::serde",
        deny_unknown_fields
    )
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "S::ParameterField: Clone"),
    Debug(bound = "S::ParameterField: Debug"),
    Eq(bound = "S::ParameterField: Eq"),
    Hash(bound = "S::ParameterField: Hash"),
    PartialEq(bound = "S::ParameterField: PartialEq")
)]
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
        Self::new_unchecked(additive_round_keys, mds_matrix)
    }

    /// Builds a new [`Permutation`] from `additive_round_keys` and `mds_matrix` without
    /// checking their sizes.
    #[inline]
    fn new_unchecked(
        additive_round_keys: Box<[S::ParameterField]>,
        mds_matrix: Box<[S::ParameterField]>,
    ) -> Self {
        Self {
            additive_round_keys,
            mds_matrix,
            __: PhantomData,
        }
    }

    /// Returns the additive keys for the given `round`.
    #[inline]
    pub fn additive_keys(&self, round: usize) -> &[S::ParameterField] {
        additive_keys::<S, S, _>(&self.additive_round_keys, round)
    }

    /// Computes a full round at the given `round` index on the internal permutation `state`.
    #[inline]
    pub fn full_round(&self, round: usize, state: &mut State<S, COM>, compiler: &mut COM) {
        let keys = self.additive_keys(round);
        S::full_round(keys, &self.mds_matrix, state, compiler)
    }

    /// Computes a partial round at the given `round` index on the internal permutation `state`.
    #[inline]
    pub fn partial_round(&self, round: usize, state: &mut State<S, COM>, compiler: &mut COM) {
        let keys = self.additive_keys(round);
        S::partial_round(keys, &self.mds_matrix, state, compiler)
    }

    /// Computes the full permutation without the first round.
    #[inline]
    fn permute_without_first_round(&self, state: &mut State<S, COM>, compiler: &mut COM) {
        S::permute_without_first_round(&self.additive_round_keys, &self.mds_matrix, state, compiler)
    }

    /// Computes the first round borrowing the `input` and `domain_tag` returning the [`State`]
    /// after the first round. This method does not check that `N + 1 = S::WIDTH`.
    #[inline]
    fn first_round_with_domain_tag_unchecked<const N: usize>(
        &self,
        domain_tag: &S::Field,
        input: [&S::Field; N],
        compiler: &mut COM,
    ) -> State<S, COM> {
        let keys = self.additive_keys(0);
        S::first_round_with_domain_tag_unchecked(
            domain_tag,
            keys,
            &self.mds_matrix,
            input,
            compiler,
        )
    }
}

impl<S, COM> Constant<COM> for Permutation<S, COM>
where
    S: Specification<COM> + Constant<COM>,
    S::Type: Specification<ParameterField = Const<S::ParameterField, COM>>,
    S::ParameterField: Constant<COM>,
{
    type Type = Permutation<S::Type>;

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

impl<S, COM> Decode for Permutation<S, COM>
where
    S: Specification<COM>,
    S::ParameterField: Decode,
{
    type Error = <S::ParameterField as Decode>::Error;

    #[inline]
    fn decode<R>(mut reader: R) -> Result<Self, DecodeError<R::Error, Self::Error>>
    where
        R: Read,
    {
        Ok(Self::new_unchecked(
            (0..S::ADDITIVE_ROUND_KEYS_COUNT)
                .map(|_| Decode::decode(&mut reader))
                .collect::<Result<_, _>>()?,
            (0..S::MDS_MATRIX_SIZE)
                .map(|_| Decode::decode(&mut reader))
                .collect::<Result<_, _>>()?,
        ))
    }
}

impl<S, COM> Encode for Permutation<S, COM>
where
    S: Specification<COM>,
    S::ParameterField: Encode,
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

impl<S, COM> PseudorandomPermutation<COM> for Permutation<S, COM>
where
    S: Specification<COM>,
{
    type Domain = State<S, COM>;

    #[inline]
    fn permute(&self, state: &mut Self::Domain, compiler: &mut COM) {
        self.full_round(0, state, compiler);
        self.permute_without_first_round(state, compiler);
    }
}

impl<S, COM> Sample for Permutation<S, COM>
where
    S: Specification<COM>,
    S::ParameterField: NativeField + FieldGeneration,
{
    #[inline]
    fn sample<R>(distribution: (), rng: &mut R) -> Self
    where
        R: RngCore + ?Sized,
    {
        let _ = (distribution, rng);
        Self::new_unchecked(
            generate_round_constants(S::WIDTH, S::FULL_ROUNDS, S::PARTIAL_ROUNDS)
                .into_boxed_slice(),
            MdsMatrices::generate_mds(S::WIDTH)
                .to_row_major()
                .into_boxed_slice(),
        )
    }
}
