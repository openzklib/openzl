//! Poseidon Encryption Implementation

use crate::{
    constraint::{HasInput, Input},
    permutation::{
        duplex::{self, Setup, Types, Verify},
        sponge::{Read, Write},
    },
    poseidon::{Field, Permutation, State},
};
use alloc::{boxed::Box, vec::Vec};
use core::{fmt::Debug, hash::Hash, iter, ops::Deref, slice};
use eclair::{
    self,
    alloc::{
        mode::{Public, Secret},
        Allocate, Allocator, Constant, Var, Variable,
    },
    bool::{Assert, Bool},
    num::Zero,
    ops::BitAnd,
    Has,
};
use openzl_util::{
    codec::{self, Decode, DecodeError, Encode},
    rand::{Rand, RngCore, Sample},
    vec::padded_chunks_with,
    BoxArray,
};

#[cfg(feature = "serde")]
use openzl_util::serde::{Deserialize, Serialize};

/// Fixed Encryption Duplexer
pub type FixedDuplexer<const N: usize, S, COM = ()> =
    duplex::Duplexer<Permutation<S, COM>, FixedEncryption<N, S, COM>, COM>;

/// Block Element
pub trait BlockElement<COM = ()> {
    /// Adds `self` to `rhs`.
    fn add(&self, rhs: &Self, compiler: &mut COM) -> Self;

    /// Subtracts `rhs` from `self`.
    fn sub(&self, rhs: &Self, compiler: &mut COM) -> Self;
}

/// Setup Block
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
pub struct SetupBlock<F, COM = ()>(Box<[F::Field]>)
where
    F: Field<COM>;

impl<F, COM> Write<Permutation<F, COM>, COM> for SetupBlock<F, COM>
where
    F: Field<COM>,
    F::Field: BlockElement<COM>,
{
    type Output = ();

    #[inline]
    fn write(&self, state: &mut State<F, COM>, compiler: &mut COM) -> Self::Output {
        for (i, elem) in state.iter_mut().skip(1).enumerate() {
            *elem = elem.add(&self.0[i], compiler);
        }
    }
}

impl<F, COM> eclair::cmp::PartialEq<Self, COM> for SetupBlock<F, COM>
where
    COM: Has<bool>,
    Bool<COM>: Constant<COM, Type = bool> + BitAnd<Bool<COM>, COM, Output = Bool<COM>>,
    F: Field<COM>,
    F::Field: eclair::cmp::PartialEq<F::Field, COM>,
{
    #[inline]
    fn eq(&self, rhs: &Self, compiler: &mut COM) -> Bool<COM> {
        self.0.eq(&rhs.0, compiler)
    }

    #[inline]
    fn assert_equal(&self, rhs: &Self, compiler: &mut COM)
    where
        COM: Assert,
    {
        self.0.assert_equal(&rhs.0, compiler)
    }
}

/// Plaintext Block
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
pub struct PlaintextBlock<F, COM = ()>(pub Box<[F::Field]>)
where
    F: Field<COM>;

impl<F, COM> Write<Permutation<F, COM>, COM> for PlaintextBlock<F, COM>
where
    F: Field<COM>,
    F::Field: Clone + BlockElement<COM>,
{
    type Output = CiphertextBlock<F, COM>;

    #[inline]
    fn write(&self, state: &mut State<F, COM>, compiler: &mut COM) -> Self::Output {
        for (i, elem) in state.iter_mut().skip(1).enumerate() {
            *elem = elem.add(&self.0[i], compiler);
        }
        CiphertextBlock(state.iter().skip(1).cloned().collect())
    }
}

impl<F, COM> eclair::cmp::PartialEq<Self, COM> for PlaintextBlock<F, COM>
where
    COM: Has<bool>,
    Bool<COM>: Constant<COM, Type = bool> + BitAnd<Bool<COM>, COM, Output = Bool<COM>>,
    F: Field<COM>,
    F::Field: eclair::cmp::PartialEq<F::Field, COM>,
{
    #[inline]
    fn eq(&self, rhs: &Self, compiler: &mut COM) -> Bool<COM> {
        self.0.eq(&rhs.0, compiler)
    }

    #[inline]
    fn assert_equal(&self, rhs: &Self, compiler: &mut COM)
    where
        COM: Assert,
    {
        self.0.assert_equal(&rhs.0, compiler)
    }
}

impl<F, COM> Variable<Secret, COM> for PlaintextBlock<F, COM>
where
    F: Field<COM> + Constant<COM>,
    F::Field: Variable<Public, COM>,
    F::Type: Field<Field = Var<F::Field, Public, COM>>,
{
    type Type = PlaintextBlock<F::Type>;

    #[inline]
    fn new_unknown(compiler: &mut COM) -> Self {
        Self(
            iter::repeat_with(|| compiler.allocate_unknown())
                .take(F::WIDTH - 1)
                .collect(),
        )
    }

    #[inline]
    fn new_known(this: &Self::Type, compiler: &mut COM) -> Self {
        Self(this.0.iter().map(|this| this.as_known(compiler)).collect())
    }
}

impl<F> Encode for PlaintextBlock<F>
where
    F: Field,
    F::Field: Encode,
{
    #[inline]
    fn encode<W>(&self, writer: W) -> Result<(), W::Error>
    where
        W: codec::Write,
    {
        self.0.encode(writer)
    }
}

impl<F, P> Input<P> for PlaintextBlock<F>
where
    F: Field,
    P: HasInput<F::Field> + ?Sized,
{
    #[inline]
    fn extend(&self, input: &mut P::Input) {
        for element in self.0.iter() {
            P::extend(input, element);
        }
    }
}

/// Ciphertext Block
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
pub struct CiphertextBlock<F, COM = ()>(pub Box<[F::Field]>)
where
    F: Field<COM>;

impl<F, COM> Write<Permutation<F, COM>, COM> for CiphertextBlock<F, COM>
where
    F: Field<COM>,
    F::Field: Clone + BlockElement<COM>,
{
    type Output = PlaintextBlock<F, COM>;

    #[inline]
    fn write(&self, state: &mut State<F, COM>, compiler: &mut COM) -> Self::Output {
        let mut plaintext = Vec::new();
        for (i, elem) in state.iter_mut().skip(1).enumerate() {
            plaintext.push(self.0[i].sub(elem, compiler));
            *elem = self.0[i].clone();
        }
        PlaintextBlock(plaintext.into())
    }
}

impl<F, COM> eclair::cmp::PartialEq<Self, COM> for CiphertextBlock<F, COM>
where
    COM: Has<bool>,
    Bool<COM>: Constant<COM, Type = bool> + BitAnd<Bool<COM>, COM, Output = Bool<COM>>,
    F: Field<COM>,
    F::Field: eclair::cmp::PartialEq<F::Field, COM>,
{
    #[inline]
    fn eq(&self, rhs: &Self, compiler: &mut COM) -> Bool<COM> {
        self.0.eq(&rhs.0, compiler)
    }

    #[inline]
    fn assert_equal(&self, rhs: &Self, compiler: &mut COM)
    where
        COM: Assert,
    {
        self.0.assert_equal(&rhs.0, compiler)
    }
}

impl<F, COM> Variable<Public, COM> for CiphertextBlock<F, COM>
where
    F: Field<COM> + Constant<COM>,
    F::Field: Variable<Public, COM>,
    F::Type: Field<Field = Var<F::Field, Public, COM>>,
{
    type Type = CiphertextBlock<F::Type>;

    #[inline]
    fn new_unknown(compiler: &mut COM) -> Self {
        Self(
            iter::repeat_with(|| compiler.allocate_unknown())
                .take(F::WIDTH - 1)
                .collect(),
        )
    }

    #[inline]
    fn new_known(this: &Self::Type, compiler: &mut COM) -> Self {
        Self(this.0.iter().map(|this| this.as_known(compiler)).collect())
    }
}

impl<F> Encode for CiphertextBlock<F>
where
    F: Field,
    F::Field: Encode,
{
    #[inline]
    fn encode<W>(&self, writer: W) -> Result<(), W::Error>
    where
        W: codec::Write,
    {
        self.0.encode(writer)
    }
}

impl<F, P> Input<P> for CiphertextBlock<F>
where
    F: Field,
    P: HasInput<F::Field> + ?Sized,
{
    #[inline]
    fn extend(&self, input: &mut P::Input) {
        for element in self.0.iter() {
            P::extend(input, element);
        }
    }
}

/// Block Array
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(
        bound(deserialize = "B: Deserialize<'de>", serialize = "B: Serialize"),
        crate = "openzl_util::serde",
        deny_unknown_fields
    )
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "B: Clone"),
    Debug(bound = "B: Debug"),
    Eq(bound = "B: Eq"),
    Hash(bound = "B: Hash"),
    PartialEq(bound = "B: PartialEq")
)]
pub struct BlockArray<B, const N: usize>(pub BoxArray<B, N>);

impl<B, const N: usize> Deref for BlockArray<B, N> {
    type Target = BoxArray<B, N>;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<B, const N: usize> FromIterator<B> for BlockArray<B, N> {
    #[inline]
    fn from_iter<I>(iter: I) -> Self
    where
        I: IntoIterator<Item = B>,
    {
        Self(iter.into_iter().collect())
    }
}

impl<'b, B, const N: usize> IntoIterator for &'b BlockArray<B, N> {
    type Item = &'b B;
    type IntoIter = slice::Iter<'b, B>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl<B, const N: usize> Encode for BlockArray<B, N>
where
    B: Encode,
{
    #[inline]
    fn encode<W>(&self, writer: W) -> Result<(), W::Error>
    where
        W: codec::Write,
    {
        self.0.encode(writer)
    }
}

impl<B, const N: usize, P> Input<P> for BlockArray<B, N>
where
    P: HasInput<B> + ?Sized,
{
    #[inline]
    fn extend(&self, input: &mut P::Input) {
        for block in &self.0 {
            P::extend(input, block);
        }
    }
}

impl<B, const N: usize, COM> eclair::cmp::PartialEq<Self, COM> for BlockArray<B, N>
where
    COM: Has<bool>,
    Bool<COM>: Constant<COM, Type = bool> + BitAnd<Bool<COM>, COM, Output = Bool<COM>>,
    B: eclair::cmp::PartialEq<B, COM>,
{
    #[inline]
    fn eq(&self, rhs: &Self, compiler: &mut COM) -> Bool<COM> {
        self.0.eq(&rhs.0, compiler)
    }

    #[inline]
    fn assert_equal(&self, rhs: &Self, compiler: &mut COM)
    where
        COM: Assert,
    {
        self.0.assert_equal(&rhs.0, compiler)
    }
}

impl<B, const N: usize, M, COM> Variable<M, COM> for BlockArray<B, N>
where
    B: Variable<M, COM>,
{
    type Type = BlockArray<B::Type, N>;

    #[inline]
    fn new_unknown(compiler: &mut COM) -> Self {
        Self(compiler.allocate_unknown())
    }

    #[inline]
    fn new_known(this: &Self::Type, compiler: &mut COM) -> Self {
        Self(this.0.as_known(compiler))
    }
}

/// Fixed Plaintext Type
pub type FixedPlaintext<const N: usize, F, COM = ()> = BlockArray<PlaintextBlock<F, COM>, N>;

/// Fixed Ciphertext Type
pub type FixedCiphertext<const N: usize, F, COM = ()> = BlockArray<CiphertextBlock<F, COM>, N>;

/// Authentication Tag
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
pub struct Tag<F, COM = ()>(pub F::Field)
where
    F: Field<COM>;

impl<F, COM> Read<Permutation<F, COM>, COM> for Tag<F, COM>
where
    F: Field<COM>,
    F::Field: Clone,
{
    #[inline]
    fn read(state: &State<F, COM>, compiler: &mut COM) -> Self {
        let _ = compiler;
        Self(state.0[1].clone())
    }
}

impl<F, COM> eclair::cmp::PartialEq<Self, COM> for Tag<F, COM>
where
    COM: Has<bool>,
    F: Field<COM>,
    F::Field: eclair::cmp::PartialEq<F::Field, COM>,
{
    #[inline]
    fn eq(&self, rhs: &Self, compiler: &mut COM) -> Bool<COM> {
        self.0.eq(&rhs.0, compiler)
    }
}

impl<F, COM> Variable<Public, COM> for Tag<F, COM>
where
    F: Field<COM> + Constant<COM>,
    F::Field: Variable<Public, COM>,
    F::Type: Field<Field = Var<F::Field, Public, COM>>,
{
    type Type = Tag<F::Type>;

    #[inline]
    fn new_unknown(compiler: &mut COM) -> Self {
        Self(compiler.allocate_unknown())
    }

    #[inline]
    fn new_known(this: &Self::Type, compiler: &mut COM) -> Self {
        Self(this.0.as_known(compiler))
    }
}

impl<F> Encode for Tag<F>
where
    F: Field,
    F::Field: Encode,
{
    #[inline]
    fn encode<W>(&self, writer: W) -> Result<(), W::Error>
    where
        W: codec::Write,
    {
        self.0.encode(writer)
    }
}

impl<F, P> Input<P> for Tag<F>
where
    F: Field,
    P: HasInput<F::Field> + ?Sized,
{
    #[inline]
    fn extend(&self, input: &mut P::Input) {
        P::extend(input, &self.0)
    }
}

/// Fixed Encryption Configuration
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
pub struct FixedEncryption<const N: usize, F, COM = ()>
where
    F: Field<COM>,
{
    /// Initial State
    pub initial_state: State<F, COM>,
}

impl<const N: usize, F, COM> Constant<COM> for FixedEncryption<N, F, COM>
where
    F: Field<COM> + Constant<COM>,
    F::Type: Field,
    State<F, COM>: Constant<COM, Type = State<F::Type>>,
{
    type Type = FixedEncryption<N, F::Type>;

    #[inline]
    fn new_constant(this: &Self::Type, compiler: &mut COM) -> Self {
        Self {
            initial_state: this.initial_state.as_constant(compiler),
        }
    }
}

impl<const N: usize, F> Decode for FixedEncryption<N, F>
where
    F: Field,
    State<F>: Decode,
{
    type Error = <State<F> as Decode>::Error;

    #[inline]
    fn decode<R>(reader: R) -> Result<Self, DecodeError<R::Error, Self::Error>>
    where
        R: codec::Read,
    {
        Ok(Self {
            initial_state: Decode::decode(reader)?,
        })
    }
}

impl<const N: usize, F> Encode for FixedEncryption<N, F>
where
    F: Field,
    State<F>: Encode,
{
    #[inline]
    fn encode<W>(&self, writer: W) -> Result<(), W::Error>
    where
        W: codec::Write,
    {
        self.initial_state.encode(writer)
    }
}

impl<const N: usize, F, D> Sample<D> for FixedEncryption<N, F>
where
    F: Field,
    State<F>: Sample<D>,
{
    #[inline]
    fn sample<R>(distribution: D, rng: &mut R) -> Self
    where
        R: RngCore + ?Sized,
    {
        Self {
            initial_state: rng.sample(distribution),
        }
    }
}

impl<const N: usize, F, COM> Types<Permutation<F, COM>, COM> for FixedEncryption<N, F, COM>
where
    F: Field<COM>,
    F::Field: Clone + BlockElement<COM>,
{
    type Key = Vec<F::Field>;
    type Header = Vec<F::Field>;
    type SetupBlock = SetupBlock<F, COM>;
    type PlaintextBlock = PlaintextBlock<F, COM>;
    type Plaintext = FixedPlaintext<N, F, COM>;
    type CiphertextBlock = CiphertextBlock<F, COM>;
    type Ciphertext = FixedCiphertext<N, F, COM>;
    type Tag = Tag<F, COM>;
}

impl<const N: usize, F, COM> Setup<Permutation<F, COM>, COM> for FixedEncryption<N, F, COM>
where
    F: Field<COM>,
    F::Field: Clone + BlockElement<COM> + Zero<COM>,
{
    #[inline]
    fn initialize(&self, compiler: &mut COM) -> State<F, COM> {
        let _ = compiler;
        self.initial_state.clone()
    }

    #[inline]
    fn setup(
        &self,
        key: &Self::Key,
        header: &Self::Header,
        compiler: &mut COM,
    ) -> Vec<Self::SetupBlock> {
        let mut blocks = padded_chunks_with(key.as_slice(), F::WIDTH - 1, || Zero::zero(compiler));
        blocks.extend(padded_chunks_with(header.as_slice(), F::WIDTH - 1, || {
            Zero::zero(compiler)
        }));
        blocks
            .into_iter()
            .map(|b| SetupBlock(b.into_boxed_slice()))
            .collect()
    }
}

impl<const N: usize, F> Verify<Permutation<F>> for FixedEncryption<N, F>
where
    F: Field,
    F::Field: Clone + PartialEq + BlockElement,
{
    type Verification = bool;

    #[inline]
    fn verify(
        &self,
        encryption_tag: &Self::Tag,
        decryption_tag: &Self::Tag,
        _: &mut (),
    ) -> Self::Verification {
        encryption_tag == decryption_tag
    }
}
