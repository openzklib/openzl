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

//! Poseidon Encryption Implementation

use crate::{
    constraint::{HasInput, Input},
    permutation::{
        duplex::{self, Setup, Types, Verify},
        sponge::{Read, Write},
    },
    poseidon::{Permutation, Specification, State},
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
pub struct SetupBlock<S, COM = ()>(Box<[S::Field]>)
where
    S: Specification<COM>;

impl<S, COM> Write<Permutation<S, COM>, COM> for SetupBlock<S, COM>
where
    S: Specification<COM>,
    S::Field: BlockElement<COM>,
{
    type Output = ();

    #[inline]
    fn write(&self, state: &mut State<S, COM>, compiler: &mut COM) -> Self::Output {
        for (i, elem) in state.iter_mut().skip(1).enumerate() {
            *elem = elem.add(&self.0[i], compiler);
        }
    }
}

impl<S, COM> eclair::cmp::PartialEq<Self, COM> for SetupBlock<S, COM>
where
    COM: Has<bool>,
    Bool<COM>: Constant<COM, Type = bool> + BitAnd<Bool<COM>, COM, Output = Bool<COM>>,
    S: Specification<COM>,
    S::Field: eclair::cmp::PartialEq<S::Field, COM>,
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
pub struct PlaintextBlock<S, COM = ()>(pub Box<[S::Field]>)
where
    S: Specification<COM>;

impl<S, COM> Write<Permutation<S, COM>, COM> for PlaintextBlock<S, COM>
where
    S: Specification<COM>,
    S::Field: Clone + BlockElement<COM>,
{
    type Output = CiphertextBlock<S, COM>;

    #[inline]
    fn write(&self, state: &mut State<S, COM>, compiler: &mut COM) -> Self::Output {
        for (i, elem) in state.iter_mut().skip(1).enumerate() {
            *elem = elem.add(&self.0[i], compiler);
        }
        CiphertextBlock(state.iter().skip(1).cloned().collect())
    }
}

impl<S, COM> eclair::cmp::PartialEq<Self, COM> for PlaintextBlock<S, COM>
where
    COM: Has<bool>,
    Bool<COM>: Constant<COM, Type = bool> + BitAnd<Bool<COM>, COM, Output = Bool<COM>>,
    S: Specification<COM>,
    S::Field: eclair::cmp::PartialEq<S::Field, COM>,
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

impl<S, COM> Variable<Secret, COM> for PlaintextBlock<S, COM>
where
    S: Specification<COM> + Constant<COM>,
    S::Field: Variable<Public, COM>,
    S::Type: Specification<Field = Var<S::Field, Public, COM>>,
{
    type Type = PlaintextBlock<S::Type>;

    #[inline]
    fn new_unknown(compiler: &mut COM) -> Self {
        Self(
            iter::repeat_with(|| compiler.allocate_unknown())
                .take(S::WIDTH - 1)
                .collect(),
        )
    }

    #[inline]
    fn new_known(this: &Self::Type, compiler: &mut COM) -> Self {
        Self(this.0.iter().map(|this| this.as_known(compiler)).collect())
    }
}

impl<S> Encode for PlaintextBlock<S>
where
    S: Specification,
    S::Field: Encode,
{
    #[inline]
    fn encode<W>(&self, writer: W) -> Result<(), W::Error>
    where
        W: codec::Write,
    {
        self.0.encode(writer)
    }
}

impl<S, P> Input<P> for PlaintextBlock<S>
where
    S: Specification,
    P: HasInput<S::Field> + ?Sized,
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
pub struct CiphertextBlock<S, COM = ()>(pub Box<[S::Field]>)
where
    S: Specification<COM>;

impl<S, COM> Write<Permutation<S, COM>, COM> for CiphertextBlock<S, COM>
where
    S: Specification<COM>,
    S::Field: Clone + BlockElement<COM>,
{
    type Output = PlaintextBlock<S, COM>;

    #[inline]
    fn write(&self, state: &mut State<S, COM>, compiler: &mut COM) -> Self::Output {
        let mut plaintext = Vec::new();
        for (i, elem) in state.iter_mut().skip(1).enumerate() {
            plaintext.push(self.0[i].sub(elem, compiler));
            *elem = self.0[i].clone();
        }
        PlaintextBlock(plaintext.into())
    }
}

impl<S, COM> eclair::cmp::PartialEq<Self, COM> for CiphertextBlock<S, COM>
where
    COM: Has<bool>,
    Bool<COM>: Constant<COM, Type = bool> + BitAnd<Bool<COM>, COM, Output = Bool<COM>>,
    S: Specification<COM>,
    S::Field: eclair::cmp::PartialEq<S::Field, COM>,
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

impl<S, COM> Variable<Public, COM> for CiphertextBlock<S, COM>
where
    S: Specification<COM> + Constant<COM>,
    S::Field: Variable<Public, COM>,
    S::Type: Specification<Field = Var<S::Field, Public, COM>>,
{
    type Type = CiphertextBlock<S::Type>;

    #[inline]
    fn new_unknown(compiler: &mut COM) -> Self {
        Self(
            iter::repeat_with(|| compiler.allocate_unknown())
                .take(S::WIDTH - 1)
                .collect(),
        )
    }

    #[inline]
    fn new_known(this: &Self::Type, compiler: &mut COM) -> Self {
        Self(this.0.iter().map(|this| this.as_known(compiler)).collect())
    }
}

impl<S> Encode for CiphertextBlock<S>
where
    S: Specification,
    S::Field: Encode,
{
    #[inline]
    fn encode<W>(&self, writer: W) -> Result<(), W::Error>
    where
        W: codec::Write,
    {
        self.0.encode(writer)
    }
}

impl<S, P> Input<P> for CiphertextBlock<S>
where
    S: Specification,
    P: HasInput<S::Field> + ?Sized,
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
pub type FixedPlaintext<const N: usize, S, COM = ()> = BlockArray<PlaintextBlock<S, COM>, N>;

/// Fixed Ciphertext Type
pub type FixedCiphertext<const N: usize, S, COM = ()> = BlockArray<CiphertextBlock<S, COM>, N>;

/// Authentication Tag
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
pub struct Tag<S, COM = ()>(pub S::Field)
where
    S: Specification<COM>;

impl<S, COM> Read<Permutation<S, COM>, COM> for Tag<S, COM>
where
    S: Specification<COM>,
    S::Field: Clone,
{
    #[inline]
    fn read(state: &State<S, COM>, compiler: &mut COM) -> Self {
        let _ = compiler;
        Self(state.0[1].clone())
    }
}

impl<S, COM> eclair::cmp::PartialEq<Self, COM> for Tag<S, COM>
where
    COM: Has<bool>,
    S: Specification<COM>,
    S::Field: eclair::cmp::PartialEq<S::Field, COM>,
{
    #[inline]
    fn eq(&self, rhs: &Self, compiler: &mut COM) -> Bool<COM> {
        self.0.eq(&rhs.0, compiler)
    }
}

impl<S, COM> Variable<Public, COM> for Tag<S, COM>
where
    S: Specification<COM> + Constant<COM>,
    S::Field: Variable<Public, COM>,
    S::Type: Specification<Field = Var<S::Field, Public, COM>>,
{
    type Type = Tag<S::Type>;

    #[inline]
    fn new_unknown(compiler: &mut COM) -> Self {
        Self(compiler.allocate_unknown())
    }

    #[inline]
    fn new_known(this: &Self::Type, compiler: &mut COM) -> Self {
        Self(this.0.as_known(compiler))
    }
}

impl<S> Encode for Tag<S>
where
    S: Specification,
    S::Field: Encode,
{
    #[inline]
    fn encode<W>(&self, writer: W) -> Result<(), W::Error>
    where
        W: codec::Write,
    {
        self.0.encode(writer)
    }
}

impl<S, P> Input<P> for Tag<S>
where
    S: Specification,
    P: HasInput<S::Field> + ?Sized,
{
    #[inline]
    fn extend(&self, input: &mut P::Input) {
        P::extend(input, &self.0)
    }
}

/// Fixed Encryption Configuration
/* TODO:
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
*/
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "S::Field: Clone"),
    Debug(bound = "S::Field: Debug"),
    Eq(bound = "S::Field: Eq"),
    Hash(bound = "S::Field: Hash"),
    PartialEq(bound = "S::Field: PartialEq")
)]
pub struct FixedEncryption<const N: usize, S, COM = ()>
where
    S: Specification<COM>,
{
    /// Initial State
    pub initial_state: State<S, COM>,
}

impl<const N: usize, S, COM> Constant<COM> for FixedEncryption<N, S, COM>
where
    S: Specification<COM> + Constant<COM>,
    S::Type: Specification,
    State<S, COM>: Constant<COM, Type = State<S::Type>>,
{
    type Type = FixedEncryption<N, S::Type>;

    #[inline]
    fn new_constant(this: &Self::Type, compiler: &mut COM) -> Self {
        Self {
            initial_state: this.initial_state.as_constant(compiler),
        }
    }
}

impl<const N: usize, S> Decode for FixedEncryption<N, S>
where
    S: Specification,
    State<S>: Decode,
{
    type Error = <State<S> as Decode>::Error;

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

impl<const N: usize, S> Encode for FixedEncryption<N, S>
where
    S: Specification,
    State<S>: Encode,
{
    #[inline]
    fn encode<W>(&self, writer: W) -> Result<(), W::Error>
    where
        W: codec::Write,
    {
        self.initial_state.encode(writer)
    }
}

impl<const N: usize, S, D> Sample<D> for FixedEncryption<N, S>
where
    S: Specification,
    State<S>: Sample<D>,
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

impl<const N: usize, S, COM> Types<Permutation<S, COM>, COM> for FixedEncryption<N, S, COM>
where
    S: Specification<COM>,
    S::Field: Clone + BlockElement<COM>,
{
    type Key = Vec<S::Field>;
    type Header = Vec<S::Field>;
    type SetupBlock = SetupBlock<S, COM>;
    type PlaintextBlock = PlaintextBlock<S, COM>;
    type Plaintext = FixedPlaintext<N, S, COM>;
    type CiphertextBlock = CiphertextBlock<S, COM>;
    type Ciphertext = FixedCiphertext<N, S, COM>;
    type Tag = Tag<S, COM>;
}

impl<const N: usize, S, COM> Setup<Permutation<S, COM>, COM> for FixedEncryption<N, S, COM>
where
    S: Specification<COM>,
    S::Field: Clone + BlockElement<COM> + Zero<COM>,
{
    #[inline]
    fn initialize(&self, compiler: &mut COM) -> State<S, COM> {
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
        let mut blocks = padded_chunks_with(key.as_slice(), S::WIDTH - 1, || Zero::zero(compiler)); // TODO is this a real error? &mut compiler vs &mut ()
        blocks.extend(padded_chunks_with(header.as_slice(), S::WIDTH - 1, || {
            Zero::zero(compiler)
        }));
        blocks
            .into_iter()
            .map(|b| SetupBlock(b.into_boxed_slice()))
            .collect()
    }
}

impl<const N: usize, S> Verify<Permutation<S>> for FixedEncryption<N, S>
where
    S: Specification,
    S::Field: Clone + PartialEq + BlockElement,
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
