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

//! Poseidon Hash Implementation

use crate::{
    hash::ArrayHashFunction,
    poseidon::{
        Field, FieldGeneration, NativeField, ParameterFieldType, Permutation, Specification,
    },
};
use alloc::vec::Vec;
use core::{fmt::Debug, hash::Hash, marker::PhantomData};
use eclair::alloc::{Allocate, Const, Constant};
use openzl_util::{
    codec::{Decode, DecodeError, Encode, Read, Write},
    rand::{Rand, RngCore, Sample},
    vec::VecExt,
};

#[cfg(feature = "serde")]
use openzl_util::serde::{Deserialize, Serialize};

/// Domain Tag
pub trait DomainTag<T>
where
    T: ParameterFieldType,
{
    /// Generates domain tag as a constant parameter.
    fn domain_tag() -> T::ParameterField;
}

/// Poseidon Hasher
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(
        bound(
            deserialize = "Permutation<F, COM>: Deserialize<'de>, F::Field: Deserialize<'de>",
            serialize = "Permutation<F, COM>: Serialize, F::Field: Serialize"
        ),
        crate = "openzl_util::serde",
        deny_unknown_fields
    )
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "Permutation<F, COM>: Clone, F::Field: Clone"),
    Debug(bound = "Permutation<F, COM>: Debug, F::Field: Debug"),
    Eq(bound = "Permutation<F, COM>: Eq, F::Field: Eq"),
    Hash(bound = "Permutation<F, COM>: Hash, F::Field: Hash"),
    PartialEq(bound = "Permutation<F, COM>: PartialEq, F::Field: PartialEq")
)]
pub struct Hasher<F, T, const ARITY: usize, COM = ()>
where
    F: Field<COM>,
    T: DomainTag<F>,
{
    /// Poseidon Permutation
    permutation: Permutation<F, COM>,

    /// Domain Tag
    domain_tag: F::Field,

    /// Type Parameter Marker
    __: PhantomData<T>,
}

impl<F, T, const ARITY: usize, COM> Hasher<F, T, ARITY, COM>
where
    F: Field<COM>,
    T: DomainTag<F>,
{
    /// Builds a new [`Hasher`] over `permutation` and `domain_tag` without checking that
    /// `ARITY + 1 == S::WIDTH`.
    #[inline]
    fn new_unchecked(permutation: Permutation<F, COM>, domain_tag: F::Field) -> Self {
        Self {
            permutation,
            domain_tag,
            __: PhantomData,
        }
    }

    /// Builds a new [`Hasher`] over `permutation` and `domain_tag`.
    #[inline]
    pub fn new(permutation: Permutation<F, COM>, domain_tag: F::Field) -> Self {
        assert_eq!(ARITY + 1, F::WIDTH);
        Self::new_unchecked(permutation, domain_tag)
    }

    /// Builds a new [`Hasher`] over `permutation` using `T` to generate the domain tag.
    #[inline]
    pub fn from_permutation(permutation: Permutation<F, COM>) -> Self {
        Self::new(permutation, F::from_parameter(T::domain_tag()))
    }

    /// Computes the hash over `input` in the given `compiler` and returns the untruncated state.
    #[inline]
    pub fn hash_untruncated(&self, input: [&F::Field; ARITY], compiler: &mut COM) -> Vec<F::Field> {
        let mut state = self.permutation.first_round_with_domain_tag_unchecked(
            &self.domain_tag,
            input,
            compiler,
        );
        self.permutation
            .permute_without_first_round(&mut state, compiler);
        state.0.into_vec()
    }
}

impl<F, T, const ARITY: usize, COM> Constant<COM> for Hasher<F, T, ARITY, COM>
where
    F: Field<COM> + Constant<COM>,
    F::Type: Field<ParameterField = Const<F::ParameterField, COM>>,
    F::ParameterField: Constant<COM>,
    T: DomainTag<F> + Constant<COM>,
    T::Type: DomainTag<F::Type>,
{
    type Type = Hasher<F::Type, T::Type, ARITY>;

    #[inline]
    fn new_constant(this: &Self::Type, compiler: &mut COM) -> Self {
        Self::from_permutation(this.permutation.as_constant(compiler))
    }
}

impl<F, T, const ARITY: usize, COM> ArrayHashFunction<ARITY, COM> for Hasher<F, T, ARITY, COM>
where
    F: Field<COM>,
    T: DomainTag<F>,
{
    type Input = F::Field;
    type Output = F::Field;

    #[inline]
    fn hash(&self, input: [&Self::Input; ARITY], compiler: &mut COM) -> Self::Output {
        self.hash_untruncated(input, compiler).take_first()
    }
}

impl<F, T, const ARITY: usize, COM> Decode for Hasher<F, T, ARITY, COM>
where
    F: Field<COM>,
    F::Field: Decode,
    F::ParameterField: Decode<Error = <F::Field as Decode>::Error>,
    T: DomainTag<F>,
{
    type Error = <F::Field as Decode>::Error;

    #[inline]
    fn decode<R>(mut reader: R) -> Result<Self, DecodeError<R::Error, Self::Error>>
    where
        R: Read,
    {
        Ok(Self::new(
            Decode::decode(&mut reader)?,
            Decode::decode(&mut reader)?,
        ))
    }
}

impl<F, T, const ARITY: usize, COM> Encode for Hasher<F, T, ARITY, COM>
where
    F: Field<COM>,
    F::Field: Encode,
    F::ParameterField: Encode,
    T: DomainTag<F>,
{
    #[inline]
    fn encode<W>(&self, mut writer: W) -> Result<(), W::Error>
    where
        W: Write,
    {
        self.permutation.encode(&mut writer)?;
        self.domain_tag.encode(&mut writer)?;
        Ok(())
    }
}

impl<F, T, const ARITY: usize, COM> Sample for Hasher<F, T, ARITY, COM>
where
    F: Field<COM>,
    F::ParameterField: NativeField + FieldGeneration,
    T: DomainTag<F>,
{
    #[inline]
    fn sample<R>(distribution: (), rng: &mut R) -> Self
    where
        R: RngCore + ?Sized,
    {
        Self::from_permutation(rng.sample(distribution))
    }
}

/* TODO: After upgrading to new Poseidon, we have to enable these tests.
/// Testing Suite
#[cfg(test)]
mod test {
    use crate::{config::Poseidon2, crypto::constraint::arkworks::Fp};
    use ark_bls12_381::Fr;
    use manta_crypto::{
        arkworks::ff::field_new,
        rand::{OsRng, Sample},
    };

    /// Tests if [`Poseidon2`](crate::config::Poseidon2) matches hardcoded sage outputs.
    #[test]
    fn poseidon_hash_matches_known_values() {
        let hasher = Poseidon2::gen(&mut OsRng);
        let inputs = [&Fp(field_new!(Fr, "1")), &Fp(field_new!(Fr, "2"))];
        assert_eq!(
            hasher.hash_untruncated(inputs, &mut ()),
            include!("permutation_hardcoded_test/width3")
        );
    }
}
*/
