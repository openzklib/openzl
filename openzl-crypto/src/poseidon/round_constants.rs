//! Round Constants Generation

use crate::poseidon::{lfsr::GrainLFSR, FieldGeneration};
use alloc::vec::Vec;
use core::iter;

/// Samples field elements of type `F` from an iterator over random bits `iter` with rejection
/// sampling.
#[inline]
pub fn sample_field_element<F, I>(iter: I) -> F
where
    F: FieldGeneration,
    I: IntoIterator<Item = bool>,
{
    let mut iter = iter.into_iter();
    loop {
        let bits = iter.by_ref().take(F::MODULUS_BITS).collect::<Vec<_>>();
        if let Some(f) = F::try_from_bits_be(&bits) {
            return f;
        }
    }
}

/// Generates the [`GrainLFSR`] for the parameter configuration of a field with `modulus_bits` and a
/// Poseidon configuration with `width`, `full_rounds`, and `partial_rounds`.
#[inline]
pub fn generate_lfsr(
    modulus_bits: usize,
    width: usize,
    full_rounds: usize,
    partial_rounds: usize,
) -> GrainLFSR {
    GrainLFSR::from_seed([
        (2, 1),
        (4, 0),
        (12, modulus_bits as u128),
        (12, width as u128),
        (10, full_rounds as u128),
        (10, partial_rounds as u128),
        (30, 0b111111111111111111111111111111u128),
    ])
}

/// Generates the round constants for Poseidon by sampling
/// `width * (full_rounds + partial_rounds)`-many field elements using [`sample_field_element`].
#[inline]
pub fn generate_round_constants<F>(
    width: usize,
    full_rounds: usize,
    partial_rounds: usize,
) -> Vec<F>
where
    F: FieldGeneration,
{
    let mut lfsr = generate_lfsr(F::MODULUS_BITS, width, full_rounds, partial_rounds);
    iter::from_fn(|| Some(sample_field_element(&mut lfsr)))
        .take(width * (full_rounds + partial_rounds))
        .collect()
}
