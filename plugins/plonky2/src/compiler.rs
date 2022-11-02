//! Plonky2 Compiler

use plonky2::{
    field::extension::Extendable, hash::hash_types::RichField,
    plonk::circuit_builder::CircuitBuilder,
};

/// Compiler
pub struct Compiler<F, const D: usize>(pub CircuitBuilder<F, D>)
where
    F: RichField + Extendable<D>;
