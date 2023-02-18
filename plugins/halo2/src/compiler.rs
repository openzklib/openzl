//! Compiler

use crate::proofs::{arithmetic::Field, plonk::ConstraintSystem};

/// Compiler
pub struct Compiler<F>
where
    F: Field,
{
    /// Constraint System
    cs: ConstraintSystem<F>,
}

/*

///
pub struct FieldVar<F>;

///
pub struct Bool;

*/
