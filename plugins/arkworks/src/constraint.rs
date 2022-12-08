//! Arkworks Constraint System

use crate::{
    ff::{FpParameters, PrimeField},
    r1cs_std::{alloc::AllocVar, eq::EqGadget, select::CondSelectGadget, ToBitsGadget},
    relations::{
        ns,
        r1cs::{
            ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, OptimizationGoal,
            SynthesisMode,
        },
    },
};
use alloc::vec::Vec;
use eclair::{
    alloc::{
        mode::{self, Public, Secret},
        Constant, Variable,
    },
    bool::{Assert, BitDecomposition, ConditionalSwap},
    num::AssertWithinBitRange,
    ops::Add,
    Has,
};
use openzl_crypto::constraint::measure::{Count, Measure};
use openzl_util::derivative;

pub use crate::{
    r1cs_std::{bits::boolean::Boolean, fields::fp::FpVar},
    relations::r1cs::SynthesisError,
};

/// Synthesis Result
pub type SynthesisResult<T = ()> = Result<T, SynthesisError>;

/// Returns an empty variable assignment for setup mode.
///
/// # Warning
///
/// This does not work for all variable assignments! For some assignments, the variable inherits
/// some structure from its input, like its length or number of bits, which are only known at
/// run-time. For those cases, some mocking is required and this function can not be used directly.
#[inline]
pub fn empty<T>() -> SynthesisResult<T> {
    Err(SynthesisError::AssignmentMissing)
}

/// Returns a filled variable assignment with the given `value`.
#[inline]
pub fn full<T>(value: T) -> impl FnOnce() -> SynthesisResult<T> {
    move || Ok(value)
}

/// Arkworks Rank-1 Constraint System
#[derive(derivative::Derivative)]
#[derivative(Clone, Debug)]
pub struct R1CS<F>(ConstraintSystemRef<F>)
where
    F: PrimeField;

impl<F> R1CS<F>
where
    F: PrimeField,
{
    /// Builds a new [`R1CS`] constraint system from `constraint_system` without checking its
    /// optimization goal or synthesis mode.
    #[inline]
    pub fn new_unchecked(constraint_system: ConstraintSystemRef<F>) -> Self {
        Self(constraint_system)
    }

    /// Constructs a new constraint system which is ready for unknown variables.
    #[inline]
    pub fn for_contexts() -> Self {
        // FIXME: This might not be the right setup for all proof systems.
        let constraint_system = ConstraintSystem::new_ref();
        constraint_system.set_optimization_goal(OptimizationGoal::Constraints);
        constraint_system.set_mode(SynthesisMode::Setup);
        Self::new_unchecked(constraint_system)
    }

    /// Constructs a new constraint system which is ready for known variables.
    #[inline]
    pub fn for_proofs() -> Self {
        // FIXME: This might not be the right setup for all proof systems.
        let constraint_system = ConstraintSystem::new_ref();
        constraint_system.set_optimization_goal(OptimizationGoal::Constraints);
        Self::new_unchecked(constraint_system)
    }

    /// Check if all constraints are satisfied.
    #[inline]
    pub fn is_satisfied(&self) -> bool {
        self.0
            .is_satisfied()
            .expect("Checking circuit satisfaction is not allowed to fail.")
    }
}

impl<F> Has<bool> for R1CS<F>
where
    F: PrimeField,
{
    type Type = Boolean<F>;
}

impl<F> Assert for R1CS<F>
where
    F: PrimeField,
{
    #[inline]
    fn assert(&mut self, b: &Boolean<F>) {
        b.enforce_equal(&Boolean::TRUE)
            .expect("Enforcing equality is not allowed to fail.");
    }
}

impl<F, const BITS: usize> AssertWithinBitRange<FpVar<F>, BITS> for R1CS<F>
where
    F: PrimeField,
{
    #[inline]
    fn assert_within_range(&mut self, value: &FpVar<F>) {
        assert!(
            BITS < F::Params::MODULUS_BITS as usize,
            "BITS must be strictly less than modulus bits of `F`."
        );
        let value_bits =
            ToBitsGadget::to_bits_le(value).expect("Bit decomposition is not allowed to fail.");
        for bit in &value_bits[BITS..] {
            bit.enforce_equal(&Boolean::FALSE)
                .expect("Enforcing equality is not allowed to fail.");
        }
    }
}

impl<F> Count<mode::Constant> for R1CS<F> where F: PrimeField {}

impl<F> Count<Public> for R1CS<F>
where
    F: PrimeField,
{
    #[inline]
    fn count(&self) -> Option<usize> {
        Some(self.0.num_instance_variables())
    }
}

impl<F> Count<Secret> for R1CS<F>
where
    F: PrimeField,
{
    #[inline]
    fn count(&self) -> Option<usize> {
        Some(self.0.num_witness_variables())
    }
}

impl<F> Measure for R1CS<F>
where
    F: PrimeField,
{
    #[inline]
    fn constraint_count(&self) -> usize {
        self.0.num_constraints()
    }
}

impl<F> ConstraintSynthesizer<F> for R1CS<F>
where
    F: PrimeField,
{
    /// Generates constraints for `self` by copying them into `cs`. This method is necessary to hook
    /// into the proof system traits defined in `arkworks`.
    #[inline]
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> SynthesisResult {
        let precomputed_cs = self
            .0
            .into_inner()
            .expect("We own this constraint system so we can consume it.");
        let mut target_cs = cs
            .borrow_mut()
            .expect("This is given to us to mutate so it can't be borrowed by anyone else.");
        *target_cs = precomputed_cs;
        Ok(())
    }
}

impl<F> Constant<R1CS<F>> for Boolean<F>
where
    F: PrimeField,
{
    type Type = bool;

    #[inline]
    fn new_constant(this: &Self::Type, compiler: &mut R1CS<F>) -> Self {
        AllocVar::new_constant(ns!(compiler.0, "boolean constant"), this)
            .expect("Variable allocation is not allowed to fail.")
    }
}

impl<F> Variable<Public, R1CS<F>> for Boolean<F>
where
    F: PrimeField,
{
    type Type = bool;

    #[inline]
    fn new_known(this: &Self::Type, compiler: &mut R1CS<F>) -> Self {
        Self::new_input(ns!(compiler.0, "boolean public input"), full(this))
            .expect("Variable allocation is not allowed to fail.")
    }

    #[inline]
    fn new_unknown(compiler: &mut R1CS<F>) -> Self {
        Self::new_input(ns!(compiler.0, "boolean public input"), empty::<bool>)
            .expect("Variable allocation is not allowed to fail.")
    }
}

impl<F> Variable<Secret, R1CS<F>> for Boolean<F>
where
    F: PrimeField,
{
    type Type = bool;

    #[inline]
    fn new_known(this: &Self::Type, compiler: &mut R1CS<F>) -> Self {
        Self::new_witness(ns!(compiler.0, "boolean secret witness"), full(this))
            .expect("Variable allocation is not allowed to fail.")
    }

    #[inline]
    fn new_unknown(compiler: &mut R1CS<F>) -> Self {
        Self::new_witness(ns!(compiler.0, "boolean secret witness"), empty::<bool>)
            .expect("Variable allocation is not allowed to fail.")
    }
}

impl<F> eclair::cmp::PartialEq<Self, R1CS<F>> for Boolean<F>
where
    F: PrimeField,
{
    #[inline]
    fn eq(&self, rhs: &Self, compiler: &mut R1CS<F>) -> Boolean<F> {
        let _ = compiler;
        self.is_eq(rhs)
            .expect("Equality checking is not allowed to fail.")
    }
}

impl<F> eclair::cmp::PartialEq<Self, R1CS<F>> for FpVar<F>
where
    F: PrimeField,
{
    #[inline]
    fn eq(&self, rhs: &Self, compiler: &mut R1CS<F>) -> Boolean<F> {
        let _ = compiler;
        self.is_eq(rhs)
            .expect("Equality checking is not allowed to fail.")
    }
}

impl<F> BitDecomposition<R1CS<F>> for FpVar<F>
where
    F: PrimeField,
{
    #[inline]
    fn to_bits_le(&self, compiler: &mut R1CS<F>) -> Vec<Boolean<F>> {
        let _ = compiler;
        ToBitsGadget::to_bits_le(self).expect("Bit decomposition is not allowed to fail.")
    }
}

/// Conditionally select from `lhs` and `rhs` depending on the value of `bit`.
#[inline]
fn conditionally_select<F>(bit: &Boolean<F>, lhs: &FpVar<F>, rhs: &FpVar<F>) -> FpVar<F>
where
    F: PrimeField,
{
    FpVar::conditionally_select(bit, lhs, rhs)
        .expect("Conditionally selecting from two values is not allowed to fail.")
}

impl<F> ConditionalSwap<R1CS<F>> for FpVar<F>
where
    F: PrimeField,
{
    #[inline]
    fn swap(bit: &Boolean<F>, lhs: &Self, rhs: &Self, compiler: &mut R1CS<F>) -> (Self, Self) {
        let _ = compiler;
        (
            conditionally_select(bit, rhs, lhs),
            conditionally_select(bit, lhs, rhs),
        )
    }
}

impl<F> Add<Self, R1CS<F>> for FpVar<F>
where
    F: PrimeField,
{
    type Output = Self;

    #[inline]
    fn add(self, rhs: Self, compiler: &mut R1CS<F>) -> Self {
        let _ = compiler;
        self + rhs
    }
}
