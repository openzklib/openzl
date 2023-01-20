//! Plonky2 Compiler

use alloc::vec::Vec;
use core::marker::PhantomData;
use openzl_crypto::constraint::ProofSystem;
use openzl_util::rand::{CryptoRng, RngCore};
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitData, ProverCircuitData, VerifierCircuitData},
        config::GenericConfig,
        proof,
        proof::ProofWithPublicInputs,
    },
};

/// Compiler
pub struct Compiler<F, const D: usize>
where
    F: RichField + Extendable<D>,
{
    /// Circuit Builder
    pub builder: CircuitBuilder<F, D>,

    /// Partial Witness
    pub partial_witness: PartialWitness<F>,
}

impl<F, const D: usize> Compiler<F, D>
where
    F: RichField + Extendable<D>,
{
    /// Builds a new [`Compiler`] using `builder` and `partial_witness`.
    #[inline]
    pub fn new(builder: CircuitBuilder<F, D>, partial_witness: PartialWitness<F>) -> Self {
        Self {
            builder,
            partial_witness,
        }
    }

    /// Sets the `target` to the `value` in the partial witness.
    #[inline]
    fn set_target(&mut self, target: Target, value: F) {
        self.partial_witness.set_target(target, value);
    }

    /// Returns a new virtual target.
    #[inline]
    pub fn add_virtual_target(&mut self) -> Target {
        self.builder.add_virtual_target()
    }

    /// Returns a new virtual public target.
    #[inline]
    pub fn add_virtual_public_target(&mut self) -> Target {
        let target = self.add_virtual_target();
        self.builder.register_public_input(target);
        target
    }

    /// Returns a new target assigned to `value`.
    #[inline]
    pub fn add_target(&mut self, value: F) -> Target {
        let target = self.add_virtual_target();
        self.set_target(target, value);
        target
    }

    /// Returns a new public target assigned to `value`.
    #[inline]
    pub fn add_public_target(&mut self, value: F) -> Target {
        let target = self.add_target(value);
        self.builder.register_public_input(target);
        target
    }

    /// Sets the boolean `target` to the `value` in the partial witness.
    #[inline]
    fn set_bool_target(&mut self, target: BoolTarget, value: bool) {
        self.partial_witness.set_bool_target(target, value);
    }

    /// Returns a new virtual boolean target.
    #[inline]
    pub fn add_virtual_bool_target(&mut self) -> BoolTarget {
        self.builder.add_virtual_bool_target_safe()
    }

    /// Returns a new virtual public boolean target.
    #[inline]
    pub fn add_virtual_public_bool_target(&mut self) -> BoolTarget {
        let target = self.add_virtual_bool_target();
        self.builder.register_public_input(target.target);
        target
    }

    /// Returns a new boolean target assigned to `value`.
    #[inline]
    pub fn add_bool_target(&mut self, value: bool) -> BoolTarget {
        let target = self.add_virtual_bool_target();
        self.set_bool_target(target, value);
        target
    }

    /// Returns a new public boolean target assigned to `value`.
    #[inline]
    pub fn add_public_bool_target(&mut self, value: bool) -> BoolTarget {
        let target = self.add_bool_target(value);
        self.builder.register_public_input(target.target);
        target
    }
}

impl<F, const D: usize> Default for Compiler<F, D>
where
    F: RichField + Extendable<D>,
{
    #[inline]
    fn default() -> Self {
        Self::new(CircuitBuilder::new(Default::default()), Default::default())
    }
}

/// Proving Context
pub struct ProvingContext<C, const D: usize>(ProverCircuitData<C::F, C, D>)
where
    C: GenericConfig<D>;

/// Verifying Context
pub struct VerifyingContext<C, const D: usize>(VerifierCircuitData<C::F, C, D>)
where
    C: GenericConfig<D>;

/// Proof
pub struct Proof<C, const D: usize>(proof::Proof<C::F, C, D>)
where
    C: GenericConfig<D>;

/// Plonky2 Proving System
pub struct Plonky2<C, const D: usize>(PhantomData<C>)
where
    C: GenericConfig<D>;

impl<C, const D: usize> ProofSystem for Plonky2<C, D>
where
    C: GenericConfig<D>,
{
    type Compiler = Compiler<C::F, D>;
    type PublicParameters = ();
    type ProvingContext = ProvingContext<C, D>;
    type VerifyingContext = VerifyingContext<C, D>;
    type Input = Vec<C::F>;
    type Proof = Proof<C, D>;
    type Error = anyhow::Error;

    #[inline]
    fn context_compiler() -> Self::Compiler {
        Default::default()
    }

    #[inline]
    fn proof_compiler() -> Self::Compiler {
        Default::default()
    }

    #[inline]
    fn compile<R>(
        public_parameters: &Self::PublicParameters,
        compiler: Self::Compiler,
        rng: &mut R,
    ) -> Result<(Self::ProvingContext, Self::VerifyingContext), Self::Error>
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        let _ = (public_parameters, rng);
        let CircuitData {
            prover_only,
            verifier_only,
            common,
        } = compiler.builder.build::<C>();
        Ok((
            ProvingContext(ProverCircuitData {
                prover_only,
                common: common.clone(),
            }),
            VerifyingContext(VerifierCircuitData {
                verifier_only,
                common,
            }),
        ))
    }

    #[inline]
    fn prove<R>(
        context: &Self::ProvingContext,
        compiler: Self::Compiler,
        rng: &mut R,
    ) -> Result<Self::Proof, Self::Error>
    where
        R: CryptoRng + RngCore + ?Sized,
    {
        let _ = rng;
        Ok(Proof(context.0.prove(compiler.partial_witness)?.proof))
    }

    #[inline]
    fn verify(
        context: &Self::VerifyingContext,
        input: &Self::Input,
        proof: &Self::Proof,
    ) -> Result<bool, Self::Error> {
        context.0.verify(ProofWithPublicInputs {
            proof: proof.0.clone(),
            public_inputs: input.clone(),
        })?;
        Ok(true)
    }
}
