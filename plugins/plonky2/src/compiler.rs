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
    plonk::circuit_builder::CircuitBuilder,
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

///
pub struct ProvingContext;

///
pub struct VerifyingContext;

///
pub struct Proof;

///
pub struct Error;

///
pub struct Plonky2<F, const D: usize>(PhantomData<F>)
where
    F: RichField + Extendable<D>;

impl<F, const D: usize> ProofSystem for Plonky2<F, D>
where
    F: RichField + Extendable<D>,
{
    type Compiler = Compiler<F, D>;
    type PublicParameters = ();
    type ProvingContext = ProvingContext;
    type VerifyingContext = VerifyingContext;
    type Input = Vec<F>;
    type Proof = Proof;
    type Error = Error;

    #[inline]
    fn context_compiler() -> Self::Compiler {
        /*
        Self::Compiler::for_contexts()
        */
        todo!()
    }

    #[inline]
    fn proof_compiler() -> Self::Compiler {
        /*
        Self::Compiler::for_proofs()
        */
        todo!()
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
        /*
        let _ = public_parameters;
        let (proving_key, verifying_key) =
            ArkGroth16::circuit_specific_setup(compiler, &mut SizedRng(rng)).map_err(|_| Error)?;
        Ok((
            ProvingContext(proving_key),
            VerifyingContext(ArkGroth16::process_vk(&verifying_key).map_err(|_| Error)?),
        ))
        */
        todo!()
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
        /*
        ArkGroth16::prove(&context.0, compiler, &mut SizedRng(rng))
            .map(Proof)
            .map_err(|_| Error)
        */
        todo!()
    }

    #[inline]
    fn verify(
        context: &Self::VerifyingContext,
        input: &Self::Input,
        proof: &Self::Proof,
    ) -> Result<bool, Self::Error> {
        /*
        ArkGroth16::verify_with_processed_vk(&context.0, input, &proof.0).map_err(|_| Error)
        */
        todo!()
    }
}
