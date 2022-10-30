//! Execution Engines

// TODO: use openzl_crypto::rand::RngCore;

/// Execution Engine
pub trait Engine<COM> {
    /* TODO:
    /// Engine Output Type
    type Output;

    /// Error Type
    type Error;

    /// Initializes a compiler that will be used to construct execution information.
    fn init(&self) -> COM;

    /// Finalizes the exectution with `compiler` producing [`Output`](Self::Output).
    fn finalize<R>(&self, compiler: COM, rng: &mut R) -> Result<Self::Output, Self::Error>
    where
        R: RngCore + ?Sized;
    */
}

/// Proof System
pub trait ProofSystem {
    /* TODO
    /// Base Compiler
    type Compiler;

    /// Proving Context
    type ProvingContext;

    /// Verifying Context
    type VerifyingContext;

    /// Context Generation Engine
    type ContextEngine: Engine<
        Self::Compiler,
        Output = (Self::ProvingContext, Self::VerifyingContext),
    >;

    /// Proof
    type Proof;

    /// Proof Engine
    type ProofEngine: Engine<Self::Compiler, Output = Self::Proof>;

    /// Public Input
    type Input;

    /// Verification Error
    type Error;

    /// Verifies that `proof` with `input` is valid with respect to the [`ContextEngine`] and
    /// [`ProofEngine`] for this proof system.
    ///
    /// [`ContextEngine`]: Self::ContextEngine
    /// [`ProofEngine`]: Self::ProofEngine
    fn verify(
        context: &Self::VerifyingContext,
        input: &Self::Input,
        proof: &Self::Proof,
    ) -> Result<bool, Self::Error>;
    */
}
