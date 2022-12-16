//! Semaphore Circuit in ECLAIR

use eclair::{
    alloc::{
        mode::{Public, Secret},
        Variable,
    },
    bool::{Assert, Bool},
    cmp::PartialEq,
    ops::MulAssign,
};
use openzl_crypto::{
    accumulator::{Model, Types},
    hash::ArrayHashFunction,
};

/// Semaphore Circuit Specification
/// TODO: What compatibility is needed among these types?
pub trait Specification<COM = ()>
where
    COM: Assert,
{
    /// Concrete Accumulator Model
    type AccumulatorModel: Model<
        Item = Self::HashOutput,
        Output = Self::AccumulatorOutput,
        Witness = Self::Witness,
    >;
    /// Accumulator Model Variable Type
    type AccumulatorModelVar: Model<
        COM,
        Item = Self::HashOutputVar,
        Output = Self::AccumulatorOutputVar,
        Witness = Self::WitnessVar,
        Verification = Bool<COM>,
    >;
    /// Accumulator Witness Type
    type Witness;
    /// Accumulator Witness Variable Type
    type WitnessVar: Variable<Secret, COM, Type = Self::Witness>;
    /// Concrete Input Type for Hash Functions
    type Input;
    /// Input Variable Type
    type InputVar: Variable<Secret, COM, Type = Self::Input>
        + Variable<Public, COM, Type = Self::Input>;
    /// Accumulator Output Type
    type AccumulatorOutput;
    /// Accumulator Output Variable Type
    type AccumulatorOutputVar: Variable<Public, COM, Type = Self::AccumulatorOutput>;
    /// Rename this hash
    type Hash: ArrayHashFunction<2usize, Input = Self::Input, Output = Self::HashOutput>;
    /// Should these really be two different types?
    type HashVar: ArrayHashFunction<
        2usize,
        COM,
        Input = Self::InputVar,
        Output = Self::HashOutputVar,
    >;
    /// Hash Output Type
    type HashOutput;
    /// Hash Output Variable Type
    type HashOutputVar: Variable<Public, COM, Type = Self::HashOutput>
        + PartialEq<Self::HashOutputVar, COM>;
    /// Message Type
    type Message;
    /// Message Variable Type
    type MessageVar: Clone
        + Variable<Public, COM, Type = Self::Message>
        + MulAssign<Self::MessageVar, COM>;

    /// Generates constraints in `compiler` to enforce the Semaphore circuit.
    fn circuit(
        identity: Identity<Self, COM>,
        signal: Signal<Self, COM>,
        accumulator: &Self::AccumulatorModelVar,
        hash: &Self::HashVar,
        compiler: &mut COM,
    ) {
        // Allocate identity data
        let identity_trapdoor: Self::InputVar =
            Variable::<Secret, COM>::new_known(&identity.trapdoor, compiler);
        let identity_nullifier: Self::InputVar =
            Variable::<Secret, COM>::new_known(&identity.nullifier, compiler);
        let witness: Self::WitnessVar =
            Variable::<Secret, COM>::new_known(&identity.witness, compiler);
        let membership_root: Self::AccumulatorOutputVar =
            Variable::<Public, COM>::new_known(&identity.membership_root, compiler);
        // Compute identity commitment (this omits the second hash of the diagram)
        let identity_commitment = hash.hash([&identity_trapdoor, &identity_nullifier], compiler);
        // Assert valid identity
        let verification =
            accumulator.verify(&identity_commitment, &witness, &membership_root, compiler);
        compiler.assert(&verification);

        // Allocate the signal data
        let external_nullifier: Self::InputVar =
            Variable::<Public, COM>::new_known(&signal.external_nullifier, compiler);
        let claimed_nullifier: Self::HashOutputVar =
            Variable::<Public, COM>::new_known(&signal.nullifier, compiler);
        let mut message: Self::MessageVar =
            Variable::<Public, COM>::new_known(&signal.message, compiler);
        // Assert correct nullifier
        let computed_nullifier = hash.hash([&identity_nullifier, &external_nullifier], compiler);
        computed_nullifier.eq(&claimed_nullifier, compiler);

        // Constrain message
        // TODO: What does this clone do exactly?
        message.mul_assign(message.clone(), compiler);
    }
}

/// Semaphore Identity Credentials
pub struct Identity<S, COM>
where
    COM: Assert,
    S: Specification<COM> + ?Sized,
{
    trapdoor: S::Input,
    nullifier: S::Input,
    witness: <S::AccumulatorModel as Types>::Witness,
    membership_root: <S::AccumulatorModel as Types>::Output,
}

pub struct Signal<S, COM>
where
    COM: Assert,
    S: Specification<COM> + ?Sized,
{
    external_nullifier: S::Input,
    nullifier: S::HashOutput,
    message: S::Message,
}
