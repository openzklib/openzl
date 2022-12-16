//! Semaphore Circuit in ECLAIR

use eclair::{
    alloc::{
        mode::{Derived, Public, Secret},
        Allocate, Allocator, Constant, Variable,
    },
    bool::{Assert, Bool},
    cmp::PartialEq,
    ops::MulAssign,
};
use openzl_crypto::{
    accumulator::{Model, Types},
    hash::ArrayHashFunction as Hash,
};

/// Semaphore Circuit Specification
pub trait Specification<COM = ()>
where
    COM: Assert,
{
    /// Accumulator Model
    type Accumulator: Model<
        COM,
        Item = <Self::Hasher as Hash<2, COM>>::Output,
        Verification = Bool<COM>,
    >;
    /// Hash function
    type Hasher: Hash<2usize, COM>;
    /// Message Type
    type Message: Clone;
}

/// Hasher
pub type Hasher<S, COM = ()> = <S as Specification<COM>>::Hasher;

/// Accumulator
pub type Accumulator<S, COM = ()> = <S as Specification<COM>>::Accumulator;

/// Semaphore Instance
pub struct Semaphore<S, COM = ()>
where
    S: Specification<COM>,
    COM: Assert,
{
    identity: Identity<S, COM>,
    signal: Signal<S, COM>,
}

impl<S, COM> Semaphore<S, COM>
where
    S: Specification<COM>,
    COM: Assert,
    <S::Hasher as Hash<2, COM>>::Output: PartialEq<<S::Hasher as Hash<2, COM>>::Output, COM>,
{
    /// Constructor
    pub fn new(identity: Identity<S, COM>, signal: Signal<S, COM>) -> Self {
        Self { identity, signal }
    }
}

impl<S, COM> Semaphore<S, COM>
where
    S: Specification<COM>,
    COM: Assert,
    <S::Hasher as Hash<2, COM>>::Output: PartialEq<<S::Hasher as Hash<2, COM>>::Output, COM>,
    S::Message: MulAssign<S::Message, COM>,
{
    /// Allocates `self` and generates constraints in `compiler`.
    pub fn circuit(self, parameters: Parameters<S, COM>, compiler: &mut COM) {
        // Compute identity commitment (this omits the second hash of the diagram)
        let identity_commitment = parameters.hasher.hash(
            [&self.identity.trapdoor, &self.identity.nullifier],
            compiler,
        );
        // Assert valid identity
        let verification = parameters.accumulator.verify(
            &identity_commitment,
            &self.identity.witness,
            &self.identity.membership_root,
            compiler,
        );
        compiler.assert(&verification);
        // Assert Correct Nullifier
        let computed_nullifier = parameters.hasher.hash(
            [&self.identity.nullifier, &self.signal.external_nullifier],
            compiler,
        );
        computed_nullifier.assert_equal(&self.signal.nullifier, compiler);
        // Constrain message
        // TODO: What's a good way to do this?
        let mut message = self.signal.message.clone();
        message.mul_assign(message.clone(), compiler);
    }

    pub fn unknown_constraints(parameters: Parameters<S, COM>, compiler: &mut COM) -> &COM
    where
        Self: Variable<Derived, COM>,
    {
        let semaphore = Self::new_unknown(compiler);
        semaphore.circuit(parameters, compiler);
        compiler
    }

    pub fn known_constraints(
        semaphore: Semaphore<S>,
        parameters: Parameters<S, COM>,
        compiler: &mut COM,
    ) -> &COM
    where
        S: Specification,
        Self: Variable<Derived, COM, Type = Semaphore<S>>,
    {
        let semaphore: Self = semaphore.as_known(compiler);
        semaphore.circuit(parameters, compiler);
        compiler
    }
}

impl<S, COM> Variable<Derived, COM> for Semaphore<S, COM>
where
    S: Specification<COM> + Specification,
    COM: Assert,
    <Hasher<S> as Hash<2>>::Input: Sized,
    Identity<S, COM>: Variable<Secret, COM, Type = Identity<S>>,
    Signal<S, COM>: Variable<Public, COM, Type = Signal<S>>,
    Accumulator<S, COM>: Constant<COM, Type = Accumulator<S>>,
    Hasher<S, COM>: Constant<COM, Type = Hasher<S>>,
    <Hasher<S, COM> as Hash<2, COM>>::Output:
        PartialEq<<Hasher<S, COM> as Hash<2, COM>>::Output, COM>,
{
    type Type = Semaphore<S>;

    fn new_known(this: &Self::Type, compiler: &mut COM) -> Self {
        Self::new(
            this.identity.as_known(compiler),
            this.signal.as_known(compiler),
        )
    }

    fn new_unknown(compiler: &mut COM) -> Self {
        Self::new(compiler.allocate_unknown(), compiler.allocate_unknown())
    }
}

/// Semaphore Identity Credentials
pub struct Identity<S, COM = ()>
where
    COM: Assert,
    S: Specification<COM> + ?Sized,
    <S::Hasher as Hash<2, COM>>::Input: Sized,
{
    trapdoor: <S::Hasher as Hash<2, COM>>::Input,
    nullifier: <S::Hasher as Hash<2, COM>>::Input,
    witness: <S::Accumulator as Types>::Witness,
    membership_root: <S::Accumulator as Types>::Output,
}

impl<S, COM> Identity<S, COM>
where
    COM: Assert,
    S: Specification<COM> + ?Sized,
    <S::Hasher as Hash<2, COM>>::Input: Sized,
{
    pub fn new(
        trapdoor: <S::Hasher as Hash<2, COM>>::Input,
        nullifier: <S::Hasher as Hash<2, COM>>::Input,
        witness: <S::Accumulator as Types>::Witness,
        membership_root: <S::Accumulator as Types>::Output,
    ) -> Self {
        Self {
            trapdoor,
            nullifier,
            witness,
            membership_root,
        }
    }
}

impl<S, COM> Variable<Secret, COM> for Identity<S, COM>
where
    COM: Assert,
    S: Specification<COM> + Specification + ?Sized,
    <Hasher<S, COM> as Hash<2, COM>>::Input:
        Variable<Secret, COM, Type = <Hasher<S> as Hash<2>>::Input> + Sized,
    <Hasher<S> as Hash<2>>::Input: Sized,
    <Accumulator<S, COM> as Types>::Output:
        Variable<Secret, COM, Type = <Accumulator<S> as Types>::Output>,
    <Accumulator<S, COM> as Types>::Witness:
        Variable<Secret, COM, Type = <Accumulator<S> as Types>::Witness>,
{
    type Type = Identity<S>;

    fn new_known(this: &Self::Type, compiler: &mut COM) -> Self {
        Self::new(
            this.trapdoor.as_known(compiler),
            this.nullifier.as_known(compiler),
            this.witness.as_known(compiler),
            this.membership_root.as_known(compiler),
        )
    }

    fn new_unknown(compiler: &mut COM) -> Self {
        Self::new(
            compiler.allocate_unknown(),
            compiler.allocate_unknown(),
            compiler.allocate_unknown(),
            compiler.allocate_unknown(),
        )
    }
}

pub struct Signal<S, COM = ()>
where
    COM: Assert,
    S: Specification<COM> + ?Sized,
    <S::Hasher as Hash<2, COM>>::Input: Sized,
{
    external_nullifier: <S::Hasher as Hash<2, COM>>::Input,
    nullifier: <S::Hasher as Hash<2, COM>>::Output,
    message: S::Message,
}

impl<S, COM> Signal<S, COM>
where
    COM: Assert,
    S: Specification<COM> + ?Sized,
    <S::Hasher as Hash<2, COM>>::Input: Sized,
{
    pub fn new(
        external_nullifier: <S::Hasher as Hash<2, COM>>::Input,
        nullifier: <S::Hasher as Hash<2, COM>>::Output,
        message: S::Message,
    ) -> Self {
        Self {
            external_nullifier,
            nullifier,
            message,
        }
    }

    // TODO: A method for forming the signal from everything but `nullifier`
}

impl<S, COM> Variable<Public, COM> for Signal<S, COM>
where
    COM: Assert,
    S: Specification<COM> + Specification + ?Sized,
    <Hasher<S> as Hash<2>>::Input: Sized,
    <Hasher<S, COM> as Hash<2, COM>>::Input:
        Variable<Public, COM, Type = <Hasher<S> as Hash<2>>::Input> + Sized,
    <Hasher<S, COM> as Hash<2, COM>>::Output:
        Variable<Public, COM, Type = <Hasher<S> as Hash<2>>::Output>,
    <S as Specification<COM>>::Message: Variable<Public, COM, Type = <S as Specification>::Message>,
{
    type Type = Signal<S>;

    fn new_known(this: &Self::Type, compiler: &mut COM) -> Self {
        Self::new(
            this.external_nullifier.as_known(compiler),
            this.nullifier.as_known(compiler),
            this.message.as_known(compiler),
        )
    }

    fn new_unknown(compiler: &mut COM) -> Self {
        Self::new(
            compiler.allocate_unknown(),
            compiler.allocate_unknown(),
            compiler.allocate_unknown(),
        )
    }
}

/// Semaphore Parameters
pub struct Parameters<S, COM = ()>
where
    S: Specification<COM>,
    COM: Assert,
{
    accumulator: Accumulator<S, COM>,
    hasher: Hasher<S, COM>,
}

impl<S, COM> Parameters<S, COM>
where
    S: Specification<COM>,
    COM: Assert,
{
    pub fn new(accumulator: Accumulator<S, COM>, hasher: Hasher<S, COM>) -> Self {
        Self {
            accumulator,
            hasher,
        }
    }
}

impl<S, COM> Constant<COM> for Parameters<S, COM>
where
    S: Specification<COM> + Specification,
    COM: Assert,
    Accumulator<S, COM>: Constant<COM, Type = Accumulator<S>>,
    Hasher<S, COM>: Constant<COM, Type = Hasher<S>>,
{
    type Type = Parameters<S>;
    fn new_constant(this: &Self::Type, compiler: &mut COM) -> Self {
        Self::new(
            this.accumulator.as_constant(compiler),
            this.hasher.as_constant(compiler),
        )
    }
}
