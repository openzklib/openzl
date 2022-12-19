//! Concrete Semaphore Protocol using Arkworks Plugin

use crate::{
    merkle_tree::arkworks::PoseidonMerkleAccumulator,
    poseidon::arkworks::Poseidon2Hasher,
    semaphore::{Parameters, Semaphore, Specification},
};
use arkworks::{bn254::Fr, constraint::fp::Fp};

/// Concrete Semaphore Specification for Bn254 Curve in Arkworks
pub struct ArkSemaphoreSpec;

impl Specification for ArkSemaphoreSpec {
    type Accumulator = PoseidonMerkleAccumulator;

    type Hasher = Poseidon2Hasher;

    type Message = Fp<Fr>;
}

pub type ArkSemaphore = Semaphore<ArkSemaphoreSpec>;

pub type ArkSemaphoreParameters = Parameters<ArkSemaphoreSpec>;

// impl Specification<R1CS<Fr>> for ArkSemaphore {

// }

/// Testing suite
#[cfg(feature = "rand")]
pub mod test {
    use super::*;
    use crate::{
        merkle_tree::arkworks::test::sample_poseidon_accumulator,
        poseidon::arkworks::concrete_permutation,
        semaphore::{Identity, Signal},
    };
    use eclair::ops::MulAssign;
    use openzl_crypto::{accumulator::Accumulator, hash::ArrayHashFunction};
    use openzl_util::rand::{Rand, RngCore};

    pub fn sample_semaphore_instance<const GROUP_SIZE: usize, R>(
        rng: &mut R,
    ) -> (ArkSemaphore, ArkSemaphoreParameters)
    where
        R: RngCore,
    {
        // Sample an accumulator
        let mut accumulator: PoseidonMerkleAccumulator =
            sample_poseidon_accumulator::<GROUP_SIZE, _>(rng);
        // Sample an identity
        let trapdoor: Fp<Fr> = rng.gen();
        let identity_nullifier: Fp<Fr> = rng.gen();
        let hasher = concrete_permutation();
        let identity_commitment = hasher.hash([&trapdoor, &identity_nullifier], &mut ());
        // Insert identity into accumulator
        assert!(accumulator.insert(&identity_commitment));
        // Extract membership proof
        let proof = accumulator
            .prove(&identity_commitment)
            .expect("This item was inserted into accumulator");

        // Sample a signal
        let external_nullifier: Fp<Fr> = rng.gen();
        let message: Fp<Fr> = rng.gen();
        let signal_nullifier = hasher.hash([&identity_nullifier, &external_nullifier], &mut ());

        (
            ArkSemaphore::new(
                Identity::new(trapdoor, identity_nullifier, proof),
                Signal::new(external_nullifier, signal_nullifier, message),
            ),
            ArkSemaphoreParameters::new(accumulator, hasher),
        )
    }

    #[test]
    fn check_concrete_semaphore_circuit() {
        use openzl_util::rand::OsRng;

        let mut rng = OsRng;
        const NUM_LEAVES: usize = 10;

        let (semaphore, parameters) = sample_semaphore_instance::<NUM_LEAVES, _>(&mut rng);
        semaphore.circuit(&parameters, &mut ());
    }

    #[test]
    #[should_panic]
    fn check_incorrect_semaphore_circuit() {
        use openzl_util::rand::OsRng;

        let mut rng = OsRng;
        const NUM_LEAVES: usize = 10;

        let (mut semaphore, parameters) = sample_semaphore_instance::<NUM_LEAVES, _>(&mut rng);
        // Make sure the the circuit with modified ID does not work:
        semaphore
            .identity
            .trapdoor
            .mul_assign(Fp(Fr::from(2u8)), &mut ());
        semaphore.circuit(&parameters, &mut ());
    }
}
