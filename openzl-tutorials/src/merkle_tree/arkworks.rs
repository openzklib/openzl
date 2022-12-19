//! Concrete Merkle Tree Using Poseidon Hasher and Arkworks

use crate::{
    merkle_tree::{ConcreteAccumulator, Hasher},
    poseidon::arkworks::Poseidon2Hasher,
};
use arkworks::{bn254::Fr, constraint::fp::Fp};
use openzl_crypto::hash::ArrayHashFunction;

impl Hasher for Poseidon2Hasher {
    type Node = Fp<Fr>;

    fn combine(&self, lhs: &Self::Node, rhs: &Self::Node, _: &mut ()) -> Self::Node {
        self.hash([lhs, rhs], &mut ())
    }
}

/// An accumulator made from a Merkle tree over Bn254
pub type PoseidonMerkleAccumulator = ConcreteAccumulator<Poseidon2Hasher>;

/// Testing suite
#[cfg(feature = "rand")]
pub mod test {
    use super::*;
    use crate::{merkle_tree::Parameters, poseidon::arkworks::concrete_permutation};
    use openzl_util::rand::{Rand, RngCore};

    use crate::merkle_tree::arkworks::PoseidonMerkleAccumulator;

    pub fn sample_poseidon_accumulator<const NUM_LEAVES: usize, R>(
        rng: &mut R,
    ) -> PoseidonMerkleAccumulator
    where
        R: RngCore,
    {
        let leaves: [Fp<Fr>; NUM_LEAVES] = rng.gen();
        PoseidonMerkleAccumulator::from_leaves(
            leaves.to_vec(),
            Parameters::new(concrete_permutation()),
        )
    }

    #[test]
    fn check_accumulator_membership() {
        use openzl_crypto::accumulator::Accumulator;
        use openzl_util::rand::OsRng;

        let mut rng = OsRng;
        const NUM_LEAVES: usize = 10;
        let mut accumulator = sample_poseidon_accumulator::<NUM_LEAVES, _>(&mut rng);
        let item: Fp<Fr> = rng.gen();
        assert!(accumulator.insert(&item));
        let proof = accumulator.prove(&item).unwrap();
        assert!(proof.verify(&accumulator, &item, &mut ()))
    }
}
