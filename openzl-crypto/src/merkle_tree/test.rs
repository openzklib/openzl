//! Testing Framework

use crate::merkle_tree::{
    Configuration, HashConfiguration, IdentityLeafHash, InnerDigest, InnerHash,
    InnerHashParameters, Leaf, LeafHashParameters, MerkleTree, Parameters, Path, Tree, WithProofs,
};
use alloc::string::String;
use core::{fmt::Debug, hash::Hash, marker::PhantomData};
use openzl_util::{
    derivative,
    rand::{RngCore, Sample},
};

/// Hash Parameter Sampling
pub trait HashParameterSampling: HashConfiguration {
    /// Leaf Hash Parameter Distribution
    type LeafHashParameterDistribution;

    /// Inner Hash Parameter Distribution
    type InnerHashParameterDistribution;

    /// Sample leaf hash parameters from `distribution` using the given `rng`.
    fn sample_leaf_hash_parameters<R>(
        distribution: Self::LeafHashParameterDistribution,
        rng: &mut R,
    ) -> LeafHashParameters<Self>
    where
        R: RngCore + ?Sized;

    /// Sample inner hash parameters from `distribution` using the given `rng`.
    fn sample_inner_hash_parameters<R>(
        distribution: Self::InnerHashParameterDistribution,
        rng: &mut R,
    ) -> InnerHashParameters<Self>
    where
        R: RngCore + ?Sized;
}

/// Hash Parameter Distribution
#[derive(derivative::Derivative)]
#[derivative(
    Clone(
        bound = "C::LeafHashParameterDistribution: Clone, C::InnerHashParameterDistribution: Clone"
    ),
    Copy(
        bound = "C::LeafHashParameterDistribution: Copy, C::InnerHashParameterDistribution: Copy"
    ),
    Debug(
        bound = "C::LeafHashParameterDistribution: Debug, C::InnerHashParameterDistribution: Debug"
    ),
    Default(
        bound = "C::LeafHashParameterDistribution: Default, C::InnerHashParameterDistribution: Default"
    ),
    Eq(bound = "C::LeafHashParameterDistribution: Eq, C::InnerHashParameterDistribution: Eq"),
    Hash(
        bound = "C::LeafHashParameterDistribution: Hash, C::InnerHashParameterDistribution: Hash"
    ),
    PartialEq(bound = "C::LeafHashParameterDistribution: PartialEq,
        C::InnerHashParameterDistribution: PartialEq")
)]
pub struct HashParameterDistribution<C>
where
    C: HashParameterSampling + ?Sized,
{
    /// Leaf Hash Parameter Distribution
    pub leaf: C::LeafHashParameterDistribution,

    /// Inner Hash Parameter Distribution
    pub inner: C::InnerHashParameterDistribution,
}

impl<C> Sample<HashParameterDistribution<C>> for Parameters<C>
where
    C: HashParameterSampling + ?Sized,
{
    #[inline]
    fn sample<R>(distribution: HashParameterDistribution<C>, rng: &mut R) -> Self
    where
        R: RngCore + ?Sized,
    {
        Self::new(
            C::sample_leaf_hash_parameters(distribution.leaf, rng),
            C::sample_inner_hash_parameters(distribution.inner, rng),
        )
    }
}

/// Tests that a tree constructed with `parameters` can accept at least two leaves without
/// failing.
#[inline]
pub fn push_twice_to_empty_tree_succeeds<C, T>(
    parameters: Parameters<C>,
    lhs: &Leaf<C>,
    rhs: &Leaf<C>,
) -> Parameters<C>
where
    C: Configuration + ?Sized,
    T: Tree<C>,
{
    let mut tree = MerkleTree::<C, T>::new(parameters);
    assert!(
        tree.push(lhs),
        "Trees always have a capacity of at least two."
    );
    assert!(
        tree.push(rhs),
        "Trees always have a capacity of at least two."
    );
    tree.into_parameters()
}

/// Tests path construction by checking that the path at the given `index` on `tree` is a valid
/// [`Path`](super::Path) for `leaf`.
#[inline]
pub fn assert_valid_path<C, T>(tree: &MerkleTree<C, T>, index: usize, leaf: &Leaf<C>)
where
    C: Configuration + ?Sized,
    T: Tree<C> + WithProofs<C>,
    InnerDigest<C>: Debug + PartialEq,
    Path<C>: Debug,
{
    let path = tree.path(index).expect("Only valid queries are accepted.");
    let root = tree.root();
    assert!(
        path.verify(tree.parameters(), root, leaf),
        "Path returned from tree was not valid: {:?}. Expected {:?} but got {:?}.",
        path,
        root,
        path.root(&tree.parameters, &tree.parameters.digest(leaf)),
    );
}

/// Tests path construction for multiple insertions. This is an extension of the
/// [`assert_valid_path`] test.
#[inline]
pub fn assert_valid_paths<C, T>(tree: &mut MerkleTree<C, T>, leaves: &[Leaf<C>])
where
    C: Configuration + ?Sized,
    T: Tree<C> + WithProofs<C>,
    InnerDigest<C>: Debug + PartialEq,
    Path<C>: Debug,
    Leaf<C>: Sized,
{
    let starting_index = tree.len();
    for (i, leaf) in leaves.iter().enumerate() {
        tree.push(leaf);
        for (j, previous_leaf) in leaves.iter().enumerate().take(i + 1) {
            assert_valid_path(tree, starting_index + j, previous_leaf);
        }
    }
}

/// Test Inner Hash
///
/// # Warning
///
/// This is only meant for testing purposes, and should not be used in any production or
/// cryptographically secure environments.
pub trait TestHash {
    /// Joins `lhs` and `rhs` into an output hash value.
    fn join(lhs: &Self, rhs: &Self) -> Self;
}

impl TestHash for u64 {
    #[inline]
    fn join(lhs: &Self, rhs: &Self) -> Self {
        *lhs ^ *rhs
    }
}

impl TestHash for String {
    #[inline]
    fn join(lhs: &Self, rhs: &Self) -> Self {
        let mut lhs = lhs.clone();
        lhs.push_str(rhs);
        lhs
    }
}

/// Test Merkle Tree Configuration
///
/// # Warning
///
/// This is only meant for testing purposes, and should not be used in production or
/// cryptographically secure environments.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Test<T, const HEIGHT: usize>(PhantomData<T>)
where
    T: Clone + Default + PartialEq + TestHash;

impl<T, const HEIGHT: usize> InnerHash for Test<T, HEIGHT>
where
    T: Clone + Default + PartialEq + TestHash,
{
    type LeafDigest = T;
    type Parameters = ();
    type Output = T;

    #[inline]
    fn join(
        parameters: &Self::Parameters,
        lhs: &Self::Output,
        rhs: &Self::Output,
        _: &mut (),
    ) -> Self::Output {
        let _ = parameters;
        TestHash::join(lhs, rhs)
    }

    #[inline]
    fn join_leaves(
        parameters: &Self::Parameters,
        lhs: &Self::LeafDigest,
        rhs: &Self::LeafDigest,
        _: &mut (),
    ) -> Self::Output {
        let _ = parameters;
        TestHash::join(lhs, rhs)
    }
}

impl<T, const HEIGHT: usize> HashConfiguration for Test<T, HEIGHT>
where
    T: Clone + Default + PartialEq + TestHash,
{
    type LeafHash = IdentityLeafHash<T>;
    type InnerHash = Test<T, HEIGHT>;
}

impl<T, const HEIGHT: usize> Configuration for Test<T, HEIGHT>
where
    T: Clone + Default + PartialEq + TestHash,
{
    const HEIGHT: usize = HEIGHT;
}

impl<T, const HEIGHT: usize> HashParameterSampling for Test<T, HEIGHT>
where
    T: Clone + Default + PartialEq + TestHash,
{
    type LeafHashParameterDistribution = ();
    type InnerHashParameterDistribution = ();

    #[inline]
    fn sample_leaf_hash_parameters<R>(
        distribution: Self::LeafHashParameterDistribution,
        rng: &mut R,
    ) -> LeafHashParameters<Self>
    where
        R: RngCore + ?Sized,
    {
        let _ = (distribution, rng);
    }

    #[inline]
    fn sample_inner_hash_parameters<R>(
        distribution: Self::InnerHashParameterDistribution,
        rng: &mut R,
    ) -> InnerHashParameters<Self>
    where
        R: RngCore + ?Sized,
    {
        let _ = (distribution, rng);
    }
}
