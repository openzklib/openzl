//! Merkle Forests

// FIXME: Replace `N` parameter on `FixedIndex` with an associated value in the trait when
//        `generic_const_exprs` is stabilized and get rid of `ConstantWidthForest`.
// FIXME: Reduce code duplication between this and `tree.rs` code.
// TODO:  What should we do if a tree fills before others? Need some way of chosing a second option
//        for a leaf.

use crate::{
    accumulator::{
        self, Accumulator, ConstantCapacityAccumulator, ExactSizeAccumulator, MembershipProof,
        OptimizedAccumulator,
    },
    merkle_tree::{
        fork::ForkedTree,
        inner_tree::InnerMap,
        path::Path,
        tree::{self, Leaf, Parameters, Root, Tree},
        InnerDigest, LeafDigest, WithProofs,
    },
};
use alloc::{boxed::Box, vec::Vec};
use core::{fmt::Debug, hash::Hash, marker::PhantomData};
use openzl_util::{derivative, persistence::Rollback, BoxArray};

#[cfg(feature = "serde")]
use openzl_util::serde::{Deserialize, Serialize};

/// Merkle Forest Configuration
pub trait Configuration: tree::Configuration {
    /// Tree Index Type
    type Index: PartialEq;

    /// Returns the index of the merkle tree where `leaf` should be inserted.
    ///
    /// # Contract
    ///
    /// This method should be deterministic and should distribute the space of leaves uniformly over
    /// the space of indices.
    fn tree_index(leaf: &Leaf<Self>) -> Self::Index;
}

/// Merkle Forest Fixed Index Type
///
/// # Contract
///
/// For a type to be a fixed index, the number of possible values must be known at compile time. In
/// this case, `N` must be the number of distinct values. If this type is used as an
/// [`Index`](Configuration::Index) for a merkle forest configuration, the
/// [`tree_index`](Configuration::tree_index) method must return values from a distribution over
/// exactly `N` values.
pub trait FixedIndex<const N: usize>: Into<usize> {
    /// Returns a representative index of type `Self` if `index` is within `0..N`.
    ///
    /// # Panics
    ///
    /// This method can return any value or panic whenever `index` is out of the correct range but
    /// cannot run into undefined behavior.
    fn from_index(index: usize) -> Self;
}

impl FixedIndex<256> for u8 {
    #[inline]
    fn from_index(index: usize) -> Self {
        index as Self
    }
}

impl FixedIndex<65536> for u16 {
    #[inline]
    fn from_index(index: usize) -> Self {
        index as Self
    }
}

/// Merkle Forest Structure
pub trait Forest<C>
where
    C: Configuration + ?Sized,
{
    /// Tree Type
    type Tree: Tree<C>;

    /// Builds a new empty merkle forest.
    fn new(parameters: &Parameters<C>) -> Self;

    /// Returns the number of items in `self`.
    fn len(&self) -> usize;

    /// Returns `true` if the length of `self` is zero.
    #[inline]
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the number of items that can be stored in `self`.
    fn capacity(&self) -> usize;

    /// Returns a shared reference to the tree at the given `index`.
    ///
    /// # Panics
    ///
    /// This method is allowed to panic if `index` is out-of-bounds.
    fn get(&self, index: C::Index) -> &Self::Tree;

    /// Returns a shared reference to the tree which `leaf` corresponds with.
    ///
    /// # Implementation Note
    ///
    /// This method is an optimization path for computing [`tree_index`](Configuration::tree_index)
    /// followed by [`get`](Self::get).
    #[inline]
    fn get_tree(&self, leaf: &Leaf<C>) -> &Self::Tree {
        self.get(C::tree_index(leaf))
    }

    /// Returns a mutable reference to the tree at the given `index`.
    ///
    /// # Panics
    ///
    /// This method is allowed to panic if `index` is out-of-bounds.
    fn get_mut(&mut self, index: C::Index) -> &mut Self::Tree;

    /// Returns a mutable reference to the tree which `leaf` corresponds with.
    ///
    /// # Implementation Note
    ///
    /// This method is an optimization path for computing [`tree_index`](Configuration::tree_index)
    /// followed by [`get_mut`](Self::get_mut).
    #[inline]
    fn get_tree_mut(&mut self, leaf: &Leaf<C>) -> &mut Self::Tree {
        self.get_mut(C::tree_index(leaf))
    }
}

/// Constant Width Forest
pub trait ConstantWidthForest<C>: Forest<C>
where
    C: Configuration + ?Sized,
{
    /// Fixed Number of Trees in the Forest
    const WIDTH: usize;
}

/// Returns the capacity of the merkle forest with the given [`C::HEIGHT`] and [`F::WIDTH`]
/// parameters.
///
/// The capacity of a merkle forest with height `H` and width `W` is `W * 2^(H - 1)`.
///
/// [`C::HEIGHT`]: tree::Configuration::HEIGHT
/// [`F::WIDTH`]: ConstantWidthForest::WIDTH
#[inline]
pub fn capacity<C, F>() -> usize
where
    C: Configuration + ?Sized,
    F: ConstantWidthForest<C>,
{
    F::WIDTH * tree::capacity::<C, _>()
}

/// Merkle Forest
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(
        bound(
            deserialize = "Parameters<C>: Deserialize<'de>, F: Deserialize<'de>",
            serialize = "Parameters<C>: Serialize, F: Serialize"
        ),
        crate = "openzl_util::serde",
        deny_unknown_fields
    )
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "Parameters<C>: Clone, F: Clone"),
    Copy(bound = "Parameters<C>: Copy, F: Copy"),
    Debug(bound = "Parameters<C>: Debug, F: Debug"),
    Default(bound = "Parameters<C>: Default, F: Default"),
    Eq(bound = "Parameters<C>: Eq, F: Eq"),
    Hash(bound = "Parameters<C>: Hash, F: Hash"),
    PartialEq(bound = "Parameters<C>: PartialEq, F: PartialEq")
)]
pub struct MerkleForest<C, F>
where
    C: Configuration + ?Sized,
    F: Forest<C>,
{
    /// Merkle Forest Parameters
    pub parameters: Parameters<C>,

    /// Underlying Forest Structure
    pub forest: F,
}

impl<C, F> MerkleForest<C, F>
where
    C: Configuration + ?Sized,
    F: Forest<C>,
{
    /// Builds a new [`MerkleForest`] from `parameters`.
    ///
    /// See [`Forest::new`] for more.
    #[inline]
    pub fn new(parameters: Parameters<C>) -> Self {
        Self::from_forest(F::new(&parameters), parameters)
    }

    /// Builds a new [`MerkleForest`] from a pre-constructed `forest` and `parameters`.
    #[inline]
    pub fn from_forest(forest: F, parameters: Parameters<C>) -> Self {
        Self { parameters, forest }
    }

    /// Returns a shared reference to the parameters used by this merkle forest.
    #[inline]
    pub fn parameters(&self) -> &Parameters<C> {
        &self.parameters
    }

    /// Returns the number of leaves that can fit in this merkle tree.
    ///
    /// See [`capacity`] for more.
    #[inline]
    pub fn capacity(&self) -> usize {
        self.forest.capacity()
    }

    /// Returns the number of items in this merkle forest.
    ///
    /// See [`Forest::len`] for more.
    #[inline]
    pub fn len(&self) -> usize {
        self.forest.len()
    }

    /// Returns `true` if this merkle forest is empty.
    ///
    /// See [`Forest::is_empty`] for more.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.forest.is_empty()
    }

    /// Inserts `leaf` at the next available leaf node of the tree corresponding with `leaf`,
    /// returning `false` if the leaf could not be inserted because its tree has exhausted its
    /// capacity.
    #[inline]
    pub fn push(&mut self, leaf: &Leaf<C>) -> bool {
        self.forest.get_tree_mut(leaf).push(&self.parameters, leaf)
    }
}

impl<C, F> AsMut<F> for MerkleForest<C, F>
where
    C: Configuration + ?Sized,
    F: Forest<C>,
{
    #[inline]
    fn as_mut(&mut self) -> &mut F {
        &mut self.forest
    }
}

impl<C, F> AsRef<F> for MerkleForest<C, F>
where
    C: Configuration + ?Sized,
    F: Forest<C>,
{
    #[inline]
    fn as_ref(&self) -> &F {
        &self.forest
    }
}

impl<C, F> accumulator::Types for MerkleForest<C, F>
where
    C: Configuration + ?Sized,
    F: Forest<C>,
{
    type Item = Leaf<C>;
    type Witness = Path<C>;
    type Output = Root<C>;
}

impl<C, F> Accumulator for MerkleForest<C, F>
where
    C: Configuration + ?Sized,
    F: Forest<C>,
    F::Tree: WithProofs<C>,
    InnerDigest<C>: Clone + PartialEq,
{
    type Model = Parameters<C>;

    #[inline]
    fn model(&self) -> &Self::Model {
        self.parameters()
    }

    #[inline]
    fn insert(&mut self, item: &Self::Item) -> bool {
        self.forest
            .get_tree_mut(item)
            .push_provable(&self.parameters, item)
    }

    #[inline]
    fn prove(&self, item: &Self::Item) -> Option<MembershipProof<Self::Model>> {
        let tree = self.forest.get_tree(item);
        Some(MembershipProof::new(
            tree.path(
                &self.parameters,
                tree.position(&self.parameters.digest(item))?,
            )
            .ok()?,
            tree.root().clone(),
        ))
    }

    #[inline]
    fn contains(&self, item: &Self::Item) -> bool {
        self.forest
            .get_tree(item)
            .contains(&self.parameters.digest(item))
    }
}

impl<C, F> ConstantCapacityAccumulator for MerkleForest<C, F>
where
    C: Configuration + ?Sized,
    F: ConstantWidthForest<C>,
    F::Tree: WithProofs<C>,
    InnerDigest<C>: Clone + PartialEq,
{
    #[inline]
    fn capacity() -> usize {
        capacity::<C, F>()
    }
}

impl<C, F> ExactSizeAccumulator for MerkleForest<C, F>
where
    C: Configuration + ?Sized,
    F: Forest<C>,
    F::Tree: WithProofs<C>,
    InnerDigest<C>: Clone + PartialEq,
{
    #[inline]
    fn len(&self) -> usize {
        self.len()
    }

    #[inline]
    fn is_empty(&self) -> bool {
        self.is_empty()
    }
}

impl<C, F> OptimizedAccumulator for MerkleForest<C, F>
where
    C: Configuration + ?Sized,
    F: Forest<C>,
    F::Tree: WithProofs<C>,
    InnerDigest<C>: Clone + PartialEq,
{
    #[inline]
    fn insert_nonprovable(&mut self, item: &Self::Item) -> bool {
        self.forest.get_tree_mut(item).push(&self.parameters, item)
    }

    #[inline]
    fn remove_proof(&mut self, item: &Self::Item) -> bool {
        let tree = self.forest.get_tree_mut(item);
        tree.position(&self.parameters.digest(item))
            .map(move |i| tree.remove_path(i))
            .unwrap_or(false)
    }
}

/// [`SingleTree`] Merkle Forest Index
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "openzl_util::serde", deny_unknown_fields)
)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SingleTreeIndex;

impl FixedIndex<1> for SingleTreeIndex {
    #[inline]
    fn from_index(index: usize) -> Self {
        let _ = index;
        Self
    }
}

impl From<SingleTreeIndex> for usize {
    #[inline]
    fn from(index: SingleTreeIndex) -> Self {
        let _ = index;
        Default::default()
    }
}

/// Single Tree Merkle Forest
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "openzl_util::serde", deny_unknown_fields)
)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SingleTree<C, COM = ()>(PhantomData<(C, COM)>)
where
    C: tree::Configuration<COM>;

impl<C, COM> tree::HashConfiguration<COM> for SingleTree<C, COM>
where
    C: tree::Configuration<COM>,
{
    type LeafHash = C::LeafHash;
    type InnerHash = C::InnerHash;
}

impl<C, COM> tree::Configuration<COM> for SingleTree<C, COM>
where
    C: tree::Configuration<COM>,
{
    const HEIGHT: usize = C::HEIGHT;
}

impl<C> Configuration for SingleTree<C>
where
    C: tree::Configuration,
{
    type Index = SingleTreeIndex;

    #[inline]
    fn tree_index(leaf: &Leaf<Self>) -> Self::Index {
        let _ = leaf;
        Default::default()
    }
}

/// Tree Array Merkle Forest Alias
pub type TreeArrayMerkleForest<C, T, const N: usize> = MerkleForest<C, TreeArray<C, T, N>>;

/// Tree Array
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(
        bound(deserialize = "T: Deserialize<'de>", serialize = "T: Serialize"),
        crate = "openzl_util::serde",
        deny_unknown_fields,
    )
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "T: Clone"),
    Debug(bound = "T: Debug"),
    Eq(bound = "T: Eq"),
    Hash(bound = "T: Hash"),
    PartialEq(bound = "T: PartialEq")
)]
pub struct TreeArray<C, T, const N: usize>
where
    C: Configuration + ?Sized,
    C::Index: FixedIndex<N>,
    T: Tree<C>,
{
    /// Array of Trees
    ///
    /// Typically, even for reasonable `N`, the size of this array is too big to fit on the stack,
    /// so we wrap it in a box to store on the heap.
    array: BoxArray<T, N>,

    /// Type Parameter Marker
    __: PhantomData<C>,
}

impl<C, T, const N: usize> TreeArray<C, T, N>
where
    C: Configuration + ?Sized,
    C::Index: FixedIndex<N>,
    T: Tree<C>,
{
    /// Builds a new [`TreeArray`] from `array`.
    #[inline]
    fn new(array: BoxArray<T, N>) -> Self {
        Self {
            array,
            __: PhantomData,
        }
    }
}

impl<C, T, const N: usize> AsRef<[T; N]> for TreeArray<C, T, N>
where
    C: Configuration + ?Sized,
    C::Index: FixedIndex<N>,
    T: Tree<C>,
{
    #[inline]
    fn as_ref(&self) -> &[T; N] {
        &self.array
    }
}

impl<C, T, const N: usize> AsMut<[T; N]> for TreeArray<C, T, N>
where
    C: Configuration + ?Sized,
    C::Index: FixedIndex<N>,
    T: Tree<C>,
{
    #[inline]
    fn as_mut(&mut self) -> &mut [T; N] {
        &mut self.array
    }
}

impl<C, T, const N: usize> Default for TreeArray<C, T, N>
where
    C: Configuration + ?Sized,
    C::Index: FixedIndex<N>,
    T: Default + Tree<C>,
{
    #[inline]
    fn default() -> Self {
        Self::new(BoxArray::from_unchecked(
            (0..N)
                .into_iter()
                .map(move |_| Default::default())
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        ))
    }
}

impl<C, T, const N: usize> Forest<C> for TreeArray<C, T, N>
where
    C: Configuration + ?Sized,
    C::Index: FixedIndex<N>,
    T: Tree<C>,
{
    type Tree = T;

    #[inline]
    fn new(parameters: &Parameters<C>) -> Self {
        Self::new(BoxArray::from_unchecked(
            (0..N)
                .into_iter()
                .map(move |_| T::new(parameters))
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        ))
    }

    #[inline]
    fn len(&self) -> usize {
        self.array.iter().map(T::len).sum()
    }

    #[inline]
    fn capacity(&self) -> usize {
        capacity::<C, Self>()
    }

    #[inline]
    fn get(&self, index: C::Index) -> &Self::Tree {
        &self.array[index.into()]
    }

    #[inline]
    fn get_mut(&mut self, index: C::Index) -> &mut Self::Tree {
        &mut self.array[index.into()]
    }
}

impl<C, T, const N: usize> ConstantWidthForest<C> for TreeArray<C, T, N>
where
    C: Configuration + ?Sized,
    C::Index: FixedIndex<N>,
    T: Tree<C>,
{
    const WIDTH: usize = N;
}

impl<C, T, const N: usize> From<[T; N]> for TreeArray<C, T, N>
where
    C: Configuration + ?Sized,
    C::Index: FixedIndex<N>,
    T: Tree<C>,
{
    #[inline]
    fn from(array: [T; N]) -> Self {
        Self::from(Box::new(array))
    }
}

impl<C, T, const N: usize> From<Box<[T; N]>> for TreeArray<C, T, N>
where
    C: Configuration + ?Sized,
    C::Index: FixedIndex<N>,
    T: Tree<C>,
{
    #[inline]
    fn from(array: Box<[T; N]>) -> Self {
        Self::new(BoxArray(array))
    }
}

impl<C, T, M, const N: usize> Rollback for MerkleForest<C, TreeArray<C, ForkedTree<C, T, M>, N>>
where
    C: Configuration + ?Sized,
    C::Index: FixedIndex<N>,
    T: Tree<C>,
    M: Default + InnerMap<C>,
    LeafDigest<C>: Clone + Default,
    InnerDigest<C>: Clone + Default + PartialEq,
{
    #[inline]
    fn rollback(&mut self) {
        for tree in self.forest.as_mut() {
            tree.reset_fork(&self.parameters);
        }
    }

    #[inline]
    fn commit(&mut self) {
        for tree in self.forest.as_mut() {
            tree.merge_fork(&self.parameters);
        }
    }
}
