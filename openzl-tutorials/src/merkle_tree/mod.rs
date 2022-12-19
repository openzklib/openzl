//! Generic Binary Merkle Tree

use core::marker::PhantomData;
use eclair::{bool::Bool, cmp::PartialEq, Has};
use openzl_crypto::accumulator::{
    Accumulator, MembershipProof as AccumulatorMembershipProof, Model as AccumulatorModel,
    Types as AccumulatorTypes,
};
use openzl_util::derivative;

#[cfg(all(feature = "alloc", feature = "bn254", feature = "groth16"))]
pub mod arkworks;

/// Merkle Tree Node Hasher
pub trait Hasher<COM = ()> {
    /// Node Type
    type Node: Default;

    /// Combines `lhs` and `rhs` nodes.
    fn combine(&self, lhs: &Self::Node, rhs: &Self::Node, compiler: &mut COM) -> Self::Node;
}

/// Proof Index
pub trait ProofIndex<COM = ()> {
    /// Computes the parent of the `self` index.
    fn parent(&self, compiler: &mut COM) -> Self;

    /// Computes the sibling of the `self` index.
    fn sibling(&self, compiler: &mut COM) -> Self;

    /// Combines `lhs` and `rhs` using `hasher` depending on the value of `self`.
    fn combine<H>(&self, hasher: &H, lhs: &H::Node, rhs: &H::Node, compiler: &mut COM) -> H::Node
    where
        H: Hasher<COM>;
}

impl ProofIndex for u64 {
    #[inline]
    fn parent(&self, _: &mut ()) -> Self {
        self >> 1
    }

    #[inline]
    fn sibling(&self, _: &mut ()) -> Self {
        match self % 2 {
            0 => self + 1,
            1 => self - 1,
            _ => unreachable!(),
        }
    }

    #[inline]
    fn combine<H>(&self, hasher: &H, lhs: &H::Node, rhs: &H::Node, compiler: &mut ()) -> H::Node
    where
        H: Hasher,
    {
        if self % 2 == 0 {
            hasher.combine(lhs, rhs, compiler)
        } else {
            hasher.combine(rhs, lhs, compiler)
        }
    }
}

/// Merkle Tree
#[derive(derivative::Derivative)]
#[derivative(Clone(bound = "H::Node: Clone"))]
pub struct MerkleTree<H>
where
    H: Hasher,
{
    /// Leaf Count
    leaf_count: usize,

    /// Node Storage
    nodes: Vec<H::Node>,
}

impl<H> MerkleTree<H>
where
    H: Hasher,
{
    /// Builds a Merkle Tree over `leaves` using `hasher`.
    #[inline]
    pub fn new(hasher: &H, mut leaves: Vec<H::Node>) -> Self {
        let leaf_count = leaves.len();
        let tree_size = leaf_count
            .checked_next_power_of_two()
            .expect("Unable to build a Merkle Tree with that size.");
        let mut nodes = Vec::with_capacity(2 * tree_size);
        nodes.resize_with(tree_size, Default::default);
        nodes.append(&mut leaves);
        nodes.resize_with(2 * tree_size, Default::default);
        for i in (1..tree_size).rev() {
            nodes[i] = hasher.combine(&nodes[2 * i], &nodes[2 * i + 1], &mut ());
        }
        Self { leaf_count, nodes }
    }

    /// Computes the size of the base of the tree.
    #[inline]
    fn tree_size(&self) -> usize {
        self.nodes.len() >> 1
    }

    /// Returns the depth of the tree.
    #[inline]
    pub fn depth(&self) -> u32 {
        self.tree_size().ilog2()
    }

    /// Returns a slice into the leaves of the tree.
    #[inline]
    pub fn leaves(&self) -> &[H::Node] {
        let tree_size = self.tree_size();
        &self.nodes[tree_size..tree_size + self.leaf_count]
    }

    /// Returns the root of the tree.
    #[inline]
    pub fn root(&self) -> &H::Node {
        &self.nodes[1]
    }

    /// Returns the path over the leaf at the given `index`.
    #[inline]
    pub fn path(&self, index: usize) -> MerklePath<H>
    where
        H::Node: Clone,
    {
        let path_length = self.depth();
        let tree_index = (index + self.tree_size()) as u32;
        let mut siblings = Vec::with_capacity(path_length as usize);
        let mut node_index = tree_index as u64;

        for _ in 0..path_length {
            siblings.push(self.nodes[node_index.sibling(&mut ()) as usize].clone());
            node_index = node_index.parent(&mut ());
        }
        MerklePath {
            index: tree_index as u64,
            siblings,
        }
    }
}

/// Merkle Path
pub struct MerklePath<H, I = u64, COM = ()>
where
    H: Hasher<COM>,
    I: ProofIndex<COM>,
{
    /// Leaf Index
    pub index: I,

    /// Sibling Nodes
    pub siblings: Vec<H::Node>,
}

impl<H, I, COM> MerklePath<H, I, COM>
where
    H: Hasher<COM>,
    I: ProofIndex<COM>,
{
    /// Computes the root of the Merkle Tree that `leaf` belongs to using `hasher`.
    #[inline]
    pub fn root(&self, hasher: &H, leaf: &H::Node, compiler: &mut COM) -> H::Node {
        let mut node = self
            .index
            .combine(hasher, leaf, &self.siblings[0], compiler);
        let mut index = self.index.parent(compiler);
        for sibling in self.siblings.iter().skip(1) {
            node = index.combine(hasher, &node, sibling, compiler);
            index = index.parent(compiler);
        }
        node
    }
}

/// Merkle Tree Parameters
#[derive(derivative::Derivative)]
#[derivative(Clone(bound = "H: Clone"))]
pub struct Parameters<H, COM = ()>
where
    H: Hasher<COM>,
{
    hasher: H,
    __: PhantomData<COM>,
}

impl<H, COM> Parameters<H, COM>
where
    H: Hasher<COM>,
{
    pub fn new(hasher: H) -> Self {
        Self {
            hasher,
            __: PhantomData,
        }
    }
}

impl<H, COM> AccumulatorTypes for Parameters<H, COM>
where
    H: Hasher<COM>,
    u64: ProofIndex<COM>,
{
    type Item = <H as Hasher<COM>>::Node;
    type Witness = MerklePath<H, u64, COM>;
    type Output = <H as Hasher<COM>>::Node;
}

impl<H, COM> AccumulatorModel<COM> for Parameters<H, COM>
where
    H: Hasher<COM>,
    u64: ProofIndex<COM>,
    Self::Output: PartialEq<Self::Output, COM>,
    COM: Has<bool>,
{
    type Verification = Bool<COM>;

    fn verify(
        &self,
        item: &Self::Item,
        witness: &Self::Witness,
        output: &Self::Output,
        compiler: &mut COM,
    ) -> Self::Verification {
        let computed_root = witness.root(&self.hasher, item, compiler);
        computed_root.eq(output, compiler)
    }
}

/// Accumulator with `COM = ()`.
#[derive(derivative::Derivative)]
#[derivative(Clone(bound = "MerkleTree<H>: Clone, Parameters<H>: Clone"))]
pub struct ConcreteAccumulator<H>
where
    H: Hasher,
{
    pub tree: MerkleTree<H>,
    pub parameters: Parameters<H>,
}

impl<H> ConcreteAccumulator<H>
where
    H: Hasher,
{
    /// Constructor
    pub fn new(tree: MerkleTree<H>, parameters: Parameters<H>) -> Self {
        Self { tree, parameters }
    }

    /// Construct a tree from `leaves`, then construct accumulator from resulting tree and `parameters`.
    pub fn from_leaves(leaves: Vec<H::Node>, parameters: Parameters<H>) -> Self
    where
        H::Node: Clone,
    {
        Self::new(MerkleTree::new(&parameters.hasher, leaves), parameters)
    }
}

impl<H> AccumulatorTypes for ConcreteAccumulator<H>
where
    H: Hasher,
{
    type Item = <H as Hasher>::Node;
    type Witness = MerklePath<H>;
    type Output = <H as Hasher>::Node;
}

impl<H> AccumulatorModel for ConcreteAccumulator<H>
where
    H: Hasher,
    H::Node: PartialEq<Self::Output>,
{
    type Verification = bool;

    fn verify(
        &self,
        item: &Self::Item,
        witness: &Self::Witness,
        output: &Self::Output,
        _: &mut (),
    ) -> Self::Verification {
        self.parameters.verify(item, witness, output, &mut ())
    }
}

impl<H> Accumulator for ConcreteAccumulator<H>
where
    H: Hasher,
    Parameters<H>:
        AccumulatorModel<Item = Self::Item, Witness = Self::Witness, Output = Self::Output> + Clone,
    Self::Item: Clone,
    H::Node: PartialEq<Self::Output> + core::cmp::PartialEq<Self::Output>,
{
    type Model = Self;

    fn model(&self) -> &Self::Model {
        self
    }

    fn insert(&mut self, item: &Self::Item) -> bool {
        // TODO: A proper `push` method for trees
        // This pushes a leaf then builds the tree from scratch
        let mut leaves = Vec::from(self.tree.leaves());
        leaves.push(item.clone());
        let tree = MerkleTree::new(&self.parameters.hasher, leaves);
        let parameters = self.parameters.clone();
        *self = Self::new(tree, parameters);
        true
    }

    fn prove(&self, item: &Self::Item) -> Option<AccumulatorMembershipProof<Self::Model>> {
        // TODO: an `index` method for nodes
        let mut node_iter = self.tree.nodes.clone().into_iter();
        let mut index = node_iter.position(|i| i == *item)?;
        index -= self.tree.tree_size();
        Some(AccumulatorMembershipProof::new(
            self.tree.path(index),
            self.tree.root().clone(),
        ))
    }
}
