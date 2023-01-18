//! Single Path Merkle Tree Storage

// TODO: Should we be storing the root? Can we have a version where we don't?
// TODO: How should we design the free functions here? We need them for now for ledger state, but
//       it would be nice to have a more elegant solution that doesn't require duplicate interfaces.

use crate::merkle_tree::{
    capacity, Configuration, CurrentPath, InnerDigest, LeafDigest, MerkleTree, Parameters, Root,
    Tree,
};
use core::{fmt::Debug, hash::Hash};
use openzl_util::derivative;

/// Tree Length State
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Length {
    /// Empty Tree
    Empty,

    /// Can Accept Leaves
    CanAccept,

    /// Full Tree
    Full,
}

/// Single Path Merkle Tree Type
pub type SinglePathMerkleTree<C> = MerkleTree<C, SinglePath<C>>;

/// Single Path Merkle Tree Backing Structure
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "LeafDigest<C>: Clone, InnerDigest<C>: Clone"),
    Debug(bound = "LeafDigest<C>: Debug, InnerDigest<C>: Debug"),
    Default(bound = "LeafDigest<C>: Default, InnerDigest<C>: Default"),
    Eq(bound = "LeafDigest<C>: Eq, InnerDigest<C>: Eq"),
    Hash(bound = "LeafDigest<C>: Hash, InnerDigest<C>: Hash"),
    PartialEq(bound = "LeafDigest<C>: PartialEq, InnerDigest<C>: PartialEq")
)]
pub struct SinglePath<C>
where
    C: Configuration + ?Sized,
{
    /// Leaf Digest
    leaf_digest: Option<LeafDigest<C>>,

    /// Current Path
    current_path: CurrentPath<C>,

    /// Root
    root: Root<C>,
}

impl<C> SinglePath<C>
where
    C: Configuration + ?Sized,
{
    /// Returns the number of leaves in the merkle tree.
    #[inline]
    fn len(&self) -> usize {
        if self.leaf_digest.is_none() {
            0
        } else {
            self.current_path.leaf_index().0 + 1
        }
    }

    /// Returns the state of the length of this tree.
    #[inline]
    pub fn length_state(&self) -> Length {
        raw::length_state(&self.leaf_digest, &self.current_path)
    }

    /// Returns the current merkle tree root.
    #[inline]
    pub fn root(&self) -> &Root<C> {
        &self.root
    }

    /// Returns the current merkle tree path for the current leaf.
    #[inline]
    pub fn current_path(&self) -> &CurrentPath<C> {
        &self.current_path
    }

    /// Returns the currently stored leaf digest, returning `None` if the tree is empty.
    #[inline]
    pub fn leaf_digest(&self) -> Option<&LeafDigest<C>> {
        self.leaf_digest.as_ref()
    }

    /// Computes the root of the tree under the assumption that `self.leaf_digest.is_some()`
    /// evaluates to `true`.
    #[inline]
    fn compute_root(&self, parameters: &Parameters<C>) -> Root<C>
    where
        InnerDigest<C>: Default,
    {
        self.current_path
            .root(parameters, self.leaf_digest().unwrap())
    }
}

impl<C> Tree<C> for SinglePath<C>
where
    C: Configuration + ?Sized,
    LeafDigest<C>: Clone + Default,
    InnerDigest<C>: Clone + Default,
{
    #[inline]
    fn new(parameters: &Parameters<C>) -> Self {
        let _ = parameters;
        Default::default()
    }

    #[inline]
    fn len(&self) -> usize {
        self.len()
    }

    #[inline]
    fn is_empty(&self) -> bool {
        self.leaf_digest.is_none()
    }

    #[inline]
    fn current_leaf(&self) -> Option<&LeafDigest<C>> {
        self.leaf_digest.as_ref()
    }

    #[inline]
    fn root(&self) -> &Root<C> {
        self.root()
    }

    #[inline]
    fn current_path(&self, parameters: &Parameters<C>) -> CurrentPath<C> {
        let _ = parameters;
        self.current_path.clone()
    }

    #[inline]
    fn maybe_push_digest<F>(&mut self, parameters: &Parameters<C>, leaf_digest: F) -> Option<bool>
    where
        F: FnOnce() -> Option<LeafDigest<C>>,
    {
        match self.length_state() {
            Length::Full => return Some(false),
            Length::Empty => {
                self.leaf_digest = Some(leaf_digest()?);
                self.root = self.compute_root(parameters);
            }
            Length::CanAccept => {
                self.root = self.current_path.update(
                    parameters,
                    self.leaf_digest.as_mut().unwrap(),
                    leaf_digest()?,
                );
            }
        }
        Some(true)
    }
}

/// Raw Merkle Tree Interfaces
pub mod raw {
    use super::*;

    /// Returns the state of the length of this tree.
    #[inline]
    pub fn length_state<C>(
        leaf_digest: &Option<LeafDigest<C>>,
        current_path: &CurrentPath<C>,
    ) -> Length
    where
        C: Configuration + ?Sized,
    {
        if leaf_digest.is_none() {
            Length::Empty
        } else if current_path.leaf_index().0 < capacity::<C, _>() - 1 {
            Length::CanAccept
        } else {
            Length::Full
        }
    }

    /// Inserts the `next` leaf digest into the tree updating the `leaf_digest` and the `current_path`.
    #[inline]
    pub fn insert<C>(
        parameters: &Parameters<C>,
        leaf_digest: &mut Option<LeafDigest<C>>,
        current_path: &mut CurrentPath<C>,
        next: LeafDigest<C>,
    ) -> Option<Root<C>>
    where
        C: Configuration + ?Sized,
        LeafDigest<C>: Default,
        InnerDigest<C>: Default,
    {
        match length_state(leaf_digest, current_path) {
            Length::Empty => {
                let root = current_path.root(parameters, &next);
                *leaf_digest = Some(next);
                Some(root)
            }
            Length::CanAccept => {
                Some(current_path.update(parameters, leaf_digest.as_mut().unwrap(), next))
            }
            Length::Full => None,
        }
    }
}
