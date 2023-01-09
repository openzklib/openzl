//! Merkle Tree Forks

use crate::merkle_tree::{
    capacity,
    inner_tree::{BTreeMap, InnerMap, PartialInnerTree},
    partial::Partial,
    path::{CurrentInnerPath, InnerPath},
    Configuration, CurrentPath, InnerDigest, Leaf, LeafDigest, Node, Parameters, Parity, Path,
    PathError, Root, Tree, WithProofs,
};
use alloc::{vec, vec::Vec};
use core::{borrow::Borrow, fmt::Debug, hash::Hash, marker::PhantomData, mem, ops::Deref};
use openzl_util::{
    derivative,
    pointer::{self, PointerFamily},
};

#[cfg(feature = "serde")]
use openzl_util::serde::{Deserialize, Serialize};

/// Fork-able Merkle Tree
#[derive(derivative::Derivative)]
#[derivative(Debug(bound = "P::Strong: Debug"))]
pub struct Trunk<C, T, P = pointer::SingleThreaded>
where
    C: Configuration + ?Sized,
    T: Tree<C>,
    P: PointerFamily<T>,
{
    /// Base Merkle Tree
    base: Option<P::Strong>,

    /// Type Parameter Marker
    __: PhantomData<C>,
}

impl<C, T, P> Trunk<C, T, P>
where
    C: Configuration + ?Sized,
    T: Tree<C>,
    P: PointerFamily<T>,
{
    /// Builds a new [`Trunk`] from a reference-counted tree.
    #[inline]
    fn build(base: Option<P::Strong>) -> Self {
        Self {
            base,
            __: PhantomData,
        }
    }

    /// Builds a new [`Trunk`] from a `base` merkle tree.
    #[inline]
    pub fn new(base: T) -> Self {
        Self::build(Some(P::new(base)))
    }

    /// Converts `self` back into its inner [`Tree`].
    ///
    /// # Crypto Safety
    ///
    /// This method automatically detaches all of the forks associated to this trunk. To attach them
    /// to another trunk, use [`Fork::attach`].
    #[inline]
    pub fn into_tree(self) -> T {
        P::claim(self.base.unwrap())
    }

    /// Creates a new fork of this trunk.
    #[inline]
    pub fn fork<M>(&self, parameters: &Parameters<C>) -> Fork<C, T, P, M>
    where
        M: Default + InnerMap<C>,
        LeafDigest<C>: Clone + Default,
        InnerDigest<C>: Default,
    {
        Fork::new(parameters, self)
    }

    /// Tries to attach `fork` to `self` as its new trunk, returning `false` if `fork` has
    /// too many leaves to fit in `self`.
    #[inline]
    pub fn attach<M>(&self, parameters: &Parameters<C>, fork: &mut Fork<C, T, P, M>) -> bool
    where
        M: Default + InnerMap<C>,
        LeafDigest<C>: Clone + Default,
        InnerDigest<C>: Default,
    {
        fork.attach(parameters, self)
    }

    /// Tries to merge `fork` onto `self`, returning `fork` back if it could not be merged.
    ///
    /// # Crypto Safety
    ///
    /// If the merge succeeds, this method automatically detaches all of the forks associated to
    /// this trunk. To attach them to another trunk, use [`Fork::attach`]. To attach them to this
    /// trunk, [`attach`](Self::attach) can also be used.
    ///
    /// Since merging will add leaves to the base tree, forks which were previously associated to
    /// this trunk will have to catch up. If [`Fork::attach`] or [`attach`](Self::attach) is used,
    /// the leaves which were added in this merge will exist before the first leaf in the fork in
    /// the final tree.
    #[inline]
    pub fn merge<M>(
        &mut self,
        parameters: &Parameters<C>,
        fork: Fork<C, T, P, M>,
    ) -> Result<(), Fork<C, T, P, M>>
    where
        M: Default + InnerMap<C>,
        LeafDigest<C>: Default,
    {
        match fork.get_attached_base(self) {
            Some(base) => {
                self.merge_branch(parameters, base, fork.branch);
                Ok(())
            }
            _ => Err(fork),
        }
    }

    /// Performs a merge of the `branch` onto `fork_base`, setting `self` equal to the resulting
    /// merged tree.
    #[inline]
    fn merge_branch<M>(
        &mut self,
        parameters: &Parameters<C>,
        fork_base: P::Strong,
        branch: Branch<C, M>,
    ) where
        M: InnerMap<C> + Default,
        LeafDigest<C>: Default,
    {
        self.base = Some(fork_base);
        let mut base = P::claim(mem::take(&mut self.base).unwrap());
        branch.merge(parameters, &mut base);
        self.base = Some(P::new(base));
    }

    /// Borrows the underlying merkle tree strong pointer.
    #[inline]
    fn borrow_base(&self) -> &P::Strong {
        self.base.as_ref().unwrap()
    }

    /// Borrows the underlying merkle tree.
    #[inline]
    fn get(&self) -> &T {
        self.borrow_base().borrow()
    }

    /// Returns a new weak pointer to the base tree.
    #[inline]
    fn downgrade(&self) -> P::Weak {
        P::downgrade(self.borrow_base())
    }

    /// Checks if the internal base tree uses the same pointer as `base`.
    #[inline]
    fn ptr_eq_base(&self, base: &P::Strong) -> bool {
        P::strong_ptr_eq(self.borrow_base(), base)
    }
}

impl<C, T, P> AsRef<T> for Trunk<C, T, P>
where
    C: Configuration + ?Sized,
    T: Tree<C>,
    P: PointerFamily<T>,
{
    #[inline]
    fn as_ref(&self) -> &T {
        self.get()
    }
}

impl<C, T, P> Borrow<T> for Trunk<C, T, P>
where
    C: Configuration + ?Sized,
    T: Tree<C>,
    P: PointerFamily<T>,
{
    #[inline]
    fn borrow(&self) -> &T {
        self.get()
    }
}

impl<C, T, P> Deref for Trunk<C, T, P>
where
    C: Configuration + ?Sized,
    T: Tree<C>,
    P: PointerFamily<T>,
{
    type Target = T;

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.get()
    }
}

/// Base Tree Leaf Contribution
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "openzl_util::serde", deny_unknown_fields)
)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
enum BaseContribution {
    /// No Leaves Contributed
    Empty,

    /// Left Leaf Contributed
    LeftLeaf,

    /// Both Leaves Contributed
    BothLeaves,
}

impl Default for BaseContribution {
    #[inline]
    fn default() -> Self {
        Self::Empty
    }
}

/// Merkle Tree Branch
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(
        bound(
            deserialize = r"
                LeafDigest<C>: Deserialize<'de>,
                InnerDigest<C>: Deserialize<'de>,
                M: Deserialize<'de>,
            ",
            serialize = r"
                LeafDigest<C>: Serialize,
                InnerDigest<C>: Serialize,
                M: Serialize,
            ",
        ),
        crate = "openzl_util::serde",
        deny_unknown_fields,
    )
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "LeafDigest<C>: Clone, InnerDigest<C>: Clone, M: Clone"),
    Debug(bound = "LeafDigest<C>: Debug, InnerDigest<C>: Debug, M: Debug"),
    Default(bound = "LeafDigest<C>: Default, InnerDigest<C>: Default")
)]
struct Branch<C, M = BTreeMap<C>>
where
    C: Configuration + ?Sized,
    M: Default + InnerMap<C>,
{
    /// Base Tree Contribution
    base_contribution: BaseContribution,

    /// Branch Data
    data: Partial<C, M>,
}

impl<C, M> Branch<C, M>
where
    C: Configuration + ?Sized,
    M: Default + InnerMap<C>,
{
    /// Builds a new branch off of `base`, extending by `leaf_digests`.
    #[inline]
    fn new<T>(
        parameters: &Parameters<C>,
        base: &T,
        leaf_digests: Vec<LeafDigest<C>>,
    ) -> Option<Self>
    where
        T: Tree<C>,
        LeafDigest<C>: Clone + Default,
        InnerDigest<C>: Default,
    {
        if leaf_digests.len() + base.len() >= capacity::<C, _>() {
            return None;
        }
        Some(Self::new_unchecked(parameters, base, leaf_digests))
    }

    /// Builds a new branch off of `base`, extending by `leaf_digests` without checking that
    /// `base` can accept new leaves.
    #[inline]
    fn new_unchecked<T>(
        parameters: &Parameters<C>,
        base: &T,
        leaf_digests: Vec<LeafDigest<C>>,
    ) -> Self
    where
        T: Tree<C>,
        LeafDigest<C>: Clone + Default,
        InnerDigest<C>: Default,
    {
        let (base_contribution, base_inner_digest, base_leaf_digests, inner_path) =
            Self::generate_branch_setup(parameters, base);
        let mut partial = Partial::new_unchecked(
            base_leaf_digests,
            PartialInnerTree::from_current(parameters, base_inner_digest, inner_path),
        );
        let partial_tree_len = partial.len();
        for (i, digest) in leaf_digests.into_iter().enumerate() {
            partial.push_leaf_digest(parameters, Node(partial_tree_len + i), digest);
        }
        Self {
            base_contribution,
            data: partial,
        }
    }

    /// Generates the setup data to compute [`new_unchecked`](Self::new_unchecked).
    #[inline]
    fn generate_branch_setup<T>(
        parameters: &Parameters<C>,
        base: &T,
    ) -> (
        BaseContribution,
        InnerDigest<C>,
        Vec<LeafDigest<C>>,
        CurrentInnerPath<C>,
    )
    where
        T: Tree<C>,
        LeafDigest<C>: Clone + Default,
        InnerDigest<C>: Default,
    {
        if base.is_empty() {
            (
                BaseContribution::Empty,
                Default::default(),
                Default::default(),
                base.current_path(parameters).inner_path,
            )
        } else {
            let current_leaf = base.current_leaf().unwrap();
            let current_path = base.current_path(parameters);
            match current_path.leaf_index().parity() {
                Parity::Left => (
                    BaseContribution::LeftLeaf,
                    parameters.join_leaves(current_leaf, &current_path.sibling_digest),
                    vec![current_leaf.clone()],
                    current_path.inner_path,
                ),
                Parity::Right => (
                    BaseContribution::BothLeaves,
                    parameters.join_leaves(&current_path.sibling_digest, current_leaf),
                    vec![current_path.sibling_digest, current_leaf.clone()],
                    current_path.inner_path,
                ),
            }
        }
    }

    /// Extracts the non-base leaves from `base_contribution` and `data`.
    #[inline]
    fn extract_leaves(
        base_contribution: BaseContribution,
        data: Partial<C, M>,
    ) -> Vec<LeafDigest<C>>
    where
        LeafDigest<C>: Default,
    {
        let mut leaf_digests = data.into_leaves();
        mem::drop(leaf_digests.drain(0..base_contribution as usize));
        leaf_digests
    }

    /// Tries to rebase `self` at `base`.
    #[inline]
    fn try_rebase<T>(&mut self, parameters: &Parameters<C>, base: &T) -> bool
    where
        T: Tree<C>,
        LeafDigest<C>: Clone + Default,
        InnerDigest<C>: Default,
    {
        if self.data.len() + base.len() - (self.base_contribution as usize) >= capacity::<C, _>() {
            return false;
        }
        let new_branch = Self::new_unchecked(
            parameters,
            base,
            Self::extract_leaves(self.base_contribution, mem::take(&mut self.data)),
        );
        *self = new_branch;
        true
    }

    /// Computes the length of this branch of the tree.
    #[inline]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns `true` if this branch is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Returns the current root of this branch.
    #[inline]
    pub fn root(&self) -> &InnerDigest<C> {
        self.data.root()
    }

    /// Returns the leaf digest at the given `index` in the tree.
    #[inline]
    pub fn leaf_digest(&self, index: usize) -> Option<&LeafDigest<C>> {
        self.data.leaf_digest(index)
    }

    /// Returns the current (right-most) leaf of the branch.
    #[inline]
    pub fn current_leaf(&self) -> Option<&LeafDigest<C>> {
        self.data.current_leaf()
    }

    /// Returns the current (right-most) path of the branch.
    #[inline]
    pub fn current_path(&self) -> CurrentPath<C>
    where
        LeafDigest<C>: Clone + Default,
        InnerDigest<C>: Clone + Default + PartialEq,
    {
        self.data.current_path()
    }

    /// Computes the modified path for leaves in the main trunk.
    #[inline]
    fn modified_path_unchecked<T>(
        &self,
        parameters: &Parameters<C>,
        index: usize,
        base: &T,
    ) -> Result<Path<C>, PathError>
    where
        T: WithProofs<C>,
        LeafDigest<C>: Clone + Default,
        InnerDigest<C>: Clone,
    {
        let base_index = Node(index);
        let base_path = base.path(parameters, base_index.0)?;
        let fork_index = self.data.starting_leaf_node();
        let mut fork_path = self.data.path_unchecked(fork_index.0);
        if !Node::are_siblings(&base_index, &fork_index) {
            let matching_index = base_index
                .parents()
                .zip(fork_index.parents())
                .position(|(b, f)| Node::are_siblings(&b, &f))
                .unwrap();
            fork_path.inner_path.path[matching_index] = InnerPath::fold(
                parameters,
                fork_index,
                fork_index.join_leaves(
                    parameters,
                    self.leaf_digest(fork_index.0)
                        .unwrap_or(&Default::default()),
                    &fork_path.sibling_digest,
                ),
                &fork_path.inner_path.path[..matching_index],
            );
            fork_path.inner_path.path[..matching_index]
                .clone_from_slice(&base_path.inner_path.path[..matching_index]);
        }
        fork_path.inner_path.leaf_index = base_path.inner_path.leaf_index;
        fork_path.sibling_digest = base_path.sibling_digest;
        Ok(fork_path)
    }

    /// Computes the path of any leaf in the forked tree, assuming that `modified_path` returns the
    /// outcome of [`modified_path_unchecked`](Self::modified_path_unchecked) on some base tree.
    #[inline]
    fn path<F>(&self, index: usize, modified_path: F) -> Result<Path<C>, PathError>
    where
        F: FnOnce(&Self) -> Result<Path<C>, PathError>,
        LeafDigest<C>: Clone + Default,
        InnerDigest<C>: Clone,
    {
        let length = self.len();
        if index > 0 && index >= length {
            return Err(PathError::IndexTooLarge { length });
        }
        if index < self.data.starting_leaf_index() {
            modified_path(self)
        } else {
            Ok(self.data.path_unchecked(index))
        }
    }

    /// Appends a new `leaf` onto this branch.
    #[inline]
    pub fn push(&mut self, parameters: &Parameters<C>, leaf: &Leaf<C>) -> bool
    where
        LeafDigest<C>: Default,
    {
        self.data.push(parameters, leaf)
    }

    /// Appends a new `leaf_digest` onto this branch.
    #[inline]
    fn maybe_push_digest<F>(&mut self, parameters: &Parameters<C>, leaf_digest: F) -> Option<bool>
    where
        F: FnOnce() -> Option<LeafDigest<C>>,
        LeafDigest<C>: Default,
    {
        self.data.maybe_push_digest(parameters, leaf_digest)
    }

    /// Merges `self` into `base`.
    ///
    /// # Panics
    ///
    /// This method panics if the [`Tree::extend_digests`] method returns an `Err` variant because
    /// the capacity invariant should have prevented the addition of leaves to this branch if they
    /// would have exceeded the capacity limit of `base`.
    #[inline]
    fn merge<T>(self, parameters: &Parameters<C>, base: &mut T)
    where
        T: Tree<C>,
        LeafDigest<C>: Default,
    {
        assert!(
            base.extend_digests(
                parameters,
                Self::extract_leaves(self.base_contribution, self.data)
            )
            .is_ok(),
            "Should have been able to extend extracted leaves."
        );
    }
}

/// Merkle Tree Fork
#[derive(derivative::Derivative)]
#[derivative(
    Debug(bound = "P::Weak: Debug, LeafDigest<C>: Debug, InnerDigest<C>: Debug, M: Debug"),
    Default(bound = "LeafDigest<C>: Default, InnerDigest<C>: Default")
)]
pub struct Fork<C, T, P = pointer::SingleThreaded, M = BTreeMap<C>>
where
    C: Configuration + ?Sized,
    T: Tree<C>,
    P: PointerFamily<T>,
    M: Default + InnerMap<C>,
{
    /// Base Merkle Tree
    base: P::Weak,

    /// Branch Data
    branch: Branch<C, M>,
}

impl<C, T, P, M> Fork<C, T, P, M>
where
    C: Configuration + ?Sized,
    T: Tree<C>,
    P: PointerFamily<T>,
    M: Default + InnerMap<C>,
{
    /// Builds a new [`Fork`] off of `trunk` with the given `base_contribution` and `branch`.
    #[inline]
    fn build(trunk: &Trunk<C, T, P>, branch: Branch<C, M>) -> Self {
        Self {
            base: trunk.downgrade(),
            branch,
        }
    }

    /// Builds a new [`Fork`] from `trunk`.
    #[inline]
    pub fn new(parameters: &Parameters<C>, trunk: &Trunk<C, T, P>) -> Self
    where
        LeafDigest<C>: Clone + Default,
        InnerDigest<C>: Default,
    {
        let branch = Branch::new_unchecked(parameters, trunk.get(), Default::default());
        Self::build(trunk, branch)
    }

    /// Builds a new [`Fork`] from `trunk` extended by `leaf_digests`, returning `None` if
    /// appending `leaf_digests` would exceed the capacity of the `trunk`.
    #[inline]
    pub fn with_leaves(
        parameters: &Parameters<C>,
        trunk: &Trunk<C, T, P>,
        leaf_digests: Vec<LeafDigest<C>>,
    ) -> Option<Self>
    where
        LeafDigest<C>: Clone + Default,
        InnerDigest<C>: Default,
    {
        let branch = Branch::new(parameters, trunk.get(), leaf_digests)?;
        Some(Self::build(trunk, branch))
    }

    /// Tries to attach this fork to a new `trunk`, returning `false` if `self` has too many leaves
    /// to fit in `trunk`.
    #[inline]
    pub fn attach(&mut self, parameters: &Parameters<C>, trunk: &Trunk<C, T, P>) -> bool
    where
        LeafDigest<C>: Clone + Default,
        InnerDigest<C>: Default,
    {
        if !self.branch.try_rebase(parameters, trunk.get()) {
            return false;
        }
        self.base = trunk.downgrade();
        true
    }

    /// Returns `true` if this fork is attached to some [`Trunk`].
    #[inline]
    pub fn is_attached(&self) -> bool {
        P::upgrade(&self.base).is_some()
    }

    /// Returns `true` if this fork is attached to `trunk`.
    #[inline]
    pub fn is_attached_to(&self, trunk: &Trunk<C, T, P>) -> bool {
        matches!(P::upgrade(&self.base), Some(base) if trunk.ptr_eq_base(&base))
    }

    /// Returns the attached base tree if `self` is attached to `trunk`.
    #[inline]
    fn get_attached_base(&self, trunk: &Trunk<C, T, P>) -> Option<P::Strong> {
        match P::upgrade(&self.base) {
            Some(base) if trunk.ptr_eq_base(&base) => Some(base),
            _ => None,
        }
    }

    /// Checks if `self` is still attached to `trunk`.
    #[inline]
    fn check_attachment(&self) -> Option<()> {
        let _ = P::upgrade(&self.base)?;
        Some(())
    }

    /// Computes the length of this fork of the tree.
    #[inline]
    pub fn len(&self) -> usize {
        self.branch.len()
    }

    /// Returns `true` if this fork is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.branch.is_empty()
    }

    /// Returns the current root of this fork.
    #[inline]
    pub fn root(&self) -> &InnerDigest<C> {
        self.branch.root()
    }

    /// Returns the leaf digest at the given `index` in the tree.
    #[inline]
    pub fn leaf_digest(&self, index: usize) -> Option<&LeafDigest<C>> {
        self.branch.leaf_digest(index)
    }

    /// Returns the position of `leaf_digest` in the tree.
    #[inline]
    pub fn position(&self, leaf_digest: &LeafDigest<C>) -> Option<usize>
    where
        T: WithProofs<C>,
        LeafDigest<C>: PartialEq,
    {
        self.branch.data.position(leaf_digest).or_else(move || {
            P::upgrade(&self.base).and_then(move |b| b.borrow().position(leaf_digest))
        })
    }

    /// Returns the current (right-most) leaf of the tree.
    #[inline]
    pub fn current_leaf(&self) -> Option<&LeafDigest<C>> {
        self.branch.current_leaf()
    }

    /// Returns the current (right-most) path of the tree.
    #[inline]
    pub fn current_path(&self) -> CurrentPath<C>
    where
        LeafDigest<C>: Clone + Default,
        InnerDigest<C>: Clone + Default + PartialEq,
    {
        self.branch.current_path()
    }

    /// Returns the path at the given `index` in the tree.
    #[inline]
    pub fn path(&self, parameters: &Parameters<C>, index: usize) -> Result<Path<C>, PathError>
    where
        T: WithProofs<C>,
        LeafDigest<C>: Clone + Default,
        InnerDigest<C>: Clone,
    {
        self.branch
            .path(index, move |branch| match P::upgrade(&self.base) {
                Some(base) => branch.modified_path_unchecked(parameters, index, base.borrow()),
                _ => Err(PathError::MissingPath),
            })
    }

    /// Appends a new `leaf` onto this fork.
    ///
    /// Returns `None` if this fork has been detached from its trunk. Use [`attach`](Self::attach)
    /// to re-associate a trunk to this fork.
    #[inline]
    pub fn push(&mut self, parameters: &Parameters<C>, leaf: &Leaf<C>) -> Option<bool>
    where
        LeafDigest<C>: Default,
    {
        self.check_attachment()?;
        Some(self.branch.push(parameters, leaf))
    }

    /// Appends a new `leaf_digest` onto this fork.
    ///
    /// Returns `None` if this fork has been detached from its trunk. Use [`attach`](Self::attach)
    /// to re-associate a trunk to this fork.
    #[inline]
    pub fn maybe_push_digest<F>(
        &mut self,
        parameters: &Parameters<C>,
        leaf_digest: F,
    ) -> Option<bool>
    where
        F: FnOnce() -> Option<LeafDigest<C>>,
        LeafDigest<C>: Default,
    {
        self.check_attachment()?;
        self.branch.maybe_push_digest(parameters, leaf_digest)
    }
}

/// Forked Tree
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(
        bound(
            deserialize = r"
                T: Deserialize<'de>,
                LeafDigest<C>: Deserialize<'de>,
                InnerDigest<C>: Deserialize<'de>,
                M: Deserialize<'de>,
            ",
            serialize = r"
                T: Serialize,
                LeafDigest<C>: Serialize,
                InnerDigest<C>: Serialize,
                M: Serialize,
            ",
        ),
        crate = "openzl_util::serde",
        deny_unknown_fields,
    )
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "T: Clone, LeafDigest<C>: Clone, InnerDigest<C>: Clone, M: Clone"),
    Debug(bound = "T: Debug, LeafDigest<C>: Debug, InnerDigest<C>: Debug, M: Debug")
)]
pub struct ForkedTree<C, T, M = BTreeMap<C>>
where
    C: Configuration + ?Sized,
    T: Tree<C>,
    M: Default + InnerMap<C>,
{
    /// Base Tree
    base: T,

    /// Branch Data
    branch: Branch<C, M>,
}

impl<C, T, M> ForkedTree<C, T, M>
where
    C: Configuration + ?Sized,
    T: Tree<C>,
    M: Default + InnerMap<C>,
{
    /// Builds a new [`ForkedTree`] for `tree`.
    #[inline]
    pub fn new(tree: T, parameters: &Parameters<C>) -> Self
    where
        LeafDigest<C>: Clone + Default,
        InnerDigest<C>: Default,
    {
        let branch = Branch::new_unchecked(parameters, &tree, Default::default());
        Self { base: tree, branch }
    }

    /// Computes the length of this forked tree.
    #[inline]
    pub fn len(&self) -> usize {
        self.branch.len()
    }

    /// Returns `true` if this forked tree is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.branch.is_empty()
    }

    /// Returns the current root of this forked tree.
    #[inline]
    pub fn root(&self) -> &InnerDigest<C> {
        self.branch.root()
    }

    /// Returns the leaf digest at the given `index` in the forked tree.
    #[inline]
    pub fn leaf_digest(&self, index: usize) -> Option<&LeafDigest<C>> {
        self.branch.leaf_digest(index)
    }

    /// Returns the position of `leaf_digest` in the forked tree.
    #[inline]
    pub fn position(&self, leaf_digest: &LeafDigest<C>) -> Option<usize>
    where
        T: WithProofs<C>,
        LeafDigest<C>: PartialEq,
    {
        self.branch
            .data
            .position(leaf_digest)
            .or_else(move || self.base.position(leaf_digest))
    }

    /// Returns the current (right-most) leaf of the forked tree.
    #[inline]
    pub fn current_leaf(&self) -> Option<&LeafDigest<C>> {
        self.branch.current_leaf()
    }

    /// Returns the current (right-most) path of the forked tree.
    #[inline]
    pub fn current_path(&self) -> CurrentPath<C>
    where
        LeafDigest<C>: Clone + Default,
        InnerDigest<C>: Clone + Default + PartialEq,
    {
        self.branch.current_path()
    }

    /// Returns the path at the given `index` in the forked tree.
    #[inline]
    pub fn path(&self, parameters: &Parameters<C>, index: usize) -> Result<Path<C>, PathError>
    where
        T: WithProofs<C>,
        LeafDigest<C>: Clone + Default,
        InnerDigest<C>: Clone,
    {
        self.branch.path(index, |branch| {
            branch.modified_path_unchecked(parameters, index, &self.base)
        })
    }

    /// Appends a new `leaf` onto this forked tree.
    #[inline]
    pub fn push(&mut self, parameters: &Parameters<C>, leaf: &Leaf<C>) -> bool
    where
        LeafDigest<C>: Default,
    {
        self.branch.push(parameters, leaf)
    }

    /// Appends a new `leaf_digest` onto this forked tree.
    #[inline]
    fn maybe_push_digest<F>(&mut self, parameters: &Parameters<C>, leaf_digest: F) -> Option<bool>
    where
        F: FnOnce() -> Option<LeafDigest<C>>,
        LeafDigest<C>: Default,
    {
        self.branch.maybe_push_digest(parameters, leaf_digest)
    }

    /// Resets the fork of the base tree back to the trunk.
    #[inline]
    pub fn reset_fork(&mut self, parameters: &Parameters<C>)
    where
        LeafDigest<C>: Clone + Default,
        InnerDigest<C>: Default,
    {
        self.branch = Branch::new_unchecked(parameters, &self.base, Default::default());
    }

    /// Merges the fork of the base tree back into the trunk.
    #[inline]
    pub fn merge_fork(&mut self, parameters: &Parameters<C>)
    where
        LeafDigest<C>: Clone + Default,
        InnerDigest<C>: Default,
    {
        mem::take(&mut self.branch).merge(parameters, &mut self.base);
        self.reset_fork(parameters)
    }
}

impl<C, T, M> Tree<C> for ForkedTree<C, T, M>
where
    C: Configuration + ?Sized,
    T: Tree<C>,
    M: Default + InnerMap<C>,
    LeafDigest<C>: Clone + Default,
    InnerDigest<C>: Clone + Default + PartialEq,
{
    #[inline]
    fn new(parameters: &Parameters<C>) -> Self {
        Self::new(T::new(parameters), parameters)
    }

    #[inline]
    fn len(&self) -> usize {
        self.len()
    }

    #[inline]
    fn current_leaf(&self) -> Option<&LeafDigest<C>> {
        self.current_leaf()
    }

    #[inline]
    fn root(&self) -> &Root<C> {
        self.root()
    }

    #[inline]
    fn current_path(&self, parameters: &Parameters<C>) -> CurrentPath<C> {
        let _ = parameters;
        self.current_path()
    }

    #[inline]
    fn maybe_push_digest<F>(&mut self, parameters: &Parameters<C>, leaf_digest: F) -> Option<bool>
    where
        F: FnOnce() -> Option<LeafDigest<C>>,
    {
        self.maybe_push_digest(parameters, leaf_digest)
    }
}

impl<C, T, M> WithProofs<C> for ForkedTree<C, T, M>
where
    C: Configuration + ?Sized,
    T: Tree<C> + WithProofs<C>,
    M: Default + InnerMap<C>,
    LeafDigest<C>: Clone + Default + PartialEq,
    InnerDigest<C>: Clone + Default,
{
    #[inline]
    fn leaf_digest(&self, index: usize) -> Option<&LeafDigest<C>> {
        self.leaf_digest(index)
    }

    #[inline]
    fn position(&self, leaf_digest: &LeafDigest<C>) -> Option<usize> {
        self.position(leaf_digest)
    }

    #[inline]
    fn maybe_push_provable_digest<F>(
        &mut self,
        parameters: &Parameters<C>,
        leaf_digest: F,
    ) -> Option<bool>
    where
        F: FnOnce() -> Option<LeafDigest<C>>,
    {
        self.maybe_push_digest(parameters, leaf_digest)
    }

    #[inline]
    fn path(&self, parameters: &Parameters<C>, index: usize) -> Result<Path<C>, PathError> {
        self.path(parameters, index)
    }
}
