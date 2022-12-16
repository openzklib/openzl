//! Inner Digest Tree

// TODO: Figure out how we want to expose the meaning of `InnerNode` coordinates. Should we share
//       some of it, to reduce potential duplication?
// TODO: We should probably move `InnerNode` and its related `struct`s to `merkle_tree::node`.

use crate::merkle_tree::{
    path::{CurrentInnerPath, InnerPath},
    path_length, Configuration, InnerDigest, Node, Parameters, Parity,
};
use alloc::collections::btree_map;
use core::{fmt::Debug, hash::Hash, iter::FusedIterator, marker::PhantomData, ops::Index};
use openzl_util::derivative;

#[cfg(feature = "serde")]
use openzl_util::serde::{Deserialize, Serialize};

#[cfg(feature = "std")]
use std::{collections::hash_map, hash::BuildHasher};

/// Inner Tree Node
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "openzl_util::serde", deny_unknown_fields)
)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct InnerNode {
    /// Depth
    depth: usize,

    /// Index
    index: Node,
}

impl InnerNode {
    /// Builds a new [`InnerNode`] from `depth` and `index`.
    #[inline]
    const fn new(depth: usize, index: Node) -> Self {
        Self { depth, index }
    }

    /// Builds an [`InnerNode`] as the parent of a `leaf_index`, returning `None` if the
    /// parent of `leaf_index` is the root and not an inner node.
    #[inline]
    pub fn from_leaf<C>(leaf_index: Node) -> Option<Self>
    where
        C: Configuration + ?Sized,
    {
        Self::new(path_length::<C, _>(), leaf_index).parent()
    }

    /// Returns the [`Parity`] of this inner node.
    #[inline]
    pub const fn parity(&self) -> Parity {
        self.index.parity()
    }

    /// Returns `true` if this inner node has left parity.
    #[inline]
    pub const fn is_left(&self) -> bool {
        self.parity().is_left()
    }

    /// Returns `true` if this inner node has right parity.
    #[inline]
    pub const fn is_right(&self) -> bool {
        self.parity().is_right()
    }

    /// Returns the [`InnerNode`] which is the sibling of `self`.
    #[inline]
    #[must_use]
    pub const fn sibling(&self) -> Self {
        Self::new(self.depth, self.index.sibling())
    }

    /// Returns the parent [`InnerNode`] of this inner node.
    #[inline]
    pub const fn parent(&self) -> Option<Self> {
        match self.depth.checked_sub(1) {
            Some(depth) => Some(Self::new(depth, self.index.parent())),
            _ => None,
        }
    }

    /// Converts `self` into its parent, if the parent exists, returning the parent [`InnerNode`].
    #[inline]
    pub fn into_parent(&mut self) -> Option<Self> {
        match self.parent() {
            Some(parent) => {
                *self = parent;
                Some(*self)
            }
            _ => None,
        }
    }

    /// Returns an iterator over `self` and its parents.
    #[inline]
    pub const fn iter(&self) -> InnerNodeIter {
        InnerNodeIter::new(Some(*self))
    }

    /// Computes the starting index for the given `self.depth` in the tree.
    #[inline]
    const fn depth_starting_index(&self) -> usize {
        (1 << (self.depth + 1)) - 1
    }

    /// Computes an [`InnerMap`] index for the coordinates represented by `self`.
    #[inline]
    pub const fn map_index(&self) -> usize {
        self.depth_starting_index() + self.index.0
    }
}

impl From<InnerNode> for Node {
    #[inline]
    fn from(inner_node: InnerNode) -> Node {
        inner_node.index
    }
}

/// Inner Node Iterator
///
/// An iterator over the ancestors of an [`InnerNode`], including the node itself.
///
/// This `struct` is created by the [`iter`](InnerNode::iter) method on [`InnerNode`].
/// See its documentation for more.
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "openzl_util::serde", deny_unknown_fields)
)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct InnerNodeIter {
    /// Current Node
    node: Option<InnerNode>,
}

impl InnerNodeIter {
    /// Builds a new [`InnerNodeIter`] from `node`.
    #[inline]
    const fn new(node: Option<InnerNode>) -> Self {
        Self { node }
    }

    /// Builds a new [`InnerNodeIter`] iterator over the parents of `leaf_index`.
    #[inline]
    pub fn from_leaf<C>(leaf_index: Node) -> Self
    where
        C: Configuration + ?Sized,
    {
        Self::new(InnerNode::from_leaf::<C>(leaf_index))
    }

    /// Returns `true` if the iterator has completed.
    #[inline]
    pub const fn is_done(&self) -> bool {
        self.node.is_none()
    }
}

// TODO: Add all methods which can be optimized.
impl Iterator for InnerNodeIter {
    type Item = InnerNode;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        let node = self.node.take()?;
        self.node = node.parent();
        Some(node)
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = self.node.map_or(0, move |n| n.depth + 1);
        (len, Some(len))
    }
}

impl ExactSizeIterator for InnerNodeIter {}

impl FusedIterator for InnerNodeIter {}

/// [`InnerTree`] Map Backend
pub trait InnerMap<C>
where
    C: Configuration + ?Sized,
{
    /// Returns the inner digest stored at `index`.
    fn get(&self, index: usize) -> Option<&InnerDigest<C>>;

    /// Sets the inner digest at `index` to `inner_digest`.
    fn set(&mut self, index: usize, inner_digest: InnerDigest<C>);

    /// Sets the inner digest at `index` to `inner_digest` and returns a reference to the
    /// newly stored value.
    #[inline]
    fn set_get(&mut self, index: usize, inner_digest: InnerDigest<C>) -> &InnerDigest<C> {
        self.set(index, inner_digest);
        self.get(index).unwrap()
    }

    /// Sets the inner digests at `lhs_index` and `rhs_index` to `lhs_digest` and `rhs_digest`
    /// respectively, returning their join.
    #[inline]
    fn set_and_join(
        &mut self,
        parameters: &Parameters<C>,
        lhs_index: usize,
        lhs_digest: InnerDigest<C>,
        rhs_index: usize,
        rhs_digest: InnerDigest<C>,
    ) -> InnerDigest<C> {
        let digest = parameters.join(&lhs_digest, &rhs_digest);
        self.set(lhs_index, lhs_digest);
        self.set(rhs_index, rhs_digest);
        digest
    }
}

impl<C, M> InnerMap<C> for &mut M
where
    C: Configuration + ?Sized,
    M: InnerMap<C>,
{
    #[inline]
    fn get(&self, index: usize) -> Option<&InnerDigest<C>> {
        (**self).get(index)
    }

    #[inline]
    fn set(&mut self, index: usize, inner_digest: InnerDigest<C>) {
        (**self).set(index, inner_digest);
    }
}

/// B-Tree Map [`InnerTree`] Backend
pub type BTreeMap<C> = btree_map::BTreeMap<usize, InnerDigest<C>>;

impl<C> InnerMap<C> for BTreeMap<C>
where
    C: Configuration + ?Sized,
{
    #[inline]
    fn get(&self, index: usize) -> Option<&InnerDigest<C>> {
        self.get(&index)
    }

    #[inline]
    fn set(&mut self, index: usize, inner_digest: InnerDigest<C>) {
        self.insert(index, inner_digest);
    }
}

/// Hash Map [`InnerTree`] Backend
#[cfg(feature = "std")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "std")))]
pub type HashMap<C, S = hash_map::RandomState> = hash_map::HashMap<usize, InnerDigest<C>, S>;

#[cfg(feature = "std")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "std")))]
impl<C, S> InnerMap<C> for HashMap<C, S>
where
    C: Configuration + ?Sized,
    S: Default + BuildHasher,
{
    #[inline]
    fn get(&self, index: usize) -> Option<&InnerDigest<C>> {
        self.get(&index)
    }

    #[inline]
    fn set(&mut self, index: usize, inner_digest: InnerDigest<C>) {
        self.insert(index, inner_digest);
    }
}

/// [`InnerTree`] Sentinel Source Tree Backend
pub trait SentinelSource<C>
where
    C: Configuration + ?Sized,
{
    /// Returns the sentinel value at the location `index` of the tree.
    fn get(&self, index: usize) -> &InnerDigest<C>;
}

impl<C, S> SentinelSource<C> for &S
where
    C: Configuration + ?Sized,
    S: SentinelSource<C>,
{
    #[inline]
    fn get(&self, index: usize) -> &InnerDigest<C> {
        (**self).get(index)
    }
}

impl<C, S> SentinelSource<C> for &mut S
where
    C: Configuration + ?Sized,
    S: SentinelSource<C>,
{
    #[inline]
    fn get(&self, index: usize) -> &InnerDigest<C> {
        (**self).get(index)
    }
}

/// Sentinel Source for a Single Sentinel Value
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(
        bound(
            deserialize = "InnerDigest<C>: Deserialize<'de>",
            serialize = "InnerDigest<C>: Serialize"
        ),
        crate = "openzl_util::serde",
        deny_unknown_fields
    )
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "InnerDigest<C>: Clone"),
    Copy(bound = "InnerDigest<C>: Copy"),
    Debug(bound = "InnerDigest<C>: Debug"),
    Default(bound = "InnerDigest<C>: Default"),
    Eq(bound = "InnerDigest<C>: Eq"),
    Hash(bound = "InnerDigest<C>: Hash"),
    PartialEq(bound = "InnerDigest<C>: PartialEq")
)]
pub struct Sentinel<C>(
    /// Sentinel Value
    pub InnerDigest<C>,
)
where
    C: Configuration + ?Sized;

impl<C> SentinelSource<C> for Sentinel<C>
where
    C: Configuration + ?Sized,
{
    #[inline]
    fn get(&self, index: usize) -> &InnerDigest<C> {
        let _ = index;
        &self.0
    }
}

/// Inner Tree
///
/// Tree data-structure for storing the inner digests of a merkle tree.
///
/// # Implementation Note
///
/// This type intentionally lacks an implementation of [`Tree`], especially since it does not store
/// leaf digests. Instead, [`Full`] should be used whenever a tree with the capability to request
/// arbitrary inner nodes is needed.
///
/// [`Tree`]: crate::merkle_tree::Tree
/// [`Full`]: crate::merkle_tree::full::Full
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "openzl_util::serde", deny_unknown_fields)
)]
#[derive(derivative::Derivative)]
#[derivative(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct InnerTree<C, M = BTreeMap<C>, S = Sentinel<C>>
where
    C: Configuration + ?Sized,
    M: InnerMap<C>,
    S: SentinelSource<C>,
{
    /// Inner Digest Map
    ///
    /// # Coordinates
    ///
    /// Locations in the tree are indexed by two coordinates `depth` and `index`. The `depth` of a
    /// node is given by its layer in the tree starting from `depth := -1` at the root increasing
    /// downwards towards the leaves. The `index` of a node is its position from left to right
    /// along a layer in the tree. See [`InnerNode`] for more details.
    map: M,

    /// Sentinel Source
    ///
    /// The background tree for sentinel values.
    sentinel_source: S,

    /// Type Parameter Marker
    __: PhantomData<C>,
}

impl<C, M, S> InnerTree<C, M, S>
where
    C: Configuration + ?Sized,
    M: InnerMap<C>,
    S: SentinelSource<C>,
{
    /// Builds a new [`InnerTree`].
    #[inline]
    pub fn new() -> Self
    where
        M: Default,
        S: Default,
    {
        Default::default()
    }

    /// Builds a new [`InnerTree`] with the given inner `map`.
    #[inline]
    pub fn with_map(map: M) -> Self
    where
        S: Default,
    {
        Self::with_map_and_sentinel(map, Default::default())
    }

    /// Builds a new [`InnerTree`] with the given `sentinel_source`.
    #[inline]
    pub fn with_sentinel(sentinel_source: S) -> Self
    where
        M: Default,
    {
        Self::with_map_and_sentinel(Default::default(), sentinel_source)
    }

    /// Builds a new [`InnerTree`] with the given `map` and `sentinel_source`.
    #[inline]
    pub fn with_map_and_sentinel(map: M, sentinel_source: S) -> Self {
        Self {
            map,
            sentinel_source,
            __: PhantomData,
        }
    }

    /// Tries to get the inner digest at `node`, returning `None` if the inner digest is missing.
    #[inline]
    pub fn get(&self, node: InnerNode) -> Option<&InnerDigest<C>> {
        self.map_get(node.map_index())
    }

    /// Returns the inner digest at `node` or a sentinel value if the inner digest is missing.
    #[inline]
    pub fn get_or_sentinel(&self, node: InnerNode) -> &InnerDigest<C> {
        self.map_get_or_sentinel(node.map_index())
    }

    /// Tries to return the inner digest at `index`, returning `None` if the inner digest is
    /// missing.
    #[inline]
    pub fn map_get(&self, index: usize) -> Option<&InnerDigest<C>> {
        self.map.get(index)
    }

    /// Returns the inner digest at `index` or a sentinel value if the inner digest is missing.
    #[inline]
    pub fn map_get_or_sentinel(&self, index: usize) -> &InnerDigest<C> {
        self.map_get(index)
            .unwrap_or_else(move || self.sentinel_source.get(index))
    }

    /// Returns a reference to the root inner digest.
    #[inline]
    pub fn root(&self) -> &InnerDigest<C> {
        self.map_get_or_sentinel(0)
    }

    /// Sets the current root to `root`.
    #[inline]
    fn set_root(&mut self, root: InnerDigest<C>) {
        self.map.set(0, root);
    }

    /// Inserts the new `inner_digest` at `node` in the tree, and returns a reference to
    /// `inner_digest` and its sibling in the tree in parity order.
    #[inline]
    fn insert_and_get_pair(
        &mut self,
        node: InnerNode,
        inner_digest: InnerDigest<C>,
    ) -> (&InnerDigest<C>, &InnerDigest<C>) {
        let index = node.map_index();
        self.map.set(index, inner_digest);
        match node.parity() {
            Parity::Left => (
                self.map_get_or_sentinel(index),
                self.map_get_or_sentinel(index + 1),
            ),
            Parity::Right => (
                self.map_get_or_sentinel(index - 1),
                self.map_get_or_sentinel(index),
            ),
        }
    }

    /// Inserts `inner_digest` into the tree at `node` and computes the join of `inner_digest`
    /// and its sibling in the tree, using the default value if its sibling is not stored in
    /// the tree.
    #[inline]
    fn insert_and_join(
        &mut self,
        parameters: &Parameters<C>,
        node: InnerNode,
        inner_digest: InnerDigest<C>,
    ) -> InnerDigest<C> {
        let (lhs, rhs) = self.insert_and_get_pair(node, inner_digest);
        parameters.join(lhs, rhs)
    }

    /// Computes the new root of the tree after inserting `base` which corresponds to the leaf at
    /// `leaf_index`.
    #[inline]
    fn compute_root(
        &mut self,
        parameters: &Parameters<C>,
        leaf_index: Node,
        base: InnerDigest<C>,
    ) -> InnerDigest<C> {
        InnerNodeIter::from_leaf::<C>(leaf_index).fold(base, move |acc, node| {
            self.insert_and_join(parameters, node, acc)
        })
    }

    /// Inserts the `base` inner digest corresponding to the leaf at `leaf_index` into the tree.
    #[inline]
    pub fn insert(&mut self, parameters: &Parameters<C>, leaf_index: Node, base: InnerDigest<C>) {
        let root = self.compute_root(parameters, leaf_index, base);
        self.set_root(root);
    }

    /// Computes the inner path starting from `node`.
    #[inline]
    pub fn path_iter(&self, node: InnerNode) -> InnerTreePathIter<C, M, S> {
        InnerTreePathIter::new(self, node.iter())
    }

    /// Computes the inner path of the leaf given by `leaf_index`.
    #[inline]
    pub fn path_iter_for_leaf(&self, leaf_index: Node) -> InnerTreePathIter<C, M, S> {
        InnerTreePathIter::new(self, InnerNodeIter::from_leaf::<C>(leaf_index))
    }

    /// Returns the path at `leaf_index`.
    #[inline]
    pub fn path(&self, leaf_index: Node) -> InnerPath<C>
    where
        InnerDigest<C>: Clone,
    {
        InnerPath::new(
            leaf_index,
            self.path_iter_for_leaf(leaf_index).cloned().collect(),
        )
    }
}

impl<C, M> InnerTree<C, M, Sentinel<C>>
where
    C: Configuration + ?Sized,
    M: InnerMap<C>,
    InnerDigest<C>: Clone + PartialEq,
{
    /// Returns the path at `leaf_index`, assuming that `leaf_index` is the right-most index,
    /// so that the return value is a valid [`CurrentInnerPath`].
    #[inline]
    pub fn current_path_unchecked(&self, leaf_index: Node) -> CurrentInnerPath<C> {
        CurrentInnerPath::new(
            leaf_index,
            self.path_iter_for_leaf(leaf_index)
                .filter(move |&d| d != &self.sentinel_source.0)
                .cloned()
                .collect(),
        )
    }
}

impl<C, M, S> Index<InnerNode> for InnerTree<C, M, S>
where
    C: Configuration + ?Sized,
    M: InnerMap<C>,
    S: SentinelSource<C>,
{
    type Output = InnerDigest<C>;

    #[inline]
    fn index(&self, index: InnerNode) -> &Self::Output {
        self.get_or_sentinel(index)
    }
}

impl<C, M, S> Index<usize> for InnerTree<C, M, S>
where
    C: Configuration + ?Sized,
    M: InnerMap<C>,
    S: SentinelSource<C>,
{
    type Output = InnerDigest<C>;

    #[inline]
    fn index(&self, index: usize) -> &Self::Output {
        self.map_get_or_sentinel(index)
    }
}

impl<C, M, S> SentinelSource<C> for InnerTree<C, M, S>
where
    C: Configuration + ?Sized,
    M: InnerMap<C>,
    S: SentinelSource<C>,
{
    #[inline]
    fn get(&self, index: usize) -> &InnerDigest<C> {
        self.map_get_or_sentinel(index)
    }
}

/// Partial Inner Tree
///
/// Tree data-structure for storing a subset of the inner digests of a merkle tree.
///
/// # Implementation Note
///
/// This type intentionally lacks an implementation of [`Tree`], especially since it does not store
/// leaf digests.
///
/// [`Tree`]: crate::merkle_tree::Tree
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(
        bound(
            deserialize = "M: Deserialize<'de>, S: Deserialize<'de>",
            serialize = "M: Serialize, S: Serialize"
        ),
        crate = "openzl_util::serde",
        deny_unknown_fields
    )
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "M: Clone, S: Clone"),
    Debug(bound = "M: Debug, S: Debug"),
    Default(bound = "M: Default, S: Default"),
    Eq(bound = "M: Eq, S: Eq"),
    Hash(bound = "M: Hash, S: Hash"),
    PartialEq(bound = "M: PartialEq, S: PartialEq")
)]
pub struct PartialInnerTree<C, M = BTreeMap<C>, S = Sentinel<C>>
where
    C: Configuration + ?Sized,
    M: InnerMap<C>,
    S: SentinelSource<C>,
{
    /// Inner Tree
    inner_tree: InnerTree<C, M, S>,

    /// Starting Leaf Index
    starting_leaf_index: Node,
}

impl<C, M, S> PartialInnerTree<C, M, S>
where
    C: Configuration + ?Sized,
    M: InnerMap<C>,
    S: SentinelSource<C>,
{
    /// Builds a new [`PartialInnerTree`] from `inner_tree` and `starting_leaf_index`.
    #[inline]
    fn new(inner_tree: InnerTree<C, M, S>, starting_leaf_index: Node) -> Self {
        Self {
            inner_tree,
            starting_leaf_index,
        }
    }

    /// Builds a new [`PartialInnerTree`] from `base` and `path`.
    #[inline]
    pub fn from_current(
        parameters: &Parameters<C>,
        base: InnerDigest<C>,
        path: CurrentInnerPath<C>,
    ) -> Self
    where
        M: Default,
        S: Default,
    {
        let mut inner_tree = InnerTree::<C, M, S>::default();
        let leaf_index = path.leaf_index.as_left();
        let node_iter = path.into_nodes();
        if node_iter.len() == 0 {
            return inner_tree.into();
        }
        let root = node_iter.fold(base, |acc, (node, digest)| {
            let index = node.map_index();
            match digest {
                Some(digest) => {
                    inner_tree
                        .map
                        .set_and_join(parameters, index - 1, digest, index, acc)
                }
                _ => parameters.join(
                    inner_tree.map.set_get(index, acc),
                    inner_tree.sentinel_source.get(index + 1),
                ),
            }
        });
        inner_tree.set_root(root);
        Self::new(inner_tree, leaf_index)
    }

    /// Returns the starting leaf index where the tree was constructed from.
    #[inline]
    pub fn starting_leaf_index(&self) -> Node {
        self.starting_leaf_index
    }

    /// Tries to get the inner digest at `node`, returning `None` if the inner digest is missing.
    #[inline]
    pub fn get(&self, node: InnerNode) -> Option<&InnerDigest<C>> {
        self.inner_tree.get(node)
    }

    /// Tries to return the inner digest at `index`, returning `None` if the inner digest is
    /// missing.
    #[inline]
    pub fn map_get(&self, index: usize) -> Option<&InnerDigest<C>> {
        self.inner_tree.map_get(index)
    }

    /// Returns a reference to the root inner digest.
    #[inline]
    pub fn root(&self) -> &InnerDigest<C> {
        self.inner_tree.root()
    }

    /// Inserts the `base` inner digest corresponding to the leaf at `leaf_index` into the tree.
    #[inline]
    pub fn insert(&mut self, parameters: &Parameters<C>, leaf_index: Node, base: InnerDigest<C>) {
        self.inner_tree.insert(parameters, leaf_index, base);
    }

    /// Computes the inner path of the leaf given by `leaf_index` without checking if
    /// `leaf_index` is later than the starting index of this tree.
    #[inline]
    pub fn path_iter_for_leaf_unchecked(&self, leaf_index: Node) -> InnerTreePathIter<C, M, S> {
        self.inner_tree.path_iter_for_leaf(leaf_index)
    }

    /// Returns the path at `leaf_index` without checking if `leaf_index` is later than the
    /// starting index of this tree.
    #[inline]
    pub fn path_unchecked(&self, leaf_index: Node) -> InnerPath<C>
    where
        InnerDigest<C>: Clone,
    {
        self.inner_tree.path(leaf_index)
    }
}

impl<C, M> PartialInnerTree<C, M, Sentinel<C>>
where
    C: Configuration + ?Sized,
    M: InnerMap<C>,
    InnerDigest<C>: Clone + PartialEq,
{
    /// Returns the path at `leaf_index`, assuming that `leaf_index` is the right-most index,
    /// so that the return value is a valid [`CurrentInnerPath`].
    #[inline]
    pub fn current_path_unchecked(&self, leaf_index: Node) -> CurrentInnerPath<C> {
        self.inner_tree.current_path_unchecked(leaf_index)
    }
}

impl<C, M, S> From<InnerTree<C, M, S>> for PartialInnerTree<C, M, S>
where
    C: Configuration + ?Sized,
    M: InnerMap<C>,
    S: SentinelSource<C>,
{
    #[inline]
    fn from(inner_tree: InnerTree<C, M, S>) -> Self {
        Self::new(inner_tree, Default::default())
    }
}

/// [`InnerTree`] Path Iterator
#[derive(derivative::Derivative)]
#[derivative(
    Copy(bound = ""),
    Clone(bound = ""),
    Debug(bound = "M: Debug, S: Debug"),
    Eq(bound = "M: Eq, S: Eq"),
    Hash(bound = "M: Hash, S: Hash"),
    PartialEq(bound = "M: PartialEq, S: PartialEq")
)]
pub struct InnerTreePathIter<'t, C, M = BTreeMap<C>, S = Sentinel<C>>
where
    C: Configuration + ?Sized,
    M: InnerMap<C>,
    S: SentinelSource<C>,
{
    /// Inner Tree
    inner_tree: &'t InnerTree<C, M, S>,

    /// Inner Node Iterator
    iter: InnerNodeIter,
}

impl<'t, C, M, S> InnerTreePathIter<'t, C, M, S>
where
    C: Configuration + ?Sized,
    M: InnerMap<C>,
    S: SentinelSource<C>,
{
    /// Builds a new [`InnerTreePathIter`] for `inner_tree` using `iter`.
    #[inline]
    fn new(inner_tree: &'t InnerTree<C, M, S>, iter: InnerNodeIter) -> Self {
        Self { inner_tree, iter }
    }
}

// TODO: Add all methods which can be optimized.
impl<'t, C, M, S> Iterator for InnerTreePathIter<'t, C, M, S>
where
    C: Configuration + ?Sized,
    M: InnerMap<C>,
    S: SentinelSource<C>,
{
    type Item = &'t InnerDigest<C>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next().map(move |n| &self.inner_tree[n.sibling()])
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.iter.size_hint()
    }
}

impl<'t, C, M, S> ExactSizeIterator for InnerTreePathIter<'t, C, M, S>
where
    C: Configuration + ?Sized,
    M: InnerMap<C>,
    S: SentinelSource<C>,
{
}

impl<'t, C, M, S> FusedIterator for InnerTreePathIter<'t, C, M, S>
where
    C: Configuration + ?Sized,
    M: InnerMap<C>,
    S: SentinelSource<C>,
{
}
