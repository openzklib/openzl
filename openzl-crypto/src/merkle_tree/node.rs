//! Merkle Tree Node Abstractions

use crate::merkle_tree::{HashConfiguration, InnerDigest, InnerHash, LeafDigest, Parameters};
use core::{
    iter::FusedIterator,
    ops::{Add, Sub},
};

#[cfg(feature = "serde")]
use openzl_util::serde::{Deserialize, Serialize};

/// Parity of a Subtree
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "openzl_util::serde", deny_unknown_fields)
)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Parity {
    /// Left Side of the Subtree
    Left,

    /// Right Side of the Subtree
    Right,
}

impl Parity {
    /// Computes the [`Parity`] of the given `index`.
    #[inline]
    pub const fn from_index(index: usize) -> Self {
        if index % 2 == 0 {
            Self::Left
        } else {
            Self::Right
        }
    }

    /// Returns `true` if `self` represents the left side of a subtree.
    #[inline]
    pub const fn is_left(&self) -> bool {
        matches!(self, Self::Left)
    }

    /// Returns `true` if `self` represents the right side of a subtree.
    #[inline]
    pub const fn is_right(&self) -> bool {
        matches!(self, Self::Right)
    }

    /// Returns the output of `f` if `self` is [`Left`](Self::Left), or returns a default value
    /// otherwise.
    #[inline]
    pub fn left_or_default<T, F>(&self, f: F) -> T
    where
        T: Default,
        F: FnOnce() -> T,
    {
        match self {
            Self::Left => f(),
            Self::Right => Default::default(),
        }
    }

    /// Returns the output of `f` if `self` is [`Right`](Self::Right), or returns a default value
    /// otherwise.
    #[inline]
    pub fn right_or_default<T, F>(&self, f: F) -> T
    where
        T: Default,
        F: FnOnce() -> T,
    {
        match self {
            Self::Left => Default::default(),
            Self::Right => f(),
        }
    }

    /// Maps `self` to the output of `lhs` and `rhs` depending on its parity.
    #[inline]
    pub fn map<T, L, R>(self, lhs: L, rhs: R) -> T
    where
        L: FnOnce() -> T,
        R: FnOnce() -> T,
    {
        match self {
            Self::Left => lhs(),
            Self::Right => rhs(),
        }
    }

    /// Returns the arguments in the order according to the parity of `self`.
    #[inline]
    pub const fn order<T>(&self, lhs: T, rhs: T) -> (T, T) {
        match self {
            Self::Left => (lhs, rhs),
            Self::Right => (rhs, lhs),
        }
    }

    /// Combines two inner digests into a new inner digest using `parameters`, swapping the order
    /// of `lhs` and `rhs` depending on the parity of `self` in its subtree.
    #[inline]
    pub fn join<C>(
        &self,
        parameters: &Parameters<C>,
        lhs: &InnerDigest<C>,
        rhs: &InnerDigest<C>,
    ) -> InnerDigest<C>
    where
        C: HashConfiguration + ?Sized,
    {
        let (lhs, rhs) = self.order(lhs, rhs);
        C::InnerHash::join(&parameters.inner, lhs, rhs, &mut ())
    }

    /// Combines two leaf digests into a new inner digest using `parameters`, swapping the order
    /// of `lhs` and `rhs` depending on the parity of `self`.
    #[inline]
    pub fn join_leaves<C>(
        &self,
        parameters: &Parameters<C>,
        lhs: &LeafDigest<C>,
        rhs: &LeafDigest<C>,
    ) -> InnerDigest<C>
    where
        C: HashConfiguration + ?Sized,
    {
        let (lhs, rhs) = self.order(lhs, rhs);
        C::InnerHash::join_leaves(&parameters.inner, lhs, rhs, &mut ())
    }
}

impl Default for Parity {
    #[inline]
    fn default() -> Self {
        Self::Left
    }
}

/// Node Index
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "openzl_util::serde", deny_unknown_fields)
)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct Node<Idx = usize>(
    /// Level-wise Index to a node in a Binary Tree
    pub Idx,
);

impl Node {
    /// Returns the [`Parity`] of this node.
    #[inline]
    pub const fn parity(&self) -> Parity {
        Parity::from_index(self.0)
    }

    /// Returns `true` if this node has left parity.
    #[inline]
    pub const fn is_left(&self) -> bool {
        self.parity().is_left()
    }

    /// Returns `true` if this node has right parity.
    #[inline]
    pub const fn is_right(&self) -> bool {
        self.parity().is_right()
    }

    /// Returns the [`Node`] which is the sibling to `self`.
    #[inline]
    #[must_use]
    pub const fn sibling(&self) -> Self {
        match self.parity() {
            Parity::Left => Self(self.0 + 1),
            Parity::Right => Self(self.0 - 1),
        }
    }

    /// Maps `self` and its sibling over `f`.
    #[inline]
    pub fn with_sibling<T, F>(self, mut f: F) -> (T, T)
    where
        F: FnMut(Self) -> T,
    {
        match self.parity() {
            Parity::Left => (f(self), f(self + 1)),
            Parity::Right => (f(self - 1), f(self)),
        }
    }

    /// Returns `true` if `lhs` and `rhs` are siblings.
    #[inline]
    pub const fn are_siblings(lhs: &Self, rhs: &Self) -> bool {
        lhs.sibling().0 == rhs.0
    }

    /// Returns `self` if `self` has left parity or returns the sibling of `self` if `self` has
    /// right parity.
    #[inline]
    #[must_use]
    pub const fn as_left(&self) -> Self {
        match self.parity() {
            Parity::Left => *self,
            Parity::Right => Self(self.0 - 1),
        }
    }

    /// Returns `self` if `self` has right parity or returns the sibling of `self` if `self` has
    /// left parity.
    #[inline]
    #[must_use]
    pub const fn as_right(&self) -> Self {
        match self.parity() {
            Parity::Left => Self(self.0 + 1),
            Parity::Right => *self,
        }
    }

    /// Returns the left child [`Node`] of this node.
    #[inline]
    #[must_use]
    pub const fn left_child(&self) -> Self {
        Self(self.0 << 1)
    }

    /// Returns the right child [`Node`] of this node.
    #[inline]
    #[must_use]
    pub const fn right_child(&self) -> Self {
        Self(self.left_child().0 + 1)
    }

    /// Returns the [`Node`] children of this node.
    #[inline]
    pub const fn children(&self) -> (Self, Self) {
        let left_child = self.left_child();
        (left_child, Self(left_child.0 + 1))
    }

    /// Returns the parent [`Node`] of this node.
    #[inline]
    #[must_use]
    pub const fn parent(&self) -> Self {
        Self(self.0 >> 1)
    }

    /// Converts `self` into its parent, returning the parent [`Node`].
    #[inline]
    #[must_use]
    pub fn into_parent(&mut self) -> Self {
        *self = self.parent();
        *self
    }

    /// Returns an iterator over the parents of `self`.
    #[inline]
    pub const fn parents(&self) -> NodeParents {
        NodeParents { index: *self }
    }

    /// Combines two inner digests into a new inner digest using `parameters`, swapping the order
    /// of `lhs` and `rhs` depending on the location of `self`.
    #[inline]
    pub fn join<C>(
        &self,
        parameters: &Parameters<C>,
        lhs: &InnerDigest<C>,
        rhs: &InnerDigest<C>,
    ) -> InnerDigest<C>
    where
        C: HashConfiguration + ?Sized,
    {
        self.parity().join(parameters, lhs, rhs)
    }

    /// Combines two leaf digests into a new inner digest using `parameters`, swapping the order
    /// of `lhs` and `rhs` depending on the location of `self`.
    #[inline]
    pub fn join_leaves<C>(
        &self,
        parameters: &Parameters<C>,
        lhs: &LeafDigest<C>,
        rhs: &LeafDigest<C>,
    ) -> InnerDigest<C>
    where
        C: HashConfiguration + ?Sized,
    {
        self.parity().join_leaves(parameters, lhs, rhs)
    }
}

impl<Idx> Add<Idx> for Node<Idx>
where
    Idx: Add<Output = Idx>,
{
    type Output = Self;

    #[inline]
    fn add(self, rhs: Idx) -> Self::Output {
        Self(self.0 + rhs)
    }
}

impl<'i, Idx> Add<&'i Idx> for &'i Node<Idx>
where
    &'i Idx: Add<Output = Idx>,
{
    type Output = Node<Idx>;

    #[inline]
    fn add(self, rhs: &'i Idx) -> Self::Output {
        Node(&self.0 + rhs)
    }
}

impl<Idx> Sub<Idx> for Node<Idx>
where
    Idx: Sub<Output = Idx>,
{
    type Output = Self;

    #[inline]
    fn sub(self, rhs: Idx) -> Self::Output {
        Self(self.0 - rhs)
    }
}

impl<'i, Idx> Sub<&'i Idx> for &'i Node<Idx>
where
    &'i Idx: Sub<Output = Idx>,
{
    type Output = Node<Idx>;

    #[inline]
    fn sub(self, rhs: &'i Idx) -> Self::Output {
        Node(&self.0 - rhs)
    }
}

impl<Idx> From<Idx> for Node<Idx> {
    #[inline]
    fn from(index: Idx) -> Self {
        Self(index)
    }
}

impl<Idx> PartialEq<Idx> for Node<Idx>
where
    Idx: PartialEq,
{
    #[inline]
    fn eq(&self, rhs: &Idx) -> bool {
        self.0 == *rhs
    }
}

/// Node Parent Iterator
///
/// An iterator over the parents of a [`Node`].
///
/// This `struct` is created by the [`parents`](Node::parents) method on [`Node`].
/// See its documentation for more.
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "openzl_util::serde", deny_unknown_fields)
)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct NodeParents {
    /// Current Index
    index: Node,
}

impl NodeParents {
    /// Stops the iterator and returns the current node index.
    #[inline]
    pub const fn stop(self) -> Node {
        self.index
    }

    /// Returns the sibling of the current parent node.
    #[inline]
    pub const fn sibling(&self) -> Node {
        self.index.sibling()
    }
}

impl AsRef<Node> for NodeParents {
    #[inline]
    fn as_ref(&self) -> &Node {
        &self.index
    }
}

// TODO: Add all methods which can be optimized.
impl Iterator for NodeParents {
    type Item = Node;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        Some(self.index.into_parent())
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        (usize::MAX, None)
    }

    #[inline]
    fn last(self) -> Option<Self::Item> {
        // NOTE: Although this iterator can never be completed, it has a well-defined
        //       final element "at infinity".
        Some(Default::default())
    }
}

impl FusedIterator for NodeParents {}
