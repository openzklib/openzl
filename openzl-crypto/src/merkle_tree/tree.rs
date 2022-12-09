//! Merkle Tree Abstractions

// FIXME: Enforce that `Configuration` and `Configuration<COM>` use the same HEIGHT when used
//        together.
// TODO:  Should we get rid of the `H > 2` requirement, and find a way to give correct
//        implementations for the trivial tree sizes?
// TODO:  Add "copy-on-write" adapters for `Root` and `Path`, and see if we can incorporate them
//        into `Tree`.
// TODO:  Use uniform construction for `Path` and `PathVar`.

use crate::{
    accumulator::{
        self, Accumulator, ConstantCapacityAccumulator, ExactSizeAccumulator, MembershipProof,
        OptimizedAccumulator,
    },
    merkle_tree::{
        fork::{ForkedTree, Trunk},
        inner_tree::InnerMap,
        path::{constraint::PathVar, CurrentPath, Path},
    },
    NonNative,
};
use core::{fmt::Debug, hash::Hash, marker::PhantomData};
use eclair::{
    self,
    alloc::{Allocate, Constant},
    bool::{AssertEq, Bool, ConditionalSwap},
    Has,
};
use openzl_util::{
    codec::{Decode, DecodeError, Encode, Read, Write},
    derivative,
    persistence::Rollback,
    pointer::PointerFamily,
};

#[cfg(feature = "serde")]
use openzl_util::serde::{Deserialize, Serialize};

/// Merkle Tree Leaf Hash
pub trait LeafHash<COM = ()> {
    /// Leaf Type
    type Leaf;

    /// Leaf Hash Parameters Type
    type Parameters;

    /// Leaf Hash Output Type
    type Output;

    /// Computes the digest of the `leaf` using `parameters`.
    fn digest(parameters: &Self::Parameters, leaf: &Self::Leaf, compiler: &mut COM)
        -> Self::Output;
}

/// Identity Leaf Hash
///
/// # Safety
///
/// This implementation of [`LeafHash`] should only be used when users cannot control the value of a
/// leaf itself, otherwise, using this implementation may not be safe.
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "openzl_util::serde", deny_unknown_fields)
)]
#[derive(derivative::Derivative)]
#[derivative(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct IdentityLeafHash<L, COM = ()>(PhantomData<(L, COM)>)
where
    L: Clone;

impl<L, COM> LeafHash<COM> for IdentityLeafHash<L, COM>
where
    L: Clone,
{
    type Leaf = L;
    type Parameters = ();
    type Output = L;

    #[inline]
    fn digest(
        parameters: &Self::Parameters,
        leaf: &Self::Leaf,
        compiler: &mut COM,
    ) -> Self::Output {
        let _ = (parameters, compiler);
        leaf.clone()
    }
}

/// Merkle Tree Inner Hash
pub trait InnerHash<COM = ()> {
    /// Leaf Digest Type
    type LeafDigest;

    /// Inner Hash Parameters Type
    type Parameters;

    /// Inner Hash Output Type
    type Output;

    /// Combines two inner digests into a new inner digest using `parameters`.
    fn join(
        parameters: &Self::Parameters,
        lhs: &Self::Output,
        rhs: &Self::Output,
        compiler: &mut COM,
    ) -> Self::Output;

    /// Combines two [`LeafDigest`](Self::LeafDigest) values into an inner digest.
    fn join_leaves(
        parameters: &Self::Parameters,
        lhs: &Self::LeafDigest,
        rhs: &Self::LeafDigest,
        compiler: &mut COM,
    ) -> Self::Output;
}

/// Merkle Tree Hash Configuration
pub trait HashConfiguration<COM = ()> {
    /// Leaf Hash Type
    type LeafHash: LeafHash<COM>;

    /// Inner Hash Type
    type InnerHash: InnerHash<COM, LeafDigest = <Self::LeafHash as LeafHash<COM>>::Output>;
}

/// Merkle Tree Configuration
pub trait Configuration<COM = ()>: HashConfiguration<COM> {
    /// Fixed Height of the Merkle Tree
    ///
    /// # Contract
    ///
    /// Trees must always have height at least `2`.
    const HEIGHT: usize;
}

/// Configuration Structure
///
/// Use this `struct` to extend any [`C: HashConfiguration`](HashConfiguration) and a given
/// `const HEIGHT: usize` to a full implementation of [`Configuration`].
///
/// # Note
///
/// Since this `struct` is meant to be used as a type parameter, any values of this type have no
/// meaning, just like values of type [`HashConfiguration`] or [`Configuration`].
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "openzl_util::serde", deny_unknown_fields)
)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Config<C, COM, const HEIGHT: usize>(PhantomData<(COM, C)>)
where
    C: HashConfiguration<COM> + ?Sized;

impl<C, COM, const HEIGHT: usize> HashConfiguration<COM> for Config<C, COM, HEIGHT>
where
    C: HashConfiguration<COM> + ?Sized,
{
    type LeafHash = C::LeafHash;
    type InnerHash = C::InnerHash;
}

impl<C, COM, const HEIGHT: usize> Configuration<COM> for Config<C, COM, HEIGHT>
where
    C: HashConfiguration<COM> + ?Sized,
{
    const HEIGHT: usize = HEIGHT;
}

/// Leaf Type
pub type Leaf<C, COM = ()> = <<C as HashConfiguration<COM>>::LeafHash as LeafHash<COM>>::Leaf;

/// Leaf Hash Parameters Type
pub type LeafHashParameters<C, COM = ()> =
    <<C as HashConfiguration<COM>>::LeafHash as LeafHash<COM>>::Parameters;

/// Leaf Hash Digest Type
pub type LeafDigest<C, COM = ()> =
    <<C as HashConfiguration<COM>>::LeafHash as LeafHash<COM>>::Output;

/// Inner Hash Parameters Type
pub type InnerHashParameters<C, COM = ()> =
    <<C as HashConfiguration<COM>>::InnerHash as InnerHash<COM>>::Parameters;

/// Inner Hash Digest Type
pub type InnerDigest<C, COM = ()> =
    <<C as HashConfiguration<COM>>::InnerHash as InnerHash<COM>>::Output;

/// Returns the capacity of the merkle tree with the given [`C::HEIGHT`](Configuration::HEIGHT)
/// parameter.
///
/// The capacity of a merkle tree with height `H` is `2^(H-1)`.
#[inline]
#[must_use]
pub fn capacity<C, COM>() -> usize
where
    C: Configuration<COM> + ?Sized,
{
    1_usize << (C::HEIGHT - 1)
}

/// Returns the path length of the merkle tree with the given [`C::HEIGHT`](Configuration::HEIGHT)
/// parameter.
///
/// The path length of a merkle tree with height `H` is `H - 2`.
#[inline]
#[must_use]
pub fn path_length<C, COM>() -> usize
where
    C: Configuration<COM> + ?Sized,
{
    C::HEIGHT - 2
}

/// Merkle Tree Structure
pub trait Tree<C>: Sized
where
    C: Configuration + ?Sized,
{
    /// Builds a new empty merkle tree.
    fn new(parameters: &Parameters<C>) -> Self;

    /// Builds a new merkle tree with the given `leaves` returning `None` if the iterator
    /// would overflow the capacity of the tree.
    #[inline]
    fn from_iter<'l, L>(parameters: &Parameters<C>, leaves: L) -> Option<Self>
    where
        Leaf<C>: 'l,
        L: IntoIterator<Item = &'l Leaf<C>>,
    {
        let mut tree = Self::new(parameters);
        tree.extend(parameters, leaves).then_some(tree)
    }

    /// Builds a new merkle tree with the given `leaves` returning `None` if the slice
    /// would overflow the capacity of the tree.
    #[inline]
    fn from_slice(parameters: &Parameters<C>, slice: &[Leaf<C>]) -> Option<Self>
    where
        Leaf<C>: Sized,
    {
        Self::from_iter(parameters, slice)
    }

    /// Returns the number of items in `self`.
    fn len(&self) -> usize;

    /// Returns `true` if the length of `self` is zero.
    #[inline]
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the current (i.e. right-most) leaf if the tree is not empty.
    fn current_leaf(&self) -> Option<&LeafDigest<C>>;

    /// Returns the [`Root`] of the merkle tree.
    fn root(&self) -> &Root<C>;

    /// Returns the [`CurrentPath`] of the current (i.e. right-most) leaf.
    fn current_path(&self, parameters: &Parameters<C>) -> CurrentPath<C>;

    /// Checks if a leaf can be inserted into the tree and if it can, it runs `leaf_digest` to
    /// extract a leaf digest to insert, returning `None` if there was no leaf digest.
    fn maybe_push_digest<F>(&mut self, parameters: &Parameters<C>, leaf_digest: F) -> Option<bool>
    where
        F: FnOnce() -> Option<LeafDigest<C>>;

    /// Inserts the `leaf_digest` at the next available leaf node of the tree, returning `false`
    /// if the leaf could not be inserted because the tree has exhausted its capacity.
    #[inline]
    fn push_digest<F>(&mut self, parameters: &Parameters<C>, leaf_digest: F) -> bool
    where
        F: FnOnce() -> LeafDigest<C>,
    {
        self.maybe_push_digest(parameters, move || Some(leaf_digest()))
            .unwrap()
    }

    /// Inserts the digest of `leaf` at the next available leaf node of the tree, returning
    /// `false` if the leaf could not be inserted because the tree has exhausted its capacity.
    #[inline]
    fn push(&mut self, parameters: &Parameters<C>, leaf: &Leaf<C>) -> bool {
        self.push_digest(parameters, || parameters.digest(leaf))
    }

    /// Appends an iterator of leaf digests at the end of the tree, returning the iterator back
    /// if it could not be inserted because the tree has exhausted its capacity.
    ///
    /// # Implementation Note
    ///
    /// This operation is meant to be atomic, so if appending the iterator should fail, the
    /// implementation must ensure that the tree returns to the same state before the insertion
    /// occured.
    #[inline]
    fn extend_digests<L>(
        &mut self,
        parameters: &Parameters<C>,
        leaf_digests: L,
    ) -> Result<(), L::IntoIter>
    where
        L: IntoIterator<Item = LeafDigest<C>>,
    {
        let mut leaf_digests = leaf_digests.into_iter();
        if matches!(leaf_digests.size_hint().1, Some(max) if max <= capacity::<C, _>() - self.len())
        {
            loop {
                match self.maybe_push_digest(parameters, || leaf_digests.next()) {
                    Some(result) => assert!(
                        result,
                        "Unable to push digest even though the tree should have enough capacity to do so."
                    ),
                    _ => return Ok(()),
                }
            }
        }
        Err(leaf_digests)
    }

    /// Appends an iterator of leaves at the end of the tree, returning `false` if the `leaves`
    /// could not be inserted because the tree has exhausted its capacity.
    ///
    /// # Implementation Note
    ///
    /// This operation is meant to be atomic, so if appending the iterator should fail, the
    /// implementation must ensure that the tree returns to the same state before the insertion
    /// occured.
    #[inline]
    fn extend<'l, L>(&mut self, parameters: &Parameters<C>, leaves: L) -> bool
    where
        Leaf<C>: 'l,
        L: IntoIterator<Item = &'l Leaf<C>>,
    {
        self.extend_digests(parameters, leaves.into_iter().map(|l| parameters.digest(l)))
            .is_ok()
    }

    /// Appends a slice of leaves at the end of the tree, returning `false` if the
    /// `leaves` could not be inserted because the tree has exhausted its capacity.
    ///
    /// # Implementation Note
    ///
    /// This operation is meant to be atomic, so if appending the slice should fail, the
    /// implementation must ensure that the tree returns to the same state before the insertion
    /// occured.
    #[inline]
    fn extend_slice(&mut self, parameters: &Parameters<C>, leaves: &[Leaf<C>]) -> bool
    where
        Leaf<C>: Sized,
    {
        self.extend(parameters, leaves)
    }
}

/// Path Error
///
/// This `enum` is the error state of the [`path`](WithProofs::path) method of the [`WithProofs`]
/// trait. See its documentation for more.
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(crate = "openzl_util::serde", deny_unknown_fields)
)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PathError {
    /// Path for the given index was not stored in the tree
    MissingPath,

    /// Given index exceeded the length of the tree
    IndexTooLarge {
        /// Length of the tree
        length: usize,
    },
}

/// Merkle Tree Membership Proof Mixin
pub trait WithProofs<C>
where
    C: Configuration + ?Sized,
{
    /// Returns the leaf digest at the given `index`.
    ///
    /// # Implementation Note
    ///
    /// This method is allowed to return `None` even if `index` is less than the current length of
    /// the tree. See [`position`](Self::position) for more.
    fn leaf_digest(&self, index: usize) -> Option<&LeafDigest<C>>;

    /// Returns the index of the `leaf_digest` if it is contained in `self`.
    ///
    /// # Implementation Note
    ///
    /// This method is allowed to return `None` even if `leaf_digest` was inserted with a call to
    /// [`push_digest`](Tree::push_digest). This method need only return an index for leaves which
    /// are inserted with a call to [`push_provable`](Self::push_provable).
    fn position(&self, leaf_digest: &LeafDigest<C>) -> Option<usize>;

    /// Returns `true` if `leaf_digest` is provably stored in `self`.
    ///
    /// See the [`position`](Self::position) and [`push_provable`](Self::push_provable) methods
    /// for more.
    #[inline]
    fn contains(&self, leaf_digest: &LeafDigest<C>) -> bool {
        self.position(leaf_digest).is_some()
    }

    /// Checks if a leaf can be inserted into the tree and if it can, it runs `leaf_digest` to
    /// extract a leaf digest to insert, returning `None` if there was no leaf digest. If this
    /// method is successful, the digest inserted will have an accompanying proof that can be
    /// returned by a call to the [`path`](Self::path) method.
    fn maybe_push_provable_digest<F>(
        &mut self,
        parameters: &Parameters<C>,
        leaf_digest: F,
    ) -> Option<bool>
    where
        F: FnOnce() -> Option<LeafDigest<C>>;

    /// Appends `leaf_digest` to the end of the tree, retaining its path for later use with a call
    /// to the [`path`](Self::path) method.
    #[inline]
    fn push_provable_digest<F>(&mut self, parameters: &Parameters<C>, leaf_digest: F) -> bool
    where
        F: FnOnce() -> LeafDigest<C>,
    {
        self.maybe_push_provable_digest(parameters, move || Some(leaf_digest()))
            .unwrap()
    }

    /// Appends `leaf` to the end of the tree, retaining its path for later use with a call to the
    /// [`path`](Self::path) method.
    #[inline]
    fn push_provable(&mut self, parameters: &Parameters<C>, leaf: &Leaf<C>) -> bool {
        self.push_provable_digest(parameters, move || parameters.digest(leaf))
    }

    /// Returns the path for the leaf stored at the given `index` if it exists.
    fn path(&self, parameters: &Parameters<C>, index: usize) -> Result<Path<C>, PathError>;

    /// Removes a single path at the given `index`, returning `true` if it was removed.
    ///
    /// # Implementation Note
    ///
    /// This method may return `false` for arbitrary inputs and is only an optimization path for
    /// removing unused memory.
    #[inline]
    fn remove_path(&mut self, index: usize) -> bool {
        let _ = index;
        false
    }
}

/// Merkle Tree Parameters
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(
        bound(
            deserialize = r"
                LeafHashParameters<C, COM>: Deserialize<'de>,
                InnerHashParameters<C, COM>: Deserialize<'de>
            ",
            serialize = r"
                LeafHashParameters<C, COM>: Serialize,
                InnerHashParameters<C, COM>: Serialize,
            "
        ),
        crate = "openzl_util::serde",
        deny_unknown_fields
    )
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "LeafHashParameters<C, COM>: Clone, InnerHashParameters<C, COM>: Clone"),
    Copy(bound = "LeafHashParameters<C, COM>: Copy, InnerHashParameters<C, COM>: Copy"),
    Debug(bound = "LeafHashParameters<C, COM>: Debug, InnerHashParameters<C, COM>: Debug"),
    Default(bound = "LeafHashParameters<C, COM>: Default, InnerHashParameters<C, COM>: Default"),
    Eq(bound = "LeafHashParameters<C, COM>: Eq, InnerHashParameters<C, COM>: Eq"),
    Hash(bound = "LeafHashParameters<C, COM>: Hash, InnerHashParameters<C, COM>: Hash"),
    PartialEq(
        bound = "LeafHashParameters<C, COM>: PartialEq, InnerHashParameters<C, COM>: PartialEq"
    )
)]
pub struct Parameters<C, COM = ()>
where
    C: HashConfiguration<COM> + ?Sized,
{
    /// Leaf Hash Parameters
    pub leaf: LeafHashParameters<C, COM>,

    /// Inner Hash Parameters
    pub inner: InnerHashParameters<C, COM>,
}

impl<C, COM> Parameters<C, COM>
where
    C: HashConfiguration<COM> + ?Sized,
{
    /// Builds a new [`Parameters`] from `leaf` and `inner` parameters.
    #[inline]
    pub fn new(leaf: LeafHashParameters<C, COM>, inner: InnerHashParameters<C, COM>) -> Self {
        Self { leaf, inner }
    }

    /// Computes the leaf digest of `leaf` using `self`.
    #[inline]
    pub fn digest_with(&self, leaf: &Leaf<C, COM>, compiler: &mut COM) -> LeafDigest<C, COM> {
        C::LeafHash::digest(&self.leaf, leaf, compiler)
    }

    /// Combines two inner digests into a new inner digest using `self`.
    #[inline]
    pub fn join_with(
        &self,
        lhs: &InnerDigest<C, COM>,
        rhs: &InnerDigest<C, COM>,
        compiler: &mut COM,
    ) -> InnerDigest<C, COM> {
        C::InnerHash::join(&self.inner, lhs, rhs, compiler)
    }

    /// Combines two leaf digests into a new inner digest using `self`.
    #[inline]
    pub fn join_leaves_with(
        &self,
        lhs: &LeafDigest<C, COM>,
        rhs: &LeafDigest<C, COM>,
        compiler: &mut COM,
    ) -> InnerDigest<C, COM> {
        C::InnerHash::join_leaves(&self.inner, lhs, rhs, compiler)
    }

    /// Verify that `path` witnesses the fact that `leaf` is a member of a merkle tree with the
    /// given `root`.
    #[inline]
    pub fn verify_path_with(
        &self,
        path: &PathVar<C, COM>,
        root: &Root<C, COM>,
        leaf: &Leaf<C, COM>,
        compiler: &mut COM,
    ) -> Bool<COM>
    where
        C: Configuration<COM>,
        COM: Has<bool>,
        InnerDigest<C, COM>:
            ConditionalSwap<COM> + eclair::cmp::PartialEq<InnerDigest<C, COM>, COM>,
        LeafDigest<C, COM>: ConditionalSwap<COM>,
    {
        path.verify(self, root, leaf, compiler)
    }
}

impl<C> Parameters<C>
where
    C: HashConfiguration + ?Sized,
{
    /// Computes the leaf digest of `leaf` using `self`.
    #[inline]
    pub fn digest(&self, leaf: &Leaf<C>) -> LeafDigest<C> {
        C::LeafHash::digest(&self.leaf, leaf, &mut ())
    }

    /// Combines two inner digests into a new inner digest using `self`.
    #[inline]
    pub fn join(&self, lhs: &InnerDigest<C>, rhs: &InnerDigest<C>) -> InnerDigest<C> {
        C::InnerHash::join(&self.inner, lhs, rhs, &mut ())
    }

    /// Combines two leaf digests into a new inner digest using `self`.
    #[inline]
    pub fn join_leaves(&self, lhs: &LeafDigest<C>, rhs: &LeafDigest<C>) -> InnerDigest<C> {
        C::InnerHash::join_leaves(&self.inner, lhs, rhs, &mut ())
    }

    /// Verify that `path` witnesses the fact that `leaf` is a member of a merkle tree with the
    /// given `root`.
    #[inline]
    pub fn verify_path(&self, path: &Path<C>, root: &Root<C>, leaf: &Leaf<C>) -> bool
    where
        C: Configuration,
        InnerDigest<C>: PartialEq,
    {
        path.verify(self, root, leaf)
    }
}

impl<C, COM> Constant<COM> for Parameters<C, COM>
where
    C: HashConfiguration<COM> + Constant<COM> + ?Sized,
    C::Type: HashConfiguration,
    LeafHashParameters<C, COM>: Constant<COM, Type = LeafHashParameters<C::Type>>,
    InnerHashParameters<C, COM>: Constant<COM, Type = InnerHashParameters<C::Type>>,
{
    type Type = Parameters<C::Type>;

    #[inline]
    fn new_constant(this: &Self::Type, compiler: &mut COM) -> Self {
        Self::new(
            this.leaf.as_constant(compiler),
            this.inner.as_constant(compiler),
        )
    }
}

/// Parameter Decode Error
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ParameterDecodeError<L, I> {
    /// Leaf Decoding Error
    Leaf(L),

    /// Inner Decoding Error
    Inner(I),
}

impl<C, COM> Decode for Parameters<C, COM>
where
    C: HashConfiguration<COM> + ?Sized,
    LeafHashParameters<C, COM>: Decode,
    InnerHashParameters<C, COM>: Decode,
{
    #[allow(clippy::type_complexity)] // NOTE: This is an implementation type so it doesn't matter.
    type Error = ParameterDecodeError<
        <LeafHashParameters<C, COM> as Decode>::Error,
        <InnerHashParameters<C, COM> as Decode>::Error,
    >;

    #[inline]
    fn decode<R>(mut reader: R) -> Result<Self, DecodeError<R::Error, Self::Error>>
    where
        R: Read,
    {
        Ok(Self::new(
            LeafHashParameters::<C, COM>::decode(&mut reader)
                .map_err(|err| err.map_decode(ParameterDecodeError::Leaf))?,
            InnerHashParameters::<C, COM>::decode(&mut reader)
                .map_err(|err| err.map_decode(ParameterDecodeError::Inner))?,
        ))
    }
}

impl<C, COM> Encode for Parameters<C, COM>
where
    C: HashConfiguration<COM> + ?Sized,
    LeafHashParameters<C, COM>: Encode,
    InnerHashParameters<C, COM>: Encode,
{
    #[inline]
    fn encode<W>(&self, mut writer: W) -> Result<(), W::Error>
    where
        W: Write,
    {
        self.leaf.encode(&mut writer)?;
        self.inner.encode(&mut writer)?;
        Ok(())
    }
}

/// Merkle Tree Root
pub type Root<C, COM = ()> = InnerDigest<C, COM>;

impl<C> accumulator::Types for Parameters<C>
where
    C: Configuration + ?Sized,
    InnerDigest<C>: PartialEq,
{
    type Item = Leaf<C>;
    type Witness = Path<C>;
    type Output = Root<C>;
}

impl<C> accumulator::Model for Parameters<C>
where
    C: Configuration + ?Sized,
    InnerDigest<C>: PartialEq,
{
    type Verification = bool;

    #[inline]
    fn verify(
        &self,
        item: &Self::Item,
        witness: &Self::Witness,
        output: &Self::Output,
        _: &mut (),
    ) -> Self::Verification {
        self.verify_path(witness, output, item)
    }
}

impl<C, COM> accumulator::Types for Parameters<C, COM>
where
    C: Configuration<COM> + ?Sized,
    COM: Has<bool> + NonNative,
    InnerDigest<C, COM>: ConditionalSwap<COM> + eclair::cmp::PartialEq<InnerDigest<C, COM>, COM>,
    LeafDigest<C, COM>: ConditionalSwap<COM>,
{
    type Item = Leaf<C, COM>;
    type Witness = PathVar<C, COM>;
    type Output = Root<C, COM>;
}

impl<C, COM> accumulator::Model<COM> for Parameters<C, COM>
where
    C: Configuration<COM> + ?Sized,
    COM: Has<bool> + NonNative,
    InnerDigest<C, COM>: ConditionalSwap<COM> + eclair::cmp::PartialEq<InnerDigest<C, COM>, COM>,
    LeafDigest<C, COM>: ConditionalSwap<COM>,
{
    type Verification = Bool<COM>;

    #[inline]
    fn verify(
        &self,
        item: &Self::Item,
        witness: &Self::Witness,
        output: &Self::Output,
        compiler: &mut COM,
    ) -> Self::Verification {
        self.verify_path_with(witness, output, item, compiler)
    }
}

impl<C, COM> accumulator::AssertValidVerification<COM> for Parameters<C, COM>
where
    C: Configuration<COM> + ?Sized,
    COM: AssertEq + NonNative,
    InnerDigest<C, COM>: ConditionalSwap<COM> + eclair::cmp::PartialEq<InnerDigest<C, COM>, COM>,
    LeafDigest<C, COM>: ConditionalSwap<COM>,
{
    #[inline]
    fn assert_valid(
        &self,
        item: &Self::Item,
        witness: &Self::Witness,
        output: &Self::Output,
        compiler: &mut COM,
    ) {
        let root = witness.root(self, &self.digest_with(item, compiler), compiler);
        compiler.assert_eq(output, &root)
    }
}

/// Merkle Tree
#[cfg_attr(
    feature = "serde",
    derive(Deserialize, Serialize),
    serde(
        bound(
            deserialize = "Parameters<C>: Deserialize<'de>, T: Deserialize<'de>",
            serialize = "Parameters<C>: Serialize, T: Serialize"
        ),
        crate = "openzl_util::serde",
        deny_unknown_fields
    )
)]
#[derive(derivative::Derivative)]
#[derivative(
    Clone(bound = "Parameters<C>: Clone, T: Clone"),
    Copy(bound = "Parameters<C>: Copy, T: Copy"),
    Debug(bound = "Parameters<C>: Debug, T: Debug"),
    Default(bound = "Parameters<C>: Default, T: Default"),
    Eq(bound = "Parameters<C>: Eq, T: Eq"),
    Hash(bound = "Parameters<C>: Hash, T: Hash"),
    PartialEq(bound = "Parameters<C>: PartialEq, T: PartialEq")
)]
pub struct MerkleTree<C, T>
where
    C: Configuration + ?Sized,
    T: Tree<C>,
{
    /// Merkle Tree Parameters
    pub parameters: Parameters<C>,

    /// Underlying Tree Structure
    pub tree: T,
}

impl<C, T> MerkleTree<C, T>
where
    C: Configuration + ?Sized,
    T: Tree<C>,
{
    /// Builds a new [`MerkleTree`].
    ///
    /// See [`Tree::new`] for more.
    #[inline]
    pub fn new(parameters: Parameters<C>) -> Self {
        Self::from_tree(T::new(&parameters), parameters)
    }

    /// Builds a new [`MerkleTree`] with the given `leaves`.
    ///
    /// See [`Tree::from_iter`] for more.
    #[inline]
    pub fn from_iter<'l, L>(parameters: Parameters<C>, leaves: L) -> Option<Self>
    where
        Leaf<C>: 'l,
        L: IntoIterator<Item = &'l Leaf<C>>,
    {
        Some(Self::from_tree(
            T::from_iter(&parameters, leaves)?,
            parameters,
        ))
    }

    /// Builds a new [`MerkleTree`] with the given `leaves`.
    ///
    /// See [`Tree::from_slice`] for more.
    #[inline]
    pub fn from_slice(parameters: Parameters<C>, leaves: &[Leaf<C>]) -> Option<Self>
    where
        Leaf<C>: Sized,
    {
        Some(Self::from_tree(
            T::from_slice(&parameters, leaves)?,
            parameters,
        ))
    }

    /// Builds a new [`MerkleTree`] from a pre-constructed `tree` and `parameters`.
    #[inline]
    pub fn from_tree(tree: T, parameters: Parameters<C>) -> Self {
        Self { parameters, tree }
    }

    /// Builds a new [`MerkleTree`] from a `trunk` and `parameters`.
    #[inline]
    pub fn from_trunk<P>(trunk: Trunk<C, T, P>, parameters: Parameters<C>) -> Self
    where
        P: PointerFamily<T>,
    {
        Self::from_tree(trunk.into_tree(), parameters)
    }

    /// Returns a shared reference to the parameters used by this merkle tree.
    #[inline]
    pub fn parameters(&self) -> &Parameters<C> {
        &self.parameters
    }

    /// Returns the number of leaves that can fit in this merkle tree.
    ///
    /// See [`capacity`] for more.
    #[inline]
    pub fn capacity(&self) -> usize {
        capacity::<C, _>()
    }

    /// Returns the number of items this merkle tree.
    ///
    /// See [`Tree::len`] for more.
    #[inline]
    pub fn len(&self) -> usize {
        self.tree.len()
    }

    /// Returns `true` if this merkle tree is empty.
    ///
    /// See [`Tree::is_empty`] for more.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.tree.is_empty()
    }

    /// Returns the current (i.e right-most) leaf.
    ///
    /// See [`Tree::current_leaf`] for more.
    #[inline]
    pub fn current_leaf(&self) -> Option<&LeafDigest<C>> {
        self.tree.current_leaf()
    }

    /// Returns the [`Root`] of the merkle tree.
    ///
    /// See [`Tree::root`] for more.
    #[inline]
    pub fn root(&self) -> &Root<C> {
        self.tree.root()
    }

    /// Returns the [`CurrentPath`] of the current (i.e right-most) leaf.
    ///
    /// See [`Tree::current_path`] for more.
    #[inline]
    pub fn current_path(&self) -> CurrentPath<C> {
        self.tree.current_path(&self.parameters)
    }

    /// Inserts `leaf` at the next avaiable leaf node of the tree, returning `false` if the
    /// leaf could not be inserted because the tree has exhausted its capacity.
    ///
    /// See [`Tree::push`] for more.
    #[inline]
    pub fn push(&mut self, leaf: &Leaf<C>) -> bool {
        self.tree.push(&self.parameters, leaf)
    }

    /// Appends an iterator of leaves at the end of the tree, returning `false` if the `leaves`
    /// could not be inserted because the tree has exhausted its capacity.
    ///
    /// See [`Tree::extend`] for more.
    #[inline]
    pub fn extend<'l, L>(&mut self, leaves: L) -> bool
    where
        Leaf<C>: 'l,
        L: IntoIterator<Item = &'l Leaf<C>>,
    {
        self.tree.extend(&self.parameters, leaves)
    }

    /// Appends a slice of leaves at the end of the tree, returning `false` if the `leaves` could
    /// not be inserted because the tree has exhausted its capacity.
    ///
    /// See [`Tree::extend_slice`] for more.
    #[inline]
    pub fn extend_slice(&mut self, leaves: &[Leaf<C>]) -> bool
    where
        Leaf<C>: Sized,
    {
        self.tree.extend_slice(&self.parameters, leaves)
    }

    /// Appends an iterator of leaf digests at the end of the tree, returning the iterator back
    /// if it could not be inserted because the tree has exhausted its capacity.
    ///
    /// See [`Tree::extend_digests`] for more.
    #[inline]
    pub fn extend_digests<L>(&mut self, leaf_digests: L) -> Result<(), L::IntoIter>
    where
        L: IntoIterator<Item = LeafDigest<C>>,
    {
        self.tree.extend_digests(&self.parameters, leaf_digests)
    }

    /// Returns the leaf digest at the given `index`.
    ///
    /// See [`WithProofs::leaf_digest`] for more.
    #[inline]
    pub fn leaf_digest(&self, index: usize) -> Option<&LeafDigest<C>>
    where
        T: WithProofs<C>,
    {
        self.tree.leaf_digest(index)
    }

    /// Returns the index of the `leaf_digest` if it is contained in `self`.
    ///
    /// See [`WithProofs::position`] for more.
    #[inline]
    pub fn position(&self, leaf_digest: &LeafDigest<C>) -> Option<usize>
    where
        T: WithProofs<C>,
    {
        self.tree.position(leaf_digest)
    }

    /// Returns `true` if `leaf_digest` is provably stored in `self`.
    ///
    /// See [`WithProofs::contains`] for more.
    #[inline]
    pub fn contains(&self, leaf_digest: &LeafDigest<C>) -> bool
    where
        T: WithProofs<C>,
    {
        self.tree.contains(leaf_digest)
    }

    /// Appends `leaf` to the end of the tree, retaining its path for later use with a call to the
    /// [`path`](Self::path) method.
    ///
    /// See [`WithProofs::push_provable`] for more.
    #[inline]
    pub fn push_provable(&mut self, leaf: &Leaf<C>) -> bool
    where
        T: WithProofs<C>,
    {
        self.tree.push_provable(&self.parameters, leaf)
    }

    /// Returns the path for the leaf stored at the given `index` if it exists.
    ///
    /// See [`WithProofs::path`] for more.
    #[inline]
    pub fn path(&self, index: usize) -> Result<Path<C>, PathError>
    where
        T: WithProofs<C>,
    {
        self.tree.path(&self.parameters, index)
    }

    /// Converts `self` into a fork-able merkle tree.
    ///
    /// Use [`Trunk::into_tree`] to convert back.
    #[inline]
    pub fn into_trunk<P>(self) -> Trunk<C, T, P>
    where
        P: PointerFamily<T>,
    {
        Trunk::new(self.tree)
    }

    /// Extracts the parameters of the merkle tree, dropping the internal tree.
    #[inline]
    pub fn into_parameters(self) -> Parameters<C> {
        self.parameters
    }
}

impl<C, T> AsMut<T> for MerkleTree<C, T>
where
    C: Configuration + ?Sized,
    T: Tree<C>,
{
    #[inline]
    fn as_mut(&mut self) -> &mut T {
        &mut self.tree
    }
}

impl<C, T> AsRef<T> for MerkleTree<C, T>
where
    C: Configuration + ?Sized,
    T: Tree<C>,
{
    #[inline]
    fn as_ref(&self) -> &T {
        &self.tree
    }
}

impl<C, T> accumulator::Types for MerkleTree<C, T>
where
    C: Configuration + ?Sized,
    T: Tree<C>,
{
    type Item = Leaf<C>;
    type Witness = Path<C>;
    type Output = Root<C>;
}

impl<C, T> Accumulator for MerkleTree<C, T>
where
    C: Configuration + ?Sized,
    T: Tree<C> + WithProofs<C>,
    InnerDigest<C>: Clone + PartialEq,
{
    type Model = Parameters<C>;

    #[inline]
    fn model(&self) -> &Self::Model {
        self.parameters()
    }

    #[inline]
    fn insert(&mut self, item: &Self::Item) -> bool {
        self.push_provable(item)
    }

    #[inline]
    fn prove(&self, item: &Self::Item) -> Option<MembershipProof<Self::Model>> {
        Some(MembershipProof::new(
            self.path(self.position(&self.parameters.digest(item))?)
                .ok()?,
            self.root().clone(),
        ))
    }

    #[inline]
    fn contains(&self, item: &Self::Item) -> bool {
        self.contains(&self.parameters.digest(item))
    }
}

impl<C, T> ConstantCapacityAccumulator for MerkleTree<C, T>
where
    C: Configuration + ?Sized,
    T: Tree<C> + WithProofs<C>,
    InnerDigest<C>: Clone + PartialEq,
{
    #[inline]
    fn capacity() -> usize {
        capacity::<C, _>()
    }
}

impl<C, T> ExactSizeAccumulator for MerkleTree<C, T>
where
    C: Configuration + ?Sized,
    T: Tree<C> + WithProofs<C>,
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

impl<C, T> OptimizedAccumulator for MerkleTree<C, T>
where
    C: Configuration + ?Sized,
    T: Tree<C> + WithProofs<C>,
    InnerDigest<C>: Clone + PartialEq,
{
    #[inline]
    fn insert_nonprovable(&mut self, item: &Self::Item) -> bool {
        self.push(item)
    }

    #[inline]
    fn remove_proof(&mut self, item: &Self::Item) -> bool {
        self.tree
            .position(&self.parameters.digest(item))
            .map(move |i| self.tree.remove_path(i))
            .unwrap_or(false)
    }
}

impl<C, T, M> Rollback for MerkleTree<C, ForkedTree<C, T, M>>
where
    C: Configuration + ?Sized,
    T: Tree<C>,
    M: Default + InnerMap<C>,
    LeafDigest<C>: Clone + Default,
    InnerDigest<C>: Clone + Default + PartialEq,
{
    #[inline]
    fn rollback(&mut self) {
        self.tree.reset_fork(&self.parameters);
    }

    #[inline]
    fn commit(&mut self) {
        self.tree.merge_fork(&self.parameters);
    }
}
