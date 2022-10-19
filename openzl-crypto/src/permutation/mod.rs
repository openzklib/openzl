//! Pseudorandom Permutations

pub mod sponge;

#[cfg(feature = "alloc")]
#[cfg_attr(doc_cfg, doc(cfg(feature = "alloc")))]
pub mod duplex;

/// Pseudorandom Permutation
pub trait PseudorandomPermutation<COM = ()> {
    /// Permutation Domain Type
    ///
    /// A pseudorandom permutation acts on this domain, and should be a bijection on this space.
    type Domain;

    /// Computes the permutation of `state`.
    fn permute(&self, state: &mut Self::Domain, compiler: &mut COM);
}

impl<P, COM> PseudorandomPermutation<COM> for &P
where
    P: PseudorandomPermutation<COM>,
{
    type Domain = P::Domain;

    #[inline]
    fn permute(&self, state: &mut Self::Domain, compiler: &mut COM) {
        (*self).permute(state, compiler)
    }
}

/// Pseudorandom Permutation Family
pub trait PseudorandomPermutationFamily<COM = ()> {
    /// Key Type
    type Key: ?Sized;

    /// Permutation Domain Type
    ///
    /// A pseudorandom permutation acts on this domain, and should be a bijection on this space.
    type Domain;

    /// Permutation Type
    ///
    /// Given a [`Key`](Self::Key) we can produce a pseudorandom permutation of this type.
    type Permutation: PseudorandomPermutation<COM, Domain = Self::Domain>;

    /// Returns the pseudorandom permutation associated to the given `key`.
    fn permutation(&self, key: &Self::Key, compiler: &mut COM) -> Self::Permutation;

    /// Computes the permutation of `state` under the pseudorandom permutation derived from `key`.
    #[inline]
    fn permute(&self, key: &Self::Key, state: &mut Self::Domain, compiler: &mut COM) {
        self.permutation(key, compiler).permute(state, compiler)
    }
}

impl<P, COM> PseudorandomPermutationFamily<COM> for &P
where
    P: PseudorandomPermutationFamily<COM>,
{
    type Key = P::Key;
    type Domain = P::Domain;
    type Permutation = P::Permutation;

    #[inline]
    fn permutation(&self, key: &Self::Key, compiler: &mut COM) -> Self::Permutation {
        (*self).permutation(key, compiler)
    }
}
