//! Sponges over Pseudorandom Permutations

use crate::permutation::PseudorandomPermutation;

/// Sponge Reader
pub trait Read<P, COM = ()>: Sized
where
    P: PseudorandomPermutation<COM>,
{
    /// Reads an element of type `Self` from the `state`.
    fn read(state: &P::Domain, compiler: &mut COM) -> Self;
}

/// Sponge Writer
pub trait Write<P, COM = ()>
where
    P: PseudorandomPermutation<COM>,
{
    /// Output Type
    type Output;

    /// Writes `self` to the `state`, returning some output data computed from `self` and `state`.
    fn write(&self, state: &mut P::Domain, compiler: &mut COM) -> Self::Output;
}

/// Permutation Sponge
///
/// This `struct` is a general sponge-like construction which takes a permutation and repeatedly
/// applies it to an internal state, with read and write access to the state via the [`absorb`]
/// and [`squeeze`] methods. Using a concrete permutation and fixed [`absorb`] input and [`squeeze`]
/// output functions one can build the classical sponge constructions.
///
/// [`absorb`]: Self::absorb
/// [`squeeze`]: Self::squeeze
pub struct Sponge<'p, P, COM = ()>
where
    P: PseudorandomPermutation<COM>,
{
    /// Permutation
    pub permutation: &'p P,

    /// Sponge State
    pub state: &'p mut P::Domain,
}

impl<'p, P, COM> Sponge<'p, P, COM>
where
    P: PseudorandomPermutation<COM>,
{
    /// Builds a new [`Sponge`] over `permutation` with the given initial `state`.
    #[inline]
    pub fn new(permutation: &'p P, state: &'p mut P::Domain) -> Self {
        Self { permutation, state }
    }

    /// Writes `input` into `self`.
    #[inline]
    pub fn write<W>(&mut self, input: &W, compiler: &mut COM) -> W::Output
    where
        W: Write<P, COM>,
    {
        input.write(self.state, compiler)
    }

    /// Updates `self` by absorbing writes into the state with `input`.
    #[inline]
    pub fn absorb<W>(&mut self, input: &W, compiler: &mut COM) -> W::Output
    where
        W: Write<P, COM>,
    {
        let out = self.write(input, compiler);
        self.permutation.permute(self.state, compiler);
        out
    }

    /// Absorbs all items in the `input` iterator, collecting all output items from writes into
    /// the state. See [`Write::write`] for more.
    #[inline]
    pub fn absorb_all<'w, W, I, C>(&mut self, input: I, compiler: &mut COM) -> C
    where
        W: 'w + Write<P, COM>,
        I: IntoIterator<Item = &'w W>,
        C: FromIterator<W::Output>,
    {
        input
            .into_iter()
            .map(|item| self.absorb(item, compiler))
            .collect()
    }

    /// Reads values from `self`.
    #[inline]
    pub fn read<R>(&self, compiler: &mut COM) -> R
    where
        R: Read<P, COM>,
    {
        R::read(self.state, compiler)
    }

    /// Returns the next values from `self` by squeezing reads of the values from the state.
    #[inline]
    pub fn squeeze<R>(&mut self, compiler: &mut COM) -> R
    where
        R: Read<P, COM>,
    {
        let out = self.read(compiler);
        self.permutation.permute(self.state, compiler);
        out
    }
}

