// Copyright 2019-2022 Manta Network.
// This file is part of manta-rs.
//
// manta-rs is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// manta-rs is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with manta-rs.  If not, see <http://www.gnu.org/licenses/>.

//! Linear Feedback Shift Register

use core::iter::FusedIterator;

/// An 80-bit linear feedback shift register, described in [GKRRS19] Appendix A.
///
/// [GKRRS19]: https://eprint.iacr.org/2019/458.pdf
///
/// # Note
///
/// This `struct` does not implement `Copy` because it also implements `Iterator` which would lead
/// to confusion when using this type in looping contexts.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct GrainLFSR {
    /// LFSR Internal State
    state: [bool; Self::SIZE],

    /// Head Pointer into [`self.state`](Self::state)
    head: usize,
}

impl GrainLFSR {
    /// LFSR State Size
    pub const SIZE: usize = 80;

    /// Generates a [`GrainLFSR`] from a
    #[inline]
    pub fn from_seed<I>(iter: I) -> Self
    where
        I: IntoIterator<Item = (usize, u128)>,
    {
        let mut lfsr = Self {
            state: [false; Self::SIZE],
            head: 0,
        };
        for (n, bits) in iter {
            lfsr.append_seed_bits(n, bits);
        }
        lfsr.skip_updates(Self::SIZE * 2);
        lfsr
    }

    /// Appends `n` seed bits into the LFSR state.
    #[inline]
    fn append_seed_bits(&mut self, n: usize, bits: u128) {
        for i in (0..n).rev() {
            self.set_next((bits >> i) & 1 != 0);
        }
    }

    /// Performs `n` updates, ignoring their results.
    #[inline]
    fn skip_updates(&mut self, n: usize) {
        for _ in 0..n {
            self.update();
        }
    }

    /// Sets the bit at the current bit pointed to by the head pointer to `next`, moving the head
    /// pointer forward one step.
    #[inline]
    fn set_next(&mut self, next: bool) -> bool {
        self.state[self.head] = next;
        self.head += 1;
        self.head %= Self::SIZE;
        next
    }

    /// Returns the bit value of `self.state` at the position `index + self.head`.
    #[inline]
    fn bit(&self, index: usize) -> bool {
        self.state[(index + self.head) % Self::SIZE]
    }

    /// Updates 1 bit at `self.state[self.head]` and increases `self.head` by 1.
    fn update(&mut self) -> bool {
        self.set_next(
            self.bit(62) ^ self.bit(51) ^ self.bit(38) ^ self.bit(23) ^ self.bit(13) ^ self.bit(0),
        )
    }
}

impl Iterator for GrainLFSR {
    type Item = bool;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        let mut bit = self.update();
        while !bit {
            self.update();
            bit = self.update();
        }
        Some(self.update())
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        (usize::MAX, None)
    }
}

impl FusedIterator for GrainLFSR {}
