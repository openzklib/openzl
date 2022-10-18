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

//! An ordered map based on a B-Tree.

use core::borrow::Borrow;

#[doc(inline)]
pub use alloc::collections::btree_map::*;

/// Error Message for the [`pop_last`] Function
const POP_LAST_ERROR_MESSAGE: &str =
    "Querying the last element of the map must guarantee that `BTreeMap::remove` always succeeds.";

/// Pops the last element in the key-ordering of `map`.
///
/// # Limitation
///
/// Until <https://github.com/rust-lang/rust/issues/62924> is stabilized this is an equivalent
/// way to pop the last key-value pair out of a [`BTreeMap`] but requires cloning the key.
#[inline]
pub fn pop_last<K, V>(map: &mut BTreeMap<K, V>) -> Option<(K, V)>
where
    K: Clone + Ord,
{
    let key = map.keys().last()?.clone();
    match map.remove(&key) {
        Some(value) => Some((key, value)),
        _ => unreachable!("{}", POP_LAST_ERROR_MESSAGE),
    }
}

/// Returns the value stored at `key` in the `map` or executes `f` on the map if there was no
/// value stored at `key`.
///
/// # Limitation
///
/// The current implementation of the borrow-checker is too conservative and forces a
/// long-living borrow of the `map` whenever we want to return borrowed data from the map. In
/// this case, we do an extra query to work around this.
#[inline]
pub fn get_or_mutate<'m, K, V, Q, F>(map: &'m mut BTreeMap<K, V>, key: &Q, f: F) -> Option<&'m V>
where
    K: Borrow<Q> + Ord,
    Q: Ord + ?Sized,
    F: FnOnce(&mut BTreeMap<K, V>) -> Option<&V>,
{
    if map.contains_key(key) {
        map.get(key)
    } else {
        f(map)
    }
}

/// Inserts the `key`-`value` pair into the `map`, returning a reference to the inserted value.
#[inline]
pub fn insert_then_get<K, V>(map: &mut BTreeMap<K, V>, key: K, value: V) -> &mut V
where
    K: Ord,
{
    match map.entry(key) {
        Entry::Vacant(entry) => entry.insert(value),
        Entry::Occupied(mut entry) => {
            entry.insert(value);
            entry.into_mut()
        }
    }
}
