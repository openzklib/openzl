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

//! Persistence and Backups Utilities

/// Rollback Trait
///
/// This trait should be implemented by strucutres which have a canonical working state which can be
/// discarded easily.
pub trait Rollback {
    /// Rolls back `self` to the previous state.
    ///
    /// # Implementation Note
    ///
    /// Rolling back to the previous state must be idempotent, i.e. two consecutive calls to
    /// [`rollback`](Self::rollback) should have the same effect as one call.
    fn rollback(&mut self);

    /// Commits `self` to the current state, preventing a future call to
    /// [`rollback`](Self::rollback) from clearing the state.
    ///
    /// # Implementation Note
    ///
    /// Commiting to the current state must be idempotent, i.e. two consecutive calls to
    /// [`commit`](Self::commit) should have the same effect as one call.
    fn commit(&mut self);
}
