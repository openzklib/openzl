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
