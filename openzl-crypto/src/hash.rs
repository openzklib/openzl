//! Hash Functions

/// Security Assumptions
///
/// The following outlines some standard security assumptions for hash functions. These security
/// properties can be attached to general types that don't exactly conform to the hash function
/// `trait`s to describe the same cryptographic assumptions or guarantees given by the type.
pub mod security {
    /// Preimage Resistance
    ///
    /// For a hash function `H` and an output `y`, it should be infeasible to find a preimage `x`
    /// such that the following function returns `true`:
    ///
    /// ```text
    /// fn is_preimage(x: H::Input, y: H::Output) -> bool {
    ///     H(x) == h
    /// }
    /// ```
    pub trait PreimageResistance {}

    /// Second Preimage Resistance
    ///
    /// For a hash function `H` and an input `x_1`, it should be infeasible to find a another input
    /// `x_2` such that the following function returns `true`:
    ///
    /// ```text
    /// fn is_collision(x_1: H::Input, x_2: H::Input) -> bool {
    ///     (x_1 != x_2) && (H(x_1) == H(x_2))
    /// }
    /// ```
    pub trait SecondPreimageResistance {}

    /// Collision Resistance
    ///
    /// For a hash function `H` it should be infeasible to find two inputs `x_1` and `x_2` such that
    /// the following function returns `true`:
    ///
    /// ```text
    /// fn is_collision(x_1: H::Input, x_2: H::Input) -> bool {
    ///     (x_1 != x_2) && (H(x_1) == H(x_2))
    /// }
    /// ```
    ///
    /// # Strength
    ///
    /// Note this is a stronger assumption than [`SecondPreimageResistance`] since we are not
    /// requiring that the attacker find a second preimage of a given input `x_1`, they only need to
    /// find any collision for any input to break this assumption.
    pub trait CollisionResistance: SecondPreimageResistance {}
}
