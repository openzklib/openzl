# Cmp

Comparison is expressed in Rust through the traits `PartialEq` and `Eq`. ECLAIR has analogues of these that explicitly mention the compiler `COM` to specify the computational environment where comparison is to occur. As in Rust, `Eq` is simply a sub-trait of `PartialEq` used to indicate that a partial equivalence relation is actually a true equivalence relation.

The ECLAIR equivalent of `PartialEq` is
```rust
/// Partial Equivalence Relations
pub trait PartialEq<Rhs, COM = ()>
where
    Rhs: ?Sized,
    COM: Has<bool> + ?Sized,
{
    /// Returns `true` if `self` and `rhs` are equal.
    fn eq(&self, rhs: &Rhs, compiler: &mut COM) -> Bool<COM>;

    /// Returns `true` if `self` and `rhs` are not equal.
    #[inline]
    fn ne(&self, other: &Rhs, compiler: &mut COM) -> Bool<COM>
    where
        Bool<COM>: Not<COM, Output = Bool<COM>>,
    {
        self.eq(other, compiler).not(compiler)
    }

    /// Asserts that `self` and `rhs` are equal.
    ///
    /// # Implementation Note
    ///
    /// This method is an optimization path for the case when 
    /// comparing for equality and then asserting is more expensive 
    /// than a custom assertion.
    #[inline]
    fn assert_equal(&self, rhs: &Rhs, compiler: &mut COM)
    where
        COM: Assert,
    {
        let are_equal = self.eq(rhs, compiler);
        compiler.assert(&are_equal);
    }
}
```
As with most traits in the ECLAIR Standard Library, `PartialEq` differs from its pure Rust equivalent mainly by the addition of the `COM` type and an argument `compiler: &mut COM` in the function signatures. This allows ECLAIR to generate appropriate constraints whenever `COM` specifies a ZK proving system. 

The other notable difference is the added method `fn assert_equal`, which does not belong to the pure Rust `PartialEq` trait. The reason for including this method is that in some ZK proving systems it may be possible to assert equality using fewer constraints than separate calls to `PartialEq::eq` and `Assert::assert`. In developing ECLAIR we have kept a careful eye out for these sorts of opportunities to allow low-level `COM`-specific optimizations.