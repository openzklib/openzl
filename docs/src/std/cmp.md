# Cmp

Comparison is expressed in Rust through the traits `PartialEq` and `Eq`. ECLAIR has analogues of these that explicitly mention the compiler `COM` to specify the computational environment where comparison occurs. As in Rust, `Eq` is simply a sub-trait of `PartialEq` used to indicate that a partial equivalence relation is actually a true equivalence relation.

The ECLAIR equivalent of `PartialEq` is
```rust
/// Partial Equivalence Relations
pub trait PartialEq<Rhs, COM = ()>
where
    COM: Has<bool>,
{
    /// Returns `true` if `self` and `rhs` are equal.
    fn eq(&self, rhs: &Rhs, compiler: &mut COM) -> Bool<COM>;

    /// Returns `true` if `self` and `rhs` are not equal.
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

For example, when an ECLAIR circuit contains the line
```rust
output = lhs.eq(rhs, &mut compiler);
```
this means that `compiler` will [allocate](../alloc.md) a variable `output` of `COM`'s boolean type and constraint `output` to carry the truth value of `lhs == rhs`.

Besides the `compiler` argument, the main difference from Rust's `PartialEq` trait is the added method `fn assert_equal`. The reason for including this method is that in some ZK proving systems it may be possible to assert equality using fewer constraints than separate calls to `PartialEq::eq` and `Assert::assert`. In such situations, the implementation of `PartialEq<COM>` should replace the blanket implementation here with the more optimized version. This is an example of the sort low-level, `COM`-specific optimizations that ECLAIR allows.