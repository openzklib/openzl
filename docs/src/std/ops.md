# Ops

ECLAIR has analogues of many of Rust's [overloadable operators](https://doc.rust-lang.org/rust-by-example/trait/ops.html). These are the traits like `Neg`, `Add`, `Mul`, *etc* that overload the behavior of the `-`, `+`, `*` operators. 

By now you can probably guess how ECLAIR defines analogues of these traits: function signatures pick up a mutable reference `compiler: &mut COM` to a compiler type and use this to generate constraints, when appropriate. For the native compiler `COM = ()`, each trait is identical to its pure Rust analogue. 

For example, the pure Rust trait `Add<Rhs>`:
```rust
pub trait Add<Rhs = Self> {
    type Output;

    fn add(self, rhs: Rhs) -> Self::Output;
}
```
is replaced with the ECLAIR trait `Add<Rhs, COM>`:
```rust
pub trait Add<Rhs = Self, COM = ()> 
where 
    COM: ?Sized,
{
    type Output;

    fn add(self, rhs: Rhs, compiler: &mut COM) -> Self::Output;
}
```
This straightforward transformation of traits is carried out for the following traits: `Neg`, `Not`, `Add`, `BitAnd`, `BitOr`, `BitXor`, `Div`, `Mul`, `Rem`, `Shl`, `Shr`, `Sub`, `AddAssign`, `BitAndAssign`, `BitOrAssign`, `BitXorAssign`, `DivAssign`, `MulAssign`, `RemAssign`, `ShlAssign`, `ShrAssign`, `SubAssign`. See the [Rust documentation](https://doc.rust-lang.org/core/ops/index.html) of these traits for more information.

## Compiler Reflection

When some type `T` implements `Add<COM>`, this means that the compiler type `COM` knows how to generate constraints that enforce correct addition of values of type `T`. It can be useful to express this as a property of `COM` rather than a property of `T`, which ECLAIR does through "compiler reflection." 

When `T: Add<COM>`, compiler reflection means that `COM: HasAdd<T>`. Explicitly, the `HasAdd<T>` trait is
```rust
pub trait HasAdd<L, R = L> {
    /// Output Type
    /// The resulting type after applying the `+` operator.
    type Output;

    /// Performs the `lhs + rhs` operation over the
    /// `self` compiler.
    fn add(&mut self, lhs: L, rhs: R) -> Self::Output;
}
```
For each of the traits listed above we include an implementation of the corresponding reflection trait:
```rust 
impl<COM, L, R> HasAdd<L, R> for COM
where
    L: Add<R, COM>
{
    fn add(&mut self, lhs: L, rhs: R) -> Self::Output {
        lhs.add(rhs, self)
    }
}
```
With this `HasAdd` trait we can now use a trait bound `COM: HasAdd<T>` to express the requirement that certain other ECLAIR traits or circuits make sense only for compilers that can add values of type `T`.