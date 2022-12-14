# Bool

Any reasonable computational environment has a notion of boolean type, but not all environments represent this concept in the same way. Native computation operates directly on bits and therefore has a very natural notion of boolean type: a single bit. However a non-native environment such as a ZK proving system may lack a natural boolean type. Thus in order for ECLAIR to express bit-wise operations or truth-valued comparisons in these environments we need to specify how each `COM` type encodes boolean operations.

## `Has<bool>`

First we must specify a given compiler's boolean type. We do so through the `eclair::Has` trait (TODO: How can that link to rust docs?):
```rust
/// Compiler Type Introspection
pub trait Has<T> {
    /// Compiler Type
    ///
    /// This type represents the allocation of `T` into `Self` as a compiler. 
    /// Whenever we need to define abstractions that require the compiler to 
    /// have access to some type internally, we can use this `trait` as a 
    /// requirement of that abstraction.
    type Type;
}
```
The `Has<T>` trait is implemented for a compiler type `COM` to specify how the type `T` is represented within `COM`'s computational environment. The native compiler `COM = ()` always represents `T` as `T`, so it implements `Has<T>` for any type `T`.

To see the usefulness of `Has<T>`, suppose `COM` corresponds to a ZK proving system such as Groth16 that represents computation as a R1CS over some finite field `F`. We can call this compiler type `R1CS<F>`. 

In this setting there are no "bits," only finite field elements. Thus we need to choose how to represent bits. A reasonable choice would be to use the field `F` itself, perhaps with the convention that the zero element represents the boolean `0` and any non-zero element represents the boolean `1`. We would specify this choice by an implementation:
```rust
impl Has<bool> for R1CS<F> {
    type Type = FVar;
}
```
Here `FVar` is a type that represents variables in the R1CS that can have values in `F`. With this implementation specify that the `R1CS<F>` compiler represents booleans as variables with values in `F`.

`Has<bool>` is a necessary trait for a compiler type to make sense of many natural operations such as comparison, conditional switching, assertion, *etc*. For example, an `==` comparison between two variables in `COM` produces a boolean truth value; this truth value must itself be represented somehow within `COM`, hence the requirement `COM: Has<bool>` in order for equality comparisons to be possible in `COM`. See [here](./cmp.md) for more on comparisons in ECLAIR.

## Assert

An example of an `ECLAIR` trait that requires `Has<bool>` is `Assert`:
```rust
/// Assertion
pub trait Assert: Has<bool> {
    /// Asserts that `bit` reduces to `true`.
    fn assert(&mut self, bit: &Bool<Self>);

    /// Asserts that all the items in the `iter` reduce to `true`.
    #[inline]
    fn assert_all<'b, I>(&mut self, iter: I)
    where
        Self: Assert,
        Bool<Self>: 'b,
        I: IntoIterator<Item = &'b Bool<Self>>,
    {
        iter.into_iter().for_each(move |b| self.assert(b));
    }
}
```
If `compiler` is of a type `COM` that implements `Assert` then `compiler.assert(bit)` should generate a constraint that is satisfied if and only if `bit` represents `true` according to `COM`'s implementation of `Has<bool>`. In the native compiler `COM = ()` the computation simply panics if `bit = false`. 

The requirement `COM: Assert` is a prerequisite for the trait `PartialEq<Rhs, COM>`. More on that [here](./cmp.md).

## Conditional Selection and Swap
Another common operation involving booleans is selection, expressed in ECLAIR through the `ConditionalSelect<COM>` trait:
```rust
/// Conditional Selection
pub trait ConditionalSelect<COM = ()>: Sized
where
    COM: Has<bool> + ?Sized,
{
    /// Selects `true_value` when `bit == true` and `false_value` when `bit == false`.
    fn select(
        bit: &Bool<COM>, 
        true_value: &Self, 
        false_value: &Self, 
        compiler: &mut COM
    ) -> Self;
}
```
If an ECLAIR circuit contains the line
```rust
output = select(bit, true_value, false_value, &mut compiler);
```
then this generates a constraint in `compiler` that enforces `output == true_value` if `bit` represents `true` and `output == false_value` otherwise. Of course this only makes sense if `compiler` knows how to interpret `bit` as a boolean value, hence the requirement `COM: Has<bool>`.

A similar operation is conditionally swapping values based on a boolean. For this we have the `ConditionalSwap<COM>` trait:
```rust
/// Conditional Swap
pub trait ConditionalSwap<COM = ()>: Sized
where
    COM: Has<bool> + ?Sized,
{
    /// Swaps `lhs` and `rhs` whenever `bit == true` and keeps 
    /// them in the same order when `bit == false`.
    fn swap(
        bit: &Bool<COM>, 
        lhs: &Self, 
        rhs: &Self, 
        compiler: &mut COM
    ) -> (Self, Self);
}
```
This trait is self-explanatory.