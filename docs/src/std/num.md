# Num
This module provides some useful traits and types for numerical operations. Currently it provides the traits `Zero`, `One`, and `AssertWithinBitRange` as well as an `UnsignedInteger` type for ECLAIR.

## `Zero`, `One`
These traits can be implemented for a type `T` relative to a compiler `COM` in order to indicate that `COM` understands a notion of zero/one value for `T`. Moreover, the trait specifies how `COM` determines whether a given instance of `T` is equal to that zero/one value:
```rust
/// Additive Identity
pub trait Zero<COM = ()> {
    /// Verification Type
    type Verification;

    /// Returns the additive identity for `Self`.
    fn zero(compiler: &mut COM) -> Self;

    /// Returns a truthy value if `self` is equal to the additive identity.
    fn is_zero(&self, compiler: &mut COM) -> Self::Verification;
}
```
Note the `Verification` type, which allows `fn is_zero` to output "truthy values" in whatever sense is appropriate for `COM`. For the native compiler `COM = ()` we would choose `Verification = bool`. For a compiler such that `COM: Has<bool>`, we would likely choose `Verification = Bool<COM>` to be this compiler's boolean type. (Note, however, that we do not require that `COM: Has<bool>` for this trait.)

The trait `One` is similar to `Zero`:
```rust
/// Multiplicative Identity
pub trait One<COM = ()> {
    /// Verification Type
    type Verification;

    /// Returns the multiplicative identity for `Self`.
    fn one(compiler: &mut COM) -> Self;

    /// Returns a truthy value if `self` is equal to the multiplicative identity.
    fn is_one(&self, compiler: &mut COM) -> Self::Verification;
}
```

## Bit Range Assertion
Range checks arise frequently in ZK circuits. One reason is that the primitive data type in a ZK proving system is often a finite field element. When we use one of these finite field elements to represent a quantity such as a 20-byte ETH address we need to ensure that the field element really is within the correct range.

In the native computation setting this is a straightforward comparison between the finite field element (represented as a positive integer) and the maximum size of a 20-byte integer. However a non-native compiler needs to generate constraints that are satisfied only if the finite field element lies in the correct range.

ECLAIR's interface for range checks is the trait `AssertWithinBitRange`:
```rust
/// Within-Bit-Range Assertion
///
/// # Restrictions
///
/// This `trait` assumes that `BITS > 0` and does not currently support `BITS = 0`. 
/// In this case we would have an assertion that `x < 2^0 = 1` which is just that 
/// `x = 0` in most systems. For this usecase, the [`Zero`] `trait` should be 
/// considered instead.
pub trait AssertWithinBitRange<T, const BITS: usize> {
    /// Asserts that `value` is smaller than `2^BITS`.
    fn assert_within_range(&mut self, value: &T);
}
```
This trait is implemented by a compiler type `COM` to specify how `COM` constrains values of type `T` to lie in the range specified by `BITS`. The line
```rust
compiler.assert_within_range::<BITS>(value);
```
causes the compiler to generate constraints that are satisfied only if `value` lies within the range specified by `BITS`.

## Unsigned Integers
The `AssertWithinBitRange` trait allows ECLAIR to handle unsigned integers within proof systems as finite field elements with a checked size. We define unsigned integers as a thin wrapper around a type `T`:
```rust
/// Unsigned Integer
pub struct UnsignedInteger<T, const BITS: usize>(T);
```
One should think of this construction as analogous to representing a boolean value with a `u8`. The `u8` type is acting as a container for the boolean value. But this container is "too large" in the sense that many `u8` values do not correspond to a boolean value. Before interpreting a `u8` as a boolean it is necessary to check that its value lies in the range `[0,1]`.

Similarly, when we work within a proving system over a finite field, we may need to use field elements as a container for unsigned integer types. In this case a range check is required to make sure that the value in this container really does have an interpretation as an unsigned integer of the given size.

The compiler type `COM` does not appear as part of the `UnsignedInteger` type, but it must be mentioned whenever we construct or mutate an `UnsignedInteger`:
```rust
impl<T, const BITS: usize> UnsignedInteger<T, BITS> {
    /// Builds a new [`UnsignedInteger`] over `value` asserting that it does not
    /// exceed `BITS`-many bits.
    pub fn new<COM>(value: T, compiler: &mut COM) -> Self
    where
        COM: AssertWithinBitRange<T, BITS>,
    {
        compiler.assert_within_range(&value);
        Self::new_unchecked(value)
    }

    /// Mutates the underlying value of `self` with `f`, asserting that after
    /// mutation the value is still within the `BITS` range.
    pub fn mutate<F, U, COM>(&mut self, f: F, compiler: &mut COM) -> U
    where
        COM: AssertWithinBitRange<T, BITS>,
        F: FnOnce(&mut T, &mut COM) -> U,
    {
        let output = f(&mut self.0, compiler);
        compiler.assert_within_range(&self.0);
        output
    }
}
```
Observe that both functions require the trait bound `COM: AssertWithinBitRange<T, BITS>`, meaning that the compiler must know how to constrain values of type `T` to the range specified by `BITS`. Before constructing an `UnsignedInteger` with `fn new`, `compiler` generates constraints that guarantee that `T` lies in the range specified by `BITS`. Similarly, `fn mutate` transforms an `UnsignedInteger`'s value in some way and generates constraints to ensure that the result of the transformation still lies within range before returning a value.

When `COM = ()` is the native compiler, `fn new` and `fn mutate` would panic if the inner value of type `T` exceeds the bit-range. In non-native computation, `compiler` would generate constraints that the inner value does not satisfy, resulting in an unsatisfied constraint system.

These functions can be seen at work in the implementation of `Add` and `AddAssign` for `UnsignedInteger`:
```rust
impl<T, COM, const BITS: usize> Add<Self, COM> for UnsignedInteger<T, BITS>
where
    T: Add<T, COM>,
    COM: AssertWithinBitRange<T::Output, BITS>,
{
    type Output = UnsignedInteger<T::Output, BITS>;

    fn add(self, rhs: Self, compiler: &mut COM) -> Self::Output {
        Self::Output::new(self.0.add(rhs.0, compiler), compiler)
    }
}

impl<T, COM, const BITS: usize> AddAssign<Self, COM> for UnsignedInteger<T, BITS>
where
    COM: AssertWithinBitRange<T, BITS>,
    T: AddAssign<T, COM>,
{
    fn add_assign(&mut self, rhs: Self, compiler: &mut COM) {
        self.mutate(|lhs, compiler| lhs.add_assign(rhs.0, compiler), compiler);
    }
}
```
As a thin wrapper around `T`, `UnsignedInteger<T, BITS>` inherits many implementations from `T`. But not all operations that can be performed on `T` result in a valid `UnsignedInteger`. For example, `fn add` uses the `UnsignedInteger::new` function to construct its return value, telling `compiler` to constrain that return value to the bit-range. Similarly `fn add_assign` calls `fn mutate` to mutate the value, again generating constraints that enforce a range check on the mutated value.

### Checked *vs* Unchecked
Looking at the body of the `UnsignedInteger::new` method we see that after a range check it uses `fn new_unchecked` to construct its return value. ECLAIR exposes `fn new_unchecked` as a public function because it allows for optimizations in instances where range checks are unnecessary. 

For example, if `T` implements `Zero<COM>` or `One<COM>` then we know that `T`'s zero/one value will pass any range check (we require `BITS >= 1` for range checks, see `AssertWithinBitRange` above). Thus the implementation is:
```rust
impl<T, const BITS: usize, COM> Zero<COM> for UnsignedInteger<T, BITS>
where
    T: Zero<COM>,
{
    type Verification = T::Verification;

    fn zero(compiler: &mut COM) -> Self {
        Self::new_unchecked(T::zero(compiler))
    }

    fn is_zero(&self, compiler: &mut COM) -> Self::Verification {
        self.0.is_zero(compiler)
    }
}
```
In this instance it would be wasteful to add a range check to the value `T::zero(compiler)` because the contract of the `Zero` trait guarantees that this is within range. The same holds for `T::one(compiler)` in the implementation of `One<COM>`.

Another example where the unchecked construction should be used is the `ConditionalSelect<COM>` trait (see [Bool](./bool.md)): 
```rust
impl<T, const BITS: usize, COM> ConditionalSelect<COM> for UnsignedInteger<T, BITS>
where
    COM: Has<bool>,
    T: ConditionalSelect<COM>,
{
    fn select(bit: &Bool<COM>, true_value: &Self, false_value: &Self, compiler: &mut COM) -> Self {
        Self::new_unchecked(T::select(bit, &true_value.0, &false_value.0, compiler))
    }
}
```
Again it is appropriate to use unchecked construction because both `true_value` and `false_value` are of type `UnsignedInteger` and so it would be wasteful to perform another range check on their inner values.