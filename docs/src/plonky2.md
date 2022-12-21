# Plonky2

The Plonky2 proof system plugin for OpenZL contains implementations of ECLAIR traits for [Plonky2](https://github.com/mir-protocol/plonky2). 

The compiler type `COM` for this proof system is a struct `Compiler` composed of two Plonky2 types:
```rust
/// Compiler
pub struct Compiler<F, const D: usize>
where
    F: RichField + Extendable<D>,
{
    /// Circuit Builder
    pub builder: CircuitBuilder<F, D>,

    /// Partial Witness
    pub partial_witness: PartialWitness<F>,
}
```
Therefore this plugin compiles ECLAIR circuit code by allocating variables and generating constraints in a `CircuitBuilder` and `PartialWitness` according to the logic specified by Plonky2. The traits implemented in this plugin provide the interface for ECLAIR code to access the internal methods of Plonky2.

For example,  the [`Has<bool>`](./std/bool.md) trait from the ECLAIR standard library specifies that booleans should be represented by a type `Bool<F, D>` that wraps Plonky2's `BoolTarget` type:
```rust
/// Boolean Type
pub struct Bool<F, const D: usize> {
    /// Target
    pub target: BoolTarget,

    /// Type Parameter Marker
    __: PhantomData<F>,
}

impl<F, const D: usize> Has<bool> for Compiler<F, D>
where
    F: RichField + Extendable<D>,
{
    type Type = Bool<F, D>;
}
```
Now that `Compiler<F, D>` has a boolean type, the [`Assert` trait](./std/bool.md) from the ECLAIR standard library can be implemented as follows:
```rust
impl<F, const D: usize> Assert for Compiler<F, D>
where
    F: RichField + Extendable<D>,
{
    #[inline]
    fn assert(&mut self, b: &Bool<F, D>) {
        self.builder.assert_bool(b.target)
    }
}
```
This implementation is referring to a Plonky2 method [`fn assert_bool`](https://github.com/mir-protocol/plonky2/blob/main/plonky2/src/gadgets/range_check.rs#L47) to generate the appropriate assertion constraints. Now when ECLAIR code is compiled by the Plonky2 plugin, assertions generate constraints within `Compiler<F, D>` using `fn assert_bool` under the hood.

## Field Variables

Variables valued in a finite field `F` are represented by a type `Field<F, D>` that wraps the Plonky2 [`Target`](https://github.com/mir-protocol/plonky2/blob/main/plonky2/src/iop/target.rs) type:
```rust
/// Variable Field Type
pub struct Field<F, const D: usize> {
    /// Target
    pub target: Target,

    /// Type Parameter Marker
    __: PhantomData<F>,
}
``` 

Making field-valued variables accessible to ECLAIR circuits requires implementing the appropriate [allocation](alloc.md) traits:
```rust
impl<F, const D: usize> Variable<Public, Compiler<F, D>> for Field<F, D>
where
    F: RichField + Extendable<D>,
{
    type Type = F;

    fn new_known(this: &Self::Type, compiler: &mut Compiler<F, D>) -> Self {
        Self::new(compiler.add_public_target(*this))
    }

    #[inline]
    fn new_unknown(compiler: &mut Compiler<F, D>) -> Self {
        Self::new(compiler.add_virtual_public_target())
    }
}

impl<F, const D: usize> Variable<Secret, Compiler<F, D>> for Field<F, D>
where
    F: RichField + Extendable<D>,
{
    type Type = F;

    fn new_known(this: &Self::Type, compiler: &mut Compiler<F, D>) -> Self {
        Self::new(compiler.add_target(*this))
    }

    #[inline]
    fn new_unknown(compiler: &mut Compiler<F, D>) -> Self {
        Self::new(compiler.add_virtual_target())
    }
}
```

Again, the implementation merely consists of referring back to Plonky2 methods for allocating `Target`. The `Type` specified is `F`, indicating that the underlying value of this variable is a finite field element.
