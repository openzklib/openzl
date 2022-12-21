# ArkGroth16

The [Arkworks plugin](https://github.com/openzklib/openzl/tree/main/plugins/arkworks/src) for OpenZL contains implementations of ECLAIR traits for the Arkworks implementation of Groth16. It also implements some traits from the OpenZL-Crypto crate to provide concrete instances of cryptographic primitives like the Poseidon hash function.

The compiler type `COM` for this plugin is `R1CS<F>`, where the generic type `F` specifies the constraint field. This type `R1CS<F>` is a wrapper around the Arkworks type [`ConstraintSystemRef<F>`](https://docs.rs/ark-relations/latest/ark_relations/r1cs/enum.ConstraintSystemRef.html). The [`ark-relations` crate](https://docs.rs/ark-relations/) specifies the internal logic of how a `ConstraintSystemRef<F>` allocates new variables and generates constraints. It is the job of this plugin to provide the interface for ECLAIR code to access those internal methods.

For example, the [`Has<bool>`](./std/bool.md) trait from the ECLAIR standard library specifies that booleans should be represented by the type that Arkworks created for this purpose, namely [`Boolean<F>`](https://docs.rs/ark-r1cs-std/latest/ark_r1cs_std/bits/boolean/enum.Boolean.html). This looks like
```rust
impl<F> Has<bool> for R1CS<F>
where
    F: PrimeField,
{
    type Type = Boolean<F>;
}
```
Now that `R1CS<F>` has a boolean type, the [`Assert` trait](./std/bool.md) from the ECLAIR standard library can be implemented as follows:
```rust
impl<F> Assert for R1CS<F>
where
    F: PrimeField,
{
    fn assert(&mut self, b: &Boolean<F>) {
        b.enforce_equal(&Boolean::TRUE)
            .expect("Enforcing equality is not allowed to fail.");
    }
}
```
This implementation is referring to an Arkworks method [`fn enforce_equal`](https://docs.rs/ark-r1cs-std/latest/ark_r1cs_std/eq/trait.EqGadget.html#method.enforce_equal) to generate the appropriate assertion constraints. Now when ECLAIR code is compiled by the ArkGroth16 plugin, assertions generate constraints within `R1CS<F>` using `fn enforce_equal` under the hood.

## Field Variables

Variables valued in a finite field `F` are represented by Arkworks' [`FpVar`](https://docs.rs/ark-r1cs-std/latest/ark_r1cs_std/fields/fp/enum.FpVar.html) type. Making these accessible to ECLAIR circuits requires implementing the appropriate [allocation](alloc.md) traits:
```rust
impl<F> Variable<Public, R1CS<F>> for FpVar<F>
where
    F: PrimeField,
{
    type Type = Fp<F>;

    fn new_known(this: &Self::Type, compiler: &mut R1CS<F>) -> Self {
        Self::new_input(ns!(compiler.0, "field public input"), full(this.0))
            .expect("Variable allocation is not allowed to fail.")
    }

    fn new_unknown(compiler: &mut R1CS<F>) -> Self {
        Self::new_input(ns!(compiler.0, "field public input"), empty::<F>)
            .expect("Variable allocation is not allowed to fail.")
    }
}

impl<F> Variable<Secret, R1CS<F>> for FpVar<F>
where
    F: PrimeField,
{
    type Type = Fp<F>;

    fn new_known(this: &Self::Type, compiler: &mut R1CS<F>) -> Self {
        Self::new_witness(ns!(compiler.0, "field secret witness"), full(this.0))
            .expect("Variable allocation is not allowed to fail.")
    }

    fn new_unknown(compiler: &mut R1CS<F>) -> Self {
        Self::new_witness(ns!(compiler.0, "field secret witness"), empty::<F>)
            .expect("Variable allocation is not allowed to fail.")
    }
}
```

Again, the implementation merely consists of referring back to Arkworks methods for allocating `FpVar`. The `Type` specified is [`Fp<F>`](https://github.com/openzklib/openzl/blob/main/plugins/arkworks/src/constraint/fp.rs), which is a wrapper around `F` that inherits implementations of Arkworks traits such as `PrimeField` and has implementations of some traits from OpenZL-Crypto.