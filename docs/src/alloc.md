# Allocation

The `alloc` module defines ECLAIR's interface for allocating values in a compiler. We use the term "allocation" here to refer to the process of declaring a variable in a ZK proof system and (maybe) assigning it a value. Note that we are *not* referring to memory-related abstractions like heap allocation.

Variables in a ZK proof system can be private witnesses, public inputs, constants, or some mixture of these. For example, in a merkle tree membership proof we would have variables representing the values stored:
- in some leaf of the tree 
- along the path from that leaf to the root
- in the root of the tree.

In the simplest case, all those values have the same type -- perhaps a finite field element. But in a ZKP, all those values should be private except the root, which would be public. So the description of this circuit must distinguish between public and private variables. 

ECLAIR calls this distinction the "allocation mode." There are four allocation modes:
1. **Constant**: values that are proper to the circuit description and never change. These are public quantities known at compilation time.

2. **Public**: values that are public but may change in each instance of the circuit. For example, the root hash of a merkle tree. These values need to be exposed to the verifier in a ZKP.
3. **Secret**: values that are private. These values are known only to the prover in a ZKP and are never revealed.
4. **Derived**: values that are a composite of some public and secret values. For example, if the above merkle tree proof were considered as a single object then its allocation mode would be derived because it consists of both private and public values.

The constant allocation mode is substantially different from the other three in that constants are known at compilation time, whereas a variable's value will not be known until execution time when an instance of the circuit is constructed. For this reason, ECLAIR uses different interfaces for allocation of constants and variables.

## Constants
The interface for allocating constants in ECLAIR is the `Constant`trait:
```rust
pub trait Constant<COM = ()> {
    /// Underlying Type
    type Type;

    /// Allocates a new constant from `this` into the `compiler`.
    fn new_constant(this: &Self::Type, compiler: &mut COM) -> Self;
}
```
So a type `T` that implements `Constant<COM>` has some "underlying type" `Type` that it represents. Given values of that underlying type, we introduce them into our circuit description using `fn new_constant`, which takes the underlying value `this`, allocates it in the `compiler`, and returns `COM`'s representation of the allocated value. We then use this output in our circuit description.

Note that ECLAIR assumes almost nothing about what it means to be a "constant"; it is up to the compiler `COM` to define how constants should be represented and manipulated. The one assumption ECLAIR does make is that constant values are known at compilation time, *i.e.* they are a fixed part of the circuit description.

## Variables
All other quantities whose values are *not* known at compilation time are considered to be "variables." ECLAIR allocates these using the `Variable` trait:
```rust
pub trait Variable<M, COM = ()> {
    /// Underlying Type
    type Type;

    /// Allocates a new unknown value into the `compiler`. The terminology "unknown" 
    /// refers to the fact that we need to allocate a slot for this variable during 
    /// compilation time, but do not yet know its underlying value.
    fn new_unknown(compiler: &mut COM) -> Self;

    /// Allocates a new known value from `this` into the `compiler`. The terminology 
    /// "known" refers to the fact that we have access to the underyling value during 
    /// execution time where we are able to use its concrete value for execution.
    fn new_known(this: &Self::Type, compiler: &mut COM) -> Self;
}
```
As with constants, variables have an underlying `Type` that they represent within `COM`. This means that some type `T` implementing `Variable<M, COM>` is a `Type`-valued variable. The generic type `M` specifies the allocation *M*ode, which can be `Public`, `Private`, or `Derived`.

As with the `Constant` allocation mode, ECLAIR makes no assumptions about what it means to be `Public`, `Private` or `Derived` in a given `COM` context. ECLAIR assumes only that a variable's value is not yet known at compilation time.

### Known *vs* Unknown Allocation
Unlike constants, there are two ways of allocating variables: as known and unknown. Allocation using `fn new_known` requires the variable's concrete value `this`. Allocation using `fn new_unknown` merely tells the `compiler` that *when execution occurs*, a value of this `Type` will go here. 

Of course execution cannot actually occur until all variables have been provided a value. Allocating variables before their values are known using `fn new_unknown` allows us to perform certain useful operations from the circuit description before execution time, akin to performing algebraic manipulations on physical formulae before substituting in concrete values for the variables.

For example, some proving systems require pre-computed prover and verifier keys. When these are circuit-specific, they must be extracted from a circuit description. Since this occurs before execution time, we need a circuit description that accounts for all of the variables without assigning them a concrete value. Therefore a description of the circuit using `fn new_unknown` to allocate variables is appropriate for computing the prover and verifier keys. At execution time, when the circuit is used to generate proofs, it is appropriate to allocate the same variables using `fn new_known`.

This suggests an important principle of circuit-writing in ECLAIR: it is generally useful to separate variable *allocation* from variable *manipulation*. That is, one should identify the variables whose values are provided as inputs, either public or private, by the prover. Then, taking those as inputs, one writes a function to describe how they are manipulated according to the circuit logic.

### Example: Merkle Tree Membership 
To illustrate this we return to the merkle tree membership example we started with above. The relevant input values are: 
- a leaf value: `leaf: L`
- the values of all sibling nodes on a path from that leaf to the root: `path: P`
- a root value: `root: R`

The first two kinds of values are private, so we require that `L: Variable<Secret, COM>` and `P: Variable<Secret, COM>`. The root value is public, so we require `R: Variable<Public, COM>`. The function that describes a merkle tree membership check would look something like this:
```rust
fn membership_check<L, P, R, COM>(leaf: L, path: P, root: R, compiler: &mut COM)
where
    L: Variable<Secret, COM>,
    P: Variable<Secret, COM>,
    R: Variable<Public, COM> {
        // hash `leaf` with its sibling
        // hash the result with the next sibling in `path`
        // ...
        // assert that final result equals `root`
}
```
The body of this function will perform computations on the input variables, allocating new intermediate variables in the process and generating constraints within `compiler`. Because we've specified that `leaf` and `path` allocate as `Secret` and `root` allocates as `Public`, the constraint generation will occur in whatever way is appropriate for dealing with public and private variables in the context of `COM`.

To extract a circuit description while leaving the variable values unknown, we might do something like this:
```rust
// Construct an instance of the compiler
let mut compiler = CompilerType::new();
// Allocate variables with unknown values
let leaf = Leaf::new_unknown(&mut compiler);
let path = Path::new_unknown(&mut compiler);
let root = Root::new_unknown(&mut compiler);
// Generate membership check constraints
membership_check(leaf, path, root, &mut compiler);
```
Now `compiler` has allocated all the intermediate variables for a membership check and generated the necessary constraints among them. We could then extract proving and verifying keys from it, or any other information that can be extracted from the circuit description without concrete values. Note that we can*not* compute a ZKP from `compiler`, since this would require concrete values for the variables.

In order to compute a ZKP in an instance where we have concrete values, we would do something like this:
```rust
// Construct an instance of the compiler
let mut compiler = CompilerType::new();
// Allocate variables with known values
let leaf = Leaf::new_known(leaf_value, &mut compiler);
let path = Path::new_known(path_value, &mut compiler);
let root = Root::new_known(root_value, &mut compiler);
// Generate membership check constraints
membership_check(leaf, path, root, &mut compiler);
// Compute proof
let proof = compiler.prove();
```
This time the compiler was able to compute a ZKP because the variables were allocated with known values. 

As mentioned above, it was useful in this example to separate allocation and manipulation. All manipulation occurs within `fn membership_check`, which takes arguments that are assumed to be already allocated in the `compiler`. This ensured that the same manipulations would be performed on the symbolic and concrete forms of these variables. 

(Of course many new variables are allocated as `fn membership_check` performs its computation, but their values are not provided directly by the prover. Perhaps it is more correct to say that one should separate variable *input* from variable manipulation.)