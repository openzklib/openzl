# Native *vs* Non-Native Computation

ECLAIR aims to unify and simplify the development of ZK applications by providing a circuit language that can target a myriad of zero knowledge proof systems. In doing so it treats each ZK proof system as its own *computational environment.* Much as Rust source code can be compiled to executables for Linux, MacOS, or Windows, a circuit written in ECLAIR can target implementations of Groth16, Plonk-like proving systems, or any other proving backend for which an appropriate plugin exists.

In this framework it is useful to distinguish between "native" and "non-native" computational environments. "Native computation" is the everyday sort of computation that simply concerns itself with executing instructions on computer hardware; it produces no ZKP to attest to the computation's correctness. This is what computers do natively.

In ECLAIR, native computation is treated on an equal footing with other computational environments that *do* produce ZKPs of a computation's correctness. These are collectively referred to as "non-native computation." A proving system such as [Groth16](https://eprint.iacr.org/2016/260.pdf) is a non-native computational environment which provides a proof of correctness for any computation that can be represented as an arithmetic circuit. Likewise there are a variety of "Plonk-like" proving systems that achieve the same goal of performing a computation and providing a succincy argument of its correctness.

Given the variety of non-native computational environments and the current rate of innovation in ZK proving systems, it is desirable to describe circuits in a *proving system agnostic* representation like ECLAIR. The main advantages of doing so are:
- **Agility**: A circuit described in ECLAIR can target any proving system via plugins. Thus a developer can quickly switch the proving system used in their ZK app according to their needs. When the next hot new ZK proving system is discovered, a new plugin allows any existing ECLAIR circuits to target that proving system.
- **Correctness**: Computation described in ECLAIR is performed the same way in all computational environments, native or non-native. This gives developers confidence that computations performed within a ZK proving system match their native version.

## The `COM` Abstraction

As explained above, a computation described in ECLAIR can be carried out in various native or non-native computational environments. The computational environment is specified by choosing a type `COM`, short for "compiler."

We think of `COM` as a compiler that takes instructions written in ECLAIR and translates them to instructions for the target computational environment. In the case of native computation, `COM` would compile ECLAIR circuits to machine code for manipulating computer hardware. In the case of non-native computation, `COM` would compile ECLAIR circuits to a constraint representation such as R1CS for ZK proof generation.

For example, consider a trait `Add` that consists of a single function `fn add` for adding like types. Ordinarily, the signature of this function would be
```rust
fn add(lhs: Self, rhs: Self) -> Self
```
But in ECLAIR, we include a generic type `COM` to define a trait `Add<COM>` for addition in an arbitrary computational environment. The signature of `fn add` becomes
```rust
fn add(lhs: Self, rhs: Self, compiler: &mut COM) -> Self
```
In an ECLAIR circuit we may see a line like
```rust
output = add(lhs, rhs, &mut compiler);
```
In the case of non-native computation, this results in a constraint being added to enforce `output = lhs + rhs` in whatever constraint system is appropriate to that computational environment. A circuit that uses addition via the `Add<COM>` trait now can be compiled to any proving system for which we have an implementation of `Add<COM>`.

### The Native Compiler Default `COM = ()`
In native computation there is no correctness proof and therefore no constraints for the compiler to generate. Thus we have defined the unit type `()` to represent the native compiler. We generally specify traits to use the native compiler by default, such as `Add<COM = ()>`. This means that unless a ZK proving system is specified by choosing some other type for `COM`, the computation will be carried out natively. When writing ECLAIR code which is intended for native computation only, we still need to include the `compiler` argument in function signatures. For native-only computation this looks like
```rust
output = add(lhs, rhs, &mut ());
```
