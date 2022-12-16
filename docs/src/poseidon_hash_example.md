# Example: Poseidon Hash

Useful cryptographic primimitives such as hash functions are built by composing smaller functions such as linear combination, permutation, exponentiation, etc. 

For example, the Poseidon Permutation [todo: cite] composes these as follows to transform a vector of inputs:

1. Add a constant to each component of the vector.
2. Raise each component of the resulting vector to a power (in a full round), or raise just one component of the vector to a power (in a partial round).
3. Multiply the resulting vector by a constant matrix.

These three operations define a full/partial "round" of permutation; these rounds are repeated to achieve a desired security level.

Thus a Poseidon permutation can be built in ECLAIR by combining three primitive operations:

- Addition of constants ("ARC", Add Round Constants)
- Exponentiation ("S-Box")
- Matrix Multiplication ("MDS")

Of course exponentiation and matrix multiplication are themselves compositions of elementary arithmetic operations that are defined in the ECLAIR Standard Library [todo link], so they have some "canonical" definition in terms of Standard Library functions. However, those canonical definitions could miss out on important optimizations specific to some ZK proving system backends. 

For example, the canonical definition of matrix multiplication is fine for an R1CS-based proving backend like Groth16 because global optimizations will inline the linear combinations to a single constraint for each row of the matrix [todo link to discussion on local/global optimizations]. But a proving backend that uses Plonk-like arithmetization does not have the same global optimizations and would generate too many constraints. For Plonk-like backends we can use local optimizations to define matrix multiplication in a way that accounts for the size of the matrix and the number of input wires to use fewer constraints.

So in ECLAIR, the signature of the `mds` function that performs matrix multiplication in a Poseidon permutation would be 
```
fn mds(
    state: &mut Vec<Field>,
    matrix: &Matrix<Field>,
    compiler: &mut COM);
```
where the type `COM` determines which ZK proving backend the function will "compile" its constraints to. So when the type `COM` determines an R1CS-based proving backend, the definition of this function can be the naive mathematical definition of matrix multiplication. When `COM` targets a Plonk-like proving backend then the definition of `mds` should account for this by chunking together the linear combinations into as few constraints as possible.

