# Tutorial: Poseidon Permutation

The Poseidon permutation, defined in [GKRRS '19](https://eprint.iacr.org/2019/458.pdf) operates on vectors of field elements. For a fixed width, the permutation transforms a vector of `width`-many field elements in repeated rounds. Each round consists of the following operations:

1. **Add Round Keys**: Add a constant to each component of the vector.
2. **S-Box**: Raise each component of the resulting vector to a power (in a full round), or raise just one component of the vector to a power (in a partial round).
3. **MDS Matrix**: Multiply the resulting vector by a constant matrix.

This tutorial will walk through building the Poseidon permutation in ECLAIR. All OpenZL tutorials are accompanied by code examples, see [here](https://github.com/openzklib). (TODO: Real link) Note that this code differs somewhat from our [optimized Poseidon implementation](https://github.com/openzklib). (TODO: Real link)

### trait `Specification`
The Poseidon permutation requires a choice of finite field. We will keep this example generic by using a Rust trait `Specification` to specify our assumptions on the field and defining the Poseidon permutation relative to any type that implements `Specification`.
```rust
/// Poseidon Specification
///
/// This trait defines basic arithmetic operations we use to define the Poseidon permutation.
pub trait Specification<COM = ()>: Constants {
    /// Field Type used for Permutation State
    type Field;

    /// Field Type used for Permutation Parameters
    type ParameterField;

    /// Returns the zero element of the field.
    fn zero(compiler: &mut COM) -> Self::Field;

    /// Adds two field elements together.
    fn add(lhs: &Self::Field, rhs: &Self::Field, compiler: &mut COM) -> Self::Field;

    /// Adds a field element `lhs` with a constant `rhs`
    fn add_const(lhs: &Self::Field, rhs: &Self::ParameterField, compiler: &mut COM) -> Self::Field;

    /// Multiplies two field elements together.
    fn mul(lhs: &Self::Field, rhs: &Self::Field, compiler: &mut COM) -> Self::Field;

    /// Multiplies a field element `lhs` with a constant `rhs`
    fn mul_const(lhs: &Self::Field, rhs: &Self::ParameterField, compiler: &mut COM) -> Self::Field;

    /// Adds the `rhs` field element to `lhs` field element, updating the value in `lhs`
    fn add_assign(lhs: &mut Self::Field, rhs: &Self::Field, compiler: &mut COM);

    /// Adds the `rhs` constant to `lhs` field element, updating the value in `lhs`
    fn add_const_assign(lhs: &mut Self::Field, rhs: &Self::ParameterField, compiler: &mut COM);

    /// Applies the S-BOX to `point`.
    fn apply_sbox(point: &mut Self::Field, compiler: &mut COM);

    /// Converts a constant parameter `point` for permutation state.
    fn from_parameter(point: Self::ParameterField) -> Self::Field;
}
```
The trait requires two types, `Field` and `ParameterField`. The permutation acts on vectors of elements of type `Field`. The constant parameters that define the permutation are of type `ParameterField`. At first it may seem strange to distinguish between these two types, since they coincide for native computation of the Poseidon permutation. But remember that one of the reasons to use ECLAIR is to specify computation in a language that applies to both [*native and non-native* computation](./native_nonnative.md).

In practice we may need to compute Poseidon in-circuit as part of a ZK-proof. In this case the type `Field` would be some representation of private witnesses to the circuit, whereas `ParameterField` would be public input constants. These are quite different types indeed! Therefore it is appropriate to treat them as distinct for now and let the `compiler` deal with them in whatever way is appropriate for the mode of computation specified by the type `COM`.

Keeping in mind that the `Field` type may represent in-circuit variables, it is easy to see that we need two distinct notions of `add` (and `mul`). When adding two in-circuit variables we use
```rust
fn add(lhs: &Self::Field, rhs: &Self::Field, compiler: &mut COM) -> Self::Field;
```
but when adding a constant to a variable it is appropriate to use
```rust
fn add_const(lhs: &Self::Field, rhs: &Self::ParameterField, compiler: &mut COM) -> Self::Field;
```
Although these two methods coincide for the native compiler type `COM = ()`, in general they are distinct. This illustrates an important principle of circuit writing in ECLAIR: We describe circuits in a general language that applies to all modes of computation; this ensures that different instances of computation (native/in-circuit) agree. Often it is useful to keep the more "exotic" case of in-circuit computation in mind.

Note that we specify the default compiler type to be `COM = ()`, meaning that by default we use the native compiler.

### trait `Constants`
You may notice that the previous trait `Specification` extends a trait `Constants`. `Constants` is a trait specifying three constant parameters that belong to the definition of a Poseidon permutation:
```rust
pub trait Constants {
    /// Width of the Permutation
    ///
    /// This number is the total number `t` of field elements in the state which is `F^t`.
    const WIDTH: usize;

    /// Number of Full Rounds
    ///
    /// The total number of full rounds in the Poseidon permutation, including the first set of full
    /// rounds and then the second set after the partial rounds.
    const FULL_ROUNDS: usize;

    /// Number of Partial Rounds
    const PARTIAL_ROUNDS: usize;

    /// Half Number of Full Rounds
    ///
    /// Poseidon Hash first has [`HALF_FULL_ROUNDS`]-many full rounds in the beginning,
    /// followed by [`PARTIAL_ROUNDS`]-many partial rounds in the middle, and finally
    /// [`HALF_FULL_ROUNDS`]-many full rounds at the end.
    ///
    /// [`HALF_FULL_ROUNDS`]: Self::HALF_FULL_ROUNDS
    /// [`PARTIAL_ROUNDS`]: Constants::PARTIAL_ROUNDS
    const HALF_FULL_ROUNDS: usize = Self::FULL_ROUNDS / 2;

    /// Total Number of Rounds
    const ROUNDS: usize = Self::FULL_ROUNDS + Self::PARTIAL_ROUNDS;

    /// Number of Entries in the MDS Matrix
    const MDS_MATRIX_SIZE: usize = Self::WIDTH * Self::WIDTH;

    /// Total Number of Additive Rounds Keys
    const ADDITIVE_ROUND_KEYS_COUNT: usize = Self::ROUNDS * Self::WIDTH;
}
```
Here `WIDTH` is the length of the vector of field elements that the permutation acts on via addition and matrix multiplication. `FULL_ROUNDS` and `PARTIAL_ROUNDS` specify the number of full and partial rounds of iteration that are performed on the state vector to achieve the desired security level. The remaining constants are computed in terms of the first three; they specify the number of "Additive Round Keys" and the size of the "MDS Matrix."

### struct `State`
Given some type `S` that implements the above `Specification` trait we next define a state for the permutation to act on. This state is a vector of length `WIDTH`. We'll use a struct `State` to represent it:
```rust
/// The state vector that a Poseidon permutation acts on.
pub struct State<S, COM = ()>(Box<[S::Field]>)
where
    S: Specification<COM>;

impl<S, COM> State<S, COM>
where
    S: Specification<COM>,
{
    /// Builds a new [`State`] from `state`.
    pub fn new(state: Box<[S::Field]>) -> Self {
        assert_eq!(state.len(), S::WIDTH);
        Self(state)
    }

    /// Returns a slice iterator over the state.
    pub fn iter(&self) -> slice::Iter<S::Field> {
        self.0.iter()
    }

    /// Returns a mutable slice iterator over the state.
    pub fn iter_mut(&mut self) -> slice::IterMut<S::Field> {
        self.0.iter_mut()
    }
}
```
Observe that although the compiler type `COM` plays no direct role in the definition of the `State` vector, it must be mentioned because it provides the context to understand the trait `Specification<COM>`. When `COM` specifies some ZK proof system to compute the permutation in, the elements of `State` will represent witness variables and the operations performed on `State` will generate constraints in whatever representation `COM` specifies. Again we have the default `COM = ()`, meaning that when no compiler type is specified `State` consists of native field elements and the operations performed on it are computed natively.

For Rust-related reasons we choose not to specify the width as part of `State`'s type. Observe however that the constructor `fn new` enforces that `State` must have the size specified by `S` via the `Constants` trait.

### struct `Permutation`
The final ingredient is the parameters, a collection of constants that define a particular instance of the Poseidon permutation. In each round the permutation adds some constants, the `additive_round_keys`, to the `State` and multiplies the `State` by a constant matrix, the `mds_matrix`. These pre-computed constants are considered to be part of the definition of a Poseidon permutation. For information on generating secure constants, please refer to [GKRRS '19](https://eprint.iacr.org/2019/458.pdf).

Since these parameters define a specific instance of the Poseidon implementation, we call this struct `Permutation`. We define the `Permutation` to be generic over a type `S` that implements `Specification`:
```rust
/// The constant parameters defining a particular instance
/// of the Poseidon permutation.
pub struct Permutation<S, COM = ()>
where
    S: Specification<COM>,
{
    /// Additive Round Keys
    additive_round_keys: Box<[S::ParameterField]>,

    /// MDS Matrix
    mds_matrix: Box<[S::ParameterField]>,

    /// Type Parameter Marker
    __: PhantomData<COM>,
}
```
The `additive_round_keys` can be thought of as a list of constants from `F::ParameterField`, whereas the `mds_matrix` should be thought of as a matrix; this struct carries the flattening of that matrix.  The sizes of these arrays are determined by the same `WIDTH` parameter that determines the length of `State`. Again, we enforce these size constraints with the constructor rather than the type system:
```rust
impl<S, COM> Permutation<S, COM>
where
    S: Specification<COM>,
{
    /// Builds a new [`Permutation`] from `additive_round_keys` and `mds_matrix`.
    ///
    /// # Panics
    ///
    /// This method panics if the input vectors are not the correct size for the specified
    /// [`Specification`].
    pub fn new(
        additive_round_keys: Box<[S::ParameterField]>,
        mds_matrix: Box<[S::ParameterField]>,
    ) -> Self {
        assert_eq!(
            additive_round_keys.len(),
            S::ADDITIVE_ROUND_KEYS_COUNT,
            "Additive Rounds Keys are not the correct size."
        );
        assert_eq!(
            mds_matrix.len(),
            S::MDS_MATRIX_SIZE,
            "MDS Matrix is not the correct size."
        );
        Self {
            additive_round_keys,
            mds_matrix,
            __: PhantomData,
        }
    }
}
```

### `fn full_round`, `fn partial_round`
A full round of permutation begins by adding the next `WIDTH`-many additive round keys to the `State` vector, then applying the "S-box" to each entry of the vector. Observe that the S-box operation is part of the `Specification` trait, `fn apply_sbox`. This operation on field elements is typically exponentiation to the power 3, 5, or -1.

A partial round of permutation also adds the next `WIDTH`-many additive round keys to the `State` vector, but then applies the S-box only to *first* element of this vector. The reason for mixing full and partial rounds is explained in [GKRRS '19](https://eprint.iacr.org/2019/458.pdf).

Both rounds finish by applying the MDS Matrix to the `State` vector. Let's add these methods to the `Permutation`:
```rust
impl<S, COM> Permutation<S, COM>
where
    S: Specification<COM>,
{
    /// Returns the additive keys for the given `round`.
    #[inline]
    pub fn additive_keys(&self, round: usize) -> &[S::ParameterField] {
        let start = round * S::WIDTH;
        &self.additive_round_keys[start..start + S::WIDTH]
    }

    /// Computes the MDS matrix multiplication against the `state`.
    pub fn mds_matrix_multiply(&self, state: &mut State<S, COM>, compiler: &mut COM) {
        let mut next = Vec::with_capacity(S::WIDTH);
        for i in 0..S::WIDTH {
            let linear_combination = state
                .iter()
                .enumerate()
                .map(|(j, elem)| S::mul_const(elem, &self.mds_matrix[S::WIDTH * i + j], compiler))
                .collect::<Vec<_>>();
            next.push(
                linear_combination
                    .into_iter()
                    .reduce(|acc, next| S::add(&acc, &next, compiler))
                    .unwrap(),
            );
        }
        mem::swap(&mut next.into_boxed_slice(), &mut state.0);
    }

    /// Computes a full round at the given `round` index on the internal permutation `state`.
    pub fn full_round(&self, round: usize, state: &mut State<S, COM>, compiler: &mut COM) {
        let keys = self.additive_keys(round);
        for (i, elem) in state.iter_mut().enumerate() {
            S::add_const_assign(elem, &keys[i], compiler);
            S::apply_sbox(elem, compiler);
        }
        self.mds_matrix_multiply(state, compiler);
    }

    /// Computes a partial round at the given `round` index on the internal permutation `state`.
    pub fn partial_round(&self, round: usize, state: &mut State<S, COM>, compiler: &mut COM) {
        let keys = self.additive_keys(round);
        for (i, elem) in state.iter_mut().enumerate() {
            S::add_const_assign(elem, &keys[i], compiler);
        }
        S::apply_sbox(&mut state.0[0], compiler);
        self.mds_matrix_multiply(state, compiler);
    }
}
```
Note that `fn full_round` and `fn partial_round` take the round number as an input; this is so that they will take correct constants for the given round. Note that they also take the `compiler` as an input. As we explained above, this enables these functions to generate constraints within the ZK proof system specified by the type `COM`. For example, when adding round constants the `add_const_assign` method will add a constraint to `compiler` that enforces the addition of a public constant to the secret witness. Similarly, `fn mds_matrix_multiply` generates constraints within `compiler` to enforce that `state` was multiplied by the MDS Matrix.

Again, when no `COM` type is specified the default `COM = ()` simply performs native computation without any constraint generation. The advantage of ECLAIR's `COM` abstraction is the certainty that `add_const_assign` or `mds_matrix_multiply` always conform to the same definition whether they are being used in native or non-native computation. 

### Putting it all Together: `fn permute`
Finally we combine the pieces to define the full permutation:
```rust
impl<S, COM> Permutation<S, COM>
where
    S: Specification<COM>,
{
    /// Computes the full permutation without the first round.
    fn permute(&self, state: &mut State<S, COM>, compiler: &mut COM) {
        for round in 0..S::HALF_FULL_ROUNDS {
            self.full_round(round, state, compiler);
        }
        for round in S::HALF_FULL_ROUNDS..(S::HALF_FULL_ROUNDS + S::PARTIAL_ROUNDS) {
            self.partial_round(round, state, compiler);
        }
        for round in (S::HALF_FULL_ROUNDS + S::PARTIAL_ROUNDS)..(S::FULL_ROUNDS + S::PARTIAL_ROUNDS)
        {
            self.full_round(round, state, compiler);
        }
    }
}
```
This function simply performs as many partial and full rounds as specified in the `Constants` trait.