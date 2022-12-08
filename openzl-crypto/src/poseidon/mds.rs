//! MDS Data Generation

use crate::poseidon::{
    matrix::{Matrix, MatrixOperations, SquareMatrix},
    FieldGeneration, NativeField,
};
use alloc::vec;
use core::fmt::Debug;
use openzl_util::vec::{Vec, VecExt};

/// MDS Matrix for both naive Poseidon Hash and optimized Poseidon Hash
/// For detailed descriptions, please refer to <https://hackmd.io/8MdoHwoKTPmQfZyIKEYWXQ>
/// Note: Naive and optimized Poseidon Hash does not change #constraints in Groth16.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MdsMatrices<F>
where
    F: NativeField,
{
    /// MDS Matrix for naive Poseidon Hash.
    pub m: SquareMatrix<F>,
    /// inversion of mds matrix. Used in optimzed Poseidon Hash.
    pub m_inv: SquareMatrix<F>,
    /// m_hat matrix. Used in optimized Poseidon Hash.
    pub m_hat: SquareMatrix<F>,
    /// Inversion of m_hat matrix. Used in optimized Poseidon Hash.
    pub m_hat_inv: SquareMatrix<F>,
    /// m prime matrix. Used in optimized Poseidon Hash.
    pub m_prime: SquareMatrix<F>,
    /// m double prime matrix. Used in optimized Poseidon Hash.
    pub m_double_prime: SquareMatrix<F>,
}

impl<F> MdsMatrices<F>
where
    F: Clone + NativeField,
{
    fn make_v_w(m: &SquareMatrix<F>) -> (Vec<F>, Vec<F>) {
        let v = m[0][1..].to_vec();
        let w = m.rows().skip(1).map(|column| column[0].clone()).collect();
        (v, w)
    }
}

impl<F> MdsMatrices<F>
where
    F: Clone + NativeField,
{
    fn make_prime(m: &SquareMatrix<F>) -> SquareMatrix<F> {
        SquareMatrix::new_unchecked(Matrix::new_unchecked(
            m.rows()
                .enumerate()
                .map(|(i, row)| match i {
                    0 => {
                        let mut new_row = Vec::allocate_with(row.len(), F::zero);
                        new_row[0] = F::one();
                        new_row
                    }
                    _ => {
                        let mut new_row = Vec::allocate_with(row.len(), F::zero);
                        new_row[1..].clone_from_slice(&row[1..]);
                        new_row
                    }
                })
                .collect(),
        ))
    }
}

impl<F> MdsMatrices<F>
where
    F: NativeField,
{
    /// Derives MDS matrix of size `dim*dim` and relevant things.
    pub fn new(dim: usize) -> Self
    where
        F: Clone + FieldGeneration + PartialEq,
    {
        Self::derive_mds_matrices(Self::generate_mds(dim))
    }

    /// Generates the mds matrix `m` for naive Poseidon Hash
    /// mds matrix is constructed to be symmetry so that row-major or col-major
    /// representation gives the same output.
    pub fn generate_mds(t: usize) -> SquareMatrix<F>
    where
        F: FieldGeneration,
    {
        let ys: Vec<F> = (t as u64..2 * t as u64).map(F::from_u64).collect();
        SquareMatrix::new_unchecked(Matrix::new_unchecked(
            (0..t as u64)
                .map(|x| {
                    ys.iter()
                        .map(|y| {
                            F::add(&F::from_u64(x), y)
                                .inverse()
                                .expect("`x+y` is invertible.")
                        })
                        .collect()
                })
                .collect(),
        ))
    }

    fn make_double_prime(m: &SquareMatrix<F>, m_hat_inv: &SquareMatrix<F>) -> SquareMatrix<F>
    where
        F: Clone,
    {
        let (v, w) = Self::make_v_w(m);
        let w_hat = m_hat_inv
            .mul_row_vec_at_left(&w)
            .expect("The shape of `m_hat_inv` and `w` should match.");
        SquareMatrix::new_unchecked(Matrix::new_unchecked(
            m.rows()
                .enumerate()
                .map(|(i, row)| match i {
                    0 => {
                        let mut new_row = Vec::with_capacity(row.len());
                        new_row.push(row[0].clone());
                        new_row.extend(v.clone());
                        new_row
                    }
                    _ => {
                        let mut new_row = vec![F::zero(); row.len()];
                        new_row[0] = w_hat[i - 1].clone();
                        new_row[i] = F::one();
                        new_row
                    }
                })
                .collect(),
        ))
    }

    /// Derives the mds matrices for optimized Poseidon Hash. Start from mds matrix `m` in naive Poseidon Hash.
    pub fn derive_mds_matrices(m: SquareMatrix<F>) -> Self
    where
        F: Clone + PartialEq,
    {
        let m_inv = m.inverse().expect("Derived MDS matrix is not invertible");
        let m_hat = m.minor(0, 0).expect("Expect minor matrix");
        let m_hat_inv = m_hat.inverse().expect("Derived MDS matrix is not correct");
        let m_prime = Self::make_prime(&m);
        let m_double_prime = Self::make_double_prime(&m, &m_hat_inv);
        MdsMatrices {
            m,
            m_inv,
            m_hat,
            m_hat_inv,
            m_prime,
            m_double_prime,
        }
    }
}

/// A `SparseMatrix` is specifically one of the form of M''.
/// This means its first row and column are each dense, and the interior matrix
/// (minor to the element in both the row and column) is the identity.
#[derive(Debug, Clone)]
pub struct SparseMatrix<F>
where
    F: NativeField,
{
    /// `w_hat` is the first column of the M'' matrix. It will be directly multiplied (scalar product) with a row of state elements.
    pub w_hat: Vec<F>,
    /// `v_rest` contains all but the first (already included in `w_hat`).
    pub v_rest: Vec<F>,
}

impl<F> SparseMatrix<F>
where
    F: NativeField,
{
    /// Checks if `self` is square and `self[1..][1..]` is identity.
    pub fn is_sparse(m: &SquareMatrix<F>) -> bool
    where
        F: Clone + PartialEq,
    {
        match m.minor(0, 0) {
            Some(minor_matrix) => minor_matrix.is_identity(),
            None => false,
        }
    }

    /// Generates sparse matrix from m_double_prime matrix.
    pub fn new(m_double_prime: SquareMatrix<F>) -> Option<Self>
    where
        F: Clone + PartialEq,
    {
        if !Self::is_sparse(&m_double_prime) {
            return None;
        }
        let m_double_prime = Matrix::from(m_double_prime);
        let w_hat = m_double_prime.rows().map(|r| r[0].clone()).collect();
        let v_rest = m_double_prime[0][1..].to_vec();
        Some(Self { w_hat, v_rest })
    }

    /// Size of the sparse matrix.
    pub fn size(&self) -> usize {
        self.w_hat.len()
    }

    /// Generates dense-matrix representation from sparse matrix representation.
    pub fn to_matrix(self) -> Matrix<F>
// where
    //     F: Clone,
    {
        let mut matrix = Matrix::identity(self.size());
        for (j, elem) in self.w_hat.into_iter().enumerate() {
            matrix[j][0] = elem;
        }
        for (i, elem) in self.v_rest.into_iter().enumerate() {
            matrix[0][i + 1] = elem;
        }
        matrix
    }
}

/// Factorizes `base_matrix` into sparse matrices.
pub fn factor_to_sparse_matrixes<F>(
    base_matrix: SquareMatrix<F>,
    n: usize,
) -> (SquareMatrix<F>, Vec<SparseMatrix<F>>)
where
    F: Clone + NativeField + FieldGeneration + PartialEq,
{
    let (pre_sparse, mut sparse_matrices) = (0..n).fold(
        (base_matrix.clone(), Vec::with_capacity(n)),
        |(curr, mut acc), _| {
            let derived = MdsMatrices::derive_mds_matrices(curr);
            acc.push(derived.m_double_prime);
            let new = base_matrix
                .matmul(&derived.m_prime)
                .expect("Input matrix shapes match.");
            (new, acc)
        },
    );
    sparse_matrices.reverse();
    let sparse_matrices = sparse_matrices
        .into_iter()
        .map(|sparse_matrix| {
            SparseMatrix::new(sparse_matrix).expect("Each `sparse_matrix` should be sparse.")
        })
        .collect();
    (pre_sparse, sparse_matrices)
}
