// Copyright 2019-2022 Manta Network.
// This file is part of manta-rs.
//
// manta-rs is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// manta-rs is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with manta-rs.  If not, see <http://www.gnu.org/licenses/>.

//! MDS Data Generation

use crate::poseidon::{
    matrix::{Matrix, MatrixOperations, SquareMatrix},
    Field, FieldGeneration,
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
    F: Field,
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
    F: Clone + Field,
{
    fn make_v_w(m: &SquareMatrix<F>) -> (Vec<F>, Vec<F>) {
        let v = m[0][1..].to_vec();
        let w = m.rows().skip(1).map(|column| column[0].clone()).collect();
        (v, w)
    }
}

impl<F> MdsMatrices<F>
where
    F: Clone + Field,
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
    F: Field,
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
    F: Field,
{
    /// `w_hat` is the first column of the M'' matrix. It will be directly multiplied (scalar product) with a row of state elements.
    pub w_hat: Vec<F>,
    /// `v_rest` contains all but the first (already included in `w_hat`).
    pub v_rest: Vec<F>,
}

impl<F> SparseMatrix<F>
where
    F: Field,
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
    F: Clone + Field + FieldGeneration + PartialEq,
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

/// Testing Suite
#[cfg(test)]
mod test {
    use super::*;
    use crate::poseidon::matrix::Matrix;
    // use crate::{
    //     arkworks::{
    //         bls12_381::Fr,
    //         constraint::fp::Fp,
    //         ff::{field_new, UniformRand},
    //     },
    //     rand::OsRng,
    // }; // TODO arkworks rand

    // /// Checks if creating mds matrices is correct.
    // #[test]
    // fn mds_matrices_creation_is_correct() {
    //     for i in 2..5 {
    //         check_mds_creation_on_single_width(i);
    //     }
    // }

    // fn check_mds_creation_on_single_width(width: usize) {
    //     let MdsMatrices {
    //         m,
    //         m_inv,
    //         m_hat,
    //         m_prime,
    //         m_double_prime,
    //         ..
    //     } = MdsMatrices::<Fp<Fr>>::new(width);
    //     for i in 0..m_hat.num_rows() {
    //         for j in 0..m_hat.num_columns() {
    //             assert_eq!(m[i + 1][j + 1], m_hat[i][j], "MDS minor has wrong value.");
    //         }
    //     }
    //     assert!(m_inv
    //         .matmul(&m)
    //         .expect("Input shape matches.")
    //         .is_identity());
    //     assert_eq!(
    //         m,
    //         m_prime
    //             .matmul(&m_double_prime)
    //             .expect("Input shape matches.")
    //     );
    // }

    // /// Checks if derived mds matrices are correct.
    // #[test]
    // fn derived_mds_is_correct() {
    //     let mut rng = OsRng;
    //     let width = 3;
    //     let mds = MdsMatrices::new(width);
    //     let base = (0..width)
    //         .map(|_| Fp(Fr::rand(&mut rng)))
    //         .collect::<Vec<_>>();
    //     let x = {
    //         let mut x = base.clone();
    //         x[0] = Fp(Fr::rand(&mut rng));
    //         x
    //     };
    //     let y = {
    //         let mut y = base;
    //         y[0] = Fp(Fr::rand(&mut rng));
    //         y
    //     };
    //     let qx = mds
    //         .m_prime
    //         .mul_row_vec_at_left(&x)
    //         .expect("Input shape matches");
    //     let qy = mds
    //         .m_prime
    //         .mul_row_vec_at_left(&y)
    //         .expect("Input shape matches");
    //     assert_eq!(qx[0], x[0]);
    //     assert_eq!(qy[0], y[0]);
    //     assert_eq!(qx[1..], qy[1..]);
    //     let mx = mds.m.mul_col_vec(&x).expect("Input shape matches");
    //     let m1_m2_x = mds
    //         .m_prime
    //         .mul_col_vec(
    //             &mds.m_double_prime
    //                 .mul_col_vec(&x)
    //                 .expect("Input shape matches"),
    //         )
    //         .expect("Input shape matches");
    //     assert_eq!(mx, m1_m2_x);
    //     let xm = mds.m.mul_row_vec_at_left(&x).expect("Input shape matches");
    //     let x_m1_m2 = mds
    //         .m_double_prime
    //         .mul_row_vec_at_left(
    //             &mds.m_prime
    //                 .mul_row_vec_at_left(&x)
    //                 .expect("Input shape matches"),
    //         )
    //         .expect("Input shape matches");
    //     assert_eq!(xm, x_m1_m2);
    // }

    // TODO hardcoded tests
    // /// Checks if `mds` matches hardcoded sage outputs.
    // #[test]
    // fn mds_matches_hardcoded_sage_output() {
    //     let test_cases = [
    //         (2, include!("mds_hardcoded_tests/width2")),
    //         (3, include!("mds_hardcoded_tests/width3")),
    //         (4, include!("mds_hardcoded_tests/width4")),
    //         (5, include!("mds_hardcoded_tests/width5")),
    //         (6, include!("mds_hardcoded_tests/width6")),
    //         (7, include!("mds_hardcoded_tests/width7")),
    //         (8, include!("mds_hardcoded_tests/width8")),
    //         (9, include!("mds_hardcoded_tests/width9")),
    //         (10, include!("mds_hardcoded_tests/width10")),
    //         (11, include!("mds_hardcoded_tests/width11")),
    //         (12, include!("mds_hardcoded_tests/width12")),
    //     ];
    //     for (width, matrix) in test_cases {
    //         assert_eq!(
    //             MdsMatrices::generate_mds(width),
    //             Matrix::new_unchecked(matrix)
    //         );
    //     }
    // }

    // /// Checks if mds is invertible.
    // #[test]
    // fn mds_is_invertible() {
    //     for t in 3..10 {
    //         assert!(MdsMatrices::<Fp<Fr>>::generate_mds(t).is_invertible());
    //     }
    // }

    // /// Checks if mds is symmetric.
    // #[test]
    // fn mds_is_symmetric() {
    //     for t in 3..10 {
    //         assert!(MdsMatrices::<Fp<Fr>>::generate_mds(t).is_symmetric());
    //     }
    // }
}
