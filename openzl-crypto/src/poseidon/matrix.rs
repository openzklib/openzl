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

//! Basic Linear Algebra Implementations

use crate::poseidon::Field;
use core::{
    fmt::Debug,
    ops::{Deref, Index, IndexMut},
    slice,
};
use openzl_util::vec::{Vec, VecExt};

/// Allocates a matrix of shape `(num_rows, num_columns)` where `allocate_row` generates default
/// values.
#[inline]
pub fn allocate_matrix<T, F>(
    num_rows: usize,
    num_columns: usize,
    mut allocate_row: F,
) -> Vec<Vec<T>>
where
    F: FnMut(usize) -> Vec<T>,
{
    Vec::allocate_with(num_rows, || allocate_row(num_columns))
}

/// Allocates a square matrix of shape `(size, size)` where `allocate_row` generates default values.
#[inline]
pub fn allocate_square_matrix<T, F>(size: usize, allocate_row: F) -> Vec<Vec<T>>
where
    F: FnMut(usize) -> Vec<T>,
{
    allocate_matrix(size, size, allocate_row)
}

/// Trait for matrix operations.
pub trait MatrixOperations {
    /// Scalar field.
    type Scalar;

    /// Assumes matrix is partially reduced to upper triangular. `column` is the
    /// column to eliminate from all rows. Returns `None` if either:
    ///   - no non-zero pivot can be found for `column`
    ///   - `column` is not the first
    fn eliminate(&self, column: usize, shadow: &mut Self) -> Option<Self>
    where
        Self: Sized,
        Self::Scalar: Clone + PartialEq;

    /// Returns an identity matrix of size `n*n`.
    fn identity(n: usize) -> Self;

    /// Multiplies matrix `self` with matrix `other` on the right side.
    fn matmul(&self, other: &Self) -> Option<Self>
    where
        Self: Sized,
        Self::Scalar: Clone;

    /// Elementwisely multiplies with `scalar`.
    fn mul_by_scalar(&self, scalar: Self::Scalar) -> Self;

    /// Returns row major representation of the matrix.
    fn to_row_major(self) -> Vec<Self::Scalar>;

    /// Returns the transpose of the matrix.
    fn transpose(self) -> Self;
}

/// Row Major Matrix Representation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Matrix<F>(Vec<Vec<F>>)
where
    F: Field;

impl<F> Matrix<F>
where
    F: Field,
{
    /// Constructs a non-empty [`Matrix`] returning `None` if `v` is empty or has the wrong shape
    /// for a matrix.
    #[inline]
    pub fn new(v: Vec<Vec<F>>) -> Option<Self> {
        if v.is_empty() {
            return None;
        }
        let first_row_length = v[0].len();
        if first_row_length == 0 {
            return None;
        }
        for row in &v {
            if row.len() != first_row_length {
                return None;
            }
        }
        Some(Self(v))
    }

    /// Builds a new [`Matrix`] without checking `v` is a valid matrix.
    #[inline]
    pub fn new_unchecked(v: Vec<Vec<F>>) -> Self {
        Self(v)
    }

    /// Returns an iterator over a specific column.
    #[inline]
    pub fn column(&self, column: usize) -> impl Iterator<Item = &'_ F> {
        self.0.iter().map(move |row| &row[column])
    }

    /// Checks if the matrix is square.
    #[inline]
    pub fn is_square(&self) -> bool {
        self.num_rows() == self.num_columns()
    }

    /// Checks if the matrix is an identity matrix.
    #[inline]
    pub fn is_identity(&self) -> bool
    where
        F: PartialEq,
    {
        if !self.is_square() {
            return false;
        }
        for (i, element) in self.0.iter().enumerate() {
            for (j, inner_element) in element.iter().enumerate() {
                if *inner_element != kronecker_delta(i, j) {
                    return false;
                }
            }
        }
        true
    }

    /// Checks if the matrix is symmetric.
    #[inline]
    pub fn is_symmetric(&self) -> bool
    where
        F: PartialEq,
    {
        if self.num_rows() != self.num_columns() {
            return false;
        }
        for (i, element) in self.0.iter().enumerate() {
            for (j, inner_element) in element.iter().enumerate().skip(i + 1) {
                if inner_element != &self.0[j][i] {
                    return false;
                }
            }
        }
        true
    }

    /// Returns an iterator over rows.
    #[inline]
    pub fn rows(&self) -> slice::Iter<Vec<F>> {
        self.0.iter()
    }

    /// Returns the number of rows.
    #[inline]
    pub fn num_rows(&self) -> usize {
        self.0.len()
    }

    /// Returns the number of columns.
    #[inline]
    pub fn num_columns(&self) -> usize {
        self.0[0].len()
    }

    /// Multiplies matrix `self` with column vector `vec` on the-right hand side.
    #[inline]
    pub fn mul_col_vec(&self, v: &[F]) -> Option<Vec<F>> {
        if self.num_rows() != v.len() {
            return None;
        }
        Some(
            self.rows()
                .map(|row| {
                    row.iter()
                        .zip(v)
                        .fold(F::zero(), |acc, (r, v)| F::add(&acc, &F::mul(r, v)))
                })
                .collect(),
        )
    }

    /// Multiplies matrix `self` with row vector `vec` on the left-hand side.
    #[inline]
    pub fn mul_row_vec_at_left(&self, v: &[F]) -> Option<Vec<F>> {
        if self.num_rows() != v.len() {
            return None;
        }
        Some(
            (0..v.len())
                .map(|j| {
                    self.0
                        .iter()
                        .zip(v)
                        .fold(F::zero(), |acc, (row, v)| F::add(&acc, &F::mul(v, &row[j])))
                })
                .collect(),
        )
    }
}

impl<F> From<SquareMatrix<F>> for Matrix<F>
where
    F: Field,
{
    #[inline]
    fn from(matrix: SquareMatrix<F>) -> Self {
        matrix.0
    }
}

impl<F> Index<usize> for Matrix<F>
where
    F: Field,
{
    type Output = Vec<F>;

    #[inline]
    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

impl<F> IndexMut<usize> for Matrix<F>
where
    F: Field,
{
    #[inline]
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.0[index]
    }
}

impl<F> MatrixOperations for Matrix<F>
where
    F: Field,
{
    type Scalar = F;

    #[inline]
    fn eliminate(&self, column: usize, shadow: &mut Self) -> Option<Self>
    where
        Self::Scalar: Clone + PartialEq,
    {
        let zero = F::zero();
        let (pivot_index, pivot) = self.0.iter().enumerate().find(|(_, row)| {
            (!F::eq(&row[column], &zero)) && (0..column).all(|j| F::eq(&row[j], &zero))
        })?;
        let inv_pivot = F::inverse(&pivot[column])
            .expect("This should never fail since we have a non-zero `pivot_val` if we got here.");
        let mut result = Vec::with_capacity(self.num_rows());
        result.push(pivot.clone());
        for (i, row) in self.rows().enumerate() {
            if i == pivot_index {
                continue;
            };
            let val = &row[column];
            if F::eq(val, &zero) {
                result.push(row.to_vec());
            } else {
                let factor = F::mul(val, &inv_pivot);
                result.push(eliminate_row(row, &factor, pivot));
                shadow[i] = eliminate_row(&shadow[i], &factor, &shadow[pivot_index]);
            }
        }
        let pivot_row = shadow.0.remove(pivot_index);
        shadow.0.insert(0, pivot_row);
        Some(Self(result))
    }

    #[inline]
    fn identity(n: usize) -> Self {
        let mut identity_matrix = allocate_square_matrix(n, |n| Vec::allocate_with(n, F::zero));
        for (i, row) in identity_matrix.iter_mut().enumerate() {
            row[i] = F::one();
        }
        Self(identity_matrix)
    }

    #[inline]
    fn to_row_major(self) -> Vec<F> {
        let mut row_major_repr = Vec::with_capacity(self.num_rows() * self.num_columns());
        for mut row in self.0 {
            row_major_repr.append(&mut row);
        }
        row_major_repr
    }

    #[inline]
    fn matmul(&self, other: &Self) -> Option<Self>
    where
        Self::Scalar: Clone,
    {
        if self.num_rows() != other.num_columns() {
            return None;
        };
        let other_transpose = other.clone().transpose();
        Some(Self(
            self.rows()
                .map(|input_row| {
                    other_transpose
                        .rows()
                        .map(|transposed_column| inner_product(input_row, transposed_column))
                        .collect()
                })
                .collect(),
        ))
    }

    #[inline]
    fn mul_by_scalar(&self, scalar: F) -> Self {
        Self(
            self.0
                .iter()
                .map(|row| row.iter().map(|val| F::mul(&scalar, val)).collect())
                .collect(),
        )
    }

    #[inline]
    fn transpose(self) -> Self {
        let mut transposed_matrix =
            allocate_matrix(self.num_columns(), self.num_rows(), Vec::with_capacity);
        for row in self.0 {
            for (j, elem) in row.into_iter().enumerate() {
                transposed_matrix[j].push(elem);
            }
        }
        Self(transposed_matrix)
    }
}

impl<F> PartialEq<SquareMatrix<F>> for Matrix<F>
where
    F: Field + PartialEq,
{
    #[inline]
    fn eq(&self, other: &SquareMatrix<F>) -> bool {
        self.eq(&other.0)
    }
}

/// Row Major Matrix Representation with Square Shape.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SquareMatrix<F>(Matrix<F>)
where
    F: Field;

impl<F> SquareMatrix<F>
where
    F: Field,
{
    /// Returns a new [`SquareMatrix`] representation of `m` if it returns `true` to
    /// [`is_square`](Matrix::is_square).
    #[inline]
    pub fn new(m: Matrix<F>) -> Option<Self> {
        m.is_square().then_some(Self::new_unchecked(m))
    }

    /// Builds a new [`SquareMatrix`] without checking whether `m` is a valid square matrix.
    #[inline]
    pub fn new_unchecked(m: Matrix<F>) -> Self {
        Self(m)
    }

    /// Returns the inversion of a matrix.
    #[inline]
    pub fn inverse(&self) -> Option<Self>
    where
        F: Clone + PartialEq,
    {
        let mut shadow = Self::identity(self.num_rows());
        self.upper_triangular(&mut shadow)?
            .reduce_to_identity(&mut shadow)?;
        Some(shadow)
    }

    /// Checks if the matrix is invertible.
    #[inline]
    pub fn is_invertible(&self) -> bool
    where
        F: Clone + PartialEq,
    {
        self.inverse().is_some()
    }

    /// Generates the `(i, j)` minor matrix by removing the `i`th row and `j`th column of `self`.
    #[inline]
    pub fn minor(&self, i: usize, j: usize) -> Option<Self>
    where
        F: Clone,
    {
        let size = self.num_rows();
        if size <= 1 {
            return None;
        }
        Some(Self(Matrix(
            self.0
                 .0
                .iter()
                .enumerate()
                .filter_map(|(ii, row)| {
                    if ii == i {
                        None
                    } else {
                        let mut row = row.clone();
                        row.remove(j);
                        Some(row)
                    }
                })
                .collect(),
        )))
    }

    /// Reduces an upper triangular matrix `self.0` to an identity matrix. This function applies the
    /// same computation on `shadow` matrix as `self.0`.
    #[inline]
    fn reduce_to_identity(&self, shadow: &mut Self) -> Option<Self>
    where
        F: Clone,
    {
        let size = self.num_rows();
        let mut result: Vec<Vec<F>> = Vec::with_capacity(size);
        let mut shadow_result: Vec<Vec<F>> = Vec::with_capacity(size);
        for i in 0..size {
            let idx = size - i - 1;
            let row = &self.0[idx];
            let inv = F::inverse(&row[idx])?;
            let mut normalized = scalar_vec_mul(&inv, row);
            let mut shadow_normalized = scalar_vec_mul(&inv, &shadow[idx]);
            for j in 0..i {
                let idx = size - j - 1;
                shadow_normalized = vec_sub(
                    &shadow_normalized,
                    &scalar_vec_mul(&normalized[idx], &shadow_result[j]),
                );
                normalized = vec_sub(&normalized, &scalar_vec_mul(&normalized[idx], &result[j]));
            }
            result.push(normalized);
            shadow_result.push(shadow_normalized);
        }
        result.reverse();
        shadow_result.reverse();
        *shadow = Self(Matrix(shadow_result));
        Some(Self(Matrix(result)))
    }

    /// Generates the upper triangular matrix such that `self[i][j]` = 0 for all `j`>`i`.
    #[inline]
    fn upper_triangular(&self, shadow: &mut Self) -> Option<Self>
    where
        F: Clone + PartialEq,
    {
        let size = self.num_rows();
        let mut result = Vec::with_capacity(size);
        let mut shadow_result = Vec::with_capacity(size);
        let mut current = self.0.clone();
        let mut shadow_matrix = shadow.0.clone();
        for column in 0..(size - 1) {
            current = current.eliminate(column, &mut shadow_matrix)?;
            result.push(current.0.remove(0));
            shadow_result.push(shadow_matrix.0.remove(0));
        }
        result.push(current.0.take_first());
        shadow_result.push(shadow_matrix.0.take_first());
        *shadow = Self(Matrix(shadow_result));
        Some(Self(Matrix(result)))
    }
}

impl<F> AsRef<Matrix<F>> for SquareMatrix<F>
where
    F: Field,
{
    #[inline]
    fn as_ref(&self) -> &Matrix<F> {
        &self.0
    }
}

impl<F> Deref for SquareMatrix<F>
where
    F: Field,
{
    type Target = Matrix<F>;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<F> PartialEq<Matrix<F>> for SquareMatrix<F>
where
    F: Field + PartialEq,
{
    #[inline]
    fn eq(&self, other: &Matrix<F>) -> bool {
        self.0.eq(other)
    }
}

impl<F> MatrixOperations for SquareMatrix<F>
where
    F: Field,
{
    type Scalar = F;

    #[inline]
    fn eliminate(&self, column: usize, shadow: &mut Self) -> Option<Self>
    where
        Self::Scalar: Clone + PartialEq,
    {
        self.0.eliminate(column, &mut shadow.0).map(Self)
    }

    #[inline]
    fn identity(n: usize) -> Self {
        Self(Matrix::identity(n))
    }

    #[inline]
    fn matmul(&self, other: &Self) -> Option<Self>
    where
        Self::Scalar: Clone,
    {
        self.0.matmul(&other.0).map(Self)
    }

    #[inline]
    fn mul_by_scalar(&self, scalar: Self::Scalar) -> Self {
        Self(self.0.mul_by_scalar(scalar))
    }

    #[inline]
    fn to_row_major(self) -> Vec<F> {
        self.0.to_row_major()
    }

    #[inline]
    fn transpose(self) -> Self {
        Self(self.0.transpose())
    }
}

/// Computes the inner product of vector `a` and `b`.
#[inline]
pub fn inner_product<F>(a: &[F], b: &[F]) -> F
where
    F: Field,
{
    a.iter()
        .zip(b)
        .fold(F::zero(), |acc, (v1, v2)| F::add(&acc, &F::mul(v1, v2)))
}

/// Adds two vectors elementwise (i.e., `out[i] = a[i] + b[i]`).
#[inline]
pub fn vec_add<F>(a: &[F], b: &[F]) -> Vec<F>
where
    F: Field,
{
    a.iter().zip(b).map(|(a, b)| F::add(a, b)).collect()
}

/// Subtracts two vectors elementwise (i.e., `out[i] = a[i] - b[i]`).
#[inline]
pub fn vec_sub<F>(a: &[F], b: &[F]) -> Vec<F>
where
    F: Field,
{
    a.iter().zip(b.iter()).map(|(a, b)| F::sub(a, b)).collect()
}

/// Multiplies a vector `v` with `scalar` elementwise (i.e., `out[i] = scalar * v[i]`).
#[inline]
pub fn scalar_vec_mul<F>(scalar: &F, v: &[F]) -> Vec<F>
where
    F: Field,
{
    v.iter().map(|val| F::mul(scalar, val)).collect()
}

/// Eliminates `row` with `factor` multiplied by the `pivot`.
#[inline]
fn eliminate_row<F>(row: &[F], factor: &F, pivot: &[F]) -> Vec<F>
where
    F: Field,
{
    vec_sub(row, &scalar_vec_mul(factor, pivot))
}

/// Returns the kronecker delta of `i` and `j`.
#[inline]
pub fn kronecker_delta<F>(i: usize, j: usize) -> F
where
    F: Field,
{
    if i == j {
        F::one()
    } else {
        F::zero()
    }
}

/// Testing Suite
#[cfg(test)]
mod test {
    use super::*;
    // use manta_crypto::arkworks::{bls12_381::Fr, constraint::fp::Fp}; // TODO

    // /// Checks if generating minor matrix is correct.
    // #[test]
    // fn minor_is_correct() {
    //     let one = Fp(Fr::from(1u64));
    //     let two = Fp(Fr::from(2u64));
    //     let three = Fp(Fr::from(3u64));
    //     let four = Fp(Fr::from(4u64));
    //     let five = Fp(Fr::from(5u64));
    //     let six = Fp(Fr::from(6u64));
    //     let seven = Fp(Fr::from(7u64));
    //     let eight = Fp(Fr::from(8u64));
    //     let nine = Fp(Fr::from(9u64));
    //     let matrix = SquareMatrix::new_unchecked(Matrix::new_unchecked(vec![
    //         vec![one, two, three],
    //         vec![four, five, six],
    //         vec![seven, eight, nine],
    //     ]));
    //     let cases = [
    //         (
    //             0,
    //             0,
    //             Matrix::new_unchecked(vec![vec![five, six], vec![eight, nine]]),
    //         ),
    //         (
    //             0,
    //             1,
    //             Matrix::new_unchecked(vec![vec![four, six], vec![seven, nine]]),
    //         ),
    //         (
    //             0,
    //             2,
    //             Matrix::new_unchecked(vec![vec![four, five], vec![seven, eight]]),
    //         ),
    //         (
    //             1,
    //             0,
    //             Matrix::new_unchecked(vec![vec![two, three], vec![eight, nine]]),
    //         ),
    //         (
    //             1,
    //             1,
    //             Matrix::new_unchecked(vec![vec![one, three], vec![seven, nine]]),
    //         ),
    //         (
    //             1,
    //             2,
    //             Matrix::new_unchecked(vec![vec![one, two], vec![seven, eight]]),
    //         ),
    //         (
    //             2,
    //             0,
    //             Matrix::new_unchecked(vec![vec![two, three], vec![five, six]]),
    //         ),
    //         (
    //             2,
    //             1,
    //             Matrix::new_unchecked(vec![vec![one, three], vec![four, six]]),
    //         ),
    //         (
    //             2,
    //             2,
    //             Matrix::new_unchecked(vec![vec![one, two], vec![four, five]]),
    //         ),
    //     ];
    //     for (i, j, expected) in &cases {
    //         let result = matrix
    //             .minor(*i, *j)
    //             .expect("A matrix of shape 3x3 should be able to generate minor matrices.");
    //         assert_eq!(expected, &result);
    //     }
    // }

    // /// Checks if scalar multiplication is correct.
    // #[test]
    // fn scalar_mul_is_correct() {
    //     let zero = Fp(Fr::from(0u64));
    //     let one = Fp(Fr::from(1u64));
    //     let two = Fp(Fr::from(2u64));
    //     let three = Fp(Fr::from(3u64));
    //     let four = Fp(Fr::from(4u64));
    //     let six = Fp(Fr::from(6u64));
    //     assert_eq!(
    //         Matrix::new_unchecked(vec![vec![zero, two], vec![four, six]]).0,
    //         Matrix::new_unchecked(vec![vec![zero, one], vec![two, three]])
    //             .mul_by_scalar(two)
    //             .0
    //     );
    // }

    // /// Checks if `inner_product` is correct.
    // #[test]
    // fn inner_product_is_correct() {
    //     let one = Fp(Fr::from(1u64));
    //     let two = Fp(Fr::from(2u64));
    //     let three = Fp(Fr::from(3u64));
    //     let four = Fp(Fr::from(4u64));
    //     let five = Fp(Fr::from(5u64));
    //     let six = Fp(Fr::from(6u64));
    //     let a = vec![one, two, three];
    //     let b = vec![four, five, six];
    //     assert_eq!(inner_product(&a, &b), Fp(Fr::from(32u64)));
    // }

    // /// Checks if `transpose` is correct.
    // #[test]
    // fn transpose_is_correct() {
    //     let one = Fp(Fr::from(1u64));
    //     let two = Fp(Fr::from(2u64));
    //     let three = Fp(Fr::from(3u64));
    //     let four = Fp(Fr::from(4u64));
    //     let five = Fp(Fr::from(5u64));
    //     let six = Fp(Fr::from(6u64));
    //     let seven = Fp(Fr::from(7u64));
    //     let eight = Fp(Fr::from(8u64));
    //     let nine = Fp(Fr::from(9u64));
    //     let matrix = Matrix::new_unchecked(vec![
    //         vec![one, two, three],
    //         vec![four, five, six],
    //         vec![seven, eight, nine],
    //     ]);
    //     let transpose = Matrix::new_unchecked(vec![
    //         vec![one, four, seven],
    //         vec![two, five, eight],
    //         vec![three, six, nine],
    //     ]);
    //     assert_eq!(matrix.transpose(), transpose);
    // }

    // /// Checks if generating upper triangular matrix is correct.
    // #[test]
    // fn upper_triangular_is_correct() {
    //     let zero = Fp(Fr::from(0u64));
    //     let two = Fp(Fr::from(2u64));
    //     let three = Fp(Fr::from(3u64));
    //     let four = Fp(Fr::from(4u64));
    //     let five = Fp(Fr::from(5u64));
    //     let six = Fp(Fr::from(6u64));
    //     let seven = Fp(Fr::from(7u64));
    //     let eight = Fp(Fr::from(8u64));
    //     let matrix = SquareMatrix::new_unchecked(Matrix::new_unchecked(vec![
    //         vec![two, three, four],
    //         vec![four, five, six],
    //         vec![seven, eight, eight],
    //     ]));
    //     let upper_triangular_form = matrix
    //         .upper_triangular(&mut SquareMatrix::identity(matrix.num_rows()))
    //         .expect("The upper triangular form for `matrix` should exist.");
    //     assert!(upper_triangular_form[0][0] != zero);
    //     assert!(upper_triangular_form[0][1] != zero);
    //     assert!(upper_triangular_form[0][2] != zero);
    //     assert!(upper_triangular_form[1][0] == zero);
    //     assert!(upper_triangular_form[1][1] != zero);
    //     assert!(upper_triangular_form[1][2] != zero);
    //     assert!(upper_triangular_form[2][0] == zero);
    //     assert!(upper_triangular_form[2][1] == zero);
    //     assert!(upper_triangular_form[2][2] != zero);
    // }

    // /// Checks if `inverse` is correct.
    // #[test]
    // fn inverse_is_correct() {
    //     let zero = Fp(Fr::from(0u64));
    //     let one = Fp(Fr::from(1u64));
    //     let two = Fp(Fr::from(2u64));
    //     let three = Fp(Fr::from(3u64));
    //     let four = Fp(Fr::from(4u64));
    //     let five = Fp(Fr::from(5u64));
    //     let six = Fp(Fr::from(6u64));
    //     let seven = Fp(Fr::from(7u64));
    //     let eight = Fp(Fr::from(8u64));
    //     let nine = Fp(Fr::from(9u64));
    //     let matrix = SquareMatrix::new_unchecked(Matrix::new_unchecked(vec![
    //         vec![one, two, three],
    //         vec![four, three, six],
    //         vec![five, eight, seven],
    //     ]));
    //     let singular_matrix = SquareMatrix::new_unchecked(Matrix::new_unchecked(vec![
    //         vec![one, two, three],
    //         vec![four, five, six],
    //         vec![seven, eight, nine],
    //     ]));
    //     assert!(matrix.is_invertible());
    //     assert!(!singular_matrix.is_invertible());

    //     let matrix_inverse = matrix
    //         .inverse()
    //         .expect("This matrix is invertible in theory.");
    //     let computed_identity = matrix
    //         .matmul(&matrix_inverse)
    //         .expect("Shape of `matrix` and `matrix_inverse` matches.");
    //     assert!(computed_identity.is_identity());

    //     // S
    //     let some_vec = vec![six, five, four];
    //     // M^-1(S)
    //     let inverse_applied = matrix_inverse
    //         .mul_row_vec_at_left(&some_vec)
    //         .expect("`matrix_inverse` and `some_vec` matches on shape.");
    //     // M(M^-1(S))
    //     let m_applied_after_inverse = matrix
    //         .mul_row_vec_at_left(&inverse_applied)
    //         .expect("`matrix` and `inverse_applied` matches on shape.");
    //     // S = M(M^-1(S))
    //     assert_eq!(
    //         some_vec, m_applied_after_inverse,
    //         "M(M^-1(V))) = V did not hold."
    //     );

    //     // B
    //     let base_vec = vec![eight, two, five];
    //     // S + M(B)
    //     let add_after_apply = vec_add(
    //         &some_vec,
    //         &matrix
    //             .mul_row_vec_at_left(&base_vec)
    //             .expect("`matrix` and `base_vec` matches on shape."),
    //     );
    //     // M(B + M^-1(S))
    //     let apply_after_add = matrix
    //         .mul_row_vec_at_left(&vec_add(&base_vec, &inverse_applied))
    //         .expect("Shape matches.");
    //     // S + M(B) = M(B + M^-1(S))
    //     assert_eq!(
    //         add_after_apply, apply_after_add,
    //         "`add_after_apply` should be same as `apply_after_add` in theory."
    //     );

    //     let matrix = SquareMatrix::new_unchecked(Matrix::new_unchecked(vec![
    //         vec![zero, one],
    //         vec![one, zero],
    //     ]));
    //     let matrix_inv = matrix.inverse().expect("`matrix` is invertible in theory.");
    //     let computed_identity = matrix
    //         .matmul(&matrix_inv)
    //         .expect("`matrix` and `matrix_inv` match on shape.");
    //     assert!(computed_identity.is_identity());
    //     let computed_identity = matrix_inv
    //         .matmul(&matrix)
    //         .expect("`matrix` and `matrix_inv` match on shape.");
    //     assert!(computed_identity.is_identity());
    // }

    // /// Checks if `eliminate` is correct.
    // #[test]
    // fn eliminate_is_correct() {
    //     let two = Fp(Fr::from(2u64));
    //     let three = Fp(Fr::from(3u64));
    //     let four = Fp(Fr::from(4u64));
    //     let five = Fp(Fr::from(5u64));
    //     let six = Fp(Fr::from(6u64));
    //     let seven = Fp(Fr::from(7u64));
    //     let eight = Fp(Fr::from(8u64));
    //     let m = Matrix::new_unchecked(vec![
    //         vec![two, three, four],
    //         vec![four, five, six],
    //         vec![seven, eight, eight],
    //     ]);
    //     for i in 0..m.num_rows() {
    //         let mut shadow = Matrix::identity(m.num_columns());
    //         let res = m.eliminate(i, &mut shadow);
    //         if i > 0 {
    //             assert!(res.is_none());
    //             continue;
    //         } else {
    //             assert!(res.is_some());
    //         }
    //         assert_eq!(
    //             1,
    //             res.expect("An eliminated matrix should exist.")
    //                 .rows()
    //                 .filter(|&row| !row[i].is_zero())
    //                 .count()
    //         );
    //     }
    // }

    // /// Checks if reducing to identity matrix is correct.
    // #[test]
    // fn reduce_to_identity_is_correct() {
    //     let two = Fp(Fr::from(2u64));
    //     let three = Fp(Fr::from(3u64));
    //     let four = Fp(Fr::from(4u64));
    //     let five = Fp(Fr::from(5u64));
    //     let six = Fp(Fr::from(6u64));
    //     let seven = Fp(Fr::from(7u64));
    //     let eight = Fp(Fr::from(8u64));
    //     let m = SquareMatrix::new_unchecked(Matrix::new_unchecked(vec![
    //         vec![two, three, four],
    //         vec![four, five, six],
    //         vec![seven, eight, eight],
    //     ]));
    //     let mut shadow = SquareMatrix::identity(m.num_columns());
    //     let ut = m.upper_triangular(&mut shadow);
    //     let res = ut
    //         .and_then(|x: SquareMatrix<Fp<Fr>>| x.reduce_to_identity(&mut shadow))
    //         .expect("This should generate an identity matrix as output.");
    //     assert!(res.is_identity());
    //     assert!(m
    //         .matmul(&shadow)
    //         .expect("Matrix shape matches.")
    //         .is_identity());
    // }
}
