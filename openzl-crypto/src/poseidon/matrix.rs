//! Basic Linear Algebra Implementations

use crate::poseidon::NativeField;
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
pub struct Matrix<F>(pub Vec<Vec<F>>)
where
    F: NativeField;

impl<F> Matrix<F>
where
    F: NativeField,
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
    F: NativeField,
{
    #[inline]
    fn from(matrix: SquareMatrix<F>) -> Self {
        matrix.0
    }
}

impl<F> Index<usize> for Matrix<F>
where
    F: NativeField,
{
    type Output = Vec<F>;

    #[inline]
    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

impl<F> IndexMut<usize> for Matrix<F>
where
    F: NativeField,
{
    #[inline]
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.0[index]
    }
}

impl<F> MatrixOperations for Matrix<F>
where
    F: NativeField,
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
    F: NativeField + PartialEq,
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
    F: NativeField;

impl<F> SquareMatrix<F>
where
    F: NativeField,
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
    pub fn reduce_to_identity(&self, shadow: &mut Self) -> Option<Self>
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
    pub fn upper_triangular(&self, shadow: &mut Self) -> Option<Self>
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
    F: NativeField,
{
    #[inline]
    fn as_ref(&self) -> &Matrix<F> {
        &self.0
    }
}

impl<F> Deref for SquareMatrix<F>
where
    F: NativeField,
{
    type Target = Matrix<F>;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<F> PartialEq<Matrix<F>> for SquareMatrix<F>
where
    F: NativeField + PartialEq,
{
    #[inline]
    fn eq(&self, other: &Matrix<F>) -> bool {
        self.0.eq(other)
    }
}

impl<F> MatrixOperations for SquareMatrix<F>
where
    F: NativeField,
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
    F: NativeField,
{
    a.iter()
        .zip(b)
        .fold(F::zero(), |acc, (v1, v2)| F::add(&acc, &F::mul(v1, v2)))
}

/// Adds two vectors elementwise (i.e., `out[i] = a[i] + b[i]`).
#[inline]
pub fn vec_add<F>(a: &[F], b: &[F]) -> Vec<F>
where
    F: NativeField,
{
    a.iter().zip(b).map(|(a, b)| F::add(a, b)).collect()
}

/// Subtracts two vectors elementwise (i.e., `out[i] = a[i] - b[i]`).
#[inline]
pub fn vec_sub<F>(a: &[F], b: &[F]) -> Vec<F>
where
    F: NativeField,
{
    a.iter().zip(b.iter()).map(|(a, b)| F::sub(a, b)).collect()
}

/// Multiplies a vector `v` with `scalar` elementwise (i.e., `out[i] = scalar * v[i]`).
#[inline]
pub fn scalar_vec_mul<F>(scalar: &F, v: &[F]) -> Vec<F>
where
    F: NativeField,
{
    v.iter().map(|val| F::mul(scalar, val)).collect()
}

/// Eliminates `row` with `factor` multiplied by the `pivot`.
#[inline]
fn eliminate_row<F>(row: &[F], factor: &F, pivot: &[F]) -> Vec<F>
where
    F: NativeField,
{
    vec_sub(row, &scalar_vec_mul(factor, pivot))
}

/// Returns the kronecker delta of `i` and `j`.
#[inline]
pub fn kronecker_delta<F>(i: usize, j: usize) -> F
where
    F: NativeField,
{
    if i == j {
        F::one()
    } else {
        F::zero()
    }
}
