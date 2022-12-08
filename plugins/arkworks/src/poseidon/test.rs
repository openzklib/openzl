// move tests that need arkworks types here

use crate::{constraint::fp::Fp, ff::field_new, poseidon::NativeField};
use ark_bls12_381::Fr;
use openzl_util::rand::OsRng;

// mod constants {
//     use crate::poseidon::config::Spec2;
//     use openzl_crypto::poseidon::constants::Constants;

//     // TODO: After upgrading to new Poseidon, we have to enable these tests.
//     /// Tests if the specifications match the known constant values.
//     #[cfg(feature = "std")] // TODO: How do I get the test to enforce this feature?
//     #[test]
//     fn specifications_match_known_values() {
//         assert_eq!(
//             Constants::from_arity(2),
//             Constants::from_specification::<Spec2>()
//         );
//         assert_eq!(
//             Constants::from_arity(4),
//             Constants::from_specification::<Spec2>()
//         );
//     }
// }

mod hash {
    // /// Tests if [`Poseidon2`](crate::config::Poseidon2) matches hardcoded sage outputs.
    // #[test]
    // fn poseidon_hash_matches_known_values() {
    //     let hasher = Spec2::gen(&mut OsRng);
    //     let inputs = [&Fp(field_new!(Fr, "1")), &Fp(field_new!(Fr, "2"))];
    //     assert_eq!(
    //         hasher.hash_untruncated(inputs, &mut ()),
    //         include!("permutation_hardcoded_test/width3") // Why doesn't this work?
    //     );
    // }
}
mod round_constants {
    use super::*;
    use openzl_crypto::poseidon::round_constants::{generate_lfsr, sample_field_element};

    #[allow(clippy::needless_borrow)] // NOTE: Clippy false positive https://github.com/rust-lang/rust-clippy/issues/9710
    /// Checks if [`GrainLFSR`] matches hardcoded sage outputs.
    #[test]
    fn grain_lfsr_is_consistent() {
        let test_cases = include!("parameters_hardcoded_test/lfsr_values");
        let mut lfsr = generate_lfsr(255, 3, 8, 55); // TODO: Change for Bn254
        for x in test_cases {
            assert_eq!(sample_field_element::<Fp<Fr>, _>(&mut lfsr), x);
        }
    }
}
mod matrix {
    use super::*;
    use openzl_crypto::poseidon::matrix::{
        inner_product, vec_add, Matrix, MatrixOperations, SquareMatrix,
    };

    /// Checks if generating minor matrix is correct.
    #[test]
    fn minor_is_correct() {
        let one = Fp(Fr::from(1u64));
        let two = Fp(Fr::from(2u64));
        let three = Fp(Fr::from(3u64));
        let four = Fp(Fr::from(4u64));
        let five = Fp(Fr::from(5u64));
        let six = Fp(Fr::from(6u64));
        let seven = Fp(Fr::from(7u64));
        let eight = Fp(Fr::from(8u64));
        let nine = Fp(Fr::from(9u64));
        let matrix = SquareMatrix::new_unchecked(Matrix::new_unchecked(vec![
            vec![one, two, three],
            vec![four, five, six],
            vec![seven, eight, nine],
        ]));
        let cases = [
            (
                0,
                0,
                Matrix::new_unchecked(vec![vec![five, six], vec![eight, nine]]),
            ),
            (
                0,
                1,
                Matrix::new_unchecked(vec![vec![four, six], vec![seven, nine]]),
            ),
            (
                0,
                2,
                Matrix::new_unchecked(vec![vec![four, five], vec![seven, eight]]),
            ),
            (
                1,
                0,
                Matrix::new_unchecked(vec![vec![two, three], vec![eight, nine]]),
            ),
            (
                1,
                1,
                Matrix::new_unchecked(vec![vec![one, three], vec![seven, nine]]),
            ),
            (
                1,
                2,
                Matrix::new_unchecked(vec![vec![one, two], vec![seven, eight]]),
            ),
            (
                2,
                0,
                Matrix::new_unchecked(vec![vec![two, three], vec![five, six]]),
            ),
            (
                2,
                1,
                Matrix::new_unchecked(vec![vec![one, three], vec![four, six]]),
            ),
            (
                2,
                2,
                Matrix::new_unchecked(vec![vec![one, two], vec![four, five]]),
            ),
        ];
        for (i, j, expected) in &cases {
            let result = matrix
                .minor(*i, *j)
                .expect("A matrix of shape 3x3 should be able to generate minor matrices.");
            assert_eq!(expected, &result);
        }
    }

    /// Checks if scalar multiplication is correct.
    #[test]
    fn scalar_mul_is_correct() {
        let zero = Fp(Fr::from(0u64));
        let one = Fp(Fr::from(1u64));
        let two = Fp(Fr::from(2u64));
        let three = Fp(Fr::from(3u64));
        let four = Fp(Fr::from(4u64));
        let six = Fp(Fr::from(6u64));
        assert_eq!(
            Matrix::new_unchecked(vec![vec![zero, two], vec![four, six]]).0,
            Matrix::new_unchecked(vec![vec![zero, one], vec![two, three]])
                .mul_by_scalar(two)
                .0
        );
    }

    /// Checks if `inner_product` is correct.
    #[test]
    fn inner_product_is_correct() {
        let one = Fp(Fr::from(1u64));
        let two = Fp(Fr::from(2u64));
        let three = Fp(Fr::from(3u64));
        let four = Fp(Fr::from(4u64));
        let five = Fp(Fr::from(5u64));
        let six = Fp(Fr::from(6u64));
        let a = vec![one, two, three];
        let b = vec![four, five, six];
        assert_eq!(inner_product(&a, &b), Fp(Fr::from(32u64)));
    }

    /// Checks if `transpose` is correct.
    #[test]
    fn transpose_is_correct() {
        let one = Fp(Fr::from(1u64));
        let two = Fp(Fr::from(2u64));
        let three = Fp(Fr::from(3u64));
        let four = Fp(Fr::from(4u64));
        let five = Fp(Fr::from(5u64));
        let six = Fp(Fr::from(6u64));
        let seven = Fp(Fr::from(7u64));
        let eight = Fp(Fr::from(8u64));
        let nine = Fp(Fr::from(9u64));
        let matrix = Matrix::new_unchecked(vec![
            vec![one, two, three],
            vec![four, five, six],
            vec![seven, eight, nine],
        ]);
        let transpose = Matrix::new_unchecked(vec![
            vec![one, four, seven],
            vec![two, five, eight],
            vec![three, six, nine],
        ]);
        assert_eq!(matrix.transpose(), transpose);
    }

    /// Checks if generating upper triangular matrix is correct.
    #[test]
    fn upper_triangular_is_correct() {
        let zero = Fp(Fr::from(0u64));
        let two = Fp(Fr::from(2u64));
        let three = Fp(Fr::from(3u64));
        let four = Fp(Fr::from(4u64));
        let five = Fp(Fr::from(5u64));
        let six = Fp(Fr::from(6u64));
        let seven = Fp(Fr::from(7u64));
        let eight = Fp(Fr::from(8u64));
        let matrix = SquareMatrix::new_unchecked(Matrix::new_unchecked(vec![
            vec![two, three, four],
            vec![four, five, six],
            vec![seven, eight, eight],
        ]));
        let upper_triangular_form = matrix
            .upper_triangular(&mut SquareMatrix::identity(matrix.num_rows()))
            .expect("The upper triangular form for `matrix` should exist.");
        assert!(upper_triangular_form[0][0] != zero);
        assert!(upper_triangular_form[0][1] != zero);
        assert!(upper_triangular_form[0][2] != zero);
        assert!(upper_triangular_form[1][0] == zero);
        assert!(upper_triangular_form[1][1] != zero);
        assert!(upper_triangular_form[1][2] != zero);
        assert!(upper_triangular_form[2][0] == zero);
        assert!(upper_triangular_form[2][1] == zero);
        assert!(upper_triangular_form[2][2] != zero);
    }

    /// Checks if `inverse` is correct.
    #[test]
    fn inverse_is_correct() {
        let zero = Fp(Fr::from(0u64));
        let one = Fp(Fr::from(1u64));
        let two = Fp(Fr::from(2u64));
        let three = Fp(Fr::from(3u64));
        let four = Fp(Fr::from(4u64));
        let five = Fp(Fr::from(5u64));
        let six = Fp(Fr::from(6u64));
        let seven = Fp(Fr::from(7u64));
        let eight = Fp(Fr::from(8u64));
        let nine = Fp(Fr::from(9u64));
        let matrix = SquareMatrix::new_unchecked(Matrix::new_unchecked(vec![
            vec![one, two, three],
            vec![four, three, six],
            vec![five, eight, seven],
        ]));
        let singular_matrix = SquareMatrix::new_unchecked(Matrix::new_unchecked(vec![
            vec![one, two, three],
            vec![four, five, six],
            vec![seven, eight, nine],
        ]));
        assert!(matrix.is_invertible());
        assert!(!singular_matrix.is_invertible());

        let matrix_inverse = matrix
            .inverse()
            .expect("This matrix is invertible in theory.");
        let computed_identity = matrix
            .matmul(&matrix_inverse)
            .expect("Shape of `matrix` and `matrix_inverse` matches.");
        assert!(computed_identity.is_identity());

        // S
        let some_vec = vec![six, five, four];
        // M^-1(S)
        let inverse_applied = matrix_inverse
            .mul_row_vec_at_left(&some_vec)
            .expect("`matrix_inverse` and `some_vec` matches on shape.");
        // M(M^-1(S))
        let m_applied_after_inverse = matrix
            .mul_row_vec_at_left(&inverse_applied)
            .expect("`matrix` and `inverse_applied` matches on shape.");
        // S = M(M^-1(S))
        assert_eq!(
            some_vec, m_applied_after_inverse,
            "M(M^-1(V))) = V did not hold."
        );

        // B
        let base_vec = vec![eight, two, five];
        // S + M(B)
        let add_after_apply = vec_add(
            &some_vec,
            &matrix
                .mul_row_vec_at_left(&base_vec)
                .expect("`matrix` and `base_vec` matches on shape."),
        );
        // M(B + M^-1(S))
        let apply_after_add = matrix
            .mul_row_vec_at_left(&vec_add(&base_vec, &inverse_applied))
            .expect("Shape matches.");
        // S + M(B) = M(B + M^-1(S))
        assert_eq!(
            add_after_apply, apply_after_add,
            "`add_after_apply` should be same as `apply_after_add` in theory."
        );

        let matrix = SquareMatrix::new_unchecked(Matrix::new_unchecked(vec![
            vec![zero, one],
            vec![one, zero],
        ]));
        let matrix_inv = matrix.inverse().expect("`matrix` is invertible in theory.");
        let computed_identity = matrix
            .matmul(&matrix_inv)
            .expect("`matrix` and `matrix_inv` match on shape.");
        assert!(computed_identity.is_identity());
        let computed_identity = matrix_inv
            .matmul(&matrix)
            .expect("`matrix` and `matrix_inv` match on shape.");
        assert!(computed_identity.is_identity());
    }

    /// Checks if `eliminate` is correct.
    #[test]
    fn eliminate_is_correct() {
        let two = Fp(Fr::from(2u64));
        let three = Fp(Fr::from(3u64));
        let four = Fp(Fr::from(4u64));
        let five = Fp(Fr::from(5u64));
        let six = Fp(Fr::from(6u64));
        let seven = Fp(Fr::from(7u64));
        let eight = Fp(Fr::from(8u64));
        let m = Matrix::new_unchecked(vec![
            vec![two, three, four],
            vec![four, five, six],
            vec![seven, eight, eight],
        ]);
        for i in 0..m.num_rows() {
            let mut shadow = Matrix::identity(m.num_columns());
            let res = m.eliminate(i, &mut shadow);
            if i > 0 {
                assert!(res.is_none());
                continue;
            } else {
                assert!(res.is_some());
            }
            assert_eq!(
                1,
                res.expect("An eliminated matrix should exist.")
                    .rows()
                    .filter(|&row| !row[i].is_zero())
                    .count()
            );
        }
    }

    /// Checks if reducing to identity matrix is correct.
    #[test]
    fn reduce_to_identity_is_correct() {
        let two = Fp(Fr::from(2u64));
        let three = Fp(Fr::from(3u64));
        let four = Fp(Fr::from(4u64));
        let five = Fp(Fr::from(5u64));
        let six = Fp(Fr::from(6u64));
        let seven = Fp(Fr::from(7u64));
        let eight = Fp(Fr::from(8u64));
        let m = SquareMatrix::new_unchecked(Matrix::new_unchecked(vec![
            vec![two, three, four],
            vec![four, five, six],
            vec![seven, eight, eight],
        ]));
        let mut shadow = SquareMatrix::identity(m.num_columns());
        let ut = m.upper_triangular(&mut shadow);
        let res = ut
            .and_then(|x: SquareMatrix<Fp<Fr>>| x.reduce_to_identity(&mut shadow))
            .expect("This should generate an identity matrix as output.");
        assert!(res.is_identity());
        assert!(m
            .matmul(&shadow)
            .expect("Matrix shape matches.")
            .is_identity());
    }
}

mod mds {
    use super::*;
    use crate::ff::UniformRand;
    use openzl_crypto::poseidon::{
        matrix::{Matrix, MatrixOperations},
        mds::MdsMatrices,
    };

    /// Checks if creating mds matrices is correct.
    #[test]
    fn mds_matrices_creation_is_correct() {
        for i in 2..5 {
            check_mds_creation_on_single_width(i);
        }
    }

    fn check_mds_creation_on_single_width(width: usize) {
        let MdsMatrices {
            m,
            m_inv,
            m_hat,
            m_prime,
            m_double_prime,
            ..
        } = MdsMatrices::<Fp<Fr>>::new(width);
        for i in 0..m_hat.num_rows() {
            for j in 0..m_hat.num_columns() {
                assert_eq!(m[i + 1][j + 1], m_hat[i][j], "MDS minor has wrong value.");
            }
        }
        assert!(m_inv
            .matmul(&m)
            .expect("Input shape matches.")
            .is_identity());
        assert_eq!(
            m,
            m_prime
                .matmul(&m_double_prime)
                .expect("Input shape matches.")
        );
    }

    /// Checks if derived mds matrices are correct.
    #[test]
    fn derived_mds_is_correct() {
        let mut rng = OsRng;
        let width = 3;
        let mds = MdsMatrices::new(width);
        let base = (0..width)
            .map(|_| Fp(Fr::rand(&mut rng)))
            .collect::<Vec<_>>();
        let x = {
            let mut x = base.clone();
            x[0] = Fp(Fr::rand(&mut rng));
            x
        };
        let y = {
            let mut y = base;
            y[0] = Fp(Fr::rand(&mut rng));
            y
        };
        let qx = mds
            .m_prime
            .mul_row_vec_at_left(&x)
            .expect("Input shape matches");
        let qy = mds
            .m_prime
            .mul_row_vec_at_left(&y)
            .expect("Input shape matches");
        assert_eq!(qx[0], x[0]);
        assert_eq!(qy[0], y[0]);
        assert_eq!(qx[1..], qy[1..]);
        let mx = mds.m.mul_col_vec(&x).expect("Input shape matches");
        let m1_m2_x = mds
            .m_prime
            .mul_col_vec(
                &mds.m_double_prime
                    .mul_col_vec(&x)
                    .expect("Input shape matches"),
            )
            .expect("Input shape matches");
        assert_eq!(mx, m1_m2_x);
        let xm = mds.m.mul_row_vec_at_left(&x).expect("Input shape matches");
        let x_m1_m2 = mds
            .m_double_prime
            .mul_row_vec_at_left(
                &mds.m_prime
                    .mul_row_vec_at_left(&x)
                    .expect("Input shape matches"),
            )
            .expect("Input shape matches");
        assert_eq!(xm, x_m1_m2);
    }

    /// Checks if `mds` matches hardcoded sage outputs.
    #[test]
    fn mds_matches_hardcoded_sage_output() {
        let test_cases = [
            (2, include!("mds_hardcoded_tests/width2")),
            (3, include!("mds_hardcoded_tests/width3")),
            (4, include!("mds_hardcoded_tests/width4")),
            (5, include!("mds_hardcoded_tests/width5")),
            (6, include!("mds_hardcoded_tests/width6")),
            (7, include!("mds_hardcoded_tests/width7")),
            (8, include!("mds_hardcoded_tests/width8")),
            (9, include!("mds_hardcoded_tests/width9")),
            (10, include!("mds_hardcoded_tests/width10")),
            (11, include!("mds_hardcoded_tests/width11")),
            (12, include!("mds_hardcoded_tests/width12")),
        ];
        for (width, matrix) in test_cases {
            assert_eq!(
                MdsMatrices::generate_mds(width),
                Matrix::new_unchecked(matrix)
            );
        }
    }

    /// Checks if mds is invertible.
    #[test]
    fn mds_is_invertible() {
        for t in 3..10 {
            assert!(MdsMatrices::<Fp<Fr>>::generate_mds(t).is_invertible());
        }
    }

    /// Checks if mds is symmetric.
    #[test]
    fn mds_is_symmetric() {
        for t in 3..10 {
            assert!(MdsMatrices::<Fp<Fr>>::generate_mds(t).is_symmetric());
        }
    }
}
