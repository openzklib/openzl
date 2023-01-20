//! ECDSA WASM

use openzl_plugin_plonky2::base::{
    ecdsa::{
        curve::{
            curve_types::{Curve, CurveScalar},
            ecdsa::{sign_message, ECDSAPublicKey, ECDSASecretKey},
            secp256k1::Secp256K1,
        },
        gadgets::{
            curve::CircuitBuilderCurve,
            ecdsa::{verify_message_circuit, ECDSAPublicKeyTarget, ECDSASignatureTarget},
            nonnative::CircuitBuilderNonNative,
        },
    },
    field::{secp256k1_scalar::Secp256K1Scalar, types::Sample},
    iop::witness::PartialWitness,
    plonk::{circuit_builder::CircuitBuilder, circuit_data::CircuitConfig, config::GenericConfig},
};

/// Tests the proving and verification of the ECDSA signature circuit.
#[inline]
pub fn test_ecdsa_circuit<C, const D: usize>(config: CircuitConfig)
where
    C: GenericConfig<D>,
{
    let pw = PartialWitness::new();
    let mut builder = CircuitBuilder::<C::F, D>::new(config);

    let msg = Secp256K1Scalar::rand();
    let msg_target = builder.constant_nonnative(msg);

    let sk = ECDSASecretKey::<Secp256K1>(Secp256K1Scalar::rand());

    let pk = ECDSAPublicKey((CurveScalar(sk.0) * Secp256K1::GENERATOR_PROJECTIVE).to_affine());
    let pk_target = ECDSAPublicKeyTarget(builder.constant_affine_point(pk.0));

    let sig = sign_message(msg, sk);
    let sig_target = ECDSASignatureTarget {
        r: builder.constant_nonnative(sig.r),
        s: builder.constant_nonnative(sig.s),
    };

    verify_message_circuit(&mut builder, msg_target, sig_target, pk_target);

    let data = builder.build::<C>();
    let proof = data.prove(pw).expect("Proving failed.");
    data.verify(proof).expect("Verification failed.");
}

/// Testing Module
#[cfg(test)]
pub mod test {
    use super::*;
    use openzl_plugin_plonky2::base::plonk::config::PoseidonGoldilocksConfig;
    use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};
    use web_sys::console;

    wasm_bindgen_test_configure!(run_in_browser);

    /// Defines a benchmark over `f` with `REPEAT` repetitions.
    #[inline]
    fn bench<F, const REPEAT: usize>(mut f: F, label: &str)
    where
        F: FnMut(),
    {
        let start_time = instant::Instant::now();
        for _ in 0..REPEAT {
            f();
        }
        let end_time = instant::Instant::now();
        console::log_1(
            &format!(
                "{:?} Performance: {:?}",
                label,
                ((end_time - start_time) / REPEAT as u32)
            )
            .into(),
        );
    }

    /// Runs the ECDSA benchmark for a narrow circuit configuration.
    #[wasm_bindgen_test]
    pub fn bench_ecdsa_circuit_narrow() {
        bench::<_, 3>(
            || {
                test_ecdsa_circuit::<PoseidonGoldilocksConfig, 2>(
                    CircuitConfig::standard_ecc_config(),
                )
            },
            "Bench ECDSA Narrow",
        )
    }

    /// Runs the ECDSA benchmark for a narrow circuit configuration.
    #[wasm_bindgen_test]
    pub fn bench_ecdsa_circuit_wide() {
        bench::<_, 3>(
            || test_ecdsa_circuit::<PoseidonGoldilocksConfig, 2>(CircuitConfig::wide_ecc_config()),
            "Bench ECDSA Wide",
        )
    }
}
