# Poseidon

## Code Structure

* `compat.rs`: Contains legacy implementation for Poseidon hash that is kept for compatibility.
* `constants.rs`: Generates poseidon permutation round numbers.
* `lfsr.rs`: Implements linear feedback shift register as a random number generator.
* `matrix.rs`: Implements basic linear algebra.
* `mds.rs`: Generate MDS matrix.
* `mod.rs`: Implements Poseidon hash.
* `preprocessing.rs`: Preprocess round constants and MDS matrix for optimized poseidon hash.
* `round_constants.rs`: Generates round constants.
* `mds_hardcoded_tests/correct_mds_generation.sage`: Generates hardcoded tests based on sage script adapted from [here](https://extgit.iaik.tugraz.at/krypto/hadeshash/-/blob/master/code/generate_parameters_grain.sage).
* `mds_hardcoded_tests/width*n*`: Contains a hardcoded $n\times n$ MDS matrix generated from the sage script.
* `parameters_hardcoded_test/generate_parameters_grain_deterministic.sage`: Generates hardcoded tests based on sage script adapted from [here](https://extgit.iaik.tugraz.at/krypto/hadeshash/-/blob/master/code/generate_parameters_grain.sage).
* `parameters_hardcoded_test/lfsr_values`: Contains a hardcoded list of round constants generated from the sage script. 
* `permutation_hardcoded_test/poseidonperm_bls381_width3.sage`: Generates hardcoded tests based on sage script adapted from [here](https://extgit.iaik.tugraz.at/krypto/hadeshash/-/blob/master/code/poseidonperm_x5_255_3.sage).
* `permutation_hardcoded_test/width3`: Contains a hardcoded width-3 permutation outputs generated from the sage script.

## Generate MDS Hardcoded Tests from SAGE

The following script generates secure MDS matrices:

```sh
cd mds_hardcoded_tests
for width in {2..12}
do
    sage correct_mds_generation.sage 1 0 $width 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
done
cd ..
```

## Generate permutation Hardcoded Tests for BLS12-381 from SAGE

The following script generates permutation hardcoded test values:

```sh
cd permutation_hardcoded_test
sage poseidonperm_bls381_width3.sage
cd ..
```

## Generate round constants Hardcoded Tests from SAGE

The following script generates secure MDS matrices:

```sh
cd parameters_hardcoded_test
sage generate_parameters_grain_deterministic.sage 1 0 255 3 8 55 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
cd ..
```