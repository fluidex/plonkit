use crate::bellman_ce::pairing::{ff::PrimeField, Engine};
use franklin_crypto::plonk::circuit::bigint::field::RnsParameters;
pub use num_bigint::BigUint;
use num_traits::Num;
use std::fmt::Display;

//export some more funcs
pub use franklin_crypto::plonk::circuit::bigint::bigint::{biguint_to_fe, fe_to_biguint};

/// convert a hex integer representation ("0x...") to decimal representation
pub fn repr_to_big<T: Display>(r: T) -> String {
    BigUint::from_str_radix(&format!("{}", r)[2..], 16).unwrap().to_str_radix(10)
}

fn from_single_size_limb_witnesses<E: Engine, F: PrimeField>(witnesses: &[BigUint], params: &RnsParameters<E, F>) -> F {
    assert_eq!(params.num_limbs_for_in_field_representation, witnesses.len());
    assert!(
        params.binary_limbs_params.limb_size_bits % params.range_check_info.minimal_multiple == 0,
        "limb size must be divisible by range constraint strategy granularity"
    );

    let mut this_value = BigUint::from(0u64);
    for (witness_idx, w) in witnesses.iter().enumerate() {
        this_value += w.clone() << (witness_idx * params.binary_limbs_params.limb_size_bits);

        //checking, we have omitted some more sophisticated like 'match over strategy'
        let (expected_width, expected_max_value) = (
            params.binary_limbs_bit_widths[witness_idx],
            params.binary_limbs_max_values[witness_idx].clone(),
        );
        assert!(expected_width > 0);
        assert!(
            w <= &expected_max_value,
            "limb is {}, max value is {}",
            w.to_str_radix(16),
            expected_max_value.to_str_radix(16)
        );
    }

    biguint_to_fe(this_value)
}

fn from_double_size_limb_witnesses<E: Engine, F: PrimeField>(
    witnesses: &[BigUint],
    top_limb_may_overflow: bool,
    params: &RnsParameters<E, F>,
) -> F {
    assert!(params.num_binary_limbs == 2 * witnesses.len());
    // until we make better handling of a case that top limb should be zero
    // we make sure that
    assert!(params.num_limbs_for_in_field_representation & 1 == 0);

    let mut this_value = BigUint::from(0u64);
    for (witness_idx, w) in witnesses.iter().enumerate() {
        this_value += w.clone() << (witness_idx * 2 * params.binary_limbs_params.limb_size_bits);

        //checking, we have omitted some more sophisticated like 'match over strategy'
        let low_idx = witness_idx * 2;
        let high_idx = witness_idx * 2 + 1;

        if low_idx < params.num_limbs_for_in_field_representation {
            assert!(high_idx < params.num_limbs_for_in_field_representation)
        }
        // if the element must fit into the field than pad with zeroes
        if !top_limb_may_overflow
            && low_idx >= params.num_limbs_for_in_field_representation
            && high_idx >= params.num_limbs_for_in_field_representation
        {
            unreachable!("should not try to allocate a value in a field with non-constant high limbs");
        }

        let (expected_low_width, expected_low_max_value) = if top_limb_may_overflow {
            (
                params.binary_limbs_params.limb_size_bits,
                params.binary_limbs_params.limb_max_value.clone(),
            )
        } else {
            (
                params.binary_limbs_bit_widths[low_idx],
                params.binary_limbs_max_values[low_idx].clone(),
            )
        };

        let (expected_high_width, _expected_high_max_value) = if top_limb_may_overflow {
            (
                params.binary_limbs_params.limb_size_bits,
                params.binary_limbs_params.limb_max_value.clone(),
            )
        } else {
            (
                params.binary_limbs_bit_widths[high_idx],
                params.binary_limbs_max_values[high_idx].clone(),
            )
        };

        assert!(expected_low_width > 0);
        assert!(expected_high_width > 0);
        if top_limb_may_overflow {
            assert_eq!(expected_low_width, expected_high_width);
        }

        assert_eq!(params.binary_limbs_params.limb_max_value.clone(), expected_low_max_value);

        assert!(expected_high_width & 1 == 0);
    }

    biguint_to_fe(this_value)
}

// refer to plonk/circuit/bigint/field, merge the limbs into prime field without allocting
// inside a cs
pub fn witness_to_field<E: Engine, F: PrimeField>(limbs: &[BigUint], params: &RnsParameters<E, F>) -> F {
    if params.can_allocate_from_double_limb_witness() {
        from_double_size_limb_witnesses(limbs, true, params)
    } else {
        from_single_size_limb_witnesses(limbs, params)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bellman_ce::pairing::bn256::Bn256;
    use franklin_crypto::plonk::circuit::verifier_circuit::utils::field_to_witness;

    #[test]
    fn test_repr_to_big() {
        assert_eq!(
            repr_to_big("0x5d182c51bcfe99583d7075a7a0c10d96bef82b8a059c4bf8c5f6e7124cf2bba3"),
            "42107805128296840955128475693973618460424912398453449171839298387937674312611"
        )
    }

    #[test]
    fn test_witness_to_field() {
        type Fq = <Bn256 as Engine>::Fq;
        let mut rns_params = RnsParameters::<Bn256, <Bn256 as Engine>::Fq>::new_for_field(68, 110, 4);
        rns_params.set_prefer_single_limb_allocation(true);

        let fq: Fq =
            biguint_to_fe(BigUint::from_str_radix(&"0x115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a"[2..], 16).unwrap());

        let wts: Vec<BigUint> = field_to_witness(&fq, &rns_params).iter().map(fe_to_biguint).collect();
        let fq_restored = witness_to_field(&wts[..], &rns_params);
        assert_eq!(fq, fq_restored);

        rns_params.set_prefer_single_limb_allocation(false);
        let wts: Vec<BigUint> = field_to_witness(&fq, &rns_params).iter().map(fe_to_biguint).collect();
        let fq_restored = witness_to_field(&wts[..], &rns_params);
        assert_eq!(fq, fq_restored);
    }
}
