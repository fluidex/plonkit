use std::fs;

use crate::circom_circuit::CircomCircuit;
use crate::{plonk, reader};
use crate::bellman_ce::bn256::Bn256;

const CIRCUIT_FILE: &'static str = concat!(env!("CARGO_MANIFEST_DIR"), "/test/circuits/simple/circuit.r1cs.json");
const WITNESS_FILE: &'static str = concat!(env!("CARGO_MANIFEST_DIR"), "/test/circuits/simple/witness.json");
const VK_FILE: &'static str = concat!(env!("CARGO_MANIFEST_DIR"), "/test/circuits/simple/vk.bin");
const PROOF_FILE: &'static str = concat!(env!("CARGO_MANIFEST_DIR"), "/test/circuits/simple/proof.bin");
const MONOMIAL_KEY_FILE: &'static str = concat!(env!("CARGO_MANIFEST_DIR"), "/keys/setup/setup_2^10.key");
const DEFAULT_TRANSCRIPT: &'static str = "keccak";

const CIRCUIT_ANALYZE_RESULT: &'static str = r#"{"num_inputs":2,"num_aux":2,"num_variables":4,"num_constraints":2,"num_nontrivial_constraints":2,"num_gates":3,"num_hints":2,"constraint_stats":[{"name":"0","num_gates":1},{"name":"1","num_gates":2}]}"#;

#[test]
fn test_analyze() {
    let circuit = CircomCircuit {
        r1cs: reader::load_r1cs(CIRCUIT_FILE),
        witness: None,
        wire_mapping: None,
        aux_offset: plonk::AUX_OFFSET,
    };

    let result = crate::plonk::analyse(circuit).unwrap();

    assert_eq!(CIRCUIT_ANALYZE_RESULT, serde_json::to_string(&result).unwrap());
}

#[test]
fn test_export_verification_key() {
    let circuit = CircomCircuit {
        r1cs: reader::load_r1cs(CIRCUIT_FILE),
        witness: None,
        wire_mapping: None,
        aux_offset: plonk::AUX_OFFSET,
    };

    let setup = plonk::SetupForProver::prepare_setup_for_prover(circuit, reader::load_key_monomial_form(MONOMIAL_KEY_FILE), None)
        .expect("prepare err");
    let vk = setup.make_verification_key().unwrap();
    let mut buf = vec![];
    vk.write(&mut buf).unwrap();
    let check_vk = fs::read(VK_FILE).unwrap();
    assert_eq!(check_vk, buf);
}

#[test]
fn test_prove() {
    let circuit = CircomCircuit {
        r1cs: reader::load_r1cs(CIRCUIT_FILE),
        witness: Some(reader::load_witness_from_file::<Bn256>(WITNESS_FILE)),
        wire_mapping: None,
        aux_offset: plonk::AUX_OFFSET,
    };

    let setup = plonk::SetupForProver::prepare_setup_for_prover(
        circuit.clone(),
        reader::load_key_monomial_form(MONOMIAL_KEY_FILE),
        reader::maybe_load_key_lagrange_form(None),
    )
    .unwrap();

    assert!(setup.validate_witness(circuit.clone()).is_ok());

    let _ = setup.get_srs_lagrange_form_from_monomial_form();

    let proof = setup.prove(circuit, DEFAULT_TRANSCRIPT).unwrap();
    let mut buf = vec![];
    proof.write(&mut buf).unwrap();
    let check_proof = fs::read(PROOF_FILE).unwrap();
    assert_eq!(check_proof, buf);
}

#[test]
fn test_verify() {
    let vk = reader::load_verification_key::<Bn256>(VK_FILE);

    let proof = reader::load_proof::<Bn256>(PROOF_FILE);
    assert!(plonk::verify(&vk, &proof, DEFAULT_TRANSCRIPT).expect("fail to verify proof"));
}
