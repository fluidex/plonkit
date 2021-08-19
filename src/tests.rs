use std::fs;

use bellman_ce::bn256::Bn256;
use crate::circom_circuit::CircomCircuit;
use crate::{reader, plonk};

const CIRCUIT_FILE: &'static str = concat!(env!("CARGO_MANIFEST_DIR"), "/test/circuits/simple/circuit.r1cs.json");
const WITNESS_FILE: &'static str = concat!(env!("CARGO_MANIFEST_DIR"), "/test/circuits/simple/witness.json");
const VK_FILE: &'static str = concat!(env!("CARGO_MANIFEST_DIR"), "/test/circuits/simple/vk.bin");
const PROOF_FILE: &'static str = concat!(env!("CARGO_MANIFEST_DIR"), "/test/circuits/simple/proof.bin");
const MONOMIAL_KEY_FILE: &'static str = concat!(env!("CARGO_MANIFEST_DIR"), "/keys/setup/setup_2^10.key");
const DEFAULT_TRANSCRIPT: &'static str = "keccak";

#[test]
fn test_export_verification_key() {
    let circuit = CircomCircuit {
        r1cs: reader::load_r1cs(CIRCUIT_FILE),
        witness: None,
        wire_mapping: None,
        aux_offset: plonk::AUX_OFFSET,
    };

    let setup = plonk::SetupForProver::prepare_setup_for_prover(
        circuit,
        reader::load_key_monomial_form(MONOMIAL_KEY_FILE),
        None
    )
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
    ).unwrap();

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