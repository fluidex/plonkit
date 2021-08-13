use franklin_crypto::bellman::pairing::bn256::Bn256;
use franklin_crypto::bellman::pairing::ff::ScalarEngine;
use franklin_crypto::bellman::plonk::better_better_cs::proof::Proof;
use franklin_crypto::bellman::plonk::better_better_cs::setup::VerificationKey;
use franklin_crypto::bellman::plonk::better_better_cs::verifier::verify as core_verify;
use franklin_crypto::bellman::plonk::commitments::transcript::keccak_transcript::RollingKeccakTranscript;
// use bellman_ce::bn256::Bn256;
// use bellman_ce::ScalarEngine;
use bellman_ce::kate_commitment::{Crs, CrsForMonomialForm};
use bellman_ce::SynthesisError;
use recursive_aggregation_circuit::circuit::{
    create_recursive_circuit_vk_and_setup,
    // make_aggregate, make_public_input_and_limbed_aggregate, make_vks_tree,
    RecursiveAggregationCircuitBn256,
};

pub fn verify(
    vk: &VerificationKey<Bn256, RecursiveAggregationCircuitBn256>,
    proof: &Proof<Bn256, RecursiveAggregationCircuitBn256>,
) -> Result<bool, SynthesisError> {
    core_verify::<_, _, RollingKeccakTranscript<<Bn256 as ScalarEngine>::Fr>>(vk, proof, None)
}

pub fn export_vk(
    num_proofs_to_check: usize,
    num_inputs: usize,
    tree_depth: usize,
    crs: &Crs<Bn256, CrsForMonomialForm>,
) -> VerificationKey<Bn256, RecursiveAggregationCircuitBn256<'static>> {
    let (recursive_circuit_vk, _recursive_circuit_setup) =
        create_recursive_circuit_vk_and_setup(num_proofs_to_check, num_inputs, tree_depth, crs)
            .expect("must create recursive circuit verification key");

    recursive_circuit_vk
}
