// use bellman_ce::bn256::Bn256;
// use bellman_ce::ScalarEngine;
use bellman_ce::kate_commitment::{Crs, CrsForMonomialForm};
use bellman_ce::plonk::{
    better_cs::cs::PlonkCsWidth4WithNextStepParams,
    better_cs::keys::{Proof as OldProof, VerificationKey as OldVerificationKey},
};
use bellman_ce::SynthesisError;
use franklin_crypto::bellman::pairing::bn256::Bn256;
use franklin_crypto::bellman::pairing::ff::ScalarEngine;
use franklin_crypto::bellman::plonk::better_better_cs::proof::Proof;
use franklin_crypto::bellman::plonk::better_better_cs::setup::VerificationKey;
use franklin_crypto::bellman::plonk::better_better_cs::verifier::verify as core_verify;
use franklin_crypto::bellman::plonk::commitments::transcript::keccak_transcript::RollingKeccakTranscript;
use recursive_aggregation_circuit::circuit::{
    create_recursive_circuit_vk_and_setup,
    // make_aggregate, make_public_input_and_limbed_aggregate, make_vks_tree,
    RecursiveAggregationCircuitBn256,
};

pub fn make_circuit(
    crs: Crs<Bn256, CrsForMonomialForm>,
    old_proofs: Vec<OldProof<Bn256, PlonkCsWidth4WithNextStepParams>>,
    old_vk: OldVerificationKey<Bn256, PlonkCsWidth4WithNextStepParams>,
) {
    let num_proofs_to_check = old_proofs.len();
    assert!(num_proofs_to_check > 0);
    let num_inputs = old_proofs[0].num_inputs;
    for p in &old_proofs {
        assert!(p.num_inputs == num_inputs, "proofs num_inputs mismatch!");
    }

    let mut vks: Vec<OldVerificationKey<Bn256, PlonkCsWidth4WithNextStepParams>> = vec![];
    // TODO: refactor?
    for _ in &old_proofs {
        vks.push(old_vk.clone());
    }

    // let recursive_circuit = //RecursiveAggregationCircuit::<Bn256, PlonkCsWidth4WithNextStepParams, WrapperUnchecked<Bn256>, _, RescueChannelGadget<Bn256>> {
    //     RecursiveAggregationCircuitBn256 {
    //         num_proofs_to_check,
    //         num_inputs,
    // //     vk_tree_depth: tree_depth,
    // //     vk_root: Some(vks_tree_root),

    //         vk_witnesses: Some(vks),
    // //     vk_auth_paths: Some(queries),
    // //     proof_ids: Some(proof_ids),
    // //     proofs: Some(vec![proof1, proof2]),

    // //     rescue_params: &rescue_params,
    // //     rns_params: &rns_params,
    // //     aux_data,
    // //     transcript_params: &rescue_params,

    // //     g2_elements: Some(g2_bases),

    //         _m: std::marker::PhantomData,
    // };
}

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
) -> Result<VerificationKey<Bn256, RecursiveAggregationCircuitBn256>, anyhow::Error> {
    let (recursive_circuit_vk, _recursive_circuit_setup) =
        create_recursive_circuit_vk_and_setup(num_proofs_to_check, num_inputs, tree_depth, crs)?;
    Ok(recursive_circuit_vk)
}
