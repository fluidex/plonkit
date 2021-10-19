#![allow(clippy::needless_range_loop)]

use bellman_ce::kate_commitment::{Crs, CrsForMonomialForm};
use bellman_ce::plonk::{
    better_cs::cs::PlonkCsWidth4WithNextStepParams,
    better_cs::keys::{Proof as OldProof, VerificationKey as OldVerificationKey},
};
use bellman_ce::SynthesisError;
use franklin_crypto::bellman::pairing::bn256;
use franklin_crypto::bellman::pairing::bn256::Bn256;
use franklin_crypto::bellman::pairing::ff::ScalarEngine;
use franklin_crypto::bellman::pairing::{CurveAffine, Engine};
use franklin_crypto::bellman::plonk::better_better_cs::cs::PlonkCsWidth4WithNextStepAndCustomGatesParams;
use franklin_crypto::bellman::plonk::better_better_cs::cs::ProvingAssembly;
use franklin_crypto::bellman::plonk::better_better_cs::cs::TrivialAssembly;
use franklin_crypto::bellman::plonk::better_better_cs::cs::Width4MainGateWithDNext;
use franklin_crypto::bellman::plonk::better_better_cs::cs::{Circuit, Setup};
use franklin_crypto::bellman::plonk::better_better_cs::setup::VerificationKey;
use franklin_crypto::bellman::plonk::better_better_cs::verifier::verify as core_verify;
use franklin_crypto::bellman::plonk::commitments::transcript::keccak_transcript::RollingKeccakTranscript;
use franklin_crypto::bellman::worker::Worker;
use franklin_crypto::plonk::circuit::bigint::field::RnsParameters;
use franklin_crypto::plonk::circuit::verifier_circuit::affine_point_wrapper::aux_data::{AuxData, BN256AuxData};
use franklin_crypto::plonk::circuit::verifier_circuit::data_structs::IntoLimbedWitness;
use franklin_crypto::plonk::circuit::Width4WithCustomGates;
use franklin_crypto::rescue::bn256::Bn256RescueParams;
use itertools::Itertools;
pub use recurisive_vk_codegen::types::{AggregatedProof, RecursiveVerificationKey};
use recursive_aggregation_circuit::circuit::{
    create_recursive_circuit_setup, create_recursive_circuit_vk_and_setup, create_vks_tree, make_aggregate,
    make_public_input_and_limbed_aggregate, RecursiveAggregationCircuitBn256,
};

// only support depth<8. different depths don't really make performance different
const VK_TREE_DEPTH: usize = 7;

// recursively prove multiple proofs, and aggregate them into one
pub fn prove(
    big_crs: Crs<Bn256, CrsForMonomialForm>,
    old_proofs: Vec<OldProof<Bn256, PlonkCsWidth4WithNextStepParams>>,
    old_vk: OldVerificationKey<Bn256, PlonkCsWidth4WithNextStepParams>,
) -> Result<AggregatedProof, SynthesisError> {
    let num_proofs_to_check = old_proofs.len();
    assert!(num_proofs_to_check > 0);
    assert!(num_proofs_to_check < 256);
    let mut individual_vk_inputs = Vec::new();
    let num_inputs = old_proofs[0].num_inputs;
    for p in &old_proofs {
        for input_value in p.input_values.clone() {
            individual_vk_inputs.push(input_value);
        }
        assert_eq!(p.num_inputs, num_inputs, "proofs num_inputs mismatch!");
    }

    let worker = Worker::new();
    let rns_params = RnsParameters::<Bn256, <Bn256 as Engine>::Fq>::new_for_field(68, 110, 4);
    let rescue_params = Bn256RescueParams::new_checked_2_into_1();

    let mut g2_bases = [<<Bn256 as Engine>::G2Affine as CurveAffine>::zero(); 2];
    g2_bases.copy_from_slice(&big_crs.g2_monomial_bases.as_ref()[..]);
    let aux_data = BN256AuxData::new();

    //notice we have only 1 vk now
    let vks = old_proofs.iter().map(|_| old_vk.clone()).collect_vec();
    let individual_vk_idxs = old_proofs.iter().map(|_| 0usize).collect_vec();
    let (_, (vks_tree, all_witness_values)) = create_vks_tree(&[old_vk], VK_TREE_DEPTH)?;
    let vks_tree_root = vks_tree.get_commitment();

    let proof_ids = individual_vk_idxs.clone();

    let mut queries = vec![];
    for proof_id in 0..num_proofs_to_check {
        let vk = &vks[individual_vk_idxs[proof_id]];

        let leaf_values = vk.into_witness_for_params(&rns_params).expect("must transform into limbed witness");

        let values_per_leaf = leaf_values.len();
        let intra_leaf_indexes_to_query: Vec<_> = ((proof_id * values_per_leaf)..((proof_id + 1) * values_per_leaf)).collect();
        let q = vks_tree.produce_query(intra_leaf_indexes_to_query, &all_witness_values);

        assert_eq!(q.values(), &leaf_values[..]);

        queries.push(q.path().to_vec());
    }

    let aggregate = make_aggregate(&old_proofs, &vks, &rescue_params, &rns_params)?;

    let (_, limbed_aggreagate) = make_public_input_and_limbed_aggregate(vks_tree_root, &proof_ids, &old_proofs, &aggregate, &rns_params);

    let circuit = RecursiveAggregationCircuitBn256 {
        num_proofs_to_check,
        num_inputs,
        vk_tree_depth: VK_TREE_DEPTH,
        vk_root: Some(vks_tree_root),
        vk_witnesses: Some(vks),
        vk_auth_paths: Some(queries),
        proof_ids: Some(proof_ids),
        proofs: Some(old_proofs),

        rescue_params: &rescue_params,
        rns_params: &rns_params,
        aux_data,
        transcript_params: &rescue_params,

        g2_elements: Some(g2_bases),

        _m: std::marker::PhantomData,
    };

    // quick_check_if_satisifed
    let mut cs = TrivialAssembly::<Bn256, Width4WithCustomGates, Width4MainGateWithDNext>::new();
    circuit.synthesize(&mut cs).expect("should synthesize");
    log::info!("Raw number of gates: {}", cs.n());
    cs.finalize();
    log::info!("Padded number of gates: {}", cs.n());
    assert!(cs.is_satisfied());
    log::info!("satisfied {}", cs.is_satisfied());
    assert_eq!(cs.num_inputs, 1);

    let setup: Setup<Bn256, RecursiveAggregationCircuitBn256> =
        create_recursive_circuit_setup(num_proofs_to_check, num_inputs, VK_TREE_DEPTH)?;

    let mut assembly = ProvingAssembly::<Bn256, PlonkCsWidth4WithNextStepAndCustomGatesParams, Width4MainGateWithDNext>::new();
    circuit.synthesize(&mut assembly).expect("must synthesize");
    assembly.finalize();

    let proof = assembly.create_proof::<_, RollingKeccakTranscript<<Bn256 as ScalarEngine>::Fr>>(&worker, &setup, &big_crs, None)?;

    Ok(AggregatedProof {
        proof,
        individual_vk_inputs,
        individual_num_inputs: num_inputs,
        individual_vk_idxs,
        aggr_limbs: limbed_aggreagate,
    })
}

// verify a recursive proof by using a corresponding verification key
pub fn verify(
    vk: VerificationKey<Bn256, RecursiveAggregationCircuitBn256>,
    aggregated_proof: AggregatedProof,
) -> Result<bool, SynthesisError> {
    let mut inputs = Vec::new();
    for chunk in aggregated_proof.individual_vk_inputs.chunks(aggregated_proof.individual_num_inputs) {
        inputs.push(chunk);
    }
    log::info!("individual_inputs: {:#?}", inputs);
    core_verify::<_, _, RollingKeccakTranscript<<Bn256 as ScalarEngine>::Fr>>(&vk, &aggregated_proof.proof, None)
}

// export a verification key for a recursion circuit
pub fn export_vk(
    num_proofs_to_check: usize,
    num_inputs: usize,
    big_crs: &Crs<Bn256, CrsForMonomialForm>,
) -> Result<VerificationKey<Bn256, RecursiveAggregationCircuitBn256>, anyhow::Error> {
    let (recursive_circuit_vk, _recursive_circuit_setup) =
        create_recursive_circuit_vk_and_setup(num_proofs_to_check, num_inputs, VK_TREE_DEPTH, big_crs)?;
    Ok(recursive_circuit_vk)
}

// hash the vk_tree root, proof_indexes, proofs' inputs and aggregated points
pub fn get_aggregated_input(
    old_proofs: Vec<OldProof<Bn256, PlonkCsWidth4WithNextStepParams>>,
    old_vk: OldVerificationKey<Bn256, PlonkCsWidth4WithNextStepParams>,
) -> Result<bn256::Fr, anyhow::Error> {
    let num_proofs_to_check = old_proofs.len();
    assert!(num_proofs_to_check > 0);
    assert!(num_proofs_to_check < 256);
    let num_inputs = old_proofs[0].num_inputs;
    for p in &old_proofs {
        assert_eq!(p.num_inputs, num_inputs, "proofs num_inputs mismatch!");
    }

    let rns_params = RnsParameters::<Bn256, <Bn256 as Engine>::Fq>::new_for_field(68, 110, 4);
    let rescue_params = Bn256RescueParams::new_checked_2_into_1();

    let vks = old_proofs.iter().map(|_| old_vk.clone()).collect_vec();
    let proof_ids = (0..num_proofs_to_check).map(|_| 0usize).collect_vec();

    let (_, (vks_tree, _)) = create_vks_tree(&[old_vk], VK_TREE_DEPTH)?;
    let vks_tree_root = vks_tree.get_commitment();

    let aggregate = make_aggregate(&old_proofs, &vks, &rescue_params, &rns_params)?;

    let (expected_input, _) = make_public_input_and_limbed_aggregate(vks_tree_root, &proof_ids, &old_proofs, &aggregate, &rns_params);

    Ok(expected_input)
}

pub fn get_vk_tree_root_hash(old_vk: OldVerificationKey<Bn256, PlonkCsWidth4WithNextStepParams>) -> Result<bn256::Fr, anyhow::Error> {
    let (_, (vks_tree, _)) = create_vks_tree(&vec![old_vk], VK_TREE_DEPTH)?;
    Ok(vks_tree.get_commitment())
}
