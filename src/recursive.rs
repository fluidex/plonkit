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
use franklin_crypto::bellman::pairing::{CurveAffine, Engine};
use franklin_crypto::bellman::plonk::better_better_cs::cs::PlonkCsWidth4WithNextStepAndCustomGatesParams;
use franklin_crypto::bellman::plonk::better_better_cs::cs::ProvingAssembly;
use franklin_crypto::bellman::plonk::better_better_cs::cs::TrivialAssembly;
use franklin_crypto::bellman::plonk::better_better_cs::cs::Width4MainGateWithDNext;
use franklin_crypto::bellman::plonk::better_better_cs::cs::{Circuit, Setup};
use franklin_crypto::bellman::plonk::better_better_cs::proof::Proof;
use franklin_crypto::bellman::plonk::better_better_cs::setup::VerificationKey;
use franklin_crypto::bellman::plonk::better_better_cs::verifier::verify as core_verify;
use franklin_crypto::bellman::plonk::commitments::transcript::keccak_transcript::RollingKeccakTranscript;
use franklin_crypto::bellman::worker::Worker;
use franklin_crypto::plonk::circuit::bigint::field::RnsParameters;
use franklin_crypto::plonk::circuit::verifier_circuit::affine_point_wrapper::aux_data::{AuxData, BN256AuxData};
use franklin_crypto::plonk::circuit::Width4WithCustomGates;
use franklin_crypto::rescue::bn256::Bn256RescueParams;
use itertools::Itertools;
use recursive_aggregation_circuit::circuit::{
    create_recursive_circuit_setup,
    create_recursive_circuit_vk_and_setup,
    // make_aggregate, make_public_input_and_limbed_aggregate, make_vks_tree,
    RecursiveAggregationCircuitBn256,
};

const VK_TREE_DEPTH: usize = 8;

pub fn prove(
    big_crs: Crs<Bn256, CrsForMonomialForm>,
    old_proofs: Vec<OldProof<Bn256, PlonkCsWidth4WithNextStepParams>>,
    old_vk: OldVerificationKey<Bn256, PlonkCsWidth4WithNextStepParams>,
) -> Result<Proof<Bn256, RecursiveAggregationCircuitBn256<'static>>, SynthesisError> {
    let num_proofs_to_check = old_proofs.len();
    assert!(num_proofs_to_check > 0);
    let num_inputs = old_proofs[0].num_inputs;
    for p in &old_proofs {
        assert!(p.num_inputs == num_inputs, "proofs num_inputs mismatch!");
    }

    let worker = Worker::new();
    let rns_params = RnsParameters::<Bn256, <Bn256 as Engine>::Fq>::new_for_field(68, 110, 4);
    let rescue_params = Bn256RescueParams::new_checked_2_into_1();

    // TODO: why 2 ????
    let mut g2_bases = [<<Bn256 as Engine>::G2Affine as CurveAffine>::zero(); 2];
    g2_bases.copy_from_slice(&big_crs.g2_monomial_bases.as_ref()[..]);
    let aux_data = BN256AuxData::new();

    // TODO: should fill in tree?
    // TODO: use make_vks_tree?
    let vks = old_proofs.iter().map(|_| old_vk.clone()).collect_vec();

    let circuit = RecursiveAggregationCircuitBn256 {
        num_proofs_to_check,
        num_inputs,
        // vk_tree_depth: tree_depth,
        // vk_root: Some(vks_tree_root),
        vk_witnesses: Some(vks),
        // vk_auth_paths: Some(queries),
        // proof_ids: Some(proof_ids),
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

    assembly.create_proof::<_, RollingKeccakTranscript<<Bn256 as ScalarEngine>::Fr>>(&worker, &setup, &big_crs, None)
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
    _tree_depth: usize,
    big_crs: &Crs<Bn256, CrsForMonomialForm>,
) -> Result<VerificationKey<Bn256, RecursiveAggregationCircuitBn256>, anyhow::Error> {
    let (recursive_circuit_vk, _recursive_circuit_setup) =
        create_recursive_circuit_vk_and_setup(num_proofs_to_check, num_inputs, VK_TREE_DEPTH, big_crs)?;
    Ok(recursive_circuit_vk)
}
