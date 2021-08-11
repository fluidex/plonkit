use franklin_crypto::bellman::kate_commitment::{Crs, CrsForMonomialForm};
use franklin_crypto::bellman::pairing::{CurveAffine, Engine};
use franklin_crypto::bellman::plonk::better_better_cs::cs::Circuit;
use franklin_crypto::bellman::plonk::better_better_cs::cs::TrivialAssembly;
use franklin_crypto::bellman::worker::Worker;
use franklin_crypto::plonk::circuit::bigint::field::RnsParameters;
use franklin_crypto::plonk::circuit::verifier_circuit::affine_point_wrapper::aux_data::{AuxData, BN256AuxData};
use franklin_crypto::plonk::circuit::verifier_circuit::data_structs::IntoLimbedWitness;
use franklin_crypto::rescue::bn256::Bn256RescueParams;

use franklin_crypto::bellman::pairing::bn256::Bn256;
use franklin_crypto::bellman::pairing::ff::ScalarEngine;
use franklin_crypto::bellman::plonk::better_better_cs::cs::PlonkCsWidth4WithNextStepAndCustomGatesParams;
use franklin_crypto::bellman::plonk::better_better_cs::cs::ProvingAssembly;
use franklin_crypto::bellman::plonk::better_better_cs::cs::Width4MainGateWithDNext;
use franklin_crypto::bellman::plonk::better_better_cs::verifier::verify;
use franklin_crypto::plonk::circuit::Width4WithCustomGates;

use recursive_aggregation_circuit::circuit::{
    create_recursive_circuit_vk_and_setup, make_aggregate, make_public_input_and_limbed_aggregate, make_vks_tree,
    RecursiveAggregationCircuitBn256,
};

use plonkit::reader;

fn main() {
    let vk = reader::load_verification_key::<Bn256>("test/circuits/poseidon_recursive/vk.bin");
    let proof1 = reader::load_proof::<Bn256>("test/circuits/poseidon_recursive/data/000/proof.bin");
    let proof2 = reader::load_proof::<Bn256>("test/circuits/poseidon_recursive/data/001/proof.bin");

    let rns_params = RnsParameters::<Bn256, <Bn256 as Engine>::Fq>::new_for_field(68, 110, 4);
    let rescue_params = Bn256RescueParams::new_checked_2_into_1();

    let worker = Worker::new();
    let crs_mons = Crs::<Bn256, CrsForMonomialForm>::crs_42(1 << 20, &worker);

    let mut g2_bases = [<<Bn256 as Engine>::G2Affine as CurveAffine>::zero(); 2];
    g2_bases.copy_from_slice(&crs_mons.g2_monomial_bases.as_ref()[..]);
    let aux_data = BN256AuxData::new();

    let vks_in_tree = vec![vk.clone(), vk.clone()];

    // make in reverse
    // all_witness_values are calculated from vks
    let (vks_tree, all_witness_values) = make_vks_tree(&vks_in_tree, &rescue_params, &rns_params);

    let vks_tree_root = vks_tree.get_commitment();

    let proof_ids = vec![1, 0];

    let mut queries = vec![];
    for proof_id in &proof_ids {
        let vk = &vks_in_tree[*proof_id];

        let leaf_values = vk.into_witness_for_params(&rns_params).expect("must transform into limbed witness");

        let values_per_leaf = leaf_values.len();
        let intra_leaf_indexes_to_query: Vec<_> = ((proof_id * values_per_leaf)..((proof_id + 1) * values_per_leaf)).collect();
        let q = vks_tree.produce_query(intra_leaf_indexes_to_query, &all_witness_values);

        assert_eq!(q.values(), &leaf_values[..]);

        queries.push(q.path().to_vec());
    }

    let aggregate = make_aggregate(
        &vec![proof1.clone(), proof2.clone()],
        &vec![vk.clone(), vk.clone()],
        &rescue_params,
        &rns_params,
    )
    .unwrap();

    let (_, _) = make_public_input_and_limbed_aggregate(
        vks_tree_root,
        &proof_ids,
        &vec![proof1.clone(), proof2.clone()],
        &aggregate,
        &rns_params,
    );

    let num_inputs = 3;
    let num_proofs_to_check = 2;
    let tree_depth = 1;

    let recursive_circuit =
            //RecursiveAggregationCircuit::<Bn256, PlonkCsWidth4WithNextStepParams, WrapperUnchecked<Bn256>, _, RescueChannelGadget<Bn256>> {
                RecursiveAggregationCircuitBn256 {
                num_proofs_to_check,
                num_inputs,
                vk_tree_depth: tree_depth,
                vk_root: Some(vks_tree_root),

                vk_witnesses: Some(vec![vk.clone(), vk]),
                vk_auth_paths: Some(queries),
                proof_ids: Some(proof_ids),
                proofs: Some(vec![proof1, proof2]),

                rescue_params: &rescue_params,
                rns_params: &rns_params,
                aux_data,
                transcript_params: &rescue_params,

                g2_elements: Some(g2_bases),

                _m: std::marker::PhantomData,
            };

    let mut cs = TrivialAssembly::<Bn256, Width4WithCustomGates, Width4MainGateWithDNext>::new();
    recursive_circuit.synthesize(&mut cs).expect("should synthesize");
    println!("Raw number of gates: {}", cs.n());
    cs.finalize();
    println!("Padded number of gates: {}", cs.n());
    assert!(cs.is_satisfied());
    println!("satisfiled {}", cs.is_satisfied());
    // why num_inputs is 1 here?
    assert_eq!(cs.num_inputs, 1);

    let crs = reader::load_key_monomial_form("keys/setup/setup_2^24.key");

    let (recursive_circuit_vk, recursive_circuit_setup) =
        create_recursive_circuit_vk_and_setup(num_proofs_to_check, num_inputs, tree_depth, &crs)
            .expect("must create recursive circuit verification key");

    use franklin_crypto::bellman::plonk::commitments::transcript::keccak_transcript::RollingKeccakTranscript;

    let mut assembly = ProvingAssembly::<Bn256, PlonkCsWidth4WithNextStepAndCustomGatesParams, Width4MainGateWithDNext>::new();
    recursive_circuit.synthesize(&mut assembly).expect("must synthesize");
    assembly.finalize();

    let proof = assembly
        .create_proof::<_, RollingKeccakTranscript<<Bn256 as ScalarEngine>::Fr>>(&worker, &recursive_circuit_setup, &crs, None)
        .expect("must create recursive proof");

    let is_valid = verify::<_, _, RollingKeccakTranscript<<Bn256 as ScalarEngine>::Fr>>(&recursive_circuit_vk, &proof, None)
        .expect("fail to verify recursive proof");

    assert!(is_valid, "recursive circuit proof is invalid");
    println!("done!!");
}
