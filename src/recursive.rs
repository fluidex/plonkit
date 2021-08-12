use franklin_crypto::bellman::plonk::better_better_cs::proof::Proof;
use franklin_crypto::bellman::plonk::better_better_cs::setup::VerificationKey;
use franklin_crypto::bellman::plonk::better_better_cs::verifier::verify as core_verify;
use franklin_crypto::bellman::pairing::bn256::Bn256;
use franklin_crypto::bellman::pairing::ff::ScalarEngine;
use franklin_crypto::bellman::plonk::commitments::transcript::keccak_transcript::RollingKeccakTranscript;
// use bellman_ce::bn256::Bn256;
// use bellman_ce::ScalarEngine;
use bellman_ce::SynthesisError;

use recursive_aggregation_circuit::circuit::RecursiveAggregationCircuitBn256;

pub fn verify(
    vk: &VerificationKey<Bn256, RecursiveAggregationCircuitBn256>,
    proof: &Proof<Bn256, RecursiveAggregationCircuitBn256>,
) -> Result<bool, SynthesisError> {
    core_verify::<_, _, RollingKeccakTranscript<<Bn256 as ScalarEngine>::Fr>>(vk, proof, None)
}

// NewVerificationKey<Bn256, RecursiveAggregationCircuitBn256>
