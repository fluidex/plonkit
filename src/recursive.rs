use bellman_ce::pairing::bn256::Bn256;
use bellman_ce::pairing::ff::ScalarEngine;
use bellman_ce::plonk::better_better_cs::proof::Proof;
use bellman_ce::plonk::better_better_cs::setup::VerificationKey;
use bellman_ce::plonk::better_better_cs::verifier::verify as core_verify;
use bellman_ce::plonk::commitments::transcript::keccak_transcript::RollingKeccakTranscript;
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
