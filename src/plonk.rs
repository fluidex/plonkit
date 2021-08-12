// Most of this file is forked from source codes of [Matter Labs's zkSync](https://github.com/matter-labs/zksync)
use crate::circom_circuit::CircomCircuit;
use crate::transpile::{transpile_with_gates_count, ConstraintStat, TranspilerWrapper};
use bellman_ce::bn256::Bn256;
use bellman_ce::{
    kate_commitment::{Crs, CrsForLagrangeForm, CrsForMonomialForm},
    pairing::Engine,
    plonk::{
        better_cs::adaptor::TranspilationVariant,
        better_cs::cs::PlonkCsWidth4WithNextStepParams,
        better_cs::keys::{Proof, SetupPolynomials, VerificationKey},
        commitments::transcript::keccak_transcript::RollingKeccakTranscript,
        is_satisfied_using_one_shot_check, make_verification_key, prove, prove_by_steps, setup,
    },
    worker::Worker,
    Circuit, ScalarEngine, SynthesisError,
};

type E = Bn256;
use franklin_crypto::plonk::circuit::bigint::field::RnsParameters;
use franklin_crypto::rescue::rescue_transcript::RescueTranscriptForRNS;
use franklin_crypto::rescue::RescueEngine;

pub const AUX_OFFSET: usize = 1;

const SETUP_MIN_POW2: u32 = 20;
const SETUP_MAX_POW2: u32 = 26;

pub fn gen_key_monomial_form(power: u32) -> Result<Crs<E, CrsForMonomialForm>, anyhow::Error> {
    anyhow::ensure!(
        (SETUP_MIN_POW2..=SETUP_MAX_POW2).contains(&power),
        "setup power of two is not in the correct range"
    );
    {
        // run a small setup to estimate time
        use std::time::Instant;
        let t = Instant::now();
        let small_power = 12;
        Crs::<E, CrsForMonomialForm>::crs_42(1 << small_power, &Worker::new());
        let elapsed = t.elapsed().as_secs_f64();
        let estimated_time = elapsed * (1 << (power - small_power)) as f64;
        log::info!("estimated run time: {} secs", estimated_time);
    }
    Ok(Crs::<E, CrsForMonomialForm>::crs_42(1 << power, &Worker::new()))
}

pub struct SetupForProver {
    setup_polynomials: SetupPolynomials<E, PlonkCsWidth4WithNextStepParams>,
    hints: Vec<(usize, TranspilationVariant)>,
    key_monomial_form: Crs<E, CrsForMonomialForm>,
    key_lagrange_form: Option<Crs<E, CrsForLagrangeForm>>,
}

#[derive(serde::Serialize)]
pub struct AnalyseResult {
    pub num_inputs: usize,
    pub num_aux: usize,
    pub num_variables: usize,
    pub num_constraints: usize,
    pub num_nontrivial_constraints: usize,
    pub num_gates: usize,
    pub num_hints: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub constraint_stats: Vec<ConstraintStat>,
}

pub fn analyse<E: Engine>(circuit: CircomCircuit<E>) -> Result<AnalyseResult, anyhow::Error> {
    let mut transpiler = TranspilerWrapper::<E, PlonkCsWidth4WithNextStepParams>::new();
    let mut result = AnalyseResult {
        num_inputs: circuit.r1cs.num_inputs,
        num_aux: circuit.r1cs.num_aux,
        num_variables: circuit.r1cs.num_variables,
        num_constraints: circuit.r1cs.constraints.len(),
        num_nontrivial_constraints: 0,
        num_gates: 0,
        num_hints: 0,
        constraint_stats: Vec::new(),
    };
    circuit
        .synthesize(&mut transpiler)
        .expect("sythesize into traspilation must succeed");
    result.num_nontrivial_constraints = transpiler.constraint_stats.len();
    result.num_gates = transpiler.num_gates();
    result.constraint_stats = transpiler.constraint_stats.clone();
    let hints = transpiler.into_hints();
    result.num_hints = hints.len();
    Ok(result)
}

impl SetupForProver {
    pub fn prepare_setup_for_prover<C: Circuit<E> + Clone>(
        circuit: C,
        key_monomial_form: Crs<E, CrsForMonomialForm>,
        key_lagrange_form: Option<Crs<E, CrsForLagrangeForm>>,
    ) -> Result<Self, anyhow::Error> {
        let (gates_count, hints) = transpile_with_gates_count(circuit.clone())?;
        log::info!("transpile done, gates_count {} hints size {}", gates_count, hints.len());
        let setup_polynomials = setup(circuit, &hints)?;
        let size = setup_polynomials.n.next_power_of_two().trailing_zeros();
        log::info!("circuit setup_polynomials.n {:?} size {}", setup_polynomials.n, size);
        let setup_power_of_two = std::cmp::max(size, SETUP_MIN_POW2); // for exit circuit
        anyhow::ensure!(
            (SETUP_MIN_POW2..=SETUP_MAX_POW2).contains(&setup_power_of_two),
            "setup power of two is not in the correct range"
        );

        Ok(SetupForProver {
            setup_polynomials,
            hints,
            key_monomial_form,
            key_lagrange_form,
        })
    }

    pub fn make_verification_key(&self) -> Result<VerificationKey<E, PlonkCsWidth4WithNextStepParams>, SynthesisError> {
        make_verification_key(&self.setup_polynomials, &self.key_monomial_form)
    }

    pub fn validate_witness<C: Circuit<E> + Clone>(&self, circuit: C) -> Result<(), SynthesisError> {
        is_satisfied_using_one_shot_check(circuit, &self.hints)
    }

    pub fn prove<C: Circuit<E> + Clone>(
        &self,
        circuit: C,
        transcript: &str,
    ) -> Result<Proof<E, PlonkCsWidth4WithNextStepParams>, SynthesisError> {
        is_satisfied_using_one_shot_check(circuit.clone(), &self.hints).expect("must satisfy");
        match &self.key_lagrange_form {
            Some(key_lagrange_form) => match transcript {
                "keccak" => prove::<_, _, RollingKeccakTranscript<<E as ScalarEngine>::Fr>>(
                    circuit,
                    &self.hints,
                    &self.setup_polynomials,
                    &self.key_monomial_form,
                    &key_lagrange_form,
                ),
                _ => {
                    unimplemented!();
                }
            },
            None => match transcript {
                "keccak" => prove_by_steps::<_, _, RollingKeccakTranscript<<E as ScalarEngine>::Fr>>(
                    circuit,
                    &self.hints,
                    &self.setup_polynomials,
                    None,
                    &self.key_monomial_form,
                    None,
                ),
                "rescue" => {
                    let (bn256_param, rns_param) = get_default_rescue_transcript_params();
                    prove_by_steps::<_, _, RescueTranscriptForRNS<E>>(
                        circuit,
                        &self.hints,
                        &self.setup_polynomials,
                        None,
                        &self.key_monomial_form,
                        Some((&bn256_param, &rns_param)),
                    )
                }
                _ => {
                    unimplemented!("invalid transcript. use 'keccak' or 'rescue'");
                }
            },
        }
    }

    pub fn get_srs_lagrange_form_from_monomial_form(&self) -> Crs<E, CrsForLagrangeForm> {
        Crs::<E, CrsForLagrangeForm>::from_powers(
            &self.key_monomial_form,
            self.setup_polynomials.n.next_power_of_two(),
            &Worker::new(),
        )
    }
}

pub fn verify(
    vk: &VerificationKey<E, PlonkCsWidth4WithNextStepParams>,
    proof: &Proof<E, PlonkCsWidth4WithNextStepParams>,
    transcript: &str,
) -> Result<bool, SynthesisError> {
    match transcript {
        "keccak" => {
            bellman_ce::plonk::better_cs::verifier::verify::<_, _, RollingKeccakTranscript<<E as ScalarEngine>::Fr>>(&proof, &vk, None)
        }
        "rescue" => {
            let (bn256_param, rns_param) = get_default_rescue_transcript_params();
            bellman_ce::plonk::better_cs::verifier::verify::<_, _, RescueTranscriptForRNS<E>>(&proof, &vk, Some((&bn256_param, &rns_param)))
        }
        _ => {
            unimplemented!("invalid transcript. use 'keccak' or 'rescue'");
        }
    }
}

fn get_default_rescue_transcript_params() -> (<E as RescueEngine>::Params, RnsParameters<E, <E as Engine>::Fq>) {
    use franklin_crypto::rescue::bn256::Bn256RescueParams;
    let rns_params = RnsParameters::<E, <E as Engine>::Fq>::new_for_field(68, 110, 4);
    let rescue_params = Bn256RescueParams::new_checked_2_into_1();
    let transcript_params: (<E as RescueEngine>::Params, RnsParameters<E, <E as Engine>::Fq>) = (rescue_params, rns_params);
    transcript_params
}
