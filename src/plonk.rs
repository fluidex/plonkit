// Most of this file is forked from source codes of [Matter Labs's zkSync](https://github.com/matter-labs/zksync)
use bellman_ce::{
    kate_commitment::{Crs, CrsForLagrangeForm, CrsForMonomialForm},
    pairing::Engine,
    plonk::{
        better_cs::cs::PlonkCsWidth4WithNextStepParams, commitments::transcript::keccak_transcript::RollingKeccakTranscript,
        make_verification_key, prove, prove_by_steps, setup, transpile, Proof, SetupPolynomials, TranspilationVariant, VerificationKey,
    },
    worker::Worker,
    Circuit, ScalarEngine, SynthesisError,
};

pub const AUX_OFFSET: usize = 1;

const SETUP_MIN_POW2: u32 = 20;
const SETUP_MAX_POW2: u32 = 26;

pub fn gen_key_monomial_form<E: Engine>(power_of_two: usize) -> Crs<E, CrsForMonomialForm> {
    Crs::<E, CrsForMonomialForm>::crs_42(power_of_two, &Worker::new())
}

pub struct SetupForProver<E: Engine> {
    setup_polynomials: SetupPolynomials<E, PlonkCsWidth4WithNextStepParams>,
    hints: Vec<(usize, TranspilationVariant)>,
    key_monomial_form: Crs<E, CrsForMonomialForm>,
    key_lagrange_form: Option<Crs<E, CrsForLagrangeForm>>,
}

impl<E: Engine> SetupForProver<E> {
    pub fn prepare_setup_for_prover<C: Circuit<E> + Clone>(
        circuit: C,
        key_monomial_form: Crs<E, CrsForMonomialForm>,
        key_lagrange_form: Option<Crs<E, CrsForLagrangeForm>>,
    ) -> Result<Self, anyhow::Error> {
        let hints = transpile(circuit.clone())?;
        let setup_polynomials = setup(circuit, &hints)?;
        let size = setup_polynomials.n.next_power_of_two().trailing_zeros();
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

    pub fn prove<C: Circuit<E> + Clone>(&self, circuit: C) -> Result<Proof<E, PlonkCsWidth4WithNextStepParams>, SynthesisError> {
        match &self.key_lagrange_form {
            Some(key_lagrange_form) => prove::<_, _, RollingKeccakTranscript<<E as ScalarEngine>::Fr>>(
                circuit,
                &self.hints,
                &self.setup_polynomials,
                &self.key_monomial_form,
                &key_lagrange_form,
            ),
            None => prove_by_steps::<_, _, RollingKeccakTranscript<<E as ScalarEngine>::Fr>>(
                circuit,
                &self.hints,
                &self.setup_polynomials,
                None,
                &self.key_monomial_form,
            ),
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

pub fn verify<E: Engine>(
    vk: &VerificationKey<E, PlonkCsWidth4WithNextStepParams>,
    proof: &Proof<E, PlonkCsWidth4WithNextStepParams>,
) -> Result<bool, SynthesisError> {
    bellman_ce::plonk::verify::<_, RollingKeccakTranscript<<E as ScalarEngine>::Fr>>(&proof, &vk)
}
