use bellman_ce::pairing::Engine;
use bellman_ce::plonk::better_cs::adaptor::{TranspilationVariant, Transpiler};
use bellman_ce::plonk::better_cs::cs::{
    ConstraintSystem as PlonkConstraintSystem, PlonkConstraintSystemParams, PlonkCsWidth4WithNextStepParams,
};
use bellman_ce::plonk::cs::gates::Variable as PlonkVariable;
use bellman_ce::SynthesisError;

#[derive(serde::Serialize, Clone)]
pub struct ConstraintStat {
    pub name: String,
    pub num_gates: usize,
}

pub struct TranspilerWrapper<E: Engine, P: PlonkConstraintSystemParams<E>> {
    inner: Transpiler<E, P>,
    pub constraint_stats: Vec<ConstraintStat>,
}

#[allow(clippy::new_without_default)]
impl<E: Engine, P: PlonkConstraintSystemParams<E>> TranspilerWrapper<E, P> {
    pub fn new() -> Self {
        Self {
            inner: Transpiler::<E, P>::new(),
            constraint_stats: Vec::new(),
        }
    }
    pub fn into_hints_and_num_gates(self) -> (usize, Vec<(usize, TranspilationVariant)>) {
        self.inner.into_hints_and_num_gates()
    }
    pub fn into_hints(self) -> Vec<(usize, TranspilationVariant)> {
        self.inner.into_hints()
    }
    pub fn num_gates(&self) -> usize {
        self.inner.num_gates()
    }
}

impl<E: Engine, P: PlonkConstraintSystemParams<E>> PlonkConstraintSystem<E, P> for TranspilerWrapper<E, P> {
    fn alloc<F>(&mut self, value: F) -> Result<PlonkVariable, SynthesisError>
    where
        F: FnOnce() -> Result<E::Fr, SynthesisError>,
    {
        self.inner.alloc(value)
    }
    fn alloc_input<F>(&mut self, value: F) -> Result<PlonkVariable, SynthesisError>
    where
        F: FnOnce() -> Result<E::Fr, SynthesisError>,
    {
        self.inner.alloc_input(value)
    }
    fn new_gate(
        &mut self,
        variables: P::StateVariables,
        this_step_coeffs: P::ThisTraceStepCoefficients,
        next_step_coeffs: P::NextTraceStepCoefficients,
    ) -> Result<(), SynthesisError> {
        self.inner.new_gate(variables, this_step_coeffs, next_step_coeffs)
    }
    fn get_dummy_variable(&self) -> PlonkVariable {
        self.inner.get_dummy_variable()
    }
}

impl<E: Engine, P: PlonkConstraintSystemParams<E>> bellman_ce::ConstraintSystem<E> for TranspilerWrapper<E, P> {
    type Root = Self;

    fn one() -> bellman_ce::Variable {
        //Transpiler<E, P>::one()
        bellman_ce::Variable::new_unchecked(bellman_ce::Index::Input(0))
    }

    fn alloc<F, A, AR>(&mut self, a: A, f: F) -> Result<bellman_ce::Variable, bellman_ce::SynthesisError>
    where
        F: FnOnce() -> Result<E::Fr, bellman_ce::SynthesisError>,
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
        <Transpiler<E, P> as bellman_ce::ConstraintSystem<E>>::alloc(&mut self.inner, a, f)
    }
    fn alloc_input<F, A, AR>(&mut self, a: A, f: F) -> Result<bellman_ce::Variable, bellman_ce::SynthesisError>
    where
        F: FnOnce() -> Result<E::Fr, bellman_ce::SynthesisError>,
        A: FnOnce() -> AR,
        AR: Into<String>,
    {
        <Transpiler<E, P> as bellman_ce::ConstraintSystem<E>>::alloc_input(&mut self.inner, a, f)
    }
    fn enforce<A, AR, LA, LB, LC>(&mut self, ann: A, a: LA, b: LB, c: LC)
    where
        A: FnOnce() -> AR,
        AR: Into<String>,
        LA: FnOnce(bellman_ce::LinearCombination<E>) -> bellman_ce::LinearCombination<E>,
        LB: FnOnce(bellman_ce::LinearCombination<E>) -> bellman_ce::LinearCombination<E>,
        LC: FnOnce(bellman_ce::LinearCombination<E>) -> bellman_ce::LinearCombination<E>,
    {
        let num_gates_before = self.inner.num_gates();
        let name_ = ann().into();
        self.inner.enforce(|| name_.clone(), a, b, c);
        self.constraint_stats.push(ConstraintStat {
            name: name_,
            num_gates: self.inner.num_gates() - num_gates_before,
        });
    }

    fn push_namespace<NR, N>(&mut self, n: N)
    where
        NR: Into<String>,
        N: FnOnce() -> NR,
    {
        self.inner.push_namespace(n)
    }

    fn pop_namespace(&mut self) {
        self.inner.pop_namespace()
    }

    fn get_root(&mut self) -> &mut Self::Root {
        self
    }
}

pub fn transpile_with_gates_count<E: Engine, C: bellman_ce::Circuit<E>>(
    circuit: C,
) -> Result<(usize, Vec<(usize, TranspilationVariant)>), SynthesisError> {
    let mut transpiler = TranspilerWrapper::<E, PlonkCsWidth4WithNextStepParams>::new();

    circuit
        .synthesize(&mut transpiler)
        .expect("sythesize into traspilation must succeed");

    let (n, hints) = transpiler.into_hints_and_num_gates();

    Ok((n, hints))
}
