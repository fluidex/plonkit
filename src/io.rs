use bellman_ce::{
    pairing::Engine,
    plonk::{better_cs::cs::PlonkCsWidth4WithNextStepParams, better_cs::keys::Proof, VerificationKey},
};
use std::fs::File;

pub fn load_proof<E: Engine>(filename: &str) -> Proof<E, PlonkCsWidth4WithNextStepParams> {
    Proof::<E, PlonkCsWidth4WithNextStepParams>::read(File::open(filename).expect("read proof file err")).expect("read proof err")
}

pub fn load_verification_key<E: Engine>(filename: &str) -> VerificationKey<E, PlonkCsWidth4WithNextStepParams> {
    VerificationKey::<E, PlonkCsWidth4WithNextStepParams>::read(File::open(filename).expect("read vk file err")).expect("read vk err")
}
