use anyhow::format_err;
use bellman_ce::{
    kate_commitment::{Crs, CrsForLagrangeForm, CrsForMonomialForm},
    pairing::Engine,
    plonk::{better_cs::cs::PlonkCsWidth4WithNextStepParams, better_cs::keys::Proof, VerificationKey},
};
use std::fs::File;
use std::io::BufReader;

pub fn load_proof<E: Engine>(filename: &str) -> Proof<E, PlonkCsWidth4WithNextStepParams> {
    Proof::<E, PlonkCsWidth4WithNextStepParams>::read(File::open(filename).expect("read proof file err")).expect("read proof err")
}

pub fn load_verification_key<E: Engine>(filename: &str) -> VerificationKey<E, PlonkCsWidth4WithNextStepParams> {
    VerificationKey::<E, PlonkCsWidth4WithNextStepParams>::read(File::open(filename).expect("read vk file err")).expect("read vk err")
}

fn get_universal_setup_file_buff_reader(setup_file_name: &str) -> Result<BufReader<File>, anyhow::Error> {
    let setup_file =
        File::open(setup_file_name).map_err(|e| format_err!("Failed to open universal setup file {}, err: {}", setup_file_name, e))?;
    Ok(BufReader::with_capacity(1 << 29, setup_file))
}

pub fn load_key_monomial_form<E: Engine>(filename: &str) -> Crs<E, CrsForMonomialForm> {
    let mut buf_reader = get_universal_setup_file_buff_reader(filename).expect("read key_monomial_form file err");
    Crs::<E, CrsForMonomialForm>::read(&mut buf_reader).expect("read key_monomial_form err")
}

pub fn maybe_load_key_lagrange_form<E: Engine>(maybe_filename: Option<String>) -> Option<Crs<E, CrsForLagrangeForm>> {
    match maybe_filename {
        None => None,
        Some(filename) => {
            let mut buf_reader = get_universal_setup_file_buff_reader(&filename).expect("read key_lagrange_form file err");
            let key_lagrange_form = Crs::<E, CrsForLagrangeForm>::read(&mut buf_reader).expect("read key_lagrange_form err");
            Some(key_lagrange_form)
        }
    }
}
