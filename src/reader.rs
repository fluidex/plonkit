use anyhow::{bail, format_err};
use byteorder::{LittleEndian, ReadBytesExt};
use itertools::Itertools;
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, Read};
use std::str;

use bellman_ce::{
    kate_commitment::{Crs, CrsForLagrangeForm, CrsForMonomialForm},
    pairing::{bn256::Bn256, ff::PrimeField, Engine},
    plonk::{
        better_cs::cs::PlonkCsWidth4WithNextStepParams,
        better_cs::keys::{Proof, VerificationKey},
    },
    Field, PrimeFieldRepr,
};

use crate::circom_circuit::{CircuitJson, R1CS};

///
/// proof
///

pub fn load_proof<E: Engine>(filename: &str) -> Proof<E, PlonkCsWidth4WithNextStepParams> {
    Proof::<E, PlonkCsWidth4WithNextStepParams>::read(File::open(filename).expect("read proof file err")).expect("read proof err")
}

///
/// verification key
///

pub fn load_verification_key<E: Engine>(filename: &str) -> VerificationKey<E, PlonkCsWidth4WithNextStepParams> {
    let mut reader = std::io::BufReader::with_capacity(1 << 24, File::open(filename).expect("read vk file err"));
    VerificationKey::<E, PlonkCsWidth4WithNextStepParams>::read(&mut reader).expect("read vk err")
}

///
/// universal setup
///

fn get_universal_setup_file_buff_reader(setup_file_name: &str) -> Result<BufReader<File>, anyhow::Error> {
    let setup_file =
        File::open(setup_file_name).map_err(|e| format_err!("Failed to open universal setup file {}, err: {}", setup_file_name, e))?;
    Ok(BufReader::with_capacity(1 << 29, setup_file))
}

pub fn load_key_monomial_form<E: Engine>(filename: &str) -> Crs<E, CrsForMonomialForm> {
    let mut buf_reader = get_universal_setup_file_buff_reader(filename).expect("read key_monomial_form file err");
    Crs::<E, CrsForMonomialForm>::read(&mut buf_reader).expect("read key_monomial_form err")
}

pub fn maybe_load_key_lagrange_form<E: Engine>(option_filename: Option<String>) -> Option<Crs<E, CrsForLagrangeForm>> {
    match option_filename {
        None => None,
        Some(filename) => {
            let mut buf_reader = get_universal_setup_file_buff_reader(&filename).expect("read key_lagrange_form file err");
            let key_lagrange_form = Crs::<E, CrsForLagrangeForm>::read(&mut buf_reader).expect("read key_lagrange_form err");
            Some(key_lagrange_form)
        }
    }
}

///
/// witness
///

pub fn load_witness_from_file<E: Engine>(filename: &str) -> Vec<E::Fr> {
    if filename.ends_with("json") {
        load_witness_from_json_file::<E>(filename)
    } else {
        load_witness_from_bin_file::<E>(filename)
    }
}

pub fn load_witness_from_json_file<E: Engine>(filename: &str) -> Vec<E::Fr> {
    let reader = OpenOptions::new().read(true).open(filename).expect("unable to open.");
    load_witness_from_json::<E, BufReader<File>>(BufReader::new(reader))
}

fn load_witness_from_json<E: Engine, R: Read>(reader: R) -> Vec<E::Fr> {
    let witness: Vec<String> = serde_json::from_reader(reader).expect("unable to read.");
    witness.into_iter().map(|x| E::Fr::from_str(&x).unwrap()).collect::<Vec<E::Fr>>()
}

pub fn load_witness_from_bin_file<E: Engine>(filename: &str) -> Vec<E::Fr> {
    let reader = OpenOptions::new().read(true).open(filename).expect("unable to open.");
    load_witness_from_bin_reader::<E, BufReader<File>>(BufReader::new(reader)).expect("read witness failed")
}

pub fn load_witness_from_array<E: Engine>(buffer: Vec<u8>) -> Result<Vec<E::Fr>, anyhow::Error> {
    load_witness_from_bin_reader::<E, _>(buffer.as_slice())
}

///
/// r1cs
///

pub fn load_r1cs(filename: &str) -> R1CS<Bn256> {
    if filename.ends_with("json") {
        load_r1cs_from_json_file(filename)
    } else {
        let (r1cs, _wire_mapping) = load_r1cs_from_bin_file(filename);
        r1cs
    }
}

fn load_r1cs_from_json_file<E: Engine>(filename: &str) -> R1CS<E> {
    let reader = OpenOptions::new().read(true).open(filename).expect("unable to open.");
    load_r1cs_from_json(BufReader::new(reader))
}

fn load_r1cs_from_json<E: Engine, R: Read>(reader: R) -> R1CS<E> {
    let circuit_json: CircuitJson = serde_json::from_reader(reader).expect("unable to read.");

    let num_inputs = circuit_json.num_inputs + circuit_json.num_outputs + 1;
    let num_aux = circuit_json.num_variables - num_inputs;

    let convert_constraint = |lc: &BTreeMap<String, String>| {
        lc.iter()
            .map(|(index, coeff)| (index.parse().unwrap(), E::Fr::from_str(coeff).unwrap()))
            .collect_vec()
    };

    let constraints = circuit_json
        .constraints
        .iter()
        .map(|c| (convert_constraint(&c[0]), convert_constraint(&c[1]), convert_constraint(&c[2])))
        .collect_vec();

    R1CS {
        num_inputs,
        num_aux,
        num_variables: circuit_json.num_variables,
        constraints,
    }
}

fn load_r1cs_from_bin_file(filename: &str) -> (R1CS<Bn256>, Vec<usize>) {
    let reader = OpenOptions::new().read(true).open(filename).expect("unable to open.");
    load_r1cs_from_bin(BufReader::new(reader))
}

fn load_r1cs_from_bin<R: Read>(reader: R) -> (R1CS<Bn256>, Vec<usize>) {
    let file = crate::r1cs_file::from_reader(reader).expect("unable to read.");
    let num_inputs = (1 + file.header.n_pub_in + file.header.n_pub_out) as usize;
    let num_variables = file.header.n_wires as usize;
    let num_aux = num_variables - num_inputs;
    (
        R1CS {
            num_aux,
            num_inputs,
            num_variables,
            constraints: file.constraints,
        },
        file.wire_mapping.iter().map(|e| *e as usize).collect_vec(),
    )
}

fn load_witness_from_bin_reader<E: Engine, R: Read>(mut reader: R) -> Result<Vec<E::Fr>, anyhow::Error> {
    let mut wtns_header = [0u8; 4];
    reader.read_exact(&mut wtns_header)?;
    if wtns_header != [119, 116, 110, 115] {
        // ruby -e 'p "wtns".bytes' => [119, 116, 110, 115]
        bail!("invalid file header");
    }
    let version = reader.read_u32::<LittleEndian>()?;
    log::info!("wtns version {}", version);
    if version > 2 {
        bail!("unsupported file version");
    }
    let num_sections = reader.read_u32::<LittleEndian>()?;
    if num_sections != 2 {
        bail!("invalid num sections");
    }
    // read the first section
    let sec_type = reader.read_u32::<LittleEndian>()?;
    if sec_type != 1 {
        bail!("invalid section type");
    }
    let sec_size = reader.read_u64::<LittleEndian>()?;
    if sec_size != 4 + 32 + 4 {
        bail!("invalid section len")
    }
    let field_size = reader.read_u32::<LittleEndian>()?;
    if field_size != 32 {
        bail!("invalid field byte size");
    }
    let mut prime = vec![0u8; field_size as usize];
    reader.read_exact(&mut prime)?;
    if prime != hex!("010000f093f5e1439170b97948e833285d588181b64550b829a031e1724e6430") {
        bail!("invalid curve prime");
    }
    let witness_len = reader.read_u32::<LittleEndian>()?;
    log::info!("witness len {}", witness_len);
    let sec_type = reader.read_u32::<LittleEndian>()?;
    if sec_type != 2 {
        bail!("invalid section type");
    }
    let sec_size = reader.read_u64::<LittleEndian>()?;
    if sec_size != (witness_len * field_size) as u64 {
        bail!("invalid witness section size {}", sec_size);
    }
    let mut result = Vec::with_capacity(witness_len as usize);
    for _ in 0..witness_len {
        let mut repr = E::Fr::zero().into_repr();
        repr.read_le(&mut reader)?;
        result.push(E::Fr::from_repr(repr)?);
    }
    Ok(result)
}
